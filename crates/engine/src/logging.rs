//! The router's log (G4.6, G4.6d): what happened, with RouterOS topics,
//! who caused it, a message for people and the technical detail.
//!
//! Every source goes through [`Session::log_event`]: the command journal
//! (every configuration change and every failed one), the NTP client's
//! state changes, DHCPv4/v6 client events and the diagnostic tools (start
//! and end). A new source calls it too, with its topic and a level — the
//! DNS resolver (G4.1a) with `["dns", "warning"]`, origin [`DAEMON`], a
//! message in Portuguese ("DNS: sem resposta de 192.0.2.53") — and logs on
//! a change of state, not on every query. An event goes to the built-in `memory` action when a rule
//! sends it there (the RouterOS defaults: `info`, `warning`, `error`,
//! `critical`), which keeps the last `memory_lines` for `log.print`; the
//! daemon reads [`Session::log_since`] and sends the events the rules route
//! to remote actions as syslog datagrams (`routes`). An event a rule sends
//! to `disk` (G4.6g) waits in a bounded queue for the daemon's writer, which
//! takes it out without doing any I/O under the session lock; the newest
//! [`crate::log_disk::WINDOW`] of them stay here, with what the files gave
//! back at boot, so `log.print` reads memory and disk without touching the
//! disk.
//!
//! **Lines that repeat (G0.3f).** A source that would say the same thing on
//! every event (a login without a password, once per connection of a script
//! that opens one per command) logs through [`Session::log_event_grouped`]
//! with a key: the first line goes out at once, the repeats are counted, and
//! one line says how many when the window ends ([`REPEAT_WINDOWS`]). The log
//! stays append-only, so `log.print since`, the remote syslog and the disk
//! all see the same lines.

use std::collections::{HashMap, VecDeque};

use corerouter_model::config::Config;
use corerouter_model::logging::{LogEvent, LogRule, Logging};
use corerouter_model::ntp::{NtpState, NtpStatus};
use serde_json::{Value, json};

use crate::{Caller, Result, Session};

/// Events kept for the remote forwarder whatever the rules say (it reads
/// them every half second; this is many seconds of a burst).
pub const MAX_RECENT: usize = 1024;
/// Longest parameter text put in a message (the datagram is cut at about
/// 1 KiB anyway; RFC 5426 §3.2).
const MAX_PARAMS_TEXT: usize = 200;
/// Longest JSON kept in the technical detail of one event.
const MAX_DETAIL_TEXT: usize = 2048;

/// How long the repeats of a grouped line are counted before one line says
/// how many: 30 s after the first line, then 2 min, then every 10 min while
/// it goes on — the schedule of BSD syslogd's "last message repeated N
/// times" (`repeatinterval[] = { 30, 120, 600 }`, FreeBSD `syslogd.c`). A
/// burst shows its count half a minute later; a loop that never stops costs
/// six lines an hour.
pub const REPEAT_WINDOWS: [u64; 3] = [30, 120, 600];
/// A group without a repeat for this long is forgotten: its next line
/// starts over, with the shortest window.
const GROUP_IDLE: u64 = 600;
/// Most groups counted at once. One more takes the place of the one quiet
/// for longest (its count, if any, is logged first): keys come from the
/// network (a login's source address), so the table has a ceiling.
pub const MAX_GROUPS: usize = 256;
/// Longest group key kept.
const MAX_GROUP_KEY: usize = 160;

/// One grouped line being counted ([`Session::log_event_grouped`]).
#[derive(Debug)]
struct Group {
    topics: Vec<String>,
    origin: String,
    message: String,
    detail: Value,
    /// [`Session::log_clock`] when this window began, and which of
    /// [`REPEAT_WINDOWS`] it is.
    since: u64,
    step: usize,
    /// Clock of the newest occurrence.
    last: u64,
    /// Occurrences counted, not logged, in this window.
    repeats: u64,
}

impl Group {
    /// Repeats are still being counted at `clock` (a clock that went back
    /// ends the window: nothing is held longer than it should).
    fn open(&self, clock: u64) -> bool {
        let window = REPEAT_WINDOWS.get(self.step).copied().unwrap_or(GROUP_IDLE);
        clock >= self.since && clock.saturating_sub(self.since) < window
    }

    /// The window ended (or the group is leaving the table): the line that
    /// says how many repeats it had, and a new window, one step longer.
    fn close(&mut self, clock: u64) -> Option<Counted> {
        let began = self.since;
        let secs = clock.saturating_sub(began).max(1);
        let repeats = std::mem::take(&mut self.repeats);
        self.since = clock;
        self.step = self.step.saturating_add(1).min(REPEAT_WINDOWS.len().saturating_sub(1));
        if repeats == 0 {
            return None;
        }
        let times = if repeats == 1 { "vez" } else { "vezes" };
        let span = if secs < 120 {
            format!("{secs} s")
        } else {
            format!("{} min", secs.saturating_add(30) / 60)
        };
        let mut detail = self.detail.clone();
        match detail.as_object_mut() {
            Some(o) => {
                o.insert("repeats".into(), json!(repeats));
                o.insert("window_secs".into(), json!(secs));
            }
            None => detail = json!({ "repeats": repeats, "window_secs": secs }),
        }
        Some(Counted {
            since: began,
            topics: self.topics.clone(),
            origin: self.origin.clone(),
            message: format!("{} — mais {repeats} {times} nos últimos {span}", self.message),
            detail,
        })
    }
}

/// The line a closed window logs.
struct Counted {
    /// When the window began (the order they are logged in).
    since: u64,
    topics: Vec<String>,
    origin: String,
    message: String,
    detail: Value,
}

/// The log at run time (`Session::ext`).
#[derive(Debug, Default)]
pub struct LogBook {
    seq: u64,
    /// Every event, for the remote forwarder.
    recent: VecDeque<LogEvent>,
    /// What rules sent to `memory`: `log.print`.
    memory: VecDeque<LogEvent>,
    /// G4.6g: a writer exists (the daemon, with a config directory).
    disk_attached: bool,
    /// What rules sent to `disk`, for the writer.
    disk_queue: Vec<LogEvent>,
    /// The newest lines of the disk, restored ones first: `log.print`.
    disk_window: VecDeque<LogEvent>,
    /// `log.clear` counts here: the writer deletes the files.
    disk_clears: u64,
    pub disk: DiskLogStatus,
    /// G0.3f: the grouped lines being counted, by key (at most [`MAX_GROUPS`]).
    groups: HashMap<String, Group>,
}

impl LogBook {
    pub fn memory(&self) -> impl DoubleEndedIterator<Item = &LogEvent> {
        self.memory.iter()
    }

    /// What `log.print` looks at, oldest first; `true`: only the disk has it.
    pub fn rows(&self) -> Vec<(&LogEvent, bool)> {
        let mut out = Vec::with_capacity(self.memory.len().saturating_add(self.disk_window.len()));
        let (mut m, mut d) = (self.memory.iter().peekable(), self.disk_window.iter().peekable());
        loop {
            match (m.peek(), d.peek()) {
                (Some(a), Some(b)) if a.seq == b.seq => {
                    out.push((*a, false));
                    m.next();
                    d.next();
                }
                (Some(a), Some(b)) if a.seq < b.seq => {
                    out.push((*a, false));
                    m.next();
                }
                (Some(a), None) => {
                    out.push((*a, false));
                    m.next();
                }
                (_, Some(b)) => {
                    out.push((*b, true));
                    d.next();
                }
                (None, None) => return out,
            }
        }
    }
}

/// How the log files are doing, reported by the writer (`disk_status` in
/// `system.logging.action.list`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DiskLogStatus {
    /// Where the files are; `None`: no writer (no `--config-dir`).
    pub dir: Option<String>,
    pub files: usize,
    pub bytes: u64,
    /// The ceiling (a share of `/config`).
    pub cap_bytes: u64,
    pub lines_written: u64,
    /// Lines that did not reach a file (queue full, disk full, stop on full).
    pub lines_dropped: u64,
    /// Files deleted before `disk_file_count` because of the ceiling.
    pub files_cut: u64,
    /// `disk_stop_on_full` reached.
    pub stopped: bool,
    /// Lines given back at boot and bad lines left out.
    pub restored: usize,
    pub bad_lines: usize,
    pub flushes: u64,
    pub last_flush: Option<u64>,
    pub last_error: Option<String>,
}

/// Topic of a command by its id, RouterOS-like.
fn area_topic(command: &str) -> &'static str {
    let starts = |p: &str| command.starts_with(p);
    if starts("user.") {
        "account"
    } else if starts("ip.dhcp-client") || starts("ipv6.dhcp-client") {
        "dhcp"
    } else if starts("system.ntp.") {
        "ntp"
    } else if starts("ip.firewall.") || starts("interface.list") {
        "firewall"
    } else if starts("interface.") {
        "interface"
    } else if starts("ip.route.") || starts("routing.") {
        "route"
    } else if starts("tool.") {
        "tool"
    } else {
        "system"
    }
}

/// Topics of a journal entry: `system,info` (plus the area's topic) for a
/// change, `…,error` for a command that failed. RouterOS logs config
/// changes under `system,info` too, so a single `info` rule sends them.
pub fn journal_topics(command: &str, ok: bool) -> Vec<String> {
    let area = area_topic(command);
    let mut topics = vec!["system".to_owned()];
    if area != "system" {
        topics.push(area.to_owned());
    }
    topics.push(if ok { "info" } else { "error" }.to_owned());
    topics
}

/// "admin · GUI", "local · terminal", "admin": who sent a command.
pub fn origin(c: &Caller) -> String {
    let who = c.principal.label();
    match c.via {
        Some(via) => format!("{who} · {via}"),
        None => who.to_owned(),
    }
}

/// The origin of what the router did by itself.
pub const DAEMON: &str = "daemon";

/// `/ip route add`: a command id as a RouterOS menu path.
fn menu_path(command: &str) -> String {
    format!("/{}", command.replace('.', " "))
}

/// `address=10.0.0.1/24 interface=ether1`, at most `max` bytes.
fn params_text(p: &Value, max: usize) -> String {
    let Value::Object(m) = p else {
        return String::new();
    };
    let words: Vec<String> = m
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| {
            let v = match v {
                Value::String(s) if s.contains(' ') || s.is_empty() => format!("\"{s}\""),
                Value::String(s) => s.clone(),
                Value::Array(items) => items
                    .iter()
                    .map(|i| i.as_str().map_or_else(|| i.to_string(), str::to_owned))
                    .collect::<Vec<_>>()
                    .join(","),
                other => other.to_string(),
            };
            format!("{}={v}", k.replace('_', "-"))
        })
        .collect();
    cut(&words.join(" "), max)
}

fn text<'a>(p: &'a Value, key: &str) -> Option<&'a str> {
    p.get(key).and_then(Value::as_str)
}

/// The two reasons Safe Mode undoes by itself, for people.
fn safe_mode_reason(reason: &str) -> &str {
    match reason {
        "the owner's connection closed" => "a conexão de quem o ligou caiu",
        "the timeout expired without confirmation" => "o prazo acabou sem confirmação",
        other => other,
    }
}

/// A command that changes configuration by its name, whatever it wrote to
/// the config store: the accounts (`user.set`) live outside it.
fn changes_by_name(command: &str) -> bool {
    let verb = command.rsplit('.').next().unwrap_or(command);
    matches!(verb, "add" | "set" | "remove" | "move" | "enable" | "disable" | "unset")
}

/// The message of a journal entry, in Portuguese: what changed, read from
/// the parameters and from `cfg` (the running config after the command).
/// `changed`: the command wrote to the configuration. One that did not (a
/// reboot, a cache flush, a lease renewed) is "Executado", not "Alterado"
/// (G0.3f): the log must not claim a change that did not happen.
pub fn journal_message(
    command: &str,
    p: &Value,
    result: &Result<Value>,
    cfg: &Config,
    changed: bool,
) -> String {
    if let Err(e) = result {
        let what = params_text(p, MAX_PARAMS_TEXT);
        let sep = if what.is_empty() { "" } else { " " };
        return format!(
            "Falhou: {}{sep}{what} — {}",
            menu_path(command),
            cut(&e.to_string(), 256)
        );
    }
    let out = result.as_ref().ok();
    let revision = out
        .and_then(|v| v.get("revision"))
        .and_then(Value::as_u64)
        .map_or_else(String::new, |r| format!(" (revisão {r})"));
    let specific = match command {
        "system.identity.set" => text(p, "name").map(|n| format!("Nome do roteador alterado para «{n}»")),
        "system.ntp.client.set" => {
            let c = &cfg.system.ntp_client;
            Some(if c.enabled {
                let servers = if c.servers.is_empty() {
                    "servidores do DHCP (opção 42)".to_owned()
                } else {
                    format!("servidores {}", c.servers.join(", "))
                };
                format!(
                    "NTP Client ligado: {servers}, poll {}–{}",
                    c.min_poll, c.max_poll
                )
            } else {
                "NTP Client desligado".to_owned()
            })
        }
        "ip.address.add" => text(p, "address").map(|a| {
            format!(
                "Endereço {a} adicionado em {}",
                text(p, "interface").unwrap_or("?")
            )
        }),
        "config.commit" => Some(format!("Configuração confirmada{revision}")),
        "config.rollback" => p
            .get("revision")
            .map(|r| format!("Configuração revertida para a revisão {r}")),
        "config.safe-mode.cancel" => Some(match text(p, "automatic") {
            Some(why) => format!(
                "Safe Mode desfeito automaticamente: {}{revision}",
                safe_mode_reason(why)
            ),
            None => format!("Safe Mode cancelado: mudanças desfeitas{revision}"),
        }),
        "log.clear" => Some("Log apagado".to_owned()),
        "user.add" => text(p, "name").map(|n| format!("Conta «{n}» criada")),
        "user.remove" => text(p, "name").map(|n| format!("Conta «{n}» removida")),
        "user.password" | "user.set-password" => Some("Senha alterada".to_owned()),
        _ => None,
    };
    specific.unwrap_or_else(|| {
        let what = params_text(p, MAX_PARAMS_TEXT);
        let sep = if what.is_empty() { "" } else { " " };
        let did = if changed || changes_by_name(command) {
            "Alterado"
        } else {
            "Executado"
        };
        format!("{did}: {}{sep}{what}", menu_path(command))
    })
}

/// The technical detail of a journal entry: the command, its parameters
/// (secrets already masked), its result or error, the revision it created.
fn journal_detail(
    seq: u64,
    command: &str,
    params: &Value,
    result: &Result<Value>,
    revision: Option<u32>,
) -> Value {
    let mut d = json!({ "journal": seq, "command": command, "params": bounded(params) });
    if let Some(o) = d.as_object_mut() {
        match result {
            Ok(v) => {
                o.insert(
                    "result".into(),
                    bounded(&crate::auth::mask_secrets(v)),
                );
            }
            Err(e) => {
                o.insert("error".into(), Value::String(cut(&e.to_string(), 512)));
            }
        }
        if let Some(r) = revision {
            o.insert("revision".into(), json!(r));
        }
    }
    d
}

/// `v`, or its JSON text cut short when it is too big to keep.
pub(crate) fn bounded(v: &Value) -> Value {
    let text = v.to_string();
    if text.len() <= MAX_DETAIL_TEXT {
        v.clone()
    } else {
        Value::String(cut(&text, MAX_DETAIL_TEXT))
    }
}

/// An NTP status change worth logging, if `now` differs from `before`:
/// synchronized (or to another server) is `ntp,info`, lost is
/// `ntp,warning`, and so is a new error while waiting ("cannot resolve").
/// Offsets alone changing do not log, nor the same error again: every poll
/// would.
pub fn ntp_event(before: &NtpStatus, now: &NtpStatus) -> Option<(&'static str, String)> {
    match (before.status, now.status) {
        (_, NtpState::Synchronized)
            if before.status != NtpState::Synchronized
                || before.synced_address != now.synced_address =>
        {
            Some((
                "info",
                format!(
                    "NTP sincronizado com {} ({}), stratum {}, diferença {} ms",
                    now.synced_server.as_deref().unwrap_or("?"),
                    now.synced_address.as_deref().unwrap_or("?"),
                    now.synced_stratum.map_or("?".into(), |s| s.to_string()),
                    now.system_offset_ms
                        .map_or("?".into(), |o| format!("{o:.3}")),
                ),
            ))
        }
        (NtpState::Synchronized, NtpState::Waiting) => Some((
            "warning",
            format!(
                "NTP perdeu a sincronização: {}",
                now.last_error
                    .as_deref()
                    .map_or_else(|| "nenhum servidor respondeu".to_owned(), ntp_error)
            ),
        )),
        (_, NtpState::Waiting) if now.last_error.is_some() && now.last_error != before.last_error => {
            now.last_error.as_deref().map(|e| {
                // G1.6zh: nobody to ask yet is how a new router starts (the
                // DHCP lease brings the server a moment later): not a warning.
                let level = if e == corerouter_model::ntp::NO_SERVER { "info" } else { "warning" };
                (level, format!("NTP: {}", ntp_error(e)))
            })
        }
        _ => None,
    }
}

/// The NTP client's error lines ("pool.ntp.org: failed to lookup address
/// information: …; 192.0.2.1: timed out"), for people.
pub fn ntp_error(raw: &str) -> String {
    let lines: Vec<String> = raw
        .split("; ")
        .map(|part| {
            let (server, why) = part.split_once(": ").unwrap_or(("", part));
            let lower = why.to_ascii_lowercase();
            let said = if lower.contains("lookup") || lower.contains("resolve") || lower.contains("name or service") {
                Some("não foi possível resolver")
            } else if lower.contains("timed out") || lower.contains("timeout") || lower.contains("no answer") {
                Some("sem resposta de")
            } else if lower.contains("unreachable") {
                Some("rede inalcançável para")
            } else if lower.contains(corerouter_model::ntp::NO_SERVER) {
                return "sem servidor: nenhum configurado e nenhum cliente DHCP entregou um (opção 42)".to_owned();
            } else {
                None
            };
            match (said, server.is_empty()) {
                (Some(s), false) => format!("{s} {server}"),
                (Some(s), true) => format!("{s}: {why}"),
                (None, false) => format!("{server}: {why}"),
                (None, true) => why.to_owned(),
            }
        })
        .collect();
    cut(&lines.join("; "), 512)
}

/// Words of the DHCP clients' history lines, in Portuguese (the history
/// itself stays as the client wrote it; the log shows people this).
const DHCP_WORDS: &[(&str, &str)] = &[
    ("searching for a DHCP server", "procurando um servidor DHCP"),
    ("soliciting DHCPv6 servers", "procurando servidores DHCPv6"),
    ("asking to keep the remembered lease", "pedindo para manter a concessão lembrada"),
    ("no server answered: using the remembered lease", "nenhum servidor respondeu: usando a concessão lembrada"),
    (" while it lasts", " enquanto durar"),
    ("got ", "obteve "),
    (" renewed by ", " renovado por "),
    (" offered by ", " oferecido por "),
    (" advertised by ", " anunciado por "),
    ("preference", "preferência"),
    (" lost: ", " perdido: "),
    (" said NAK", " respondeu NAK"),
    ("ignored server ", "servidor ignorado "),
    (": not in allowed-servers", ": fora de allowed-servers"),
    (" is already used by ", " já está em uso por "),
    ("; DECLINE sent", "; DECLINE enviado"),
    ("answer from ", "resposta de "),
    (" ignored: ", " ignorada: "),
    (" from ", " de "),
    (", lease ", ", concessão "),
    ("infinite", "infinita"),
];

/// A DHCP client's history line as a log event: topics, message, detail.
/// `v6`: the DHCPv6 client.
pub(crate) fn dhcp_event(
    v6: bool,
    client: &str,
    interface: &str,
    event: &str,
    message: &str,
) -> ([&'static str; 2], String, Value) {
    let level = match event {
        "error" | "refused" | "declined" | "nak" | "lost" | "gateway" | "fallback" | "status" => {
            "warning"
        }
        "searching" | "offered" | "advertised" | "ignored" => "debug",
        _ => "info",
    };
    let mut text = if event == "stopped" {
        format!("cliente parado: {message}")
    } else {
        message.to_owned()
    };
    for (en, pt) in DHCP_WORDS {
        text = text.replace(en, pt);
    }
    let proto = if v6 { "DHCPv6" } else { "DHCP" };
    (
        ["dhcp", level],
        cut(&format!("{proto} em {interface}: {text}"), 512),
        json!({ "client": client, "interface": interface, "event": event, "text": cut(message, 512) }),
    )
}

/// The rules an event goes to, at most once per remote action (two rules
/// naming the same action do not duplicate the datagram), with the first
/// matching rule's prefix. `memory` is not here: [`Session::log_event`]
/// keeps it.
pub fn routes<'a>(logging: &'a Logging, ev: &LogEvent) -> Vec<&'a LogRule> {
    let mut out: Vec<&LogRule> = Vec::new();
    for r in logging.rules.iter().filter(|r| r.matches(&ev.topics)) {
        if logging.action(&r.action).is_some() && !out.iter().any(|o| o.action == r.action) {
            out.push(r);
        }
    }
    out
}

/// `s` with every control character (newline, ESC, …) as a space.
pub(crate) fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub(crate) fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", s.get(..end).unwrap_or_default())
}

impl LogBook {
    /// `ev` goes to the writer and to `log.print`'s window.
    fn disk_note(&mut self, ev: &LogEvent) {
        if self.disk_queue.len() < crate::log_disk::MAX_QUEUE {
            self.disk_queue.push(ev.clone());
        } else {
            self.disk.lines_dropped = self.disk.lines_dropped.saturating_add(1);
        }
        self.disk_window.push_back(ev.clone());
        while self.disk_window.len() > crate::log_disk::WINDOW {
            self.disk_window.pop_front();
        }
    }
}

impl Session {
    /// Log one event: numbered, timed by the session clock, kept for the
    /// remote forwarder and, when a rule says so, in `memory`.
    pub fn log_event(&mut self, topics: &[&str], origin: &str, message: String, detail: Value) {
        let time = self.now().unwrap_or(0);
        let logging = &self.store().running().system.logging;
        let topics: Vec<String> = topics.iter().map(|t| (*t).to_owned()).collect();
        let keep = logging.to_memory(&topics);
        let to_disk = logging.to_disk(&topics);
        let lines = usize::try_from(logging.memory_lines.max(1)).unwrap_or(usize::MAX);
        let Some(book) = self.ext_mut::<LogBook>() else {
            return;
        };
        book.seq = book.seq.saturating_add(1);
        let ev = LogEvent {
            seq: book.seq,
            time,
            topics,
            origin: origin.to_owned(),
            // One line, no terminal escapes: a failed command's parameters
            // end up here, and the log is shown in terminals (audit #14).
            message: one_line(&message),
            detail,
        };
        if keep {
            book.memory.push_back(ev.clone());
        }
        while book.memory.len() > lines {
            book.memory.pop_front();
        }
        if to_disk && book.disk_attached {
            book.disk_note(&ev);
        }
        book.recent.push_back(ev);
        while book.recent.len() > MAX_RECENT {
            book.recent.pop_front();
        }
    }

    /// The clock of the repeat windows: the steady one when the platform
    /// has it (an NTP step must not end or stretch a window), else the
    /// session's; 0 before any clock (no time passes: repeats are counted
    /// until the first tick).
    fn log_clock(&self) -> u64 {
        self.hal().monotonic_secs().or_else(|| self.now()).unwrap_or(0)
    }

    /// [`Session::log_event`] for a line that repeats (G0.3f): `key` names
    /// what repeats (the source, the account). The first line of a key is
    /// logged at once; the next ones are counted until the window ends
    /// ([`REPEAT_WINDOWS`]), when one line says how many there were. After
    /// a window without repeats the next one is a line again. `true`: this
    /// one was logged; `false`: counted.
    pub fn log_event_grouped(
        &mut self,
        key: &str,
        topics: &[&str],
        origin: &str,
        message: String,
        detail: Value,
    ) -> bool {
        let clock = self.log_clock();
        self.log_groups_close(clock);
        let key = cut(key, MAX_GROUP_KEY);
        let Some(book) = self.ext_mut::<LogBook>() else {
            return false;
        };
        let mut pushed_out = None;
        if let Some(g) = book.groups.get_mut(&key) {
            g.last = clock;
            if g.open(clock) {
                g.repeats = g.repeats.saturating_add(1);
                return false;
            }
            // Its window ended without a repeat: a line again, and the
            // next window is longer.
            g.close(clock);
        } else {
            if book.groups.len() >= MAX_GROUPS {
                let quietest = book
                    .groups
                    .iter()
                    .min_by_key(|(_, g)| g.last)
                    .map(|(k, _)| k.clone());
                pushed_out = quietest
                    .and_then(|k| book.groups.remove(&k))
                    .and_then(|mut g| g.close(clock));
            }
            book.groups.insert(
                key,
                Group {
                    topics: topics.iter().map(|t| (*t).to_owned()).collect(),
                    origin: origin.to_owned(),
                    message: one_line(&message),
                    detail: detail.clone(),
                    since: clock,
                    step: 0,
                    last: clock,
                    repeats: 0,
                },
            );
        }
        if let Some(c) = pushed_out {
            self.log_counted(c);
        }
        self.log_event(topics, origin, message, detail);
        true
    }

    /// Log the count of every group whose window ended and forget the
    /// groups quiet for [`GROUP_IDLE`]. Every tick and every `log.print`
    /// call this: at most [`MAX_GROUPS`] entries, nothing when none.
    pub(crate) fn log_groups_flush(&mut self) {
        let clock = self.log_clock();
        self.log_groups_close(clock);
    }

    fn log_groups_close(&mut self, clock: u64) {
        let Some(book) = self.ext_mut::<LogBook>() else {
            return;
        };
        if book.groups.is_empty() {
            return;
        }
        let mut counted: Vec<Counted> = Vec::new();
        book.groups.retain(|_, g| {
            if g.open(clock) {
                return true;
            }
            if g.repeats > 0 {
                counted.extend(g.close(clock));
                return true;
            }
            clock >= g.last && clock.saturating_sub(g.last) < GROUP_IDLE
        });
        // The table has no order: oldest window first.
        counted.sort_by(|a, b| (a.since, &a.message).cmp(&(b.since, &b.message)));
        for c in counted {
            self.log_counted(c);
        }
    }

    fn log_counted(&mut self, c: Counted) {
        let topics: Vec<&str> = c.topics.iter().map(String::as_str).collect();
        self.log_event(&topics, &c.origin, c.message, c.detail);
    }

    /// Every event after `after_seq` still kept (the remote forwarder).
    pub fn log_since(&self, after_seq: u64) -> Vec<LogEvent> {
        self.ext::<LogBook>().map_or_else(Vec::new, |b| {
            b.recent
                .iter()
                .filter(|e| e.seq > after_seq)
                .cloned()
                .collect()
        })
    }

    /// Number of the last event logged (0: none yet).
    pub fn log_seq(&self) -> u64 {
        self.ext::<LogBook>().map_or(0, |b| b.seq)
    }

    /// Empty `memory` and the disk (`log.clear`; the writer deletes the
    /// files); the numbering goes on.
    pub(crate) fn log_clear(&mut self) -> usize {
        self.ext_mut::<LogBook>().map_or(0, |b| {
            let n = b.rows().len();
            b.memory.clear();
            b.disk_window.clear();
            b.disk_queue.clear();
            b.disk_clears = b.disk_clears.saturating_add(1);
            // The counts were of lines that are gone: start over.
            b.groups.clear();
            n
        })
    }

    /// G4.6g, at boot, before any service reads the log: a writer exists and
    /// the files gave these lines back. They become the oldest lines: 1..=k,
    /// and what the boot logged so far moves up (nobody has seen those
    /// numbers yet). What the boot logged goes to the writer too.
    pub fn log_disk_attach(&mut self, mut restored: Vec<LogEvent>, bad_lines: usize) {
        let skip = restored.len().saturating_sub(crate::log_disk::WINDOW);
        restored.drain(..skip);
        let k = restored.len() as u64;
        let logging = self.store().running().system.logging.clone();
        let Some(book) = self.ext_mut::<LogBook>() else { return };
        for (e, seq) in restored.iter_mut().zip(1u64..) {
            e.seq = seq;
        }
        for e in book.memory.iter_mut().chain(book.recent.iter_mut()) {
            e.seq = e.seq.saturating_add(k);
        }
        book.seq = book.seq.saturating_add(k);
        book.disk.restored = restored.len();
        book.disk.bad_lines = bad_lines;
        book.disk_window = restored.into();
        book.disk_attached = true;
        let booted: Vec<LogEvent> = book.recent.iter().filter(|e| logging.to_disk(&e.topics)).cloned().collect();
        for e in &booted {
            book.disk_note(e);
        }
    }

    /// How many `log.clear` so far.
    pub fn log_disk_clears(&self) -> u64 {
        self.ext::<LogBook>().map_or(0, |b| b.disk_clears)
    }

    /// What is waiting for the writer, and how many `log.clear` so far.
    pub fn log_disk_take(&mut self) -> (Vec<LogEvent>, u64) {
        self.ext_mut::<LogBook>()
            .map_or_else(|| (Vec::new(), 0), |b| (std::mem::take(&mut b.disk_queue), b.disk_clears))
    }

    /// A trimmed `memory_lines` takes effect at once.
    pub(crate) fn log_trim(&mut self) {
        let lines = usize::try_from(self.store().running().system.logging.memory_lines.max(1))
            .unwrap_or(usize::MAX);
        if let Some(b) = self.ext_mut::<LogBook>() {
            while b.memory.len() > lines {
                b.memory.pop_front();
            }
        }
    }

    /// The journal entry `seq` as an event, by whoever sent the command.
    pub(crate) fn log_journal(
        &mut self,
        seq: u64,
        command: &str,
        params: &Value,
        result: &Result<Value>,
        revision: Option<u32>,
        changed: bool,
    ) {
        let topics = journal_topics(command, result.is_ok());
        let topics: Vec<&str> = topics.iter().map(String::as_str).collect();
        let automatic = params.get("automatic").is_some();
        let who = if automatic {
            DAEMON.to_owned()
        } else {
            origin(self.caller())
        };
        let message = journal_message(command, params, result, self.store().running(), changed);
        let detail = journal_detail(seq, command, params, result, revision);
        self.log_event(&topics, &who, message, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineError;

    #[test]
    fn journal_entries_get_routeros_topics() {
        assert_eq!(journal_topics("ip.address.add", true), ["system", "info"]);
        assert_eq!(
            journal_topics("user.add", false),
            ["system", "account", "error"]
        );
        assert_eq!(
            journal_topics("ip.firewall.filter.add", true),
            ["system", "firewall", "info"]
        );
        assert_eq!(journal_topics("tool.ping.start", true), ["system", "tool", "info"]);
    }

    #[test]
    fn messages_read_like_routeros_paths() {
        let cfg = Config::default();
        let p = json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"});
        assert_eq!(
            journal_message("ip.route.add", &p, &Ok(json!({"id": "*1"})), &cfg, true),
            "Alterado: /ip route add dst-address=0.0.0.0/0 gateway=10.0.0.1"
        );
        // G0.3f: what wrote nothing to the configuration was executed, not
        // changed; a command that changes by its name says so either way
        // (the accounts live outside the config store).
        assert_eq!(
            journal_message("ip.dns.cache.flush", &json!({}), &Ok(Value::Null), &cfg, false),
            "Executado: /ip dns cache flush"
        );
        assert_eq!(
            journal_message("ip.arp.make-static", &json!({"id": "*1"}), &Ok(Value::Null), &cfg, true),
            "Alterado: /ip arp make-static id=*1"
        );
        assert_eq!(
            journal_message("user.set", &json!({"name": "noc"}), &Ok(Value::Null), &cfg, false),
            "Alterado: /user set name=noc"
        );
        let err = Err(EngineError::bad("gateway", "unreachable"));
        let m = journal_message("ip.route.add", &p, &err, &cfg, false);
        assert!(m.starts_with("Falhou: /ip route add dst-address="), "{m}");
        assert!(m.contains("unreachable"), "{m}");
        assert_eq!(
            journal_message(
                "ip.address.add",
                &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
                &Ok(Value::Null),
                &cfg,
                true
            ),
            "Endereço 10.0.0.1/24 adicionado em ether1"
        );
        let mut on = cfg.clone();
        on.system.ntp_client.enabled = true;
        on.system.ntp_client.servers = vec!["pool.ntp.org".into()];
        assert_eq!(
            journal_message("system.ntp.client.set", &json!({}), &Ok(Value::Null), &on, true),
            "NTP Client ligado: servidores pool.ntp.org, poll 6–10"
        );
    }

    #[test]
    fn long_params_are_cut_on_a_char_boundary() {
        let p = json!({ "name": "ã".repeat(600) });
        let m = journal_message("system.note.set", &p, &Ok(Value::Null), &Config::default(), true);
        assert!(m.len() < 300, "{}", m.len());
        assert!(m.ends_with('…'));
        let big = json!({ "x": "y".repeat(5000) });
        assert!(matches!(bounded(&big), Value::String(s) if s.len() < 2100));
    }

    #[test]
    fn ntp_logs_only_state_changes() {
        let waiting = NtpStatus {
            status: NtpState::Waiting,
            ..NtpStatus::default()
        };
        let synced = NtpStatus {
            status: NtpState::Synchronized,
            synced_server: Some("pool.ntp.org".into()),
            synced_address: Some("192.0.2.1".into()),
            synced_stratum: Some(2),
            system_offset_ms: Some(1.5),
            ..NtpStatus::default()
        };
        let (level, m) = ntp_event(&waiting, &synced).unwrap();
        assert_eq!(level, "info");
        assert!(m.contains("pool.ntp.org (192.0.2.1), stratum 2"), "{m}");
        let drift = NtpStatus {
            system_offset_ms: Some(2.0),
            ..synced.clone()
        };
        assert_eq!(ntp_event(&synced, &drift), None);
        let lost = ntp_event(&synced, &waiting).unwrap();
        assert_eq!(lost.0, "warning");
        assert_eq!(ntp_event(&NtpStatus::default(), &waiting), None);
        // A new error while waiting logs once, not every poll.
        let failing = NtpStatus {
            last_error: Some(
                "pool.ntp.org: failed to lookup address information: Name or service not known"
                    .into(),
            ),
            ..waiting.clone()
        };
        let (level, m) = ntp_event(&waiting, &failing).unwrap();
        assert_eq!(level, "warning");
        assert_eq!(m, "NTP: não foi possível resolver pool.ntp.org");
        assert_eq!(ntp_event(&failing, &failing.clone()), None);
        // G1.6zh: nobody to ask yet (a new router before its DHCP lease) is
        // said once, as information.
        let nobody = NtpStatus {
            last_error: Some(corerouter_model::ntp::NO_SERVER.into()),
            ..waiting.clone()
        };
        let (level, m) = ntp_event(&waiting, &nobody).unwrap();
        assert_eq!(level, "info");
        assert!(m.contains("nenhum cliente DHCP entregou um (opção 42)"), "{m}");
        assert_eq!(ntp_event(&nobody, &nobody.clone()), None);
    }

    #[test]
    fn dhcp_lines_read_in_portuguese() {
        let (t, m, d) = dhcp_event(
            false,
            "*1",
            "ether1",
            "bound",
            "got 10.0.0.5/24 from 10.0.0.1, lease 1h",
        );
        assert_eq!(t, ["dhcp", "info"]);
        assert_eq!(m, "DHCP em ether1: obteve 10.0.0.5/24 de 10.0.0.1, concessão 1h");
        assert_eq!(d["event"], "bound");
        let (t, _, _) = dhcp_event(true, "*2", "ether2", "searching", "soliciting DHCPv6 servers");
        assert_eq!(t, ["dhcp", "debug"]);
        let (t, m, _) = dhcp_event(false, "*1", "ether1", "nak", "10.0.0.1 said NAK");
        assert_eq!(t, ["dhcp", "warning"]);
        assert!(m.ends_with("10.0.0.1 respondeu NAK"), "{m}");
    }

    #[test]
    fn memory_keeps_what_the_rules_send_up_to_its_lines() {
        let mut s = Session::virtual_lab();
        s.log_event(&["dhcp", "debug"], DAEMON, "debug".into(), Value::Null);
        s.log_event(&["ntp", "warning"], DAEMON, "w".into(), Value::Null);
        let book = s.ext::<LogBook>().unwrap();
        assert_eq!(book.memory().count(), 1, "debug is not in the default rules");
        assert_eq!(s.log_since(0).len(), 2, "the forwarder sees both");
        s.execute(
            "system.logging.action.set",
            &json!({"name": "memory", "memory_lines": 2}),
        )
        .unwrap();
        for i in 0..5 {
            s.log_event(&["system", "info"], DAEMON, format!("{i}"), Value::Null);
        }
        let kept: Vec<&str> = s
            .ext::<LogBook>()
            .unwrap()
            .memory()
            .map(|e| e.message.as_str())
            .collect();
        assert_eq!(kept, ["3", "4"]);
    }

    /// The `memory` lines with `needle`, oldest first.
    fn lines(s: &Session, needle: &str) -> Vec<String> {
        s.ext::<LogBook>()
            .unwrap()
            .memory()
            .filter(|e| e.message.contains(needle))
            .map(|e| e.message.clone())
            .collect()
    }

    fn login(s: &mut Session, key: &str, text: &str) -> bool {
        s.log_event_grouped(
            key,
            &["system", "account", "warning"],
            "auth",
            text.to_owned(),
            json!({"address": key}),
        )
    }

    /// G0.3f: the first line at once, the repeats as one count when the
    /// window ends, on BSD syslogd's schedule: 30 s, 2 min, then 10 min.
    #[test]
    fn a_repeated_line_is_logged_once_and_then_counted() {
        let mut s = Session::virtual_lab();
        s.tick(1_000);
        assert!(login(&mut s, "a", "sem senha de A"), "the first one is a line");
        for _ in 0..29 {
            assert!(!login(&mut s, "a", "sem senha de A"), "a repeat is counted");
        }
        assert_eq!(lines(&s, "sem senha de A"), ["sem senha de A"]);
        s.tick(1_029);
        assert_eq!(lines(&s, "sem senha").len(), 1, "the window is still open");
        s.tick(1_030);
        assert_eq!(
            lines(&s, "sem senha"),
            ["sem senha de A", "sem senha de A — mais 29 vezes nos últimos 30 s"]
        );
        let counted = s.log_since(0).pop().unwrap();
        assert_eq!(counted.topics, ["system", "account", "warning"]);
        assert_eq!(counted.origin, "auth");
        assert_eq!(counted.detail["repeats"], 29);
        assert_eq!(counted.detail["window_secs"], 30);
        assert_eq!(counted.detail["address"], "a", "the first line's detail");
        // It goes on: the next count comes 2 min later, then every 10 min.
        login(&mut s, "a", "sem senha de A");
        s.tick(1_149);
        assert_eq!(lines(&s, "sem senha").len(), 2);
        s.tick(1_150);
        assert_eq!(
            lines(&s, "sem senha").last().unwrap(),
            "sem senha de A — mais 1 vez nos últimos 2 min"
        );
        for t in [1_151, 1_400, 1_749] {
            s.tick(t);
            login(&mut s, "a", "sem senha de A");
        }
        assert_eq!(lines(&s, "sem senha").len(), 3);
        s.tick(1_750);
        assert_eq!(
            lines(&s, "sem senha").last().unwrap(),
            "sem senha de A — mais 3 vezes nos últimos 10 min"
        );
        login(&mut s, "a", "sem senha de A");
        s.tick(2_350);
        assert_eq!(
            lines(&s, "sem senha").last().unwrap(),
            "sem senha de A — mais 1 vez nos últimos 10 min",
            "10 min is the longest window"
        );
    }

    #[test]
    fn groups_do_not_mix() {
        let mut s = Session::virtual_lab();
        s.tick(1_000);
        assert!(login(&mut s, "a", "sem senha de A"));
        assert!(login(&mut s, "b", "sem senha de B"), "another source: its own line");
        for _ in 0..3 {
            login(&mut s, "a", "sem senha de A");
        }
        login(&mut s, "b", "sem senha de B");
        // An ordinary line in between is not held back nor counted.
        s.log_event(&["system", "info"], DAEMON, "outra coisa".into(), Value::Null);
        s.tick(1_030);
        assert_eq!(
            lines(&s, ""),
            [
                "sem senha de A",
                "sem senha de B",
                "outra coisa",
                "sem senha de A — mais 3 vezes nos últimos 30 s",
                "sem senha de B — mais 1 vez nos últimos 30 s",
            ]
        );
    }

    /// After a window without repeats the next one is a line again (with a
    /// longer window, so a slow loop still ends at one line per 10 min);
    /// after 10 min of silence the group starts over.
    #[test]
    fn a_quiet_group_logs_again_and_is_forgotten() {
        let mut s = Session::virtual_lab();
        s.tick(1_000);
        assert!(login(&mut s, "a", "sem senha de A"));
        s.tick(1_045);
        assert!(login(&mut s, "a", "sem senha de A"), "45 s later, nothing in between");
        s.tick(1_090);
        assert!(!login(&mut s, "a", "sem senha de A"), "the second window is 2 min");
        s.tick(1_165);
        assert_eq!(lines(&s, "mais 1 vez nos últimos 2 min").len(), 1);
        assert_eq!(s.ext::<LogBook>().unwrap().groups.len(), 1);
        // Its 10 min window ends with nothing counted and 10 min of silence.
        s.tick(1_764);
        assert_eq!(s.ext::<LogBook>().unwrap().groups.len(), 1);
        s.tick(1_765);
        assert!(s.ext::<LogBook>().unwrap().groups.is_empty(), "forgotten");
        assert!(login(&mut s, "a", "sem senha de A"));
        s.tick(1_775);
        assert!(!login(&mut s, "a", "sem senha de A"));
        s.tick(1_795);
        assert_eq!(lines(&s, "mais 1 vez nos últimos 30 s").len(), 1, "from the start");
    }

    /// Keys come from the network: the table has a ceiling, and the group
    /// that leaves it says what it had counted.
    #[test]
    fn the_group_table_has_a_ceiling() {
        let mut s = Session::virtual_lab();
        s.execute(
            "system.logging.action.set",
            &json!({"name": "memory", "memory_lines": 5000}),
        )
        .unwrap();
        s.tick(1_000);
        login(&mut s, "first", "sem senha de first");
        login(&mut s, "first", "sem senha de first");
        s.tick(1_001);
        for n in 0..MAX_GROUPS + 50 {
            assert!(login(&mut s, &format!("k{n}"), &format!("sem senha de k{n}")));
        }
        let book = s.ext::<LogBook>().unwrap();
        assert_eq!(book.groups.len(), MAX_GROUPS);
        assert!(!book.groups.contains_key("first"), "the quietest one left");
        assert_eq!(lines(&s, "sem senha de first — mais 1 vez nos últimos 1 s").len(), 1);
        // A hostile key is cut, not kept whole.
        login(&mut s, &"x".repeat(100_000), "sem senha de x");
        let longest = s.ext::<LogBook>().unwrap().groups.keys().map(String::len).max();
        assert!(longest.unwrap() <= MAX_GROUP_KEY + 4, "{longest:?}");
    }

    /// No clock yet (before the first tick): nothing is lost, the repeats
    /// are counted and logged once there is one. A clock that goes back
    /// ends the window instead of holding the count.
    #[test]
    fn grouping_survives_a_missing_or_stepped_clock() {
        let mut s = Session::virtual_lab();
        assert!(login(&mut s, "a", "sem senha de A"));
        assert!(!login(&mut s, "a", "sem senha de A"));
        s.tick(1_700_000_000);
        assert_eq!(lines(&s, "sem senha de A — mais 1 vez").len(), 1);
        assert!(!login(&mut s, "a", "sem senha de A"));
        s.tick(1_000);
        assert_eq!(lines(&s, "sem senha de A — mais 1 vez").len(), 2);
    }

    #[test]
    fn clear_forgets_the_counts() {
        let mut s = Session::virtual_lab();
        s.tick(1_000);
        login(&mut s, "a", "sem senha de A");
        login(&mut s, "a", "sem senha de A");
        s.execute("log.clear", &json!({})).unwrap();
        assert!(login(&mut s, "a", "sem senha de A"), "a line again after the clear");
        s.tick(1_030);
        assert!(lines(&s, "mais").is_empty());
    }

    /// `log.print` shows a count whose window ended even without a tick.
    #[test]
    fn print_logs_the_counts_that_are_due() {
        let mut s = Session::virtual_lab();
        s.tick(1_000);
        login(&mut s, "a", "sem senha de A");
        login(&mut s, "a", "sem senha de A");
        s.safe_mode_mut().clock = Some(1_030);
        let rows = s.execute("log.print", &json!({"find": "sem senha"})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 2, "{rows}");
        assert_eq!(rows[1]["detail"]["repeats"], 1);
    }
}

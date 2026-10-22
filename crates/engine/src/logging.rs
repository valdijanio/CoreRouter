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
//! to remote actions as syslog datagrams (`routes`).

use std::collections::VecDeque;

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

/// The log at run time (`Session::ext`): never saved, gone on restart
/// (writing it to disk is G4.6f).
#[derive(Debug, Default)]
pub struct LogBook {
    seq: u64,
    /// Every event, for the remote forwarder.
    recent: VecDeque<LogEvent>,
    /// What rules sent to `memory`: `log.print`.
    memory: VecDeque<LogEvent>,
}

impl LogBook {
    pub fn memory(&self) -> impl DoubleEndedIterator<Item = &LogEvent> {
        self.memory.iter()
    }
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

/// The message of a journal entry, in Portuguese: what changed, read from
/// the parameters and from `cfg` (the running config after the command).
pub fn journal_message(command: &str, p: &Value, result: &Result<Value>, cfg: &Config) -> String {
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
                    "nenhum servidor".to_owned()
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
        format!("Alterado: {}{sep}{what}", menu_path(command))
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
fn bounded(v: &Value) -> Value {
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
            now.last_error
                .as_deref()
                .map(|e| ("warning", format!("NTP: {}", ntp_error(e))))
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
            } else if lower.contains("no server to ask") {
                return "nenhum servidor configurado".to_owned();
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

impl Session {
    /// Log one event: numbered, timed by the session clock, kept for the
    /// remote forwarder and, when a rule says so, in `memory`.
    pub fn log_event(&mut self, topics: &[&str], origin: &str, message: String, detail: Value) {
        let time = self.now().unwrap_or(0);
        let logging = &self.store().running().system.logging;
        let topics: Vec<String> = topics.iter().map(|t| (*t).to_owned()).collect();
        let keep = logging.to_memory(&topics);
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
            message,
            detail,
        };
        if keep {
            book.memory.push_back(ev.clone());
        }
        while book.memory.len() > lines {
            book.memory.pop_front();
        }
        book.recent.push_back(ev);
        while book.recent.len() > MAX_RECENT {
            book.recent.pop_front();
        }
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

    /// Empty `memory` (`log.clear`); the numbering goes on.
    pub(crate) fn log_clear(&mut self) -> usize {
        self.ext_mut::<LogBook>().map_or(0, |b| {
            let n = b.memory.len();
            b.memory.clear();
            n
        })
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
    ) {
        let topics = journal_topics(command, result.is_ok());
        let topics: Vec<&str> = topics.iter().map(String::as_str).collect();
        let automatic = params.get("automatic").is_some();
        let who = if automatic {
            DAEMON.to_owned()
        } else {
            origin(self.caller())
        };
        let message = journal_message(command, params, result, self.store().running());
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
            journal_message("ip.route.add", &p, &Ok(json!({"id": "*1"})), &cfg),
            "Alterado: /ip route add dst-address=0.0.0.0/0 gateway=10.0.0.1"
        );
        let err = Err(EngineError::bad("gateway", "unreachable"));
        let m = journal_message("ip.route.add", &p, &err, &cfg);
        assert!(m.starts_with("Falhou: /ip route add dst-address="), "{m}");
        assert!(m.contains("unreachable"), "{m}");
        assert_eq!(
            journal_message(
                "ip.address.add",
                &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
                &Ok(Value::Null),
                &cfg
            ),
            "Endereço 10.0.0.1/24 adicionado em ether1"
        );
        let mut on = cfg.clone();
        on.system.ntp_client.enabled = true;
        on.system.ntp_client.servers = vec!["pool.ntp.org".into()];
        assert_eq!(
            journal_message("system.ntp.client.set", &json!({}), &Ok(Value::Null), &on),
            "NTP Client ligado: servidores pool.ntp.org, poll 6–10"
        );
    }

    #[test]
    fn long_params_are_cut_on_a_char_boundary() {
        let p = json!({ "name": "ã".repeat(600) });
        let m = journal_message("system.note.set", &p, &Ok(Value::Null), &Config::default());
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
}

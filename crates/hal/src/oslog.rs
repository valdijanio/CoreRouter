//! The operating system's log (G4.8b): the kernel's (`/dev/kmsg`), the
//! services' and the logins' (the systemd journal), as lines the engine
//! keeps and `log.os.print` shows. Not the router's own log (`log.print`,
//! the engine's events): this is what Linux says under it.
//!
//! Here are the line, the two record parsers and the lab's made-up lines;
//! reading the real files and the `journalctl` process is `hal-linux`'s.
//! Both parsers take hostile input — a record is whatever the kernel or a
//! program wrote — so they cap every field, drop control and bidi
//! characters and never panic (proptest here, fuzz target `oslog`).

use serde::Serialize;
use serde_json::Value;

/// Characters of a message kept; the rest is cut with "…".
pub const MAX_MESSAGE: usize = 2048;
/// Characters of a unit, driver or device name kept.
pub const MAX_UNIT: usize = 64;
/// Bytes of one record read at most (the kernel's own limit for a
/// `/dev/kmsg` record is 8 KiB with its dictionary).
pub const MAX_RECORD: usize = 16 * 1024;
/// Characters of a journal cursor accepted (they are ~130).
pub const MAX_CURSOR: usize = 512;

/// RFC 5424 §6.2.1 severities, 0 (emergency) to 7 (debug).
pub const SEVERITIES: [&str; 8] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
];

/// The severity named `name` (RFC 5424 names, plus the short `emerg`,
/// `crit`, `err` of syslog).
pub fn severity_of(name: &str) -> Option<u8> {
    let n = match name {
        "emerg" | "panic" => "emergency",
        "crit" => "critical",
        "err" => "error",
        "warn" => "warning",
        other => other,
    };
    SEVERITIES
        .iter()
        .position(|s| *s == n)
        .and_then(|i| u8::try_from(i).ok())
}

/// The name of severity `n` (7 and above: debug).
pub fn severity_name(n: u8) -> &'static str {
    SEVERITIES.get(usize::from(n)).copied().unwrap_or("debug")
}

/// Where a line comes from, as the OS Log window groups them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsSource {
    /// The kernel: drivers, the network stack, memory, disks.
    Kernel,
    /// Programs and services (systemd units, daemons).
    Services,
    /// Logins and privileges: sshd, sudo, PAM (syslog facilities 4 and 10).
    Auth,
}

impl OsSource {
    pub const ALL: [Self; 3] = [Self::Kernel, Self::Services, Self::Auth];

    pub fn name(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Services => "services",
            Self::Auth => "auth",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }
}

/// One line of the OS log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsLine {
    /// Wall clock, microseconds since the Unix epoch; 0: unknown.
    pub time_us: u64,
    /// RFC 5424 severity, 0..=7.
    pub severity: u8,
    pub source: OsSource,
    /// The driver (kernel: `r8169`, `nf_conntrack`), the systemd unit or
    /// the program (`sshd`); "" when none.
    pub unit: String,
    /// The device the line is about (`ether1`, `nvme0n1`), when it says.
    pub device: String,
    pub pid: Option<u32>,
    pub message: String,
    /// Boot id (32 hex digits) the line was written in; "" when unknown.
    pub boot: String,
}

/// How a source of the OS log is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceState {
    /// `kmsg`, `journal`, `lab`.
    pub name: String,
    pub ok: bool,
    /// Why it cannot be read, for people: "unavailable: …".
    pub reason: Option<String>,
    /// Lines read from it since the start.
    pub lines: u64,
}

impl SourceState {
    pub fn ok(name: &str, lines: u64) -> Self {
        Self {
            name: name.to_owned(),
            ok: true,
            reason: None,
            lines,
        }
    }

    pub fn unavailable(name: &str, reason: impl Into<String>, lines: u64) -> Self {
        Self {
            name: name.to_owned(),
            ok: false,
            reason: Some(cut(&reason.into(), 300)),
            lines,
        }
    }
}

/// What one read of the OS log gave: the new lines and how each source is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OsLogBatch {
    pub lines: Vec<OsLine>,
    pub sources: Vec<SourceState>,
    /// The boot running now (to tell "this boot" from older ones).
    pub boot: String,
}

/// `s` without control characters (a newline stays, a tab turns into a
/// space) nor bidi overrides, cut at `max` characters with "…".
pub fn clean(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max.saturating_mul(4)));
    let mut n = 0usize;
    for c in s.chars() {
        let c = match c {
            '\t' => ' ',
            '\n' => '\n',
            c if c.is_control() => continue,
            // Bidi embeddings, overrides and isolates (Trojan Source).
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' => {
                continue;
            }
            c => c,
        };
        if n == max {
            out.push('…');
            return out;
        }
        out.push(c);
        n += 1;
    }
    out
}

fn cut(s: &str, max: usize) -> String {
    clean(s, max)
}

/// A whole line read from `/dev/kmsg` (Documentation/ABI/testing/dev-kmsg):
/// `prio,seq,usec,flag[,…];message` and then ` KEY=value` lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRecord {
    /// syslog facility (0: kernel; a program writing to /dev/kmsg: 1).
    pub facility: u8,
    pub severity: u8,
    pub seq: u64,
    /// Microseconds since boot (the kernel's clock, CLOCK_MONOTONIC-like).
    pub since_boot_us: u64,
    /// `c` / `+`: a piece of a line printed in parts.
    pub continuation: bool,
    pub message: String,
    pub subsystem: String,
    pub device: String,
}

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("record too long ({0} bytes)")]
    TooLong(usize),
    #[error("no ';' between the prefix and the message")]
    NoPrefix,
    #[error("bad field '{0}' in the prefix")]
    BadField(&'static str),
    #[error("not JSON: {0}")]
    Json(String),
    #[error("no message")]
    NoMessage,
}

/// Parse one `/dev/kmsg` record (one `read` returns one).
pub fn parse_kmsg(raw: &[u8]) -> Result<KmsgRecord, ParseError> {
    if raw.len() > MAX_RECORD {
        return Err(ParseError::TooLong(raw.len()));
    }
    let semi = raw
        .iter()
        .position(|b| *b == b';')
        .ok_or(ParseError::NoPrefix)?;
    let (prefix, rest) = raw.split_at(semi);
    let rest = rest.get(1..).unwrap_or(&[]);
    let prefix = std::str::from_utf8(prefix).map_err(|_| ParseError::BadField("prefix"))?;
    let mut fields = prefix.split(',');
    let prio: u32 = fields
        .next()
        .and_then(|f| f.trim().parse().ok())
        .ok_or(ParseError::BadField("priority"))?;
    let seq: u64 = fields
        .next()
        .and_then(|f| f.parse().ok())
        .ok_or(ParseError::BadField("sequence"))?;
    let since_boot_us: u64 = fields
        .next()
        .and_then(|f| f.parse().ok())
        .ok_or(ParseError::BadField("timestamp"))?;
    let flag = fields.next().unwrap_or("-");
    // The facility is up to 2^28; more is not a syslog prefix.
    let facility = u8::try_from((prio >> 3).min(255)).unwrap_or(255);
    let severity = u8::try_from(prio & 7).unwrap_or(7);
    // Message up to the newline; the dictionary after it.
    let (msg, dict) = match rest.iter().position(|b| *b == b'\n') {
        Some(i) => (
            rest.get(..i).unwrap_or(&[]),
            rest.get(i + 1..).unwrap_or(&[]),
        ),
        None => (rest, &[][..]),
    };
    let mut subsystem = String::new();
    let mut device = String::new();
    for line in dict.split(|b| *b == b'\n') {
        let Some(kv) = line.strip_prefix(b" ") else {
            continue;
        };
        let kv = unescape(kv);
        if let Some(v) = kv.strip_prefix("SUBSYSTEM=") {
            subsystem = clean(v, MAX_UNIT);
        } else if let Some(v) = kv.strip_prefix("DEVICE=") {
            device = clean(v, MAX_UNIT);
        }
    }
    Ok(KmsgRecord {
        facility,
        severity,
        seq,
        since_boot_us,
        continuation: matches!(flag, "c" | "+"),
        message: clean(&unescape(msg), MAX_MESSAGE),
        subsystem,
        device,
    })
}

/// The kernel writes a byte it would not print as `\xNN` (and `\` as
/// `\x5c`); undo that, then read the bytes as UTF-8 (lossy).
fn unescape(raw: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut i = 0usize;
    while let Some(&b) = raw.get(i) {
        if b == b'\\'
            && raw.get(i + 1) == Some(&b'x')
            && let (Some(h), Some(l)) = (
                raw.get(i + 2).and_then(|c| hex(*c)),
                raw.get(i + 3).and_then(|c| hex(*c)),
            )
        {
            bytes.push(h << 4 | l);
            i += 4;
            continue;
        }
        bytes.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// What the start of a kernel message says about who wrote it:
/// `r8169 0000:02:00.0 ether1: Link is Down` → (`r8169`, `ether1`);
/// `nf_conntrack: table full` → (`nf_conntrack`, ""); `EXT4-fs (sda1):` →
/// (`EXT4-fs`, `sda1`); `sshd[812]: segfault at …` → (`sshd`, "", 812).
pub fn kernel_origin(message: &str) -> (String, String, Option<u32>) {
    let first = message.lines().next().unwrap_or("");
    let Some(colon) = first.find(": ") else {
        return (String::new(), String::new(), None);
    };
    let Some(prefix) = first.get(..colon).filter(|p| p.len() <= 96) else {
        return (String::new(), String::new(), None);
    };
    let tokens: Vec<&str> = prefix.split_whitespace().collect();
    let Some(head) = tokens.first() else {
        return (String::new(), String::new(), None);
    };
    // `comm[pid]`
    if tokens.len() == 1
        && let Some(open) = head.rfind('[')
        && let Some(pid) = head
            .get(open + 1..)
            .and_then(|p| p.strip_suffix(']'))
            .and_then(|p| p.parse::<u32>().ok())
    {
        return (
            clean(head.get(..open).unwrap_or(""), MAX_UNIT),
            String::new(),
            Some(pid),
        );
    }
    let name = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    };
    fn bare(t: &str) -> &str {
        t.trim_matches(|c| c == '(' || c == ')')
    }
    let device = match tokens.as_slice() {
        // driver bus-id netdev (netdev_printk): the bus id has ':' or '.'.
        [_, bus, dev] if bus.contains([':', '.']) && name(bare(dev)) => bare(dev),
        // `EXT4-fs (sda1)`, `usb 7-1.2`, `nvme nvme0`: a device has a digit.
        [_, dev] if dev.contains(|c: char| c.is_ascii_digit()) && name(bare(dev)) => bare(dev),
        [_] => "",
        // Words, not a driver: `Out of memory: Killed process …`.
        _ => return (String::new(), String::new(), None),
    };
    if !name(head) {
        return (String::new(), String::new(), None);
    }
    (clean(head, MAX_UNIT), clean(device, MAX_UNIT), None)
}

/// syslog facilities of logins and privileges (auth, authpriv).
const AUTH_FACILITIES: [u8; 2] = [4, 10];
/// Programs whose lines are about logins even when they log elsewhere.
const AUTH_PROGRAMS: &[&str] = &[
    "login",
    "polkitd",
    "sshd",
    "su",
    "sudo",
    "systemd-logind",
    "unix_chkpwd",
];

/// The source of a line from the journal or syslog.
pub fn source_of(transport: &str, facility: Option<u8>, program: &str) -> OsSource {
    if transport == "kernel" {
        OsSource::Kernel
    } else if facility.is_some_and(|f| AUTH_FACILITIES.contains(&f))
        || AUTH_PROGRAMS.contains(&program)
    {
        OsSource::Auth
    } else {
        OsSource::Services
    }
}

/// The OS line of a kernel record; `boot_realtime_us` is the wall clock
/// at boot (0: unknown, the line has no time).
pub fn kmsg_line(r: &KmsgRecord, boot_realtime_us: u64, boot: &str) -> OsLine {
    let (unit, dev, pid) = kernel_origin(&r.message);
    let source = if r.facility == 0 {
        OsSource::Kernel
    } else {
        source_of("syslog", Some(r.facility), &unit)
    };
    OsLine {
        time_us: if boot_realtime_us == 0 {
            0
        } else {
            boot_realtime_us.saturating_add(r.since_boot_us)
        },
        severity: r.severity,
        source,
        unit: if unit.is_empty() {
            r.subsystem.clone()
        } else {
            unit
        },
        device: dev,
        pid,
        message: r.message.clone(),
        boot: boot.to_owned(),
    }
}

/// One entry of `journalctl -o json`, with its cursor (to go on after it)
/// and its transport (`kernel`, `syslog`, `journal`, `stdout`, `audit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub line: OsLine,
    pub cursor: String,
    pub transport: String,
}

/// A field's text: a string, the first string of a repeated field, or a
/// byte array (journalctl sends a value that is not UTF-8 so).
fn field(v: &Value, key: &str, max: usize) -> String {
    match v.get(key) {
        Some(Value::String(s)) => clean(s, max),
        Some(Value::Array(items)) => {
            if items.iter().all(Value::is_u64) {
                let bytes: Vec<u8> = items
                    .iter()
                    .take(MAX_RECORD)
                    .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                    .collect();
                clean(&String::from_utf8_lossy(&bytes), max)
            } else {
                items
                    .iter()
                    .find_map(Value::as_str)
                    .map(|s| clean(s, max))
                    .unwrap_or_default()
            }
        }
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Parse one line of `journalctl -o json`.
pub fn parse_journal(line: &str) -> Result<JournalEntry, ParseError> {
    if line.len() > MAX_RECORD * 4 {
        return Err(ParseError::TooLong(line.len()));
    }
    let v: Value =
        serde_json::from_str(line).map_err(|e| ParseError::Json(cut(&e.to_string(), 80)))?;
    if !v.is_object() {
        return Err(ParseError::Json("not an object".into()));
    }
    let message = field(&v, "MESSAGE", MAX_MESSAGE);
    if message.is_empty() && v.get("MESSAGE").is_none() {
        return Err(ParseError::NoMessage);
    }
    let num = |k: &str| field(&v, k, 24).trim().parse::<u64>().ok();
    let transport = field(&v, "_TRANSPORT", 16);
    let facility = num("SYSLOG_FACILITY").and_then(|f| u8::try_from(f).ok());
    let program = {
        let id = field(&v, "SYSLOG_IDENTIFIER", MAX_UNIT);
        if id.is_empty() {
            field(&v, "_COMM", MAX_UNIT)
        } else {
            id
        }
    };
    let source = source_of(&transport, facility, &program);
    let (unit, device, kpid) = if source == OsSource::Kernel {
        kernel_origin(&message)
    } else {
        let unit = field(&v, "_SYSTEMD_UNIT", MAX_UNIT);
        (
            if program.is_empty() { unit } else { program },
            String::new(),
            None,
        )
    };
    let cursor = field(&v, "__CURSOR", MAX_CURSOR + 1);
    let boot = field(&v, "_BOOT_ID", 40);
    Ok(JournalEntry {
        line: OsLine {
            time_us: num("__REALTIME_TIMESTAMP").unwrap_or(0),
            severity: num("PRIORITY")
                .and_then(|p| u8::try_from(p.min(7)).ok())
                .unwrap_or(6),
            source,
            unit,
            device,
            pid: kpid.or_else(|| num("_PID").and_then(|p| u32::try_from(p).ok())),
            message,
            boot: if boot.chars().all(|c| c.is_ascii_hexdigit()) {
                boot
            } else {
                String::new()
            },
        },
        cursor: if valid_cursor(&cursor) {
            cursor
        } else {
            String::new()
        },
        transport,
    })
}

/// A cursor safe to hand back to journalctl as an argument: printable
/// ASCII without spaces, at most [`MAX_CURSOR`] characters.
pub fn valid_cursor(c: &str) -> bool {
    !c.is_empty() && c.len() <= MAX_CURSOR && c.bytes().all(|b| b.is_ascii_graphic())
}

/// The lab's OS log: a made-up router's kernel, services and logins, so
/// the OS Log window has something real-looking to show without a host.
/// The first read gives the boot and an afternoon of trouble (a NIC whose
/// ring fills, a flapping link, a full conntrack table, an OOM kill, SSH
/// guesses); every fifth read after it the NIC drops frames again.
#[derive(Debug, Clone, Default)]
pub struct LabOsLog {
    reads: u64,
    lines: u64,
}

/// The lab's boot id.
pub const LAB_BOOT: &str = "1ab0b007c0de4c0ffee0000000000001";
/// The wall clock the lab's lines hang on when the session has none
/// (2026-10-24 12:00:00 UTC).
const LAB_EPOCH: u64 = 1_792_843_200;

impl LabOsLog {
    /// The lines since the last read, `now` being the session's clock.
    pub fn read(&mut self, now: Option<u64>, max: usize) -> OsLogBatch {
        let now = now.unwrap_or(LAB_EPOCH);
        let reads = self.reads;
        self.reads = self.reads.saturating_add(1);
        let mut lines = Vec::new();
        if reads == 0 {
            lines = lab_seed(now);
        } else if reads.is_multiple_of(5) {
            lines.push(lab(
                now,
                0,
                4,
                OsSource::Kernel,
                "r8169",
                "ether2",
                None,
                "r8169 0000:03:00.0 ether2: rx_missed 1 (ring full, frame dropped)",
            ));
        }
        lines.truncate(max);
        self.lines = self.lines.saturating_add(lines.len() as u64);
        OsLogBatch {
            lines,
            sources: vec![SourceState::ok("lab", self.lines)],
            boot: LAB_BOOT.to_owned(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn lab(
    now: u64,
    ago_secs: u64,
    severity: u8,
    source: OsSource,
    unit: &str,
    device: &str,
    pid: Option<u32>,
    message: &str,
) -> OsLine {
    OsLine {
        time_us: now.saturating_sub(ago_secs).saturating_mul(1_000_000),
        severity,
        source,
        unit: unit.to_owned(),
        device: device.to_owned(),
        pid,
        message: message.to_owned(),
        boot: LAB_BOOT.to_owned(),
    }
}

/// The lab's first lines, oldest first.
fn lab_seed(now: u64) -> Vec<OsLine> {
    use OsSource::{Auth, Kernel, Services};
    let k = Kernel;
    let mut v = vec![
        lab(
            now,
            7200,
            5,
            k,
            "",
            "",
            None,
            "Linux version 6.8.0-corerouter (gcc 13.2) #1 SMP PREEMPT_DYNAMIC",
        ),
        lab(
            now,
            7199,
            6,
            k,
            "r8169",
            "ether1",
            None,
            "r8169 0000:02:00.0 ether1: RTL8125B, 02:00:5e:00:53:01, XID 641, IRQ 49",
        ),
        lab(
            now,
            7199,
            6,
            k,
            "r8169",
            "ether2",
            None,
            "r8169 0000:03:00.0 ether2: RTL8125B, 02:00:5e:00:53:02, XID 641, IRQ 50",
        ),
        lab(
            now,
            7198,
            6,
            k,
            "nvme",
            "nvme0",
            None,
            "nvme nvme0: 8/0/0 default/read/poll queues",
        ),
        lab(
            now,
            7190,
            6,
            Services,
            "systemd",
            "",
            Some(1),
            "Started corerouter.service - CoreRouter daemon.",
        ),
        lab(
            now,
            7189,
            6,
            Services,
            "corerouter",
            "",
            Some(412),
            "control channel listening on 127.0.0.1:7979",
        ),
        lab(
            now,
            7188,
            6,
            k,
            "r8169",
            "ether1",
            None,
            "r8169 0000:02:00.0 ether1: Link is Up - 1Gbps/Full - flow control rx/tx",
        ),
        lab(
            now,
            7188,
            6,
            k,
            "r8169",
            "ether2",
            None,
            "r8169 0000:03:00.0 ether2: Link is Up - 1Gbps/Full - flow control rx/tx",
        ),
        lab(
            now,
            5400,
            6,
            Auth,
            "sshd",
            "",
            Some(733),
            "Accepted publickey for admin from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:lab",
        ),
    ];
    // Nine minutes of drops on ether2, up to a minute ago: the ring is
    // full (37 times).
    for i in 0..37u64 {
        v.push(lab(
            now,
            600 - i * 15,
            4,
            k,
            "r8169",
            "ether2",
            None,
            "r8169 0000:03:00.0 ether2: rx_missed 1 (ring full, frame dropped)",
        ));
    }
    v.extend([
        lab(now, 3000, 6, k, "r8169", "ether3", None, "r8169 0000:04:00.0 ether3: Link is Down"),
        lab(now, 2990, 6, k, "r8169", "ether3", None, "r8169 0000:04:00.0 ether3: Link is Up - 100Mbps/Full - flow control off"),
        lab(now, 2400, 4, k, "nf_conntrack", "", None, "nf_conntrack: nf_conntrack: table full, dropping packet"),
        lab(now, 2390, 4, k, "nf_conntrack", "", None, "nf_conntrack: nf_conntrack: table full, dropping packet"),
        lab(now, 1800, 3, k, "", "", Some(2211), "Out of memory: Killed process 2211 (unbound) total-vm:812344kB, anon-rss:602112kB, file-rss:0kB"),
        lab(now, 1799, 4, Services, "systemd", "", Some(1), "unbound.service: A process of this unit has been killed by the OOM killer."),
        lab(now, 1200, 5, Auth, "sshd", "", Some(901), "Failed password for invalid user admin from 203.0.113.77 port 41234 ssh2"),
        lab(now, 1190, 5, Auth, "sshd", "", Some(902), "Failed password for invalid user admin from 203.0.113.77 port 41240 ssh2"),
        lab(now, 600, 4, k, "TCP", "", None, "TCP: request_sock_TCP: Possible SYN flooding on port 0.0.0.0:443. Sending cookies."),
        lab(now, 300, 6, Services, "corerouter", "", Some(412), "dhcp-server: 128 leases, pool lan 50% used"),
    ]);
    v.sort_by_key(|l| l.time_us);
    v
}

/// The fuzz target `oslog`'s oracle (docs/fuzzing.md): the bytes as one
/// `/dev/kmsg` record and as one journal line never panic, and what parses
/// keeps the limits (severity 0..=7, capped message without control or bidi
/// characters, a cursor safe to hand back to journalctl or none).
pub fn fuzz_check(data: &[u8]) -> Result<(), String> {
    let ok_text = |m: &str| {
        m.chars().count() <= MAX_MESSAGE + 1
            && !m
                .chars()
                .any(|c| (c.is_control() && c != '\n') || ('\u{202A}'..='\u{202E}').contains(&c))
    };
    if let Ok(r) = parse_kmsg(data) {
        if r.severity > 7 || !ok_text(&r.message) {
            return Err(format!("kmsg record out of bounds: {r:?}"));
        }
        let l = kmsg_line(&r, u64::MAX, "");
        if l.unit.chars().count() > MAX_UNIT + 1 {
            return Err(format!("unit too long: {}", l.unit));
        }
    }
    if let Ok(e) = parse_journal(&String::from_utf8_lossy(data)) {
        if e.line.severity > 7 || !ok_text(&e.line.message) {
            return Err(format!("journal entry out of bounds: {e:?}"));
        }
        if !e.cursor.is_empty() && !valid_cursor(&e.cursor) {
            return Err(format!("unsafe cursor kept: {:?}", e.cursor));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KMSG: &str = include_str!("../tests/fixtures/oslog/kmsg.txt");
    const JOURNAL: &str = include_str!("../tests/fixtures/oslog/journal.jsonl");
    const JOURNAL_ODD: &str = include_str!("../tests/fixtures/oslog/journal-odd.jsonl");

    /// Odd and truncated journal lines: `ok`/`err` and the line.
    #[test]
    fn odd_journal_fixture_lines() {
        let mut n = 0;
        for l in JOURNAL_ODD.lines() {
            let (want, line) = l.split_once('\t').unwrap();
            let got = parse_journal(line);
            assert_eq!(got.is_ok(), want == "ok", "{line}: {got:?}");
            if let Ok(e) = got {
                assert!(e.line.severity <= 7);
                assert!(e.line.message.chars().count() <= MAX_MESSAGE + 1);
                assert!(!e.line.message.contains(['\u{202E}', '\u{7}']));
                assert!(
                    e.line.boot.is_empty() || e.line.boot.chars().all(|c| c.is_ascii_hexdigit())
                );
                assert!(e.cursor.is_empty() || valid_cursor(&e.cursor));
            }
            fuzz_check(line.as_bytes()).unwrap();
            n += 1;
        }
        assert!(n >= 10);
    }

    /// Kinds of message the fixtures must cover (the catalogue's cases).
    #[test]
    fn fixtures_cover_the_known_kinds() {
        for needle in [
            "rx_missed",
            "I/O error",
            "Out of memory",
            "Link is Down",
            "Machine check",
            "throttled",
            "table full",
            "segfault",
            "CRON",
            "Failed password",
            "\n SUBSYSTEM=",
        ] {
            assert!(
                JOURNAL.contains(needle) || KMSG.contains(needle),
                "{needle}"
            );
        }
    }

    /// The fixture's records: a line and its ` KEY=value` lines.
    fn kmsg_records() -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in KMSG.lines().filter(|l| !l.starts_with('#')) {
            match out.last_mut() {
                Some(last) if l.starts_with(' ') => {
                    last.push('\n');
                    last.push_str(l);
                }
                _ => out.push(l.to_owned()),
            }
        }
        out
    }

    #[test]
    fn every_fixture_kmsg_record_parses() {
        let recs = kmsg_records();
        assert!(recs.len() > 60, "{}", recs.len());
        assert!(
            recs.iter().any(|r| r.contains("\n SUBSYSTEM=")),
            "a record with its dictionary"
        );
        for r in &recs {
            let k = parse_kmsg(r.as_bytes()).unwrap_or_else(|e| panic!("{e}: {r}"));
            assert!(k.severity <= 7 && !k.message.is_empty(), "{r}");
        }
    }

    #[test]
    fn kmsg_fields_and_dictionary() {
        let r = parse_kmsg(
            b"6,5012,812345678901,-;usb 7-1.2: reset high-speed USB device number 4 using xhci_hcd\n SUBSYSTEM=usb\n DEVICE=c189:2\n",
        )
        .unwrap();
        assert_eq!((r.facility, r.severity, r.seq), (0, 6, 5012));
        assert_eq!(r.since_boot_us, 812_345_678_901);
        assert_eq!(r.subsystem, "usb");
        assert_eq!(r.device, "c189:2");
        assert!(!r.continuation);
        let line = kmsg_line(&r, 1_000_000, "b");
        assert_eq!(line.time_us, 812_346_678_901);
        assert_eq!((line.unit.as_str(), line.device.as_str()), ("usb", "7-1.2"));
        // A program writing to /dev/kmsg: facility user (1).
        let u = parse_kmsg(b"14,7,10,-;systemd[1]: Started x").unwrap();
        assert_eq!((u.facility, u.severity), (1, 6));
        assert_eq!(kmsg_line(&u, 0, "").source, OsSource::Services);
        assert_eq!(kmsg_line(&u, 0, "").time_us, 0, "no clock, no time");
        // Extra prefix fields (caller=) and the continuation flag.
        let c = parse_kmsg(b"4,9,11,c,caller=T12;tail").unwrap();
        assert!(c.continuation);
        assert_eq!(c.message, "tail");
    }

    #[test]
    fn kmsg_escapes_and_hostile_bytes() {
        // `\x5c` is a backslash; `\x1b` (ESC) is dropped after unescaping.
        let r = parse_kmsg(b"3,1,2,-;a\\x5cb \\x1b[31mred \\xe2\\x80\\xae bidi").unwrap();
        assert_eq!(r.message, "a\\b [31mred  bidi");
        // Not hex, or cut short: left as written.
        assert_eq!(
            parse_kmsg(b"3,1,2,-;\\xZZ \\x4").unwrap().message,
            "\\xZZ \\x4"
        );
        // Invalid UTF-8: replaced, not refused.
        assert_eq!(
            parse_kmsg(b"3,1,2,-;\xff ok").unwrap().message,
            "\u{FFFD} ok"
        );
    }

    #[test]
    fn kmsg_odd_and_truncated_input() {
        for bad in [
            &b""[..],
            b"6,1,2",
            b";msg",
            b"x,1,2,-;m",
            b"6,,2,-;m",
            b"6,1,,-;m",
            b"6,1,-5,-;m",
            b"6,99999999999999999999999,1,-;m",
            b"\xff,1,2,-;m",
        ] {
            assert!(
                parse_kmsg(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(
            parse_kmsg(&vec![b'a'; MAX_RECORD + 1]),
            Err(ParseError::TooLong(MAX_RECORD + 1))
        );
        // Huge priority: facility capped, severity still 0..7.
        let r = parse_kmsg(b"4294967295,1,2,-;m").unwrap();
        assert_eq!((r.facility, r.severity), (255, 7));
        // An empty message parses (and is empty).
        assert_eq!(parse_kmsg(b"6,1,2,-;").unwrap().message, "");
        // A long message is cut.
        let long = format!("6,1,2,-;{}", "x".repeat(MAX_MESSAGE + 50));
        let m = parse_kmsg(long.as_bytes()).unwrap().message;
        assert_eq!(m.chars().count(), MAX_MESSAGE + 1);
        assert!(m.ends_with('…'));
    }

    #[test]
    fn kernel_origin_of_real_prefixes() {
        let cases = [
            (
                "r8169 0000:02:00.0 ether1: Link is Down",
                ("r8169", "ether1", None),
            ),
            (
                "nf_conntrack: table full, dropping packet",
                ("nf_conntrack", "", None),
            ),
            (
                "EXT4-fs (nvme0n1p7): mounted filesystem",
                ("EXT4-fs", "nvme0n1p7", None),
            ),
            (
                "nvme nvme0: using unchecked data buffer",
                ("nvme", "nvme0", None),
            ),
            (
                "dnsmasq[4242]: segfault at 0 ip 0",
                ("dnsmasq", "", Some(4242)),
            ),
            (
                "TCP: request_sock_TCP: Possible SYN flooding",
                ("TCP", "", None),
            ),
            ("b1bond: Warning: No 802.3ad response", ("b1bond", "", None)),
            ("Linux version 6.8", ("", "", None)),
            ("", ("", "", None)),
            ("[x]: y", ("", "", None)),
            (
                "Out of memory: Killed process 2211 (unbound)",
                ("", "", None),
            ),
            ("usb 7-1.2: reset", ("usb", "7-1.2", None)),
            ("Freeing unused: x", ("", "", None)),
        ];
        for (msg, (unit, dev, pid)) in cases {
            let (u, d, p) = kernel_origin(msg);
            assert_eq!((u.as_str(), d.as_str(), p), (unit, dev, pid), "{msg}");
        }
    }

    #[test]
    fn every_fixture_journal_entry_parses() {
        let mut sources = std::collections::BTreeSet::new();
        let mut n = 0;
        for l in JOURNAL.lines() {
            let e = parse_journal(l).unwrap_or_else(|err| panic!("{err}: {l}"));
            assert!(valid_cursor(&e.cursor), "{l}");
            assert_eq!(e.line.boot.len(), 32);
            assert!(e.line.time_us > 1_700_000_000_000_000);
            sources.insert(e.line.source);
            n += 1;
        }
        assert!(n > 100, "{n}");
        assert_eq!(
            sources.len(),
            3,
            "kernel, services and auth all in the fixture"
        );
    }

    #[test]
    fn journal_fields() {
        let e = parse_journal(
            r#"{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1792800000000000","_BOOT_ID":"1ab0b007c0de4c0ffee00000000000b1","PRIORITY":"5","SYSLOG_FACILITY":"10","SYSLOG_IDENTIFIER":"sudo","_PID":"4321","_TRANSPORT":"syslog","MESSAGE":"pam_unix(sudo:session): session opened"}"#,
        )
        .unwrap();
        assert_eq!(e.line.source, OsSource::Auth);
        assert_eq!((e.line.severity, e.line.pid), (5, Some(4321)));
        assert_eq!(e.line.unit, "sudo");
        assert_eq!(e.cursor, "s=1;i=2");
        // Kernel through the journal: the driver comes from the message.
        let k = parse_journal(
            r#"{"_TRANSPORT":"kernel","PRIORITY":"6","MESSAGE":"r8169 0000:02:00.0 eno1: Link is Up - 1Gbps/Full"}"#,
        )
        .unwrap();
        assert_eq!(
            (k.line.source, k.line.unit.as_str(), k.line.device.as_str()),
            (OsSource::Kernel, "r8169", "eno1")
        );
        // A unit without identifier; a repeated field; a byte-array message.
        let s = parse_journal(
            r#"{"_SYSTEMD_UNIT":"unbound.service","_PID":["7","8"],"MESSAGE":[104,105,255]}"#,
        )
        .unwrap();
        assert_eq!(s.line.unit, "unbound.service");
        assert_eq!(s.line.message, "hi\u{FFFD}");
        assert_eq!(s.line.pid, Some(7), "a repeated field: its first value");
        assert_eq!(s.line.severity, 6, "no PRIORITY: info");
        assert_eq!(s.cursor, "");
    }

    #[test]
    fn journal_odd_and_truncated_input() {
        for bad in [
            "",
            "{",
            "[]",
            "1",
            "null",
            r#"{"PRIORITY":"3"}"#,
            "{\"MESSAGE\":\"x\"",
            "\u{0}",
        ] {
            assert!(parse_journal(bad).is_err(), "{bad:?}");
        }
        // Wrong types do not fail the line: they are left out.
        let e = parse_journal(
            r#"{"MESSAGE":null,"PRIORITY":"99","__REALTIME_TIMESTAMP":"-1","_PID":"x","_BOOT_ID":"../../etc","__CURSOR":"a b\nc"}"#,
        )
        .unwrap();
        assert_eq!(e.line.message, "");
        assert_eq!(e.line.severity, 7);
        assert_eq!((e.line.time_us, e.line.pid), (0, None));
        assert_eq!(e.line.boot, "");
        assert_eq!(
            e.cursor, "",
            "a cursor with spaces never goes back to journalctl"
        );
        assert!(!valid_cursor(&"a".repeat(MAX_CURSOR + 1)));
    }

    #[test]
    fn severities_follow_rfc5424() {
        // RFC 5424 §6.2.1, table 2.
        assert_eq!(severity_of("emergency"), Some(0));
        assert_eq!(severity_of("err"), Some(3));
        assert_eq!(severity_of("warning"), Some(4));
        assert_eq!(severity_of("debug"), Some(7));
        assert_eq!(severity_of("loud"), None);
        assert_eq!(severity_name(5), "notice");
        assert_eq!(severity_name(200), "debug");
    }

    #[test]
    fn clean_drops_controls_and_bidi() {
        assert_eq!(clean("a\u{202E}b\u{7}c\td\ne", 100), "abc d\ne");
        assert_eq!(clean("ábcd", 2), "áb…");
    }

    #[test]
    fn lab_log_seeds_then_repeats() {
        let mut lab = LabOsLog::default();
        let first = lab.read(Some(1_000_000), 10_000);
        assert!(first.lines.len() > 50);
        assert!(
            first
                .lines
                .windows(2)
                .all(|w| w.first().map(|l| l.time_us) <= w.get(1).map(|l| l.time_us))
        );
        assert_eq!(first.sources.first().map(|s| s.ok), Some(true));
        let mut more = 0;
        for _ in 0..10 {
            more += lab.read(Some(1_000_010), 10).lines.len();
        }
        assert_eq!(more, 2, "every fifth read: one more drop");
        assert!(lab.read(None, 0).lines.is_empty());
    }

    #[test]
    fn fixtures_pass_the_fuzz_oracle() {
        for r in kmsg_records() {
            fuzz_check(r.as_bytes()).unwrap();
        }
        for l in JOURNAL.lines() {
            fuzz_check(l.as_bytes()).unwrap();
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]
        #[test]
        fn fuzz_oracle_holds(raw in proptest::collection::vec(any::<u8>(), 0..400)) {
            prop_assert!(fuzz_check(&raw).is_ok());
        }

        #[test]
        fn kmsg_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(r) = parse_kmsg(&raw) {
                prop_assert!(r.severity <= 7);
                prop_assert!(r.message.chars().count() <= MAX_MESSAGE + 1);
                prop_assert!(!r.message.chars().any(|c| c.is_control() && c != '\n'));
                let _ = kmsg_line(&r, u64::MAX, "");
            }
        }

        #[test]
        fn kmsg_prefix_round_trip(prio in 0u32..2048, seq in any::<u64>(), ts in any::<u64>(), msg in "[ -~]{0,80}") {
            let raw = format!("{prio},{seq},{ts},-;{msg}");
            let r = parse_kmsg(raw.as_bytes()).unwrap();
            prop_assert_eq!(u32::from(r.severity), prio & 7);
            prop_assert_eq!((r.seq, r.since_boot_us), (seq, ts));
        }

        #[test]
        fn journal_never_panics(s in ".{0,300}") {
            if let Ok(e) = parse_journal(&s) {
                prop_assert!(e.line.severity <= 7);
                prop_assert!(e.cursor.is_empty() || valid_cursor(&e.cursor));
            }
        }

        #[test]
        fn journal_objects_never_panic(msg in ".{0,100}", prio in ".{0,4}", pid in ".{0,8}", t in ".{0,4}") {
            let v = serde_json::json!({"MESSAGE": msg, "PRIORITY": prio, "_PID": pid, "_TRANSPORT": t});
            let e = parse_journal(&v.to_string()).unwrap();
            prop_assert!(e.line.severity <= 7);
        }
    }
}

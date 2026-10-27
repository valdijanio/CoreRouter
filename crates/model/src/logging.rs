//! `/system logging` (G4.6): rules that send log events with some topics
//! to an action, and the remote (syslog) actions they name.
//!
//! As in RouterOS, an event carries topics (`system,info`, `ntp,warning`)
//! and a rule matches when the event has every topic of the rule and none
//! of its `!`-negated ones. Action targets: `remote` (syslog over UDP,
//! RFC 5424 + RFC 5426) and the built-in `memory` (the router's own log,
//! `log.print`; G4.6d), which keeps the last [`Logging::memory_lines`],
//! and the built-in `analytics` (G4.4f), the `logs` table of the external
//! ClickHouse (`system.analytics`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::{ItemId, ParseError};

pub const MAX_ACTIONS: usize = 16;
pub const MAX_RULES: usize = 64;
pub const MAX_TOPICS: usize = 16;
pub const MAX_NAME: usize = 32;
pub const MAX_PREFIX: usize = 64;
/// RFC 5426 §3.3: syslog over UDP goes to port 514 unless configured.
pub const DEFAULT_PORT: u16 = 514;
/// The built-in action of the router's own log (RouterOS `memory`): always
/// there, never in [`Logging::actions`], cannot be removed.
pub const MEMORY_ACTION: &str = "memory";
/// The built-in action of the ClickHouse exporter (G4.4f): like
/// [`MEMORY_ACTION`], always there and never in [`Logging::actions`].
pub const ANALYTICS_ACTION: &str = "analytics";
/// RouterOS `memory-lines` default and range.
pub const DEFAULT_MEMORY_LINES: u32 = 1000;
pub const MAX_MEMORY_LINES: u32 = 65_535;

/// Topics an event can carry. Rules may only name these, so a typo cannot
/// make a rule that never matches.
pub const TOPICS: &[&str] = &[
    "account",
    "arp",
    "cgnat",
    "critical",
    "debug",
    "dhcp",
    "dns",
    "error",
    "firewall",
    "info",
    "interface",
    "ntp",
    "ppp",
    "radius",
    "route",
    "system",
    "tool",
    "warning",
];

/// Topics that say how bad, not what (RouterOS levels), mildest first.
pub const LEVELS: &[&str] = &["debug", "info", "warning", "error", "critical"];

/// RFC 5424 §6.2.1, Table 1, with RouterOS' names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Facility {
    Kern,
    User,
    Mail,
    #[default]
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Ntp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl Facility {
    pub const ALL: [Facility; 21] = [
        Self::Kern,
        Self::User,
        Self::Mail,
        Self::Daemon,
        Self::Auth,
        Self::Syslog,
        Self::Lpr,
        Self::News,
        Self::Uucp,
        Self::Cron,
        Self::Authpriv,
        Self::Ftp,
        Self::Ntp,
        Self::Local0,
        Self::Local1,
        Self::Local2,
        Self::Local3,
        Self::Local4,
        Self::Local5,
        Self::Local6,
        Self::Local7,
    ];

    /// Numeric code (RFC 5424 Table 1; `authpriv` is 10, `ntp` 12).
    pub fn code(self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Authpriv => 10,
            Self::Ftp => 11,
            Self::Ntp => 12,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kern => "kern",
            Self::User => "user",
            Self::Mail => "mail",
            Self::Daemon => "daemon",
            Self::Auth => "auth",
            Self::Syslog => "syslog",
            Self::Lpr => "lpr",
            Self::News => "news",
            Self::Uucp => "uucp",
            Self::Cron => "cron",
            Self::Authpriv => "authpriv",
            Self::Ftp => "ftp",
            Self::Ntp => "ntp",
            Self::Local0 => "local0",
            Self::Local1 => "local1",
            Self::Local2 => "local2",
            Self::Local3 => "local3",
            Self::Local4 => "local4",
            Self::Local5 => "local5",
            Self::Local6 => "local6",
            Self::Local7 => "local7",
        }
    }
}

impl FromStr for Facility {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        Self::ALL
            .into_iter()
            .find(|f| f.as_str().eq_ignore_ascii_case(t))
            .ok_or_else(|| ParseError::new("syslog_facility", s, "expected kern, user, mail, daemon, auth, syslog, lpr, news, uucp, cron, authpriv, ftp, ntp or local0..local7"))
    }
}

/// RFC 5424 §6.2.1, Table 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

impl Severity {
    pub const ALL: [Severity; 8] = [
        Self::Emergency,
        Self::Alert,
        Self::Critical,
        Self::Error,
        Self::Warning,
        Self::Notice,
        Self::Info,
        Self::Debug,
    ];

    pub fn code(self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Alert => "alert",
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    /// RouterOS `syslog-severity=auto`: from the event's topics.
    pub fn of_topics(topics: &[String]) -> Self {
        let has = |t: &str| topics.iter().any(|x| x == t);
        if has("critical") {
            Self::Critical
        } else if has("error") {
            Self::Error
        } else if has("warning") {
            Self::Warning
        } else if has("debug") {
            Self::Debug
        } else {
            Self::Info
        }
    }
}

/// `syslog_severity` of an action: fixed, or `auto` (from the topics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityChoice {
    #[default]
    Auto,
    #[serde(untagged)]
    Fixed(Severity),
}

impl SeverityChoice {
    pub fn resolve(self, topics: &[String]) -> Severity {
        match self {
            Self::Auto => Severity::of_topics(topics),
            Self::Fixed(s) => s,
        }
    }
}

impl fmt::Display for SeverityChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Fixed(s) => f.write_str(s.as_str()),
        }
    }
}

impl FromStr for SeverityChoice {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        Severity::ALL
            .into_iter()
            .find(|v| v.as_str().eq_ignore_ascii_case(t))
            .map(Self::Fixed)
            .ok_or_else(|| ParseError::new("syslog_severity", s, "expected auto, emergency, alert, critical, error, warning, notice, info or debug"))
    }
}

/// A remote action (RouterOS `/system logging action … target=remote`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogAction {
    pub name: String,
    pub remote: IpAddr,
    #[serde(default = "default_port")]
    pub remote_port: u16,
    /// Source address of the datagrams (`None`: the kernel picks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_address: Option<IpAddr>,
    #[serde(default)]
    pub syslog_facility: Facility,
    #[serde(default)]
    pub syslog_severity: SeverityChoice,
    #[serde(default)]
    pub comment: String,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// A rule (RouterOS `/system logging add topics=… action=…`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRule {
    pub id: ItemId,
    /// Topics from [`TOPICS`]; `!topic` excludes events that carry it.
    pub topics: Vec<String>,
    /// Name of a [`LogAction`].
    pub action: String,
    /// Put in front of the message text.
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub disabled: bool,
}

impl LogRule {
    /// RouterOS semantics: every plain topic present, no `!` topic present.
    pub fn matches(&self, event_topics: &[String]) -> bool {
        let has = |t: &str| event_topics.iter().any(|x| x == t);
        !self.disabled
            && self.topics.iter().any(|t| !t.starts_with('!'))
            && self.topics.iter().all(|t| match t.strip_prefix('!') {
                Some(not) => !has(not),
                None => has(t),
            })
    }
}

/// Checks one rule topic (`info`, `!debug`).
pub fn valid_topic(t: &str) -> Result<(), String> {
    let name = t.strip_prefix('!').unwrap_or(t);
    if TOPICS.contains(&name) {
        Ok(())
    } else {
        Err(format!(
            "unknown topic '{}' (topics: {})",
            t.chars().take(32).collect::<String>(),
            TOPICS.join(", ")
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logging {
    /// Remote actions; the built-in [`MEMORY_ACTION`] is not listed here.
    pub actions: Vec<LogAction>,
    pub rules: Vec<LogRule>,
    /// Next id handed out by `next_rule_id`.
    pub next_rule_id: u32,
    /// Lines the `memory` action keeps (RouterOS `memory-lines`).
    pub memory_lines: u32,
}

/// RouterOS' default rules: `info`, `error`, `warning` and `critical` go to
/// `memory`, so the router's log shows them out of the box (`debug` does
/// not: it would push the useful lines out).
impl Default for Logging {
    fn default() -> Self {
        let rules: Vec<LogRule> = ["info", "error", "warning", "critical"]
            .iter()
            .zip(1u32..)
            .map(|(topic, id)| LogRule {
                id: ItemId(id),
                topics: vec![(*topic).to_owned()],
                action: MEMORY_ACTION.to_owned(),
                prefix: String::new(),
                disabled: false,
            })
            .collect();
        Self {
            actions: Vec::new(),
            next_rule_id: u32::try_from(rules.len()).unwrap_or(0),
            rules,
            memory_lines: DEFAULT_MEMORY_LINES,
        }
    }
}

impl Logging {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_rule_id(&mut self) -> ItemId {
        self.next_rule_id = self.next_rule_id.saturating_add(1);
        ItemId(self.next_rule_id)
    }

    pub fn action(&self, name: &str) -> Option<&LogAction> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// `name` is an action a rule may name: a remote one, `memory` or
    /// `analytics`.
    pub fn has_action(&self, name: &str) -> bool {
        name == MEMORY_ACTION || name == ANALYTICS_ACTION || self.action(name).is_some()
    }

    /// The first enabled rule that sends events with `topics` to
    /// `analytics` (its prefix goes in front of the message).
    pub fn to_analytics(&self, topics: &[String]) -> Option<&LogRule> {
        self.rules
            .iter()
            .find(|r| r.action == ANALYTICS_ACTION && r.matches(topics))
    }

    /// Some enabled rule sends events with `topics` to `memory`.
    pub fn to_memory(&self, topics: &[String]) -> bool {
        self.rules
            .iter()
            .any(|r| r.action == MEMORY_ACTION && r.matches(topics))
    }
}

/// One thing that happened, ready to be matched against the rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    /// Number in the router's log, rising from 1 since start (0: not
    /// logged yet).
    #[serde(default)]
    pub seq: u64,
    /// Unix time, seconds (0: the router had no clock yet).
    pub time: u64,
    pub topics: Vec<String>,
    /// Who caused it: `daemon`, or the account and channel of a command
    /// (`admin · GUI`).
    #[serde(default)]
    pub origin: String,
    /// For people, in Portuguese: "Ping para uol.com.br iniciado (tarefa 1)".
    pub message: String,
    /// For the technical view: the command, its parameters, its result or
    /// error, the revision it created. `null` when there is nothing more.
    #[serde(default)]
    pub detail: serde_json::Value,
}

impl LogEvent {
    /// The level topic it carries (`info` when none).
    pub fn level(&self) -> &str {
        LEVELS
            .iter()
            .rev()
            .find(|l| self.topics.iter().any(|t| t == *l))
            .copied()
            .unwrap_or("info")
    }
}

/// Rank of a level in [`LEVELS`] (unknown: `info`'s).
pub fn level_rank(level: &str) -> usize {
    LEVELS.iter().position(|l| *l == level).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(topics: &[&str]) -> LogRule {
        LogRule {
            id: ItemId(1),
            topics: topics.iter().map(|t| (*t).to_owned()).collect(),
            action: "remote".into(),
            prefix: String::new(),
            disabled: false,
        }
    }

    fn topics(t: &[&str]) -> Vec<String> {
        t.iter().map(|t| (*t).to_owned()).collect()
    }

    #[test]
    fn rules_match_like_routeros() {
        let ev = topics(&["ntp", "info"]);
        assert!(rule(&["info"]).matches(&ev));
        assert!(rule(&["ntp", "info"]).matches(&ev));
        assert!(!rule(&["ntp", "error"]).matches(&ev));
        assert!(rule(&["info", "!debug"]).matches(&ev));
        assert!(!rule(&["info", "!ntp"]).matches(&ev));
        // Only negations: matches nothing (RouterOS needs a plain topic).
        assert!(!rule(&["!debug"]).matches(&ev));
        let mut off = rule(&["info"]);
        off.disabled = true;
        assert!(!off.matches(&ev));
    }

    #[test]
    fn codes_follow_rfc_5424_tables() {
        assert_eq!(Facility::Kern.code(), 0);
        assert_eq!(Facility::Daemon.code(), 3);
        assert_eq!(Facility::Local4.code(), 20);
        assert_eq!(Severity::Notice.code(), 5);
        assert_eq!("LOCAL7".parse::<Facility>().unwrap(), Facility::Local7);
        assert!("local8".parse::<Facility>().is_err());
        assert_eq!(
            "warning".parse::<SeverityChoice>().unwrap(),
            SeverityChoice::Fixed(Severity::Warning)
        );
        assert_eq!(
            SeverityChoice::Auto.resolve(&topics(&["system", "error"])),
            Severity::Error
        );
    }

    #[test]
    fn severity_choice_round_trips_in_json() {
        for s in ["\"auto\"", "\"debug\"", "\"emergency\""] {
            let v: SeverityChoice = serde_json::from_str(s).unwrap();
            assert_eq!(serde_json::to_string(&v).unwrap(), s);
        }
        let a: LogAction = serde_json::from_str(r#"{"name": "r", "remote": "192.0.2.1"}"#).unwrap();
        assert_eq!(a.remote_port, 514);
        assert_eq!(a.syslog_facility, Facility::Daemon);
        assert_eq!(a.syslog_severity, SeverityChoice::Auto);
    }

    #[test]
    fn defaults_send_the_four_levels_to_memory() {
        let l = Logging::default();
        assert_eq!(l.rules.len(), 4);
        assert_eq!(l.memory_lines, 1000);
        assert!(l.to_memory(&topics(&["ntp", "warning"])));
        assert!(!l.to_memory(&topics(&["dhcp", "debug"])));
        assert!(l.has_action("memory") && !l.has_action("siem"));
        // An old config without the field keeps the default size.
        let back: Logging = serde_json::from_str(r#"{"rules": []}"#).unwrap();
        assert_eq!(back.memory_lines, 1000);
        assert!(back.rules.is_empty());
        let mut ev = LogEvent {
            seq: 1,
            time: 0,
            topics: topics(&["tool", "warning"]),
            origin: String::new(),
            message: String::new(),
            detail: serde_json::Value::Null,
        };
        assert_eq!(ev.level(), "warning");
        ev.topics = topics(&["system"]);
        assert_eq!(ev.level(), "info");
        assert!(level_rank("error") > level_rank("warning"));
    }

    #[test]
    fn topics_are_checked() {
        assert!(valid_topic("info").is_ok());
        assert!(valid_topic("!debug").is_ok());
        assert!(valid_topic("inf").is_err());
    }
}

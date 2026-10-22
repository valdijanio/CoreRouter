//! Log events for `/system logging` (G4.6): what the router reports and
//! with which topics. The daemon turns them into syslog datagrams for the
//! rules that match (`LogRule::matches`).
//!
//! Sources today: the command journal (every configuration change and
//! every failed command) and the NTP client's state changes.

use corerouter_model::logging::{LogEvent, LogRule, Logging};
use corerouter_model::ntp::{NtpState, NtpStatus};
use serde_json::Value;

use crate::JournalEntry;

/// Longest parameter text put in a message (the datagram is cut at about
/// 1 KiB anyway; RFC 5426 §3.2).
const MAX_PARAMS_TEXT: usize = 512;

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
    } else {
        "system"
    }
}

/// A journal entry as an event: `system,info` (plus the area's topic) for
/// a change, `…,error` for a command that failed. RouterOS logs config
/// changes under `system,info` too, so a single `info` rule sends them.
pub fn journal_event(e: &JournalEntry, time: u64) -> LogEvent {
    let area = area_topic(&e.command);
    let mut topics = vec!["system".to_owned()];
    if area != "system" {
        topics.push(area.to_owned());
    }
    topics.push(if e.ok { "info" } else { "error" }.to_owned());
    let params = match &e.params {
        Value::Null => String::new(),
        Value::Object(m) if m.is_empty() => String::new(),
        p => format!(" {}", cut(&p.to_string(), MAX_PARAMS_TEXT)),
    };
    let message = match &e.error {
        Some(err) if !e.ok => format!("{}{params} failed: {}", e.command, cut(err, 256)),
        _ => format!("{}{params}", e.command),
    };
    LogEvent {
        time,
        topics,
        message,
    }
}

/// An NTP state change worth logging, if `now` differs from `before`:
/// synchronized (or to another server) is `ntp,info`, lost is
/// `ntp,warning`. Offsets alone changing do not log (every poll would).
pub fn ntp_event(before: &NtpStatus, now: &NtpStatus, time: u64) -> Option<LogEvent> {
    let ev = |level: &str, message: String| LogEvent {
        time,
        topics: vec!["ntp".to_owned(), level.to_owned()],
        message,
    };
    match (before.status, now.status) {
        (_, NtpState::Synchronized)
            if before.status != NtpState::Synchronized
                || before.synced_address != now.synced_address =>
        {
            Some(ev(
                "info",
                format!(
                    "synchronized with {} ({}), stratum {}, offset {} ms",
                    now.synced_server.as_deref().unwrap_or("?"),
                    now.synced_address.as_deref().unwrap_or("?"),
                    now.synced_stratum.map_or("?".into(), |s| s.to_string()),
                    now.system_offset_ms
                        .map_or("?".into(), |o| format!("{o:.3}")),
                ),
            ))
        }
        (NtpState::Synchronized, NtpState::Waiting) => Some(ev(
            "warning",
            format!(
                "lost synchronization: {}",
                now.last_error.as_deref().unwrap_or("no server answered")
            ),
        )),
        _ => None,
    }
}

/// The rules an event goes to, at most once per action (two rules naming
/// the same action do not duplicate the datagram), with the first
/// matching rule's prefix.
pub fn routes<'a>(logging: &'a Logging, ev: &LogEvent) -> Vec<&'a LogRule> {
    let mut out: Vec<&LogRule> = Vec::new();
    for r in logging.rules.iter().filter(|r| r.matches(&ev.topics)) {
        if logging.action(&r.action).is_some() && !out.iter().any(|o| o.action == r.action) {
            out.push(r);
        }
    }
    out
}

fn cut(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", s.get(..end).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(command: &str, ok: bool) -> JournalEntry {
        JournalEntry {
            seq: 1,
            command: command.into(),
            params: json!({"address": "10.0.0.1/24"}),
            ok,
            error: (!ok).then(|| "bad".into()),
        }
    }

    #[test]
    fn journal_entries_get_routeros_topics() {
        let e = journal_event(&entry("ip.address.add", true), 5);
        assert_eq!(e.topics, ["system", "info"]);
        assert_eq!(e.message, r#"ip.address.add {"address":"10.0.0.1/24"}"#);
        let e = journal_event(&entry("user.add", false), 5);
        assert_eq!(e.topics, ["system", "account", "error"]);
        assert!(e.message.ends_with("failed: bad"), "{}", e.message);
        let e = journal_event(&entry("ip.firewall.filter.add", true), 5);
        assert_eq!(e.topics, ["system", "firewall", "info"]);
    }

    #[test]
    fn long_params_are_cut_on_a_char_boundary() {
        let mut e = entry("system.identity.set", true);
        e.params = json!({ "name": "ã".repeat(600) });
        let ev = journal_event(&e, 0);
        assert!(ev.message.len() < 600, "{}", ev.message.len());
        assert!(ev.message.ends_with('…'));
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
        let e = ntp_event(&waiting, &synced, 1).unwrap();
        assert_eq!(e.topics, ["ntp", "info"]);
        assert!(e.message.contains("pool.ntp.org (192.0.2.1), stratum 2"));
        let drift = NtpStatus {
            system_offset_ms: Some(2.0),
            ..synced.clone()
        };
        assert_eq!(ntp_event(&synced, &drift, 2), None);
        let lost = ntp_event(&synced, &waiting, 3).unwrap();
        assert_eq!(lost.topics, ["ntp", "warning"]);
        assert_eq!(ntp_event(&NtpStatus::default(), &waiting, 4), None);
    }
}

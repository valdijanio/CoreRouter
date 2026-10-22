//! /log (G4.6d): the router's own log, what the rules sent to the `memory`
//! action — journal, DHCP, NTP and the tools, with topics, origin, a
//! message for people and the technical detail.

use corerouter_model::logging::{LEVELS, LogEvent, level_rank, valid_topic};
use serde_json::{Value, json};

use super::args::{opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::logging::LogBook;
use crate::{EngineError, Result, Session};

/// Lines one `log.print` returns at most (the GUI asks again with `since`).
pub const MAX_PRINT: usize = 2000;
const MAX_FIND: usize = 128;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "log.print", "Log", [], None,
        "{topics?: [string], level?: debug|info|warning|error|critical, since?: int, find?: string, limit?: int 1..2000} → [{seq, date, topics, message, origin, level, time, detail}]",
        always, print),
    cmd!(
        "log.clear",
        "Clear Log",
        [],
        None,
        "{} → {cleared}",
        always,
        clear
    ),
];

/// `topics` as a list or `"dhcp,ntp"`: the event has any of them.
fn wanted_topics(p: &Value) -> Result<Vec<String>> {
    let raw: Vec<String> = match p.get("topics") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) => s.split(',').map(|t| t.trim().to_owned()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|t| t.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("topics", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("topics", "must be a list, e.g. [\"ntp\"]")),
    };
    let out: Vec<String> = raw.into_iter().filter(|t| !t.is_empty()).take(16).collect();
    for t in &out {
        if t.starts_with('!') {
            return Err(EngineError::bad(
                "topics",
                "log.print shows events with any of the topics; '!' is for logging rules",
            ));
        }
        valid_topic(t).map_err(|e| EngineError::bad("topics", e))?;
    }
    Ok(out)
}

/// A line; `date` is `time` for people (UTC, the router has no time zone
/// yet), first so a terminal table shows it with the message.
fn row(e: &LogEvent) -> Value {
    let date = if e.time == 0 {
        String::new()
    } else {
        crate::safe_mode::utc(e.time)
    };
    json!({
        "seq": e.seq,
        "date": date,
        "time": e.time,
        "topics": e.topics,
        "level": e.level(),
        "origin": e.origin,
        "message": e.message,
        "detail": e.detail,
    })
}

/// The kept lines, oldest first: of any of `topics`, at least `level`,
/// after `since` (a `seq`), with `find` in the message or origin
/// (case-insensitive); the newest `limit` of them.
fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let topics = wanted_topics(p)?;
    let min_rank = match opt_str(p, "level")? {
        None => 0,
        Some(l) if LEVELS.contains(&l) => level_rank(l),
        Some(l) => {
            return Err(EngineError::bad(
                "level",
                format!(
                    "'{}' is not a level ({})",
                    l.chars().take(16).collect::<String>(),
                    LEVELS.join(", ")
                ),
            ));
        }
    };
    let since = match p.get("since") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|t| t.trim().parse().ok()))
            .ok_or_else(|| EngineError::bad("since", "must be a log number (seq), 0 or more"))?,
    };
    let find = opt_text(p, "find", MAX_FIND)?
        .map(|f| f.trim().to_lowercase())
        .filter(|f| !f.is_empty());
    let limit = opt_u32(p, "limit")?.map_or(MAX_PRINT, |n| {
        usize::try_from(n).unwrap_or(MAX_PRINT).clamp(1, MAX_PRINT)
    });
    s.log_trim();
    let Some(book) = s.ext::<LogBook>() else {
        return Ok(Value::Array(Vec::new()));
    };
    let mut out: Vec<Value> = book
        .memory()
        .rev()
        .filter(|e| e.seq > since)
        .filter(|e| topics.is_empty() || e.topics.iter().any(|t| topics.contains(t)))
        .filter(|e| level_rank(e.level()) >= min_rank)
        .filter(|e| {
            find.as_ref().is_none_or(|f| {
                e.message.to_lowercase().contains(f) || e.origin.to_lowercase().contains(f)
            })
        })
        .take(limit)
        .map(row)
        .collect();
    out.reverse();
    Ok(Value::Array(out))
}

fn clear(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(json!({ "cleared": s.log_clear() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Caller;
    use crate::auth::Principal;
    use crate::logging::DAEMON;

    fn print(s: &mut Session, p: Value) -> Vec<Value> {
        s.execute("log.print", &p)
            .unwrap()
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn config_changes_are_logged_with_origin_and_detail() {
        let mut s = Session::virtual_lab();
        s.tick(1_700_000_000);
        let admin = Caller::new(7, "tcp 10.0.0.9:5000")
            .with_principal(Principal::Local)
            .with_via(&json!({"via": "gui"}));
        s.execute_as(&admin, "system.identity.set", &json!({"name": "edge1"}))
            .unwrap();
        let rows = print(&mut s, json!({}));
        let last = rows.last().unwrap();
        assert_eq!(last["message"], "Nome do roteador alterado para «edge1»");
        assert_eq!(last["origin"], "local · GUI");
        assert_eq!(last["topics"], json!(["system", "info"]));
        assert_eq!(last["time"], 1_700_000_000);
        assert_eq!(last["detail"]["command"], "system.identity.set");
        assert_eq!(last["detail"]["params"]["name"], "edge1");
        assert!(last["detail"]["revision"].as_u64().is_some(), "{last}");

        // A failure is an error, with the reason.
        s.execute("ip.address.add", &json!({"address": "bad", "interface": "ether1"}))
            .unwrap_err();
        let errors = print(&mut s, json!({"level": "error"}));
        assert_eq!(errors.len(), 1);
        assert!(errors[0]["message"].as_str().unwrap().starts_with("Falhou: /ip address add"));
        assert!(errors[0]["detail"]["error"].is_string());
    }

    #[test]
    fn secrets_never_reach_the_log() {
        let mut s = Session::virtual_lab();
        s.execute(
            "user.add",
            &json!({"name": "ops", "group": "read", "password": "s3cret-pass"}),
        )
        .unwrap();
        let text = serde_json::to_string(&print(&mut s, json!({}))).unwrap();
        assert!(!text.contains("s3cret-pass"), "{text}");
    }

    #[test]
    fn filters_and_incremental_reads() {
        let mut s = Session::virtual_lab();
        s.log_event(&["ntp", "warning"], DAEMON, "NTP: não foi possível resolver pool.ntp.org".into(), Value::Null);
        s.log_event(&["dhcp", "info"], DAEMON, "DHCP em ether1: obteve 10.0.0.5".into(), Value::Null);
        s.log_event(&["tool", "info"], "admin · GUI", "Ping para uol.com.br iniciado (tarefa 1)".into(), Value::Null);
        assert_eq!(print(&mut s, json!({})).len(), 3);
        assert_eq!(print(&mut s, json!({"topics": ["ntp", "tool"]})).len(), 2);
        assert_eq!(print(&mut s, json!({"topics": "dhcp"})).len(), 1);
        let warn = print(&mut s, json!({"level": "warning"}));
        assert_eq!(warn.len(), 1);
        assert_eq!(warn[0]["level"], "warning");
        assert_eq!(print(&mut s, json!({"find": "UOL"})).len(), 1);
        assert_eq!(print(&mut s, json!({"find": "admin"})).len(), 1);
        let after = print(&mut s, json!({"since": 2}));
        assert_eq!(after.len(), 1);
        assert_eq!(after[0]["seq"], 3);
        let newest = print(&mut s, json!({"limit": 2}));
        assert_eq!(newest[0]["seq"], 2);
    }

    #[test]
    fn bad_filters_are_refused() {
        let mut s = Session::virtual_lab();
        for (p, needle) in [
            (json!({"level": "loud"}), "not a level"),
            (json!({"topics": ["nope"]}), "unknown topic"),
            (json!({"topics": ["!ntp"]}), "'!' is for logging rules"),
            (json!({"since": -1}), "since"),
            (json!({"limit": "x"}), "limit"),
        ] {
            let e = s.execute("log.print", &p).unwrap_err().to_string();
            assert!(e.contains(needle), "{p}: {e}");
        }
    }

    #[test]
    fn clear_empties_and_says_so() {
        let mut s = Session::virtual_lab();
        s.log_event(&["system", "info"], DAEMON, "x".into(), Value::Null);
        assert_eq!(s.execute("log.clear", &json!({})).unwrap()["cleared"], 1);
        let rows = print(&mut s, json!({}));
        assert_eq!(rows.len(), 1, "only the clear itself: {rows:?}");
        assert_eq!(rows[0]["message"], "Log apagado");
    }
}

//! /log (G4.6d): the router's own log, what the rules sent to the `memory`
//! and `disk` actions — journal, DHCP, NTP and the tools, with topics,
//! origin, a message for people and the technical detail. What only the
//! disk has (from before the last boot, or past `memory_lines`) says
//! `from_disk`; G4.6g.

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
        "{topics?: [string], level?: debug|info|warning|error|critical, since?: int, find?: string, limit?: int 1..2000} → [{seq, date, topics, message, origin, level, time, from_disk, detail}]",
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
fn row(e: &LogEvent, from_disk: bool) -> Value {
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
        "from_disk": from_disk,
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
    s.log_groups_flush();
    let Some(book) = s.ext::<LogBook>() else {
        return Ok(Value::Array(Vec::new()));
    };
    let mut out: Vec<Value> = book
        .rows()
        .into_iter()
        .rev()
        .filter(|(e, _)| e.seq > since)
        .filter(|(e, _)| topics.is_empty() || e.topics.iter().any(|t| topics.contains(t)))
        .filter(|(e, _)| level_rank(e.level()) >= min_rank)
        .filter(|(e, _)| {
            find.as_ref().is_none_or(|f| {
                e.message.to_lowercase().contains(f) || e.origin.to_lowercase().contains(f)
            })
        })
        .take(limit)
        .map(|(e, from_disk)| row(e, from_disk))
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

    /// G0.3f: "Alterado" is for what changed the configuration (also one
    /// still waiting for a commit); an action on the router was "Executado";
    /// a `quiet` command (the commit mode, a test) leaves no line.
    #[test]
    fn only_a_change_says_alterado() {
        let mut s = Session::virtual_lab();
        let last = |s: &mut Session| print(s, json!({})).pop().unwrap()["message"].as_str().unwrap().to_owned();
        s.execute("ip.dns.cache.flush", &json!({})).unwrap();
        assert_eq!(last(&mut s), "Executado: /ip dns cache flush");
        let seq = s.log_seq();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        assert_eq!(s.log_seq(), seq, "not journaled, not logged");
        s.execute("interface.set", &json!({"name": "ether1", "comment": "uplink"})).unwrap();
        assert_eq!(last(&mut s), "Alterado: /interface set comment=uplink name=ether1");
        s.execute("config.discard", &json!({})).unwrap();
        assert_eq!(last(&mut s), "Alterado: /config discard");
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

    fn disk_rule(s: &mut Session) {
        s.execute("system.logging.add", &json!({"topics": ["info"], "action": "disk"})).unwrap();
    }

    fn event(text: &str) -> LogEvent {
        LogEvent {
            seq: 0,
            time: 1_700_000_000,
            topics: vec!["system".into(), "info".into()],
            origin: DAEMON.into(),
            message: text.into(),
            detail: Value::Null,
        }
    }

    /// G4.6g: what the files gave back comes first, marked; nothing shows
    /// twice; the numbers keep rising; the boot's own lines go to the writer.
    #[test]
    fn print_reads_memory_and_disk_and_says_which() {
        let mut s = Session::virtual_lab();
        disk_rule(&mut s);
        let booted = print(&mut s, json!({})).len();
        assert!(booted > 0);
        s.log_disk_attach(vec![event("antes de reiniciar 1"), event("antes de reiniciar 2")], 0);
        let rows = print(&mut s, json!({}));
        assert_eq!(rows.len(), booted + 2);
        assert_eq!(rows[0]["message"], "antes de reiniciar 1");
        assert_eq!(rows[0]["seq"], 1);
        assert_eq!(rows[0]["from_disk"], true);
        assert_eq!(rows[1]["from_disk"], true);
        assert_eq!(rows[2]["from_disk"], false);
        assert_eq!(rows[2]["seq"], 3, "the boot's lines moved up");
        let seqs: Vec<u64> = rows.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
        let (queued, _) = s.log_disk_take();
        assert!(queued.iter().any(|e| e.topics.iter().any(|t| t == "info")));
        assert!(!queued.iter().any(|e| e.message.starts_with("antes")), "not written again");

        // Live lines are in both, shown once, from memory; `since` still
        // goes forward only.
        s.log_event(&["system", "info"], DAEMON, "novo".into(), Value::Null);
        let last = print(&mut s, json!({})).pop().unwrap();
        assert_eq!(last["message"], "novo");
        assert_eq!(last["from_disk"], false);
        let seq = last["seq"].as_u64().unwrap();
        assert!(print(&mut s, json!({"since": seq})).is_empty());
        let (queued, _) = s.log_disk_take();
        assert_eq!(queued.len(), 1);
        assert!(s.log_disk_take().0.is_empty(), "taken once");
    }

    /// Past `memory_lines`, the disk still has it.
    #[test]
    fn a_line_past_memory_lines_comes_from_the_disk() {
        let mut s = Session::virtual_lab();
        disk_rule(&mut s);
        s.log_disk_attach(Vec::new(), 0);
        s.execute("system.logging.action.set", &json!({"name": "memory", "memory_lines": 2})).unwrap();
        for i in 0..5 {
            s.log_event(&["system", "info"], DAEMON, format!("l{i}"), Value::Null);
        }
        let rows = print(&mut s, json!({"find": "l"}));
        let of = |m: &str| rows.iter().find(|r| r["message"] == m).unwrap()["from_disk"].clone();
        assert_eq!(of("l0"), true);
        assert_eq!(of("l4"), false);
    }

    /// No writer (the GUI's lab, no --config-dir): nothing piles up.
    #[test]
    fn without_a_writer_nothing_is_queued() {
        let mut s = Session::virtual_lab();
        disk_rule(&mut s);
        s.log_event(&["system", "info"], DAEMON, "x".into(), Value::Null);
        assert!(s.log_disk_take().0.is_empty());
    }

    /// Every line of a full queue is counted; memory does not grow.
    #[test]
    fn the_queue_and_the_window_are_bounded() {
        let mut s = Session::virtual_lab();
        disk_rule(&mut s);
        s.log_disk_attach(Vec::new(), 0);
        let extra = 10;
        for _ in 0..crate::log_disk::MAX_QUEUE + extra {
            s.log_event(&["system", "info"], DAEMON, "x".into(), Value::Null);
        }
        let book = s.ext::<LogBook>().unwrap();
        assert!(book.disk.lines_dropped >= extra as u64, "{:?}", book.disk);
        assert!(book.rows().len() <= crate::log_disk::WINDOW + 1000 + extra, "{}", book.rows().len());
    }

    #[test]
    fn clear_also_tells_the_writer_to_delete_the_files() {
        let mut s = Session::virtual_lab();
        disk_rule(&mut s);
        s.log_disk_attach(vec![event("velho")], 0);
        let (_, clears) = s.log_disk_take();
        assert_eq!(clears, 0);
        s.execute("log.clear", &json!({})).unwrap();
        let (queued, clears) = s.log_disk_take();
        assert_eq!(clears, 1);
        assert!(queued.iter().all(|e| e.message == "Log apagado"), "{queued:?}");
        assert!(print(&mut s, json!({"find": "velho"})).is_empty());
    }
}

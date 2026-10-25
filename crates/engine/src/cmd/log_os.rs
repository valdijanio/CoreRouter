//! /log os (G4.8b): the operating system's log under the router — the
//! kernel (drivers, network stack, memory, disks), the services and the
//! logins — as the System › Resources › OS Log tab shows it: levels of
//! RFC 5424, repeats folded into one row with a count, and for messages
//! the router knows, what they mean and where to go.
//!
//! The lines are in the session ([`OsLogBook`]); the daemon's `oslog`
//! service feeds them. Without it (the lab, the CLI alone) the command
//! asks the backend (`Hal::os_log`), which never blocks.

use corerouter_hal::oslog::{OsSource, severity_name, severity_of, SEVERITIES};
use serde_json::{Value, json};

use super::args::{opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::oslog::{Entry, OsLogBook};
use crate::oslog_known::{KNOWN, known, known_json};
use crate::{EngineError, Result, Session};

/// Rows one `log.os.print` returns at most (the GUI asks again with `since`).
pub const MAX_PRINT: usize = 2000;
/// Lines taken from the backend in one go.
const PULL: usize = 5000;
const MAX_FIND: usize = 128;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "log.os.print", "OS Log", [], None,
        "{since?: int, level?: emergency|alert|critical|error|warning|notice|info|debug, source?: kernel|services|auth (comma-separated), find?: string (message, unit, device or pid), limit?: int 1..2000} → {entries: [{id, seq, date, level, source, unit, device, pid, message, count, first, time, time_us, severity, boot, this_boot, known}], sources: [{name, ok, reason, lines}], counts: {error, warning, info}, total, last, boot}",
        always, print),
    cmd!(query "log.os.known", "OS Log Known Messages", [], None,
        "{} → [{id, source, title, meaning, alert, actions}]",
        always, list_known),
];

/// Ask the backend for new lines when no daemon feeds the book.
fn pull(s: &mut Session) {
    if s.ext::<OsLogBook>().is_some_and(|b| b.fed) {
        return;
    }
    let now = s.now();
    let got = s.hal_mut().os_log(now, PULL);
    let Some(book) = s.ext_mut::<OsLogBook>() else {
        return;
    };
    match got {
        Ok(batch) => {
            book.ingest(batch);
        }
        Err(e) => {
            book.sources = vec![corerouter_hal::oslog::SourceState::unavailable(
                "os",
                format!("unavailable: {e}"),
                0,
            )];
        }
    }
}

fn sources_wanted(p: &Value) -> Result<Vec<OsSource>> {
    let raw: Vec<String> = match p.get("source") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) => s.split(',').map(|t| t.trim().to_owned()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|t| t.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("source", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("source", "kernel, services or auth")),
    };
    raw.iter()
        .filter(|t| !t.is_empty())
        .take(3)
        .map(|t| {
            OsSource::parse(t).ok_or_else(|| {
                EngineError::bad(
                    "source",
                    format!(
                        "'{}' is not a source (kernel, services, auth)",
                        t.chars().take(16).collect::<String>()
                    ),
                )
            })
        })
        .collect()
}

fn date(time_us: u64) -> String {
    if time_us == 0 {
        String::new()
    } else {
        crate::safe_mode::utc(time_us / 1_000_000)
    }
}

fn row(e: &Entry, boot: &str) -> Value {
    let l = &e.line;
    json!({
        "id": e.id,
        "seq": e.seq,
        "date": date(l.time_us),
        "level": severity_name(l.severity),
        "source": l.source.name(),
        "unit": l.unit,
        "device": l.device,
        "pid": l.pid,
        "message": l.message,
        "count": e.count,
        "first": e.first_us / 1_000_000,
        "time": l.time_us / 1_000_000,
        "time_us": l.time_us,
        "severity": l.severity,
        "boot": l.boot,
        "this_boot": !l.boot.is_empty() && l.boot == boot,
        "known": known(l).map(|k| known_json(k, l)),
    })
}

fn matches_find(e: &Entry, find: &str) -> bool {
    let l = &e.line;
    l.message.to_lowercase().contains(find)
        || l.unit.to_lowercase().contains(find)
        || l.device.to_lowercase().contains(find)
        || l.pid.is_some_and(|p| p.to_string() == find)
}

/// The rows changed after `since` (a `seq`), at least `level`, of the
/// sources asked, with `find`; the newest `limit` of them, oldest first.
fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let max_sev = match opt_str(p, "level")? {
        None => 7,
        Some(l) => severity_of(l).ok_or_else(|| {
            EngineError::bad(
                "level",
                format!(
                    "'{}' is not a level ({})",
                    l.chars().take(16).collect::<String>(),
                    SEVERITIES.join(", ")
                ),
            )
        })?,
    };
    let sources = sources_wanted(p)?;
    let since = match p.get("since") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|t| t.trim().parse().ok()))
            .ok_or_else(|| EngineError::bad("since", "must be a row number (seq), 0 or more"))?,
    };
    let find = opt_text(p, "find", MAX_FIND)?
        .map(|f| f.trim().to_lowercase())
        .filter(|f| !f.is_empty());
    let limit = opt_u32(p, "limit")?.map_or(MAX_PRINT, |n| {
        usize::try_from(n).unwrap_or(MAX_PRINT).clamp(1, MAX_PRINT)
    });
    pull(s);
    let Some(book) = s.ext::<OsLogBook>() else {
        return Ok(json!({"entries": [], "sources": [], "counts": {}, "total": 0, "last": 0}));
    };
    let mut entries: Vec<Value> = book
        .since(since)
        .rev()
        .filter(|e| e.line.severity <= max_sev)
        .filter(|e| sources.is_empty() || sources.contains(&e.line.source))
        .filter(|e| find.as_deref().is_none_or(|f| matches_find(e, f)))
        .take(limit)
        .map(|e| row(e, &book.boot))
        .collect();
    entries.reverse();
    let c = book.counts();
    Ok(json!({
        "entries": entries,
        "sources": book.sources,
        "counts": {"error": c.error, "warning": c.warning, "info": c.info},
        "total": book.len(),
        "last": book.last_seq(),
        "boot": book.boot,
    }))
}

fn list_known(_: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        KNOWN
            .iter()
            .map(|k| {
                json!({
                    "id": k.id,
                    "source": k.source.map(OsSource::name),
                    "title": k.title,
                    "meaning": k.meaning,
                    "alert": k.alert,
                    "actions": k.actions.iter().map(|a| json!({
                        "label": a.label, "window": a.window, "command": a.command,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::oslog::{OsLine, OsLogBatch, SourceState};

    fn print(s: &mut Session, p: Value) -> Value {
        s.execute("log.os.print", &p).unwrap()
    }

    fn entries(v: &Value) -> Vec<Value> {
        v["entries"].as_array().unwrap().clone()
    }

    #[test]
    fn the_lab_shows_its_os_log_with_repeats_and_explanations() {
        let mut s = Session::virtual_lab();
        s.tick(1_792_843_200);
        let v = print(&mut s, json!({}));
        let rows = entries(&v);
        assert!(rows.len() > 15, "{}", rows.len());
        assert_eq!(v["sources"][0]["name"], "lab");
        assert_eq!(v["sources"][0]["ok"], true);
        // The 37 drops on ether2 are one row.
        let ring = rows
            .iter()
            .find(|r| r["message"].as_str().unwrap().contains("rx_missed"))
            .unwrap();
        assert_eq!(ring["count"], 37);
        assert_eq!(ring["level"], "warning");
        assert_eq!(ring["unit"], "r8169");
        assert_eq!(ring["device"], "ether2");
        assert_eq!(ring["this_boot"], true);
        assert_eq!(ring["known"]["id"], "nic-ring-full");
        assert_eq!(ring["known"]["actions"][0]["label"], "Abrir Tuning › ether2");
        assert_eq!(ring["time"].as_u64().unwrap() - ring["first"].as_u64().unwrap(), 36 * 15);
        assert!(ring["date"].as_str().unwrap().starts_with("2026-10-24"));
        // Counts by chip.
        let c = &v["counts"];
        assert!(c["error"].as_u64().unwrap() >= 1 && c["warning"].as_u64().unwrap() >= 3);
        // since: nothing new at once; the lab adds a drop every fifth ask.
        let last = v["last"].as_u64().unwrap();
        let mut more = Vec::new();
        for _ in 0..5 {
            more.extend(entries(&print(&mut s, json!({"since": last}))));
        }
        assert_eq!(more.len(), 1);
        assert_eq!(more[0]["id"], ring["id"], "the same row, moved");
        assert_eq!(more[0]["count"], 38);
    }

    #[test]
    fn filters_level_source_find_limit() {
        let mut s = Session::virtual_lab();
        let all = entries(&print(&mut s, json!({})));
        let errors = entries(&print(&mut s, json!({"level": "error"})));
        assert!(!errors.is_empty() && errors.len() < all.len());
        assert!(errors.iter().all(|r| r["severity"].as_u64().unwrap() <= 3));
        let auth = entries(&print(&mut s, json!({"source": "auth"})));
        assert!(auth.len() >= 2 && auth.iter().all(|r| r["source"] == "auth"));
        let two = entries(&print(&mut s, json!({"source": ["kernel", "auth"]})));
        assert!(two.iter().all(|r| r["source"] != "services"));
        let found = entries(&print(&mut s, json!({"find": "ETHER3"})));
        assert_eq!(found.len(), 2, "Link Down and Link Up");
        let pid = entries(&print(&mut s, json!({"find": "2211"})));
        assert!(pid.iter().any(|r| r["pid"] == 2211));
        let newest = entries(&print(&mut s, json!({"limit": 3})));
        assert_eq!(newest.len(), 3);
        assert!(newest.windows(2).all(|w| w[0]["seq"].as_u64() < w[1]["seq"].as_u64()));
        assert!(entries(&print(&mut s, json!({"level": "crit"}))).len() <= errors.len());
    }

    #[test]
    fn bad_params_are_refused_with_the_reason() {
        let mut s = Session::virtual_lab();
        for (p, words) in [
            (json!({"level": "loud"}), "not a level"),
            (json!({"source": "disk"}), "not a source"),
            (json!({"source": 7}), "kernel, services or auth"),
            (json!({"since": -1}), "row number"),
            (json!({"since": "x"}), "row number"),
            (json!({"find": "x".repeat(500)}), "find"),
            (json!({"levle": "error"}), "level"),
        ] {
            let e = s.execute("log.os.print", &p).unwrap_err().to_string();
            assert!(e.contains(words), "{p}: {e}");
        }
    }

    #[test]
    fn a_fed_book_is_not_refilled_by_the_backend() {
        let mut s = Session::virtual_lab();
        if let Some(b) = s.ext_mut::<OsLogBook>() {
            b.fed = true;
            b.ingest(OsLogBatch {
                lines: vec![OsLine {
                    time_us: 5_000_000,
                    severity: 2,
                    source: OsSource::Kernel,
                    unit: "mce".into(),
                    device: String::new(),
                    pid: None,
                    message: "mce: [Hardware Error]: Machine check events logged".into(),
                    boot: "b1".into(),
                }],
                sources: vec![
                    SourceState::ok("kmsg", 1),
                    SourceState::unavailable("journal", "unavailable: journalctl not found", 0),
                ],
                boot: "b2".into(),
            });
        }
        let v = print(&mut s, json!({}));
        let rows = entries(&v);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["level"], "critical");
        assert_eq!(rows[0]["this_boot"], false, "written in another boot");
        assert_eq!(rows[0]["known"]["id"], "mce");
        assert_eq!(v["sources"][1]["ok"], false);
        assert!(v["sources"][1]["reason"].as_str().unwrap().contains("not found"));
    }

    #[test]
    fn known_lists_the_catalogue() {
        let mut s = Session::virtual_lab();
        let v = s.execute("log.os.known", &json!({})).unwrap();
        assert_eq!(v.as_array().unwrap().len(), KNOWN.len());
        assert!(v.as_array().unwrap().iter().any(|k| k["id"] == "conntrack-full"));
    }
}

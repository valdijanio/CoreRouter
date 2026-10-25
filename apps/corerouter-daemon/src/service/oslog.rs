//! OS log reader (G4.8b): tails the host's kernel ring (`/dev/kmsg`, every
//! second) and systemd journal (`journalctl`, every two seconds) on its
//! own thread, and hands the lines to the session's OS log book
//! (`log.os.print`) under the lock only for the hand-over — the reads
//! never hold it. Repeats fold into one row in the book; a known message
//! that costs traffic or hardware (ring full, conntrack full, OOM, disk,
//! MCE, heat…) also goes to the router's log (`system,error`), once per
//! row, so `/system logging` rules (remote syslog, e-mail later) see it.
//!
//! `--os-log host` reads this machine (the default with `--backend linux`);
//! `lab` leaves the book to the virtual lab's made-up lines (the default
//! with `--backend virtual`); `off` reads nothing.

use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use corerouter_engine::{Shared, lock};

const TICK: Duration = Duration::from_secs(1);
/// Lines handed over per source and tick at most (a storm waits a tick).
#[cfg(target_os = "linux")]
const MAX_PER_TICK: usize = 5000;
#[cfg(target_os = "linux")]
const JOURNAL_EVERY: Duration = Duration::from_secs(2);
/// Router-log lines one tick may add (a burst of new alert rows).
const MAX_ALERTS: usize = 10;
/// Lines older than this (the backlog read at start) never alert.
const ALERT_AGE_US: u64 = 300 * 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Host,
    Lab,
    Off,
}

fn mode(flag: Option<&str>, lab: bool) -> Result<Mode, String> {
    match flag {
        None | Some("") => Ok(if lab { Mode::Lab } else { Mode::Host }),
        Some("host") => Ok(Mode::Host),
        Some("lab") => Ok(Mode::Lab),
        Some("off") => Ok(Mode::Off),
        Some(other) => Err(format!(
            "--os-log {}: host, lab or off",
            other.chars().take(16).collect::<String>()
        )),
    }
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "os-log",
    flags: &[super::Flag {
        name: "--os-log",
        value: Some("host|lab|off"),
        help: "what System › Resources › OS Log shows: host = this machine's kernel\nring and journal (default with --backend linux), lab = the virtual lab's\nlines (default with --backend virtual), off = nothing",
    }],
    topic: "system",
    enable: "--os-log host",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let lab = lock(&session).backend().starts_with("virtual lab");
    let mode = mode(ctx.flag("--os-log"), lab)?;
    Ok(Box::new(move |health: &super::Health| {
        match mode {
            Mode::Host => host(&session, health),
            Mode::Lab => idle(health, "the virtual lab's OS log (--os-log host reads this machine's)"),
            Mode::Off => idle(health, "--os-log off"),
        }
        Ok(())
    }))
}

fn idle(health: &super::Health, why: &str) {
    health.disabled(Some(why));
    while health.sleep(TICK) {
        health.beat();
    }
}

#[cfg(not(target_os = "linux"))]
fn host(session: &Shared, health: &super::Health) {
    let _ = session;
    idle(health, "no OS log reader on this platform");
}

#[cfg(target_os = "linux")]
fn host(session: &Shared, health: &super::Health) {
    use corerouter_hal_linux::oslog::HostOsLog;
    let mut os = HostOsLog::new();
    let mut journal_at: Option<Instant> = None;
    loop {
        health.beat();
        let mut lines = os.read_kmsg(MAX_PER_TICK);
        if journal_at.is_none_or(|t| t.elapsed() >= JOURNAL_EVERY) {
            lines.extend(os.read_journal(MAX_PER_TICK));
            journal_at = Some(Instant::now());
        }
        let batch = corerouter_hal::oslog::OsLogBatch {
            lines,
            sources: os.sources(),
            boot: os.boot().to_owned(),
        };
        let down: Vec<String> = batch
            .sources
            .iter()
            .filter_map(|s| s.reason.clone())
            .collect();
        hand_over(session, batch, now_us());
        if batch_all_down(&os) {
            health.error(down.join("; "));
        } else {
            health.clear_error();
            if let Some(d) = down.first() {
                health.event(d);
            }
        }
        if !health.sleep(TICK) {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn batch_all_down(os: &corerouter_hal_linux::oslog::HostOsLog) -> bool {
    os.sources().iter().all(|s| !s.ok)
}

#[cfg(target_os = "linux")]
fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(0))
        .unwrap_or(0)
}

/// Put `batch` in the book (the only moment the lock is held) and send the
/// recent new rows of alert messages to the router's log.
pub(crate) fn hand_over(session: &Shared, batch: corerouter_hal::oslog::OsLogBatch, now_us: u64) -> usize {
    use corerouter_engine::oslog::{OsLogBook, Pushed};
    use corerouter_engine::oslog_known::known;
    let mut s = lock(session);
    let Some(book) = s.ext_mut::<OsLogBook>() else {
        return 0;
    };
    book.fed = true;
    let lines = batch.lines.clone();
    let pushed = book.ingest(batch);
    let alerts: Vec<(String, &'static str)> = lines
        .iter()
        .zip(&pushed)
        .filter(|(_, p)| matches!(p, Pushed::New(_)))
        .filter(|(l, _)| l.time_us.saturating_add(ALERT_AGE_US) >= now_us)
        .filter_map(|(l, _)| {
            let k = known(l).filter(|k| k.alert)?;
            let msg: String = l.message.chars().take(200).collect();
            Some((
                format!("SO: {}: {msg}", k.title),
                if l.severity <= 3 { "error" } else { "warning" },
            ))
        })
        .take(MAX_ALERTS)
        .collect();
    let n = alerts.len();
    for (msg, level) in alerts {
        s.log_event(
            &["system", level],
            corerouter_engine::logging::DAEMON,
            msg,
            serde_json::Value::Null,
        );
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::oslog::OsLogBook;
    use corerouter_engine::{Session, shared};
    use corerouter_hal::oslog::{OsLine, OsLogBatch, OsSource, SourceState};
    use serde_json::json;

    fn line(t_us: u64, sev: u8, msg: &str) -> OsLine {
        OsLine {
            time_us: t_us,
            severity: sev,
            source: OsSource::Kernel,
            unit: "nf_conntrack".into(),
            device: String::new(),
            pid: None,
            message: msg.into(),
            boot: "b".into(),
        }
    }

    #[test]
    fn modes_follow_the_backend_unless_asked() {
        assert_eq!(mode(None, true), Ok(Mode::Lab));
        assert_eq!(mode(None, false), Ok(Mode::Host));
        assert_eq!(mode(Some("host"), true), Ok(Mode::Host));
        assert_eq!(mode(Some("off"), false), Ok(Mode::Off));
        assert!(mode(Some("everything"), false).unwrap_err().contains("host, lab or off"));
    }

    #[test]
    fn hand_over_feeds_the_book_and_alerts_once_per_row() {
        let session = shared(Session::virtual_lab());
        let now = 10_000_000_000u64;
        let full = "nf_conntrack: nf_conntrack: table full, dropping packet";
        let batch = OsLogBatch {
            lines: vec![
                line(now - 1_000_000, 4, full),
                line(now, 4, full),
                // From the backlog: too old to alert.
                line(now - 3_600_000_000, 2, "mce: [Hardware Error]: Machine check events logged"),
                line(now, 6, "r8169 0000:03:00.0 ether1: Link is Up"),
            ],
            sources: vec![SourceState::ok("kmsg", 4)],
            boot: "b".into(),
        };
        assert_eq!(hand_over(&session, batch, now), 1);
        let mut s = lock(&session);
        assert!(s.ext::<OsLogBook>().unwrap().fed);
        let v = s.execute("log.os.print", &json!({})).unwrap();
        let rows = v["entries"].as_array().unwrap();
        assert_eq!(rows.len(), 3, "the lab backend was not asked: the daemon feeds");
        assert!(rows.iter().any(|r| r["count"] == 2));
        let log = s.execute("log.print", &json!({"find": "SO:"})).unwrap();
        let log = log.as_array().unwrap();
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(log[0]["message"].as_str().unwrap().contains("conntrack"));
        assert_eq!(log[0]["level"], "warning");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_mode_reads_this_machine_without_holding_the_lock() {
        // The real host: kmsg and/or the journal, whichever this user may
        // read; the service thread runs a few ticks and stops.
        let session = shared(Session::virtual_lab());
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        let s2 = session.clone();
        let h2 = health.clone();
        let t = std::thread::spawn(move || host(&s2, &h2));
        // The lock stays free for commands while the reader works.
        let start = Instant::now();
        let mut rows = 0;
        while start.elapsed() < Duration::from_secs(8) && rows == 0 {
            std::thread::sleep(Duration::from_millis(200));
            let t0 = Instant::now();
            let mut s = lock(&session);
            assert!(t0.elapsed() < Duration::from_millis(500), "lock held {:?}", t0.elapsed());
            if s.ext::<OsLogBook>().is_some_and(|b| b.fed) {
                rows = s.execute("log.os.print", &json!({"limit": 5})).unwrap()["total"]
                    .as_u64()
                    .unwrap_or(0);
            }
        }
        health.stop();
        t.join().unwrap();
        let s = lock(&session);
        let book = s.ext::<OsLogBook>().unwrap();
        assert!(book.fed);
        assert!(
            rows > 0 || book.sources.iter().all(|s| !s.ok),
            "a readable source gave lines: {:?}",
            book.sources
        );
    }
}

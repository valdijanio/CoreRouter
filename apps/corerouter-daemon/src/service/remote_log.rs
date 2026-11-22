//! Remote syslog (G4.6): sends the log events of `/system logging` rules
//! to their remote actions as RFC 5424 messages over UDP (RFC 5426).
//!
//! One thread. Every [`TICK`] it copies out of the session lock what is new
//! in the router's log (`Session::log_since`: journal, NTP, DHCP, tools;
//! G4.6d) and the rules and actions, then sends without the lock: a slow or absent collector
//! never stalls a command. UDP is fire-and-forget (RFC 5426 §3.1, one
//! message per datagram); a send error is logged once per action until it
//! changes.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::logging::routes;
use corerouter_engine::{Shared, lock};
use corerouter_model::logging::{LogAction, LogEvent};
use corerouter_proto_syslog::{DEFAULT_MAX_LEN, Message, encode};

const TICK: Duration = Duration::from_millis(500);
/// RFC 5424 §6.2.5: APP-NAME identifies the application.
const APP_NAME: &str = "corerouter";
/// Topics that say how bad, not what: never the MSGID.
const LEVELS: &[&str] = &["critical", "debug", "error", "info", "warning"];

/// The loop on a thread of its own, outside the supervisor (tests).
#[cfg(test)]
pub fn spawn(session: Shared) -> std::io::Result<()> {
    let health = super::Health::new(corerouter_control::Shutdown::default());
    thread::Builder::new()
        .name("remote-log".into())
        .spawn(move || run(&session, &health, &Resume::default()))
        .map(|_| ())
}

/// Where the next run of the service starts reading the log: the first
/// run from now (the boot's history is not replayed), a restart from where
/// the last run stopped, so what was logged while it was down (other
/// services' "failed" lines among them) is still sent. The log keeps a
/// bounded window (`MAX_RECENT`), so this never replays without bound.
#[derive(Debug)]
struct Resume(AtomicU64);

impl Default for Resume {
    fn default() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }
}

impl Resume {
    fn start(&self, now: u64) -> u64 {
        match self.0.load(Ordering::Relaxed) {
            u64::MAX => now,
            seq => seq.min(now),
        }
    }

    fn save(&self, seq: u64) {
        self.0.store(seq, Ordering::Relaxed);
    }
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn run(session: &Shared, health: &super::Health, resume: &Resume) {
    let mut last_seq = resume.start(lock(session).log_seq());
    resume.save(last_seq);
    let pid = std::process::id().to_string();
    let mut sender = Sender::default();
    while health.sleep(TICK) {
        health.beat();
        let (logging, hostname, mut events) = {
            let s = lock(session);
            let events: Vec<LogEvent> = s.log_since(last_seq);
            last_seq = events.last().map_or(last_seq, |e| e.seq);
            let cfg = s.store().running();
            (
                cfg.system.logging.clone(),
                cfg.system.identity.clone(),
                events,
            )
        };
        for ev in events.drain(..) {
            for rule in routes(&logging, &ev) {
                if let Some(action) = logging.action(&rule.action) {
                    let bytes = datagram(action, &rule.prefix, &ev, &hostname, &pid, now_micros());
                    sender.send(action, &bytes);
                }
            }
        }
        resume.save(last_seq);
        sender.forget_removed(&logging);
        let remote = logging
            .rules
            .iter()
            .any(|r| logging.action(&r.action).is_some());
        health.disabled((!remote).then_some("no rule sends to a remote action (system.logging.add)"));
        match sender.errors.iter().next() {
            Some((action, e)) => health.error(format!("action '{action}': {e}")),
            None => health.clear_error(),
        }
    }
}

/// The RFC 5424 message for one event and action (pure).
pub fn datagram(
    action: &LogAction,
    prefix: &str,
    ev: &LogEvent,
    hostname: &str,
    pid: &str,
    time_micros: i64,
) -> Vec<u8> {
    let severity = action.syslog_severity.resolve(&ev.topics);
    let msgid = ev
        .topics
        .iter()
        .rev()
        .find(|t| !LEVELS.contains(&t.as_str()))
        .map_or("system", String::as_str);
    let text = if prefix.is_empty() {
        ev.message.clone()
    } else {
        format!("{prefix} {}", ev.message)
    };
    encode(
        &Message {
            facility: action.syslog_facility.code(),
            severity: severity.code(),
            time_micros: Some(time_micros),
            hostname,
            app_name: APP_NAME,
            procid: pid,
            msgid,
            msg: &text,
        },
        DEFAULT_MAX_LEN,
    )
}

/// Sockets by source address (unbound per family when the action has none),
/// and the last error per action.
#[derive(Default)]
struct Sender {
    sockets: BTreeMap<IpAddr, UdpSocket>,
    errors: BTreeMap<String, String>,
}

impl Sender {
    /// Errors of actions that no longer exist (deleted or renamed: the
    /// operator's fix) stop being reported.
    fn forget_removed(&mut self, logging: &corerouter_model::logging::Logging) {
        self.errors.retain(|name, _| logging.action(name).is_some());
    }

    fn send(&mut self, action: &LogAction, bytes: &[u8]) {
        let to = SocketAddr::new(action.remote, action.remote_port);
        let result = self.socket(action).and_then(|s| s.send_to(bytes, to));
        match result {
            Ok(_) => {
                if self.errors.remove(&action.name).is_some() {
                    log::info!("logging action '{}': sending to {to} again", action.name);
                }
            }
            Err(e) => {
                let e = e.to_string();
                if self.errors.get(&action.name) != Some(&e) {
                    log::warn!("logging action '{}': cannot send to {to}: {e}", action.name);
                    self.errors.insert(action.name.clone(), e);
                }
            }
        }
    }

    fn socket(&mut self, action: &LogAction) -> std::io::Result<&mut UdpSocket> {
        let src = action.src_address.unwrap_or(if action.remote.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        Ok(match self.sockets.entry(src) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(UdpSocket::bind(SocketAddr::new(src, 0))?),
        })
    }
}


/// No flags: configured with `system.logging.*`.
pub(crate) const SERVICE: super::Service = super::Service {
    name: "remote-logging",
    flags: &[],
    topic: "system",
    enable: "system.logging.action.add + system.logging.add",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let resume = Arc::new(Resume::default());
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health, &resume);
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_model::logging::{Facility, SeverityChoice};
    use serde_json::json;

    fn action(port: u16) -> LogAction {
        LogAction {
            name: "a".into(),
            remote: [127, 0, 0, 1].into(),
            remote_port: port,
            src_address: None,
            syslog_facility: Facility::Local3,
            syslog_severity: SeverityChoice::Auto,
            comment: String::new(),
        }
    }

    #[test]
    fn datagram_is_rfc_5424() {
        let ev = LogEvent {
            seq: 1,
            time: 0,
            topics: vec!["system".into(), "account".into(), "error".into()],
            origin: "admin · GUI".into(),
            message: "user.add failed: bad".into(),
            detail: serde_json::Value::Null,
        };
        let out = datagram(&action(514), "r1", &ev, "edge 1", "42", 0);
        // local3 (19) × 8 + error (3) = 155.
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<155>1 1970-01-01T00:00:00.000000Z edge_1 corerouter 42 account - r1 user.add failed: bad"
        );
    }

    #[test]
    fn config_changes_reach_a_local_collector() {
        let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
        collector
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = collector.local_addr().unwrap().port();
        let session = shared(Session::virtual_lab());
        {
            let mut s = lock(&session);
            s.execute(
                "system.logging.action.add",
                &json!({"name": "siem", "remote": "127.0.0.1", "remote_port": port}),
            )
            .unwrap();
            s.execute(
                "system.logging.add",
                &json!({"topics": ["info"], "action": "siem"}),
            )
            .unwrap();
        }
        // Started after the setup: only what happens from now on is sent.
        spawn(session.clone()).unwrap();
        thread::sleep(TICK * 2);
        lock(&session)
            .execute("system.identity.set", &json!({"name": "edge1"}))
            .unwrap();
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
        // daemon (3) × 8 + info (6) = 30.
        assert!(msg.starts_with("<30>1 "), "{msg}");
        assert!(msg.contains(" edge1 corerouter "), "{msg}");
        // Not ASCII: RFC 5424 §6.4 puts a BOM before the UTF-8 text.
        assert!(
            msg.ends_with(" system - \u{feff}Nome do roteador alterado para «edge1»"),
            "{msg}"
        );
    }

    /// audit-services #13: an action's error stayed in the service row
    /// after the action was deleted.
    #[test]
    fn errors_of_removed_actions_are_forgotten() {
        let mut logging = corerouter_model::logging::Logging::default();
        logging.actions.push(action(514));
        let mut sender = Sender::default();
        sender.errors.insert("a".into(), "unreachable".into());
        sender.errors.insert("gone".into(), "unreachable".into());
        sender.forget_removed(&logging);
        assert_eq!(sender.errors.keys().collect::<Vec<_>>(), ["a"]);
        logging.actions.clear();
        sender.forget_removed(&logging);
        assert!(sender.errors.is_empty());
    }

    /// audit-services #13: a restart started at the log's end, dropping
    /// what was logged while the service was down.
    #[test]
    fn a_restart_resumes_where_the_last_run_stopped() {
        let r = Resume::default();
        assert_eq!(r.start(40), 40, "first run: from now");
        r.save(40);
        assert_eq!(r.start(55), 40, "restart: from where it stopped");
        assert_eq!(r.start(10), 10, "never past the log (a new log book)");
    }
}

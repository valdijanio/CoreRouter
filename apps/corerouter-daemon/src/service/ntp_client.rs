//! SNTP client (G4.6): asks the servers of `/system ntp client` for the
//! time and reports offset, delay and stratum to the session
//! (`system.ntp.client.get`).
//!
//! One thread, blocking sockets with a timeout, never holding the session
//! lock across the network. Every second it re-reads the running config; a
//! change restarts at `min_poll`. A round asks every server once and keeps
//! the answer with the smallest round trip (RFC 5905 §10 prefers it: the
//! offset error is at most half the delay). After a good round the poll
//! interval doubles up to `max_poll`; a bad round goes back to `min_poll`
//! (never below 64 s: RFC 4330 §5). Kiss-o'-Death (RFC 5905 §7.4): DENY and
//! RSTR drop that server until the config changes, RATE jumps to
//! `max_poll`.
//!
//! It measures; it does not set the system clock yet (gap G4.6b): a large
//! offset is logged so the operator knows.

use std::collections::BTreeSet;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_model::ntp::{NtpClient, NtpState, NtpStatus};
use corerouter_proto_ntp::{Packet, ReplyError, Sample, Timestamp, check_reply, sample_of};

/// How long to wait for one server's answer.
const ANSWER_WAIT: Duration = Duration::from_secs(2);
/// How often the thread looks at the config.
const TICK: Duration = Duration::from_secs(1);
/// Warn when the clock is off by more than this (ntpd steps at 128 ms;
/// Junos logs above 1000 s and still syncs).
const WARN_OFFSET_MS: f64 = 1000.0;

pub fn spawn(session: Shared, port: u16) -> std::io::Result<()> {
    thread::Builder::new()
        .name("ntp-client".into())
        .spawn(move || run(&session, port))
        .map(|_| ())
}

fn unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0)
}

fn run(session: &Shared, port: u16) {
    let mut cfg: Option<NtpClient> = None;
    let mut status = NtpStatus::default();
    let mut poll_exp = 0u8;
    let mut next = Instant::now();
    let mut denied: BTreeSet<String> = BTreeSet::new();
    let mut warned = false;
    loop {
        let now_cfg = lock(session).store().running().system.ntp_client.clone();
        if cfg.as_ref() != Some(&now_cfg) {
            poll_exp = now_cfg.min_poll;
            next = Instant::now();
            denied.clear();
            status = NtpStatus {
                status: if now_cfg.enabled {
                    NtpState::Waiting
                } else {
                    NtpState::Stopped
                },
                ..NtpStatus::default()
            };
            lock(session).set_ntp_status(status.clone());
            cfg = Some(now_cfg.clone());
        }
        if now_cfg.enabled && Instant::now() >= next {
            let round = poll_round(&now_cfg.servers, port, &mut denied);
            poll_exp = next_poll(poll_exp, &now_cfg, &round);
            let wait = 1u64 << poll_exp.min(17);
            status = round.status(&status, wait);
            if let Some(off) = status.system_offset_ms
                && off.abs() > WARN_OFFSET_MS
                && !warned
            {
                log::warn!(
                    "NTP: the system clock is off by {:.1} s from {}; CoreRouter does not \
                     set the clock yet, use the host's NTP service",
                    off / 1000.0,
                    status.synced_server.as_deref().unwrap_or("?")
                );
                warned = true;
            }
            next = Instant::now() + Duration::from_secs(wait);
            lock(session).set_ntp_status(status.clone());
        }
        thread::sleep(TICK);
    }
}

/// What one round learned.
#[derive(Debug, Default)]
pub struct Round {
    /// Best answer: (server as configured, address, stratum, sample).
    pub best: Option<(String, SocketAddr, u8, Sample)>,
    pub errors: Vec<String>,
    pub rate_limited: bool,
}

impl Round {
    fn status(&self, before: &NtpStatus, poll_secs: u64) -> NtpStatus {
        let ms = |n: i64| n as f64 / 1e6;
        let error = (!self.errors.is_empty()).then(|| self.errors.join("; "));
        match &self.best {
            Some((server, addr, stratum, s)) => NtpStatus {
                status: NtpState::Synchronized,
                synced_server: Some(server.clone()),
                synced_address: Some(addr.ip().to_string()),
                synced_stratum: Some(*stratum),
                system_offset_ms: Some(ms(s.offset_nanos)),
                round_trip_ms: Some(ms(s.delay_nanos)),
                last_sync: u64::try_from(unix_nanos() / 1_000_000_000).ok(),
                last_error: error,
                poll_secs: Some(poll_secs),
            },
            None => NtpStatus {
                status: NtpState::Waiting,
                last_sync: before.last_sync,
                last_error: Some(error.unwrap_or_else(|| "no server to ask".into())),
                poll_secs: Some(poll_secs),
                ..NtpStatus::default()
            },
        }
    }
}

fn next_poll(exp: u8, cfg: &NtpClient, round: &Round) -> u8 {
    if round.rate_limited {
        cfg.max_poll
    } else if round.best.is_some() {
        exp.saturating_add(1).clamp(cfg.min_poll, cfg.max_poll)
    } else {
        cfg.min_poll
    }
}

/// Asks every server not denied; keeps the smallest round trip.
pub fn poll_round(servers: &[String], port: u16, denied: &mut BTreeSet<String>) -> Round {
    let mut round = Round::default();
    for server in servers {
        if denied.contains(server) {
            continue;
        }
        let addr = match (server.as_str(), port).to_socket_addrs() {
            Ok(mut a) => a.next(),
            Err(e) => {
                round.errors.push(format!("{server}: {e}"));
                continue;
            }
        };
        let Some(addr) = addr else {
            round.errors.push(format!("{server}: no address"));
            continue;
        };
        match query(addr, ANSWER_WAIT) {
            Ok((reply, sample)) => {
                let better = round
                    .best
                    .as_ref()
                    .is_none_or(|(_, _, _, b)| sample.delay_nanos < b.delay_nanos);
                if better {
                    round.best = Some((server.clone(), addr, reply.stratum, sample));
                }
            }
            Err(QueryError::Reply(ReplyError::Kiss(code))) => {
                if code == "DENY" || code == "RSTR" {
                    log::warn!("NTP: {server} refused us ({code}); not asking it again");
                    denied.insert(server.clone());
                } else if code == "RATE" {
                    round.rate_limited = true;
                }
                round.errors.push(format!("{server}: kiss-o'-death {code}"));
            }
            Err(e) => round.errors.push(format!("{server}: {e}")),
        }
    }
    round
}

#[derive(Debug)]
pub enum QueryError {
    Io(std::io::Error),
    Timeout,
    Reply(ReplyError),
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("no answer"),
            Self::Reply(e) => write!(f, "{e}"),
        }
    }
}

/// One exchange with `addr`. Replies that do not answer this request
/// (another origin timestamp: late or forged) are skipped until `wait`.
pub fn query(addr: SocketAddr, wait: Duration) -> Result<(Packet, Sample), QueryError> {
    let local: SocketAddr = if addr.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let sock = UdpSocket::bind(local).map_err(QueryError::Io)?;
    // `connect` makes the kernel drop datagrams from anyone else.
    sock.connect(addr).map_err(QueryError::Io)?;
    let t1 = unix_nanos();
    let sent = Timestamp::from_unix_nanos(t1);
    sock.send(&Packet::client_request(sent).encode())
        .map_err(QueryError::Io)?;
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(QueryError::Timeout);
        }
        sock.set_read_timeout(Some(left)).map_err(QueryError::Io)?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(QueryError::Timeout);
            }
            Err(e) => return Err(QueryError::Io(e)),
        };
        let t4 = unix_nanos();
        let Ok(reply) = Packet::decode(buf.get(..n).unwrap_or_default()) else {
            continue;
        };
        match check_reply(sent, &reply) {
            Ok(()) => return Ok((reply, sample_of(&reply, t1, t4))),
            Err(ReplyError::WrongOrigin) => continue,
            Err(e) => return Err(QueryError::Reply(e)),
        }
    }
}


/// No flags: configured with `system.ntp.client.*`.
pub(crate) const SERVICE: super::Service = super::Service {
    name: "ntp client",
    flags: &[],
    start,
};

/// A router without it still forwards: a failure is logged, not fatal.
fn start(ctx: &super::Ctx) -> Result<(), String> {
    if let Err(e) = spawn(ctx.session.clone(), corerouter_proto_ntp::PORT) {
        log::error!("NTP client is off: cannot start its thread: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_ntp::MODE_SERVER;
    use serde_json::json;

    /// A one-socket SNTP server whose clock is `skew_ms` ahead, or that
    /// answers with a kiss code.
    fn server(skew_ms: i128, kiss: Option<&'static [u8; 4]>) -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buf = [0u8; 128];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let req = Packet::decode(&buf[..n]).unwrap();
                let now = Timestamp::from_unix_nanos(unix_nanos() + skew_ms * 1_000_000);
                let mut reply = Packet {
                    version: 4,
                    mode: MODE_SERVER,
                    stratum: 2,
                    reference_id: *b"TEST",
                    origin: req.transmit,
                    receive: now,
                    transmit: now,
                    ..Packet::default()
                };
                if let Some(code) = kiss {
                    reply.stratum = 0;
                    reply.reference_id = *code;
                }
                let _ = sock.send_to(&reply.encode(), from);
            }
        });
        port
    }

    #[test]
    fn measures_the_offset_of_a_local_server() {
        let port = server(2_000, None);
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let (reply, s) = query(addr, ANSWER_WAIT).unwrap();
        assert_eq!(reply.stratum, 2);
        let off_ms = s.offset_nanos / 1_000_000;
        assert!((1_900..=2_100).contains(&off_ms), "{off_ms} ms");
        assert!(s.delay_nanos < 500_000_000);
    }

    #[test]
    fn silence_is_a_timeout() {
        // Bound but never answering.
        let mute = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = mute.local_addr().unwrap();
        let err = query(addr, Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, QueryError::Timeout), "{err}");
    }

    #[test]
    fn deny_drops_the_server_and_rate_slows_down() {
        let deny = server(0, Some(b"DENY"));
        let mut denied = BTreeSet::new();
        let r = poll_round(&["127.0.0.1".into()], deny, &mut denied);
        assert!(r.best.is_none());
        assert!(denied.contains("127.0.0.1"));
        assert!(
            poll_round(&["127.0.0.1".into()], deny, &mut denied)
                .errors
                .is_empty()
        );

        let rate = server(0, Some(b"RATE"));
        let r = poll_round(&["127.0.0.1".into()], rate, &mut BTreeSet::new());
        let cfg = NtpClient::default();
        assert_eq!(next_poll(cfg.min_poll, &cfg, &r), cfg.max_poll);
    }

    #[test]
    fn poll_interval_backs_off_and_resets() {
        let cfg = NtpClient {
            min_poll: 6,
            max_poll: 8,
            ..NtpClient::default()
        };
        let good = Round {
            best: Some((
                "s".into(),
                ([127, 0, 0, 1], 123).into(),
                1,
                Sample {
                    offset_nanos: 0,
                    delay_nanos: 0,
                },
            )),
            ..Round::default()
        };
        assert_eq!(next_poll(6, &cfg, &good), 7);
        assert_eq!(next_poll(8, &cfg, &good), 8);
        assert_eq!(next_poll(8, &cfg, &Round::default()), 6);
    }

    #[test]
    fn the_thread_reports_to_the_session() {
        let port = server(-500, None);
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "system.ntp.client.set",
                &json!({"enabled": true, "servers": ["127.0.0.1"]}),
            )
            .unwrap();
        spawn(session.clone(), port).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let st = loop {
            let st = lock(&session).ntp_status();
            if st.status == NtpState::Synchronized || Instant::now() > deadline {
                break st;
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(st.status, NtpState::Synchronized, "{st:?}");
        assert_eq!(st.synced_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(st.poll_secs, Some(128), "doubled after a good round");
        let off = st.system_offset_ms.unwrap();
        assert!((-600.0..=-400.0).contains(&off), "{off}");
    }
}

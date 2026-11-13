//! G4.1t: one lookup upstream as a state machine, without sockets or
//! threads. It says what to send ([`Exchange`]) and is told what came back
//! ([`Lookup::reply`]), what failed ([`Lookup::failed`]) and that time
//! passed ([`Lookup::tick`]), until it is [`Lookup::done`].
//!
//! Why: the LAN forwarder had a thread blocked per query in flight, so the
//! misses stopped at `max_concurrent_queries` / RTT (100 / 20 ms = 5 000/s)
//! and a thousand in flight meant a thousand threads (`docs/dns-stress.md`,
//! **medido**). With the state here, the daemon's event loop carries every
//! lookup on a few sockets (as Unbound's `num-queries-per-thread`), and the
//! router's own tools still ask one blocking exchange at a time through
//! [`super::Transport`] ([`super::Resolver::resolve`]). Both run this one
//! copy of the rules:
//!
//! - the servers in order, each for at most `query_server_timeout`, all for
//!   at most `query_total_timeout`; an encrypted one for at least
//!   [`super::SECURE_TIMEOUT_MS`];
//! - a truncated UDP answer is asked again over TCP of the same server
//!   (RFC 7766 §5);
//! - a reply that is not for this query (id, question) is skipped and the
//!   wait goes on (RFC 5452 §9.1);
//! - NOERROR and NXDOMAIN are final; SERVFAIL, REFUSED, a malformed reply or
//!   a transport error move on to the next server.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hickory_proto::rr::RecordType;

use super::flight::Lead;
use super::{
    ResolveError, SECURE_TIMEOUT_MS, Settings, Target, TransportError, Tried, Via, failed, tried,
};
use crate::encrypted::{Proto, SecureServer};
use crate::message::{Answer, QName, ReplyError, check_reply, query};

/// How an [`Exchange`] goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Way {
    Udp,
    /// TCP, after a truncated UDP answer (RFC 1035 §4.2.2 framing).
    Tcp,
    /// DNS over TLS or HTTPS (`encrypted.rs`).
    Secure(SecureServer),
}

/// One message to send, and how long its answer may take.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// Names this exchange in [`Lookup::reply`] and [`Lookup::failed`].
    pub token: u32,
    pub server: SocketAddr,
    pub way: Way,
    /// The query's id (0 for an encrypted server, RFC 8484 §4.1).
    pub id: u16,
    pub query: Vec<u8>,
    pub wait_ms: u64,
}

/// An exchange sent and not answered yet.
#[derive(Debug, Clone)]
struct Try {
    token: u32,
    /// Index in `targets`.
    target: usize,
    ip: IpAddr,
    way: Way,
    id: u16,
    /// When this server was asked (UDP, before a TCP retry): its RTT.
    since_ms: u64,
    until_ms: u64,
    /// How long it was given (the server's RTO then, G4.1u).
    wait_ms: u64,
    /// Past its wait: counted as a timeout and another server asked, but
    /// a late answer to it is still taken (G4.1u).
    expired: bool,
}

/// G4.1u: per server, what this lookup did with it.
#[derive(Debug, Clone, Copy, Default)]
struct Per {
    /// Queries sent (UDP; RFC 9520 §3.1: three at most).
    sent: u32,
    /// A definite failure (SERVFAIL, REFUSED, malformed, unreachable): not
    /// asked again in this lookup.
    dead: bool,
    /// Its retransmission timeout now (RFC 6298; doubled after each
    /// timeout, §5.5).
    rto_ms: u64,
}

/// RFC 9520 §3.1: a query is sent to one server address over one
/// transport at most three times.
pub const MAX_SENDS_PER_SERVER: u32 = 3;

/// One lookup of a name and type, led by this resolver (G4.1o).
#[derive(Debug)]
pub struct Lookup {
    pub(super) qn: QName,
    pub(super) rtype: RecordType,
    pub(super) via: Option<super::Upstreams>,
    pub(super) settings: Arc<Settings>,
    /// Encrypted servers whose address must be looked up first (by the
    /// plain servers): only the blocking driver does that.
    pub(super) unresolved: Vec<SecureServer>,
    pub(super) targets: Vec<Target>,
    /// The RTO each server had when the lookup began (G4.1u).
    pub(super) rtos: Vec<(IpAddr, u64)>,
    per: Vec<Per>,
    /// The next server to ask, in turn.
    cursor: usize,
    sends: u32,
    deadline_ms: u64,
    tries: Vec<Try>,
    seq: u32,
    pub(super) tried: Vec<Tried>,
    pub(super) errors: Vec<String>,
    pub(super) result: Option<Result<(Answer, IpAddr, usize), ResolveError>>,
    /// Publishes the result to the followers (also when dropped).
    pub(super) lead: Option<Lead>,
}

impl Lookup {
    pub(super) fn new(
        qn: QName,
        rtype: RecordType,
        via: Option<super::Upstreams>,
        settings: Arc<Settings>,
        targets: Vec<Target>,
        unresolved: Vec<SecureServer>,
        lead: Option<Lead>,
    ) -> Self {
        Self {
            qn,
            rtype,
            via,
            settings,
            unresolved,
            targets,
            rtos: Vec::new(),
            per: Vec::new(),
            cursor: 0,
            sends: 0,
            deadline_ms: 0,
            tries: Vec::new(),
            seq: 0,
            tried: Vec::new(),
            errors: Vec::new(),
            result: None,
            lead,
        }
    }

    /// The name asked (its lowercase key) and the type.
    pub fn key(&self) -> (&str, RecordType) {
        (&self.qn.key, self.rtype)
    }

    /// Whether it needs a thread: an encrypted server (TLS and HTTP/2 are
    /// blocking streams in the daemon), or one whose address must be
    /// looked up first.
    pub fn needs_thread(&self) -> bool {
        !self.unresolved.is_empty() || self.targets.iter().any(|t| matches!(t, Target::Secure(..)))
    }

    /// Whether an expired answer may be served (`serve_stale` on, G4.1v).
    pub fn serves_stale(&self) -> bool {
        self.settings.stale_secs > 0
    }

    /// The first exchange; the lookup's clock starts now.
    pub fn start(&mut self, now_ms: u64) -> Vec<Exchange> {
        self.deadline_ms = now_ms.saturating_add(u64::from(self.settings.total_timeout_ms));
        self.per = self
            .targets
            .iter()
            .map(|t| Per {
                rto_ms: self
                    .rtos
                    .iter()
                    .find(|(ip, _)| *ip == t.ip())
                    .map_or(super::UNKNOWN_RTT_MS, |(_, rto)| *rto),
                ..Per::default()
            })
            .collect();
        if self.targets.is_empty() {
            self.result = Some(Err(if self.errors.is_empty() {
                ResolveError::NoServers
            } else {
                failed(&self.qn, &self.errors)
            }));
            return Vec::new();
        }
        self.advance(now_ms)
    }

    /// Done: [`super::Resolver::complete`] takes it from here.
    pub fn done(&self) -> bool {
        self.result.is_some()
    }

    /// When [`Self::tick`] has something to do (`None`: done, or nothing
    /// sent).
    pub fn wake_at(&self) -> Option<u64> {
        if self.done() {
            return None;
        }
        self.tries
            .iter()
            .filter(|t| !t.expired)
            .map(|t| t.until_ms)
            .min()
    }

    /// Whether `msg` answers exchange `token` (not a stray: RFC 5452 §9.1).
    pub fn accepts(&self, token: u32, msg: &[u8]) -> bool {
        self.tries.iter().any(|t| {
            t.token == token
                && !matches!(
                    check_reply(t.id, &self.qn.name, self.rtype, msg),
                    Err(ReplyError::Mismatch)
                )
        })
    }

    /// A message came for exchange `token` (also one past its wait, G4.1u).
    pub fn reply(&mut self, token: u32, msg: &[u8], now_ms: u64) -> Vec<Exchange> {
        let Some(i) = self.tries.iter().position(|t| t.token == token) else {
            return Vec::new();
        };
        let Some(t) = self.tries.get(i).cloned() else {
            return Vec::new();
        };
        let tcp = t.way == Way::Tcp;
        match check_reply(t.id, &self.qn.name, self.rtype, msg) {
            // Late, or forged: keep waiting for the real one.
            Err(ReplyError::Mismatch) => Vec::new(),
            Ok(m) => {
                // Each query has its own id: the sample is never ambiguous
                // (RFC 6298 §3, Karn), also for a late answer.
                let rtt = now_ms.saturating_sub(t.since_ms);
                self.tried.push(tried(
                    t.ip,
                    via(&t.way),
                    super::Outcome::Answered(rtt),
                    tcp,
                    t.wait_ms,
                ));
                self.tries.clear();
                self.result = Some(Ok((
                    Answer::from_reply(&self.qn.name, self.rtype, &m),
                    t.ip,
                    msg.len(),
                )));
                Vec::new()
            }
            // RFC 7766 §5: a truncated UDP answer is retried over TCP.
            Err(ReplyError::Truncated) if t.way == Way::Udp => {
                self.tries.remove(i);
                let per = u64::from(self.settings.server_timeout_ms);
                match self.send(t.target, Way::Tcp, t.since_ms, per, now_ms) {
                    Some(x) => vec![x],
                    None => self.advance(now_ms),
                }
            }
            Err(e) => {
                self.tries.remove(i);
                self.server_failed(&t, Ask::Reply(e), now_ms)
            }
        }
    }

    /// Exchange `token` failed in the transport: a timeout the transport
    /// counted itself (the blocking driver), a stream that broke, the
    /// server unreachable.
    pub fn failed(&mut self, token: u32, e: TransportError, now_ms: u64) -> Vec<Exchange> {
        let Some(i) = self.tries.iter().position(|t| t.token == token) else {
            return Vec::new();
        };
        let t = self.tries.remove(i);
        if matches!(e, TransportError::Timeout) && !t.expired {
            return self.timed_out(&t, now_ms);
        }
        self.server_failed(&t, Ask::Transport(e), now_ms)
    }

    /// Time passed: an exchange past its wait counts as a timeout and the
    /// next server is asked; the expired one keeps listening (G4.1u).
    pub fn tick(&mut self, now_ms: u64) -> Vec<Exchange> {
        let mut out = Vec::new();
        while !self.done() {
            let Some(t) = self
                .tries
                .iter_mut()
                .find(|t| !t.expired && t.until_ms <= now_ms)
            else {
                break;
            };
            t.expired = true;
            let t = t.clone();
            out.extend(self.timed_out(&t, now_ms));
        }
        out
    }

    /// The tokens of the exchanges still waiting, expired ones included
    /// (the event loop forgets the others).
    pub fn waiting(&self) -> impl Iterator<Item = u32> + '_ {
        self.tries.iter().map(|t| t.token)
    }

    /// No answer from `t` in its wait: its RTO doubles (RFC 6298 §5.5)
    /// and the lookup moves on.
    fn timed_out(&mut self, t: &Try, now_ms: u64) -> Vec<Exchange> {
        let ceiling = u64::from(self.settings.server_timeout_ms).max(super::RTO_MIN_MS);
        if let Some(p) = self.per.get_mut(t.target) {
            p.rto_ms = p.rto_ms.saturating_mul(2).min(ceiling);
        }
        self.tried.push(tried(
            t.ip,
            via(&t.way),
            super::Outcome::Timeout,
            t.way == Way::Tcp,
            t.wait_ms,
        ));
        self.errors
            .push(describe(t, &Ask::Transport(TransportError::Timeout)));
        // A stream (TCP, TLS) is not asked again (RFC 9520 §3.1 counts per
        // transport; the old wait was already the long one).
        if t.way != Way::Udp
            && let Some(p) = self.per.get_mut(t.target)
        {
            p.dead = true;
        }
        self.advance(now_ms)
    }

    fn server_failed(&mut self, t: &Try, e: Ask, now_ms: u64) -> Vec<Exchange> {
        let outcome = match &e {
            Ask::Transport(TransportError::Timeout) => super::Outcome::Timeout,
            Ask::Reply(ReplyError::ServFail) => super::Outcome::ServFail,
            _ => super::Outcome::Failed,
        };
        if let Some(p) = self.per.get_mut(t.target) {
            p.dead = true;
        }
        self.tried.push(tried(
            t.ip,
            via(&t.way),
            outcome,
            t.way == Way::Tcp,
            t.wait_ms,
        ));
        self.errors.push(describe(t, &e));
        self.advance(now_ms)
    }

    /// The next query, if time and tries are left (G4.1u): the servers in
    /// turn, each at most [`MAX_SENDS_PER_SERVER`] times (an encrypted one
    /// once), at most that many in all unless there are more servers
    /// (each is asked once). Each waits its RTO, the last one the whole
    /// `query_server_timeout`, while the earlier ones still listen. Nothing
    /// left and nothing listening: the lookup failed.
    fn advance(&mut self, now_ms: u64) -> Vec<Exchange> {
        let n = self.targets.len();
        let budget = MAX_SENDS_PER_SERVER.max(u32::try_from(n).unwrap_or(u32::MAX));
        while self.deadline_ms > now_ms && self.sends < budget {
            let next = (0..n).map(|k| (self.cursor + k) % n.max(1)).find(|&i| {
                let (Some(p), Some(t)) = (self.per.get(i), self.targets.get(i)) else {
                    return false;
                };
                let most = match t {
                    Target::Plain(_) => MAX_SENDS_PER_SERVER,
                    Target::Secure(..) => 1,
                };
                !p.dead && p.sent < most
            });
            let Some(i) = next else { break };
            self.cursor = i + 1;
            self.sends += 1;
            if let Some(p) = self.per.get_mut(i) {
                p.sent += 1;
            }
            let Some(target) = self.targets.get(i).cloned() else {
                break;
            };
            let per = u64::from(self.settings.server_timeout_ms);
            let (way, wait) = match target {
                Target::Plain(_) => {
                    // The last query (no other send left) waits it all.
                    let last = self.sends >= budget || !self.another_after();
                    let rto = self.per.get(i).map_or(per, |p| p.rto_ms);
                    let wait = if last {
                        per
                    } else {
                        rto.clamp(super::RTO_MIN_MS, per.max(super::RTO_MIN_MS))
                    };
                    (Way::Udp, wait)
                }
                Target::Secure(_, s) => (Way::Secure(s), per.max(SECURE_TIMEOUT_MS)),
            };
            if let Some(x) = self.send(i, way, now_ms, wait, now_ms) {
                return vec![x];
            }
            if let Some(p) = self.per.get_mut(i) {
                p.dead = true;
            }
        }
        if self.tries.iter().any(|t| !t.expired) {
            return Vec::new();
        }
        if self.deadline_ms <= now_ms {
            self.errors.push("query_total_timeout reached".into());
        }
        self.tries.clear();
        self.result = Some(Err(failed(&self.qn, &self.errors)));
        Vec::new()
    }

    /// Whether a server could still be asked (after the one just counted).
    fn another_after(&self) -> bool {
        self.per.iter().zip(&self.targets).any(|(p, t)| {
            let most = match t {
                Target::Plain(_) => MAX_SENDS_PER_SERVER,
                Target::Secure(..) => 1,
            };
            !p.dead && p.sent < most
        })
    }

    /// One exchange with target `i`, waiting `wait` at most (and never
    /// past the total deadline), or none if no time is left or the query
    /// cannot be built (the error is noted; the caller moves on).
    fn send(
        &mut self,
        i: usize,
        way: Way,
        since_ms: u64,
        wait: u64,
        now_ms: u64,
    ) -> Option<Exchange> {
        let ip = self.targets.get(i)?.ip();
        let left = self.deadline_ms.saturating_sub(now_ms);
        if left == 0 {
            return None;
        }
        let payload = self.settings.udp_payload;
        let built = match &way {
            // RFC 8484 §4.1: id 0; RFC 8467 §4.1: padded.
            Way::Secure(_) => {
                crate::encrypted::query(&self.qn.name, self.rtype, payload).map(|b| (0, b))
            }
            _ => query(&self.qn.name, self.rtype, payload),
        };
        let (id, bytes) = match built {
            Ok(b) => b,
            Err(e) => {
                self.errors.push(format!("{ip}: {e}"));
                return None;
            }
        };
        let port = match &way {
            Way::Secure(s) => s.port,
            _ => self.settings.port,
        };
        let wait = left.min(wait);
        self.seq = self.seq.wrapping_add(1);
        let token = self.seq;
        self.tries.push(Try {
            token,
            target: i,
            ip,
            way: way.clone(),
            id,
            since_ms,
            until_ms: now_ms.saturating_add(wait),
            wait_ms: wait,
            expired: false,
        });
        Some(Exchange {
            token,
            server: SocketAddr::new(ip, port),
            way,
            id,
            query: bytes,
            wait_ms: wait,
        })
    }

    /// The lookup's result so far (for [`super::Resolver::complete`]).
    pub(super) fn take_result(&mut self) -> Result<(Answer, IpAddr, usize), ResolveError> {
        self.result.take().unwrap_or_else(|| {
            Err(ResolveError::Failed {
                name: self.qn.key.clone(),
                why: "the lookup ended without an answer".into(),
            })
        })
    }
}

fn via(way: &Way) -> Via {
    match way {
        Way::Udp | Way::Tcp => Via::Plain,
        Way::Secure(s) => match s.proto {
            Proto::Tls => Via::Tls,
            Proto::Https => Via::Https,
        },
    }
}

fn describe(t: &Try, e: &Ask) -> String {
    match &t.way {
        Way::Secure(s) => format!("{} ({}): {e}", s.url(), t.ip),
        _ => format!("{}: {e}", t.ip),
    }
}

/// Why a server did not give a final answer.
#[derive(Debug, thiserror::Error)]
enum Ask {
    #[error("{0}")]
    Transport(TransportError),
    #[error("{0}")]
    Reply(ReplyError),
}

#[cfg(test)]
mod tests;

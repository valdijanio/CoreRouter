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
    ip: IpAddr,
    way: Way,
    id: u16,
    /// When this server was first asked (UDP, before a TCP retry): its RTT.
    since_ms: u64,
    until_ms: u64,
}

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
    next: usize,
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
            next: 0,
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

    /// The first exchange; the lookup's clock starts now.
    pub fn start(&mut self, now_ms: u64) -> Vec<Exchange> {
        self.deadline_ms = now_ms.saturating_add(u64::from(self.settings.total_timeout_ms));
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
        self.tries.iter().map(|t| t.until_ms).min()
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

    /// A message came for exchange `token`.
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
                let rtt = now_ms.saturating_sub(t.since_ms);
                self.tried
                    .push(tried(t.ip, via(&t.way), super::Outcome::Answered(rtt), tcp));
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
                match self.send(t.ip, Way::Tcp, t.since_ms, now_ms) {
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

    /// Exchange `token` failed in the transport (a stream that broke, a
    /// timeout the transport counted itself).
    pub fn failed(&mut self, token: u32, e: TransportError, now_ms: u64) -> Vec<Exchange> {
        let Some(i) = self.tries.iter().position(|t| t.token == token) else {
            return Vec::new();
        };
        let t = self.tries.remove(i);
        self.server_failed(&t, Ask::Transport(e), now_ms)
    }

    /// Time passed: an exchange past its wait has failed.
    pub fn tick(&mut self, now_ms: u64) -> Vec<Exchange> {
        let mut out = Vec::new();
        while !self.done() {
            let Some(i) = self.tries.iter().position(|t| t.until_ms <= now_ms) else {
                break;
            };
            let t = self.tries.remove(i);
            out.extend(self.server_failed(&t, Ask::Transport(TransportError::Timeout), now_ms));
        }
        out
    }

    /// The tokens of the exchanges still waiting (the event loop forgets
    /// them when the lookup is done).
    pub fn waiting(&self) -> impl Iterator<Item = u32> + '_ {
        self.tries.iter().map(|t| t.token)
    }

    fn server_failed(&mut self, t: &Try, e: Ask, now_ms: u64) -> Vec<Exchange> {
        let tcp = t.way == Way::Tcp;
        let outcome = match &e {
            Ask::Transport(TransportError::Timeout) => super::Outcome::Timeout,
            Ask::Reply(ReplyError::ServFail) => super::Outcome::ServFail,
            _ => super::Outcome::Failed,
        };
        self.tried.push(tried(t.ip, via(&t.way), outcome, tcp));
        self.errors.push(match &t.way {
            Way::Secure(s) => format!("{} ({}): {e}", s.url(), t.ip),
            _ => format!("{}: {e}", t.ip),
        });
        self.advance(now_ms)
    }

    /// The next server, if time is left.
    fn advance(&mut self, now_ms: u64) -> Vec<Exchange> {
        while let Some(target) = self.targets.get(self.next).cloned() {
            self.next += 1;
            if self.deadline_ms <= now_ms {
                break;
            }
            let ip = target.ip();
            let way = match target {
                Target::Plain(_) => Way::Udp,
                Target::Secure(_, s) => Way::Secure(s),
            };
            if let Some(x) = self.send(ip, way, now_ms, now_ms) {
                return vec![x];
            }
        }
        if self.deadline_ms <= now_ms {
            self.errors.push("query_total_timeout reached".into());
        }
        self.result = Some(Err(failed(&self.qn, &self.errors)));
        Vec::new()
    }

    /// One exchange with `ip`, or none if no time is left or the query
    /// cannot be built (the error is noted; the caller moves on).
    fn send(&mut self, ip: IpAddr, way: Way, since_ms: u64, now_ms: u64) -> Option<Exchange> {
        let left = self.deadline_ms.saturating_sub(now_ms);
        if left == 0 {
            return None;
        }
        let per = u64::from(self.settings.server_timeout_ms);
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
        let (port, wait) = match &way {
            Way::Secure(s) => (s.port, left.min(per.max(SECURE_TIMEOUT_MS))),
            _ => (self.settings.port, left.min(per)),
        };
        self.seq = self.seq.wrapping_add(1);
        let token = self.seq;
        self.tries.push(Try {
            token,
            ip,
            way: way.clone(),
            id,
            since_ms,
            until_ms: now_ms.saturating_add(wait),
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

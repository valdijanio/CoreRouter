//! The upstream servers, through the shared resolver (failover, fastest
//! server, TCP on truncation, serve-stale: `resolver.rs`). The only stage
//! that waits on the network. G4.1t: the daemon's event loop runs the
//! lookup ([`crate::server::Forwarder::upstream`]) and brings the result
//! back ([`crate::server::Forwarder::resume`]); a blocking caller (the
//! router's DNS Lookup) runs it here with a transport. Every server
//! failing, with nothing stale to serve, is SERVFAIL (RFC 1035 §4.1.1
//! RCODE 2); so is a lookup past `max_concurrent_queries` ("busy").

use hickory_proto::op::ResponseCode;

use crate::resolver::{ResolveError, Resolved, Source, Transport};
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "upstream",
    order: 90,
    handle,
    after: None,
};

fn handle(f: &Forwarder, q: &mut Query, t: Option<&mut dyn Transport>) -> Step {
    if let Some(got) = q.upstream.take() {
        return decide(q, got, None);
    }
    let Some(t) = t else { return Step::Wait };
    let held = if q.explaining() {
        f.resolver.held_secs(&q.name.key, q.qtype, t.now_ms())
    } else {
        None
    };
    let got = f
        .resolver
        .resolve(t, &q.name, q.qtype, q.forward_to.as_ref());
    decide(q, got, held)
}

/// The reply for the resolver's result `got` (`held`: seconds a failure
/// stays held, when explaining).
fn decide(q: &mut Query, got: Result<Resolved, ResolveError>, held: Option<u64>) -> Step {
    match got {
        Err(ResolveError::Busy) => {
            q.busy = true;
            q.note(|| Note::new("upstream.failed").arg("why", ResolveError::Busy.to_string()));
            Step::Reply(Reply::code(ResponseCode::ServFail))
        }
        Ok(r) => {
            q.source = Some(r.source);
            let via = match &q.forward_to {
                Some(_) => " (the servers a static entry or zone named)",
                None => "",
            };
            q.note(|| match r.source {
                Source::Server(ip) => Note::new("upstream.server").arg("server", ip).arg("via", via),
                Source::Cache => Note::new("upstream.cached"),
                Source::Stale => Note::new("upstream.stale"),
            });
            Step::Reply(Reply::from_answer(&r.answer))
        }
        Err(e) => {
            // RFC 8914: a failure held by RFC 9520 (no server asked) is a
            // Cached Error (13); every server failing, No Reachable
            // Authority (22).
            let cached = held.is_some()
                || matches!(&e, crate::resolver::ResolveError::Failed { why, .. } if why.contains("RFC 9520"));
            q.ede = Some(if cached {
                super::statistics::EDE_CACHED_ERROR
            } else {
                super::statistics::EDE_NO_REACHABLE_AUTHORITY
            });
            q.note(|| match held {
                Some(secs) => Note::new("upstream.held").arg("secs", secs),
                None => {
                    let why: String = e.to_string().chars().take(200).collect();
                    Note::new("upstream.failed").arg("why", why)
                }
            });
            Step::Reply(Reply::code(ResponseCode::ServFail))
        }
    }
}

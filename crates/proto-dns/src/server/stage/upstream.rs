//! The upstream servers, through the shared resolver (failover, fastest
//! server, TCP on truncation, serve-stale: `resolver.rs`). The only stage
//! that waits on the network: it runs on a worker. Every server failing,
//! with nothing stale to serve, is SERVFAIL (RFC 1035 §4.1.1 RCODE 2).

use hickory_proto::op::ResponseCode;

use crate::resolver::{Source, Transport};
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "upstream",
    order: 90,
    handle,
    after: None,
};

fn handle(f: &Forwarder, q: &mut Query, t: Option<&mut dyn Transport>) -> Step {
    let Some(t) = t else { return Step::Wait };
    let held = if q.explaining() {
        f.resolver.held_secs(&q.name.key, q.qtype, t.now_ms())
    } else {
        None
    };
    match f
        .resolver
        .resolve(t, &q.name, q.qtype, q.forward_to.as_ref())
    {
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

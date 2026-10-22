//! The upstream servers, through the shared resolver (failover, fastest
//! server, TCP on truncation, serve-stale: `resolver.rs`). The only stage
//! that waits on the network: it runs on a worker. Every server failing,
//! with nothing stale to serve, is SERVFAIL (RFC 1035 §4.1.1 RCODE 2).

use hickory_proto::op::ResponseCode;

use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::resolver::Transport;

pub(crate) const STAGE: Stage = Stage {
    name: "upstream",
    order: 90,
    handle,
    after: None,
};

fn handle(f: &Forwarder, q: &mut Query, t: Option<&mut dyn Transport>) -> Step {
    let Some(t) = t else { return Step::Wait };
    match f
        .resolver
        .resolve(t, &q.name, q.qtype, q.forward_to.as_ref())
    {
        Ok(r) => {
            q.source = Some(r.source);
            Step::Reply(Reply::from_answer(&r.answer))
        }
        Err(_) => Step::Reply(Reply::code(ResponseCode::ServFail)),
    }
}

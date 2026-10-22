//! The cache shared with the router's own lookups (G4.1a): a fresh answer
//! goes back at once, on the listener's thread, with its TTL counted down.
//! Answers got through a static FWD entry are cached like any other
//! (RouterOS does the same).

use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::resolver::{Source, Transport};

pub(crate) const STAGE: Stage = Stage {
    name: "cache",
    order: 60,
    handle,
    after: None,
};

fn handle(f: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    match f.resolver.cached(&q.name.key, q.qtype, q.now_ms) {
        Some(hit) => {
            q.source = Some(Source::Cache);
            Step::Reply(Reply::from_answer(&hit.answer))
        }
        None => Step::Next,
    }
}

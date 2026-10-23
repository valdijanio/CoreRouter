//! The cache shared with the router's own lookups (G4.1a): a fresh answer
//! goes back at once, on the listener's thread, with its TTL counted down.
//! Answers got through a static FWD entry are cached like any other
//! (RouterOS does the same).

use crate::resolver::{Source, Transport};
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

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
            let ttl = hit.answer.records.iter().map(|r| r.ttl).min().unwrap_or(0);
            q.note(|| Note::new("cache.hit").arg("ttl", ttl));
            Step::Reply(Reply::from_answer(&hit.answer))
        }
        None => {
            q.note(|| Note::new("cache.miss"));
            Step::Next
        }
    }
}

//! L2 — DNS for the router itself (G4.1a): a stub resolver over
//! `hickory-proto` messages, with a TTL cache and server failover. The LAN
//! forwarder (G4.1b) and the full server on `hickory-server` (G4.1c) build
//! on the same cache and config (`/ip dns`, docs/architecture.md "DNS").
//! PTR and the Team Cymru TXT answers give MTR hops a name and an AS
//! number (G6.3b).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod asn;
pub mod cache;
pub mod message;
pub mod resolver;
pub mod reverse;

use corerouter_model::{Config, Issue};

/// Validate `/ip dns` in the candidate.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    cfg.ip
        .dns
        .problem()
        .map(|m| Issue::new("ip.dns", m))
        .into_iter()
        .collect()
}

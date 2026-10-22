//! L2 — DNS resolver/cache and static records.
//!
//! Scope: forwarders, cache, static records, DoT/DoH upstreams; runtime on
//! `hickory-server` + `hickory-resolver` embedded in the daemon (G4.1).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use corerouter_model::{Config, Issue};

/// Validate this subsystem's part of the candidate. No config section exists
/// yet, so there is nothing to reject.
pub fn validate(_cfg: &Config) -> Vec<Issue> {
    Vec::new()
}

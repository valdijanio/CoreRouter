//! L2 — MPLS/LDP config model, label ranges, validation.
//!
//! Scope: label ranges, LDP (transport address, neighbors), static LSPs,
//! VPLS later; kernel MPLS routes via netlink, LDP via FRR `ldpd` (G3.5).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use corerouter_model::{Config, Issue};

/// Validate this subsystem's part of the candidate. No config section exists
/// yet, so there is nothing to reject.
pub fn validate(_cfg: &Config) -> Vec<Issue> {
    Vec::new()
}

//! L2 — CGNAT policies (NAT44, port-block allocation, deterministic NAT).
//!
//! Scope: inside/outside pools, port-block allocation (RFC 6888/7422),
//! deterministic mapping, logging; rendered to nftables (G2.3) and later to the
//! XDP fast path in `dataplane-ebpf` (G2.5).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use corerouter_model::{Config, Issue};

/// Validate this subsystem's part of the candidate. No config section exists
/// yet, so there is nothing to reject.
pub fn validate(_cfg: &Config) -> Vec<Issue> {
    Vec::new()
}

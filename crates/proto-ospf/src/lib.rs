//! L2 — OSPFv2/OSPFv3 config model, validation and rendering.
//!
//! Scope: areas, interfaces, costs, stub/NSSA, authentication; rendered to the
//! FRR `ospfd`/`ospf6d` backend (docs/gaps.md G3.4). Simulator FSM for the lab.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use corerouter_model::{Config, Issue};

/// Validate this subsystem's part of the candidate. No config section exists
/// yet, so there is nothing to reject.
pub fn validate(_cfg: &Config) -> Vec<Issue> {
    Vec::new()
}

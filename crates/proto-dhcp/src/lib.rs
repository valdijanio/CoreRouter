//! L2 — DHCPv4/DHCPv6 server and relay.
//!
//! Scope: pools, leases, options, relay, DHCPv6-PD; packet codec `dhcproto`,
//! lease database owned by the daemon (G4.2).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

use corerouter_model::{Config, Issue};

/// Validate this subsystem's part of the candidate. No config section exists
/// yet, so there is nothing to reject.
pub fn validate(_cfg: &Config) -> Vec<Issue> {
    Vec::new()
}

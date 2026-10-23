//! L2 — CGNAT policies (G2.3): what a pool definition gets wrong.
//!
//! The mapping itself (subscriber → public address and ports) is
//! `corerouter_model::cgnat::Layout`, shared with the kernel backend and
//! the XDP path, and the rules they become are `corerouter_firewall::cgnat`
//! (L1, so `hal-linux` renders them too); this crate checks the pools
//! against each other and the rest of the config ([`checks`]).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod checks;

use corerouter_model::{Config, Issue};

/// The errors of [`checks::checks`]: the engine refuses the commit.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    checks::checks(cfg)
        .into_iter()
        .filter(|c| c.level == checks::Level::Error)
        .map(|c| Issue::new(c.path, c.text))
        .collect()
}

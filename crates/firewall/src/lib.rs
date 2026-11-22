//! L1 (pure, no I/O) — the firewall's rules about rules.
//!
//! - [`validate`]: what makes a firewall config wrong (action not valid in
//!   that chain, ports without a protocol that has ports, jump loops…), used
//!   by the engine before every commit and, per rule, by the commands.
//! - [`eval`]: which rule decides a packet (the engine's lockout check).
//! - [`path`]: the way of one packet through every table (`ip.firewall.test`).
//! - [`shadow`]: rules an earlier rule makes unreachable.
//! - [`diff`]: line diff of two rulesets (the Diff tab).
//! - [`describe`]: a rule in plain Portuguese, for the GUI.
//! - [`nft`]: the nftables ruleset for a config, in table `inet corerouter`
//!   only (rules of other owners are never touched). `hal-linux` applies it
//!   atomically; the engine shows it (preview).
//! - [`cgnat`]: the CGNAT pools as table `ip corerouter_cgnat` (G2.3), a
//!   [`program::Table`]: the nftables objects as data, which `hal-linux`
//!   sends over nfnetlink and the GUI prints.
//! - [`fastpath`]: the flowtable as table `inet corerouter_fastpath` (G2.4).
//! - [`notice`]: the subscriber notices' chains (G4.10), in `inet corerouter`.
//!
//! It sits in L1 instead of L2 (`proto-*`) because `hal-linux` (L1) must
//! render too and may not depend upward; it compiles everywhere (wasm too).

pub mod bytecode;
pub mod cgnat;
pub mod describe;
pub mod diff;
pub mod eval;
pub mod fastpath;
pub mod graph;
pub mod nft;
pub mod notice;
pub mod path;
pub mod program;
pub mod sample;
pub mod shadow;
pub mod validate;

pub use nft::{TABLE, render, script};
pub use validate::{rule_issues, table_issues, validate};

//! L1 — Hardware/OS abstraction.
//!
//! The engine only talks to `dyn Hal`. Real backends (`hal-linux` netlink,
//! future `hal-frr`, `dataplane-ebpf`) live in platform crates that only the
//! apps (L6) may depend on; `VirtualHal` runs everywhere, including wasm, CI,
//! Windows, macOS and iOS, without root.

pub mod probe;
pub mod sim;
pub mod virt;

use corerouter_model::{Config, IfName};
use serde::Serialize;

pub use probe::{Prober, SharedProber};
pub use sim::SimProber;
pub use virt::VirtualHal;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HalError {
    #[error("not supported by this backend: {0}")]
    Unsupported(String),
    #[error("backend rejected the change: {0}")]
    Rejected(String),
    #[error("I/O error: {0}")]
    Io(String),
}

/// A physical (or virtual) port discovered on the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkInfo {
    pub name: IfName,
    pub mac: Option<String>,
    pub mtu: u16,
}

/// Live operational state of a link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkState {
    pub name: IfName,
    pub running: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Why `ip.vrf.add` is disabled, and what a failed `vrf` link create means.
pub const NO_VRF: &str = "this kernel has no VRF support (CONFIG_NET_VRF / module vrf)";

/// What the platform can do, so a command can refuse up front (with the
/// reason) instead of failing at apply time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Features {
    /// VRF devices (Linux: `CONFIG_NET_VRF`, module `vrf`).
    pub vrf: bool,
}

impl Default for Features {
    /// Everything: a backend that does not probe lets `apply` say no.
    fn default() -> Self {
        Self { vrf: true }
    }
}

pub trait Hal: Send {
    /// Human/agent readable description: "virtual lab (8 ports)", "linux netlink".
    fn describe(&self) -> String;

    /// Ports present on the platform (used to seed the default config).
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError>;

    /// Apply the transition `from` → `to`. Must be all-or-nothing: on `Err`
    /// the platform is left as `from`.
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError>;

    /// Sample live link state/counters.
    fn poll(&mut self) -> Vec<LinkState>;

    /// Wall clock in seconds since the Unix epoch, if the platform has one.
    fn now_unix(&self) -> Option<u64>;

    /// What this platform supports. Cheap after the first call: backends
    /// that probe the kernel do it once and cache the answer.
    fn features(&self) -> Features {
        Features::default()
    }

    /// ICMP prober for the diagnostic tools (ping, MTU, MTR), or why there
    /// is none. Cheap: backends build it once and hand out clones.
    fn prober(&self) -> Result<SharedProber, String> {
        Err(format!("{} cannot send probes", self.describe()))
    }
}

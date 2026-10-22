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

/// A port the platform lets CoreRouter manage (used to seed the default
/// config). Links CoreRouter must not touch are never `LinkInfo`s; they
/// show up only in [`Hal::poll`], with [`LinkState::unmanaged`] set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkInfo {
    pub name: IfName,
    pub mac: Option<String>,
    pub mtu: u16,
    /// Administratively up: the seed sets `disabled = !up`, so the first
    /// apply changes nothing in the kernel.
    pub up: bool,
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
    /// What the platform says the link is: `ether` (a physical port),
    /// `veth`, `bridge`, `vlan`, `loopback`, `dummy`, `ppp`, `tun`, …
    pub kind: String,
    /// `u32` like the kernel (`lo` has 65536).
    pub mtu: u32,
    pub mac: Option<String>,
    /// `Some(why)`: a link CoreRouter did not create and must not manage
    /// (another program's bridge, a container's veth, the host `lo`…).
    /// It is listed, never applied to, and commands refuse to change it.
    pub unmanaged: Option<String>,
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

    /// Links present on the platform that CoreRouter must not change, with
    /// the reason (see [`LinkState::unmanaged`]). Commands check it before
    /// touching a name; the default (virtual lab) has none.
    fn unmanaged(&mut self) -> Vec<(IfName, String)> {
        Vec::new()
    }

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

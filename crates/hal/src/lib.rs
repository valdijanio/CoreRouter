//! L1 — Hardware/OS abstraction.
//!
//! The engine only talks to `dyn Hal`. Real backends (`hal-linux` netlink,
//! future `hal-frr`, `dataplane-ebpf`) live in platform crates that only the
//! apps (L6) may depend on; `VirtualHal` runs everywhere, including wasm, CI,
//! Windows, macOS and iOS, without root.

pub mod address_state;
pub mod capture;
pub mod cgnat;
pub mod conntrack;
pub mod dhcp;
pub mod dhcp_server;
pub mod drift;
pub mod fastpath;
pub mod icmp_ext;
pub mod lab_conntrack;
pub mod lab_flow;
pub mod nic;
pub mod probe;
pub mod resources;
pub mod route_get;
pub mod sff;
pub mod sim;
pub mod tuning;
pub mod virt;
pub mod xdp;
pub mod xdp_nat;

use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, IfName};
use serde::Serialize;

pub use dhcp::{
    Dhcp6Port, Dhcp6Responder, DhcpPort, DhcpResponder, SharedResponder, SharedResponder6,
};
pub use nic::{
    CablePair, CableTest, CableTestResult, Counter, CounterGroup, EthernetMonitor, LinkCounters,
    NicHardware, Offload,
};
pub use probe::{Prober, SharedProber};
pub use sff::SfpModule;
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
    /// Error and drop counters when the poll already carries them (Linux:
    /// `IFLA_STATS64`), so `system.metrics` needs no per-link query.
    /// `None`: ask `counters` (or the platform does not count them).
    #[serde(skip)]
    pub errors: Option<LinkErrors>,
}

/// The four error/drop counters `system.metrics` exports per link, named
/// as in the platform's `interface` counter group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkErrors {
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
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

/// Something the platform learned from IPv6 Router Advertisements (or
/// set up on its own) on a managed interface, outside the config: a SLAAC
/// address or a route of `proto ra`. Shown with flag D by the lists
/// (G4.7b); never applied by CoreRouter, removed by the platform when RA is
/// no longer accepted there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Learned {
    Address {
        interface: IfName,
        address: ipnet::Ipv6Net,
        /// Seconds left; `None`: forever.
        valid_secs: Option<u32>,
        preferred_secs: Option<u32>,
    },
    Route {
        interface: IfName,
        dst: ipnet::Ipv6Net,
        gateway: Option<std::net::Ipv6Addr>,
        /// Kernel metric (RA default routes: 1024).
        metric: u32,
        /// Kernel table id.
        table: u32,
        expires_secs: Option<u32>,
    },
}

/// A change to the dynamic address-list entries (G2.1): entries with a
/// timeout, which live in the data plane only (never in the config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicChange<'a> {
    Add(&'a DynamicAddress),
    Remove(&'a DynamicAddress),
    /// Their timeout ran out: the data plane's own timer already dropped
    /// them (the kernel set has the same timeout), so a backend only
    /// forgets them; all of one tick in one call.
    Expired(&'a [DynamicAddress]),
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

    /// Seconds on a clock that only moves forward at a steady rate (an NTP
    /// step does not move it), from any fixed origin, if the platform has
    /// one. Deadlines (the Safe Mode timeout) follow it rather than the
    /// wall clock. Default: none (deadlines fall back to the wall clock).
    fn monotonic_secs(&self) -> Option<u64> {
        None
    }

    /// What this platform supports. Cheap after the first call: backends
    /// that probe the kernel do it once and cache the answer.
    fn features(&self) -> Features {
        Features::default()
    }

    /// Add or remove one dynamic address-list entry in the data plane,
    /// which expires it by itself. `apply` keeps the ones present.
    fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
        let _ = change;
        Ok(())
    }

    /// ICMP prober for the diagnostic tools (ping, MTU, MTR), or why there
    /// is none. Cheap: backends build it once and hand out clones.
    fn prober(&self) -> Result<SharedProber, String> {
        Err(format!("{} cannot send probes", self.describe()))
    }

    /// Packet capture for Torch and the sniffer (G6.4a), shared with task
    /// threads; `Err(why)` when this backend has none.
    fn packet_capture(&self) -> Result<capture::SharedCapture, String> {
        Err(format!("{} cannot capture packets", self.describe()))
    }

    /// Live Ethernet state of `name` (G1.19). Fields the driver does not
    /// report are `None`; `Unsupported` means nothing at all.
    fn ethernet_monitor(&mut self, name: &IfName) -> Result<EthernetMonitor, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no Ethernet state for '{name}'",
            self.describe()
        )))
    }

    /// The NIC behind `name`: ids, driver, queues, rings, offloads (G1.19).
    fn hardware(&mut self, name: &IfName) -> Result<NicHardware, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no hardware details for '{name}'",
            self.describe()
        )))
    }

    /// Every counter of `name` the platform has, by group (G1.19).
    fn counters(&mut self, name: &IfName) -> Result<LinkCounters, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no counters for '{name}'",
            self.describe()
        )))
    }

    /// The pluggable module in `name`'s cage, decoded (G1.20). An empty
    /// cage is `Ok` with `module_present: false`; a port without a cage
    /// is `Unsupported`.
    fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        Err(HalError::Unsupported(format!(
            "{} reads no module EEPROM for '{name}'",
            self.describe()
        )))
    }

    /// A cable test of `name`, to run on a task thread (G1.20): building it
    /// is cheap and checks what can be checked up front.
    fn cable_tester(&mut self, name: &IfName) -> Result<Box<dyn CableTest>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} cannot test the cable of '{name}'",
            self.describe()
        )))
    }

    /// Open the DHCP client socket of interface `name` (G4.7).
    fn dhcp_port(&mut self, name: &IfName) -> Result<Box<dyn DhcpPort>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCP client transport (asked for '{name}')",
            self.describe()
        )))
    }

    /// The simulated DHCP server of the lab, offered by the engine at
    /// start-up. A backend on a real network ignores it; the virtual lab
    /// uses it unless it already has one (a test's own).
    fn offer_dhcp_lab_server(&mut self, server: SharedResponder) {
        let _ = server;
    }

    /// Open the DHCP server socket of interface `name` (G4.2a).
    fn dhcp_server_port(
        &mut self,
        name: &IfName,
    ) -> Result<Box<dyn dhcp_server::DhcpServerPort>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCP server transport (asked for '{name}')",
            self.describe()
        )))
    }

    /// Open the DHCP relay's socket towards the servers (G4.2b).
    fn dhcp_relay_uplink(&mut self) -> Result<Box<dyn dhcp_server::DhcpUplink>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCP relay transport (only servers on the router itself)",
            self.describe()
        )))
    }

    /// Open the DHCPv6 server socket of interface `name` (G4.2c).
    fn dhcp6_server_port(
        &mut self,
        name: &IfName,
    ) -> Result<Box<dyn dhcp_server::Dhcp6ServerPort>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCPv6 server transport (asked for '{name}')",
            self.describe()
        )))
    }

    /// The DHCPv6 relay's socket towards the servers (G4.2c).
    fn dhcp6_relay_uplink(&mut self) -> Result<Box<dyn dhcp_server::Dhcp6Uplink>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCPv6 relay transport",
            self.describe()
        )))
    }

    /// The lab's simulated DHCPv6 clients (G4.2c).
    fn offer_dhcp6_lab_clients(&mut self, hosts: dhcp_server::SharedLabClients6) {
        let _ = hosts;
    }

    /// The lab's simulated DHCP clients (G4.2a), offered by the engine like
    /// [`Hal::offer_dhcp_lab_server`].
    fn offer_dhcp_lab_clients(&mut self, hosts: dhcp_server::SharedLabClients) {
        let _ = hosts;
    }

    /// Open the DHCPv6 client socket of interface `name` (G4.7b).
    fn dhcp6_port(&mut self, name: &IfName) -> Result<Box<dyn Dhcp6Port>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCPv6 client transport (asked for '{name}')",
            self.describe()
        )))
    }

    /// The lab's simulated DHCPv6 server (see [`Hal::offer_dhcp_lab_server`]).
    fn offer_dhcp6_lab_server(&mut self, server: SharedResponder6) {
        let _ = server;
    }

    /// IPv6 state learned from Router Advertisements on managed interfaces
    /// (G4.7b). Which interfaces accept RA follows the applied config
    /// (`corerouter_model::ipv6::ra_mode`).
    fn ipv6_learned(&mut self) -> Result<Vec<Learned>, HalError> {
        Ok(Vec::new())
    }

    /// The kernel's states of the managed addresses that are not plainly
    /// usable (G1.28): tentative or failed IPv6 DAD, deprecated. Default:
    /// nothing to report (the virtual lab runs no DAD).
    fn address_states(&mut self) -> Result<Vec<address_state::AddressState>, HalError> {
        Ok(Vec::new())
    }

    /// Where the data plane sends a packet to `q.dst` (G1.27, Linux
    /// `RTM_GETROUTE`, see [`route_get`]); `cfg` is the applied config.
    fn route_get(
        &mut self,
        cfg: &Config,
        q: &route_get::RouteQuery,
    ) -> Result<route_get::KernelLookup, HalError> {
        let _ = (cfg, q);
        Err(HalError::Unsupported(format!(
            "{} cannot look routes up",
            self.describe()
        )))
    }

    /// What the data plane holds now of what `cfg` (the applied config)
    /// manages, for the drift check (G1.3, see [`drift`]).
    fn snapshot(&mut self, cfg: &Config) -> Result<drift::Snapshot, HalError> {
        let _ = cfg;
        Err(HalError::Unsupported(format!(
            "{} cannot read its state back",
            self.describe()
        )))
    }

    /// Put back, where it drifted, what `cfg` (the applied config) puts in
    /// the data plane. All or nothing, like `apply`; a port that is gone
    /// is left to come back by itself.
    fn reconcile(&mut self, cfg: &Config) -> Result<(), HalError> {
        let _ = cfg;
        Err(HalError::Unsupported(format!(
            "{} cannot reconcile",
            self.describe()
        )))
    }

    /// The machine, for System › Tuning (G1.26, [`tuning`]).
    fn system_info(&mut self) -> Result<tuning::SystemInfo, HalError> {
        Err(HalError::Unsupported(format!(
            "{} does not describe the machine",
            self.describe()
        )))
    }

    /// The current value of kernel parameters `names` (catalog names of
    /// `corerouter_model::tuning`).
    fn sysctls(&mut self, names: &[&str]) -> Result<tuning::Sysctls, HalError> {
        let _ = names;
        Err(HalError::Unsupported(format!(
            "{} has no kernel parameters",
            self.describe()
        )))
    }

    /// Port `name`'s tuning settings (rings, queues, coalescing,
    /// transmit queue, `rp_filter`) and the NIC's maxima (G1.26b).
    fn port_tuning(&mut self, name: &IfName) -> Result<tuning::PortTuning, HalError> {
        let _ = name;
        Err(HalError::Unsupported(format!(
            "{} has no port settings",
            self.describe()
        )))
    }

    /// The CPU settings: governor, C-state limit, watchdog (G1.26c).
    fn cpu_tuning(&mut self) -> Result<tuning::CpuTuning, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no CPU settings",
            self.describe()
        )))
    }

    /// The kernel command line the system booted with (G1.26d).
    fn boot_cmdline(&mut self) -> Result<String, HalError> {
        Err(HalError::Unsupported(format!(
            "{} does not say how it booted",
            self.describe()
        )))
    }

    /// IP › Firewall › XDP (G2.5a): where the filter is attached, its
    /// counters and the most dropped sources (`top` of them).
    fn xdp_status(&mut self, top: usize) -> Result<xdp::XdpStatus, HalError> {
        let _ = top;
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// Zero the XDP counters and forget the dropped sources.
    fn xdp_reset(&mut self) -> Result<(), HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// Counters behind the tuning diagnosis.
    fn kernel_stats(&mut self) -> Result<tuning::KernelStats, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no kernel counters",
            self.describe()
        )))
    }

    /// The connection tracking table (G2.2), at most `conntrack::MAX_READ`.
    fn connections(&mut self) -> Result<Vec<conntrack::Conn>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking",
            self.describe()
        )))
    }

    /// How full the table is and its trouble counters (G2.2).
    fn connection_stats(&mut self) -> Result<conntrack::Stats, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking",
            self.describe()
        )))
    }

    /// Set or remove CGNAT port blocks (G2.3c): elements of a blocks-mode
    /// pool's map, kept across a replace of the table.
    fn cgnat_blocks(&mut self, changes: &[cgnat::BlockChange]) -> Result<(), HalError> {
        let _ = changes;
        Err(HalError::Unsupported(format!(
            "{} has no CGNAT data plane",
            self.describe()
        )))
    }

    /// Subscribers of blocks-mode pools that want a block and have no
    /// queue to ask through (the lab's pretend online subscribers).
    fn cgnat_waiting(&mut self) -> Vec<cgnat::Waiting> {
        Vec::new()
    }

    /// What port `name`'s card offers the fast path (G2.4).
    fn eswitch(&mut self, name: &IfName) -> Result<fastpath::Eswitch, HalError> {
        Err(HalError::Unsupported(format!(
            "{} cannot tell what '{name}' offloads",
            self.describe()
        )))
    }

    /// The fast path as the last apply installed it (G2.4).
    fn fastpath_state(&mut self) -> fastpath::FastPathState {
        fastpath::FastPathState::default()
    }

    /// The queue of first packets of subscribers without a block (G2.3c).
    fn cgnat_queue(&mut self) -> Result<Box<dyn cgnat::CgnatQueue>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no packet queue",
            self.describe()
        )))
    }

    /// Remove these connections; how many went (G2.2).
    fn connections_kill(&mut self, conns: &[conntrack::Conn]) -> Result<usize, HalError> {
        let _ = conns;
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking",
            self.describe()
        )))
    }

    /// CPU, memory and conntrack readings for the graphs (G4.5), taken
    /// every second: `None` where the platform has none.
    fn resources(&mut self) -> Option<resources::Resources> {
        None
    }

    /// A live feed of conntrack events for the flow exporter (G4.4b).
    fn conntrack_events(&mut self) -> Result<Box<dyn conntrack::EventSource>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking events",
            self.describe()
        )))
    }
}

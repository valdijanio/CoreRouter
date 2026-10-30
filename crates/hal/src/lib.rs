//! L1 — Hardware/OS abstraction.
//!
//! The engine only talks to `dyn Hal` (and `dyn routing::RoutingDaemon`).
//! Real backends (`hal-linux` netlink, `hal-frr`, `dataplane-ebpf`) live in
//! platform crates that only the apps (L6) may depend on; `VirtualHal` runs
//! everywhere, including wasm, CI, Windows, macOS and iOS, without root.

pub mod absent;
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
pub mod lab_neigh;
pub mod link_reader;
pub mod lsp;
pub mod mpls;
pub mod neigh;
pub mod nic;
pub mod oslog;
pub mod pppoe;
pub mod pppoe_client;
pub mod probe;
pub mod queue;
pub mod resources;
pub mod route_get;
pub mod routing;
pub mod sff;
pub mod sim;
pub mod system_resource;
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

/// A firewall rule ([`Hal::check_firewall`]) or a static route
/// ([`Hal::apply_routes_each`]) the data plane refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RefusedItem {
    pub id: corerouter_model::ItemId,
    pub reason: String,
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
    /// The bus of the device behind the link (`pci`, `usb`, `virtio`), as
    /// the platform's link dump carries it (Linux: `IFLA_PARENT_DEV_BUS_NAME`);
    /// `None` for software links. Lets `interface.list` mark USB adapters
    /// (G1.29b) without a per-port query.
    #[serde(skip)]
    pub bus: Option<String>,
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
    /// MPLS forwarding (G3.5, Linux: module `mpls_router`).
    pub mpls: bool,
}

impl Default for Features {
    /// Everything: a backend that does not probe lets `apply` say no.
    fn default() -> Self {
        Self {
            vrf: true,
            mpls: true,
        }
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

    /// G1.3g: whether `to`'s firewall would load, checked without loading
    /// anything (nftables' `--check`: the kernel validates the batch and
    /// throws it away). `Ok`: the first rule it refuses, by id, with the
    /// kernel's reason (empty: it loads whole); the rules after a refused
    /// one may be refused only because of it, so the caller takes that one
    /// out and checks again. `Err(Rejected)`: refused
    /// without naming a rule. The default cannot check (`Unsupported`):
    /// the boot then leaves a refused firewall out whole (G1.3e).
    fn check_firewall(&mut self, to: &Config) -> Result<Vec<RefusedItem>, HalError> {
        let _ = to;
        Err(HalError::Unsupported(
            "checking a firewall without loading it".into(),
        ))
    }

    /// G1.3g: add the static routes `to` has and `from` lacks one at a
    /// time, keeping each one the kernel takes (no undo): the boot's
    /// `routes` section, since routes have no dry run. Only when nothing
    /// but added routes separates the two; `Ok`: the routes refused, by
    /// id, with the kernel's reason. The default cannot
    /// (`Unsupported`): the caller applies the section whole.
    fn apply_routes_each(
        &mut self,
        from: &Config,
        to: &Config,
    ) -> Result<Vec<RefusedItem>, HalError> {
        let _ = (from, to);
        Err(HalError::Unsupported("adding routes one at a time".into()))
    }

    /// Sample live link state/counters.
    fn poll(&mut self) -> Vec<LinkState>;

    /// A reader of the links that runs with the session unlocked (G1.3f,
    /// see [`link_reader`]); `None` (the default): this backend reads them
    /// cheaply, [`Hal::poll`] it is.
    fn link_reader(&self) -> Option<Box<dyn link_reader::LinkReader>> {
        None
    }

    /// [`Hal::poll`] with the links a [`Hal::link_reader`] read. `None`:
    /// the sample is older than a change of the hal (an `apply` since the
    /// reader was made); poll instead.
    fn poll_sample(&mut self, sample: link_reader::LinkSample) -> Option<Vec<LinkState>> {
        let _ = sample;
        Some(self.poll())
    }

    /// Physical ports of the applied config that the platform does not
    /// have (G1.3b, see [`absent`]): `apply` left them out and puts their
    /// configuration back on the first `apply` after they return. The
    /// default (a backend whose ports never go away) has none.
    fn absent_ports(&self) -> Vec<IfName> {
        Vec::new()
    }

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

    /// Many [`Hal::address_list_dynamic`] changes in one go (the PPP
    /// service adds one per subscriber that logs in: one `nft` run per
    /// round, not per entry). Applied in order; the first error stops.
    fn address_list_dynamic_many(&mut self, changes: &[DynamicChange<'_>]) -> Result<(), HalError> {
        for c in changes {
            self.address_list_dynamic(*c)?;
        }
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

    /// The kernel's transmit timeouts of `name` (`NETDEV WATCHDOG`), summed
    /// over its queues: read every second by the USB watchdog (G1.29d), so
    /// cheap. `None`: the platform does not count them.
    fn usb_tx_timeouts(&mut self, name: &IfName) -> Option<u64> {
        let _ = name;
        None
    }

    /// A manual recovery of USB adapter `name` (G1.29c).
    fn usb_reset(
        &mut self,
        name: &IfName,
        level: nic::UsbResetLevel,
    ) -> Result<Box<dyn nic::UsbReset>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} cannot reset '{name}' ({})",
            self.describe(),
            level.as_str()
        )))
    }

    /// Open the DHCP client socket of interface `name` (G4.7).
    fn dhcp_port(&mut self, name: &IfName) -> Result<Box<dyn DhcpPort>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no DHCP client transport (asked for '{name}')",
            self.describe()
        )))
    }

    /// Open the port of PPPoE client `client` on Ethernet port `uplink`
    /// (G3.9ga): its control frames, and the relay of its session.
    fn pppoe_client_port(
        &mut self,
        client: &IfName,
        uplink: &IfName,
    ) -> Result<Box<dyn pppoe_client::PppoeClientPort>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no PPPoE client transport (asked for '{client}' on '{uplink}')",
            self.describe()
        )))
    }

    /// The lab's simulated BNG (see [`Hal::offer_dhcp_lab_server`]).
    fn offer_pppoe_lab_server(&mut self, server: pppoe_client::SharedPppoeLab) {
        let _ = server;
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

    /// The CGNAT fast path's link to the XDP flow map and to conntrack
    /// (G2.5b), for the daemon's `xdp-nat` service.
    fn xdp_nat_link(&mut self) -> Result<Box<dyn xdp_nat::NatLink>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// PPPoE subscribers in the XDP data plane (G4.3c, for the BNG
    /// service G4.3d): switch it on for the access ports `ports` (the XDP
    /// program must be attached there). `Err`: the service carries the
    /// traffic itself.
    fn pppoe_dataplane(&mut self, on: bool, ports: &[IfName]) -> Result<(), HalError> {
        let _ = (on, ports);
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// IPoE subscribers in the XDP data plane (G4.3f): the access ports
    /// whose subscribers' sessions go in the same maps as PPPoE's. Off
    /// (or `Err`): the sessions exist without the policer.
    fn ipoe_dataplane(&mut self, on: bool, ports: &[IfName]) -> Result<(), HalError> {
        let _ = (on, ports);
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// Change the XDP session map, in order.
    fn pppoe_apply(&mut self, ops: &[pppoe::PppoeOp]) -> Result<(), HalError> {
        let _ = ops;
        Err(HalError::Unsupported(format!(
            "{} has no XDP data plane",
            self.describe()
        )))
    }

    /// The counters of the sessions at `slots` (unknown ones left out).
    fn pppoe_counters(&mut self, slots: &[u32]) -> Vec<(u32, pppoe::PppoeCounters)> {
        let _ = slots;
        Vec::new()
    }

    /// Queues (G4.9b): make the shaper hold `plan` — the tc programs on its
    /// ports, `fq` on their transmit queues, the queue maps. An empty plan
    /// takes it all away. `Err`: nothing is shaped (the commit stays).
    fn shaper_apply(&mut self, plan: &queue::ShaperPlan) -> Result<(), HalError> {
        if plan.is_empty() {
            return Ok(());
        }
        Err(HalError::Unsupported(format!(
            "{} has no shaper (tc and eBPF)",
            self.describe()
        )))
    }

    /// What the shaper counted (by queue key) and why it is not there.
    fn shaper_status(&mut self) -> queue::ShaperStatus {
        queue::ShaperStatus {
            unavailable: Some(format!("{} has no shaper", self.describe())),
            ..queue::ShaperStatus::default()
        }
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

    /// The subscribers near the end of their ports (G2.7): only their new
    /// connections go through the exhaustion queues, so everyone else's
    /// packets never leave the kernel. Replaces the whole set.
    fn cgnat_full(&mut self, subscribers: &[std::net::Ipv4Addr]) -> Result<(), HalError> {
        let _ = subscribers;
        Err(HalError::Unsupported(format!(
            "{} has no CGNAT data plane",
            self.describe()
        )))
    }

    /// Exhaustion queue `index` (0..[`cgnat::EXHAUSTED_QUEUES`]) (G2.7),
    /// for a daemon thread to serve outside the session lock.
    fn cgnat_exhaustion_queue(
        &mut self,
        index: u16,
    ) -> Result<Box<dyn cgnat::ExhaustionQueue>, HalError> {
        let _ = index;
        Err(HalError::Unsupported(format!(
            "{} has no packet queue",
            self.describe()
        )))
    }

    /// A reader of the conntrack table for a thread outside the session
    /// lock (G2.7b: the CGNAT usage scan). Cheap to build.
    fn conntrack_scanner(&self) -> Result<Box<dyn conntrack::Scanner>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking scanner",
            self.describe()
        )))
    }

    /// Connections refused for lack of ports, and the ICMP sent about
    /// them, since the last call (G2.7).
    fn cgnat_exhausted(
        &mut self,
    ) -> (
        Vec<(std::net::Ipv4Addr, cgnat::Hit)>,
        cgnat::ExhaustionStats,
    ) {
        (Vec::new(), cgnat::ExhaustionStats::default())
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
    /// The OS log's lines since the last call (G4.8b), at most `max`, and
    /// how each source is; `now` is the session's clock. Cheap and never
    /// blocking (it runs under the session lock): a backend whose sources
    /// are slow leaves this to the daemon's `oslog` service, which reads
    /// them on its own thread. Default: no OS log here.
    fn os_log(&mut self, now: Option<u64>, max: usize) -> Result<oslog::OsLogBatch, HalError> {
        let _ = (now, max);
        Err(HalError::Unsupported(
            "this backend has no OS log (the daemon's oslog service reads it)".into(),
        ))
    }

    fn resources(&mut self) -> Option<resources::Resources> {
        None
    }

    /// A sampler of the machine for System › Resources and health (G4.8a,
    /// [`system_resource`]), or why there is none. Cheap to build; the
    /// caller keeps it and reads with it outside the session lock.
    fn resource_sampler(&self) -> Result<Box<dyn system_resource::ResourceSampler>, String> {
        Err(format!(
            "{} has no system resource readings",
            self.describe()
        ))
    }

    /// The neighbor tables now (G1.27d, [`neigh`]): ARP and IPv6 ND.
    fn neighbors(&mut self) -> Result<Vec<neigh::Neighbor>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no neighbor table",
            self.describe()
        )))
    }

    /// A live feed of the neighbor tables, for a thread of the app.
    fn neighbor_feed(&mut self) -> Result<Box<dyn neigh::NeighborFeed>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no neighbor events",
            self.describe()
        )))
    }

    /// Remove learned entries (`ip.arp.flush`, `ipv6.neighbor.flush`);
    /// how many were there. One already gone is not an error.
    fn neighbor_remove(&mut self, items: &[(IfName, std::net::IpAddr)]) -> Result<usize, HalError> {
        let _ = items;
        Err(HalError::Unsupported(format!(
            "{} cannot flush neighbors",
            self.describe()
        )))
    }

    /// Static ARP entries outside the config (DHCP `add-arp`, G1.27d):
    /// `mac: None` removes. One already gone is not an error.
    fn neighbor_static(&mut self, ops: &[neigh::StaticNeigh]) -> Result<(), HalError> {
        let _ = ops;
        Err(HalError::Unsupported(format!(
            "{} cannot add static neighbors",
            self.describe()
        )))
    }

    /// An ARP pinger on `name` (`ip.arp.ping`), used outside the session
    /// lock.
    fn arp_pinger(&mut self, name: &IfName) -> Result<Box<dyn neigh::ArpPinger>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} cannot send ARP on {name}",
            self.describe()
        )))
    }

    /// The kernel's label table (G3.5, [`mpls`]), read now. A full LSR
    /// has 10⁵ labels: the daemon reads through [`Hal::mpls_reader`] on a
    /// thread instead.
    fn mpls_routes(&mut self) -> Result<Vec<mpls::MplsRoute>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no MPLS label table",
            self.describe()
        )))
    }

    /// A reader of the label table for a thread outside the session lock.
    fn mpls_reader(&self) -> Result<Box<dyn mpls::MplsReader>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no MPLS label table",
            self.describe()
        )))
    }

    /// LSP ping / traceroute sockets (G3.5b, [`lsp`]), or why there are
    /// none. Cheap: built once, handed out as clones.
    fn lsp_prober(&self) -> Result<lsp::SharedLspProber, String> {
        Err(format!(
            "{} cannot send MPLS echo requests",
            self.describe()
        ))
    }

    /// The MPLS echo responder's I/O (G3.5b), for a thread of the daemon.
    fn lsp_responder(&self) -> Result<Box<dyn lsp::LspResponderIo>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} cannot answer MPLS echo requests",
            self.describe()
        )))
    }

    /// A live feed of conntrack events for the flow exporter (G4.4b).
    fn conntrack_events(&mut self) -> Result<Box<dyn conntrack::EventSource>, HalError> {
        Err(HalError::Unsupported(format!(
            "{} has no connection tracking events",
            self.describe()
        )))
    }
}

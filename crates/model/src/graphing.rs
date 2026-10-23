//! `/tool graphing` of the config (G4.5): which interfaces the router keeps
//! a traffic history of, how often that history goes to disk and how big it
//! may grow. The history itself is operational data (the engine's
//! `graph` module and the daemon's `graphing` service), never part of a
//! revision.
//!
//! RouterOS keeps one rule per interface (`/tool graphing interface add
//! interface=all store-on-disk=yes`). A carrier box has hundreds of VLANs
//! and PPPoE sessions, so here the choice is by class of interface
//! (physical by default; bridges, VLANs and tunnels when asked) plus names
//! always kept (`include`) or never kept (`exclude`), under a memory cap.

use serde::{Deserialize, Serialize};

use crate::types::IfName;

/// Default `store_every`: RouterOS `store-every=5min`.
pub const DEFAULT_STORE_EVERY: u32 = 300;
pub const MIN_STORE_EVERY: u32 = 60;
pub const MAX_STORE_EVERY: u32 = 86_400;
/// Default memory (and disk) cap, MiB: about 90 interfaces of a year each.
pub const DEFAULT_MAX_MEMORY_MIB: u32 = 64;
pub const MIN_MAX_MEMORY_MIB: u32 = 1;
pub const MAX_MAX_MEMORY_MIB: u32 = 4096;
/// Most names in `include` or `exclude`.
pub const MAX_NAMES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Graphing {
    /// Collect at all (on by default, like the WinBox Traffic tab is always
    /// there).
    pub enabled: bool,
    /// Seconds between writes of the history to disk (flash wears with
    /// every write; a crash loses at most this much).
    pub store_every: u32,
    /// Ethernet ports and bonds.
    pub physical: bool,
    pub bridges: bool,
    pub vlans: bool,
    /// PPP, PPPoE, GRE, IPIP, WireGuard, VXLAN, EoIP and other tunnels.
    pub tunnels: bool,
    /// CPU, memory and the conntrack table.
    pub resources: bool,
    /// Kept whatever their class (a loopback, one VLAN of a transit).
    pub include: Vec<IfName>,
    /// Never kept, even when their class is.
    pub exclude: Vec<IfName>,
    /// Memory for the history, MiB; the same bytes go to disk. Interfaces
    /// past it are not kept (and `system.graph.print` says which).
    pub max_memory_mib: u32,
}

impl Default for Graphing {
    fn default() -> Self {
        Self {
            enabled: true,
            store_every: DEFAULT_STORE_EVERY,
            physical: true,
            bridges: false,
            vlans: false,
            tunnels: false,
            resources: true,
            include: Vec::new(),
            exclude: Vec::new(),
            max_memory_mib: DEFAULT_MAX_MEMORY_MIB,
        }
    }
}

/// The class an interface falls in, from its kind (`ether`, `vlan`,
/// `pppoe-in`…, the config's label or the platform's link kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Physical,
    Bridge,
    Vlan,
    Tunnel,
    /// Loopback, VRF devices, dummies, veths: kept only when named.
    Other,
}

impl Class {
    pub fn of(kind: &str) -> Self {
        match kind {
            "ether" | "ethernet" | "bonding" | "bond" | "sfp" => Self::Physical,
            "bridge" => Self::Bridge,
            "vlan" | "macvlan" => Self::Vlan,
            k if k.starts_with("ppp")
                || k.starts_with("l2tp")
                || k.starts_with("sstp")
                || k.starts_with("ovpn") =>
            {
                Self::Tunnel
            }
            "tun" | "tap" | "gre" | "gretap" | "ip6gre" | "ipip" | "ip6tnl" | "sit"
            | "wireguard" | "vxlan" | "eoip" | "geneve" => Self::Tunnel,
            _ => Self::Other,
        }
    }
}

impl Graphing {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether interface `name` of kind `kind` is kept (the memory cap
    /// aside).
    pub fn keeps(&self, name: &IfName, kind: &str) -> bool {
        if !self.enabled || self.exclude.contains(name) {
            return false;
        }
        if self.include.contains(name) {
            return true;
        }
        match Class::of(kind) {
            Class::Physical => self.physical,
            Class::Bridge => self.bridges,
            Class::Vlan => self.vlans,
            Class::Tunnel => self.tunnels,
            Class::Other => false,
        }
    }

    pub fn max_memory_bytes(&self) -> u64 {
        u64::from(self.max_memory_mib) * 1024 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    #[test]
    fn physical_by_default_and_names_win() {
        let mut g = Graphing::default();
        assert!(g.keeps(&n("ether1"), "ether"));
        assert!(g.keeps(&n("bond0"), "bonding"));
        assert!(!g.keeps(&n("vlan10"), "vlan"));
        assert!(!g.keeps(&n("pppoe-1"), "pppoe-in"));
        assert!(!g.keeps(&n("lo"), "loopback"));
        g.include.push(n("lo"));
        g.exclude.push(n("ether1"));
        assert!(g.keeps(&n("lo"), "loopback"));
        assert!(!g.keeps(&n("ether1"), "ether"));
        g.vlans = true;
        g.tunnels = true;
        assert!(g.keeps(&n("vlan10"), "vlan"));
        assert!(g.keeps(&n("wg0"), "wireguard"));
        g.enabled = false;
        assert!(!g.keeps(&n("lo"), "loopback"), "off keeps nothing");
    }

    #[test]
    fn old_configs_read_with_defaults() {
        let g: Graphing = serde_json::from_str(r#"{"vlans": true}"#).unwrap();
        assert!(g.vlans && g.physical && g.enabled);
        assert_eq!(g.store_every, DEFAULT_STORE_EVERY);
    }
}

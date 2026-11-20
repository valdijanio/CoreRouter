//! `/routing management-guard` (G3.4z): the networks the router is managed
//! from, which no learned route may cut into.
//!
//! A route more specific than a connected network wins over it (longest
//! match, RFC 1812 §5.2.4.3), whatever its distance: an OSPF or BGP `/32`
//! inside the management `/24` sends the router's replies to the operator
//! out of another port, and the session dies. For each network here the
//! routing daemon refuses to install, from any protocol, a prefix inside it
//! and longer than it (FRR zebra `ip protocol any route-map`, which takes
//! the route out of the FIB and leaves it in the protocol's RIB; RFC 2328
//! §2 keeps the LSDB itself whole). Connected and static routes are not
//! touched: zebra does not filter the kernel's own routes.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::types::ItemId;

/// Hostile-input bound; also bounds the prefix-list zebra checks every
/// learned route against (a handful in practice).
pub const MAX_NETWORKS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagementGuard {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<GuardNetwork>,
    /// Next id handed out (never reused, like RouterOS).
    #[serde(skip_serializing_if = "is_zero")]
    pub next_id: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardNetwork {
    pub id: ItemId,
    /// Always the network itself (host bits zero), never a /32 or /128:
    /// nothing is more specific than those.
    pub network: IpNet,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl ManagementGuard {
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    /// The networks in force (not disabled), in id order.
    pub fn active(&self) -> impl Iterator<Item = &IpNet> {
        self.networks.iter().filter(|n| !n.disabled).map(|n| &n.network)
    }

    /// Whether a learned route to `prefix` is refused: inside an active
    /// network and longer than it.
    pub fn refuses(&self, prefix: &IpNet) -> bool {
        self.active()
            .any(|n| n.contains(prefix) && prefix.prefix_len() > n.prefix_len())
    }
}

/// A route of the routing daemon's RIB inside a guarded network, as zebra
/// sees it (`show ip route <net> longer-prefixes json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RibRoute {
    pub prefix: IpNet,
    /// FRR's name: `ospf`, `bgp`, `connected`, `kernel`, `static`…
    pub protocol: String,
    /// In the FIB (the kernel has it).
    pub installed: bool,
    /// No next hop of it is active: the route-map (or a dead next hop)
    /// took it out.
    pub inactive: bool,
    /// The first next hop, for people (`10.0.1.2 ether2`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub via: String,
}

/// Protocols of a routing daemon (the ones a guard is about), as FRR names
/// them: everything but the kernel's own routes.
pub fn is_learned(protocol: &str) -> bool {
    !matches!(protocol, "connected" | "kernel" | "local" | "system")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn a_longer_prefix_inside_is_refused_and_the_network_itself_is_not() {
        let g = ManagementGuard {
            networks: vec![
                GuardNetwork { id: ItemId(1), network: net("192.168.0.0/24"), disabled: false, comment: String::new() },
                GuardNetwork { id: ItemId(2), network: net("100.64.0.0/24"), disabled: true, comment: String::new() },
            ],
            next_id: 2,
        };
        assert!(g.refuses(&net("192.168.0.2/32")));
        assert!(g.refuses(&net("192.168.0.0/25")));
        assert!(!g.refuses(&net("192.168.0.0/24")), "the same length: the connected route wins on distance");
        assert!(!g.refuses(&net("192.168.0.0/16")), "shorter: the connected route wins on length");
        assert!(!g.refuses(&net("100.64.0.9/32")), "a disabled network refuses nothing");
        assert!(!g.refuses(&net("2001:db8::1/128")));
    }

    #[test]
    fn an_old_config_without_the_guard_loads() {
        let r: crate::Routing = serde_json::from_str("{}").unwrap();
        assert!(r.management_guard.is_empty());
        let back = serde_json::to_string(&r).unwrap();
        assert!(!back.contains("management_guard"), "{back}");
    }
}

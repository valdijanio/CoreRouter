//! `/ip firewall fastpath` (G2.4): the Linux flowtable (`nf_flowtable`),
//! RouterOS's FastTrack. After the firewall accepted a connection, its
//! later packets skip the forward rules and go straight from the ingress
//! of one port to the egress of another, NAT included; with
//! `hw_offload` and a card that takes it (NVIDIA ConnectX in switchdev
//! mode) the card itself forwards them.
//!
//! Unlike RouterOS there is no `fasttrack-connection` rule to write and no
//! `accept` twin to remember: the flowtable is fed by a chain that runs
//! **after** the firewall's forward chain, so only what the rules accepted
//! enters it, and a drop rule always wins. IPv4 and IPv6, TCP and UDP.

use serde::{Deserialize, Serialize};

use crate::types::IfName;

/// Ports one flowtable may name (**estimado**, hostile-input bound; a
/// device in two flowtables is refused by the kernel anyway).
pub const MAX_INTERFACES: usize = 256;

/// Whether the flowtable asks the card to forward the flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HwOffload {
    /// Ask for it; a refusal falls back to software (status says why).
    #[default]
    Auto,
    /// Require it: a refusal refuses the change.
    Yes,
    /// Software only.
    No,
}

impl HwOffload {
    pub fn as_str(self) -> &'static str {
        match self {
            HwOffload::Auto => "auto",
            HwOffload::Yes => "yes",
            HwOffload::No => "no",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(HwOffload::Auto),
            "yes" => Some(HwOffload::Yes),
            "no" => Some(HwOffload::No),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FastPath {
    pub enabled: bool,
    /// The ports of the flowtable; empty: every Ethernet and bond port.
    /// A VLAN or PPPoE on a port needs only the port (kernel 5.13+).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<IfName>,
    pub hw_offload: HwOffload,
    /// Flowtable counters (kernel 5.7+): offloaded bytes still show in the
    /// connection's counters. On by default; off saves a little per packet.
    pub counters: bool,
}

impl Default for FastPath {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            hw_offload: HwOffload::Auto,
            counters: true,
        }
    }
}

impl FastPath {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_round_trip() {
        let d = FastPath::default();
        assert!(!d.enabled && d.counters && d.hw_offload == HwOffload::Auto);
        let v: FastPath = serde_json::from_str(r#"{"enabled":true,"hw_offload":"yes"}"#).unwrap();
        assert!(v.counters, "absent counters keep the default");
        assert_eq!(serde_json::from_value::<FastPath>(serde_json::to_value(&v).unwrap()).unwrap(), v);
        assert!(serde_json::from_str::<FastPath>(r#"{"bogus":1}"#).is_err());
    }
}

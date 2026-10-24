//! IP › Firewall › XDP (G2.5a): a filter that runs in the NIC driver
//! (XDP), before the kernel spends anything on the packet — before
//! `/ip firewall raw`, connection tracking and routing. It drops what an
//! attack sends in volume: sources in block lists (the firewall's address
//! lists), sources over a per-source rate, malformed headers and TCP flag
//! combinations no connection uses.
//!
//! RouterOS has no XDP; the closest is a `raw` `prerouting` rule with
//! `src-address-list=… action=drop` and `dst-limit=…,src-address`. Here it
//! is one filter shared by every interface it is attached to.

use serde::{Deserialize, Serialize};

use crate::firewall::Name;
use crate::types::IfName;

/// Interfaces the filter can be attached to (the counters map has one
/// slot per interface and reason).
pub const MAX_INTERFACES: usize = 256;
/// Address lists per kind (block, allow).
pub const MAX_LISTS: usize = 16;
/// Rate limit bounds (packets per second, packets).
pub const MAX_RATE: u32 = 100_000_000;
pub const MAX_BURST: u32 = 10_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Xdp {
    /// Where the filter runs, in the order added.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<XdpInterface>,
    pub filter: XdpFilter,
    /// CGNAT fast path (G2.5b): the connections the kernel's CGNAT
    /// (nftables, G2.3) already translated are translated and forwarded
    /// here, in the driver; their first packets, and everything this does
    /// not take, still go through the kernel.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fast_nat: bool,
}

impl Xdp {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The interfaces it runs on now (not disabled).
    pub fn active(&self) -> impl Iterator<Item = &XdpInterface> {
        self.interfaces.iter().filter(|i| !i.disabled)
    }
}

/// How the program is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// Native (driver) mode where the driver has it, generic otherwise.
    #[default]
    Auto,
    /// In the driver, before the kernel allocates the packet: the fast
    /// one (mlx5, i40e, ice, ixgbe, bnxt, virtio_net, veth…). Refused
    /// where the driver lacks it.
    Native,
    /// After the driver, on the kernel's packet buffer: any interface,
    /// a fraction of native's speed.
    Generic,
}

impl XdpMode {
    pub fn name(self) -> &'static str {
        match self {
            XdpMode::Auto => "auto",
            XdpMode::Native => "native",
            XdpMode::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [XdpMode::Auto, XdpMode::Native, XdpMode::Generic]
            .into_iter()
            .find(|m| m.name() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpInterface {
    pub interface: IfName,
    #[serde(default)]
    pub mode: XdpMode,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// What the filter drops (the same on every interface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XdpFilter {
    /// Firewall address lists whose sources are dropped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub block_lists: Vec<Name>,
    /// Firewall address lists whose sources neither block lists nor the
    /// rate limit touch (BGP peers, management, resolvers).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_lists: Vec<Name>,
    /// Packets per second each source may send; 0 = no limit.
    pub rate_limit: u32,
    /// Packets a source may send at once above the rate.
    pub rate_burst: u32,
    /// Drop frames with broken headers (truncated, impossible lengths,
    /// tiny fragments, RFC 1858).
    pub drop_malformed: bool,
    /// Drop TCP segments with flag combinations no connection uses.
    pub drop_invalid_tcp_flags: bool,
}

impl Default for XdpFilter {
    fn default() -> Self {
        Self {
            block_lists: Vec::new(),
            allow_lists: Vec::new(),
            rate_limit: 0,
            rate_burst: 0,
            drop_malformed: true,
            drop_invalid_tcp_flags: true,
        }
    }
}

impl XdpFilter {
    /// The burst used: the configured one, or one second's worth.
    pub fn burst(&self) -> u32 {
        if self.rate_burst == 0 {
            self.rate_limit
        } else {
            self.rate_burst
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_skipped_and_round_trips() {
        let x = Xdp::default();
        assert!(x.is_default());
        let json = serde_json::to_value(&x).unwrap();
        assert_eq!(serde_json::from_value::<Xdp>(json).unwrap(), x);
        let mut y = Xdp::default();
        y.interfaces.push(XdpInterface {
            interface: "ether1".parse().unwrap(),
            mode: XdpMode::Native,
            disabled: false,
            comment: String::new(),
        });
        y.filter.block_lists.push("bogons".parse().unwrap());
        let json = serde_json::to_value(&y).unwrap();
        assert_eq!(json["interfaces"][0]["mode"], "native");
        assert_eq!(serde_json::from_value::<Xdp>(json).unwrap(), y);
    }

    #[test]
    fn burst_defaults_to_a_second() {
        let f = XdpFilter {
            rate_limit: 500,
            ..XdpFilter::default()
        };
        assert_eq!(f.burst(), 500);
        assert_eq!(XdpMode::parse("generic"), Some(XdpMode::Generic));
        assert_eq!(XdpMode::parse("x"), None);
    }
}

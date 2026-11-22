//! `/ip arp` (G1.27d): static ARP entries and the ARP mode of each
//! interface. The size of the kernel's neighbor tables (`gc_thresh1/2/3`)
//! is a kernel parameter of `system.tuning` (G1.26), not repeated here.
//!
//! Only what the operator configures lives here. The dynamic entries (what
//! the kernel learned) are runtime state, read by `hal::neigh`.
//!
//! Names follow RouterOS v7: an entry has `address`, `mac-address`,
//! `interface`, `published`; an interface has `arp` (enabled, disabled,
//! reply-only, proxy-arp, local-proxy-arp) and `arp-timeout` (auto).

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId, MacAddr, ParseError};

/// Static entries the config may hold (hostile input: a config file).
pub const MAX_ENTRIES: usize = 65_536;
/// Longest `arp-timeout`, in seconds (one day; RouterOS takes any time,
/// but a neighbor not confirmed for a day is no longer a neighbor).
pub const MAX_TIMEOUT_SECS: u32 = 86_400;

/// What the interface does with ARP (RouterOS `/interface … arp=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArpMode {
    /// Learns and answers (RFC 826).
    #[default]
    Enabled,
    /// No ARP at all: only static entries reach hosts (Linux `IFF_NOARP`).
    Disabled,
    /// Answers requests for its addresses but learns nothing: only static
    /// entries (or DHCP `add-arp`) reach hosts, the anti-spoofing mode.
    ReplyOnly,
    /// Answers for addresses it routes elsewhere (RFC 1027).
    ProxyArp,
    /// Answers for hosts of the same port, so isolated clients reach each
    /// other through the router (Linux `proxy_arp_pvlan`, RFC 3069 style).
    LocalProxyArp,
}

impl ArpMode {
    pub const ALL: [Self; 5] = [
        Self::Enabled,
        Self::Disabled,
        Self::ReplyOnly,
        Self::ProxyArp,
        Self::LocalProxyArp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::ReplyOnly => "reply-only",
            Self::ProxyArp => "proxy-arp",
            Self::LocalProxyArp => "local-proxy-arp",
        }
    }

    /// Whether the mode can cut hosts off or answer for others: the
    /// command asks to confirm it.
    pub fn risky(self) -> bool {
        matches!(self, Self::Disabled | Self::ProxyArp | Self::ReplyOnly)
    }
}

impl fmt::Display for ArpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ArpMode {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str() == s.trim())
            .ok_or_else(|| {
                ParseError::new(
                    "arp",
                    s,
                    "expected enabled, disabled, reply-only, proxy-arp or local-proxy-arp",
                )
            })
    }
}

/// ARP settings of one interface; an interface without any has the
/// defaults (enabled, timeout auto).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArpInterface {
    pub mode: ArpMode,
    /// How long a learned entry stays `reachable` without confirmation
    /// (`base_reachable_time_ms`); `None` = auto (the kernel's 30 s,
    /// RFC 4861 §10 REACHABLE_TIME).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
}

impl ArpInterface {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// One static entry (`/ip arp add`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArpEntry {
    pub id: ItemId,
    pub address: Ipv4Addr,
    pub mac: MacAddr,
    pub interface: IfName,
    /// Answer ARP for this address as if it were ours (proxy for one host).
    #[serde(default)]
    pub published: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// `/ip arp` and its settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Arp {
    pub entries: Vec<ArpEntry>,
    pub next_id: u32,
    /// Only interfaces off the defaults.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub interfaces: BTreeMap<IfName, ArpInterface>,
}

impl Arp {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// The settings of `name` (the defaults when it has none).
    pub fn interface(&self, name: &IfName) -> ArpInterface {
        self.interfaces.get(name).copied().unwrap_or_default()
    }

    /// Store `s` for `name`, dropping it when it is back to the defaults.
    pub fn set_interface(&mut self, name: IfName, s: ArpInterface) {
        if s.is_default() {
            self.interfaces.remove(&name);
        } else {
            self.interfaces.insert(name, s);
        }
    }

    /// The enabled static entries on interfaces the config has.
    pub fn active<'a>(
        &'a self,
        has: impl Fn(&IfName) -> bool + 'a,
    ) -> impl Iterator<Item = &'a ArpEntry> + 'a {
        self.entries
            .iter()
            .filter(move |e| !e.disabled && has(&e.interface))
    }
}

/// Whether `mac` can be a host's address: not all zeros, not group
/// (multicast or broadcast: the low bit of the first octet).
pub fn unicast_mac(mac: MacAddr) -> bool {
    mac.0 != [0; 6] && mac.0[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_round_trip() {
        for m in ArpMode::ALL {
            assert_eq!(m.as_str().parse::<ArpMode>(), Ok(m));
        }
        assert!("proxy".parse::<ArpMode>().is_err());
        assert!(ArpMode::ProxyArp.risky() && !ArpMode::Enabled.risky());
    }

    #[test]
    fn default_settings_are_not_stored() {
        let mut a = Arp::default();
        let e: IfName = "ether1".parse().unwrap();
        a.set_interface(
            e.clone(),
            ArpInterface {
                mode: ArpMode::ReplyOnly,
                timeout_secs: None,
            },
        );
        assert_eq!(a.interface(&e).mode, ArpMode::ReplyOnly);
        a.set_interface(e.clone(), ArpInterface::default());
        assert!(a.is_empty() || a.interfaces.is_empty());
    }

    #[test]
    fn group_macs_are_not_hosts() {
        assert!(!unicast_mac(MacAddr([0xff; 6])));
        assert!(!unicast_mac(MacAddr([0x01, 0, 0x5e, 0, 0, 1])));
        assert!(!unicast_mac(MacAddr([0; 6])));
        assert!(unicast_mac(MacAddr([0x02, 0, 0, 0, 0, 1])));
    }
}

//! `/interface pppoe-client` (G3.9ga): the router dialing a PPPoE server,
//! as the WAN of a provider. A client is an interface
//! (`InterfaceKind::PppoeClient`, type `pppoe-out` as in RouterOS), so
//! firewall rules, `ip address`, the DHCPv6 client and interface lists name
//! it like any other; its settings live here. Names and defaults follow
//! RouterOS v7 (`docs/pppoe-client.md`).

use serde::{Deserialize, Serialize};

use crate::IfName;
use crate::sealed::Sealed;

/// RouterOS `max-mtu`/`max-mru` default.
pub const DEFAULT_MTU: u16 = 1460;
/// RFC 2516 §7: the most a PPPoE link carries without RFC 4638.
pub const MAX_MTU: u16 = 1492;
/// RFC 1661 §6.1 floor for an MRU.
pub const MIN_MTU: u16 = 64;
/// RouterOS `keepalive-timeout` default (seconds).
pub const DEFAULT_KEEPALIVE: u32 = 60;
/// Longest user, service-name or ac-name (RFC 2516 tags are 16-bit, but a
/// provider's names are short; hostile input elsewhere).
pub const MAX_NAME: usize = 128;

/// Authentication protocols the client agrees to (RouterOS `allow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Allow {
    Mschap2,
    Mschap1,
    Chap,
    Pap,
}

impl Allow {
    pub const ALL: [Allow; 4] = [Allow::Mschap2, Allow::Mschap1, Allow::Chap, Allow::Pap];

    pub fn as_str(self) -> &'static str {
        match self {
            Allow::Mschap2 => "mschap2",
            Allow::Mschap1 => "mschap1",
            Allow::Chap => "chap",
            Allow::Pap => "pap",
        }
    }

    pub fn parse(s: &str) -> Option<Allow> {
        Allow::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

fn default_allow() -> Vec<Allow> {
    Allow::ALL.to_vec()
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_distance() -> u8 {
    crate::DEFAULT_DISTANCE
}

fn default_keepalive() -> u32 {
    DEFAULT_KEEPALIVE
}

fn default_profile() -> String {
    "default".into()
}

fn is_default_profile(p: &str) -> bool {
    p == "default"
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One PPPoE client: what `interface.pppoe-client.add` stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeClient {
    /// The Ethernet port or VLAN it dials on (RouterOS `interface`).
    pub interface: IfName,
    pub user: String,
    /// Sealed at rest, like the PPP secrets (`crate::sealed`).
    #[serde(default, skip_serializing_if = "Sealed::is_empty")]
    pub password: Sealed,
    /// Service-Name asked for in the PADI (empty = any).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_name: String,
    /// Only the AC with this AC-Name (empty = the first offer).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ac_name: String,
    /// Host-Uniq tag, hex (empty = one the router picks).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_uniq: String,
    /// Install a default route via the session (RouterOS default: no).
    #[serde(default, skip_serializing_if = "is_false")]
    pub add_default_route: bool,
    #[serde(default = "default_distance")]
    pub default_route_distance: u8,
    /// Take the DNS servers IPCP gives (RouterOS default: no).
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_peer_dns: bool,
    /// `/ppp profile` for `change-tcp-mss`, `use-ipv6`, `address-list`.
    #[serde(default = "default_profile", skip_serializing_if = "is_default_profile")]
    pub profile: String,
    #[serde(default = "default_mtu")]
    pub max_mtu: u16,
    #[serde(default = "default_mtu")]
    pub max_mru: u16,
    /// Seconds without an LCP echo answer before the link is declared
    /// down; 0 = disabled.
    #[serde(default = "default_keepalive")]
    pub keepalive_timeout: u32,
    #[serde(default = "default_allow")]
    pub allow: Vec<Allow>,
}

impl PppoeClient {
    pub fn new(interface: IfName, user: String) -> Self {
        PppoeClient {
            interface,
            user,
            password: Sealed::default(),
            service_name: String::new(),
            ac_name: String::new(),
            host_uniq: String::new(),
            add_default_route: false,
            default_route_distance: crate::DEFAULT_DISTANCE,
            use_peer_dns: false,
            profile: default_profile(),
            max_mtu: DEFAULT_MTU,
            max_mru: DEFAULT_MTU,
            keepalive_timeout: DEFAULT_KEEPALIVE,
            allow: default_allow(),
        }
    }

    /// `allow` as RouterOS prints it (`mschap2,mschap1,chap,pap`).
    pub fn allow_text(&self) -> String {
        self.allow
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Linux `IFNAMSIZ` - 1.
const MAX_IFNAME: usize = 15;

/// Kernel name of the hidden end of client `name`'s veth pair (G3.9ga):
/// the relay reads and writes the session's packets there. `<name>-r` when
/// it fits in 15 bytes, else `crpr` and a hash of the name.
pub fn relay_peer(name: &str) -> String {
    if name.len() + 2 <= MAX_IFNAME {
        return format!("{name}-r");
    }
    // FNV-1a: stable across runs and platforms.
    let h = name
        .bytes()
        .fold(0x811c_9dc5_u32, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193));
    format!("crpr{h:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, InterfaceKind};

    #[test]
    fn interface_round_trips_with_routeros_defaults() {
        let c = PppoeClient::new("ether1".parse::<IfName>().unwrap(), "cliente@isp".into());
        let i = Interface::new(
            "pppoe-out1".parse::<IfName>().unwrap(),
            InterfaceKind::PppoeClient(Box::new(c.clone())),
        );
        let text = serde_json::to_string(&i).unwrap();
        assert!(text.contains(r#""type":"pppoe-client""#), "{text}");
        assert!(!text.contains("password"), "{text}");
        let back: Interface = serde_json::from_str(&text).unwrap();
        assert_eq!(back, i);
        assert_eq!(back.kind.label(), "pppoe-out");
        // A minimal stored entry gets the RouterOS defaults.
        let min: Interface = serde_json::from_str(
            r#"{"name":"wan","kind":{"type":"pppoe-client","interface":"ether1","user":"u"}}"#,
        )
        .unwrap();
        let InterfaceKind::PppoeClient(c) = min.kind else { panic!() };
        assert_eq!(c.max_mtu, 1460);
        assert_eq!(c.keepalive_timeout, 60);
        assert_eq!(c.default_route_distance, 1);
        assert!(!c.add_default_route && !c.use_peer_dns);
        assert_eq!(c.allow_text(), "mschap2,mschap1,chap,pap");
    }

    #[test]
    fn relay_peer_fits_ifnamsiz() {
        assert_eq!(relay_peer("pppoe-out1"), "pppoe-out1-r");
        let long = relay_peer("pppoe-out-vivo1");
        assert!(long.starts_with("crpr") && long.len() == 12, "{long}");
        assert_eq!(long, relay_peer("pppoe-out-vivo1"));
        assert_ne!(long, relay_peer("pppoe-out-vivo2"));
    }

    #[test]
    fn unknown_keys_are_refused() {
        let r: Result<Interface, _> = serde_json::from_str(
            r#"{"name":"wan","kind":{"type":"pppoe-client","interface":"ether1","user":"u","bogus":1}}"#,
        );
        assert!(r.is_err());
    }
}

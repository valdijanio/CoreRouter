//! MPLS and LDP (G3.5), as RouterOS v7 models them:
//!
//! - `/mpls settings`: the dynamic label range and TTL propagation;
//! - `/mpls interface`: where labeled packets are accepted (Linux
//!   `net.mpls.conf.<if>.input`);
//! - `/mpls ldp` (one instance: FRR's `ldpd` runs LDP in the main table
//!   only), `/mpls ldp interface` and the configured `/mpls ldp neighbor`s;
//! - `/mpls static` (Cisco `mpls static binding`, Junos
//!   `static-label-switched-path`; RouterOS has none): label switching
//!   entries CoreRouter programs in the kernel itself.
//!
//! Label values follow RFC 3032 §2.1: 0..=15 are reserved, the rest of the
//! 20-bit space is free for the router to hand out.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;
use crate::types::IfName;

/// Highest label value (20 bits, RFC 3032 §2.1).
pub const MAX_LABEL: u32 = (1 << 20) - 1;
/// First label value outside the reserved range (RFC 3032 §2.1: 0..=15).
pub const FIRST_UNRESERVED: u32 = 16;
/// RFC 3032 §2.1 reserved values that mean something on the wire.
pub const IPV4_EXPLICIT_NULL: u32 = 0;
pub const ROUTER_ALERT: u32 = 1;
pub const IPV6_EXPLICIT_NULL: u32 = 2;
/// Implicit NULL (RFC 3032 §2.1): advertised, never on the wire — the
/// upstream router pops (penultimate hop popping).
pub const IMPLICIT_NULL: u32 = 3;
/// Largest `net.mpls.platform_labels` Linux accepts
/// (Documentation/networking/mpls-sysctl.rst: 0..=1048575).
pub const LINUX_MAX_PLATFORM_LABELS: u32 = MAX_LABEL;
/// Bytes one label stack entry adds to a packet (RFC 3032 §2.1).
pub const LABEL_BYTES: u32 = 4;
/// Longest outgoing label stack a static entry may push (Linux
/// `MAX_NEW_LABELS`, net/mpls/internal.h).
pub const MAX_PUSH: usize = 30;
/// Static entries at most (hostile input; each is one kernel route).
pub const MAX_STATIC: usize = 200_000;
/// LDP interfaces and configured neighbors at most.
pub const MAX_LDP_INTERFACES: usize = 1024;
pub const MAX_LDP_NEIGHBORS: usize = 1024;

/// RFC 5036 §2.4.1 / §3.5.2: link Hello every 5 s, held 15 s (3 ×).
pub const DEFAULT_HELLO_INTERVAL: u16 = 5;
pub const DEFAULT_HOLD_TIME: u16 = 15;
/// RFC 5036 §2.5.5: KeepAlive hold time FRR and RouterOS use (180 s).
pub const DEFAULT_KEEPALIVE_HOLD: u16 = 180;
/// The IP packet a customer sends: the MTU check adds the label stack
/// to it (RFC 3032 §3.2).
pub const DEFAULT_PAYLOAD_MTU: u32 = 1500;

/// `/mpls` as a whole. Empty: no MPLS at all (nothing applied).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mpls {
    #[serde(skip_serializing_if = "MplsSettings::is_default")]
    pub settings: MplsSettings,
    /// `/mpls interface`, by interface name (`all` is every interface).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub interfaces: BTreeMap<String, MplsInterface>,
    /// `/mpls ldp`: `None` until one is added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldp: Option<LdpInstance>,
    /// `/mpls ldp interface`, by interface.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub ldp_interfaces: BTreeMap<IfName, LdpInterface>,
    /// `/mpls ldp neighbor` (configured ones: targeted sessions and the
    /// per-neighbor password), by the neighbor's LSR id.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub ldp_neighbors: BTreeMap<Ipv4Addr, LdpNeighbor>,
    /// `/mpls static`, by incoming label.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub statics: BTreeMap<u32, StaticLsp>,
}

impl Mpls {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// MPLS is in use: something needs the kernel's label table.
    pub fn in_use(&self) -> bool {
        self.ldp.as_ref().is_some_and(|l| !l.disabled)
            || self.statics.values().any(|s| !s.disabled)
            || self.interfaces.values().any(|i| !i.disabled)
    }

    /// The LDP instance, when it runs.
    pub fn ldp_running(&self) -> Option<&LdpInstance> {
        self.ldp.as_ref().filter(|l| !l.disabled)
    }

    /// Whether interface `name` accepts labeled packets (Linux
    /// `net.mpls.conf.<name>.input`): an enabled `/mpls interface` for it
    /// or for `all`, or LDP running on it (RouterOS: LDP needs input).
    pub fn input_on(&self, name: &IfName) -> bool {
        let entry = self
            .interfaces
            .get(name.as_str())
            .or_else(|| self.interfaces.get(ALL))
            .filter(|i| !i.disabled);
        if let Some(e) = entry {
            return e.input;
        }
        self.ldp_running().is_some()
            && self.ldp_interfaces.get(name).is_some_and(|i| !i.disabled)
    }
}

/// The `/mpls interface` entry that covers every interface.
pub const ALL: &str = "all";

/// `/mpls settings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MplsSettings {
    /// Labels the router hands out (RouterOS `dynamic-label-range`,
    /// default 16-1048575). Linux sizes its label table from the end
    /// (`platform_labels` = end + 1, at most 1048575: Linux cannot use
    /// label 1048575 itself).
    pub dynamic_label_range: (u32, u32),
    /// Copy the IP TTL into the label and back (RFC 3032 §2.4.3; Linux
    /// `ip_ttl_propagate`). Off hides the core from traceroute.
    pub propagate_ttl: bool,
    /// The IP packet size the MTU check assumes (not a RouterOS setting).
    pub payload_mtu: u32,
    /// Answer MPLS echo requests (LSP ping / traceroute, RFC 8029; G3.5b).
    /// On by default, as on Cisco and Junos: a ping that reaches this
    /// router would otherwise look like a broken LSP.
    pub lsp_ping_responder: bool,
    /// Echo replies per second at most (RFC 8029 §5: "A rate limiter
    /// SHOULD be applied"); the rest are dropped and counted.
    pub lsp_ping_rate: u32,
    /// Send ICMP "time exceeded" (with the RFC 4950 label stack) for a
    /// labeled packet whose TTL expires here (G3.9d): the Linux forwarder
    /// drops it silently and traceroute shows `*`. On by default, as on
    /// RouterOS, Cisco and Junos.
    pub icmp_ttl_exceeded: bool,
    /// Those errors per second at most; the rest are dropped and counted.
    pub icmp_rate: u32,
}

/// Default of [`MplsSettings::lsp_ping_rate`] (replies per second).
pub const DEFAULT_LSP_PING_RATE: u32 = 100;
/// Default of [`MplsSettings::icmp_rate`] (errors per second).
pub const DEFAULT_ICMP_RATE: u32 = 100;
/// Highest [`MplsSettings::icmp_rate`].
pub const MAX_ICMP_RATE: u32 = 10_000;
/// Highest [`MplsSettings::lsp_ping_rate`].
pub const MAX_LSP_PING_RATE: u32 = 10_000;

impl Default for MplsSettings {
    fn default() -> Self {
        Self {
            dynamic_label_range: (FIRST_UNRESERVED, MAX_LABEL),
            propagate_ttl: true,
            payload_mtu: DEFAULT_PAYLOAD_MTU,
            lsp_ping_responder: true,
            lsp_ping_rate: DEFAULT_LSP_PING_RATE,
            icmp_ttl_exceeded: true,
            icmp_rate: DEFAULT_ICMP_RATE,
        }
    }
}

impl MplsSettings {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Linux `net.mpls.platform_labels`: one more than the highest label
    /// accepted (the table holds 0..platform_labels).
    pub fn platform_labels(&self) -> u32 {
        self.dynamic_label_range.1.saturating_add(1).min(LINUX_MAX_PLATFORM_LABELS)
    }
}

/// `/mpls interface`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MplsInterface {
    /// Accept labeled packets here.
    #[serde(default = "yes")]
    pub input: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}

/// Which address families LDP runs (RouterOS `afi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Afi {
    /// IPv4 (RouterOS `ip`).
    Ip,
    Ipv6,
}

impl Afi {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Ipv6 => "ipv6",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ip" | "ipv4" => Some(Self::Ip),
            "ipv6" => Some(Self::Ipv6),
            _ => None,
        }
    }
}

fn default_afi() -> Vec<Afi> {
    vec![Afi::Ip]
}

fn is_default_afi(a: &[Afi]) -> bool {
    a == [Afi::Ip]
}

/// `/mpls ldp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdpInstance {
    /// The LSR id (RFC 5036 §2.2.2: the first four octets of the LDP
    /// identifier), usually the loopback address.
    pub lsr_id: Ipv4Addr,
    /// Address families (`ip`, `ipv6`).
    #[serde(default = "default_afi", skip_serializing_if = "is_default_afi")]
    pub afi: Vec<Afi>,
    /// The address TCP sessions start from, at most one per family
    /// (RFC 5036 §2.5.2). IPv4 default: the LSR id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_addresses: Vec<IpAddr>,
    /// RFC 7552 §6.1: with both families, the session goes over IPv6
    /// unless this says `ip`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_afi: Option<Afi>,
    /// Advertise explicit NULL instead of implicit NULL for local routes
    /// (RFC 3032 §2.1): the last hop sees the label and its TC bits.
    #[serde(default)]
    pub use_explicit_null: bool,
    /// LDP-IGP synchronization (RFC 5443): the IGP keeps a link at its
    /// maximum cost until LDP is up on it, so traffic never takes a link
    /// without labels. On by default (an addition to RouterOS).
    #[serde(default = "yes")]
    pub igp_sync: bool,
    /// Seconds the IGP waits for LDP before using the link anyway
    /// (RFC 5443 §4, FRR `holddown`); `None`: forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub igp_sync_holddown: Option<u16>,
    /// GTSM (RFC 6720): LDP packets of directly connected peers must
    /// arrive with TTL 255. On by default (RFC 7552 §9 makes it the
    /// default for IPv6).
    #[serde(default = "yes")]
    pub gtsm: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

impl LdpInstance {
    pub fn new(lsr_id: Ipv4Addr) -> Self {
        Self {
            lsr_id,
            afi: default_afi(),
            transport_addresses: Vec::new(),
            preferred_afi: None,
            use_explicit_null: false,
            igp_sync: true,
            igp_sync_holddown: None,
            gtsm: true,
            disabled: false,
            comment: String::new(),
        }
    }

    pub fn runs(&self, afi: Afi) -> bool {
        self.afi.contains(&afi)
    }

    /// The transport address of `afi`: the configured one, or the LSR id
    /// for IPv4 (RFC 5036 §2.5.2 default). IPv6 has no default here: FRR
    /// then uses the interface's address, so one is required.
    pub fn transport(&self, afi: Afi) -> Option<IpAddr> {
        let want_v4 = afi == Afi::Ip;
        self.transport_addresses
            .iter()
            .copied()
            .find(|a| a.is_ipv4() == want_v4)
            .or_else(|| want_v4.then_some(IpAddr::V4(self.lsr_id)))
    }
}

/// `/mpls ldp interface`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdpInterface {
    /// Seconds between link Hellos (RFC 5036 §2.4.1).
    #[serde(default = "default_hello")]
    pub hello_interval: u16,
    /// Seconds a neighbor's Hello is held (RFC 5036 §3.5.2).
    #[serde(default = "default_hold")]
    pub hold_time: u16,
    /// Families on this interface; empty: the instance's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub afi: Vec<Afi>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn default_hello() -> u16 {
    DEFAULT_HELLO_INTERVAL
}

fn default_hold() -> u16 {
    DEFAULT_HOLD_TIME
}

impl Default for LdpInterface {
    fn default() -> Self {
        Self {
            hello_interval: DEFAULT_HELLO_INTERVAL,
            hold_time: DEFAULT_HOLD_TIME,
            afi: Vec::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

/// A configured `/mpls ldp neighbor`: the LSR id names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdpNeighbor {
    /// Send targeted Hellos to this address (RFC 5036 §2.4.2, extended
    /// discovery): a session to a router that is not adjacent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targeted: Option<IpAddr>,
    /// TCP MD5 signature key (RFC 5036 §2.9), sealed like a BGP key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Sealed>,
    /// KeepAlive hold time of the session, seconds (RFC 5036 §2.5.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_hold: Option<u16>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// What a static entry does with the top label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLsp {
    /// Where the packet goes next.
    pub nexthop: IpAddr,
    /// The outgoing interface; `None`: the kernel finds it from `nexthop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<IfName>,
    /// The labels that replace the incoming one, top first; empty: pop
    /// (implicit NULL, RFC 3032 §2.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_labels: Vec<u32>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// RouterOS text of an outgoing label stack: `implicit-null (pop)` when
/// empty, `16 17` otherwise.
pub fn stack_text(labels: &[u32]) -> String {
    if labels.is_empty() {
        return "implicit-null (pop)".to_owned();
    }
    labels
        .iter()
        .map(|l| label_text(*l))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A label, with the name of a reserved value (RFC 3032 §2.1).
pub fn label_text(l: u32) -> String {
    match l {
        IPV4_EXPLICIT_NULL => "explicit-null".to_owned(),
        ROUTER_ALERT => "router-alert".to_owned(),
        IPV6_EXPLICIT_NULL => "ipv6-explicit-null".to_owned(),
        IMPLICIT_NULL => "implicit-null".to_owned(),
        l => l.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_has_no_mpls_and_round_trips() {
        let m = Mpls::default();
        assert!(m.is_default());
        assert!(!m.in_use());
        assert_eq!(serde_json::to_string(&m).unwrap(), "{}");
        let back: Mpls = serde_json::from_str("{}").unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn platform_labels_follow_the_range() {
        let mut s = MplsSettings::default();
        assert_eq!(s.platform_labels(), 1_048_575);
        s.dynamic_label_range = (16, 9999);
        assert_eq!(s.platform_labels(), 10_000);
    }

    #[test]
    fn input_comes_from_mpls_interface_or_ldp() {
        let e1: IfName = "ether1".parse().unwrap();
        let e2: IfName = "ether2".parse().unwrap();
        let mut m = Mpls::default();
        assert!(!m.input_on(&e1));
        m.ldp = Some(LdpInstance::new([10, 0, 0, 1].into()));
        m.ldp_interfaces.insert(e1.clone(), LdpInterface::default());
        assert!(m.input_on(&e1));
        assert!(!m.input_on(&e2));
        m.interfaces.insert(
            ALL.into(),
            MplsInterface {
                input: true,
                disabled: false,
                comment: String::new(),
            },
        );
        assert!(m.input_on(&e2));
        m.interfaces.insert(
            "ether1".into(),
            MplsInterface {
                input: false,
                disabled: false,
                comment: String::new(),
            },
        );
        assert!(!m.input_on(&e1), "an entry of its own wins over all");
    }

    #[test]
    fn transport_defaults_to_the_lsr_id_for_ipv4_only() {
        let l = LdpInstance::new([10, 0, 0, 1].into());
        assert_eq!(l.transport(Afi::Ip), Some(IpAddr::from([10, 0, 0, 1])));
        assert_eq!(l.transport(Afi::Ipv6), None);
        // RFC 5443 and RFC 6720 on by default.
        assert!(l.igp_sync && l.gtsm);
        let j: LdpInstance = serde_json::from_str(r#"{"lsr_id":"10.0.0.1"}"#).unwrap();
        assert_eq!(j, l);
    }

    #[test]
    fn stacks_read_like_routeros() {
        assert_eq!(stack_text(&[]), "implicit-null (pop)");
        assert_eq!(stack_text(&[16, 0]), "16 explicit-null");
    }
}

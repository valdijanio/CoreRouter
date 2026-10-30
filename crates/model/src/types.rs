//! Network value types. Every constructor validates; parsing never panics.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} '{input}': {reason}")]
pub struct ParseError {
    pub kind: &'static str,
    pub input: String,
    pub reason: &'static str,
}

impl ParseError {
    pub(crate) fn new(kind: &'static str, input: &str, reason: &'static str) -> Self {
        // Hostile input may be huge: keep only a bounded prefix in the message.
        let input: String = input.chars().take(64).collect();
        Self {
            kind,
            input,
            reason,
        }
    }
}

/// Implements Display/Serialize/Deserialize through `Display` + `FromStr`.
macro_rules! string_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                raw.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Autonomous System Number (RFC 6793, 4-byte). Accepts asplain (`65000`)
/// and asdot (`1.10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// AS_TRANS (RFC 6793) — never valid as a local or peer AS.
    pub const TRANS: Asn = Asn(23456);

    pub fn is_private(self) -> bool {
        (64512..=65534).contains(&self.0) || (4_200_000_000..=4_294_967_294).contains(&self.0)
    }

    pub fn is_reserved(self) -> bool {
        self.0 == 0 || self == Self::TRANS || self.0 == 65535 || self.0 == u32::MAX
    }
}

impl FromStr for Asn {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s
            .strip_prefix("AS")
            .or_else(|| s.strip_prefix("as"))
            .unwrap_or(s);
        if let Some((hi, lo)) = s.split_once('.') {
            let hi: u16 = hi
                .parse()
                .map_err(|_| ParseError::new("ASN", s, "asdot high part must be 0..=65535"))?;
            let lo: u16 = lo
                .parse()
                .map_err(|_| ParseError::new("ASN", s, "asdot low part must be 0..=65535"))?;
            return Ok(Asn((u32::from(hi) << 16) | u32::from(lo)));
        }
        s.parse::<u32>()
            .map(Asn)
            .map_err(|_| ParseError::new("ASN", s, "expected 0..=4294967295 or asdot X.Y"))
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Asn {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Asn(n)),
            Raw::Text(t) => t.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// 802.1Q VLAN id, 1..=4094 (0 and 4095 are reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct VlanId(u16);

impl VlanId {
    pub fn new(id: u16) -> Result<Self, ParseError> {
        if (1..=4094).contains(&id) {
            Ok(Self(id))
        } else {
            Err(ParseError::new(
                "VLAN id",
                &id.to_string(),
                "must be 1..=4094",
            ))
        }
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for VlanId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        VlanId::new(u16::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// EUI-48 MAC address, `AA:BB:CC:DD:EE:FF` (also accepts `-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl FromStr for MacAddr {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);
        for byte in out.iter_mut() {
            let part = parts
                .next()
                .ok_or_else(|| ParseError::new("MAC", s, "expected 6 octets"))?;
            if part.len() != 2 {
                return Err(ParseError::new("MAC", s, "each octet is 2 hex digits"));
            }
            *byte = u8::from_str_radix(part, 16)
                .map_err(|_| ParseError::new("MAC", s, "invalid hex digit"))?;
        }
        if parts.next().is_some() {
            return Err(ParseError::new("MAC", s, "expected 6 octets"));
        }
        Ok(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}
string_serde!(MacAddr);

/// Interface name with Linux rules: 1..=15 bytes (IFNAMSIZ - 1), ASCII
/// alphanumerics plus `-`, `_`, `.`; never `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfName(String);

impl IfName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for IfName {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 15 {
            return Err(ParseError::new("interface name", s, "must be 1..=15 bytes"));
        }
        if s == "." || s == ".." {
            return Err(ParseError::new("interface name", s, "reserved name"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ParseError::new(
                "interface name",
                s,
                "allowed: ASCII letters, digits, '-', '_', '.'",
            ));
        }
        Ok(IfName(s.to_owned()))
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(IfName);

/// MikroTik-style item id, displayed as `*1`, `*2A` (hex).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId(pub u32);

impl FromStr for ItemId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.trim().strip_prefix('*').unwrap_or(s.trim());
        u32::from_str_radix(hex, 16)
            .map(ItemId)
            .map_err(|_| ParseError::new("item id", s, "expected *<hex>"))
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "*{:X}", self.0)
    }
}
string_serde!(ItemId);

/// What a route with no next hop does with a packet (G1.5a): RouterOS v6
/// `type=blackhole|unreachable|prohibit` (v7: `blackhole`), Junos
/// `discard`/`reject`, IOS `Null0`; in Linux `RTN_BLACKHOLE`,
/// `RTN_UNREACHABLE`, `RTN_PROHIBIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Discard {
    /// Dropped silently.
    Blackhole,
    /// Dropped with ICMP "network unreachable" (RFC 792; ICMPv6 "no route",
    /// RFC 4443 §3.1).
    Unreachable,
    /// Dropped with ICMP "administratively prohibited" (RFC 1812 §5.2.7.1;
    /// ICMPv6 "administratively prohibited").
    Prohibit,
}

impl Discard {
    pub const ALL: [Self; 3] = [Self::Blackhole, Self::Unreachable, Self::Prohibit];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blackhole => "blackhole",
            Self::Unreachable => "unreachable",
            Self::Prohibit => "prohibit",
        }
    }

    /// The flag of `ip.route.list` (RouterOS v6: B, U, P).
    pub fn flag(self) -> char {
        match self {
            Self::Blackhole => 'B',
            Self::Unreachable => 'U',
            Self::Prohibit => 'P',
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == s)
    }
}

/// Next hop of a static route, RouterOS syntax: `10.0.0.1` (resolved through
/// a connected network), `ether1` (out of that interface) or
/// `fe80::1%ether1` (that address, out of that interface); or no next hop
/// at all, `blackhole`, `unreachable` or `prohibit` (G1.5a, [`Discard`]).
/// An address or an interface is present unless it discards.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gateway {
    address: Option<IpAddr>,
    interface: Option<IfName>,
    discard: Option<Discard>,
}

impl Gateway {
    /// No next hop: the route drops what it matches (G1.5a).
    pub fn discard(d: Discard) -> Self {
        Self {
            address: None,
            interface: None,
            discard: Some(d),
        }
    }

    /// What it does without a next hop; `None` for a next hop.
    pub fn discards(&self) -> Option<Discard> {
        self.discard
    }

    pub fn ip(address: IpAddr) -> Self {
        Self {
            address: Some(address),
            interface: None,
            discard: None,
        }
    }

    pub fn interface(interface: IfName) -> Self {
        Self {
            address: None,
            interface: Some(interface),
            discard: None,
        }
    }

    pub fn via(address: IpAddr, interface: IfName) -> Self {
        Self {
            address: Some(address),
            interface: Some(interface),
            discard: None,
        }
    }

    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    pub fn iface(&self) -> Option<&IfName> {
        self.interface.as_ref()
    }
}

impl FromStr for Gateway {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if let Some((ip, iface)) = t.split_once('%') {
            let ip = ip
                .parse()
                .map_err(|_| ParseError::new("gateway", s, "expected <ip>%<interface>"))?;
            let iface = iface
                .parse()
                .map_err(|_| ParseError::new("gateway", s, "invalid interface after '%'"))?;
            return Ok(Self::via(ip, iface));
        }
        // The three words of a route without next hop win over interfaces
        // of the same name (`blackhole%` would need an address before it).
        if let Some(d) = Discard::parse(t) {
            return Ok(Self::discard(d));
        }
        // An address wins: "10.0.0.1" would also be a legal interface name.
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(Self::ip(ip));
        }
        t.parse::<IfName>().map(Self::interface).map_err(|_| {
            ParseError::new(
                "gateway",
                s,
                "expected an IP, an interface, <ip>%<interface>, blackhole, unreachable or \
                 prohibit",
            )
        })
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = self.discard {
            return f.write_str(d.as_str());
        }
        match (&self.address, &self.interface) {
            (Some(a), Some(i)) => write!(f, "{a}%{i}"),
            (Some(a), None) => write!(f, "{a}"),
            (None, Some(i)) => write!(f, "{i}"),
            (None, None) => Ok(()),
        }
    }
}
string_serde!(Gateway);

/// Routing table of a route: `main`, or the name of a VRF (whose kernel
/// device has the same name, so VRF names follow interface-name rules).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoutingTable {
    #[default]
    Main,
    Vrf(IfName),
}

impl RoutingTable {
    pub const MAIN: &'static str = "main";

    pub fn is_main(&self) -> bool {
        matches!(self, Self::Main)
    }
}

impl FromStr for RoutingTable {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if t == Self::MAIN {
            return Ok(Self::Main);
        }
        t.parse::<IfName>().map(Self::Vrf).map_err(|_| {
            ParseError::new(
                "routing table",
                s,
                "expected \"main\" or a VRF name (1..=15 of A-Z a-z 0-9 - _ .)",
            )
        })
    }
}

impl fmt::Display for RoutingTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Main => f.write_str(Self::MAIN),
            Self::Vrf(name) => write!(f, "{name}"),
        }
    }
}
string_serde!(RoutingTable);

/// Destination of a route: a prefix, or a bare address meaning a host route
/// (`/32`, `/128`), as RouterOS accepts it.
pub fn parse_destination(s: &str) -> Result<IpNet, ParseError> {
    let t = s.trim();
    if let Ok(net) = t.parse::<IpNet>() {
        return Ok(net);
    }
    t.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| ParseError::new("destination", s, "expected a prefix like 10.0.0.0/8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn asn_forms() {
        assert_eq!("65000".parse::<Asn>().unwrap(), Asn(65000));
        assert_eq!("AS65000".parse::<Asn>().unwrap(), Asn(65000));
        assert_eq!("1.10".parse::<Asn>().unwrap(), Asn(65546));
        assert!("1.70000".parse::<Asn>().is_err());
        assert!(Asn::TRANS.is_reserved());
        assert!(Asn(64512).is_private());
    }

    #[test]
    fn vlan_bounds() {
        assert!(VlanId::new(0).is_err());
        assert!(VlanId::new(4095).is_err());
        assert_eq!(VlanId::new(100).unwrap().get(), 100);
        assert!(serde_json::from_str::<VlanId>("4095").is_err());
    }

    #[test]
    fn ifname_rules() {
        assert!("ether1".parse::<IfName>().is_ok());
        assert!("vlan100.ether1".parse::<IfName>().is_ok());
        assert!("a-very-long-interface".parse::<IfName>().is_err());
        assert!("eth 0".parse::<IfName>().is_err());
        assert!("..".parse::<IfName>().is_err());
    }

    #[test]
    fn mac_and_item_roundtrip() {
        let mac: MacAddr = "aa:bb:cc:00:11:22".parse().unwrap();
        assert_eq!(mac.to_string(), "AA:BB:CC:00:11:22");
        assert!("aa:bb:cc:00:11".parse::<MacAddr>().is_err());
        let id: ItemId = "*1F".parse().unwrap();
        assert_eq!(id, ItemId(31));
        assert_eq!(id.to_string(), "*1F");
    }

    #[test]
    fn gateway_forms_roundtrip() {
        for (text, ip, iface) in [
            ("10.0.0.1", Some("10.0.0.1"), None),
            ("ether1", None, Some("ether1")),
            ("fe80::1%ether1", Some("fe80::1"), Some("ether1")),
            ("2001:db8::1", Some("2001:db8::1"), None),
        ] {
            let g: Gateway = text.parse().unwrap();
            assert_eq!(g.address(), ip.map(|i| i.parse().unwrap()), "{text}");
            assert_eq!(g.iface().map(IfName::as_str), iface, "{text}");
            assert_eq!(g.to_string(), text);
        }
        assert!("10.0.0.1%".parse::<Gateway>().is_err());
        assert!("x%ether1".parse::<Gateway>().is_err());
        assert!("eth 1".parse::<Gateway>().is_err());
        assert!("".parse::<Gateway>().is_err());
    }

    #[test]
    fn tables_and_destinations() {
        assert_eq!("main".parse::<RoutingTable>().unwrap(), RoutingTable::Main);
        assert_eq!(
            "vrf-cust".parse::<RoutingTable>().unwrap().to_string(),
            "vrf-cust"
        );
        assert!("a b".parse::<RoutingTable>().is_err());
        assert_eq!(
            parse_destination("0.0.0.0/0").unwrap().to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(parse_destination("::/0").unwrap().to_string(), "::/0");
        assert_eq!(
            parse_destination("10.1.1.1").unwrap().to_string(),
            "10.1.1.1/32"
        );
        assert_eq!(parse_destination("2001:db8::1").unwrap().prefix_len(), 128);
        assert!(parse_destination("10.0.0.0/33").is_err());
    }

    proptest! {
        #[test]
        fn parsers_never_panic(s in ".{0,64}") {
            let _ = s.parse::<Asn>();
            let _ = s.parse::<IfName>();
            let _ = s.parse::<MacAddr>();
            let _ = s.parse::<ItemId>();
            let _ = s.parse::<Gateway>();
            let _ = s.parse::<RoutingTable>();
            let _ = parse_destination(&s);
        }
    }
}

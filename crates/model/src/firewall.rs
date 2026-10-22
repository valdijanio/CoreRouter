//! `/ip firewall` (filter, nat, mangle, address-lists), RouterOS model with
//! one difference: IPv4 and IPv6 rules live in the same lists, and each rule
//! says which families it applies to (`family`).
//!
//! Matchers are stored in RouterOS syntax, `!` negation included
//! (`"src_address": "!10.0.0.0/8"`, `"dst_port": "80,443,8000-8080"`), so the
//! JSON, the CLI and the GUI read the same. Every value type validates when
//! parsed; cross-checks (action valid in that chain, ports only with a
//! protocol that has ports…) live in `corerouter-firewall::validate`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::{IfName, ItemId, ParseError};

/// Implements Serialize/Deserialize through `Display` + `FromStr`.
macro_rules! text_serde {
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

/// The three rule tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Table {
    Filter,
    Nat,
    Mangle,
}

impl Table {
    pub const ALL: [Table; 3] = [Table::Filter, Table::Nat, Table::Mangle];

    pub fn name(self) -> &'static str {
        match self {
            Table::Filter => "filter",
            Table::Nat => "nat",
            Table::Mangle => "mangle",
        }
    }

    /// Built-in chains, in packet order.
    pub fn builtin_chains(self) -> &'static [&'static str] {
        match self {
            Table::Filter => &["input", "forward", "output"],
            Table::Nat => &["dstnat", "srcnat"],
            Table::Mangle => &["prerouting", "input", "forward", "output", "postrouting"],
        }
    }
}

impl FromStr for Table {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "filter" => Ok(Table::Filter),
            "nat" => Ok(Table::Nat),
            "mangle" => Ok(Table::Mangle),
            _ => Err(ParseError::new(
                "table",
                s,
                "expected filter, nat or mangle",
            )),
        }
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A name the operator gives: address list, interface list, chain, mark.
/// 1..=63 bytes of ASCII letters, digits, `-`, `_`, `.` — safe to embed in
/// an nftables identifier without quoting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    pub const MAX: usize = 63;

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Name {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > Self::MAX {
            return Err(ParseError::new("name", s, "must be 1..=63 characters"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ParseError::new(
                "name",
                s,
                "allowed: ASCII letters, digits, '-', '_', '.'",
            ));
        }
        Ok(Name(s.to_owned()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
text_serde!(Name);

/// Which IP families a rule applies to. RouterOS keeps `/ip firewall` and
/// `/ipv6 firewall` apart; here one list holds both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    #[default]
    Both,
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }

    pub fn has_v4(self) -> bool {
        self != Family::Ipv6
    }

    pub fn has_v6(self) -> bool {
        self != Family::Ipv4
    }

    /// Both constraints at once, or `None` if they exclude each other.
    pub fn and(self, other: Family) -> Option<Family> {
        match (self, other) {
            (Family::Both, x) | (x, Family::Both) => Some(x),
            (a, b) if a == b => Some(a),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Family::Both => "both",
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }
}

impl FromStr for Family {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "both" | "any" | "" => Ok(Family::Both),
            "ipv4" | "ip" | "4" => Ok(Family::Ipv4),
            "ipv6" | "6" => Ok(Family::Ipv6),
            _ => Err(ParseError::new("family", s, "expected both, ipv4 or ipv6")),
        }
    }
}

/// A matcher value with RouterOS `!` negation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Neg<T> {
    pub not: bool,
    pub value: T,
}

impl<T> Neg<T> {
    pub fn is(value: T) -> Self {
        Self { not: false, value }
    }
}

impl<T: FromStr<Err = ParseError>> FromStr for Neg<T> {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        match s.strip_prefix('!') {
            Some(rest) => Ok(Neg {
                not: true,
                value: rest.trim().parse()?,
            }),
            None => Ok(Neg {
                not: false,
                value: s.parse()?,
            }),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Neg<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.not {
            f.write_str("!")?;
        }
        self.value.fmt(f)
    }
}

impl<T: fmt::Display> Serialize for Neg<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de, T: FromStr<Err = ParseError>> Deserialize<'de> for Neg<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// An address, a prefix (`10.0.0.0/8`) or a range (`10.0.0.1-10.0.0.9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddrMatch {
    Net(IpNet),
    Range(IpAddr, IpAddr),
}

impl AddrMatch {
    pub fn family(&self) -> Family {
        match self {
            AddrMatch::Net(n) => Family::of(n.addr()),
            AddrMatch::Range(a, _) => Family::of(*a),
        }
    }

    /// First and last address covered.
    pub fn bounds(&self) -> (IpAddr, IpAddr) {
        match self {
            AddrMatch::Net(n) => (n.network(), n.broadcast()),
            AddrMatch::Range(a, b) => (*a, *b),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (lo, hi) = self.bounds();
        Family::of(ip) == self.family() && lo <= ip && ip <= hi
    }

    /// Whether every address of `other` is in `self`.
    pub fn covers(&self, other: &AddrMatch) -> bool {
        let (lo, hi) = self.bounds();
        let (olo, ohi) = other.bounds();
        self.family() == other.family() && lo <= olo && ohi <= hi
    }
}

impl FromStr for AddrMatch {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            let a: IpAddr = a
                .trim()
                .parse()
                .map_err(|_| ParseError::new("address range", s, "expected IP-IP"))?;
            let b: IpAddr = b
                .trim()
                .parse()
                .map_err(|_| ParseError::new("address range", s, "expected IP-IP"))?;
            if Family::of(a) != Family::of(b) {
                return Err(ParseError::new(
                    "address range",
                    s,
                    "both ends must be the same family",
                ));
            }
            if a > b {
                return Err(ParseError::new(
                    "address range",
                    s,
                    "the first address must not be above the last",
                ));
            }
            return Ok(AddrMatch::Range(a, b));
        }
        if s.contains('/') {
            let net: IpNet = s
                .parse()
                .map_err(|_| ParseError::new("address", s, "expected IP, IP/prefix or IP-IP"))?;
            if net != net.trunc() {
                return Err(ParseError::new(
                    "address",
                    s,
                    "host bits set (write the network address)",
                ));
            }
            return Ok(AddrMatch::Net(net));
        }
        let ip: IpAddr = s
            .parse()
            .map_err(|_| ParseError::new("address", s, "expected IP, IP/prefix or IP-IP"))?;
        Ok(AddrMatch::Net(IpNet::from(ip)))
    }
}

impl fmt::Display for AddrMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => write!(f, "{}", n.addr()),
            AddrMatch::Net(n) => write!(f, "{n}"),
            AddrMatch::Range(a, b) => write!(f, "{a}-{b}"),
        }
    }
}
text_serde!(AddrMatch);

/// IP protocol number, with RouterOS names for the common ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Protocol(pub u8);

const PROTOCOLS: &[(&str, u8)] = &[
    ("icmp", 1),
    ("igmp", 2),
    ("ipip", 4),
    ("tcp", 6),
    ("udp", 17),
    ("ipv6-encap", 41),
    ("rsvp", 46),
    ("gre", 47),
    ("ipsec-esp", 50),
    ("ipsec-ah", 51),
    ("icmpv6", 58),
    ("ospf", 89),
    ("pim", 103),
    ("vrrp", 112),
    ("l2tp", 115),
    ("sctp", 132),
    ("udp-lite", 136),
];

impl Protocol {
    pub const ICMP: Protocol = Protocol(1);
    pub const TCP: Protocol = Protocol(6);
    pub const UDP: Protocol = Protocol(17);
    pub const ICMPV6: Protocol = Protocol(58);
    pub const SCTP: Protocol = Protocol(132);
    pub const UDPLITE: Protocol = Protocol(136);

    /// Protocols with source/destination ports.
    pub fn has_ports(self) -> bool {
        matches!(self.0, 6 | 17 | 132 | 136 | 33)
    }

    pub fn name(self) -> Option<&'static str> {
        PROTOCOLS
            .iter()
            .find(|(_, n)| *n == self.0)
            .map(|(s, _)| *s)
    }
}

impl FromStr for Protocol {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let alias = match s {
            "ipv6-icmp" | "icmp6" => "icmpv6",
            "esp" => "ipsec-esp",
            "ah" => "ipsec-ah",
            "udplite" => "udp-lite",
            other => other,
        };
        if let Some((_, n)) = PROTOCOLS.iter().find(|(name, _)| *name == alias) {
            return Ok(Protocol(*n));
        }
        s.parse::<u8>().map(Protocol).map_err(|_| {
            ParseError::new(
                "protocol",
                s,
                "expected a name (tcp, udp, icmp, icmpv6, gre…) or 0..=255",
            )
        })
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "{}", self.0),
        }
    }
}
text_serde!(Protocol);

/// A port or a range of ports, `80` or `8000-8080`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.first <= port && port <= self.last
    }
}

impl FromStr for PortRange {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let port = |p: &str| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| ParseError::new("port", s, "expected 0..=65535 or a range A-B"))
        };
        let (first, last) = match s.split_once('-') {
            Some((a, b)) => (port(a)?, port(b)?),
            None => {
                let p = port(s)?;
                (p, p)
            }
        };
        if first > last {
            return Err(ParseError::new("port", s, "range start above its end"));
        }
        Ok(PortRange { first, last })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}
text_serde!(PortRange);

/// Comma-separated ports and ranges: `22,80,8000-8080` (at most 32 items).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortSet(pub Vec<PortRange>);

impl PortSet {
    pub const MAX: usize = 32;

    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|r| r.contains(port))
    }

    /// Whether every port of `other` is in `self`.
    pub fn covers(&self, other: &PortSet) -> bool {
        other.0.iter().all(|o| {
            // Each range of `other` must sit inside one of ours (ranges are
            // not merged, which only makes this answer "no" more often).
            self.0
                .iter()
                .any(|r| r.first <= o.first && o.last <= r.last)
        })
    }
}

impl FromStr for PortSet {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items: Vec<&str> = s.split(',').map(str::trim).collect();
        if items.len() > Self::MAX {
            return Err(ParseError::new("ports", s, "at most 32 ports or ranges"));
        }
        let mut out: Vec<PortRange> = Vec::with_capacity(items.len());
        for item in items {
            let r: PortRange = item.parse()?;
            if !out.contains(&r) {
                out.push(r);
            }
        }
        Ok(PortSet(out))
    }
}

impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            r.fmt(f)?;
        }
        Ok(())
    }
}
text_serde!(PortSet);

/// Connection tracking state (RouterOS `connection-state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnState {
    Established,
    Related,
    New,
    Invalid,
    Untracked,
}

impl ConnState {
    pub const ALL: [ConnState; 5] = [
        ConnState::Established,
        ConnState::Related,
        ConnState::New,
        ConnState::Invalid,
        ConnState::Untracked,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ConnState::Established => "established",
            ConnState::Related => "related",
            ConnState::New => "new",
            ConnState::Invalid => "invalid",
            ConnState::Untracked => "untracked",
        }
    }
}

/// `connection-nat-state`: the connection was source- or destination-NATed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NatState {
    Srcnat,
    Dstnat,
}

impl NatState {
    pub const ALL: [NatState; 2] = [NatState::Srcnat, NatState::Dstnat];

    pub fn name(self) -> &'static str {
        match self {
            NatState::Srcnat => "srcnat",
            NatState::Dstnat => "dstnat",
        }
    }
}

/// Comma-separated flags, kept sorted and without repeats.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Flags<T>(pub Vec<T>);

/// Names a flag type parses from.
pub trait Flag: Copy + Ord + 'static {
    const KIND: &'static str;
    const EXPECTED: &'static str;
    fn all() -> &'static [Self];
    fn flag_name(self) -> &'static str;
}

impl Flag for ConnState {
    const KIND: &'static str = "connection state";
    const EXPECTED: &'static str = "established, related, new, invalid, untracked";
    fn all() -> &'static [Self] {
        &ConnState::ALL
    }
    fn flag_name(self) -> &'static str {
        self.name()
    }
}

impl Flag for NatState {
    const KIND: &'static str = "connection NAT state";
    const EXPECTED: &'static str = "srcnat, dstnat";
    fn all() -> &'static [Self] {
        &NatState::ALL
    }
    fn flag_name(self) -> &'static str {
        self.name()
    }
}

impl<T: Flag> Flags<T> {
    pub fn contains(&self, f: T) -> bool {
        self.0.contains(&f)
    }
}

impl<T: Flag> FromStr for Flags<T> {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = Vec::new();
        for item in s.split(',').map(str::trim) {
            let f = T::all()
                .iter()
                .find(|f| f.flag_name() == item)
                .ok_or_else(|| ParseError::new(T::KIND, s, T::EXPECTED))?;
            if !out.contains(f) {
                out.push(*f);
            }
        }
        out.sort();
        Ok(Flags(out))
    }
}

impl<T: Flag> fmt::Display for Flags<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, x) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(x.flag_name())?;
        }
        Ok(())
    }
}

/// `icmp-options`: `type` or `type:code` (`8:0` is an echo request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcmpOptions {
    pub kind: u8,
    pub code: Option<u8>,
}

impl FromStr for IcmpOptions {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let num = |p: &str| {
            p.trim().parse::<u8>().map_err(|_| {
                ParseError::new("icmp options", s, "expected type or type:code (0..=255)")
            })
        };
        match s.split_once(':') {
            Some((t, c)) => Ok(IcmpOptions {
                kind: num(t)?,
                code: Some(num(c)?),
            }),
            None => Ok(IcmpOptions {
                kind: num(s)?,
                code: None,
            }),
        }
    }
}

impl fmt::Display for IcmpOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(c) => write!(f, "{}:{c}", self.kind),
            None => write!(f, "{}", self.kind),
        }
    }
}
text_serde!(IcmpOptions);

/// The unit of a [`Limit`] (the ones nftables has).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LimitPeriod {
    Second,
    Minute,
    Hour,
    Day,
}

impl LimitPeriod {
    pub fn secs(self) -> u32 {
        match self {
            LimitPeriod::Second => 1,
            LimitPeriod::Minute => 60,
            LimitPeriod::Hour => 3600,
            LimitPeriod::Day => 86_400,
        }
    }

    /// The nftables keyword.
    pub fn name(self) -> &'static str {
        match self {
            LimitPeriod::Second => "second",
            LimitPeriod::Minute => "minute",
            LimitPeriod::Hour => "hour",
            LimitPeriod::Day => "day",
        }
    }

    fn short(self) -> &'static str {
        match self {
            LimitPeriod::Second => "1s",
            LimitPeriod::Minute => "1m",
            LimitPeriod::Hour => "1h",
            LimitPeriod::Day => "1d",
        }
    }
}

/// `limit`: the rule matches at most `count` packets per `period`, plus a
/// `burst` of extra packets (RouterOS `limit=count/time,burst`; the times
/// are the ones nftables has: 1s, 1m, 1h, 1d).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limit {
    pub count: u32,
    pub period: LimitPeriod,
    pub burst: u32,
}

impl Limit {
    /// Hostile-input bound (**estimado**: far above any real rate).
    pub const MAX: u32 = 1_000_000;
    /// nftables' default burst.
    pub const DEFAULT_BURST: u32 = 5;
}

impl FromStr for Limit {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let bad = |why: &'static str| ParseError::new("limit", s, why);
        let (rate, burst) = match s.split_once(',') {
            Some((r, b)) => (r.trim(), Some(b.trim())),
            None => (s, None),
        };
        let (count, period) = rate
            .split_once('/')
            .ok_or_else(|| bad("expected count/time[,burst], like 5/1s,10"))?;
        let count: u32 = count
            .trim()
            .parse()
            .map_err(|_| bad("the count must be a whole number"))?;
        let period = match period.trim() {
            "s" | "1s" | "sec" | "second" => LimitPeriod::Second,
            "m" | "1m" | "min" | "minute" => LimitPeriod::Minute,
            "h" | "1h" | "hour" => LimitPeriod::Hour,
            "d" | "1d" | "day" => LimitPeriod::Day,
            _ => return Err(bad("the time must be 1s, 1m, 1h or 1d")),
        };
        let burst = match burst {
            Some(b) => b
                .trim()
                .parse()
                .map_err(|_| bad("the burst must be a whole number"))?,
            None => Limit::DEFAULT_BURST,
        };
        if count == 0 || count > Limit::MAX || burst > Limit::MAX {
            return Err(bad("count 1..=1000000, burst 0..=1000000"));
        }
        Ok(Limit {
            count,
            period,
            burst,
        })
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{},{}", self.count, self.period.short(), self.burst)
    }
}
text_serde!(Limit);

/// A RouterOS duration: `90` (seconds), `30s`, `5m`, `1h30m`, `1d`, `1w`;
/// 1 second ..= 35 days (nftables keeps timeouts in 32-bit milliseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeout(pub u32);

impl Timeout {
    pub const MAX: u32 = 35 * 86_400;

    pub fn secs(self) -> u32 {
        self.0
    }
}

impl FromStr for Timeout {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let text = s.trim();
        let bad = || {
            ParseError::new(
                "timeout",
                s,
                "expected seconds or a duration like 30s, 5m, 1h30m, 1d",
            )
        };
        if text.is_empty() || text.len() > 32 {
            return Err(bad());
        }
        let mut total: u64 = 0;
        let mut num = String::new();
        for c in text.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let unit: u64 = match c {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                _ => return Err(bad()),
            };
            let n: u64 = num.parse().map_err(|_| bad())?;
            total = total.saturating_add(n.saturating_mul(unit));
            num.clear();
        }
        if !num.is_empty() {
            let n: u64 = num.parse().map_err(|_| bad())?;
            total = total.saturating_add(n);
        }
        if total == 0 || total > u64::from(Timeout::MAX) {
            return Err(ParseError::new(
                "timeout",
                s,
                "must be 1 second ..= 35 days",
            ));
        }
        u32::try_from(total).map(Timeout).map_err(|_| bad())
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0;
        let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
        for (n, u) in [(d, "d"), (h, "h"), (m, "m"), (s, "s")] {
            if n > 0 {
                write!(f, "{n}{u}")?;
            }
        }
        Ok(())
    }
}
text_serde!(Timeout);

/// What a rule matches. Absent = any.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Matchers {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_address: Option<Neg<AddrMatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_address: Option<Neg<AddrMatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_address_list: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_address_list: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Neg<Protocol>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<Neg<PortSet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<Neg<PortSet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_interface: Option<Neg<IfName>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_interface: Option<Neg<IfName>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_interface_list: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_interface_list: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state: Option<Neg<Flags<ConnState>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_nat_state: Option<Neg<Flags<NatState>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_options: Option<IcmpOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_mark: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_mark: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<Neg<Name>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

impl Matchers {
    pub fn is_empty(&self) -> bool {
        *self == Matchers::default()
    }
}

/// `reject-with`, RouterOS names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum RejectWith {
    #[default]
    IcmpNoRoute,
    IcmpAdminProhibited,
    IcmpAddressUnreachable,
    IcmpPortUnreachable,
    TcpReset,
}

impl RejectWith {
    pub const ALL: [RejectWith; 5] = [
        RejectWith::IcmpNoRoute,
        RejectWith::IcmpAdminProhibited,
        RejectWith::IcmpAddressUnreachable,
        RejectWith::IcmpPortUnreachable,
        RejectWith::TcpReset,
    ];

    pub fn name(self) -> &'static str {
        match self {
            RejectWith::IcmpNoRoute => "icmp-no-route",
            RejectWith::IcmpAdminProhibited => "icmp-admin-prohibited",
            RejectWith::IcmpAddressUnreachable => "icmp-address-unreachable",
            RejectWith::IcmpPortUnreachable => "icmp-port-unreachable",
            RejectWith::TcpReset => "tcp-reset",
        }
    }
}

impl FromStr for RejectWith {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RejectWith::ALL
            .into_iter()
            .find(|r| r.name() == s.trim())
            .ok_or_else(|| {
                ParseError::new(
                    "reject-with",
                    s,
                    "expected icmp-no-route, icmp-admin-prohibited, icmp-address-unreachable, \
                     icmp-port-unreachable or tcp-reset",
                )
            })
    }
}

impl fmt::Display for RejectWith {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
text_serde!(RejectWith);

/// NAT target address: one address or a range of the same family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatTarget {
    pub first: IpAddr,
    pub last: IpAddr,
}

impl NatTarget {
    pub fn family(&self) -> Family {
        Family::of(self.first)
    }
}

impl FromStr for NatTarget {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<AddrMatch>()? {
            AddrMatch::Range(first, last) => Ok(NatTarget { first, last }),
            AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => Ok(NatTarget {
                first: n.addr(),
                last: n.addr(),
            }),
            AddrMatch::Net(_) => Err(ParseError::new(
                "to-addresses",
                s,
                "expected one address or a range A-B, not a prefix",
            )),
        }
    }
}

impl fmt::Display for NatTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}
text_serde!(NatTarget);

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

/// What a matching rule does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Accept,
    Drop,
    Reject {
        #[serde(default)]
        reject_with: RejectWith,
    },
    Jump {
        jump_target: Name,
    },
    Return,
    Log {
        #[serde(default)]
        log_prefix: String,
    },
    Passthrough,
    Masquerade {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_ports: Option<PortRange>,
    },
    SrcNat {
        to_addresses: NatTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_ports: Option<PortRange>,
    },
    DstNat {
        to_addresses: NatTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_ports: Option<PortRange>,
    },
    MarkConnection {
        new_connection_mark: Name,
        #[serde(default = "yes", skip_serializing_if = "is_true")]
        passthrough: bool,
    },
    MarkPacket {
        new_packet_mark: Name,
        #[serde(default = "yes", skip_serializing_if = "is_true")]
        passthrough: bool,
    },
    MarkRouting {
        new_routing_mark: Name,
        #[serde(default = "yes", skip_serializing_if = "is_true")]
        passthrough: bool,
    },
    /// Put the packet's source address in `address_list` (dynamic, kept in
    /// the kernel; without a timeout it stays until the next restart).
    /// The packet goes on to the next rule.
    AddSrcToAddressList {
        address_list: Name,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address_list_timeout: Option<Timeout>,
    },
    /// Same with the destination address.
    AddDstToAddressList {
        address_list: Name,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address_list_timeout: Option<Timeout>,
    },
}

impl Action {
    /// RouterOS action names, in menu order.
    pub const NAMES: [&'static str; 15] = [
        "accept",
        "drop",
        "reject",
        "jump",
        "return",
        "log",
        "passthrough",
        "masquerade",
        "src-nat",
        "dst-nat",
        "mark-connection",
        "mark-packet",
        "mark-routing",
        "add-src-to-address-list",
        "add-dst-to-address-list",
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Reject { .. } => "reject",
            Action::Jump { .. } => "jump",
            Action::Return => "return",
            Action::Log { .. } => "log",
            Action::Passthrough => "passthrough",
            Action::Masquerade { .. } => "masquerade",
            Action::SrcNat { .. } => "src-nat",
            Action::DstNat { .. } => "dst-nat",
            Action::MarkConnection { .. } => "mark-connection",
            Action::MarkPacket { .. } => "mark-packet",
            Action::MarkRouting { .. } => "mark-routing",
            Action::AddSrcToAddressList { .. } => "add-src-to-address-list",
            Action::AddDstToAddressList { .. } => "add-dst-to-address-list",
        }
    }

    /// The address list an `add-*-to-address-list` action fills.
    pub fn fills_list(&self) -> Option<&Name> {
        match self {
            Action::AddSrcToAddressList { address_list, .. }
            | Action::AddDstToAddressList { address_list, .. } => Some(address_list),
            _ => None,
        }
    }

    /// Whether a matching packet goes on to the next rule.
    pub fn continues(&self) -> bool {
        match self {
            Action::Log { .. }
            | Action::Passthrough
            | Action::AddSrcToAddressList { .. }
            | Action::AddDstToAddressList { .. } => true,
            Action::MarkConnection { passthrough, .. }
            | Action::MarkPacket { passthrough, .. }
            | Action::MarkRouting { passthrough, .. } => *passthrough,
            _ => false,
        }
    }
}

/// One firewall rule, or a section header (`section`: the comment is the
/// title, nothing is matched).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub id: ItemId,
    pub chain: Name,
    #[serde(default)]
    pub family: Family,
    #[serde(default, skip_serializing_if = "Matchers::is_empty")]
    pub matchers: Matchers,
    pub action: Action,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
    /// A section header groups the rules below it (until the next header);
    /// it never reaches the data plane.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub section: bool,
    /// Generated by the zone matrix (`ip.firewall.zone.*`): rewritten
    /// whenever the matrix changes, so the rule commands refuse to edit it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zone: bool,
}

/// One side of a zone-matrix cell: the router itself or the interfaces of
/// an interface list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Zone {
    Router,
    List(Name),
}

impl Zone {
    pub const ROUTER: &'static str = "router";
}

impl FromStr for Zone {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == Zone::ROUTER {
            return Ok(Zone::Router);
        }
        s.parse().map(Zone::List)
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zone::Router => f.write_str(Zone::ROUTER),
            Zone::List(n) => n.fmt(f),
        }
    }
}
text_serde!(Zone);

/// What a zone-matrix cell does with new connections from → to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneAction {
    Allow,
    Block,
}

impl ZoneAction {
    pub fn name(self) -> &'static str {
        match self {
            ZoneAction::Allow => "allow",
            ZoneAction::Block => "block",
        }
    }
}

/// One cell of the zone matrix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZonePolicy {
    pub from: Zone,
    pub to: Zone,
    pub action: ZoneAction,
}

/// A static `/ip firewall address-list` entry (IPv4 and IPv6 together).
/// Entries with a timeout are dynamic: they are operational state, not
/// config (see the engine), like RouterOS' dynamic entries that a reboot
/// clears.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressListEntry {
    pub id: ItemId,
    pub list: Name,
    pub address: AddrMatch,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// A dynamic address-list entry, as the data plane gets it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DynamicAddress {
    pub list: Name,
    pub address: AddrMatch,
    /// Seconds left; the data plane expires it on its own. 0 = no timeout
    /// (only for `added_by_rule` entries).
    pub timeout_secs: u64,
    /// Put there by an `add-*-to-address-list` rule (kept in the list's
    /// dynamic set, see `corerouter-firewall::nft`), not by a command.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub added_by_rule: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Firewall {
    pub filter: Vec<FirewallRule>,
    pub nat: Vec<FirewallRule>,
    pub mangle: Vec<FirewallRule>,
    pub address_lists: Vec<AddressListEntry>,
    /// Next rule id (shared by the three tables; never reused).
    pub next_rule_id: u32,
    pub next_address_list_id: u32,
    /// The simple mode's zone matrix (G2.1b); its rules are the `zone`
    /// ones of the filter table.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<ZonePolicy>,
}

impl Firewall {
    pub fn rules(&self, table: Table) -> &Vec<FirewallRule> {
        match table {
            Table::Filter => &self.filter,
            Table::Nat => &self.nat,
            Table::Mangle => &self.mangle,
        }
    }

    pub fn rules_mut(&mut self, table: Table) -> &mut Vec<FirewallRule> {
        match table {
            Table::Filter => &mut self.filter,
            Table::Nat => &mut self.nat,
            Table::Mangle => &mut self.mangle,
        }
    }

    pub fn next_rule_id(&mut self) -> ItemId {
        self.next_rule_id = self.next_rule_id.saturating_add(1);
        ItemId(self.next_rule_id)
    }

    pub fn next_address_list_id(&mut self) -> ItemId {
        self.next_address_list_id = self.next_address_list_id.saturating_add(1);
        ItemId(self.next_address_list_id)
    }

    /// Nothing for the data plane to do (no rules, no list entries).
    pub fn is_empty(&self) -> bool {
        self.filter.is_empty()
            && self.nat.is_empty()
            && self.mangle.is_empty()
            && self.address_lists.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip_in_routeros_syntax() {
        for s in [
            "10.0.0.0/8",
            "192.0.2.7",
            "10.0.0.1-10.0.0.9",
            "2001:db8::/32",
            "fe80::1",
        ] {
            assert_eq!(s.parse::<AddrMatch>().unwrap().to_string(), s);
        }
        let n: Neg<AddrMatch> = "!10.0.0.0/8".parse().unwrap();
        assert!(n.not);
        assert_eq!(n.to_string(), "!10.0.0.0/8");
        assert_eq!(
            "22, 80,8000-8080".parse::<PortSet>().unwrap().to_string(),
            "22,80,8000-8080"
        );
        assert_eq!(
            "related,established"
                .parse::<Flags<ConnState>>()
                .unwrap()
                .to_string(),
            "established,related"
        );
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::TCP);
        assert_eq!("99".parse::<Protocol>().unwrap().to_string(), "99");
        assert_eq!("8:0".parse::<IcmpOptions>().unwrap().code, Some(0));
    }

    #[test]
    fn hostile_values_are_refused() {
        assert!("10.0.0.1/8".parse::<AddrMatch>().is_err(), "host bits");
        assert!("10.0.0.9-10.0.0.1".parse::<AddrMatch>().is_err());
        assert!("10.0.0.1-::1".parse::<AddrMatch>().is_err());
        assert!("90-80".parse::<PortRange>().is_err());
        assert!("70000".parse::<PortRange>().is_err());
        assert_eq!("80,80".parse::<PortSet>().unwrap().0.len(), 1);
        let many: Vec<String> = (1..=33).map(|p| p.to_string()).collect();
        assert!(many.join(",").parse::<PortSet>().is_err());
        assert!("bad name".parse::<Name>().is_err());
        assert!("a\"b".parse::<Name>().is_err());
        assert!("x".repeat(64).parse::<Name>().is_err());
        assert!("10.0.0.0/24".parse::<NatTarget>().is_err());
        assert!("bogus".parse::<Flags<ConnState>>().is_err());
    }

    #[test]
    fn rules_serialize_compactly_and_load_back() {
        let rule = FirewallRule {
            id: ItemId(1),
            chain: "input".parse().unwrap(),
            family: Family::Both,
            matchers: Matchers {
                connection_state: Some("established,related".parse().unwrap()),
                ..Matchers::default()
            },
            action: Action::Accept,
            disabled: false,
            comment: String::new(),
            section: false,
            zone: false,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(
            json.contains(r#""connection_state":"established,related""#),
            "{json}"
        );
        assert!(!json.contains("section"), "{json}");
        assert_eq!(serde_json::from_str::<FirewallRule>(&json).unwrap(), rule);

        let mark: Action =
            serde_json::from_str(r#"{"type": "mark-connection", "new_connection_mark": "web"}"#)
                .unwrap();
        assert!(mark.continues(), "passthrough defaults to yes");
    }

    #[test]
    fn limits_timeouts_and_zones_parse() {
        let l: Limit = "5/s".parse().unwrap();
        assert_eq!(l.to_string(), "5/1s,5");
        assert_eq!("10/1m,20".parse::<Limit>().unwrap().burst, 20);
        assert!("0/1s".parse::<Limit>().is_err());
        assert!("5/5s".parse::<Limit>().is_err(), "nftables has no 5s unit");
        assert!("5".parse::<Limit>().is_err());
        let t: Timeout = "1h30m".parse().unwrap();
        assert_eq!(t.secs(), 5400);
        assert_eq!(t.to_string(), "1h30m");
        assert_eq!("90".parse::<Timeout>().unwrap().to_string(), "1m30s");
        assert!("36d".parse::<Timeout>().is_err());
        assert!("0".parse::<Timeout>().is_err());
        assert!("1x".parse::<Timeout>().is_err());
        assert_eq!("router".parse::<Zone>().unwrap(), Zone::Router);
        assert_eq!(
            "LAN".parse::<Zone>().unwrap(),
            Zone::List("LAN".parse().unwrap())
        );
        let add: Action = serde_json::from_str(
            r#"{"type": "add-src-to-address-list", "address_list": "bad", "address_list_timeout": "1d"}"#,
        )
        .unwrap();
        assert!(add.continues());
        assert_eq!(add.fills_list().map(Name::as_str), Some("bad"));
    }

    #[test]
    fn address_matching() {
        let net: AddrMatch = "10.0.0.0/8".parse().unwrap();
        let host: AddrMatch = "10.1.2.3".parse().unwrap();
        let range: AddrMatch = "10.0.0.5-10.0.0.9".parse().unwrap();
        assert!(net.covers(&host) && net.covers(&range));
        assert!(!host.covers(&net));
        assert!(net.contains("10.200.0.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
    }
}

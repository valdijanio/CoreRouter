//! Routes to a subscriber (G4.3cd): a business customer's routed block
//! (`203.0.113.8/29`, `2001:db8:100::/48`) behind its PPPoE or IPoE
//! session.
//!
//! Three sources say the same thing in the same text:
//! - RADIUS `Framed-Route` (RFC 2865 §5.22): "a destination prefix in dotted
//!   quad form optionally followed by a slash and a decimal length
//!   specifier", then a space, a gateway and one or more metrics
//!   (`192.168.1.0/24 192.168.1.1 1 2 -1 3 400`). The gateway MAY be
//!   `0.0.0.0`: the user's own address;
//! - RADIUS `Framed-IPv6-Route` (RFC 3162 §2.5), the same with an IPv6
//!   prefix; the gateway MAY be `::`;
//! - `routes` of `/ppp secret` (RouterOS: `dst-address gateway metric`,
//!   several separated by commas).
//!
//! The routes of every session and secret must not overlap: two
//! subscribers cannot both own a block. [`RouteSet`] keeps them disjoint,
//! which also makes its lookup the longest-prefix match.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer};


/// Routes per secret or per session (a /29 and a /48 are the usual; a
/// customer with more blocks should have them aggregated).
pub const MAX_ROUTES: usize = 16;
/// The text of one route: a RADIUS attribute's value is at most 253 bytes.
pub const MAX_TEXT: usize = 253;
/// The metric when none is given (RouterOS `distance` of a static route).
pub const DEFAULT_METRIC: u32 = 1;

/// Why a route's text was refused (the input, cut short, and the cause).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteError(pub String);

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RouteError {}

/// One route to a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FramedRoute {
    /// The block, without host bits.
    pub dst: IpNet,
    /// `None`: the subscriber (`0.0.0.0`, `::` or no gateway).
    pub gateway: Option<IpAddr>,
    pub metric: u32,
}

impl FramedRoute {
    pub fn new(dst: IpNet) -> Self {
        Self {
            dst,
            gateway: None,
            metric: DEFAULT_METRIC,
        }
    }

    pub fn is_v6(&self) -> bool {
        matches!(self.dst, IpNet::V6(_))
    }

    /// Why this block cannot be routed to a subscriber, if it cannot.
    pub fn martian(&self) -> Option<&'static str> {
        martian(&self.dst)
    }

    /// Several routes as RouterOS writes them: comma separated. `""` is
    /// none. Each one is parsed with [`FromStr`]; duplicates and overlaps
    /// inside the list are refused.
    pub fn parse_list(text: &str) -> Result<Vec<FramedRoute>, RouteError> {
        let mut out: Vec<FramedRoute> = Vec::new();
        for item in text.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let r: FramedRoute = item.parse()?;
            if let Some(o) = out.iter().find(|o| overlaps(&o.dst, &r.dst)) {
                return Err(bad(item, &format!("overlaps {} of the same list", o.dst)));
            }
            out.push(r);
            if out.len() > MAX_ROUTES {
                return Err(RouteError(format!("at most {MAX_ROUTES} routes")));
            }
        }
        Ok(out)
    }

    /// The list back in RouterOS form (`a, b`).
    pub fn list_text(routes: &[FramedRoute]) -> String {
        routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn bad(s: &str, why: &str) -> RouteError {
    let shown: String = s.chars().take(64).collect();
    RouteError(format!("route '{shown}': {why}"))
}

impl FromStr for FramedRoute {
    type Err = RouteError;

    /// `dst[/len] [gateway] [metric [more metrics]]`. Without a length the
    /// prefix is one host (/32, /128): RFC 2865 makes the length optional
    /// and a classful guess would route more than was written. A prefix
    /// with host bits set is refused (`10.0.0.1/24` is a typo for either
    /// the host or the block, and the wrong guess blackholes a customer).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_TEXT {
            return Err(bad(s, "longer than 253 bytes"));
        }
        let mut words = s.split_whitespace();
        let Some(first) = words.next() else {
            return Err(bad(s, "empty: expected 203.0.113.8/29 [gateway] [metric]"));
        };
        let dst: IpNet = if first.contains('/') {
            first
                .parse()
                .map_err(|_| bad(s, "not a prefix (203.0.113.8/29 or 2001:db8::/48)"))?
        } else {
            first
                .parse::<IpAddr>()
                .map(IpNet::from)
                .map_err(|_| bad(s, "not an address or prefix (203.0.113.8/29)"))?
        };
        if dst.trunc() != dst {
            let why = format!("host bits set: the block is {}", dst.trunc());
            return Err(bad(s, &why));
        }
        let mut gateway = None;
        let mut metric = None;
        for w in words {
            if metric.is_none()
                && gateway.is_none()
                && let Ok(ip) = w.parse::<IpAddr>()
            {
                if ip.is_ipv4() != dst.addr().is_ipv4() {
                    return Err(bad(s, "the gateway is not of the prefix's family"));
                }
                // RFC 2865 §5.22 / RFC 3162 §2.5: 0.0.0.0 / :: = the user.
                gateway = Some((!ip.is_unspecified()).then_some(ip));
                continue;
            }
            // RFC 2865's example ends in "1 2 -1 3 400": the first metric
            // is the route's; the rest (other routing protocols) is read
            // and ignored.
            let n: i64 = w
                .parse()
                .map_err(|_| bad(s, "expected prefix [gateway] [metric]"))?;
            if metric.is_none() {
                metric = Some(u32::try_from(n).map_err(|_| bad(s, "metric out of range"))?);
            }
        }
        Ok(Self {
            dst,
            gateway: gateway.flatten(),
            metric: metric.unwrap_or(DEFAULT_METRIC),
        })
    }
}

impl fmt::Display for FramedRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.dst)?;
        match (self.gateway, self.metric) {
            (Some(g), m) => write!(f, " {g} {m}"),
            (None, DEFAULT_METRIC) => Ok(()),
            (None, m) => {
                let unspec = if self.is_v6() {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                };
                write!(f, " {unspec} {m}")
            }
        }
    }
}

impl Serialize for FramedRoute {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FramedRoute {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let t = String::deserialize(d)?;
        t.parse().map_err(serde::de::Error::custom)
    }
}

/// Where a session's route came from (the origin chip of the PPP window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteOrigin {
    /// `routes` of the `/ppp secret`.
    #[default]
    Secret,
    /// RADIUS `Framed-Route` (RFC 2865 §5.22).
    FramedRoute,
    /// RADIUS `Framed-IPv6-Route` (RFC 3162 §2.5).
    FramedIpv6Route,
    /// A second (or later) RADIUS `Framed-IPv6-Prefix` (RFC 3162 §2.3: it
    /// MAY repeat): the first is the link's /64, the others are routed to
    /// the session.
    FramedIpv6Prefix,
}

impl RouteOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::FramedRoute => "framed-route",
            Self::FramedIpv6Route => "framed-ipv6-route",
            Self::FramedIpv6Prefix => "framed-ipv6-prefix",
        }
    }

    /// The RADIUS attribute (or the menu) as the operator knows it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::FramedRoute => "Framed-Route",
            Self::FramedIpv6Route => "Framed-IPv6-Route",
            Self::FramedIpv6Prefix => "Framed-IPv6-Prefix",
        }
    }
}

/// A route of an active session, as `ppp.active.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionRoute {
    /// RouterOS text (`203.0.113.8/29 0.0.0.0 1`).
    pub route: String,
    pub origin: RouteOrigin,
}

/// Why `dst` cannot be routed to a subscriber: special-purpose space
/// (RFC 6890, RFC 5735/5156) or wider than any customer block.
pub fn martian(dst: &IpNet) -> Option<&'static str> {
    match dst {
        IpNet::V4(n) => martian4(n),
        IpNet::V6(n) => martian6(n),
    }
}

fn v4(a: [u8; 4], len: u8) -> Ipv4Net {
    Ipv4Net::new(Ipv4Addr::from(a), len).unwrap_or_default()
}

fn martian4(n: &Ipv4Net) -> Option<&'static str> {
    if n.prefix_len() < 8 {
        return Some("wider than a /8: the default route or a typo");
    }
    let special: [(Ipv4Net, &'static str); 5] = [
        (v4([0, 0, 0, 0], 8), "0.0.0.0/8 is \"this network\" (RFC 6890)"),
        (v4([127, 0, 0, 0], 8), "loopback (127.0.0.0/8)"),
        (v4([169, 254, 0, 0], 16), "link-local (169.254.0.0/16)"),
        (v4([224, 0, 0, 0], 4), "multicast (224.0.0.0/4)"),
        (v4([240, 0, 0, 0], 4), "reserved (240.0.0.0/4) or broadcast"),
    ];
    special
        .iter()
        .find(|(s, _)| s.contains(n) || n.contains(s))
        .map(|(_, why)| *why)
}

fn v6(a: [u16; 8], len: u8) -> Ipv6Net {
    let [a0, a1, a2, a3, a4, a5, a6, a7] = a;
    Ipv6Net::new(Ipv6Addr::new(a0, a1, a2, a3, a4, a5, a6, a7), len).unwrap_or_default()
}

fn martian6(n: &Ipv6Net) -> Option<&'static str> {
    if n.prefix_len() < 16 {
        return Some("wider than a /16: the default route or a typo");
    }
    let special: [(Ipv6Net, &'static str); 5] = [
        (v6([0; 8], 128), "the unspecified address (::)"),
        (v6([0, 0, 0, 0, 0, 0, 0, 1], 128), "loopback (::1)"),
        (v6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96), "IPv4-mapped (::ffff:0:0/96)"),
        (v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), "link-local (fe80::/10)"),
        (v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8), "multicast (ff00::/8)"),
    ];
    special
        .iter()
        .find(|(s, _)| s.contains(n) || n.contains(s))
        .map(|(_, why)| *why)
}

/// Whether two blocks share an address (one holds the other).
pub fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(b) || b.contains(a)
}

/// The first and last address of a block, on one axis per family.
fn span(n: &IpNet) -> (u8, u128, u128) {
    match n {
        IpNet::V4(n) => (
            4,
            u128::from(u32::from(n.network())),
            u128::from(u32::from(n.broadcast())),
        ),
        IpNet::V6(n) => (6, u128::from(n.network()), u128::from(n.broadcast())),
    }
}

fn point(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(a) => (4, u128::from(u32::from(a))),
        IpAddr::V6(a) => (6, u128::from(a)),
    }
}

/// Disjoint blocks, each with a value (who owns it). Insert refuses an
/// overlap, so at most one block holds an address and [`RouteSet::lookup`]
/// is the longest-prefix match. O(log n) for every operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSet<V> {
    /// (family, first address) → (last address, block, value).
    map: BTreeMap<(u8, u128), (u128, IpNet, V)>,
}

impl<V> Default for RouteSet<V> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<V> RouteSet<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Every block that shares an address with `dst`, with its value.
    pub fn overlapping(&self, dst: &IpNet) -> impl Iterator<Item = (&IpNet, &V)> {
        let (fam, start, end) = span(dst);
        self.overlapping_span(fam, start, end)
    }

    /// Every block that shares an address with the range `first..=last`
    /// (an `/ip pool` range); none when the two are of different families.
    pub fn overlapping_range(&self, first: IpAddr, last: IpAddr) -> impl Iterator<Item = (&IpNet, &V)> {
        let ((fam, start), (fam2, end)) = (point(first), point(last));
        let (start, end) = if fam == fam2 { (start, end) } else { (1, 0) };
        self.overlapping_span(fam, start, end)
    }

    fn overlapping_span(&self, fam: u8, start: u128, end: u128) -> impl Iterator<Item = (&IpNet, &V)> {
        // A reversed range (families differ) matches nothing.
        let (fam, start, end) = if start > end { (0, 0, 0) } else { (fam, start, end) };
        // The blocks that start inside `dst`, and the one before it if it
        // reaches into `dst` (disjoint: no other can).
        let inside = self
            .map
            .range((fam, start)..=(fam, end))
            .map(|(_, (_, n, v))| (n, v));
        let before = self
            .map
            .range(..(fam, start))
            .next_back()
            .filter(|((f, _), (last, _, _))| *f == fam && *last >= start)
            .map(|(_, (_, n, v))| (n, v));
        before.into_iter().chain(inside)
    }

    /// Add `dst`; refused (with the first block in the way) when it
    /// overlaps one already there.
    pub fn insert(&mut self, dst: IpNet, v: V) -> Result<(), IpNet> {
        if let Some((n, _)) = self.overlapping(&dst).next() {
            return Err(*n);
        }
        let (fam, start, end) = span(&dst);
        self.map.insert((fam, start), (end, dst, v));
        Ok(())
    }

    /// Remove exactly `dst`, if it is there.
    pub fn remove(&mut self, dst: &IpNet) -> Option<V> {
        let (fam, start, _) = span(dst);
        match self.map.get(&(fam, start)) {
            Some((_, n, _)) if n == dst => self.map.remove(&(fam, start)).map(|(_, _, v)| v),
            _ => None,
        }
    }

    /// The block holding `ip` (the longest match: blocks are disjoint).
    pub fn lookup(&self, ip: IpAddr) -> Option<(&IpNet, &V)> {
        let (fam, at) = point(ip);
        self.map
            .range(..=(fam, at))
            .next_back()
            .filter(|((f, _), (last, _, _))| *f == fam && *last >= at)
            .map(|(_, (_, n, v))| (n, v))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IpNet, &V)> {
        self.map.values().map(|(_, n, v)| (n, v))
    }

    /// Keep only the entries `f` says yes to.
    pub fn retain(&mut self, mut f: impl FnMut(&IpNet, &mut V) -> bool) {
        self.map.retain(|_, (_, n, v)| f(n, v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn r(t: &str) -> FramedRoute {
        t.parse().unwrap()
    }

    fn net(t: &str) -> IpNet {
        t.parse().unwrap()
    }

    #[test]
    fn rfc_texts_parse() {
        // RFC 2865 §5.22's example: the first metric counts.
        let x = r("192.168.1.0/24 192.168.1.1 1 2 -1 3 400");
        assert_eq!(x.dst, net("192.168.1.0/24"));
        assert_eq!(x.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(x.metric, 1);
        // RFC 2865: 0.0.0.0 = the user's address.
        let x = r("203.0.113.8/29 0.0.0.0 5");
        assert_eq!((x.gateway, x.metric), (None, 5));
        // RFC 3162 §2.5's example and `::`.
        let x = r("2000:0:0:106::/64 2000::106:a00:20ff:fe99:a998 1");
        assert!(x.is_v6() && x.gateway.is_some());
        assert_eq!(r("2001:db8:100::/48 ::").gateway, None);
        // MikroTik `routes` and short forms.
        assert_eq!(r("10.1.0.0/24 10.0.0.1 1").metric, 1);
        assert_eq!(r("203.0.113.8/29").to_string(), "203.0.113.8/29");
        assert_eq!(r("203.0.113.8/29 7").metric, 7);
        assert_eq!(r("203.0.113.8").dst, net("203.0.113.8/32"));
        assert_eq!(r("2001:db8::1").dst, net("2001:db8::1/128"));
        assert_eq!(r("203.0.113.8/29 0.0.0.0 7").to_string(), "203.0.113.8/29 0.0.0.0 7");
        assert_eq!(r("2001:db8::/48 :: 9").to_string(), "2001:db8::/48 :: 9");
    }

    #[test]
    fn bad_texts_are_refused() {
        for t in [
            "",
            "10.0.0.1/24",
            "10.0.0.0/33",
            "x",
            "10.0.0.0/24 2001:db8::1",
            "10.0.0.0/24 10.0.0.1 x",
            "10.0.0.0/24 10.0.0.1 -1",
            "2001:db8::1/48",
        ] {
            assert!(t.parse::<FramedRoute>().is_err(), "{t}");
        }
        assert!("1".repeat(300).parse::<FramedRoute>().is_err());
    }

    #[test]
    fn martians() {
        for t in [
            "0.0.0.0/0", "10.0.0.0/7", "127.0.0.0/8", "127.1.0.0/16", "169.254.1.0/24",
            "224.0.0.0/24", "255.255.255.255/32", "0.1.0.0/16", "::/0", "::1/128",
            "fe80::/64", "ff02::/16", "::ffff:10.0.0.0/120", "2000::/8",
        ] {
            assert!(r(t).martian().is_some(), "{t}");
        }
        for t in ["203.0.113.8/29", "100.64.0.0/24", "10.0.0.0/8", "2001:db8:100::/48"] {
            assert!(r(t).martian().is_none(), "{t}");
        }
    }

    #[test]
    fn lists_like_routeros() {
        let l = FramedRoute::parse_list(" 203.0.113.8/29 0.0.0.0 1 , 2001:db8:100::/48,").unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(FramedRoute::list_text(&l), "203.0.113.8/29,2001:db8:100::/48");
        assert!(FramedRoute::parse_list("").unwrap().is_empty());
        assert!(FramedRoute::parse_list("203.0.113.8/29,203.0.113.12/30").is_err());
        let many: Vec<String> = (0..17).map(|i| format!("10.0.{i}.0/24")).collect();
        assert!(FramedRoute::parse_list(&many.join(",")).is_err());
    }

    #[test]
    fn serialized_as_text() {
        let x = r("203.0.113.8/29 0.0.0.0 3");
        let j = serde_json::to_value(x).unwrap();
        assert_eq!(j, "203.0.113.8/29 0.0.0.0 3");
        assert_eq!(serde_json::from_value::<FramedRoute>(j).unwrap(), x);
        assert!(serde_json::from_value::<FramedRoute>("10.0.0.1/8".into()).is_err());
    }

    #[test]
    fn set_refuses_overlaps_and_finds_the_holder() {
        let mut s = RouteSet::new();
        s.insert(net("203.0.113.8/29"), "a").unwrap();
        s.insert(net("203.0.113.16/28"), "b").unwrap();
        s.insert(net("2001:db8:100::/48"), "c").unwrap();
        assert_eq!(s.insert(net("203.0.113.0/24"), "x"), Err(net("203.0.113.8/29")));
        assert_eq!(s.insert(net("203.0.113.12/30"), "x"), Err(net("203.0.113.8/29")));
        assert!(s.insert(net("203.0.113.0/29"), "d").is_ok());
        let all: Vec<_> = s.overlapping(&net("203.0.113.0/24")).map(|(_, v)| *v).collect();
        assert_eq!(all, ["d", "a", "b"]);
        assert_eq!(s.lookup("203.0.113.13".parse().unwrap()).map(|x| *x.1), Some("a"));
        assert_eq!(s.lookup("203.0.113.32".parse().unwrap()), None);
        assert_eq!(s.lookup("2001:db8:100:5::1".parse().unwrap()).map(|x| *x.1), Some("c"));
        // An IPv4 block never matches an IPv6 address on the same axis.
        assert_eq!(s.lookup("::cb00:710d".parse().unwrap()), None);
        assert_eq!(s.remove(&net("203.0.113.8/30")), None);
        assert_eq!(s.remove(&net("203.0.113.8/29")), Some("a"));
        assert_eq!(s.lookup("203.0.113.13".parse().unwrap()), None);
        assert_eq!(s.len(), 3);
    }

    fn any_net() -> impl Strategy<Value = IpNet> {
        prop_oneof![
            (any::<u32>(), 8u8..=32).prop_map(|(a, l)| IpNet::V4(
                Ipv4Net::new(Ipv4Addr::from(a), l).unwrap().trunc()
            )),
            (any::<u128>(), 16u8..=128).prop_map(|(a, l)| IpNet::V6(
                Ipv6Net::new(Ipv6Addr::from(a), l).unwrap().trunc()
            )),
        ]
    }

    proptest! {
        #[test]
        fn text_never_panics_and_round_trips(t in "\\PC{0,80}") {
            if let Ok(x) = t.parse::<FramedRoute>() {
                prop_assert_eq!(x.to_string().parse::<FramedRoute>().unwrap(), x);
            }
            let _ = FramedRoute::parse_list(&t);
        }

        #[test]
        fn display_round_trips(n in any_net(), m in 0u32..1000, gw in any::<bool>()) {
            let gateway = gw.then(|| n.addr());
            let x = FramedRoute { dst: n, gateway: gateway.filter(|g| !g.is_unspecified()), metric: m };
            prop_assert_eq!(x.to_string().parse::<FramedRoute>().unwrap(), x);
        }

        /// The set agrees with a walk of every block: same overlaps, same
        /// lookups.
        #[test]
        fn set_matches_a_linear_walk(nets in proptest::collection::vec(any_net(), 0..40),
                                     probes in proptest::collection::vec(any_net(), 0..40)) {
            let mut s = RouteSet::new();
            let mut kept: Vec<IpNet> = Vec::new();
            for (i, n) in nets.iter().enumerate() {
                let walk = kept.iter().any(|k| overlaps(k, n));
                prop_assert_eq!(s.insert(*n, i).is_err(), walk);
                if !walk { kept.push(*n); }
            }
            for p in &probes {
                let mut got: Vec<IpNet> = s.overlapping(p).map(|(n, _)| *n).collect();
                let mut want: Vec<IpNet> = kept.iter().copied().filter(|k| overlaps(k, p)).collect();
                got.sort();
                want.sort();
                prop_assert_eq!(got, want);
                let hit = s.lookup(p.addr()).map(|(n, _)| *n);
                let want = kept.iter().copied().find(|k| k.contains(&p.addr()));
                prop_assert_eq!(hit, want);
            }
        }
    }
}

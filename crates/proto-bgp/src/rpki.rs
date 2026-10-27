//! RPKI origin validation (G3.2c): the VRP table, RFC 6811 validation
//! (updated by RFC 8481 and RFC 8893), the checks of `routing.rpki` and
//! its render for FRR's `bgpd_rpki`.
//!
//! FRR validates and drops on its own (`rpki` node and `match rpki
//! invalid` in the neighbor's inbound route-map). The table here gives
//! the same answer on CoreRouter's side, from the VRPs the daemon's own
//! RTR client holds (`crate::rtr`), for the badges of the route lists, the
//! share of each state per session and `routing.rpki.check`, with no
//! query to FRR per route.
//!
//! The table is a path-compressed binary trie per family (one node per
//! distinct VRP prefix and per branch point): a lookup walks only the
//! prefixes that cover the route and the branch points above them. 551 k
//! VRPs build in 54 ms and 1 M routes validate in 81 ms in prefix order
//! (746 ms in random order: the walk then leaves the cache), **medido** in
//! `benches/rpki.rs`.

use std::fmt;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::bgp::BgpParams;
use corerouter_model::rpki::{
    EXPIRE_RANGE, MAX_CACHES, REFRESH_RANGE, RETRY_RANGE, RpkiCache, RpkiInvalid, RpkiState,
};
use corerouter_model::{Issue, Routing};

/// A Validated ROA Payload (RFC 6811 §2): `prefix/len-max_len` may be
/// originated by `asn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Vrp {
    /// Left-aligned address bits (IPv4 in the top 32), masked to `len`.
    key: u128,
    v6: bool,
    len: u8,
    pub max_len: u8,
    pub asn: u32,
}

fn mask(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len.min(128)))
    }
}

/// Bit `at` of a left-aligned key (`true`: the right child).
fn bit(key: u128, at: u8) -> bool {
    (key >> (127 - u32::from(at.min(127)))) & 1 == 1
}

/// Left-aligned bits of an address, and its family's width.
pub fn key_of(addr: IpAddr) -> (u128, bool) {
    match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)) << 96, false),
        IpAddr::V6(a) => (u128::from(a), true),
    }
}

impl Vrp {
    /// `None` unless `len <= max_len <= the family's bits` (RFC 8210 §5.6).
    pub fn new(addr: IpAddr, len: u8, max_len: u8, asn: u32) -> Option<Vrp> {
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        if len > max_len || max_len > bits {
            return None;
        }
        let (key, v6) = key_of(addr);
        Some(Vrp {
            key: key & mask(len),
            v6,
            len,
            max_len,
            asn,
        })
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn addr(&self) -> IpAddr {
        if self.v6 {
            IpAddr::V6(Ipv6Addr::from(self.key))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::try_from(self.key >> 96).unwrap_or(0)))
        }
    }
}

impl fmt::Display for Vrp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}-{} AS{}",
            self.addr(),
            self.len,
            self.max_len,
            self.asn
        )
    }
}

const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct Node {
    key: u128,
    len: u8,
    left: u32,
    right: u32,
    /// The VRPs of this exact prefix: `entries[first..first + count]`.
    first: u32,
    count: u32,
}

impl Node {
    fn child(&self, right: bool) -> u32 {
        if right { self.right } else { self.left }
    }

    fn set_child(&mut self, right: bool, to: u32) {
        if right {
            self.right = to;
        } else {
            self.left = to;
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Trie {
    nodes: Vec<Node>,
    root: Option<u32>,
    /// (max_len, asn) of every VRP, grouped by node.
    entries: Vec<(u8, u32)>,
}

impl Trie {
    fn node(&mut self, key: u128, len: u8) -> u32 {
        let idx = u32::try_from(self.nodes.len()).unwrap_or(NONE);
        self.nodes.push(Node {
            key,
            len,
            left: NONE,
            right: NONE,
            first: 0,
            count: 0,
        });
        idx
    }

    fn get(&self, i: u32) -> Option<&Node> {
        usize::try_from(i).ok().and_then(|i| self.nodes.get(i))
    }

    fn get_mut(&mut self, i: u32) -> Option<&mut Node> {
        usize::try_from(i).ok().and_then(|i| self.nodes.get_mut(i))
    }

    /// Point whoever pointed at `old` (the root or a parent's child) at `new`.
    fn relink(&mut self, parent: Option<(u32, bool)>, new: u32) {
        match parent {
            None => self.root = Some(new),
            Some((p, side)) => {
                if let Some(n) = self.get_mut(p) {
                    n.set_child(side, new);
                }
            }
        }
    }

    /// The node of exactly `key/len`, made if missing.
    fn insert(&mut self, key: u128, len: u8) -> u32 {
        let Some(mut idx) = self.root else {
            let n = self.node(key, len);
            self.root = Some(n);
            return n;
        };
        let mut parent: Option<(u32, bool)> = None;
        loop {
            let Some(&n) = self.get(idx) else { return NONE };
            let diff = (key ^ n.key).leading_zeros();
            let common = u8::try_from(diff.min(u32::from(len.min(n.len)))).unwrap_or(0);
            if common < n.len {
                if common == len {
                    // The new prefix sits above `n`.
                    let new = self.node(key, len);
                    if let Some(m) = self.get_mut(new) {
                        m.set_child(bit(n.key, len), idx);
                    }
                    self.relink(parent, new);
                    return new;
                }
                // Branch where they part.
                let branch = self.node(key & mask(common), common);
                let leaf = self.node(key, len);
                if let Some(b) = self.get_mut(branch) {
                    b.set_child(bit(key, common), leaf);
                    b.set_child(bit(n.key, common), idx);
                }
                self.relink(parent, branch);
                return leaf;
            }
            if n.len == len {
                return idx;
            }
            let side = bit(key, n.len);
            let next = n.child(side);
            if next == NONE {
                let leaf = self.node(key, len);
                if let Some(m) = self.get_mut(idx) {
                    m.set_child(side, leaf);
                }
                return leaf;
            }
            parent = Some((idx, side));
            idx = next;
        }
    }

    fn validate(&self, key: u128, len: u8, origin: Option<u32>) -> RpkiState {
        let mut covered = false;
        let mut idx = self.root.unwrap_or(NONE);
        while let Some(n) = self.get(idx) {
            if n.len > len || key & mask(n.len) != n.key {
                break;
            }
            if n.count > 0 {
                covered = true;
                let from = usize::try_from(n.first).unwrap_or(usize::MAX);
                let to = from.saturating_add(usize::try_from(n.count).unwrap_or(0));
                // RFC 6811 §2: matched when the route is no longer than the
                // max length and the origin is the VRP's AS. An AS 0 VRP
                // matches nothing (RFC 6483 §4, RFC 7607), and a route with
                // no origin (AS_SET last, RFC 6811 §2) matches nothing.
                if let Some(o) = origin
                    && self.entries.get(from..to).is_some_and(|es| {
                        es.iter()
                            .any(|&(max, asn)| len <= max && asn == o && asn != 0)
                    })
                {
                    return RpkiState::Valid;
                }
            }
            if n.len >= 128 {
                break;
            }
            idx = n.child(bit(key, n.len));
        }
        if covered {
            RpkiState::Invalid
        } else {
            RpkiState::Unknown
        }
    }

    fn covering(&self, key: u128, len: u8, out: &mut Vec<(u128, u8, u8, u32)>) {
        let mut idx = self.root.unwrap_or(NONE);
        while let Some(n) = self.get(idx) {
            if n.len > len || key & mask(n.len) != n.key {
                break;
            }
            let from = usize::try_from(n.first).unwrap_or(usize::MAX);
            let to = from.saturating_add(usize::try_from(n.count).unwrap_or(0));
            for &(max, asn) in self.entries.get(from..to).unwrap_or_default() {
                out.push((n.key, n.len, max, asn));
            }
            if n.len >= 128 {
                break;
            }
            idx = n.child(bit(key, n.len));
        }
    }
}

/// The VRPs of a group, ready for RFC 6811 lookups. Immutable once built:
/// the daemon builds a new one on each End of Data and swaps an `Arc`.
#[derive(Debug, Clone, Default)]
pub struct VrpTable {
    v4: Trie,
    v6: Trie,
    count_v4: usize,
    count_v6: usize,
}

impl VrpTable {
    pub fn build<'a>(vrps: impl IntoIterator<Item = &'a Vrp>) -> VrpTable {
        let mut all: Vec<Vrp> = vrps.into_iter().copied().collect();
        all.sort_unstable();
        all.dedup();
        let mut t = VrpTable::default();
        for fam in [false, true] {
            let trie = if fam { &mut t.v6 } else { &mut t.v4 };
            let mut owners: Vec<(u32, u8, u32)> = Vec::new();
            for v in all.iter().filter(|v| v.v6 == fam) {
                let node = trie.insert(v.key, v.len);
                owners.push((node, v.max_len, v.asn));
            }
            owners.sort_unstable();
            trie.entries.reserve(owners.len());
            let mut i = 0;
            while let Some(&(node, _, _)) = owners.get(i) {
                let first = u32::try_from(trie.entries.len()).unwrap_or(NONE);
                let mut count = 0u32;
                while let Some(&(n, max, asn)) = owners.get(i)
                    && n == node
                {
                    trie.entries.push((max, asn));
                    count += 1;
                    i += 1;
                }
                if let Some(m) = trie.get_mut(node) {
                    m.first = first;
                    m.count = count;
                }
            }
            if fam {
                t.count_v6 = owners.len();
            } else {
                t.count_v4 = owners.len();
            }
        }
        t
    }

    pub fn len_v4(&self) -> usize {
        self.count_v4
    }

    pub fn len_v6(&self) -> usize {
        self.count_v6
    }

    pub fn is_empty(&self) -> bool {
        self.count_v4 + self.count_v6 == 0
    }

    /// RFC 6811 §2 for `addr/len` originated by `origin` (`None`: the
    /// route has no origin AS, e.g. an AS_SET last).
    pub fn validate(&self, addr: IpAddr, len: u8, origin: Option<u32>) -> RpkiState {
        let (key, v6) = key_of(addr);
        let trie = if v6 { &self.v6 } else { &self.v4 };
        trie.validate(key & mask(len), len, origin)
    }

    /// The VRPs that cover `addr/len` (the "why" of a state).
    pub fn covering(&self, addr: IpAddr, len: u8) -> Vec<Vrp> {
        let (key, v6) = key_of(addr);
        let trie = if v6 { &self.v6 } else { &self.v4 };
        let mut raw = Vec::new();
        trie.covering(key & mask(len), len, &mut raw);
        raw.into_iter()
            .map(|(key, len, max_len, asn)| Vrp {
                key,
                v6,
                len,
                max_len,
                asn,
            })
            .collect()
    }
}

/// The origin AS of a path as FRR prints it (`64500 64501`, `{64510,64511}`
/// for an AS_SET, `(65001 65002)` for confederation segments), per RFC 6811
/// §2 and RFC 8481 §4:
/// - the last AS of a final AS_SEQUENCE;
/// - `None` (no origin, never Valid) when the path ends in an AS_SET;
/// - `local_as` when the path is empty or holds only confederation
///   segments (the route started in our AS or confederation).
pub fn origin_as(path: &str, local_as: Option<u32>) -> Option<u32> {
    let path = path.trim();
    if path.is_empty() || path.eq_ignore_ascii_case("local") {
        return local_as;
    }
    if path.ends_with('}') {
        return None;
    }
    if path.ends_with(')') {
        return local_as;
    }
    let last = path.rsplit([' ', ')']).next()?;
    // `asdot` (1.10) is 1 × 65536 + 10 (RFC 5396).
    match last.split_once('.') {
        Some((hi, lo)) => Some(
            hi.parse::<u32>()
                .ok()?
                .checked_mul(65_536)?
                .checked_add(lo.parse::<u32>().ok()?)?,
        ),
        None => last.parse().ok(),
    }
}

/// The route-map CoreRouter types for RPKI: `deny` invalid routes,
/// `permit` the rest. Sequences 1..=9 are RPKI's (the contract with the
/// G3.2b policies, which go after).
pub const ROUTE_MAP_IN: &str = "CR-RPKI-IN";

/// The enabled validators, most preferred first (higher preference; then
/// the lower address, as RouterOS without a preference).
pub fn enabled(routing: &Routing) -> Vec<&RpkiCache> {
    let mut v: Vec<&RpkiCache> = routing.rpki.values().filter(|c| !c.disabled).collect();
    v.sort_by(|a, b| {
        b.preference
            .unwrap_or(0)
            .cmp(&a.preference.unwrap_or(0))
            .then(a.address.cmp(&b.address))
            .then(a.port.cmp(&b.port))
    });
    v
}

/// Whether a neighbor drops invalid routes: a validator is enabled, the
/// connection did not say `accept`, and the drop cannot open an eBGP
/// session that RFC 8212 keeps closed. Any route-map satisfies FRR's
/// `ebgp-requires-policy`, so an eBGP neighbor gets the RPKI entries only
/// inside the policy the G3.2b render gives it; until then eBGP accepts
/// nothing at all, invalid included.
pub fn drops_invalid(routing: &Routing, ibgp: bool, eff: &BgpParams) -> bool {
    !enabled(routing).is_empty() && drops_invalid_ibgp(ibgp, eff)
}

/// [`drops_invalid`] once a validator is known to be enabled.
pub fn drops_invalid_ibgp(ibgp: bool, eff: &BgpParams) -> bool {
    ibgp && eff.rpki_invalid.unwrap_or_default() == RpkiInvalid::Reject
}

/// The route-map entries that go first in the inbound map of a neighbor
/// that drops invalid routes (FRR route-map syntax, sequences 1..=9).
pub fn route_map_prelude(name: &str) -> String {
    format!("route-map {name} deny 1\n match rpki invalid\nexit\n")
}

/// FRR's `rpki` node and CoreRouter's RPKI route-map, in FRR's canonical
/// form; empty without an enabled validator (FRR without the module would
/// refuse `rpki` and `match rpki`).
pub fn render_frr(routing: &Routing) -> String {
    let caches = enabled(routing);
    if caches.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    let _ = writeln!(s, "rpki");
    // FRR's timers are global; the most preferred validator's own win.
    // FRR polls at most every hour (`polling_period (1-3600)`).
    if let Some(r) = caches.iter().find_map(|c| c.refresh_interval) {
        let _ = writeln!(s, " rpki polling_period {}", r.min(3_600));
    }
    if let Some(r) = caches.iter().find_map(|c| c.expire_interval) {
        let _ = writeln!(s, " rpki expire_interval {r}");
    }
    if let Some(r) = caches.iter().find_map(|c| c.retry_interval) {
        let _ = writeln!(s, " rpki retry_interval {r}");
    }
    for c in &caches {
        // rtrlib prefers the lower preference; RouterOS the higher.
        let pref = 255 - u16::from(c.preference.unwrap_or(0).min(254));
        let _ = writeln!(
            s,
            " rpki cache tcp {} {} preference {pref}",
            c.address, c.port
        );
    }
    let _ = writeln!(s, "exit");
    s.push_str(&route_map_prelude(ROUTE_MAP_IN));
    let _ = writeln!(s, "route-map {ROUTE_MAP_IN} permit 65535");
    let _ = writeln!(s, "exit");
    s
}

/// The checks of `routing.rpki`.
pub fn validate(routing: &Routing) -> Vec<Issue> {
    let mut out = Vec::new();
    if routing.rpki.len() > MAX_CACHES {
        out.push(Issue::new(
            "routing.rpki",
            format!("at most {MAX_CACHES} RPKI validators"),
        ));
    }
    let mut seen: Vec<(IpAddr, u16, &str)> = Vec::new();
    for (key, c) in &routing.rpki {
        let path = format!("routing.rpki.{key}");
        if c.name != *key {
            out.push(Issue::new(&path, "validator name does not match its key"));
        }
        if c.group.is_empty() || c.group.len() > 63 {
            out.push(Issue::new(
                format!("{path}.group"),
                "group must be 1..63 characters",
            ));
        }
        if c.address.is_unspecified() || c.address.is_multicast() {
            out.push(Issue::new(
                format!("{path}.address"),
                format!("{} cannot be an RTR validator", c.address),
            ));
        }
        if c.port == 0 {
            out.push(Issue::new(format!("{path}.port"), "port must be 1..65535"));
        }
        if let Some((_, _, other)) = seen
            .iter()
            .find(|(a, p, _)| *a == c.address && *p == c.port)
        {
            out.push(Issue::new(
                format!("{path}.address"),
                format!("{}:{} is already validator {other:?}", c.address, c.port),
            ));
        }
        seen.push((c.address, c.port, &c.name));
        // RFC 8210 §6 ranges.
        for (field, v, (lo, hi)) in [
            ("refresh_interval", c.refresh_interval, REFRESH_RANGE),
            ("retry_interval", c.retry_interval, RETRY_RANGE),
            ("expire_interval", c.expire_interval, EXPIRE_RANGE),
        ] {
            if let Some(v) = v
                && !(lo..=hi).contains(&v)
            {
                out.push(Issue::new(
                    format!("{path}.{field}"),
                    format!("{v} s is outside {lo}..={hi} s (RFC 8210 §6)"),
                ));
            }
        }
        // §6: the expire interval must exceed the other two.
        let refresh = c.refresh_interval.unwrap_or(0);
        let retry = c.retry_interval.unwrap_or(0);
        if let Some(e) = c.expire_interval
            && (e <= refresh || e <= retry)
        {
            out.push(Issue::new(
                format!("{path}.expire_interval"),
                format!("{e} s must be longer than the refresh and retry intervals (RFC 8210 §6)"),
            ));
        }
        if c.preference == Some(255) {
            out.push(Issue::new(
                format!("{path}.preference"),
                "preference must be 0..254",
            ));
        }
    }
    out
}

/// The share of each state among `states` (the badge row of a session).
pub fn shares(states: impl IntoIterator<Item = RpkiState>) -> [u64; 4] {
    let mut n = [0u64; 4];
    for s in states {
        let i = match s {
            RpkiState::Valid => 0,
            RpkiState::Invalid => 1,
            RpkiState::Unknown => 2,
            RpkiState::Unverified => 3,
        };
        if let Some(c) = n.get_mut(i) {
            *c += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::rpki::RpkiCache;

    fn vrp(s: &str, max: u8, asn: u32) -> Vrp {
        let (a, l) = s.split_once('/').unwrap();
        Vrp::new(a.parse().unwrap(), l.parse().unwrap(), max, asn).unwrap()
    }

    fn check(t: &VrpTable, p: &str, origin: Option<u32>) -> RpkiState {
        let (a, l) = p.split_once('/').unwrap();
        t.validate(a.parse().unwrap(), l.parse().unwrap(), origin)
    }

    #[test]
    fn rfc6811_states() {
        // RFC 6811 §2 and the examples of RFC 6483 §2: a /16 ROA for AS
        // 64496 with max length 24.
        let t = VrpTable::build(&[
            vrp("10.0.0.0/16", 24, 64496),
            vrp("10.0.0.0/16", 16, 64497),
            vrp("192.0.2.0/24", 24, 0),
            vrp("2001:db8::/32", 48, 64500),
        ]);
        assert_eq!(check(&t, "10.0.1.0/24", Some(64496)), RpkiState::Valid);
        // Too long for the VRP's max length.
        assert_eq!(check(&t, "10.0.1.0/25", Some(64496)), RpkiState::Invalid);
        // The other VRP of the same prefix allows only the /16.
        assert_eq!(check(&t, "10.0.0.0/16", Some(64497)), RpkiState::Valid);
        assert_eq!(check(&t, "10.0.1.0/24", Some(64497)), RpkiState::Invalid);
        // Wrong origin, and no origin (AS_SET).
        assert_eq!(check(&t, "10.0.1.0/24", Some(1)), RpkiState::Invalid);
        assert_eq!(check(&t, "10.0.1.0/24", None), RpkiState::Invalid);
        // Not covered: a shorter prefix and a neighbor.
        assert_eq!(check(&t, "10.0.0.0/8", Some(64496)), RpkiState::Unknown);
        assert_eq!(check(&t, "10.1.0.0/24", Some(64496)), RpkiState::Unknown);
        // AS 0 VRP: everything it covers is invalid (RFC 6483 §4).
        assert_eq!(check(&t, "192.0.2.0/24", Some(0)), RpkiState::Invalid);
        assert_eq!(check(&t, "192.0.2.0/24", Some(64496)), RpkiState::Invalid);
        assert_eq!(check(&t, "2001:db8:1::/48", Some(64500)), RpkiState::Valid);
        assert_eq!(
            check(&t, "2001:db8:1::/49", Some(64500)),
            RpkiState::Invalid
        );
        assert_eq!(check(&t, "2001:db9::/32", Some(64500)), RpkiState::Unknown);
        assert_eq!((t.len_v4(), t.len_v6()), (3, 1));
        assert_eq!(t.covering("10.0.1.0".parse().unwrap(), 24).len(), 2);
    }

    #[test]
    fn the_trie_agrees_with_a_linear_scan() {
        // Pseudo-random VRPs and routes (a fixed LCG: no rand crate).
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = || {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            x
        };
        let mut vrps = Vec::new();
        for _ in 0..3_000 {
            let r = next();
            let len = 8 + u8::try_from(r % 17).unwrap();
            let addr =
                Ipv4Addr::from(u32::try_from((r >> 16) & 0x0fff_ffff).unwrap() | 0x1000_0000);
            vrps.push(
                Vrp::new(
                    addr.into(),
                    len,
                    len + u8::try_from((r >> 8) % 4).unwrap(),
                    u32::try_from(r % 7).unwrap(),
                )
                .unwrap(),
            );
        }
        let t = VrpTable::build(&vrps);
        for _ in 0..20_000 {
            let r = next();
            let len = 8 + u8::try_from(r % 25).unwrap();
            let addr = IpAddr::V4(Ipv4Addr::from(
                u32::try_from((r >> 16) & 0x0fff_ffff).unwrap() | 0x1000_0000,
            ));
            let origin = Some(u32::try_from((r >> 40) % 7).unwrap());
            let (key, _) = key_of(addr);
            let key = key & mask(len);
            let covering: Vec<&Vrp> = vrps
                .iter()
                .filter(|v| !v.v6 && v.len <= len && key & mask(v.len) == v.key)
                .collect();
            let want = if covering.is_empty() {
                RpkiState::Unknown
            } else if covering
                .iter()
                .any(|v| len <= v.max_len && Some(v.asn) == origin && v.asn != 0)
            {
                RpkiState::Valid
            } else {
                RpkiState::Invalid
            };
            assert_eq!(
                t.validate(addr, len, origin),
                want,
                "{addr}/{len} {origin:?}"
            );
        }
    }

    #[test]
    fn origin_of_paths() {
        assert_eq!(origin_as("64500 64501 13335", None), Some(13335));
        assert_eq!(origin_as("64500 {64510,64511}", None), None);
        assert_eq!(origin_as("", Some(65000)), Some(65000));
        assert_eq!(origin_as("Local", Some(65000)), Some(65000));
        assert_eq!(origin_as("(65001 65002)", Some(65000)), Some(65000));
        assert_eq!(origin_as("(65001) 64500 64501", Some(65000)), Some(64501));
        assert_eq!(origin_as("1.10", None), Some(65_546));
        assert_eq!(origin_as("x", None), None);
    }

    fn cache(name: &str, addr: &str, pref: Option<u8>) -> RpkiCache {
        RpkiCache {
            name: name.into(),
            group: "default".into(),
            address: addr.parse().unwrap(),
            port: 3323,
            refresh_interval: None,
            retry_interval: None,
            expire_interval: None,
            preference: pref,
            disabled: false,
            comment: String::new(),
        }
    }

    #[test]
    fn renders_frr_and_validates() {
        let mut r = Routing::default();
        assert_eq!(render_frr(&r), "");
        r.rpki.insert("b".into(), cache("b", "192.0.2.20", None));
        let mut a = cache("a", "192.0.2.30", Some(10));
        a.refresh_interval = Some(7_200);
        r.rpki.insert("a".into(), a);
        assert_eq!(
            render_frr(&r),
            "rpki\n rpki polling_period 3600\n rpki cache tcp 192.0.2.30 3323 preference 245\n \
             rpki cache tcp 192.0.2.20 3323 preference 255\nexit\n\
             route-map CR-RPKI-IN deny 1\n match rpki invalid\nexit\n\
             route-map CR-RPKI-IN permit 65535\nexit\n"
        );
        assert!(validate(&r).is_empty());
        let mut bad = cache("c", "192.0.2.20", Some(255));
        bad.expire_interval = Some(700);
        bad.refresh_interval = Some(900);
        bad.retry_interval = Some(0);
        r.rpki.insert("c".into(), bad);
        let issues: Vec<String> = validate(&r).iter().map(|i| i.message.clone()).collect();
        assert_eq!(issues.len(), 4, "{issues:?}");
        assert!(issues.iter().any(|m| m.contains("already validator \"b\"")));
        assert!(issues.iter().any(|m| m.contains("RFC 8210 §6")));
    }
}

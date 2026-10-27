//! IP › Firewall › XDP (G2.5a): what the data plane must hold for a
//! config ([`XdpPlan`], pure, shared by every backend) and what it reports
//! back ([`XdpStatus`]).

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{AddrMatch, AddressListEntry, DynamicAddress, Name};
use corerouter_model::xdp::XdpMode;
use corerouter_model::{Config, IfName};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Serialize;

/// Prefixes one address-list entry may expand to (a range is covered by
/// CIDR blocks; `0.0.0.1-255.255.255.254` takes 62).
const MAX_PREFIXES_PER_ENTRY: usize = 256;

/// The filter as the data plane must hold it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XdpPlan {
    /// Interfaces to attach to, in config order.
    pub interfaces: Vec<(IfName, XdpMode)>,
    pub drop_malformed: bool,
    pub drop_invalid_tcp_flags: bool,
    /// Packets per second per source (0 = off) and burst.
    pub rate_limit: u64,
    pub rate_burst: u64,
    /// Blocked prefixes with the index (in the config's `block_lists`) of
    /// a list holding them, sorted and without duplicates.
    pub block: Vec<(IpNet, u32)>,
    pub allow: Vec<(IpNet, u32)>,
    /// The CGNAT fast path is on (G2.5b).
    pub fast_nat: bool,
}

impl XdpPlan {
    /// What `cfg` (plus the dynamic address-list entries, which live in
    /// the data plane only) asks for. No interfaces: nothing to load.
    pub fn of(cfg: &Config, dynamic: &[DynamicAddress]) -> Self {
        let mut plan = Self::settings_of(cfg);
        if !plan.is_empty() {
            let f = &cfg.ip.xdp.filter;
            plan.block = prefixes(cfg, dynamic, &f.block_lists);
            plan.allow = prefixes(cfg, dynamic, &f.allow_lists);
        }
        plan
    }

    /// [`XdpPlan::of`] without the prefixes (`block` and `allow` empty): a
    /// backend that follows them with [`XdpPrefixes`] reads only the
    /// entries that changed, not every address-list entry per commit.
    pub fn settings_of(cfg: &Config) -> Self {
        let x = &cfg.ip.xdp;
        let f = &x.filter;
        let interfaces: Vec<(IfName, XdpMode)> = x
            .active()
            .filter(|i| cfg.interfaces.contains_key(&i.interface))
            .map(|i| (i.interface.clone(), i.mode))
            .collect();
        if interfaces.is_empty() {
            return Self::default();
        }
        Self {
            interfaces,
            drop_malformed: f.drop_malformed,
            drop_invalid_tcp_flags: f.drop_invalid_tcp_flags,
            rate_limit: u64::from(f.rate_limit),
            rate_burst: u64::from(f.burst()),
            block: Vec::new(),
            allow: Vec::new(),
            fast_nat: x.fast_nat,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

/// One side of [`XdpPrefixes`] (block or allow).
#[derive(Debug, Clone, Default)]
struct Side {
    /// The config's `block_lists` (or `allow_lists`) the counts are for.
    lists: Vec<Name>,
    /// Prefix → (list index, entries of that list covering it with it),
    /// lowest index first: the first is the one the data plane holds.
    held: HashMap<IpNet, Vec<(u32, u32)>>,
    /// Prefixes whose holder may have changed since the last
    /// [`XdpPrefixes::take_changes`].
    dirty: BTreeSet<IpNet>,
}

impl Side {
    fn count(&mut self, list: &Name, a: &AddrMatch, up: bool) {
        let Some(i) = self.lists.iter().position(|n| n == list) else {
            return;
        };
        let i = i as u32;
        for n in cover(a) {
            let holders = self.held.entry(n).or_default();
            match holders.binary_search_by_key(&i, |h| h.0) {
                Ok(at) if up => {
                    if let Some(h) = holders.get_mut(at) {
                        h.1 = h.1.saturating_add(1);
                    }
                }
                Ok(at) => {
                    if let Some(h) = holders.get_mut(at) {
                        h.1 = h.1.saturating_sub(1);
                        if h.1 == 0 {
                            holders.remove(at);
                        }
                    }
                }
                Err(at) if up => holders.insert(at, (i, 1)),
                // Not counted (never seen): nothing to take back.
                Err(_) => {}
            }
            if holders.is_empty() {
                self.held.remove(&n);
            }
            self.dirty.insert(n);
        }
    }

    fn changes(&mut self) -> Vec<(IpNet, Option<u32>)> {
        std::mem::take(&mut self.dirty)
            .into_iter()
            .map(|n| (n, self.held.get(&n).and_then(|h| h.first()).map(|h| h.0)))
            .collect()
    }

    fn all(&self) -> Vec<(IpNet, u32)> {
        let mut v: Vec<(IpNet, u32)> = self
            .held
            .iter()
            .filter_map(|(n, h)| h.first().map(|h| (*n, h.0)))
            .collect();
        v.sort();
        v
    }
}

/// The block and allow prefixes of the filter followed change by change
/// (G0.22 × G2.5a), so a commit or a dynamic entry costs what it changed:
/// [`XdpPlan::of`] walks every address-list entry, and a backend that
/// called it per commit paid for 100 000 entries on every unrelated change
/// (and per PPP session that came up with an address list). The static
/// entries are diffed by block ([`CowList::shared_blocks`]); each prefix
/// counts the entries of each list that cover it, so an entry twice, or in
/// two lists, comes and goes exactly. [`XdpPrefixes::take_changes`] says
/// which prefixes to write or remove; [`XdpPrefixes::all`] equals what
/// [`XdpPlan::of`] puts in `block` and `allow`.
#[derive(Debug, Clone, Default)]
pub struct XdpPrefixes {
    block: Side,
    allow: Side,
    /// The static entries counted (shares their blocks with the config).
    statics: CowList<AddressListEntry>,
}

/// The changes [`XdpPrefixes::take_changes`] hands over: prefix → the list
/// index to hold it with, or `None` to remove it.
pub type PrefixChanges = Vec<(IpNet, Option<u32>)>;

/// Prefixes with the list index that holds each, sorted (`XdpPlan::block`).
pub type Held = Vec<(IpNet, u32)>;

impl XdpPrefixes {
    /// Follow `cfg`: its static entries (the blocks that changed since the
    /// last call) and its list names. `dynamic` is every dynamic entry the
    /// backend holds, read only when the list names changed (everything
    /// is counted again then).
    pub fn follow<'a>(
        &mut self,
        cfg: &Config,
        dynamic: impl IntoIterator<Item = &'a DynamicAddress>,
    ) {
        let f = &cfg.ip.xdp.filter;
        let lists = cfg.ip.firewall.address_lists.list();
        if f.block_lists != self.block.lists || f.allow_lists != self.allow.lists {
            for (side, names) in [
                (&mut self.block, &f.block_lists),
                (&mut self.allow, &f.allow_lists),
            ] {
                let old = std::mem::take(&mut side.held);
                side.dirty.extend(old.into_keys());
                side.lists = names.clone();
            }
            self.statics = lists.clone();
            for e in lists.iter().filter(|e| !e.disabled) {
                self.count(&e.list, &e.address, true);
            }
            for d in dynamic {
                self.count(&d.list, &d.address, true);
            }
            return;
        }
        if CowList::ptr_eq(&self.statics, lists) {
            return;
        }
        let old = std::mem::replace(&mut self.statics, lists.clone());
        for (block, (_, shared)) in old.blocks().zip(old.shared_blocks(lists)) {
            if shared.is_none() {
                for e in block.iter().filter(|e| !e.disabled) {
                    self.count(&e.list, &e.address, false);
                }
            }
        }
        for (block, (_, shared)) in lists.blocks().zip(lists.shared_blocks(&old)) {
            if shared.is_none() {
                for e in block.iter().filter(|e| !e.disabled) {
                    self.count(&e.list, &e.address, true);
                }
            }
        }
    }

    /// A dynamic entry came (`up`) or went. The caller counts each one
    /// once: an entry added again (a new timeout) is not a second one.
    pub fn dynamic(&mut self, d: &DynamicAddress, up: bool) {
        self.count(&d.list, &d.address, up);
    }

    fn count(&mut self, list: &Name, a: &AddrMatch, up: bool) {
        self.block.count(list, a, up);
        self.allow.count(list, a, up);
    }

    /// Some prefix may have changed since the last [`Self::take_changes`].
    pub fn pending(&self) -> bool {
        !self.block.dirty.is_empty() || !self.allow.dirty.is_empty()
    }

    /// What changed since the last call, block then allow: the prefixes to
    /// write (with their list index) or to remove.
    pub fn take_changes(&mut self) -> (PrefixChanges, PrefixChanges) {
        (self.block.changes(), self.allow.changes())
    }

    /// Changes taken but not written (the data plane refused): taken again
    /// by the next [`Self::take_changes`].
    pub fn retake(&mut self, block: &PrefixChanges, allow: &PrefixChanges) {
        self.block.dirty.extend(block.iter().map(|c| c.0));
        self.allow.dirty.extend(allow.iter().map(|c| c.0));
    }

    /// Forget the pending changes (the maps are written whole, or not at
    /// all).
    pub fn clear_changes(&mut self) {
        self.block.dirty.clear();
        self.allow.dirty.clear();
    }

    /// Every prefix with its list index, sorted: `block` and `allow` of
    /// [`XdpPlan::of`].
    pub fn all(&self) -> (Held, Held) {
        (self.block.all(), self.allow.all())
    }

    /// The prefixes a map may hold: every one counted and every one
    /// pending (removing them all empties it).
    pub fn every_key(&self) -> (Vec<IpNet>, Vec<IpNet>) {
        let keys = |s: &Side| {
            s.held
                .keys()
                .chain(s.dirty.iter())
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        (keys(&self.block), keys(&self.allow))
    }

    /// Prefixes held: (block, allow).
    pub fn len(&self) -> (usize, usize) {
        (self.block.held.len(), self.allow.held.len())
    }
}

/// Every prefix of `lists` (static entries not disabled, then dynamic
/// ones), tagged with the first list's index that holds it.
fn prefixes(cfg: &Config, dynamic: &[DynamicAddress], lists: &[Name]) -> Vec<(IpNet, u32)> {
    let index = |l: &Name| lists.iter().position(|n| n == l).map(|i| i as u32);
    let statics = cfg
        .ip
        .firewall
        .address_lists
        .iter()
        .filter(|e| !e.disabled)
        .map(|e| (&e.list, &e.address));
    let dynamics = dynamic.iter().map(|d| (&d.list, &d.address));
    let mut out: Vec<(IpNet, u32)> = statics
        .chain(dynamics)
        .filter_map(|(l, a)| Some((index(l)?, a)))
        .flat_map(|(i, a)| cover(a).into_iter().map(move |n| (n, i)))
        .collect();
    out.sort();
    // One entry per prefix: the lowest list index wins.
    out.dedup_by(|b, a| a.0 == b.0);
    out
}

/// CIDR blocks that exactly cover an address-list entry.
pub fn cover(a: &AddrMatch) -> Vec<IpNet> {
    match a {
        AddrMatch::Net(n) => vec![n.trunc()],
        AddrMatch::Range(IpAddr::V4(lo), IpAddr::V4(hi)) => {
            let (mut lo, hi) = (u32::from(*lo), u32::from(*hi));
            let mut out = Vec::new();
            while lo <= hi && out.len() < MAX_PREFIXES_PER_ENTRY {
                // Largest block aligned at `lo` that stays within `hi`.
                let mut len = 32 - lo.trailing_zeros().min(32);
                loop {
                    let size = 1u64 << (32 - len);
                    if u64::from(lo) + size - 1 <= u64::from(hi) {
                        break;
                    }
                    len += 1;
                }
                if let Ok(n) = Ipv4Net::new(lo.into(), len as u8) {
                    out.push(IpNet::V4(n));
                }
                let size = 1u64 << (32 - len);
                match u32::try_from(u64::from(lo) + size) {
                    Ok(next) => lo = next,
                    Err(_) => break,
                }
            }
            out
        }
        AddrMatch::Range(IpAddr::V6(lo), IpAddr::V6(hi)) => {
            let (mut lo, hi) = (u128::from(*lo), u128::from(*hi));
            let mut out = Vec::new();
            while lo <= hi && out.len() < MAX_PREFIXES_PER_ENTRY {
                let mut len = 128 - lo.trailing_zeros().min(128);
                loop {
                    let span = if len == 0 {
                        u128::MAX
                    } else {
                        (1u128 << (128 - len)) - 1
                    };
                    if lo.checked_add(span).is_some_and(|end| end <= hi) {
                        break;
                    }
                    len += 1;
                }
                if let Ok(n) = Ipv6Net::new(lo.into(), len as u8) {
                    out.push(IpNet::V6(n));
                }
                let span = if len == 0 {
                    u128::MAX
                } else {
                    (1u128 << (128 - len)) - 1
                };
                match lo.checked_add(span).and_then(|e| e.checked_add(1)) {
                    Some(next) => lo = next,
                    None => break,
                }
            }
            out
        }
        // Mixed families: the model refuses them; nothing to cover.
        AddrMatch::Range(..) => Vec::new(),
    }
}

/// Why a frame passed or was dropped, with its stable name.
pub const REASONS: [&str; 6] = [
    "pass",
    "blocked",
    "rate-limit",
    "malformed",
    "tcp-flags",
    "fast-nat",
];
/// The reasons that are drops (indexes in [`REASONS`]).
pub const DROPS: [usize; 4] = [1, 2, 3, 4];
/// The CGNAT fast path's index in [`REASONS`] (G2.5b).
pub const FAST_NAT: usize = 5;

/// One interface of the filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XdpPort {
    pub interface: IfName,
    pub mode: XdpMode,
    /// How it is attached now: `native` or `generic`; `None`: not
    /// attached (see `error`).
    pub active: Option<&'static str>,
    /// Why not attached, or why `auto` fell back to generic.
    pub note: Option<String>,
    /// `(packets, bytes)` by reason, in [`REASONS`] order.
    pub counters: Vec<(u64, u64)>,
}

/// A dropped source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XdpTop {
    pub address: IpAddr,
    pub packets: u64,
    pub bytes: u64,
    /// The reason of its last drop ([`REASONS`]).
    pub reason: &'static str,
    /// The block list of its last drop, when blocked.
    pub list: Option<Name>,
    /// Seconds since its last drop.
    pub last_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct XdpStatus {
    /// `Some(why)`: XDP cannot run here (no BPF, no permission, not Linux).
    pub unavailable: Option<String>,
    pub ports: Vec<XdpPort>,
    /// Most dropped sources, most packets first.
    pub top: Vec<XdpTop>,
    /// Prefixes in the block and allow tries.
    pub block_prefixes: usize,
    pub allow_prefixes: usize,
    /// Flow directions in the CGNAT fast path's map (G2.5b).
    pub fast_nat_flows: usize,
    /// Why packets of known flows went to the kernel (reason, packets).
    pub fast_nat_misses: Vec<(&'static str, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::firewall::AddressListEntry;
    use corerouter_model::xdp::XdpInterface;
    use corerouter_model::{Interface, InterfaceKind, ItemId};

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn ranges_become_exact_prefixes() {
        let r = |a: &str, b: &str| cover(&AddrMatch::Range(a.parse().unwrap(), b.parse().unwrap()));
        assert_eq!(r("10.0.0.0", "10.0.0.255"), vec![net("10.0.0.0/24")]);
        assert_eq!(
            r("10.0.0.1", "10.0.0.6"),
            vec![
                net("10.0.0.1/32"),
                net("10.0.0.2/31"),
                net("10.0.0.4/31"),
                net("10.0.0.6/32")
            ]
        );
        assert_eq!(r("0.0.0.0", "255.255.255.255"), vec![net("0.0.0.0/0")]);
        assert_eq!(
            r("255.255.255.255", "255.255.255.255"),
            vec![net("255.255.255.255/32")]
        );
        assert_eq!(
            r("::", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            vec![net("::/1")]
        );
        assert_eq!(
            r("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            vec![net("::/0")]
        );
        assert_eq!(
            r("2001:db8::1", "2001:db8::2"),
            vec![net("2001:db8::1/128"), net("2001:db8::2/128")]
        );
        assert_eq!(
            cover(&AddrMatch::Net(net("192.0.2.77/24"))),
            vec![net("192.0.2.0/24")]
        );
        assert_eq!(r("0.0.0.1", "255.255.255.254").len(), 62);
    }

    #[test]
    fn plan_takes_listed_entries_once() {
        let mut cfg = Config::default();
        let e1: IfName = "ether1".parse().unwrap();
        cfg.interfaces.insert(
            e1.clone(),
            Interface::new(e1.clone(), InterfaceKind::Ethernet),
        );
        assert!(XdpPlan::of(&cfg, &[]).is_empty());
        let fw = &mut cfg.ip.firewall;
        for (i, (list, a, off)) in [
            ("bad", "198.51.100.0/24", false),
            ("worse", "198.51.100.0/24", false),
            ("bad", "203.0.113.0/24", true),
            ("other", "192.0.2.0/24", false),
        ]
        .into_iter()
        .enumerate()
        {
            fw.address_lists.push(AddressListEntry {
                id: ItemId(i as u32 + 1),
                list: list.parse().unwrap(),
                address: AddrMatch::Net(net(a)),
                disabled: off,
                comment: String::new(),
            });
        }
        let ip = &mut cfg.ip;
        ip.xdp.interfaces.push(XdpInterface {
            interface: e1.clone(),
            mode: XdpMode::Auto,
            disabled: false,
            comment: String::new(),
        });
        ip.xdp.filter.block_lists = vec!["worse".parse().unwrap(), "bad".parse().unwrap()];
        let dynamic = [DynamicAddress {
            list: "bad".parse().unwrap(),
            address: AddrMatch::Net(net("2001:db8::/32")),
            timeout_secs: 60,
            added_by_rule: false,
        }];
        let plan = XdpPlan::of(&cfg, &dynamic);
        assert_eq!(plan.interfaces, vec![(e1, XdpMode::Auto)]);
        assert_eq!(
            plan.block,
            vec![(net("198.51.100.0/24"), 0), (net("2001:db8::/32"), 1)]
        );
        assert!(plan.allow.is_empty());
    }

    fn pool(k: u8) -> AddrMatch {
        match k % 6 {
            0 => AddrMatch::Net(net("10.0.0.0/24")),
            1 => AddrMatch::Net(net("10.0.0.0/25")),
            2 => AddrMatch::Range("10.0.0.1".parse().unwrap(), "10.0.0.6".parse().unwrap()),
            3 => AddrMatch::Net(net("2001:db8::/32")),
            4 => AddrMatch::Net(net(&format!("10.1.{k}.0/24"))),
            _ => AddrMatch::Net(net(&format!("10.2.0.{k}/32"))),
        }
    }

    fn list(k: u8) -> Name {
        ["a", "b", "c"][usize::from(k % 3)].parse().unwrap()
    }

    proptest::proptest! {
        /// The prefixes followed change by change, written to a mirror of
        /// the data plane's maps, equal what [`XdpPlan::of`] computes from
        /// scratch, after any series of static, dynamic and list-name
        /// changes.
        #[test]
        fn followed_prefixes_equal_the_plan(ops in proptest::collection::vec((0u8..6, 0u16..400, 0u8..255), 1..50)) {
            let mut cfg = Config::default();
            cfg.ip.xdp.filter.block_lists = vec![list(0), list(1)];
            cfg.ip.xdp.filter.allow_lists = vec![list(2)];
            for i in 0..300u32 {
                cfg.ip.firewall.address_lists.push(AddressListEntry {
                    id: ItemId(i + 1),
                    list: list(i as u8),
                    address: pool((i % 251) as u8),
                    disabled: i % 7 == 0,
                    comment: String::new(),
                });
            }
            let mut dynamic: HashMap<(Name, AddrMatch), DynamicAddress> = HashMap::new();
            let mut x = XdpPrefixes::default();
            let mut maps: [std::collections::BTreeMap<IpNet, u32>; 2] = Default::default();
            let mut next = 1000u32;
            for (op, at, v) in ops {
                let lists = &mut cfg.ip.firewall.address_lists;
                let at = usize::from(at) % lists.len().max(1);
                match op {
                    0 => {
                        next += 1;
                        lists.push(AddressListEntry {
                            id: ItemId(next),
                            list: list(v),
                            address: pool(v / 3),
                            disabled: v % 5 == 0,
                            comment: String::new(),
                        });
                    }
                    1 => {
                        lists.remove(at);
                    }
                    2 => {
                        lists.update(at, |e| e.disabled = !e.disabled);
                    }
                    3 => {
                        let d = DynamicAddress { list: list(v), address: pool(v / 3), timeout_secs: 60, added_by_rule: false };
                        if dynamic.insert((d.list.clone(), d.address), d.clone()).is_none() {
                            x.dynamic(&d, true);
                        }
                    }
                    4 => {
                        if let Some(k) = dynamic.keys().nth(usize::from(v) % dynamic.len().max(1)).cloned()
                            && let Some(d) = dynamic.remove(&k)
                        {
                            x.dynamic(&d, false);
                        }
                    }
                    _ => {
                        let f = &mut cfg.ip.xdp.filter;
                        f.block_lists = (0..v % 3).map(|k| list(k + v)).collect();
                        f.allow_lists = vec![list(v / 3)];
                    }
                }
                x.follow(&cfg, dynamic.values());
                let (b, a) = x.take_changes();
                for (map, changes) in maps.iter_mut().zip([b, a]) {
                    for (n, held) in changes {
                        match held {
                            Some(i) => map.insert(n, i),
                            None => map.remove(&n),
                        };
                    }
                }
                let dynv: Vec<DynamicAddress> = dynamic.values().cloned().collect();
                let f = &cfg.ip.xdp.filter;
                let want_b = prefixes(&cfg, &dynv, &f.block_lists);
                let want_a = prefixes(&cfg, &dynv, &f.allow_lists);
                let got: [Vec<(IpNet, u32)>; 2] = [
                    maps[0].iter().map(|(n, i)| (*n, *i)).collect(),
                    maps[1].iter().map(|(n, i)| (*n, *i)).collect(),
                ];
                proptest::prop_assert_eq!(&got[0], &want_b);
                proptest::prop_assert_eq!(&got[1], &want_a);
                proptest::prop_assert_eq!(x.all(), (want_b, want_a));
            }
        }
    }
}

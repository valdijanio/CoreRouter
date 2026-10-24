//! IP › Firewall › XDP (G2.5a): what the data plane must hold for a
//! config ([`XdpPlan`], pure, shared by every backend) and what it reports
//! back ([`XdpStatus`]).

use std::net::IpAddr;

use corerouter_model::firewall::{AddrMatch, DynamicAddress, Name};
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
            block: prefixes(cfg, dynamic, &f.block_lists),
            allow: prefixes(cfg, dynamic, &f.allow_lists),
            fast_nat: x.fast_nat,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
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
}

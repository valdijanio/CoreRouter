//! "Where does the data plane send a packet to X?" (G1.27): the platform's
//! own answer, what Linux's `ip route get` (`RTM_GETROUTE`) gives, so
//! `ip.route.lookup` can show it next to the engine's and say when the two
//! differ (drift, a route of another program, the kernel's own rules).

use std::net::IpAddr;

use corerouter_model::{Config, IfName, InterfaceKind, route};
use ipnet::IpNet;
use serde::Serialize;

use crate::drift::Snapshot;

/// A lookup: destination, kernel table id, and the source when the
/// operator gave one (`ip route get <dst> from <src> table <t>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteQuery {
    pub dst: IpAddr,
    pub table: u32,
    pub src: Option<IpAddr>,
}

/// What the route found is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteKind {
    /// Forwarded: through `hops`.
    Unicast,
    /// One of the router's own addresses.
    Local,
    /// No route (`ENETUNREACH`), or a reject route.
    Unreachable,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::Local => "local",
            Self::Unreachable => "unreachable",
        }
    }
}

/// One next hop of the data plane's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelHop {
    pub gateway: Option<IpAddr>,
    pub interface: IfName,
}

/// The data plane's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelLookup {
    pub kind: RouteKind,
    /// The matching entry's prefix, when the platform says it
    /// (`RTM_F_FIB_MATCH`).
    pub prefix: Option<IpNet>,
    pub hops: Vec<KernelHop>,
    /// Preferred source (`RTA_PREFSRC`).
    pub src: Option<IpAddr>,
    pub table: u32,
}

/// Kernel table the link `name` routes in (its VRF's, or main).
fn table_of_link(cfg: &Config, snap: &Snapshot, name: &IfName) -> u32 {
    if let Some(InterfaceKind::Vrf { table }) = cfg.interfaces.get(name).map(|i| &i.kind) {
        return *table;
    }
    snap.links
        .get(name)
        .and_then(|l| l.master.as_ref())
        .and_then(|m| match cfg.interfaces.get(m).map(|i| &i.kind) {
            Some(InterfaceKind::Vrf { table }) => Some(*table),
            _ => None,
        })
        .unwrap_or(route::MAIN_TABLE_ID)
}

/// The lab's answer: longest prefix over what `snap` holds (its addresses
/// make the connected and local routes), then the lowest metric; equal
/// metrics are all returned (ECMP). The table ids of VRFs come from `cfg`.
pub fn lookup(cfg: &Config, snap: &Snapshot, q: &RouteQuery) -> KernelLookup {
    let in_table = |link: &IfName| table_of_link(cfg, snap, link) == q.table;
    let src_of = |link: &IfName, gw: Option<IpAddr>| {
        q.src.or_else(|| {
            let mine = || {
                snap.addresses
                    .iter()
                    .filter(|(l, a)| l == link && a.addr().is_ipv4() == q.dst.is_ipv4())
            };
            mine()
                .find(|(_, a)| a.contains(&gw.unwrap_or(q.dst)))
                .or_else(|| mine().next())
                .map(|(_, a)| a.addr())
        })
    };
    if let Some((link, _)) = snap
        .addresses
        .iter()
        .find(|(l, a)| a.addr() == q.dst && in_table(l))
    {
        return KernelLookup {
            kind: RouteKind::Local,
            prefix: IpNet::new(q.dst, if q.dst.is_ipv4() { 32 } else { 128 }).ok(),
            hops: vec![KernelHop {
                gateway: None,
                interface: link.clone(),
            }],
            src: Some(q.src.unwrap_or(q.dst)),
            table: q.table,
        };
    }
    // (prefix, metric, hop): connected first with metric 0.
    let mut best: Option<(IpNet, u32)> = None;
    let mut hops: Vec<KernelHop> = Vec::new();
    let mut consider = |net: IpNet, metric: u32, hop: KernelHop| {
        let better = match best {
            None => true,
            Some((b, m)) => {
                (net.prefix_len(), std::cmp::Reverse(metric))
                    > (b.prefix_len(), std::cmp::Reverse(m))
            }
        };
        let same = best.is_some_and(|(b, m)| b == net && m == metric);
        if better {
            best = Some((net, metric));
            hops = vec![hop];
        } else if same && !hops.contains(&hop) {
            hops.push(hop);
        }
    };
    for (link, a) in &snap.addresses {
        if a.contains(&q.dst) && in_table(link) {
            consider(
                a.trunc(),
                0,
                KernelHop {
                    gateway: None,
                    interface: link.clone(),
                },
            );
        }
    }
    for r in &snap.routes {
        if r.table == q.table && r.dst.contains(&q.dst) {
            consider(
                r.dst,
                r.metric,
                KernelHop {
                    gateway: r.gateway,
                    interface: r.link.clone(),
                },
            );
        }
    }
    match (best, hops.first()) {
        (Some((prefix, _)), Some(first)) => KernelLookup {
            kind: RouteKind::Unicast,
            prefix: Some(prefix),
            src: src_of(&first.interface, first.gateway),
            hops,
            table: q.table,
        },
        _ => KernelLookup {
            kind: RouteKind::Unreachable,
            prefix: None,
            hops: Vec::new(),
            src: None,
            table: q.table,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::KernelRoute;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn snap() -> Snapshot {
        let mut s = Snapshot::default();
        s.addresses
            .insert((n("ether1"), "10.0.0.2/24".parse().unwrap()));
        s.addresses
            .insert((n("ether2"), "10.0.1.2/24".parse().unwrap()));
        for (dst, gw, link, metric) in [
            ("0.0.0.0/0", "10.0.0.1", "ether1", 1),
            ("192.0.2.0/24", "10.0.0.1", "ether1", 1),
            ("192.0.2.0/25", "10.0.1.1", "ether2", 1),
            ("198.51.100.0/24", "10.0.0.1", "ether1", 1),
            ("198.51.100.0/24", "10.0.1.1", "ether2", 1),
            ("198.51.100.0/24", "10.0.1.9", "ether2", 5),
        ] {
            s.routes.insert(KernelRoute {
                table: route::MAIN_TABLE_ID,
                dst: dst.parse().unwrap(),
                metric,
                link: n(link),
                gateway: Some(gw.parse().unwrap()),
            });
        }
        s
    }

    fn get(dst: &str) -> KernelLookup {
        lookup(
            &Config::default(),
            &snap(),
            &RouteQuery {
                dst: dst.parse().unwrap(),
                table: route::MAIN_TABLE_ID,
                src: None,
            },
        )
    }

    #[test]
    fn longest_prefix_then_metric_then_ecmp() {
        let r = get("192.0.2.7");
        assert_eq!(r.prefix, Some("192.0.2.0/25".parse().unwrap()));
        assert_eq!(r.hops[0].interface, n("ether2"));
        assert_eq!(r.src, Some("10.0.1.2".parse().unwrap()));
        assert_eq!(
            get("192.0.2.200").prefix,
            Some("192.0.2.0/24".parse().unwrap())
        );
        assert_eq!(get("8.8.8.8").prefix, Some("0.0.0.0/0".parse().unwrap()));
        let ecmp = get("198.51.100.1");
        assert_eq!(ecmp.hops.len(), 2, "metric 5 is left out: {ecmp:?}");
        let conn = get("10.0.1.77");
        assert_eq!(
            (conn.kind, conn.hops[0].gateway),
            (RouteKind::Unicast, None)
        );
        assert_eq!(get("10.0.0.2").kind, RouteKind::Local);
        assert_eq!(get("2001:db8::1").kind, RouteKind::Unreachable);
    }
}

//! `ip.route.lookup` (G1.27): which route a packet to an address takes —
//! Linux's `ip route get`, RouterOS v7's `/ip route check`. Answered from
//! the engine's own table (so it works in the virtual lab), then checked
//! against the data plane's answer (`Hal::route_get`) when there is one.
//!
//! Order of the rules: the router's own addresses first (the kernel's
//! `local` table, rule 0), then the longest matching prefix among the
//! active routes of the table (RFC 1812 §5.2.4.3, RFC 4632 §5.1); an ECMP
//! group gives every path. There are no policy rules yet (`/routing rule`
//! is gap G1.27e): the table is the one asked for, the VRF of the source
//! address, or main.

use std::net::IpAddr;

use corerouter_hal::route_get::{KernelLookup, RouteKind, RouteQuery};
use corerouter_model::route::{self, is_link_local, table_of};
use corerouter_model::{Config, IfName, RoutingTable};
use ipnet::IpNet;
use serde::Serialize;

use crate::route_table::{Line, State};

/// What the engine answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hop {
    pub gateway: Option<IpAddr>,
    pub interface: IfName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub table: RoutingTable,
    pub table_id: u32,
    /// How the table was chosen.
    pub rule: String,
    pub kind: RouteKind,
    /// Key of the route that matched (`None`: local or unreachable).
    pub route: Option<String>,
    pub prefix: Option<IpNet>,
    pub hops: Vec<Hop>,
    pub src: Option<IpAddr>,
}

/// The table to look in, and why. `Err((field, why))` for a bad request.
pub fn choose_table(
    cfg: &Config,
    table: Option<&RoutingTable>,
    src: Option<IpAddr>,
) -> Result<(RoutingTable, String), (&'static str, String)> {
    if let Some(src) = src
        && !cfg.ip.addresses.iter().any(|a| a.address.addr() == src)
    {
        return Err((
            "src",
            format!(
                "{src} is not an address of this router (a forwarded packet's source would also \
                 need its incoming interface)"
            ),
        ));
    }
    if let Some(t) = table {
        if route::table_id(cfg, t).is_none() {
            return Err((
                "table",
                format!("routing table '{t}' does not exist (see ip.vrf.list)"),
            ));
        }
        return Ok((t.clone(), format!("routing table '{t}' asked for")));
    }
    let by_src = src.and_then(|s| {
        cfg.ip
            .addresses
            .iter()
            .find(|a| a.address.addr() == s)
            .map(|a| (table_of(cfg, &a.interface), a.interface.clone()))
    });
    match by_src {
        Some((t @ RoutingTable::Vrf(_), iface)) => {
            let why = format!("source is on '{iface}', a member of VRF '{t}'");
            Ok((t, why))
        }
        _ => Ok((
            RoutingTable::Main,
            "main table: no routing rule matches (there are none yet)".into(),
        )),
    }
}

/// The source the kernel would pick on `link`: the operator's, else an
/// enabled address there whose network holds `toward` (the gateway, or
/// the destination on link), else the first one of the family. IPv6 skips
/// link-local addresses unless the destination is one (a simplified RFC
/// 6724 §5 rule 2, "prefer appropriate scope").
fn source(cfg: &Config, link: &IfName, toward: IpAddr, dst: IpAddr) -> Option<IpAddr> {
    let fits = |a: &&corerouter_model::AddressEntry| {
        !a.disabled
            && a.interface == *link
            && a.address.addr().is_ipv4() == dst.is_ipv4()
            && (is_link_local(dst) || !is_link_local(a.address.addr()))
    };
    let mine = || cfg.ip.addresses.iter().filter(fits);
    mine()
        .find(|a| a.address.contains(&toward))
        .or_else(|| mine().next())
        .map(|a| a.address.addr())
}

/// Answer from the engine's table (`lines`, from [`crate::route_table::build`]
/// over `cfg`).
pub fn lookup(
    cfg: &Config,
    lines: &[Line],
    dst: IpAddr,
    table: RoutingTable,
    rule: String,
    src: Option<IpAddr>,
) -> Lookup {
    let table_id = route::table_id(cfg, &table).unwrap_or(route::MAIN_TABLE_ID);
    let own = cfg.ip.addresses.iter().find(|a| {
        a.address.addr() == dst && !a.disabled && table_of(cfg, &a.interface) == table
    });
    if let Some(a) = own {
        return Lookup {
            table,
            table_id,
            rule: format!("{dst} is an address of this router (local table, before {rule})"),
            kind: RouteKind::Local,
            route: None,
            prefix: IpNet::new(dst, if dst.is_ipv4() { 32 } else { 128 }).ok(),
            hops: vec![Hop {
                gateway: None,
                interface: a.interface.clone(),
            }],
            src: Some(src.unwrap_or(dst)),
        };
    }
    let best = lines
        .iter()
        .filter(|l| l.state == State::Active && l.table == table && l.dst.contains(&dst))
        .max_by_key(|l| l.dst.prefix_len());
    let Some(best) = best else {
        return Lookup {
            table,
            table_id,
            rule,
            kind: RouteKind::Unreachable,
            route: None,
            prefix: None,
            hops: Vec::new(),
            src: None,
        };
    };
    // The whole ECMP group: the active lines of the same prefix.
    let hops: Vec<Hop> = lines
        .iter()
        .filter(|l| l.state == State::Active && l.table == table && l.dst == best.dst)
        .filter_map(|l| l.via.as_ref())
        .map(|v| Hop {
            gateway: v.gateway,
            interface: v.link.clone(),
        })
        .collect();
    let src = src.or_else(|| {
        let first = hops.first()?;
        source(cfg, &first.interface, first.gateway.unwrap_or(dst), dst)
    });
    Lookup {
        table,
        table_id,
        rule,
        kind: RouteKind::Unicast,
        route: Some(best.key.clone()),
        prefix: Some(best.dst),
        hops,
        src,
    }
}

/// Where the data plane's answer differs from the engine's, one line per
/// difference (empty: they agree).
pub fn differences(engine: &Lookup, kernel: &KernelLookup) -> Vec<String> {
    let mut out = Vec::new();
    if engine.kind != kernel.kind {
        out.push(format!(
            "the kernel says {}, the config says {}",
            kernel.kind.as_str(),
            engine.kind.as_str()
        ));
        return out;
    }
    if let (Some(e), Some(k)) = (engine.prefix, kernel.prefix)
        && e != k
    {
        out.push(format!("the kernel matches {k}, the config {e}"));
    }
    let mut a: Vec<_> = engine
        .hops
        .iter()
        .map(|h| (h.gateway, h.interface.clone()))
        .collect();
    let mut b: Vec<_> = kernel
        .hops
        .iter()
        .map(|h| (h.gateway, h.interface.clone()))
        .collect();
    a.sort();
    b.sort();
    // The kernel answers one path of an ECMP group (the flow's hash).
    let hop = |h: &(Option<IpAddr>, IfName)| match h.0 {
        Some(g) => format!("{g}%{}", h.1),
        None => h.1.to_string(),
    };
    let covered = !b.is_empty() && b.iter().all(|h| a.contains(h));
    if a != b && !(covered && a.len() > 1) {
        out.push(format!(
            "the kernel sends it via {}, the config via {}",
            b.iter().map(hop).collect::<Vec<_>>().join(", "),
            a.iter().map(hop).collect::<Vec<_>>().join(", ")
        ));
    }
    if let (Some(e), Some(k)) = (engine.src, kernel.src)
        && e != k
    {
        out.push(format!("the kernel picks source {k}, the config {e}"));
    }
    out
}

/// The query for the data plane.
pub fn query(l: &Lookup, dst: IpAddr, src: Option<IpAddr>) -> RouteQuery {
    RouteQuery {
        dst,
        table: l.table_id,
        src,
    }
}

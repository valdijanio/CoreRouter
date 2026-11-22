//! `ip.route.lookup` (G1.27): which route a packet to an address takes —
//! Linux's `ip route get`, RouterOS v7's `/ip route check`. Answered from
//! the engine's own table (so it works in the virtual lab), then checked
//! against the data plane's answer (`Hal::route_get`) when there is one.
//!
//! Order of the rules: the router's own addresses first (the kernel's
//! `local` table, rule 0), then the longest matching prefix among the
//! active routes of the table (RFC 1812 §5.2.4.3, RFC 4632 §5.1); an ECMP
//! group gives every path. The table is the one asked for or, as the
//! kernel chooses it (G1.27e), what the rule list says: the routing marks of
//! the mangle, the VRF, `/routing rule`, main (`corerouter_hal::policy`).

use std::net::IpAddr;

use corerouter_hal::policy::{KernelRuleAction, L3MDEV_PREF, RulePacket, RuleVerdict, expected_rules, walk};
use corerouter_hal::route_get::{KernelLookup, RouteKind, RouteQuery};
use corerouter_model::route::{self, is_link_local, table_of};
use corerouter_model::{Config, IfName, ItemId, RoutingTable};
use ipnet::IpNet;
use serde::Serialize;

use crate::policy_rule::describe_pref;
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
    forwarded: bool,
) -> Result<(RoutingTable, String), (&'static str, String)> {
    if let Some(src) = src
        && !forwarded
        && !cfg.ip.addresses.iter().any(|a| a.address.addr() == src)
    {
        return Err((
            "src",
            format!(
                "{src} is not an address of this router (for a forwarded packet give its \
                 incoming interface too)"
            ),
        ));
    }
    if let Some(t) = table {
        if route::table_id(cfg, t).is_none() {
            return Err((
                "table",
                format!("routing table '{t}' does not exist (see routing.table.list)"),
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
            "main table: no routing rule decided".into(),
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
        // G1.5b: a discard route has no next hop; it says what it does.
        kind: best.discard.map_or(RouteKind::Unicast, RouteKind::from),
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
    // Which table chose it: only a forwarded route says (the kernel's local
    // table holds the router's own addresses).
    if engine.kind == RouteKind::Unicast && engine.table_id != kernel.table {
        out.push(format!(
            "the kernel looks in table {}, the config in {}",
            kernel.table, engine.table_id
        ));
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

/// The query for the data plane: `policy` to walk its rule list too.
pub fn query(
    l: &Lookup,
    dst: IpAddr,
    src: Option<IpAddr>,
    policy: Option<corerouter_hal::route_get::PolicyQuery>,
) -> RouteQuery {
    RouteQuery {
        dst,
        table: l.table_id,
        src,
        policy,
    }
}

/// What the walk of the rules looks at besides the addresses.
#[derive(Debug, Clone, Default)]
pub struct Flow<'a> {
    pub iif: Option<&'a IfName>,
    pub mark: u32,
}

/// One rule the packet matched, for the answer's `trace`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceStep {
    pub priority: u32,
    /// The id of the routing rule; `None`: not one of `/routing rule`.
    pub rule: Option<ItemId>,
    pub what: String,
    /// `route found`, `no route: next`, `dropped`, `unreachable`.
    pub result: &'static str,
}

/// The kernel table id of the VRF a packet is in: its incoming interface's,
/// else its source's (an address of this router).
pub fn vrf_of(cfg: &Config, iif: Option<&IfName>, src: Option<IpAddr>) -> Option<u32> {
    let holder = iif.or_else(|| {
        let src = src?;
        cfg.ip
            .addresses
            .iter()
            .find(|a| a.address.addr() == src)
            .map(|a| &a.interface)
    })?;
    let table = table_of(cfg, holder);
    if route::is_vrf_table(cfg, &table) {
        route::table_id(cfg, &table)
    } else {
        None
    }
}

/// [`lookup`] with the table chosen the kernel's way: rule 0 (`local`), then
/// the rule list. The second value says which rules the packet matched.
pub fn lookup_by_rules(
    cfg: &Config,
    lines: &[Line],
    dst: IpAddr,
    src: Option<IpAddr>,
    flow: &Flow<'_>,
) -> (Lookup, Vec<TraceStep>) {
    let vrf = vrf_of(cfg, flow.iif, src);
    let tables = route::tables_by_id(cfg);
    let start = vrf
        .and_then(|t| tables.get(&t).cloned())
        .unwrap_or(RoutingTable::Main);
    // Rule 0: the router's own addresses (in a VRF, its table holds them).
    let own = lookup(cfg, lines, dst, start.clone(), String::new(), src);
    if own.kind == RouteKind::Local {
        let local = TraceStep {
            priority: 0,
            rule: None,
            what: "local table".to_owned(),
            result: "route found",
        };
        return (own, vec![local]);
    }
    let packet = RulePacket {
        src,
        dst,
        iif: flow.iif,
        mark: flow.mark,
        vrf,
    };
    let rules = expected_rules(cfg);
    let walked = walk(&rules, &packet, |id, suppress| {
        let Some(t) = tables.get(&id) else {
            return false;
        };
        let found = lookup(cfg, lines, dst, t.clone(), String::new(), src);
        // An `unreachable` route decides too (G1.5b); only no route goes on.
        (found.kind != RouteKind::Unreachable || found.route.is_some())
            && suppress.is_none_or(|s| found.prefix.is_some_and(|p| p.prefix_len() > s))
    });
    let trace: Vec<TraceStep> = walked
        .steps
        .iter()
        .map(|st| {
            let (rule, mut what) = describe_pref(cfg, st.pref);
            if st.pref == L3MDEV_PREF {
                what = format!("the table of VRF '{start}'");
            }
            let result = match (st.action, st.decided) {
                (KernelRuleAction::Table(_), true) => "route found",
                (KernelRuleAction::Table(_), false) => "no route: next",
                (KernelRuleAction::Blackhole, _) => "dropped",
                (KernelRuleAction::Unreachable | KernelRuleAction::Other(_), _) => "unreachable",
            };
            TraceStep {
                priority: st.pref,
                rule,
                what,
                result,
            }
        })
        .collect();
    let why = trace
        .last()
        .map_or_else(String::new, |t| t.what.clone());
    let found = match walked.verdict {
        RuleVerdict::Table(id) => {
            let table = tables.get(&id).cloned().unwrap_or(RoutingTable::Main);
            lookup(cfg, lines, dst, table, why, src)
        }
        verdict => {
            let kind = if verdict == RuleVerdict::Blackhole {
                RouteKind::Blackhole
            } else {
                RouteKind::Unreachable
            };
            Lookup {
                table: start,
                table_id: vrf.unwrap_or(route::MAIN_TABLE_ID),
                rule: why,
                kind,
                route: None,
                prefix: None,
                hops: Vec::new(),
                src: None,
            }
        }
    };
    (found, trace)
}

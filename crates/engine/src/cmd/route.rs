//! /ip route — static routes, plus the connected routes derived from IP
//! addresses in `ip.route.list` (flagged dynamic/connected, as in RouterOS).

use corerouter_model::dhcp_client::CheckGateway;
use corerouter_model::{
    Config, DEFAULT_DISTANCE, Gateway, ItemId, RouteEntry, RoutingTable, parse_destination,
};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::dhcp_client::is_dynamic;
use crate::route_table::{Changed, Line, Origin, RouteWatch, State};
use crate::validate::route_issues;
use crate::{EngineError, Result, Session};

/// Hostile-input bound on static routes (a full BGP table belongs to BGP,
/// not to static routes; **estimado**).
pub const MAX_ROUTES: usize = 65_536;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.route.add",
        "Add Route",
        ["IP", "Routes"],
        None,
        "{dst_address: cidr | ip (0.0.0.0/0, ::/0, 10.1.0.0/16, 192.0.2.7), gateway: ip | interface | ip%interface, distance?: u32 (1..=255, default 1), routing_table?: string (main | VRF name, default main), check_gateway?: none | ping | arp | bfd (default none; ping/arp every 10 s, down after 2 misses: the route leaves the kernel and the next distance wins), bfd_profile?: string (check_gateway=bfd; default 'default'), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.route.set",
        "Set Route",
        [],
        None,
        "{id: *hex, dst_address?: cidr | ip, gateway?: ip | interface | ip%interface, distance?: u32 (1..=255), routing_table?: string, check_gateway?: none | ping | arp | bfd, bfd_profile?: string (check_gateway=bfd; empty: default), disabled?: bool, comment?: string} → {id}",
        has_routes,
        set
    ),
    cmd!(
        "ip.route.remove",
        "Remove Route",
        [],
        None,
        "{id: *hex (a static route; connected ones go with their address)} → {id}",
        has_routes,
        remove
    ),
    cmd!(query "ip.route.check.list", "Gateway Checks", [], None,
        "{} → [{gateway, method (arp | ping | bfd), routing_table, bfd_profile (bfd; null), routes (static routes sharing this check), status (checking | reachable | unreachable), misses, down_secs (null: up), hold_down_secs (null: no hold-down), flaps_15m}]",
        always, check_list),
    cmd!(query "ip.route.check.history", "Gateway Check History", [], None,
        "{gateway?: ip} → [{time (Unix s; null: no clock), gateway, method, to (up | down), routes, message}]",
        always, check_history),
    cmd!(query "ip.route.list", "Routes", ["IP", "Routes"], None,
        "{routing_table?: string, family?: string (ipv4 | ipv6), state?: string (active | standby | inactive), origin?: string (connected | static | dhcp | ra)} → [{key (stable row key), id (null if connected), dst_address, family, gateway (as configured), gateway_address, gateway_interface, gateway_status (reachable | unreachable | incomplete: the gateway does not answer ARP/ND; null if connected), check_gateway (null | {method (arp | ping | bfd), interval_secs (0: bfd), misses, state (up | down), status (checking | reachable | unreachable | not-checked), hold_down_secs (answers again, held for flapping; null), bfd_profile (bfd; null)}), distance, routing_table, flags (X disabled, A active, D dynamic, C connected, S static, + ECMP), state (active | standby: a lower distance wins | inactive), active, static, connected, dynamic (from a DHCP lease, a Router Advertisement or connected), origin (connected | static | dhcp | ra), disabled, immediate_gw, interface, ecmp (paths of its ECMP group), reason (why standby or inactive), reason_id, reason_args, notice (null | {level (info: paths of one origin | warning: origins mixed or the default route, split per connection between uplinks), text, id, args, fix (the command that makes one path a backup; null)}), changed_at (Unix s it took its state; null: before watching), changed_secs, comment}]",
        always, list),
];

fn has_routes(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.routes.is_empty() {
        Err("there are no static routes".into())
    } else {
        Ok(())
    }
}

fn opt_dst(p: &Value) -> Result<Option<IpNet>> {
    opt_str(p, "dst_address")?
        .map(|s| parse_destination(s).map_err(|e| EngineError::bad("dst_address", e.to_string())))
        .transpose()
}

fn opt_distance(p: &Value) -> Result<Option<u8>> {
    opt_u32(p, "distance")?
        .map(|d| {
            u8::try_from(d)
                .ok()
                .filter(|d| *d >= 1)
                .ok_or_else(|| EngineError::bad("distance", "must be 1..=255"))
        })
        .transpose()
}

/// Refuse `r` with the first problem the validator sees in it.
fn check(cfg: &Config, r: &RouteEntry) -> Result<()> {
    // The routes on the same hop, in O(1) from the index (G0.31d).
    let same = cfg.ip.routes.same_hop(r);
    match route_issues(cfg, r, same).into_iter().next() {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let dst = parse_destination(req_str(p, "dst_address")?)
        .map_err(|e| EngineError::bad("dst_address", e.to_string()))?;
    let gateway: Gateway = req_parse(p, "gateway")?;
    let distance = opt_distance(p)?.unwrap_or(DEFAULT_DISTANCE);
    let routing_table: RoutingTable = opt_parse(p, "routing_table")?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let check_gateway: CheckGateway = opt_parse(p, "check_gateway")?.unwrap_or_default();
    let bfd_profile = opt_text(p, "bfd_profile", 48)?.unwrap_or_default();

    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.routes.len() >= MAX_ROUTES {
        return Err(EngineError::bad(
            "dst_address",
            format!("at most {MAX_ROUTES} static routes"),
        ));
    }
    let id = cfg.ip.next_route_id();
    let route = RouteEntry {
        id,
        dst_address: dst,
        gateway,
        distance,
        routing_table,
        disabled,
        comment,
        check_gateway,
        bfd_profile,
    };
    check(cfg, &route)?;
    cfg.ip.routes.push(route);
    Ok(json!({ "id": id }))
}

/// Parse `id` as a static route of the candidate.
fn existing(cfg: &Config, p: &Value) -> Result<(usize, ItemId)> {
    let id: ItemId = req_parse(p, "id")?;
    if is_dynamic(id) {
        return Err(EngineError::bad(
            "id",
            format!(
                "{id} is dynamic (a DHCP client's route or a Router Advertisement); change the \
                 client instead (ip.dhcp-client.set / ipv6.dhcp-client.set add_default_route, \
                 default_route_distance) or stop accepting RA (ipv6.settings.set)"
            ),
        ));
    }
    let pos = cfg.ip.routes.position(id).ok_or_else(|| {
            EngineError::bad(
                "id",
                format!(
                    "no static route {id} (see ip.route.list; connected routes come and go with \
                 their IP address)"
                ),
            )
        })?;
    Ok((pos, id))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let dst = opt_dst(p)?;
    let gateway: Option<Gateway> = opt_parse(p, "gateway")?;
    let distance = opt_distance(p)?;
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let check_gateway: Option<CheckGateway> = opt_parse(p, "check_gateway")?;
    let bfd_profile = opt_text(p, "bfd_profile", 48)?;

    let cfg = s.store_mut().candidate_mut();
    let (pos, id) = existing(cfg, p)?;
    let mut route = cfg
        .ip
        .routes
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no static route {id}")))?;
    if let Some(d) = dst {
        route.dst_address = d;
    }
    if let Some(g) = gateway {
        route.gateway = g;
    }
    if let Some(d) = distance {
        route.distance = d;
    }
    if let Some(t) = table {
        route.routing_table = t;
    }
    if let Some(d) = disabled {
        route.disabled = d;
    }
    if let Some(c) = comment {
        route.comment = c;
    }
    if let Some(m) = check_gateway {
        route.check_gateway = m;
        // Leaving bfd drops its profile, unless one is given anyway.
        if m != CheckGateway::Bfd && bfd_profile.is_none() {
            route.bfd_profile.clear();
        }
    }
    if let Some(b) = bfd_profile {
        route.bfd_profile = b;
    }
    check(cfg, &route)?;
    cfg.ip.routes.update(pos, |slot| *slot = route);
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let (pos, id) = existing(cfg, p)?;
    cfg.ip.routes.remove(pos);
    Ok(json!({ "id": id }))
}

/// A filter value of `ip.route.list`, checked against its choices.
fn opt_choice<'a>(p: &'a Value, key: &str, choices: &[&str]) -> Result<Option<&'a str>> {
    match opt_str(p, key)? {
        Some(v) if choices.contains(&v) => Ok(Some(v)),
        Some(v) => Err(EngineError::bad(
            key,
            format!(
                "'{}' is not one of {}",
                v.chars().take(32).collect::<String>(),
                choices.join(", ")
            ),
        )),
        None => Ok(None),
    }
}

/// G1.27d: a gateway whose neighbor entry did not resolve (RFC 4861
/// §7.3.2 INCOMPLETE, or FAILED: nothing answered the ARP request or the
/// Neighbor Solicitation) is `incomplete`: routed, but the packets go
/// nowhere. No entry: not asked yet, so still `reachable`.
pub(crate) fn layer2(row: &mut Value, l: &Line, t: &crate::neigh_table::NeighTable) {
    if incomplete(l, t)
        && let Some(o) = row.as_object_mut()
    {
        o.insert("gateway_status".into(), json!("incomplete"));
    }
}

/// [`layer2`]: the neighbor entry of `l`'s gateway did not resolve.
fn incomplete(l: &Line, t: &crate::neigh_table::NeighTable) -> bool {
    let Some(crate::route_table::Via {
        link,
        gateway: Some(gw),
    }) = &l.via
    else {
        return false;
    };
    t.get(link, *gw).is_some_and(|r| !r.state.resolved())
}

/// `ip.route.list`'s view of one route (as a [`Value`], for the page and
/// the detail; the list writes [`Row`] straight into the connection).
pub(crate) fn row(l: &Line, watch: Option<&Changed>, now: Option<u64>) -> Value {
    serde_json::to_value(Row::new(l, watch, now)).unwrap_or(Value::Null)
}

/// One row of `ip.route.list`, serialized straight from the line: no
/// `Value` tree of 31 keys per route (G0.31h). The fields are in the
/// alphabetical order the `Value` map had, so the JSON is the same.
#[derive(serde::Serialize)]
pub(crate) struct Row<'a> {
    active: bool,
    changed_at: Option<u64>,
    changed_secs: Option<u64>,
    check_gateway: Option<CheckRow<'a>>,
    comment: &'a str,
    connected: bool,
    disabled: bool,
    distance: u8,
    #[serde(serialize_with = "display")]
    dst_address: &'a IpNet,
    dynamic: bool,
    ecmp: usize,
    family: &'static str,
    flags: String,
    gateway: &'a str,
    gateway_address: Option<std::net::IpAddr>,
    gateway_interface: Option<&'a corerouter_model::IfName>,
    gateway_status: Option<&'static str>,
    id: Option<ItemId>,
    immediate_gw: Option<String>,
    interface: Option<&'a corerouter_model::IfName>,
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mpls_in: Option<Option<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mpls_out: Option<Option<String>>,
    notice: Option<NoticeRow<'a>>,
    origin: &'static str,
    reason: Option<&'a str>,
    reason_args: Option<Args<'a>>,
    reason_id: Option<&'static str>,
    routing_table: &'a RoutingTable,
    state: &'static str,
    #[serde(rename = "static")]
    is_static: bool,
}

#[derive(serde::Serialize)]
struct CheckRow<'a> {
    bfd_profile: &'a Option<String>,
    hold_down_secs: Option<u64>,
    interval_secs: u64,
    method: &'static str,
    misses: u32,
    state: &'static str,
    status: &'static str,
}

#[derive(serde::Serialize)]
struct NoticeRow<'a> {
    args: Args<'a>,
    fix: &'a Option<String>,
    id: &'static str,
    level: &'static str,
    text: &'a str,
}

/// The `{argument: value}` of a reason, as a JSON object (keys sorted,
/// as in a `Value` map).
struct Args<'a>(&'a [(&'static str, String)]);

impl serde::Serialize for Args<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut args: Vec<&(&str, String)> = self.0.iter().collect();
        args.sort_unstable_by_key(|(k, _)| *k);
        s.collect_map(args.into_iter().map(|(k, v)| (*k, v)))
    }
}

fn display<S: serde::Serializer>(
    v: &&IpNet,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(v)
}

impl<'a> Row<'a> {
    pub(crate) fn new(l: &'a Line, watch: Option<&Changed>, now: Option<u64>) -> Self {
        let changed_at = watch.and_then(|w| w.changed_at(&l.key));
        let gateway_status = match l.origin {
            Origin::Connected => None,
            _ if l.via.is_some() => Some("reachable"),
            _ => Some("unreachable"),
        };
        Self {
            active: l.state == State::Active,
            changed_at,
            changed_secs: changed_at.zip(now).map(|(at, now)| now.saturating_sub(at)),
            check_gateway: l.check.as_ref().map(|c| CheckRow {
                bfd_profile: &c.profile,
                hold_down_secs: c.hold_secs,
                interval_secs: c.interval_secs,
                method: c.method,
                misses: c.misses,
                state: if c.down { "down" } else { "up" },
                status: c.status,
            }),
            comment: &l.comment,
            connected: l.origin == Origin::Connected,
            disabled: l.disabled,
            dst_address: &l.dst,
            distance: l.distance,
            dynamic: l.origin != Origin::Static,
            ecmp: l.ecmp,
            family: if l.dst.addr().is_ipv4() { "ipv4" } else { "ipv6" },
            flags: l.flags(),
            gateway: &l.gateway,
            gateway_address: l.gateway_address,
            gateway_interface: l.gateway_interface.as_ref(),
            gateway_status,
            id: l.id,
            immediate_gw: l.immediate_gw(),
            interface: l.via.as_ref().map(|v| &v.link),
            key: &l.key,
            mpls_in: None,
            mpls_out: None,
            notice: l.notice.as_ref().map(|n| NoticeRow {
                args: Args(&n.why.args),
                fix: &n.fix,
                id: n.why.id,
                level: n.level.as_str(),
                text: &n.why.text,
            }),
            origin: l.origin.as_str(),
            reason: l.why.as_ref().map(|w| w.text.as_str()),
            reason_args: l.why.as_ref().map(|w| Args(&w.args)),
            reason_id: l.why.as_ref().map(|w| w.id),
            routing_table: &l.table,
            state: l.state.as_str(),
            is_static: matches!(l.origin, Origin::Static | Origin::Dhcp),
        }
    }
}

fn check_list(s: &mut Session, _p: &Value) -> Result<Value> {
    Ok(Value::Array(s.route_check_rows()))
}

fn check_history(s: &mut Session, p: &Value) -> Result<Value> {
    let gateway: Option<std::net::IpAddr> = opt_parse(p, "gateway")?;
    Ok(Value::Array(s.route_check_history(gateway)))
}

/// G0.31h: a list this long is "large": one at a time per session.
pub const LARGE_LIST: usize = 10_000;

/// The large lists being written now (G0.31h). Streamed, each holds a
/// row at a time, but the snapshot of the lines and the time of a slow
/// reader are still the router's: two `/ip route print` of a full table
/// at once wait for each other instead of doubling the cost.
#[derive(Default)]
struct LargeLists(std::sync::Arc<std::sync::atomic::AtomicUsize>);

/// One of [`LargeLists`], given back when the answer is written.
struct LargeSlot(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for LargeSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn large_slot(s: &mut Session, rows: usize) -> Result<Option<LargeSlot>> {
    use std::sync::atomic::Ordering;
    if rows < LARGE_LIST {
        return Ok(None);
    }
    let Some(l) = s.ext_mut::<LargeLists>() else {
        return Ok(None);
    };
    let busy = l
        .0
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err();
    if busy {
        return Err(EngineError::Disabled {
            id: "ip.route.list".into(),
            reason: format!(
                "busy: another list of {LARGE_LIST}+ routes is being sent; try again in a \
                 moment, filter it (routing_table, family, state, origin) or page it \
                 (ip.route.page)"
            ),
        });
    }
    Ok(Some(LargeSlot(l.0.clone())))
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let family = opt_choice(p, "family", &["ipv4", "ipv6"])?.map(|f| f == "ipv4");
    let state = opt_choice(p, "state", &["active", "standby", "inactive"])?.map(str::to_owned);
    let origin = opt_choice(p, "origin", &["connected", "static", "dhcp", "ra"])?.map(str::to_owned);
    let keep = move |l: &Line| {
        table.as_ref().is_none_or(|t| *t == l.table)
            && family.is_none_or(|v4| v4 == l.dst.addr().is_ipv4())
            && state.as_deref().is_none_or(|st| st == l.state.as_str())
            && origin.as_deref().is_none_or(|o| o == l.origin.as_str())
    };
    // Under the lock: pointers to the cached lines, the watch's states,
    // the neighbour table and the LDP bindings (G0.31b). The rows of
    // 60 000 routes are written after it is released, one at a time
    // (G0.31h).
    let (lines, now) = s.watched_route_lines();
    let slot = if lines.len() >= LARGE_LIST {
        large_slot(s, lines.iter().filter(|l| keep(l)).count())?
    } else {
        None
    };
    let answer = ListAnswer {
        lines,
        keep: Box::new(keep),
        now,
        neigh: s.neigh_fresh(),
        changed: s.ext::<RouteWatch>().map(RouteWatch::changed),
        ldp: crate::mpls::ldp_state(s),
        _slot: slot,
    };
    s.defer_stream(answer)
}

/// What `ip.route.list` needs to answer without the session (G0.31h).
struct ListAnswer {
    lines: std::sync::Arc<Vec<Line>>,
    keep: Box<dyn Fn(&Line) -> bool + Send>,
    now: Option<u64>,
    neigh: crate::neigh_table::NeighShared,
    changed: Option<Changed>,
    ldp: Option<std::sync::Arc<corerouter_model::mpls_state::LdpState>>,
    _slot: Option<LargeSlot>,
}

impl ListAnswer {
    /// Each row in order, to `f`.
    fn each(&self, mut f: impl FnMut(Row<'_>) -> std::io::Result<()>) -> std::io::Result<()> {
        // The neighbour table only for this pass: a slow reader must not
        // hold it while the rows go out.
        let unresolved: std::collections::HashSet<usize> = {
            let neigh = self.neigh.lock();
            self.lines
                .iter()
                .enumerate()
                .filter(|(_, l)| (self.keep)(l) && incomplete(l, &neigh))
                .map(|(i, _)| i)
                .collect()
        };
        let labels = crate::mpls::LdpLabels::new(self.ldp.as_deref());
        for (i, l) in self.lines.iter().enumerate().filter(|(_, l)| (self.keep)(l)) {
            let mut r = Row::new(l, self.changed.as_ref(), self.now);
            if unresolved.contains(&i) {
                r.gateway_status = Some("incomplete");
            }
            if let Some((local, out)) = labels.get(&l.dst) {
                r.mpls_in = Some(local);
                r.mpls_out = Some(out);
            }
            f(r)?;
        }
        Ok(())
    }
}

impl crate::off_lock::Streamed for ListAnswer {
    fn write(self: Box<Self>, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        w.write_all(b"[")?;
        let mut first = true;
        self.each(|r| {
            if !first {
                w.write_all(b",")?;
            }
            first = false;
            serde_json::to_writer(&mut *w, &r).map_err(std::io::Error::from)
        })?;
        w.write_all(b"]")
    }

    fn value(self: Box<Self>) -> Result<Value> {
        let mut rows = Vec::new();
        self.each(|r| {
            rows.push(serde_json::to_value(r).map_err(std::io::Error::from)?);
            Ok(())
        })
        .map_err(|e| EngineError::Internal(format!("ip.route.list: {e}")))?;
        Ok(Value::Array(rows))
    }
}

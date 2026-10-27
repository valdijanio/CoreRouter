//! Firewall diagnosis (G2.1c): the packet tester, live rule counters, the
//! packet trace and the ruleset preview.
//!
//! - `ip.firewall.test`: the way of one made-up packet through raw, mangle,
//!   NAT, the routing decision and filter (`corerouter_firewall::path`),
//!   with the rule that decides. Pure: the config only.
//! - `ip.firewall.counters`, `ip.firewall.<table>.reset-counters`: packets,
//!   bytes, rate and last use per rule, read by the daemon outside the lock
//!   (`crate::firewall_diag`).
//! - `ip.firewall.trace.*`: real packets, `meta nftrace` on for a filter,
//!   bounded in time and events (Junos `packet-trace`, nftables trace).
//! - `ip.firewall.preview`: the nftables ruleset of the running config
//!   against the candidate's, line by line (the Diff tab, next to
//!   `config.diff`).

use std::net::IpAddr;

use corerouter_firewall::diff;
use corerouter_firewall::eval::Packet;
use corerouter_firewall::path::{Route, path};
use corerouter_model::firewall::{AddrMatch, ConnState, Family, Protocol, Table};
use corerouter_model::route::{self};
use corerouter_model::{IfName, ItemId, RoutingTable};
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::firewall_diag::{
    FwDiag, STALE_DAYS, TRACE_DEFAULT_EVENTS, TRACE_DEFAULT_SECS, TRACE_MAX_EVENTS,
    TRACE_MAX_SECS, TraceFilter, TraceJob,
};
use crate::lockout::{local_interface, route_out};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.firewall.test", "Test Packet", ["IP", "Firewall"], None,
        "{src: ip, dst: ip, protocol?: tcp | udp | icmp | icmpv6 | 0..255 (default tcp), src_port?: u16, dst_port?: u16, icmp_type?: u8, icmp_code?: u8, in_interface?: interface (absent = sent by the router itself), state?: new | established | related | invalid (default new)} → {family, steps: [{table, chain, skipped (why the kernel does not run it, else null), verdict (accept | drop | reject | nat | notrack, null when skipped), rule (*hex that decided in this chain, null = policy), hits: [{id, chain, action}] (every rule it matched, in order)}], route: local | <interface> | unreachable, fate: delivered | sent | dropped | no-route, decided_by: {table, id, summary} | null, packet: {src, dst, src_port, dst_port, state, out_interface}} (assumes no marks, limits not exceeded, address lists without the kernel's own entries)",
        always, test),
    cmd!(query "ip.firewall.preview", "Ruleset Preview", ["IP", "Firewall"], None,
        "{} → {changed: bool, added, removed, lines: [{op: \" \" | + | -, text}], running: string, candidate: string} (the nftables table inet corerouter now and after config.commit)",
        always, preview),
    cmd!(query "ip.firewall.counters", "Rule Counters", ["IP", "Firewall"], None,
        "{table?: filter | nat | mangle | raw, stale_days?: u32 (default 30)} → {read_at (unix seconds, null before the first read), interval (seconds), error (why the kernel could not be read, else null), rules: [{table, id, packets, bytes, pps, bps, last_used (unix seconds, null = not since the reads began), idle_secs, stale (unused stale_days or more)}]} (live, not saved; reads go on while this is asked for)",
        always, counters),
    cmd!("ip.firewall.filter.reset-counters", "Reset Counters", [], None,
        "{id?: *hex (absent = every rule of the table)} → {reset}", always, reset_filter),
    cmd!("ip.firewall.nat.reset-counters", "Reset Counters", [], None,
        "{id?: *hex (absent = every rule of the table)} → {reset}", always, reset_nat),
    cmd!("ip.firewall.mangle.reset-counters", "Reset Counters", [], None,
        "{id?: *hex (absent = every rule of the table)} → {reset}", always, reset_mangle),
    cmd!("ip.firewall.raw.reset-counters", "Reset Counters", [], None,
        "{id?: *hex (absent = every rule of the table)} → {reset}", always, reset_raw),
    cmd!("ip.firewall.trace.start", "Trace Packets", ["IP", "Firewall"], None,
        "{src?: ip | cidr, dst?: ip | cidr, protocol?: tcp | udp | icmp | icmpv6 | 0..255, port?: u16 (destination port), in_interface?: interface, duration?: seconds (1..300, default 60), max_events?: u32 (1..10000, default 1000)} → {generation, until} (at least one of src, dst, protocol, port, in_interface; the kernel marks at most 20 matching packets per second; replaces a running trace)",
        always, trace_start),
    cmd!("ip.firewall.trace.stop", "Stop Trace", [], None,
        "{} → {stopped: bool}", always, trace_stop),
    cmd!(query "ip.firewall.trace.list", "Trace", ["IP", "Firewall"], None,
        "{} → {active: bool, until, ended (time | events | stopped | why it failed, else null), filter, packets: [{trace, at, src, dst, protocol, sport, dport, iif, oif, fate (accept | drop | …, the last verdict), steps: [{table, chain, rule (*hex or null), kind (rule | return | policy), verdict}]}]}",
        always, trace_list),
];

fn parse_state(p: &Value) -> Result<ConnState> {
    let Some(s) = opt_str(p, "state")? else {
        return Ok(ConnState::New);
    };
    ConnState::ALL
        .into_iter()
        .find(|c| c.name() == s.trim())
        .ok_or_else(|| {
            EngineError::bad(
                "state",
                "expected new, established, related, invalid or untracked",
            )
        })
}

fn port(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| u16::try_from(v).map_err(|_| EngineError::bad(key, "a port is 0..65535")))
        .transpose()
}

fn byte(p: &Value, key: &str) -> Result<Option<u8>> {
    opt_u32(p, key)?
        .map(|v| u8::try_from(v).map_err(|_| EngineError::bad(key, "0..255")))
        .transpose()
}

/// The packet `ip.firewall.test` asks about.
fn test_packet(s: &Session, p: &Value) -> Result<Packet> {
    let src: IpAddr = req_parse(p, "src")?;
    let dst: IpAddr = req_parse(p, "dst")?;
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(EngineError::bad("dst", "src and dst must be the same family"));
    }
    let protocol: Protocol = opt_parse(p, "protocol")?.unwrap_or(Protocol::TCP);
    let (src_port, dst_port) = (port(p, "src_port")?, port(p, "dst_port")?);
    let ports = protocol.has_ports();
    if !ports && (src_port.is_some() || dst_port.is_some()) {
        let k = if src_port.is_some() { "src_port" } else { "dst_port" };
        return Err(EngineError::bad(k, format!("protocol {protocol} has no ports")));
    }
    let icmp_proto = protocol == Protocol::ICMP || protocol == Protocol::ICMPV6;
    let (t, c) = (byte(p, "icmp_type")?, byte(p, "icmp_code")?);
    if !icmp_proto && (t.is_some() || c.is_some()) {
        return Err(EngineError::bad("icmp_type", "needs protocol icmp or icmpv6"));
    }
    if (protocol == Protocol::ICMP && dst.is_ipv6()) || (protocol == Protocol::ICMPV6 && dst.is_ipv4()) {
        return Err(EngineError::bad("protocol", "icmp is IPv4, icmpv6 is IPv6"));
    }
    let in_interface: Option<IfName> = opt_parse(p, "in_interface")?;
    if let Some(i) = &in_interface
        && !s.store().candidate().interfaces.contains_key(i)
    {
        return Err(EngineError::bad(
            "in_interface",
            format!("no interface {i} (see interface.list)"),
        ));
    }
    Ok(Packet {
        src,
        dst,
        protocol,
        // A port-less matcher needs a value: an ephemeral source by default.
        src_port: if ports { src_port.or(Some(40_000)) } else { None },
        dst_port: if ports { dst_port.or(Some(80)) } else { None },
        icmp: icmp_proto.then(|| (t.unwrap_or(8), c.unwrap_or(0))),
        in_interface: in_interface.map(|i| i.as_str().to_owned()),
        out_interface: None,
        state: parse_state(p)?,
        nat: None,
    })
}

fn test(s: &mut Session, p: &Value) -> Result<Value> {
    let packet = test_packet(s, p)?;
    let cfg = s.store().candidate();
    let dynamic = s.dynamic_now();
    let router = |dst: IpAddr, iif: Option<&str>| {
        if local_interface(cfg, dst).is_some() {
            return Route::Local;
        }
        let table = iif
            .and_then(|i| i.parse::<IfName>().ok())
            .map_or(RoutingTable::Main, |i| route::table_of(cfg, &i));
        route_out(cfg, dst, &table).map_or(Route::Unreachable, Route::Out)
    };
    let way = path(cfg, &dynamic, &packet, &router);
    let steps: Vec<Value> = way
        .steps
        .iter()
        .map(|st| {
            json!({
                "table": st.table.name(),
                "chain": st.chain,
                "skipped": st.skipped,
                "verdict": st.outcome.map(|o| verdict(o.verdict)),
                "rule": st.outcome.and_then(|o| o.rule),
                "hits": st.hits.iter().map(|h| json!({
                    "id": h.rule, "chain": h.chain.as_str(), "action": h.action,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let decided = way.decided_by.and_then(|(t, id)| {
        cfg.ip
            .firewall
            .rules(t)
            .iter()
            .find(|r| r.id == id)
            .map(|r| json!({"table": t.name(), "id": id, "summary": super::firewall::summary(r)}))
    });
    let route = match &way.route {
        Route::Local => "local".to_owned(),
        Route::Out(i) => i.clone(),
        Route::Unreachable => "unreachable".to_owned(),
    };
    Ok(json!({
        "family": Family::of(packet.src).name(),
        "steps": steps,
        "route": route,
        "fate": way.fate.name(),
        "decided_by": decided,
        "packet": {
            "src": way.packet.src.to_string(),
            "dst": way.packet.dst.to_string(),
            "src_port": way.packet.src_port,
            "dst_port": way.packet.dst_port,
            "state": way.packet.state.name(),
            "out_interface": way.packet.out_interface,
        },
    }))
}

fn verdict(v: corerouter_firewall::eval::Verdict) -> &'static str {
    use corerouter_firewall::eval::Verdict;
    match v {
        Verdict::Accept => "accept",
        Verdict::Drop => "drop",
        Verdict::Reject => "reject",
        Verdict::Nat => "nat",
        Verdict::Notrack => "notrack",
    }
}

fn preview(s: &mut Session, _p: &Value) -> Result<Value> {
    let dynamic = s.dynamic_now();
    let store = s.store();
    let (run, cand) = (store.running(), store.candidate());
    let render = |c| corerouter_firewall::render(c, &dynamic).unwrap_or_default();
    let (old, new) = (render(run), render(cand));
    let lines = diff::lines(&old, &new);
    let count = |op: &str| lines.iter().filter(|l| l.op() == op).count();
    let (added, removed) = (count("+"), count("-"));
    Ok(json!({
        "changed": added + removed > 0,
        "added": added,
        "removed": removed,
        "lines": lines.iter().map(|l| json!({"op": l.op(), "text": l.text()})).collect::<Vec<_>>(),
        "running": old,
        "candidate": new,
    }))
}

fn counters(s: &mut Session, p: &Value) -> Result<Value> {
    let table: Option<Table> = opt_parse(p, "table")?;
    let stale_days = u64::from(opt_u32(p, "stale_days")?.unwrap_or(STALE_DAYS as u32));
    s.firewall_counters_want();
    let now = s.now().unwrap_or(0);
    let Some(d) = s.ext::<FwDiag>() else {
        return Ok(json!({"read_at": null, "rules": []}));
    };
    let mut rows: Vec<(&(Table, ItemId), _)> = d
        .live
        .iter()
        .filter(|((t, _), _)| table.is_none_or(|x| x == *t))
        .collect();
    rows.sort_by_key(|(k, _)| **k);
    Ok(json!({
        "read_at": d.read_at,
        "interval": crate::firewall_diag::INTERVAL_SECS,
        "error": d.read_error,
        "rules": rows.into_iter().map(|((t, id), l)| {
            let idle = l.idle_secs(now);
            json!({
                "table": t.name(),
                "id": id,
                "packets": l.shown_packets(),
                "bytes": l.shown_bytes(),
                "pps": (l.pps * 10.0).round() / 10.0,
                "bps": l.bps.round(),
                "last_used": l.last_used,
                "idle_secs": idle,
                "stale": idle >= stale_days.saturating_mul(86_400),
            })
        }).collect::<Vec<_>>(),
    }))
}

fn reset(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    let id: Option<ItemId> = opt_parse(p, "id")?;
    if let Some(id) = id
        && !s
            .store()
            .candidate()
            .ip
            .firewall
            .rules(table)
            .iter()
            .any(|r| r.id == id)
    {
        return Err(EngineError::bad(
            "id",
            format!("no {} rule {id} (see ip.firewall.{}.list)", table.name(), table.name()),
        ));
    }
    Ok(json!({"reset": s.firewall_counters_reset(table, id)}))
}

fn reset_filter(s: &mut Session, p: &Value) -> Result<Value> {
    reset(s, Table::Filter, p)
}
fn reset_nat(s: &mut Session, p: &Value) -> Result<Value> {
    reset(s, Table::Nat, p)
}
fn reset_mangle(s: &mut Session, p: &Value) -> Result<Value> {
    reset(s, Table::Mangle, p)
}
fn reset_raw(s: &mut Session, p: &Value) -> Result<Value> {
    reset(s, Table::Raw, p)
}

fn trace_start(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = TraceFilter {
        family: None,
        src: opt_parse::<AddrMatch>(p, "src")?,
        dst: opt_parse::<AddrMatch>(p, "dst")?,
        protocol: opt_parse(p, "protocol")?,
        port: port(p, "port")?,
        in_interface: opt_parse::<IfName>(p, "in_interface")?.map(|i| i.as_str().to_owned()),
    };
    for (key, a) in [("src", &filter.src), ("dst", &filter.dst)] {
        if matches!(a, Some(AddrMatch::Range(..))) {
            return Err(EngineError::bad(key, "an address or a prefix (a range cannot be traced)"));
        }
    }
    if filter.is_empty() {
        return Err(EngineError::bad(
            "src",
            "a trace needs a filter (src, dst, protocol, port or in_interface): tracing \
             every packet would cost the router",
        ));
    }
    let fam = |a: &Option<AddrMatch>| a.as_ref().map(AddrMatch::family);
    let family = match (fam(&filter.src), fam(&filter.dst)) {
        (Some(a), Some(b)) if a != b => {
            return Err(EngineError::bad("dst", "src and dst must be the same family"));
        }
        (a, b) => a.or(b),
    };
    if filter.port.is_some() && filter.protocol.is_none_or(|p| !p.has_ports()) {
        return Err(EngineError::bad("port", "needs protocol tcp, udp, sctp or udp-lite"));
    }
    let secs = u64::from(opt_u32(p, "duration")?.unwrap_or(TRACE_DEFAULT_SECS as u32));
    if !(1..=TRACE_MAX_SECS).contains(&secs) {
        return Err(EngineError::bad("duration", format!("1..{TRACE_MAX_SECS} seconds")));
    }
    let max = opt_u32(p, "max_events")?.map_or(TRACE_DEFAULT_EVENTS, |m| m as usize);
    if !(1..=TRACE_MAX_EVENTS).contains(&max) {
        return Err(EngineError::bad("max_events", format!("1..{TRACE_MAX_EVENTS}")));
    }
    let now = s.now().unwrap_or(0);
    let d = s
        .ext_mut::<FwDiag>()
        .ok_or_else(|| EngineError::Internal("no diagnosis state".into()))?;
    d.trace.generation = d.trace.generation.wrapping_add(1);
    let job = TraceJob {
        generation: d.trace.generation,
        filter: TraceFilter { family, ..filter },
        until: now.saturating_add(secs),
        max_events: max,
    };
    d.trace.events.clear();
    d.trace.ended = None;
    d.trace.started = Some(now);
    d.trace.job = Some(job.clone());
    Ok(json!({"generation": job.generation, "until": job.until}))
}

fn trace_stop(s: &mut Session, _p: &Value) -> Result<Value> {
    let Some(d) = s.ext_mut::<FwDiag>() else {
        return Ok(json!({"stopped": false}));
    };
    let was = d.trace.job.take().is_some();
    if was {
        d.trace.ended = Some("stopped".into());
    }
    Ok(json!({"stopped": was}))
}

fn trace_list(s: &mut Session, _p: &Value) -> Result<Value> {
    let now = s.now().unwrap_or(0);
    let Some(d) = s.ext::<FwDiag>() else {
        return Ok(json!({"active": false, "packets": []}));
    };
    let t = &d.trace;
    // Events of one packet share its trace id; first seen first.
    let mut order: Vec<u32> = Vec::new();
    let mut by: std::collections::HashMap<u32, Vec<&crate::firewall_diag::TraceEvent>> =
        std::collections::HashMap::new();
    for e in &t.events {
        let v = by.entry(e.trace).or_default();
        if v.is_empty() {
            order.push(e.trace);
        }
        v.push(e);
    }
    let packets: Vec<Value> = order
        .iter()
        .filter_map(|id| by.get(id))
        .filter_map(|evs| {
            let first = evs.first()?;
            let last = evs.last()?;
            Some(json!({
                "trace": first.trace,
                "at": first.at,
                "src": first.src.map(|a| a.to_string()),
                "dst": first.dst.map(|a| a.to_string()),
                "protocol": first.protocol.map(|p| Protocol(p).to_string()),
                "sport": first.sport,
                "dport": first.dport,
                "iif": first.iif,
                "oif": evs.iter().rev().find_map(|e| e.oif.clone()),
                "fate": last.verdict,
                "steps": evs.iter().map(|e| json!({
                    "table": e.table, "chain": e.chain, "rule": e.rule,
                    "kind": e.kind, "verdict": e.verdict,
                })).collect::<Vec<_>>(),
            }))
        })
        .collect();
    let job = t.job.as_ref();
    Ok(json!({
        "active": job.is_some_and(|j| now < j.until),
        "until": job.map(|j| j.until),
        "ended": t.ended,
        "filter": job.map(|j| json!({
            "src": j.filter.src.as_ref().map(ToString::to_string),
            "dst": j.filter.dst.as_ref().map(ToString::to_string),
            "protocol": j.filter.protocol.map(|p| p.to_string()),
            "port": j.filter.port,
            "in_interface": j.filter.in_interface,
        })),
        "packets": packets,
    }))
}

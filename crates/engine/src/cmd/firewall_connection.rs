//! /ip firewall connection (G2.2): the conntrack table, live — filters,
//! the subscribers with the most connections, kill, the tracking
//! timeouts (`/ip firewall connection tracking`) and how full the table
//! is (`nf_conntrack_max`, the Tuning parameter of G1.26).
//!
//! The kernel's table is read whole (`Hal::connections`, ctnetlink) and
//! filtered and paged here; a dump is reused for [`CACHE_SECS`] so a GUI
//! scrolling a million connections reads them once, not per page.

use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_hal::conntrack::{Conn, Stats, Via, status};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows of one page.
pub const MAX_PAGE: u32 = 5000;
/// A dump younger than this is reused.
pub const CACHE_SECS: u64 = 2;

/// RouterOS `/ip firewall connection tracking` names → Tuning sysctls.
pub const TIMEOUTS: &[(&str, &str)] = &[
    ("tcp_established_timeout", "net.netfilter.nf_conntrack_tcp_timeout_established"),
    ("tcp_syn_sent_timeout", "net.netfilter.nf_conntrack_tcp_timeout_syn_sent"),
    ("tcp_syn_received_timeout", "net.netfilter.nf_conntrack_tcp_timeout_syn_recv"),
    ("tcp_fin_wait_timeout", "net.netfilter.nf_conntrack_tcp_timeout_fin_wait"),
    ("tcp_close_wait_timeout", "net.netfilter.nf_conntrack_tcp_timeout_close_wait"),
    ("tcp_time_wait_timeout", "net.netfilter.nf_conntrack_tcp_timeout_time_wait"),
    ("udp_timeout", "net.netfilter.nf_conntrack_udp_timeout"),
    ("udp_stream_timeout", "net.netfilter.nf_conntrack_udp_timeout_stream"),
    ("icmp_timeout", "net.netfilter.nf_conntrack_icmp_timeout"),
    ("generic_timeout", "net.netfilter.nf_conntrack_generic_timeout"),
];
const MAX_ENTRIES: &str = "net.netfilter.nf_conntrack_max";

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.firewall.connection.list", "Connections", ["IP", "Firewall"], None,
        "{protocol?: string (tcp, udp, icmp or a number), src?: string (address or prefix of the original source), dst?: string (address or prefix of the original destination), port?: u16 (either port of the original direction), state?: string (established, new, time-wait…), subscriber?: string (a CGNAT subscriber: the original source), public?: string (the public address the NAT chose), via?: rules | software | hardware, nat?: srcnat | dstnat, sort?: timeout | bytes | packets (largest first), offset?: u32, count?: u32 (1..5000; default 200)} → {total (matching), offset, rows: [{id, protocol, src, dst, reply_src, reply_dst, nat? (public address:port of a srcnat), state, flags (S seen-reply, A assured, C confirmed, s srcnat, d dstnat, F fasttrack, H hw-offload), timeout, via, orig_packets, orig_bytes, repl_packets, repl_bytes, pool? (the CGNAT pool of the source)}], table: {count, max, percent, insert_failed, drop, early_drop}}",
        always, list),
    cmd!(query "ip.firewall.connection.top", "Top Subscribers", [], None,
        "{count?: u32 (1..100; default 10), protocol?: string} → [{subscriber, connections, tcp, udp, icmp, other, pool?, ports_used (public ports of its srcnat connections), ports (its slot), percent}] (most connections first)",
        always, top),
    cmd!(
        "ip.firewall.connection.kill",
        "Kill Connections",
        [],
        None,
        "{id?: u32 (one connection), protocol?: string, src?: string, dst?: string, port?: u16, state?: string, subscriber?: string, public?: string, via?: string, nat?: string, all?: bool (needed when no filter is given)} → {matched, killed}",
        always,
        kill
    ),
    cmd!(query "ip.firewall.connection.tracking.info", "Connection Tracking", [], None,
        "{} → {tcp_established_timeout, tcp_syn_sent_timeout, tcp_syn_received_timeout, tcp_fin_wait_timeout, tcp_close_wait_timeout, tcp_time_wait_timeout, udp_timeout, udp_stream_timeout, icmp_timeout, generic_timeout, max_entries, total_entries, loaded} (seconds; the kernel's values, null when conntrack is not loaded; kept as System › Tuning parameters, exported there)",
        always, tracking_info),
    cmd!(
        "ip.firewall.connection.tracking.set",
        "Connection Tracking Settings",
        [],
        None,
        "{tcp_established_timeout?: duration, tcp_syn_sent_timeout?: duration, tcp_syn_received_timeout?: duration, tcp_fin_wait_timeout?: duration, tcp_close_wait_timeout?: duration, tcp_time_wait_timeout?: duration, udp_timeout?: duration, udp_stream_timeout?: duration, icmp_timeout?: duration, generic_timeout?: duration, max_entries?: u32} → {changed: [{name, value}]} (kept as System › Tuning parameters)",
        always,
        tracking_set
    ),
];

/// The last dump and when it was read (`Hal::monotonic_secs`).
#[derive(Default)]
pub struct ConnCache {
    at: Option<u64>,
    conns: std::sync::Arc<Vec<Conn>>,
    stats: Stats,
}

impl ConnCache {
    /// Read again next time (the fast path changed what Via says).
    pub(crate) fn forget(&mut self) {
        self.at = None;
    }
}

impl Session {
    /// The kernel's connections, read at most every [`CACHE_SECS`].
    /// `fresh`: read now (after a kill).
    pub(crate) fn connections(&mut self, fresh: bool) -> Result<(std::sync::Arc<Vec<Conn>>, Stats)> {
        let now = self.hal().monotonic_secs();
        if !fresh
            && let (Some(now), Some(c)) = (now, self.ext::<ConnCache>())
            && c.at.is_some_and(|at| now.saturating_sub(at) < CACHE_SECS)
        {
            return Ok((c.conns.clone(), c.stats));
        }
        let conns = self
            .hal_mut()
            .connections()
            .map_err(|e| EngineError::Hal(e.to_string()))?;
        let stats = self.hal_mut().connection_stats().unwrap_or_default();
        let conns = std::sync::Arc::new(conns);
        if let Some(c) = self.ext_mut::<ConnCache>() {
            c.at = now;
            c.conns = conns.clone();
            c.stats = stats;
        }
        Ok((conns, stats))
    }
}

fn protocol_number(text: &str) -> Option<u8> {
    match text.trim() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "icmp" => Some(1),
        "icmpv6" | "ipv6-icmp" => Some(58),
        "gre" => Some(47),
        "esp" => Some(50),
        "sctp" => Some(132),
        n => n.parse().ok(),
    }
}

pub fn protocol_name(n: u8) -> String {
    match n {
        6 => "tcp".into(),
        17 => "udp".into(),
        1 => "icmp".into(),
        58 => "icmpv6".into(),
        47 => "gre".into(),
        50 => "esp".into(),
        132 => "sctp".into(),
        n => n.to_string(),
    }
}

fn prefix(p: &Value, key: &str) -> Result<Option<IpNet>> {
    let Some(t) = opt_str(p, key)? else { return Ok(None) };
    let t = t.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if let Ok(n) = t.parse::<IpNet>() {
        return Ok(Some(n.trunc()));
    }
    t.parse::<IpAddr>()
        .map(|a| Some(IpNet::from(a)))
        .map_err(|_| EngineError::bad(key, "an address or prefix (10.0.0.0/8)"))
}

/// A connection filter from the parameters (shared by list and kill).
#[derive(Debug, Default)]
struct Filter {
    protocol: Option<u8>,
    src: Option<IpNet>,
    dst: Option<IpNet>,
    port: Option<u16>,
    state: Option<String>,
    subscriber: Option<IpAddr>,
    public: Option<IpAddr>,
    via: Option<Via>,
    nat: Option<u32>,
    id: Option<u32>,
}

impl Filter {
    fn of(p: &Value) -> Result<Self> {
        let protocol = match opt_str(p, "protocol")? {
            None => None,
            Some(t) if t.trim().is_empty() => None,
            Some(t) => Some(
                protocol_number(t)
                    .ok_or_else(|| EngineError::bad("protocol", "tcp, udp, icmp or a number 0..255"))?,
            ),
        };
        let port = match opt_u32(p, "port")? {
            Some(n) => Some(u16::try_from(n).map_err(|_| EngineError::bad("port", "0..65535"))?),
            None => None,
        };
        let via = match opt_str(p, "via")? {
            None => None,
            Some("rules") => Some(Via::Rules),
            Some("software") => Some(Via::Software),
            Some("hardware") => Some(Via::Hardware),
            Some(_) => return Err(EngineError::bad("via", "rules, software or hardware")),
        };
        let nat = match opt_str(p, "nat")? {
            None => None,
            Some("srcnat") => Some(status::SRC_NAT),
            Some("dstnat") => Some(status::DST_NAT),
            Some(_) => return Err(EngineError::bad("nat", "srcnat or dstnat")),
        };
        let state = match opt_str(p, "state")? {
            None => None,
            Some(t) if t.len() > 32 => return Err(EngineError::bad("state", "at most 32 characters")),
            Some(t) => Some(t.trim().to_owned()),
        };
        Ok(Self {
            protocol,
            src: prefix(p, "src")?,
            dst: prefix(p, "dst")?,
            port,
            state,
            subscriber: opt_parse::<IpAddr>(p, "subscriber")?,
            public: opt_parse::<IpAddr>(p, "public")?,
            via,
            nat,
            id: opt_u32(p, "id")?,
        })
    }

    fn empty(&self) -> bool {
        self.protocol.is_none()
            && self.src.is_none()
            && self.dst.is_none()
            && self.port.is_none()
            && self.state.is_none()
            && self.subscriber.is_none()
            && self.public.is_none()
            && self.via.is_none()
            && self.nat.is_none()
            && self.id.is_none()
    }

    fn keeps(&self, c: &Conn) -> bool {
        self.id.is_none_or(|id| c.id == id)
            && self.protocol.is_none_or(|n| c.protocol == n)
            && self.src.is_none_or(|n| n.contains(&c.orig.src))
            && self.dst.is_none_or(|n| n.contains(&c.orig.dst))
            && self
                .port
                .is_none_or(|n| !matches!(c.protocol, 1 | 58) && (c.orig.src_port == n || c.orig.dst_port == n))
            && self.state.as_deref().is_none_or(|s| c.state() == s)
            && self.subscriber.is_none_or(|a| c.orig.src == a)
            && self.public.is_none_or(|a| c.has(status::SRC_NAT) && c.reply.dst == a)
            && self.via.is_none_or(|v| c.via() == v)
            && self.nat.is_none_or(|bit| c.has(bit))
    }
}

fn addr_port(a: IpAddr, port: u16, proto: u8) -> String {
    let ports = matches!(proto, 6 | 17 | 132 | 33 | 136);
    match (a, ports) {
        (IpAddr::V6(v6), true) => format!("[{v6}]:{port}"),
        (a, true) => format!("{a}:{port}"),
        (a, false) => a.to_string(),
    }
}

/// The public address and port (or ICMP query id) a srcnat chose: the
/// reply's destination.
fn public_port(c: &Conn) -> u16 {
    if matches!(c.protocol, 1 | 58) {
        c.reply.src_port
    } else {
        c.reply.dst_port
    }
}

fn nat_text(c: &Conn) -> String {
    if matches!(c.protocol, 1 | 58) {
        format!("{} id {}", c.reply.dst, c.reply.src_port)
    } else {
        addr_port(c.reply.dst, c.reply.dst_port, c.protocol)
    }
}

/// RouterOS-like flags of a connection.
fn flags(c: &Conn) -> String {
    let mut f = String::new();
    for (bit, ch) in [
        (status::SEEN_REPLY, 'S'),
        (status::ASSURED, 'A'),
        (status::CONFIRMED, 'C'),
        (status::SRC_NAT, 's'),
        (status::DST_NAT, 'd'),
        (status::OFFLOAD, 'F'),
        (status::HW_OFFLOAD, 'H'),
    ] {
        if c.has(bit) {
            f.push(ch);
        }
    }
    f
}

fn table_json(s: &Stats) -> Value {
    let percent = s.count.saturating_mul(100).checked_div(s.max).unwrap_or(0);
    json!({
        "count": s.count, "max": s.max, "percent": percent,
        "insert_failed": s.insert_failed, "drop": s.drop, "early_drop": s.early_drop,
    })
}

fn row(c: &Conn, pools: &[(String, Vec<corerouter_model::cgnat::Range>)]) -> Value {
    let mut v = json!({
        "id": c.id,
        "protocol": protocol_name(c.protocol),
        "src": if matches!(c.protocol, 1 | 58) { format!("{} id {}", c.orig.src, c.orig.src_port) } else { addr_port(c.orig.src, c.orig.src_port, c.protocol) },
        "dst": addr_port(c.orig.dst, c.orig.dst_port, c.protocol),
        "reply_src": addr_port(c.reply.src, c.reply.src_port, c.protocol),
        "reply_dst": addr_port(c.reply.dst, c.reply.dst_port, c.protocol),
        "state": c.state(),
        "flags": flags(c),
        "timeout": c.timeout,
        "via": c.via().as_str(),
        "orig_packets": c.orig_packets,
        "orig_bytes": c.orig_bytes,
        "repl_packets": c.reply_packets,
        "repl_bytes": c.reply_bytes,
    });
    if let Some(o) = v.as_object_mut() {
        if c.has(status::SRC_NAT) {
            o.insert("nat".into(), json!(nat_text(c)));
        }
        if let IpAddr::V4(a) = c.orig.src
            && let Some((name, _)) = pools.iter().find(|(_, r)| r.iter().any(|r| r.contains(a)))
        {
            o.insert("pool".into(), json!(name));
        }
    }
    v
}

fn pools(s: &Session) -> Vec<(String, Vec<corerouter_model::cgnat::Range>)> {
    s.store()
        .running()
        .ip
        .cgnat
        .pools
        .iter()
        .filter(|p| !p.disabled)
        .map(|p| (p.name.clone(), p.inside.clone()))
        .collect()
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let f = Filter::of(p)?;
    let offset = opt_u32(p, "offset")?.unwrap_or(0) as usize;
    let count = match opt_u32(p, "count")? {
        Some(n) if !(1..=MAX_PAGE).contains(&n) => {
            return Err(EngineError::bad("count", format!("1..={MAX_PAGE}")));
        }
        n => n.unwrap_or(200) as usize,
    };
    let sort = opt_str(p, "sort")?.map(str::to_owned);
    if let Some(k) = &sort
        && !matches!(k.as_str(), "timeout" | "bytes" | "packets")
    {
        return Err(EngineError::bad("sort", "timeout, bytes or packets"));
    }
    let (conns, stats) = s.connections(false)?;
    let mut hits: Vec<&Conn> = conns.iter().filter(|c| f.keeps(c)).collect();
    match sort.as_deref() {
        Some("timeout") => hits.sort_by_key(|c| std::cmp::Reverse(c.timeout)),
        Some("bytes") => hits.sort_by_key(|c| std::cmp::Reverse(c.orig_bytes.saturating_add(c.reply_bytes))),
        Some("packets") => hits.sort_by_key(|c| std::cmp::Reverse(c.orig_packets.saturating_add(c.reply_packets))),
        _ => {}
    }
    let pools = pools(s);
    let rows: Vec<Value> = hits.iter().skip(offset).take(count).map(|c| row(c, &pools)).collect();
    Ok(json!({"total": hits.len(), "offset": offset, "rows": rows, "table": table_json(&stats)}))
}

fn top(s: &mut Session, p: &Value) -> Result<Value> {
    let count = match opt_u32(p, "count")? {
        Some(n) if !(1..=100).contains(&n) => return Err(EngineError::bad("count", "1..=100")),
        n => n.unwrap_or(10) as usize,
    };
    let f = Filter {
        protocol: match opt_str(p, "protocol")? {
            None => None,
            Some(t) => Some(protocol_number(t).ok_or_else(|| EngineError::bad("protocol", "tcp, udp, icmp or a number"))?),
        },
        ..Filter::default()
    };
    let (conns, _) = s.connections(false)?;
    #[derive(Default)]
    struct Tally {
        n: u64,
        tcp: u64,
        udp: u64,
        icmp: u64,
        other: u64,
        ports: std::collections::HashSet<(u8, u16)>,
    }
    let mut by: HashMap<IpAddr, Tally> = HashMap::new();
    for c in conns.iter().filter(|c| f.keeps(c)) {
        let t = by.entry(c.orig.src).or_default();
        t.n += 1;
        match c.protocol {
            6 => t.tcp += 1,
            17 => t.udp += 1,
            1 | 58 => t.icmp += 1,
            _ => t.other += 1,
        }
        if c.has(status::SRC_NAT) {
            t.ports.insert((c.protocol, public_port(c)));
        }
    }
    let mut ranked: Vec<(IpAddr, Tally)> = by.into_iter().collect();
    ranked.sort_by(|a, b| b.1.n.cmp(&a.1.n).then(a.0.cmp(&b.0)));
    let cgnat = s.store().running().ip.cgnat.clone();
    let rows: Vec<Value> = ranked
        .into_iter()
        .take(count)
        .map(|(sub, t)| {
            let mut v = json!({
                "subscriber": sub, "connections": t.n, "tcp": t.tcp, "udp": t.udp,
                "icmp": t.icmp, "other": t.other,
            });
            if let (IpAddr::V4(a), Some(o)) = (sub, v.as_object_mut())
                && let Some(pool) = cgnat.pool_of(a)
            {
                o.insert("pool".into(), json!(pool.name));
                // Ports in use: per protocol (TCP and UDP ports are apart),
                // the busiest protocol is what runs out first.
                let used = [6u8, 17, 1]
                    .iter()
                    .map(|pr| t.ports.iter().filter(|(p, _)| p == pr).count())
                    .max()
                    .unwrap_or(0);
                let ports = u64::from(pool.ports_per_subscriber);
                o.insert("ports_used".into(), json!(used));
                o.insert("ports".into(), json!(ports));
                o.insert("percent".into(), json!((used as u64).saturating_mul(100) / ports.max(1)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn kill(s: &mut Session, p: &Value) -> Result<Value> {
    let f = Filter::of(p)?;
    let all = super::args::opt_bool(p, "all")?.unwrap_or(false);
    if f.empty() && !all {
        return Err(EngineError::bad("all", "no filter given: pass all=true to kill every connection"));
    }
    let (conns, _) = s.connections(true)?;
    let victims: Vec<Conn> = conns.iter().filter(|c| f.keeps(c)).cloned().collect();
    let killed = s
        .hal_mut()
        .connections_kill(&victims)
        .map_err(|e| EngineError::Hal(e.to_string()))?;
    // The next list reads the table again.
    if let Some(c) = s.ext_mut::<ConnCache>() {
        c.at = None;
    }
    Ok(json!({"matched": victims.len(), "killed": killed}))
}

/// The Tuning rows of the conntrack parameters (`system.tuning.parameter.print`).
fn tuning_rows(s: &mut Session) -> Result<Vec<Value>> {
    let spec = super::find("system.tuning.parameter.print")
        .ok_or_else(|| EngineError::bad("name", "no tuning"))?;
    let v = (spec.run)(s, &json!({"tab": "kernel"}))?;
    Ok(v.get("params").and_then(Value::as_array).cloned().unwrap_or_default())
}

fn tracking_info(s: &mut Session, _: &Value) -> Result<Value> {
    let rows = tuning_rows(s)?;
    let current = |name: &str| {
        rows.iter()
            .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|r| r.get("current").cloned())
            .unwrap_or(Value::Null)
    };
    let mut out = serde_json::Map::new();
    for (key, sysctl) in TIMEOUTS {
        out.insert((*key).into(), current(sysctl));
    }
    out.insert("max_entries".into(), current(MAX_ENTRIES));
    let stats = s.hal_mut().connection_stats().ok();
    out.insert("total_entries".into(), json!(stats.map(|s| s.count)));
    out.insert("loaded".into(), json!(!current(MAX_ENTRIES).is_null()));
    Ok(Value::Object(out))
}

fn tracking_set(s: &mut Session, p: &Value) -> Result<Value> {
    let set = super::find("system.tuning.set").ok_or_else(|| EngineError::bad("name", "no tuning"))?;
    let mut changed = Vec::new();
    let mut todo: Vec<(&str, &str, i64)> = Vec::new();
    for (key, sysctl) in TIMEOUTS {
        if let Some(t) = super::dhcp_server::opt_secs(p, key)? {
            todo.push((key, sysctl, i64::from(t)));
        }
    }
    if let Some(n) = opt_u32(p, "max_entries")? {
        todo.push(("max_entries", MAX_ENTRIES, i64::from(n)));
    }
    for (key, sysctl, value) in todo {
        (set.run)(s, &json!({"name": sysctl, "value": value})).map_err(|e| match e {
            EngineError::BadParam { reason, .. } => EngineError::bad(key, reason),
            other => other,
        })?;
        changed.push(json!({"name": key, "value": value}));
    }
    Ok(json!({"changed": changed}))
}

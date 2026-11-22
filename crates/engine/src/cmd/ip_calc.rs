//! Tools › IP Calculator (G6.9): subnets, IPv6 prefix delegation and the
//! CGNAT planner, as queries (pure arithmetic, no change). The planner uses
//! the CGNAT's own formula (`corerouter_model::cgnat::Layout`) and checks
//! (`proto-cgnat`), so what it promises is what a pool will do.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::Config;
use corerouter_model::cgnat::{self as cg, Mode, Pool, Range};
use corerouter_model::firewall::PortRange;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, opt_u32, req_str};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Subnets listed at most by `split` (the count is always given).
pub const MAX_LIST: u64 = 4096;
/// Mapping rows previewed at most.
pub const MAX_PREVIEW: u32 = 1000;
/// Rows an export holds at most (a /14 of subscribers).
pub const MAX_EXPORT: u64 = 262_144;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.ip-calc.subnet", "Subnet Calculator", ["Tools"], None,
        "{address: string (10.1.2.3/24, 10.1.2.3 255.255.255.0, 2001:db8::1/64)} → {family, address, network, broadcast?, first, last, hosts, prefix, mask?, wildcard?, scope (private, shared (RFC 6598), loopback, link-local, documentation, global…), overlaps: [{what, item}] (configured addresses, routes, pools, CGNAT ranges that overlap)}",
        always, subnet),
    cmd!(query "tool.ip-calc.split", "Split Network", [], None,
        "{network: string, prefix?: u8 (the new length) , count?: u32 (at least this many subnets)} → {prefix, total, subnets: [string] (at most 4096)}",
        always, split),
    cmd!(query "tool.ip-calc.summarize", "Summarize", [], None,
        "{prefixes: [string] | string} → {aggregated: [string] (the same addresses, fewest prefixes), supernet (the smallest single prefix covering all), extra (addresses the supernet adds)}",
        always, summarize),
    cmd!(query "tool.ip-calc.range", "Range to Prefixes", [], None,
        "{first: string, last: string} → {prefixes: [string], addresses}",
        always, range_cmd),
    cmd!(query "tool.ip-calc.pd", "Prefix Delegation Planner", [], None,
        "{prefix: string (2001:db8::/40), length: u8 (delegated size: 48, 56, 60, 64), show?: u32 (1..1000; default 16)} → {prefix, length, count (delegations, as text: can exceed 2^64), customers_per (/64s each delegation holds), first: [string], last, pools: [{name, prefix, prefix_length, inside (whether it lies in this prefix)}] (the configured DHCPv6-PD pools)}",
        always, pd),
    cmd!(query "tool.ip-calc.cgnat.plan", "CGNAT Planner", ["Tools"], None,
        "{inside: [string] | string (subscriber ranges, or a count like \"4096\"), outside: [string] | string (public ranges, or a count), ports_per_subscriber?: u16 (default 1000), port_range?: string (default 1024-65535), mode?: deterministic | blocks, preview?: u32 (0..1000; default 20)} → {subscribers, public, per_address, capacity, public_needed, public_spare, ports_left_per_address, ports_if_spread, fits, warnings: [{level, text, suggestion?}], preview: [{subscriber, public, first_port, last_port}], pool? (the params of ip.firewall.cgnat.pool.add)}",
        always, cgnat),
    cmd!(query "tool.ip-calc.cgnat.export", "Export CGNAT Plan", [], None,
        "{inside: [string] | string, outside: [string] | string, ports_per_subscriber?: u16, port_range?: string, format: csv | text | routeros | nft, name?: string (pool name in scripts; default cgnat1)} → {format, rows, text}",
        always, export),
];

fn bad(key: &str, why: impl Into<String>) -> EngineError {
    EngineError::bad(key, why.into())
}

/// `a.b.c.d/n`, `a.b.c.d m.m.m.m`, or a bare address (a host prefix).
fn parse_net(text: &str, key: &str) -> Result<(IpAddr, IpNet)> {
    let t = text.trim();
    if t.len() > 64 {
        return Err(bad(key, "at most 64 characters"));
    }
    if let Some((a, m)) = t.split_once(char::is_whitespace) {
        let a: Ipv4Addr = a.trim().parse().map_err(|_| bad(key, "an address and a mask: 10.1.2.3 255.255.255.0"))?;
        let m: Ipv4Addr = m.trim().parse().map_err(|_| bad(key, "an address and a mask: 10.1.2.3 255.255.255.0"))?;
        let bits = u32::from(m);
        if bits.leading_ones() + bits.trailing_zeros() != 32 {
            return Err(bad(key, "the mask is not contiguous"));
        }
        let len = u8::try_from(bits.leading_ones()).unwrap_or(32);
        let net = Ipv4Net::new(a, len).map_err(|e| bad(key, e.to_string()))?;
        return Ok((IpAddr::V4(a), IpNet::V4(net)));
    }
    if t.contains('/') {
        let net: IpNet = t.parse().map_err(|_| bad(key, "a prefix: 10.1.2.3/24 or 2001:db8::/48"))?;
        return Ok((net.addr(), net));
    }
    let a: IpAddr = t.parse().map_err(|_| bad(key, "an address, a prefix or an address and a mask"))?;
    let net = IpNet::from(a);
    Ok((a, net))
}

fn scope(a: IpAddr) -> &'static str {
    match a {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback() {
                "loopback"
            } else if v.is_private() {
                "private (RFC 1918)"
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                "shared (RFC 6598, CGNAT)"
            } else if v.is_link_local() {
                "link-local"
            } else if v.is_documentation() {
                "documentation (RFC 5737)"
            } else if v.is_multicast() {
                "multicast"
            } else if v.is_unspecified() || v.is_broadcast() {
                "special"
            } else {
                "global"
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() {
                "loopback"
            } else if s[0] & 0xfe00 == 0xfc00 {
                "unique local (RFC 4193)"
            } else if s[0] & 0xffc0 == 0xfe80 {
                "link-local"
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                "documentation (RFC 3849)"
            } else if v.is_multicast() {
                "multicast"
            } else {
                "global"
            }
        }
    }
}

fn overlaps(cfg: &Config, net: &IpNet) -> Vec<Value> {
    let mut out = Vec::new();
    let hit = |other: &IpNet| net.contains(other) || other.contains(net);
    for a in cfg.ip.addresses.iter() {
        if hit(&a.address.trunc()) {
            out.push(json!({"what": "address", "item": format!("{} on {}", a.address, a.interface)}));
        }
    }
    for r in cfg.ip.routes.iter() {
        if let Ok(dst) = r.dst_address.to_string().parse::<IpNet>()
            && dst.prefix_len() > 0
            && hit(&dst)
        {
            out.push(json!({"what": "route", "item": r.dst_address.to_string()}));
        }
    }
    if let IpNet::V4(v4) = net {
        let (lo, hi) = (u32::from(v4.network()), u32::from(v4.broadcast()));
        let mine = Range::new(Ipv4Addr::from(lo), Ipv4Addr::from(hi));
        for p in &cfg.ip.pools.pools {
            for r in &p.ranges {
                if mine.is_some_and(|m| m.overlaps(&Range { start: r.start, end: r.end })) {
                    out.push(json!({"what": "ip pool", "item": format!("{} {r}", p.name)}));
                }
            }
        }
        for p in &cfg.ip.cgnat.pools {
            for (side, rs) in [("CGNAT inside", &p.inside), ("CGNAT outside", &p.outside)] {
                for r in rs {
                    if mine.is_some_and(|m| m.overlaps(r)) {
                        out.push(json!({"what": side, "item": format!("{} {r}", p.name)}));
                    }
                }
            }
        }
    }
    out.truncate(64);
    out
}

fn subnet(s: &mut Session, p: &Value) -> Result<Value> {
    let (addr, net) = parse_net(req_str(p, "address")?, "address")?;
    let net_t = net.trunc();
    let cfg = s.store().running();
    let mut v = json!({
        "address": addr,
        "network": net_t.to_string(),
        "prefix": net.prefix_len(),
        "scope": scope(addr),
        "overlaps": overlaps(cfg, &net_t),
    });
    let o = v.as_object_mut().ok_or_else(|| bad("address", "internal"))?;
    match net_t {
        IpNet::V4(n) => {
            let len = u32::from(n.prefix_len());
            let size: u64 = 1u64 << (32 - len);
            let (first, last, hosts) = match len {
                32 => (n.network(), n.network(), 1),
                31 => (n.network(), n.broadcast(), 2),
                _ => (
                    Ipv4Addr::from(u32::from(n.network()) + 1),
                    Ipv4Addr::from(u32::from(n.broadcast()) - 1),
                    size - 2,
                ),
            };
            o.insert("family".into(), json!("ipv4"));
            o.insert("broadcast".into(), json!(n.broadcast()));
            o.insert("first".into(), json!(first));
            o.insert("last".into(), json!(last));
            o.insert("hosts".into(), json!(hosts));
            o.insert("addresses".into(), json!(size));
            o.insert("mask".into(), json!(n.netmask()));
            o.insert("wildcard".into(), json!(n.hostmask()));
        }
        IpNet::V6(n) => {
            let len = u32::from(n.prefix_len());
            o.insert("family".into(), json!("ipv6"));
            o.insert("first".into(), json!(n.network()));
            o.insert("last".into(), json!(n.broadcast()));
            o.insert("hosts".into(), json!(pow2_text(128 - len)));
            o.insert("addresses".into(), json!(pow2_text(128 - len)));
        }
    }
    Ok(v)
}

/// 2^n as decimal text (up to 2^128).
fn pow2_text(n: u32) -> String {
    match n {
        0..=127 => (1u128 << n).to_string(),
        _ => "340282366920938463463374607431768211456".into(),
    }
}

fn split(_s: &mut Session, p: &Value) -> Result<Value> {
    let (_, net) = parse_net(req_str(p, "network")?, "network")?;
    let net = net.trunc();
    let max = net.max_prefix_len();
    let new = match (opt_u32(p, "prefix")?, opt_u32(p, "count")?) {
        (Some(n), _) => u8::try_from(n).map_err(|_| bad("prefix", "0..128"))?,
        (None, Some(c)) if c >= 1 => {
            let bits = u32::BITS - (c - 1).leading_zeros();
            net.prefix_len().saturating_add(u8::try_from(bits).unwrap_or(0))
        }
        _ => return Err(bad("prefix", "give prefix (the new length) or count")),
    };
    if new < net.prefix_len() || new > max {
        return Err(bad("prefix", format!("{}..={max}", net.prefix_len())));
    }
    let diff = u32::from(new - net.prefix_len());
    let total = if diff >= 64 { u64::MAX } else { 1u64 << diff };
    let subnets: Vec<String> = net
        .subnets(new)
        .map_err(|e| bad("prefix", e.to_string()))?
        .take(usize::try_from(MAX_LIST).unwrap_or(4096))
        .map(|n| n.to_string())
        .collect();
    Ok(json!({"prefix": new, "total": if diff >= 64 { pow2_text(diff) } else { total.to_string() }, "subnets": subnets}))
}

fn summarize(_s: &mut Session, p: &Value) -> Result<Value> {
    let items = opt_list(p, "prefixes")?.ok_or_else(|| bad("prefixes", "is required"))?;
    if items.is_empty() {
        return Err(bad("prefixes", "at least one"));
    }
    let nets: Vec<IpNet> = items
        .iter()
        .map(|t| parse_net(t, "prefixes").map(|(_, n)| n.trunc()))
        .collect::<Result<_>>()?;
    let v4 = nets.iter().all(|n| matches!(n, IpNet::V4(_)));
    let v6 = nets.iter().all(|n| matches!(n, IpNet::V6(_)));
    if !v4 && !v6 {
        return Err(bad("prefixes", "IPv4 and IPv6 cannot be summarized together"));
    }
    let aggregated: Vec<String> = IpNet::aggregate(&nets).iter().map(ToString::to_string).collect();
    // The smallest single prefix holding them all: shorten the first
    // until it contains every other.
    let mut sup = nets.first().copied().ok_or_else(|| bad("prefixes", "at least one"))?;
    while !nets.iter().all(|n| sup.contains(n)) {
        let Some(parent) = sup.supernet() else { break };
        sup = parent;
    }
    let held: u128 = IpNet::aggregate(&nets)
        .iter()
        .map(|n| 1u128 << (u32::from(n.max_prefix_len() - n.prefix_len())).min(127))
        .sum();
    let sup_size = 1u128 << (u32::from(sup.max_prefix_len() - sup.prefix_len())).min(127);
    Ok(json!({"aggregated": aggregated, "supernet": sup.to_string(), "extra": sup_size.saturating_sub(held).to_string()}))
}

fn range_cmd(_s: &mut Session, p: &Value) -> Result<Value> {
    let first: IpAddr = opt_parse(p, "first")?.ok_or_else(|| bad("first", "is required"))?;
    let last: IpAddr = opt_parse(p, "last")?.ok_or_else(|| bad("last", "is required"))?;
    let (a, b, bits): (u128, u128, u32) = match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u128::from(u32::from(a)), u128::from(u32::from(b)), 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return Err(bad("last", "both IPv4 or both IPv6")),
    };
    if a > b {
        return Err(bad("last", "comes before first"));
    }
    let mut out = Vec::new();
    let mut at = a;
    while at <= b && out.len() < 256 {
        let mut size_bits = if at == 0 { bits } else { at.trailing_zeros().min(bits) };
        while size_bits > 0 && at + ((1u128 << size_bits) - 1) > b {
            size_bits -= 1;
        }
        let len = u8::try_from(bits - size_bits).unwrap_or(0);
        let net = if bits == 32 {
            IpNet::V4(Ipv4Net::new(Ipv4Addr::from(u32::try_from(at).unwrap_or(0)), len).map_err(|e| bad("first", e.to_string()))?)
        } else {
            IpNet::V6(Ipv6Net::new(Ipv6Addr::from(at), len).map_err(|e| bad("first", e.to_string()))?)
        };
        out.push(net.to_string());
        let Some(next) = at.checked_add(1u128 << size_bits) else { break };
        at = next;
    }
    Ok(json!({"prefixes": out, "addresses": (b - a + 1).to_string()}))
}

fn pd(s: &mut Session, p: &Value) -> Result<Value> {
    let (_, net) = parse_net(req_str(p, "prefix")?, "prefix")?;
    let IpNet::V6(net) = net.trunc() else {
        return Err(bad("prefix", "an IPv6 prefix (2001:db8::/40)"));
    };
    let len = opt_u32(p, "length")?.ok_or_else(|| bad("length", "is required"))?;
    let len = u8::try_from(len).map_err(|_| bad("length", "0..128"))?;
    if len < net.prefix_len() || len > 128 {
        return Err(bad("length", format!("{}..=128", net.prefix_len())));
    }
    let show = match opt_u32(p, "show")? {
        Some(n) if !(1..=1000).contains(&n) => return Err(bad("show", "1..=1000")),
        n => n.unwrap_or(16) as usize,
    };
    let diff = u32::from(len - net.prefix_len());
    let first: Vec<String> = net.subnets(len).map_err(|e| bad("length", e.to_string()))?.take(show).map(|n| n.to_string()).collect();
    // The last delegation: the prefix's last address, at `len`.
    let last = Ipv6Net::new(net.broadcast(), len).map(|n| n.trunc().to_string()).unwrap_or_default();
    let per64 = if len <= 64 { pow2_text(u32::from(64 - len)) } else { "0".into() };
    let pools: Vec<Value> = s
        .store()
        .running()
        .ipv6
        .dhcp_server
        .pools
        .iter()
        .map(|x| {
            json!({"name": x.name, "prefix": x.prefix.to_string(), "prefix_length": x.prefix_length, "inside": net.contains(&x.prefix)})
        })
        .collect();
    Ok(json!({
        "prefix": net.to_string(), "length": len, "count": pow2_text(diff), "customers_per": per64,
        "first": first, "last": last, "pools": pools,
    }))
}

/// Ranges, or a count (`"4096"`) of addresses from `base`.
fn side(p: &Value, key: &str, base: Ipv4Addr) -> Result<Vec<Range>> {
    let items = opt_list(p, key)?.ok_or_else(|| bad(key, "is required"))?;
    if let [one] = items.as_slice()
        && let Ok(n) = one.trim().parse::<u64>()
    {
        if n == 0 || n > cg::MAX_SUBSCRIBERS {
            return Err(bad(key, format!("1..={}", cg::MAX_SUBSCRIBERS)));
        }
        let end = u64::from(u32::from(base)) + n - 1;
        let end = u32::try_from(end).map_err(|_| bad(key, "too many"))?;
        return Ok(vec![Range { start: base, end: Ipv4Addr::from(end) }]);
    }
    if items.is_empty() || items.len() > cg::MAX_RANGES {
        return Err(bad(key, format!("1..={} ranges", cg::MAX_RANGES)));
    }
    items.iter().map(|t| t.parse::<Range>().map_err(|e| bad(key, e.to_string()))).collect()
}

fn draft(p: &Value) -> Result<Pool> {
    let inside = side(p, "inside", Ipv4Addr::new(100, 64, 0, 0))?;
    let outside = side(p, "outside", Ipv4Addr::new(203, 0, 113, 0))?;
    let ports = match opt_u32(p, "ports_per_subscriber")? {
        Some(n) => u16::try_from(n).map_err(|_| bad("ports_per_subscriber", "1..65535"))?,
        None => 1000,
    };
    let port_range = opt_parse::<PortRange>(p, "port_range")?.unwrap_or(PortRange { first: cg::FIRST_DYNAMIC, last: u16::MAX });
    let mode = opt_parse::<Mode>(p, "mode")?.unwrap_or_default();
    let name = opt_str(p, "name")?.map_or_else(|| "cgnat1".to_owned(), str::to_owned);
    let mut pool: Pool = serde_json::from_value(json!({"id": "*1", "name": name, "inside": [], "outside": []}))
        .map_err(|e| bad("inside", e.to_string()))?;
    pool.inside = inside;
    pool.outside = outside;
    pool.ports_per_subscriber = ports;
    pool.port_range = port_range;
    pool.mode = mode;
    Ok(pool)
}

fn cgnat(_s: &mut Session, p: &Value) -> Result<Value> {
    let pool = draft(p)?;
    let preview = match opt_u32(p, "preview")? {
        Some(n) if n > MAX_PREVIEW => return Err(bad("preview", format!("0..={MAX_PREVIEW}"))),
        n => n.unwrap_or(20),
    };
    let (subs, public) = (pool.subscribers(), pool.public_addresses());
    let plan = cg::plan(subs, public, pool.ports_per_subscriber, pool.port_range);
    let fits = plan.capacity >= subs || pool.mode == Mode::Blocks;
    let mut warnings: Vec<Value> = Vec::new();
    // The pool's own checks, as a commit would see them.
    let mut cfg = Config::default();
    cfg.ip.cgnat.pools.push(pool.clone());
    for c in corerouter_proto_cgnat::checks::checks(&cfg) {
        if c.level != corerouter_proto_cgnat::checks::Level::Ok {
            warnings.push(json!({"level": c.level, "text": c.text}));
        }
    }
    // What would make it fit, or waste less.
    if plan.capacity < subs && plan.per_address > 0 {
        let fit = u16::try_from(plan.ports_if_spread.min(u32::from(u16::MAX))).unwrap_or(0);
        warnings.push(json!({
            "level": "warn",
            "text": format!("{} public addresses are needed for {} ports each; you have {public}", plan.public_needed, pool.ports_per_subscriber),
            "suggestion": format!("add {} public addresses, or use {fit} ports per subscriber", plan.public_needed.saturating_sub(public)),
        }));
    }
    if plan.ports_left_per_address > 0 && plan.per_address > 0 {
        let even = plan.port_range / plan.per_address;
        warnings.push(json!({
            "level": "ok",
            "text": format!("{} ports of each public address are left unused", plan.ports_left_per_address),
            "suggestion": format!("{even} ports per subscriber use the whole range with the same {} per address", plan.per_address),
        }));
    }
    let spare = public.saturating_sub(plan.public_needed);
    if spare > 0 && plan.capacity >= subs {
        let more = u32::try_from(u64::from(plan.port_range) / subs.div_ceil(public).max(1)).unwrap_or(0);
        warnings.push(json!({
            "level": "ok",
            "text": format!("{spare} public addresses are spare"),
            "suggestion": format!("or give each subscriber up to {more} ports"),
        }));
    }
    let rows: Vec<Value> = match pool.layout() {
        Ok(l) => l
            .entries()
            .take(preview as usize)
            .map(|(sub, slot)| json!({"subscriber": sub, "public": slot.public, "first_port": slot.first_port, "last_port": slot.last_port}))
            .collect(),
        Err(_) => Vec::new(),
    };
    let mut v = json!({
        "subscribers": subs, "public": public, "per_address": plan.per_address, "capacity": plan.capacity,
        "public_needed": plan.public_needed, "public_spare": spare, "ports_left_per_address": plan.ports_left_per_address,
        "ports_if_spread": plan.ports_if_spread, "fits": fits, "warnings": warnings, "preview": rows,
    });
    if fits && let Some(o) = v.as_object_mut() {
        o.insert(
            "pool".into(),
            json!({
                "name": pool.name, "mode": pool.mode.as_str(),
                "inside": pool.inside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "outside": pool.outside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ports_per_subscriber": pool.ports_per_subscriber, "port_range": pool.port_range.to_string(),
            }),
        );
    }
    Ok(v)
}

fn export(_s: &mut Session, p: &Value) -> Result<Value> {
    let pool = draft(p)?;
    let format = req_str(p, "format")?.to_owned();
    let layout = pool.layout().map_err(|e| bad("outside", e.to_string()))?;
    if layout.subscribers() > MAX_EXPORT {
        return Err(bad("inside", format!("at most {MAX_EXPORT} subscribers in one export")));
    }
    let rows = layout.subscribers();
    let text = match format.as_str() {
        "csv" => {
            let mut t = String::from("subscriber,public,first_port,last_port\r\n");
            for (sub, s) in layout.entries() {
                t.push_str(&format!("{sub},{},{},{}\r\n", s.public, s.first_port, s.last_port));
            }
            t
        }
        "text" => {
            let mut t = format!(
                "CGNAT pool {} (deterministic, RFC 7422)\nsubscribers {} in {}\npublic {} in {}\n{} ports each, range {}, {} per public address\n\n{:<16} {:<16} {}\n",
                pool.name,
                layout.subscribers(),
                pool.inside.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                layout.public_addresses(),
                pool.outside.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                pool.ports_per_subscriber,
                pool.port_range,
                layout.per_address(),
                "SUBSCRIBER",
                "PUBLIC",
                "PORTS"
            );
            for (sub, s) in layout.entries() {
                t.push_str(&format!("{:<16} {:<16} {}-{}\n", sub.to_string(), s.public.to_string(), s.first_port, s.last_port));
            }
            t
        }
        "routeros" => {
            // RouterOS has no formula: one src-nat per subscriber and
            // protocol (its own CGNAT recipe), ICMP and the rest with the
            // address only.
            let mut t = format!(
                "# CGNAT {} — deterministic (RFC 7422), generated by CoreRouter\n/ip firewall nat\n",
                pool.name
            );
            for (sub, s) in layout.entries() {
                for proto in ["tcp", "udp"] {
                    t.push_str(&format!(
                        "add chain=srcnat action=src-nat protocol={proto} src-address={sub} to-addresses={} to-ports={}-{} comment=\"{}\"\n",
                        s.public, s.first_port, s.last_port, pool.name
                    ));
                }
                t.push_str(&format!(
                    "add chain=srcnat action=src-nat src-address={sub} to-addresses={} comment=\"{}\"\n",
                    s.public, pool.name
                ));
            }
            t
        }
        "nft" => {
            let mut c = corerouter_model::cgnat::Cgnat::default();
            c.pools.push(pool.clone());
            corerouter_firewall::cgnat::render(&c, None).script
        }
        _ => return Err(bad("format", "csv, text, routeros or nft")),
    };
    Ok(json!({"format": format, "rows": rows, "text": text}))
}

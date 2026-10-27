//! /ip firewall cgnat capacity (G2.7b): how full the pools really get,
//! and the `ports_per_subscriber` that fits. The numbers come from the
//! capacity store (`crate::cgnat_capacity`), filled by the usage scan
//! outside the session lock; applying a suggestion is
//! `ip.firewall.cgnat.pool.set` (under Safe Mode, from the window).

use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::conntrack::status;
use corerouter_model::cgnat::{LayoutError, Mode, Pool};
use serde_json::{Value, json};

use super::args::{req_str, req_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Peak bands, in % of a subscriber's ports: (label, from, to).
pub const BANDS: [(&str, u64, u64); 6] = [
    ("0-25", 0, 25),
    ("25-50", 25, 50),
    ("50-75", 50, 75),
    ("75-90", 75, 90),
    ("90-100", 90, 100),
    ("100", 100, u64::MAX),
];
/// Room left above the p99 peak in a suggestion.
pub const HEADROOM_PERCENT: u64 = 125;
/// Suggestions are multiples of this (whole blocks of a power of two).
pub const STEP: u64 = 64;
/// Never suggested below this (`proto-cgnat` warns under 300 ports).
pub const MIN_PORTS: u64 = 320;
/// More than this share (‰) of the seen subscribers refused in 24 h asks
/// for more ports whatever the p99.
pub const REFUSED_PER_MILLE: u64 = 10;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.firewall.cgnat.capacity.get", "CGNAT Capacity", [], None,
        "{pool: string (name or *id)} → {pool, mode, ports (each subscriber's limit: ports_per_subscriber, × max_blocks in blocks mode), ports_per_subscriber, subscribers, seen (subscribers with readings in 7 days), days, per_address, public_addresses, p99 (ports at the 99th percentile of the 7-day peaks), p99_percent, max, hit_24h (subscribers refused for lack of a port in 24 h), refused_24h, icmp_24h, bands: [{band, count}], suggestion?: {ports_per_subscriber, per_address, gain_per_address (subscribers per public address, + more), public_needed, fits, reason}}",
        always, capacity),
    cmd!(query "ip.firewall.cgnat.capacity.preview", "Preview CGNAT Capacity Change", [], None,
        "{pool: string, ports_per_subscriber: u16} → {remapped (subscribers whose address or ports change), connections (live connections that would be killed), per_address, per_address_now, fits, error?, command: {command, params}} (nothing changes)",
        always, preview),
];

fn pool_of(s: &Session, key: &str) -> Result<Pool> {
    let c = &s.store().running().ip.cgnat;
    c.pools
        .iter()
        .find(|p| p.name == key || format!("*{:x}", p.id.0) == key)
        .cloned()
        .ok_or_else(|| EngineError::bad("pool", format!("no CGNAT pool '{key}'")))
}

/// The ports one subscriber of `p` may use at most.
fn limit(p: &Pool) -> u64 {
    let blocks = if p.mode == Mode::Blocks { u64::from(p.max_blocks.max(1)) } else { 1 };
    u64::from(p.ports_per_subscriber) * blocks
}

/// The value at the `pct`th percentile of sorted `v` (nearest rank).
pub fn percentile(v: &[u16], pct: u64) -> u16 {
    if v.is_empty() {
        return 0;
    }
    let rank = (v.len() as u64 * pct).div_ceil(100).max(1);
    v.get(usize::try_from(rank - 1).unwrap_or(0)).copied().unwrap_or(0)
}

/// What `ports_per_subscriber` the numbers ask for, and why.
pub fn suggest(now_ports: u64, p99: u64, seen: u64, hit: u64, range: u64) -> (u64, &'static str) {
    let round = |n: u64| n.div_ceil(STEP) * STEP;
    let mut want = round(p99 * HEADROOM_PERCENT / 100).max(MIN_PORTS);
    let mut why = "p99 of the 7-day peaks plus 25 %";
    if seen > 0 && hit * 1000 > seen * REFUSED_PER_MILLE {
        let more = round(now_ports * 3 / 2);
        if more > want {
            want = more;
            why = "more than 1 % of the subscribers ran out of ports in 24 h";
        }
    }
    (want.min(range).max(1), why)
}

fn capacity(s: &mut Session, p: &Value) -> Result<Value> {
    let pool = pool_of(s, req_str(p, "pool")?)?;
    let layout = pool.layout().map_err(|e| EngineError::bad("pool", e.to_string()))?;
    let now = s.now().unwrap_or(0);
    let ports = limit(&pool);
    // The 7-day peak of every subscriber of the pool with readings.
    let since = now.saturating_sub(86_400);
    let (mut peaks, hit, refused_24h, icmp_24h) = {
        let Some(store) = s.cgnat_capacity() else {
            return Err(EngineError::Hal("no capacity store".into()));
        };
        let mut peaks: Vec<u16> = Vec::new();
        let mut hit = 0u64;
        for i in 0..layout.subscribers() {
            let Some(sub) = layout.subscriber(i) else { continue };
            if let Some(v) = store.peak(sub, now) {
                peaks.push(v);
            }
            if store.refused_since(sub, since) {
                hit += 1;
            }
        }
        let (r, i) = store.pool_day(&pool.name, now);
        (peaks, hit, r, i)
    };
    peaks.sort_unstable();
    let seen = peaks.len() as u64;
    let p99 = u64::from(percentile(&peaks, 99));
    let max = u64::from(peaks.last().copied().unwrap_or(0));
    let pct = |n: u64| (n * 100).checked_div(ports).unwrap_or(0);
    let bands: Vec<Value> = BANDS
        .iter()
        .map(|(label, from, to)| {
            let count = peaks
                .iter()
                .filter(|v| {
                    let p = pct(u64::from(**v));
                    p >= *from && p < *to
                })
                .count();
            json!({"band": label, "count": count})
        })
        .collect();
    let range = u64::from(pool.port_range.last.saturating_sub(pool.port_range.first)) + 1;
    let mut out = json!({
        "pool": pool.name, "mode": if pool.mode == Mode::Blocks { "blocks" } else { "deterministic" },
        "ports": ports, "ports_per_subscriber": pool.ports_per_subscriber,
        "subscribers": layout.subscribers(), "seen": seen,
        "per_address": layout.per_address(), "public_addresses": layout.public_addresses(),
        "p99": p99, "p99_percent": pct(p99), "max": max,
        "hit_24h": hit, "refused_24h": refused_24h, "icmp_24h": icmp_24h, "bands": bands,
    });
    if seen > 0
        && pool.mode == Mode::Deterministic
        && let Some(o) = out.as_object_mut()
    {
        let (want, why) = suggest(ports, p99, seen, hit, range);
        let mut np = pool.clone();
        np.ports_per_subscriber = u16::try_from(want).unwrap_or(u16::MAX);
        let (per_address, needed, fits) = match np.layout() {
            Ok(l) => (u64::from(l.per_address()), l.public_used(), true),
            Err(LayoutError::Capacity { per_address, public_needed, .. }) => (u64::from(per_address), public_needed, false),
            Err(_) => (0, 0, false),
        };
        let reason = if want == u64::from(pool.ports_per_subscriber) { "already right" } else { why };
        o.insert(
            "suggestion".into(),
            json!({
                "ports_per_subscriber": want, "per_address": per_address,
                "gain_per_address": i64::try_from(per_address).unwrap_or(0) - i64::from(layout.per_address()),
                "public_needed": needed, "fits": fits, "reason": reason,
            }),
        );
    }
    Ok(out)
}

fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let pool = pool_of(s, req_str(p, "pool")?)?;
    let ports = req_u32(p, "ports_per_subscriber")?;
    let ports = u16::try_from(ports).map_err(|_| EngineError::bad("ports_per_subscriber", "1..65535"))?;
    let mut np = pool.clone();
    np.ports_per_subscriber = ports;
    let now_per = pool.layout().map(|l| l.per_address()).unwrap_or(0);
    let mut out = json!({
        "per_address_now": now_per,
        "command": {"command": "ip.firewall.cgnat.pool.set", "params": {"id": pool.name, "ports_per_subscriber": ports}},
    });
    let Some(o) = out.as_object_mut() else { return Ok(out) };
    match np.layout() {
        Ok(l) => {
            o.insert("per_address".into(), json!(l.per_address()));
            o.insert("fits".into(), json!(true));
        }
        Err(e) => {
            o.insert("per_address".into(), json!(0));
            o.insert("fits".into(), json!(false));
            o.insert("error".into(), json!(e.to_string()));
        }
    }
    // Who moves, and the connections that the commit would kill.
    let from = s.store().running().ip.cgnat.clone();
    let mut to = from.clone();
    if let Some(q) = to.pools.iter_mut().find(|q| q.id == pool.id) {
        q.ports_per_subscriber = ports;
    }
    let moved: Vec<Ipv4Addr> = corerouter_firewall::cgnat::remapped(&from, &to);
    o.insert("remapped".into(), json!(moved.len()));
    let killed = match s.connections(false) {
        Ok((conns, _)) => conns
            .iter()
            .filter(|c| c.has(status::SRC_NAT))
            .filter(|c| matches!(c.orig.src, IpAddr::V4(a) if moved.binary_search(&a).is_ok()))
            .count(),
        Err(_) => 0,
    };
    o.insert("connections".into(), json!(killed));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_is_the_nearest_rank() {
        let v: Vec<u16> = (1..=100).collect();
        assert_eq!(percentile(&v, 99), 99);
        assert_eq!(percentile(&v, 100), 100);
        assert_eq!(percentile(&[7], 99), 7);
        assert_eq!(percentile(&[], 99), 0);
    }

    #[test]
    fn suggestions_round_up_and_grow_when_people_run_out() {
        // p99 400 → 500 → 512.
        assert_eq!(suggest(1000, 400, 1000, 0, 64512).0, 512);
        // Light users: never below the floor.
        assert_eq!(suggest(1000, 10, 1000, 0, 64512).0, MIN_PORTS);
        // 2 % refused: at least 1.5 × today.
        assert_eq!(suggest(1000, 400, 1000, 20, 64512).0, 1536);
        // Never past the range.
        assert_eq!(suggest(60000, 60000, 10, 5, 64512).0, 64512);
    }
}

//! /ip firewall cgnat block and alert (G2.3c): the port blocks handed out
//! on demand (blocks mode), their log, and the subscribers that ran out of
//! ports. The allocator is `crate::cgnat_blocks`.

use std::net::Ipv4Addr;

use corerouter_proto_dhcp::server::history::{parse_time, utc};
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows of one page.
pub const MAX_PAGE: u32 = 5000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.firewall.cgnat.block.list", "CGNAT Blocks", [], None,
        "{pool?: string, subscriber?: ipv4, offset?: u32, count?: u32 (1..5000; default 200)} → {total, rows: [{subscriber, pool, public, first_port, last_port, since (UTC), current (the one new connections use), idle? (seconds without connections)}]}",
        always, list),
    cmd!(query "ip.firewall.cgnat.block.history", "CGNAT Block Log", [], None,
        "{subscriber?: ipv4, public?: ipv4, port?: u16, from?: string (unix or RFC 3339), to?: string, count?: u32 (1..5000; default 200)} → [{subscriber, pool, public, first_port, last_port, from (UTC), until? (UTC)}] (newest first; RFC 6888 §4: one record per block)",
        always, history),
    cmd!(query "ip.firewall.cgnat.alert.list", "CGNAT Port Alerts", [], None,
        "{} → {insert_failed (new connections the kernel could not translate since the start: no free port), rows: [{subscriber, pool, used, ports, percent, peak, crossings, first (UTC), last (UTC), above}]}",
        always, alerts),
    cmd!(
        "ip.firewall.cgnat.alert.clear",
        "Clear CGNAT Alerts",
        [],
        None,
        "{subscriber?: ipv4 (one; default all)} → {cleared}",
        always,
        alerts_clear
    ),
];

fn page(p: &Value) -> Result<(usize, usize)> {
    let offset = opt_u32(p, "offset")?.unwrap_or(0) as usize;
    let count = match opt_u32(p, "count")? {
        Some(n) if !(1..=MAX_PAGE).contains(&n) => return Err(EngineError::bad("count", format!("1..={MAX_PAGE}"))),
        n => n.unwrap_or(200) as usize,
    };
    Ok((offset, count))
}

fn time(p: &Value, key: &str) -> Result<Option<u64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| EngineError::bad(key, "unix seconds")),
        Some(Value::String(t)) => parse_time(t)
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "unix seconds or like 2026-05-03T14:02:00-03:00")),
        Some(_) => Err(EngineError::bad(key, "unix seconds or an RFC 3339 string")),
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let pool = opt_str(p, "pool")?.map(str::to_owned);
    let sub = opt_parse::<Ipv4Addr>(p, "subscriber")?;
    let (offset, count) = page(p)?;
    let now = s.now().unwrap_or(0);
    let Some(rt) = s.cgnat_blocks() else {
        return Ok(json!({"total": 0, "rows": []}));
    };
    let mut rows = Vec::new();
    for (subscriber, blocks) in rt.active() {
        if sub.is_some_and(|x| x != *subscriber) {
            continue;
        }
        let n = blocks.len();
        for (i, b) in blocks.iter().enumerate() {
            if pool.as_deref().is_some_and(|x| x != b.pool_name) {
                continue;
            }
            let mut v = json!({
                "subscriber": subscriber, "pool": b.pool_name, "public": b.slot.public,
                "first_port": b.slot.first_port, "last_port": b.slot.last_port,
                "since": utc(b.since), "current": i + 1 == n,
            });
            if let (Some(e), Some(o)) = (b.empty_since, v.as_object_mut()) {
                o.insert("idle".into(), json!(now.saturating_sub(e)));
            }
            rows.push(v);
        }
    }
    let total = rows.len();
    let rows: Vec<Value> = rows.into_iter().skip(offset).take(count).collect();
    Ok(json!({"total": total, "rows": rows}))
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let sub = opt_parse::<Ipv4Addr>(p, "subscriber")?;
    let public = opt_parse::<Ipv4Addr>(p, "public")?;
    let port = match opt_u32(p, "port")? {
        Some(n) => Some(u16::try_from(n).map_err(|_| EngineError::bad("port", "0..65535"))?),
        None => None,
    };
    let (from, to) = (time(p, "from")?, time(p, "to")?);
    let (_, count) = page(p)?;
    let Some(rt) = s.cgnat_blocks() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = rt
        .records()
        .iter()
        .rev()
        .filter(|r| sub.is_none_or(|x| r.subscriber == x))
        .filter(|r| public.is_none_or(|x| r.slot.public == x))
        .filter(|r| port.is_none_or(|x| (r.slot.first_port..=r.slot.last_port).contains(&x)))
        .filter(|r| to.is_none_or(|t| r.from <= t))
        .filter(|r| from.is_none_or(|f| r.until.is_none_or(|u| u >= f)))
        .take(count)
        .map(|r| {
            let mut v = json!({
                "subscriber": r.subscriber, "pool": r.pool, "public": r.slot.public,
                "first_port": r.slot.first_port, "last_port": r.slot.last_port, "from": utc(r.from),
            });
            if let (Some(u), Some(o)) = (r.until, v.as_object_mut()) {
                o.insert("until".into(), json!(utc(u)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn alerts(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(rt) = s.cgnat_blocks() else {
        return Ok(json!({"insert_failed": 0, "rows": []}));
    };
    let mut rows: Vec<&crate::cgnat_blocks::Alert> = rt.alerts().values().collect();
    rows.sort_by(|a, b| b.above.cmp(&a.above).then(b.percent.cmp(&a.percent)).then(b.last.cmp(&a.last)));
    let rows: Vec<Value> = rows
        .into_iter()
        .map(|a| {
            json!({
                "subscriber": a.subscriber, "pool": a.pool, "used": a.used, "ports": a.ports,
                "percent": a.percent, "peak": a.peak, "crossings": a.crossings,
                "first": utc(a.first), "last": utc(a.last), "above": a.above,
            })
        })
        .collect();
    Ok(json!({"insert_failed": rt.insert_failed(), "rows": rows}))
}

fn alerts_clear(s: &mut Session, p: &Value) -> Result<Value> {
    let sub = opt_parse::<Ipv4Addr>(p, "subscriber")?;
    let _ = s.cgnat_blocks();
    Ok(json!({"cleared": s.cgnat_alerts_clear(sub)}))
}

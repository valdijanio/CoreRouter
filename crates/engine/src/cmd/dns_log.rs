//! /ip dns log (G4.1zd): the LAN forwarder's query log on the router's
//! disk. RouterOS has no such menu (only the `dns` topic of `/system
//! logging`); the knobs follow Pi-hole, AdGuard Home and Unbound, plus a
//! ceiling in bytes (`docs/dns-query-log.md`).
//!
//! - `ip.dns.log.set` / `get`: the settings (off by default; turning the
//!   log on takes `acknowledge`, because a log of who asked what is, at a
//!   connection provider, what Marco Civil art. 14 forbids keeping), the
//!   writer's numbers and an estimate (GB a day at the current rate, the
//!   retention the ceiling gives, disk wear a year).
//! - `ip.dns.log.print`: a page of queries, newest first, filtered.
//! - `ip.dns.log.export`: the same as CSV or JSON lines (journaled: who
//!   exported what).
//! - `ip.dns.log.clear`: deletes, everything, before a time or one client
//!   (LGPD art. 18).
//!
//! The files are the daemon's (`crate::dns_log`); reading them happens off
//! the session lock ([`Session::defer`]).

use std::net::IpAddr;

use corerouter_model::dns_log::{ACKNOWLEDGE, ClientAddress, DnsLog, MAX_LIST, exclude_problem};
use corerouter_proto_dns::querylog::format::{DROPPED, Mode, Record, TCP, TRUNCATED};
use corerouter_proto_dns::querylog::{BY, ClientMatch, Filter, RCODE_DROPPED, by_name, type_code};
use corerouter_proto_dns::server::{ede_name, type_name};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::config_disk::{ConfigDisk, dns_log_budget};
use crate::dns_log::{Found, LogStatus};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.log.set",
        "DNS Query Log",
        [],
        None,
        "{enabled?: bool (write the queries the LAN forwarder answers to disk; default no), acknowledge?: string (\"marco-civil-art14\": needed to turn the log on; a log of who asked what is, at a connection provider, the application access record Marco Civil art. 14 forbids keeping, and personal data under the LGPD), client_address?: full | truncated | hashed | none (how clients are written; default truncated), ipv4_prefix?: int 8..32 (bits kept by truncated; default 24), ipv6_prefix?: int 16..128 (default 56), salt_rotation_hours?: int 1..8760 (hashed: a new key this often, kept only in memory; default 24), max_size_mib?: int 1..1048576 (default 1024; also capped at 20 % of /config), max_age_hours?: int 1..8760 (default 24), exclude?: [name] (never logged, with the names under them), only_from?: [prefix] (only these clients; empty: all), except_from?: [prefix] (never these clients)} → {enabled, client_address, ipv4_prefix, ipv6_prefix, salt_rotation_hours, max_size_mib, max_age_hours, exclude, only_from, except_from}",
        always,
        set
    ),
    cmd!(query "ip.dns.log.get", "DNS Query Log", ["IP", "DNS"], None,
        "{} → {enabled, client_address, ipv4_prefix, ipv6_prefix, salt_rotation_hours, max_size_mib, max_age_hours, exclude, only_from, except_from, acknowledge (the text set needs), writer: {writing, reason, files, bytes, oldest (unix ms), newest, written, written_bytes, dropped_queue, dropped_disk, budget_bytes, rotated} | null (no daemon), budget_bytes, estimate: {queries_per_sec (the forwarder, last minute), bytes_per_query, gb_per_day, retention_hours, limited_by: size|age, wear_tb_per_year}, warnings: [{key, severity, text}]}",
        always, get),
    cmd!(query "ip.dns.log.print", "DNS Query Log", [], None,
        "{last_secs?: int 1..31536000 (the last N seconds; instead of from), from?: int (unix seconds), to?: int (unix seconds), client?: string (address, network or h:<hash>), name?: string (*.example.com: it and the names under it; else contained in the name), type?: string (A, AAAA, HTTPS…), rcode?: noerror | formerr | servfail | nxdomain | notimp | refused | dropped, answered_by?: cache | upstream | stale | static | adlist | zones | special | refused | limit | busy, limit?: int 1..1000 (default 100), cursor?: string (next of the previous page)} → {rows: [{time (unix ms), client, name, type, rcode, answered_by, ede?, ede_name?, latency_ms, tcp, truncated}], next: string|null, scanned, partial (the scan budget ended before limit rows: next goes on), anonymization}",
        has_backend, print),
    cmd!(
        "ip.dns.log.export",
        "Export DNS Query Log",
        [],
        None,
        "{format?: csv | jsonl (default csv), last_secs?: int, from?: int, to?: int, client?: string, name?: string, type?: string, rcode?: string, answered_by?: string, limit?: int 1..100000 (default 10000), cursor?: string} → {format, rows, text, next: string|null, partial}",
        has_backend,
        export
    ),
    cmd!(
        "ip.dns.log.clear",
        "Clear DNS Query Log",
        [],
        None,
        "{all?: bool (everything), before?: int (unix seconds: the queries older than this), older_than_secs?: int (instead of before: the queries older than this many seconds), client?: string (address, network or h:<hash>: that client's queries, LGPD art. 18)} → {files, bytes, queries}",
        has_backend,
        clear
    ),
];

/// Rows a page holds at most.
const MAX_PAGE: u32 = 1000;
/// Rows an export holds at most.
const MAX_EXPORT: u32 = 100_000;
/// Queries one call looks at, at most: ~1 s on one core (12 million/s,
/// **medido**), so a search never holds a control connection for long.
const SCAN_BUDGET: u64 = 20_000_000;
/// Bytes a query takes on disk when nothing was written yet (**medido**:
/// 12.3 with Zipf names and 4096 CGNAT clients, `docs/dns-query-log.md`).
const BYTES_PER_QUERY: f64 = 12.3;
/// Disk writes per byte logged (ext4, large sequential appends; **estimado**).
const WRITE_AMPLIFICATION: f64 = 1.2;

fn has_backend(s: &Session) -> std::result::Result<(), String> {
    if s.dns_log_backend().is_none() {
        Err("the query log is written by the router daemon; this session has none".into())
    } else {
        Ok(())
    }
}

fn bad(e: &str) -> EngineError {
    EngineError::NotSaved(format!("query log: {e}"))
}

/// A list of strings: a JSON array or, from the CLI, one comma-separated
/// string. At most [`MAX_LIST`].
fn strings(p: &Value, key: &str) -> Result<Option<Vec<String>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_owned).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(|s| s.trim().to_owned()).ok_or_else(|| EngineError::bad(key, "each item must be a string")))
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad(key, "a list of strings")),
    };
    if raw.len() > MAX_LIST {
        return Err(EngineError::bad(key, format!("at most {MAX_LIST} entries")));
    }
    Ok(Some(raw))
}

fn nets(p: &Value, key: &str) -> Result<Option<Vec<IpNet>>> {
    let Some(raw) = strings(p, key)? else {
        return Ok(None);
    };
    let mut out: Vec<IpNet> = Vec::new();
    for s in raw {
        let n = match s.parse::<IpNet>() {
            Ok(n) => n.trunc(),
            Err(_) => match s.parse::<IpAddr>() {
                Ok(a) => IpNet::from(a.to_canonical()),
                Err(_) => {
                    let shown: String = s.chars().take(64).collect();
                    return Err(EngineError::bad(key, format!("'{shown}' is not an address or a prefix")));
                }
            },
        };
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(Some(out))
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => Err(EngineError::bad(key, format!("must be {lo}..{hi}"))),
        v => Ok(v),
    }
}

fn config_json(d: &DnsLog) -> Value {
    json!({
        "enabled": d.enabled,
        "client_address": d.client_address.as_str(),
        "ipv4_prefix": d.ipv4_prefix,
        "ipv6_prefix": d.ipv6_prefix,
        "salt_rotation_hours": d.salt_rotation_hours,
        "max_size_mib": d.max_size_mib,
        "max_age_hours": d.max_age_hours,
        "exclude": d.exclude,
        "only_from": d.only_from.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "except_from": d.except_from.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut d = s.store().candidate().ip.dns_log.clone();
    let was_on = d.enabled;
    if let Some(v) = opt_bool(p, "enabled")? {
        d.enabled = v;
    }
    if d.enabled && !was_on && opt_str(p, "acknowledge")? != Some(ACKNOWLEDGE) {
        return Err(EngineError::bad(
            "acknowledge",
            format!(
                "turning the query log on needs acknowledge=\"{ACKNOWLEDGE}\": a log of which client asked which name and when is, at a connection provider, the application access record Marco Civil (Lei 12.965/2014) art. 14 forbids keeping, and personal data under the LGPD"
            ),
        ));
    }
    if let Some(v) = opt_str(p, "client_address")? {
        d.client_address = ClientAddress::parse(v).map_err(|e| EngineError::bad("client_address", e))?;
    }
    if let Some(v) = ranged(p, "ipv4_prefix", 8, 32)? {
        d.ipv4_prefix = u8::try_from(v).unwrap_or(24);
    }
    if let Some(v) = ranged(p, "ipv6_prefix", 16, 128)? {
        d.ipv6_prefix = u8::try_from(v).unwrap_or(56);
    }
    if let Some(v) = ranged(p, "salt_rotation_hours", 1, corerouter_model::dns_log::MAX_AGE_HOURS)? {
        d.salt_rotation_hours = v;
    }
    if let Some(v) = ranged(p, "max_size_mib", 1, corerouter_model::dns_log::MAX_SIZE_MIB)? {
        d.max_size_mib = v;
    }
    if let Some(v) = ranged(p, "max_age_hours", 1, corerouter_model::dns_log::MAX_AGE_HOURS)? {
        d.max_age_hours = v;
    }
    if let Some(names) = strings(p, "exclude")? {
        let mut out: Vec<String> = Vec::new();
        for n in names {
            let n = n.trim_end_matches('.').to_ascii_lowercase();
            if let Some(why) = exclude_problem(&n) {
                return Err(EngineError::bad("exclude", why));
            }
            if !out.contains(&n) {
                out.push(n);
            }
        }
        d.exclude = out;
    }
    if let Some(v) = nets(p, "only_from")? {
        d.only_from = v;
    }
    if let Some(v) = nets(p, "except_from")? {
        d.except_from = v;
    }
    if let Some(why) = d.problem() {
        return Err(EngineError::bad("enabled", why));
    }
    let out = config_json(&d);
    let now_on = d.enabled;
    s.store_mut().candidate_mut().ip.dns_log = d;
    if now_on != was_on {
        let who = s.caller().principal.label().to_owned();
        let (msg, sev) = if now_on {
            (format!("DNS query log turned on by {who}"), "warning")
        } else {
            (format!("DNS query log turned off by {who}"), "info")
        };
        s.log_event(&["dns", sev], "dns-log", msg, json!({"enabled": now_on, "by": who}));
    }
    Ok(out)
}

/// The forwarder's queries per second over the last minute (the
/// statistics' readings), when there are any.
fn queries_per_sec(s: &Session) -> Option<f64> {
    let r = s.dns_readings();
    let (first, last) = (r.first()?, r.last()?);
    let secs = last.t.saturating_sub(first.t);
    (secs > 0).then(|| last.queries.saturating_sub(first.queries) as f64 / secs as f64)
}

fn estimate(d: &DnsLog, budget: u64, qps: Option<f64>, w: Option<&LogStatus>) -> Value {
    let bpq = w
        .filter(|w| w.written >= 10_000)
        .map_or(BYTES_PER_QUERY, |w| w.written_bytes as f64 / w.written as f64);
    let Some(qps) = qps else {
        return json!({"queries_per_sec": null, "bytes_per_query": round1(bpq)});
    };
    let per_day = qps * bpq * 86_400.0;
    let age_h = f64::from(d.max_age_hours);
    let size_h = if per_day > 0.0 { budget as f64 / per_day * 24.0 } else { f64::INFINITY };
    let (retention, limited_by) = if size_h < age_h { (size_h, "size") } else { (age_h, "age") };
    json!({
        "queries_per_sec": round1(qps),
        "bytes_per_query": round1(bpq),
        "gb_per_day": round1(per_day / 1e9),
        "retention_hours": round1(retention),
        "limited_by": limited_by,
        "wear_tb_per_year": round1(per_day * 365.0 * WRITE_AMPLIFICATION / 1e12),
    })
}

fn round1(x: f64) -> f64 {
    if x.is_finite() { (x * 10.0).round() / 10.0 } else { 0.0 }
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let d = s.store().running().ip.dns_log.clone();
    let capacity = s.ext::<ConfigDisk>().and_then(|c| c.capacity);
    let budget = dns_log_budget(capacity, d.max_size_mib);
    let status = s.dns_log_backend().map(|b| b.status());
    let mut out = config_json(&d);
    let mut warnings: Vec<Value> = Vec::new();
    let warn = |key: &str, severity: &str, text: String| json!({"key": key, "severity": severity, "text": text});
    if d.enabled {
        warnings.push(warn(
            "law",
            "warning",
            "query log on: which client asked which name and when is kept on this router (Marco Civil art. 14, LGPD)".into(),
        ));
        if d.client_address == ClientAddress::Full {
            warnings.push(warn("full_address", "warning", "clients are written with their whole address".into()));
        }
        match &status {
            None => warnings.push(warn("no_daemon", "error", "no router daemon: nothing is written".into())),
            Some(w) if !w.writing => warnings.push(warn(
                "not_writing",
                "error",
                w.reason.clone().unwrap_or_else(|| "the writer is not writing".into()),
            )),
            Some(w) if w.dropped_queue + w.dropped_disk > 0 => warnings.push(warn(
                "dropped",
                "warning",
                format!("{} queries were not written (writer behind or no room)", w.dropped_queue + w.dropped_disk),
            )),
            Some(_) => {}
        }
    }
    let est = estimate(&d, budget, queries_per_sec(s), status.as_ref());
    if d.enabled && est.get("retention_hours").and_then(Value::as_f64).is_some_and(|h| h < 1.0) {
        warnings.push(warn(
            "short_retention",
            "warning",
            "at this rate the ceiling holds less than an hour of queries".into(),
        ));
    }
    if let Some(o) = out.as_object_mut() {
        o.insert("acknowledge".into(), json!(ACKNOWLEDGE));
        o.insert("budget_bytes".into(), json!(budget));
        o.insert(
            "writer".into(),
            status.map_or(Value::Null, |w| {
                json!({
                    "writing": w.writing, "reason": w.reason, "files": w.files, "bytes": w.bytes,
                    "oldest": w.oldest_ms, "newest": w.newest_ms, "written": w.written,
                    "written_bytes": w.written_bytes, "dropped_queue": w.dropped_queue,
                    "dropped_disk": w.dropped_disk, "budget_bytes": w.budget_bytes, "rotated": w.rotated,
                })
            }),
        );
        o.insert("estimate".into(), est);
        o.insert("warnings".into(), Value::Array(warnings));
    }
    Ok(out)
}

/// A search's filter and page from the parameters.
fn filter(s: &Session, p: &Value) -> Result<Filter> {
    let mut f = Filter::default();
    let secs = |key: &str| -> Result<Option<u64>> {
        match p.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_u64().map(Some).ok_or_else(|| EngineError::bad(key, "unix seconds")),
        }
    };
    if let Some(last) = ranged(p, "last_secs", 1, 31_536_000)? {
        let now = s.now().unwrap_or(0);
        f.from_ms = Some(now.saturating_sub(u64::from(last)).saturating_mul(1000));
    }
    if let Some(from) = secs("from")? {
        f.from_ms = Some(from.saturating_mul(1000));
    }
    if let Some(to) = secs("to")? {
        f.to_ms = Some(to.saturating_mul(1000).saturating_add(999));
    }
    if let Some(c) = opt_str(p, "client")?.filter(|c| !c.trim().is_empty()) {
        f.client = Some(ClientMatch::parse(c).map_err(|e| EngineError::bad("client", e))?);
    }
    if let Some(n) = opt_str(p, "name")?.map(str::trim).filter(|n| !n.is_empty()) {
        if n.len() > 255 {
            return Err(EngineError::bad("name", "at most 255 characters"));
        }
        f.name = Some(n.trim_end_matches('.').to_ascii_lowercase());
    }
    if let Some(t) = opt_str(p, "type")?.map(str::trim).filter(|t| !t.is_empty()) {
        f.qtype = Some(type_code(t).ok_or_else(|| EngineError::bad("type", "a record type (A, AAAA, HTTPS…)"))?);
    }
    if let Some(r) = opt_str(p, "rcode")?.map(str::trim).filter(|r| !r.is_empty()) {
        f.rcode = Some(match r.to_ascii_lowercase().as_str() {
            "noerror" => 0,
            "formerr" => 1,
            "servfail" => 2,
            "nxdomain" => 3,
            "notimp" => 4,
            "refused" => 5,
            "dropped" => RCODE_DROPPED,
            _ => return Err(EngineError::bad("rcode", "noerror, formerr, servfail, nxdomain, notimp, refused or dropped")),
        });
    }
    if let Some(b) = opt_str(p, "answered_by")?.map(str::trim).filter(|b| !b.is_empty()) {
        let code = BY
            .iter()
            .position(|x| *x == b)
            .and_then(|i| u8::try_from(i).ok())
            .ok_or_else(|| EngineError::bad("answered_by", format!("one of {}", BY.join(", "))))?;
        f.by = Some(code);
    }
    Ok(f)
}

fn cursor(p: &Value) -> Result<Option<String>> {
    match opt_str(p, "cursor")? {
        Some(c) if c.len() > 64 || !c.bytes().all(|b| b.is_ascii_digit() || b == b':') => {
            Err(EngineError::bad("cursor", "the next of a previous page"))
        }
        Some(c) if !c.is_empty() => Ok(Some(c.to_owned())),
        _ => Ok(None),
    }
}

fn rcode_name(r: &Record) -> &'static str {
    if r.flags & DROPPED != 0 {
        return "dropped";
    }
    match r.rcode {
        0 => "noerror",
        1 => "formerr",
        2 => "servfail",
        3 => "nxdomain",
        4 => "notimp",
        5 => "refused",
        _ => "other",
    }
}

fn row(r: &Record, mode: Mode) -> Value {
    let mut v = json!({
        "time": r.at_ms,
        "client": r.client.show(mode),
        "name": if r.name.is_empty() { ".".to_owned() } else { r.name.clone() },
        "type": type_name(r.qtype),
        "rcode": rcode_name(r),
        "answered_by": by_name(r.by),
        "latency_ms": f64::from(r.latency_us) / 1000.0,
        "tcp": r.flags & TCP != 0,
        "truncated": r.flags & TRUNCATED != 0,
    });
    if let (Some(e), Some(o)) = (r.ede, v.as_object_mut()) {
        o.insert("ede".into(), json!(e));
        o.insert("ede_name".into(), json!(ede_name(e)));
    }
    v
}

fn anonymization(found: &Found) -> &'static str {
    found.rows.first().map_or("", |(_, m)| m.as_str())
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let f = filter(s, p)?;
    let limit = ranged(p, "limit", 1, MAX_PAGE)?.unwrap_or(100);
    let from = cursor(p)?;
    let Some(b) = s.dns_log_backend() else {
        return Err(bad("no router daemon"));
    };
    s.defer(move || {
        let found = b
            .search(&f, usize::try_from(limit).unwrap_or(100), from.as_deref(), SCAN_BUDGET)
            .map_err(|e| bad(&e))?;
        Ok(json!({
            "rows": found.rows.iter().map(|(r, m)| row(r, *m)).collect::<Vec<_>>(),
            "next": found.next,
            "scanned": found.scanned,
            "partial": found.partial,
            "anonymization": anonymization(&found),
        }))
    })
}

/// CSV field: quoted when it holds a comma, a quote or a line break.
fn csv(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let f = filter(s, p)?;
    let limit = ranged(p, "limit", 1, MAX_EXPORT)?.unwrap_or(10_000);
    let format = match opt_str(p, "format")?.unwrap_or("csv") {
        "csv" => "csv",
        "jsonl" => "jsonl",
        _ => return Err(EngineError::bad("format", "csv or jsonl")),
    };
    let from = cursor(p)?;
    let Some(b) = s.dns_log_backend() else {
        return Err(bad("no router daemon"));
    };
    s.defer(move || {
        // An export may look at more than a page: ten scan budgets.
        let found = b
            .search(&f, usize::try_from(limit).unwrap_or(10_000), from.as_deref(), SCAN_BUDGET * 10)
            .map_err(|e| bad(&e))?;
        let mut text = String::new();
        if format == "csv" {
            text.push_str("time_ms,client,name,type,rcode,answered_by,ede,latency_ms,tcp,truncated\n");
        }
        for (r, m) in &found.rows {
            let v = row(r, *m);
            if format == "jsonl" {
                text.push_str(&v.to_string());
                text.push('\n');
                continue;
            }
            let g = |k: &str| match v.get(k) {
                Some(Value::String(s)) => csv(s),
                Some(Value::Null) | None => String::new(),
                Some(x) => x.to_string(),
            };
            let line = [
                g("time"),
                g("client"),
                g("name"),
                g("type"),
                g("rcode"),
                g("answered_by"),
                g("ede"),
                g("latency_ms"),
                g("tcp"),
                g("truncated"),
            ]
            .join(",");
            text.push_str(&line);
            text.push('\n');
        }
        Ok(json!({
            "format": format,
            "rows": found.rows.len(),
            "text": text,
            "next": found.next,
            "partial": found.partial,
        }))
    })
}

fn clear(s: &mut Session, p: &Value) -> Result<Value> {
    let all = opt_bool(p, "all")?.unwrap_or(false);
    let mut before = match p.get("before") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| EngineError::bad("before", "unix seconds"))?),
    };
    if let Some(age) = ranged(p, "older_than_secs", 1, u32::MAX)? {
        if before.is_some() {
            return Err(EngineError::bad("older_than_secs", "give before or older_than_secs, not both"));
        }
        before = Some(s.now().unwrap_or(0).saturating_sub(u64::from(age)));
    }
    let client = match opt_str(p, "client")?.filter(|c| !c.trim().is_empty()) {
        Some(c) => Some(ClientMatch::parse(c).map_err(|e| EngineError::bad("client", e))?),
        None => None,
    };
    if !all && before.is_none() && client.is_none() {
        return Err(EngineError::bad("all", "say what to delete: all=yes, before or client"));
    }
    if all && (before.is_some() || client.is_some()) {
        return Err(EngineError::bad("all", "all=yes deletes everything: leave before and client out"));
    }
    let Some(b) = s.dns_log_backend() else {
        return Err(bad("no router daemon"));
    };
    s.defer(move || {
        let c = b
            .clear(before.map(|t| t.saturating_mul(1000)), client.as_ref())
            .map_err(|e| bad(&e))?;
        Ok(json!({"files": c.files, "bytes": c.bytes, "queries": c.queries}))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use corerouter_proto_dns::querylog::format::Client;
    use serde_json::json;

    use super::*;
    use crate::dns_log::{Cleared, DnsLogBackend};

    #[derive(Default)]
    struct Fake {
        cleared: Mutex<Vec<(Option<u64>, Option<ClientMatch>)>>,
        asked: Mutex<Vec<(Filter, usize, Option<String>)>>,
    }

    impl DnsLogBackend for Fake {
        fn status(&self) -> LogStatus {
            LogStatus { writing: true, files: 2, bytes: 4096, written: 100_000, written_bytes: 1_200_000, budget_bytes: 1 << 30, ..LogStatus::default() }
        }
        fn search(&self, f: &Filter, limit: usize, cursor: Option<&str>, _: u64) -> std::result::Result<Found, String> {
            self.asked.lock().unwrap().push((f.clone(), limit, cursor.map(str::to_owned)));
            let r = Record {
                at_ms: 1_763_000_000_123,
                client: Client::Addr("100.64.12.0".parse().unwrap()),
                name: "www.example.com".into(),
                qtype: 28,
                rcode: 3,
                flags: TCP,
                by: 1,
                ede: Some(22),
                latency_us: 1500,
            };
            Ok(Found { rows: vec![(r, Mode::Truncated { v4: 24, v6: 56 })], next: Some("1:2:3".into()), scanned: 10, partial: false })
        }
        fn clear(&self, before: Option<u64>, client: Option<&ClientMatch>) -> std::result::Result<Cleared, String> {
            self.cleared.lock().unwrap().push((before, client.cloned()));
            Ok(Cleared { files: 1, bytes: 10, queries: 3 })
        }
    }

    fn lab() -> Session {
        Session::virtual_lab()
    }

    #[test]
    fn off_by_default_and_on_needs_the_acknowledgement() {
        let mut s = lab();
        let g = s.execute("ip.dns.log.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], false);
        assert_eq!(g["client_address"], "truncated");
        assert_eq!(g["writer"], Value::Null);
        let e = s.execute("ip.dns.log.set", &json!({"enabled": true})).unwrap_err().to_string();
        assert!(e.contains("marco-civil-art14") && e.contains("art. 14"), "{e}");
        assert!(!s.store().running().ip.dns_log.enabled, "refused: nothing changed");
        s.execute("ip.dns.log.set", &json!({"enabled": true, "acknowledge": ACKNOWLEDGE, "client_address": "hashed", "exclude": "Example.COM., arpa", "only_from": ["100.64.0.0/10", "192.168.88.7"]}))
            .unwrap();
        let d = &s.store().running().ip.dns_log;
        assert!(d.enabled);
        assert_eq!(d.client_address, ClientAddress::Hashed);
        assert_eq!(d.exclude, ["example.com", "arpa"]);
        assert_eq!(d.only_from[1].to_string(), "192.168.88.7/32");
        // Already on: other changes need no acknowledgement.
        s.execute("ip.dns.log.set", &json!({"max_age_hours": 48})).unwrap();
        let g = s.execute("ip.dns.log.get", &json!({})).unwrap();
        assert!(g["warnings"].as_array().unwrap().iter().any(|w| w["key"] == "law"));
        assert!(g["warnings"].as_array().unwrap().iter().any(|w| w["key"] == "no_daemon"));
        // Turning it on and off is in the router's log.
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert!(log.contains("DNS query log turned on by"), "{log}");
    }

    #[test]
    fn validation_errors() {
        let mut s = lab();
        for p in [
            json!({"client_address": "anonymous"}),
            json!({"ipv4_prefix": 7}),
            json!({"ipv6_prefix": 200}),
            json!({"max_size_mib": 0}),
            json!({"max_age_hours": 9000}),
            json!({"exclude": ["bad name"]}),
            json!({"only_from": ["nope"]}),
            json!({"exclude": vec!["a"; MAX_LIST + 1]}),
            json!({"enabled": true, "acknowledge": "yes"}),
        ] {
            assert!(s.execute("ip.dns.log.set", &p).is_err(), "{p}");
        }
        assert!(s.store().running().ip.dns_log.is_default());
        // No daemon: the file commands are disabled with the reason.
        let e = s.execute("ip.dns.log.print", &json!({})).unwrap_err().to_string();
        assert!(e.contains("router daemon"), "{e}");
    }

    #[test]
    fn rollback_restores_the_previous_settings() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ip.dns.log.set", &json!({"enabled": true, "acknowledge": ACKNOWLEDGE, "max_size_mib": 10})).unwrap();
        assert!(!s.store().running().ip.dns_log.enabled, "not committed yet");
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.dns_log.is_default());
        s.execute("config.mode.set", &json!({"mode": "immediate"})).unwrap();
        s.execute("ip.dns.log.set", &json!({"enabled": true, "acknowledge": ACKNOWLEDGE})).unwrap();
        let rev = s.execute("config.history", &json!({})).unwrap();
        let revs = rev.as_array().or_else(|| rev["revisions"].as_array()).cloned().unwrap_or_default();
        assert!(!revs.is_empty());
    }

    #[test]
    fn print_export_and_clear_through_the_backend() {
        let mut s = lab();
        let fake = Arc::new(Fake::default());
        s.set_dns_log_backend(fake.clone());
        let out = s
            .execute("ip.dns.log.print", &json!({"client": "100.64.12.34", "name": "*.Example.com.", "type": "aaaa", "rcode": "nxdomain", "answered_by": "upstream", "limit": 5, "cursor": "9:8:7"}))
            .unwrap();
        let r = &out["rows"][0];
        assert_eq!(r["client"], "100.64.12.0/24");
        assert_eq!((r["type"].as_str(), r["rcode"].as_str(), r["answered_by"].as_str()), (Some("AAAA"), Some("nxdomain"), Some("upstream")));
        assert_eq!(r["ede_name"], "No Reachable Authority");
        assert_eq!(r["latency_ms"], 1.5);
        assert_eq!(out["next"], "1:2:3");
        assert_eq!(out["anonymization"], "truncated");
        let (f, limit, cur) = fake.asked.lock().unwrap()[0].clone();
        assert_eq!((limit, cur.as_deref()), (5, Some("9:8:7")));
        assert_eq!(f.name.as_deref(), Some("*.example.com"));
        assert_eq!((f.qtype, f.rcode, f.by), (Some(28), Some(3), Some(1)));
        for bad in [json!({"type": "NOPE"}), json!({"rcode": "x"}), json!({"answered_by": "x"}), json!({"cursor": "a;b"}), json!({"limit": 0}), json!({"client": "x"})] {
            assert!(s.execute("ip.dns.log.print", &bad).is_err(), "{bad}");
        }
        let csv = s.execute("ip.dns.log.export", &json!({"format": "csv"})).unwrap();
        let text = csv["text"].as_str().unwrap();
        assert!(text.starts_with("time_ms,client,name"));
        assert!(text.contains("1763000000123,100.64.12.0/24,www.example.com,AAAA,nxdomain,upstream,22,1.5,true,false"), "{text}");
        let jl = s.execute("ip.dns.log.export", &json!({"format": "jsonl"})).unwrap();
        assert!(jl["text"].as_str().unwrap().starts_with("{\""));
        assert!(s.execute("ip.dns.log.export", &json!({"format": "xml"})).is_err());

        assert!(s.execute("ip.dns.log.clear", &json!({})).is_err(), "says what");
        assert!(s.execute("ip.dns.log.clear", &json!({"all": true, "client": "10.0.0.1"})).is_err());
        let c = s.execute("ip.dns.log.clear", &json!({"client": "10.0.0.1"})).unwrap();
        assert_eq!(c["queries"], 3);
        s.execute("ip.dns.log.clear", &json!({"before": 1000})).unwrap();
        assert!(s.execute("ip.dns.log.clear", &json!({"before": 1000, "older_than_secs": 60})).is_err());
        s.execute("ip.dns.log.clear", &json!({"all": true})).unwrap();
        let cleared = fake.cleared.lock().unwrap().clone();
        assert_eq!(cleared.len(), 3);
        assert_eq!(cleared[1].0, Some(1_000_000));
        assert_eq!(cleared[2], (None, None));

        let g = s.execute("ip.dns.log.get", &json!({})).unwrap();
        assert_eq!(g["writer"]["files"], 2);
        assert_eq!(g["estimate"]["bytes_per_query"], 12.0);
    }

    #[test]
    fn estimate_from_the_rate() {
        let d = DnsLog::default();
        let e = estimate(&d, 4 << 30, Some(20_000.0), None);
        assert_eq!(e["limited_by"], "size");
        // 4 GiB at 20 000 q/s × 12.3 B: ~4.85 h; 21.3 GB a day; ~9.3 TB a
        // year with the write amplification.
        assert_eq!(e["retention_hours"], 4.8);
        assert_eq!(e["gb_per_day"], 21.3);
        assert_eq!(e["wear_tb_per_year"], 9.3);
        let e = estimate(&d, 4 << 30, Some(10.0), None);
        assert_eq!((e["limited_by"].as_str(), e["retention_hours"].as_f64()), (Some("age"), Some(24.0)));
        assert_eq!(estimate(&d, 1, None, None)["queries_per_sec"], Value::Null);
    }
}

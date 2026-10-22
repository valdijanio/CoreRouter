//! /ip dns (G4.1a, G4.1b): the resolver and LAN forwarder settings and the
//! shared cache. Static entries: `dns_static.rs`.

use std::net::IpAddr;

use corerouter_model::dns::{
    AllowedFrom, CACHE_SIZE_KIB, CONCURRENCY, Dns, MAX_ALLOWED_FROM, MAX_SERVERS, MAX_TTL_SECS,
    QUERIES_PER_CLIENT, SERVE_STALE_SECS, SERVER_TIMEOUT_MS, ServerSelection, TOTAL_TIMEOUT_MS,
    UDP_PACKET_SIZE, usable_server,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.set",
        "DNS",
        ["IP", "DNS"],
        None,
        "{servers?: [ip], allow_remote_requests?: bool (answer the LAN on UDP/TCP 53), allowed_from?: [interface list | prefix] (who may ask; default LAN; others get REFUSED), max_queries_per_client?: int 0..100000 (per second, 0 = no limit), server_selection?: fastest | sequential, serve_stale_secs?: int 0..604800 (RFC 8767; 0 = off), max_concurrent_queries?: int 1..1000, max_concurrent_tcp_sessions?: int 1..1000, address_list_extra_time_secs?: int, cache_size?: int 0..1048576, cache_max_ttl_secs?: int, query_server_timeout_ms?: int 100..60000, query_total_timeout_ms?: int 100..600000, max_udp_packet_size?: int 512..65507} → {servers, allow_remote_requests, allowed_from, max_queries_per_client, server_selection, serve_stale_secs, max_concurrent_queries, max_concurrent_tcp_sessions, address_list_extra_time_secs, cache_size, cache_max_ttl_secs, query_server_timeout_ms, query_total_timeout_ms, max_udp_packet_size}",
        always,
        set
    ),
    cmd!(query "ip.dns.get", "DNS", [], None,
        "{} → {servers, dynamic_servers, allow_remote_requests, allowed_from, allowed_networks (what allowed_from stands for now), max_queries_per_client, server_selection, serve_stale_secs, max_concurrent_queries, max_concurrent_tcp_sessions, address_list_extra_time_secs, cache_size, cache_max_ttl_secs, query_server_timeout_ms, query_total_timeout_ms, max_udp_packet_size, cache_used, resolver: router|simulated, upstream: [{server, srtt_ms, answers, failures, down}]}",
        always, get),
    cmd!(query "ip.dns.cache.print", "DNS Cache", [], None,
        "{name?: string, type?: string (A, MX, …)} → [{name, type, kind: records|nx-domain|no-data, data: [record text], addresses, ttl, hits, server, stale}]",
        always, cache_print),
    cmd!(
        "ip.dns.cache.flush",
        "Flush Cache",
        [],
        None,
        "{} → {flushed}",
        always,
        cache_flush
    ),
];

fn settings_json(d: &Dns) -> Value {
    json!({
        "servers": d.servers,
        "allow_remote_requests": d.allow_remote_requests,
        "allowed_from": d.allowed_from,
        "max_queries_per_client": d.max_queries_per_client,
        "server_selection": d.server_selection.as_str(),
        "serve_stale_secs": d.serve_stale_secs,
        "max_concurrent_queries": d.max_concurrent_queries,
        "max_concurrent_tcp_sessions": d.max_concurrent_tcp_sessions,
        "address_list_extra_time_secs": d.address_list_extra_time_secs,
        "cache_size": d.cache_size,
        "cache_max_ttl_secs": d.cache_max_ttl_secs,
        "query_server_timeout_ms": d.query_server_timeout_ms,
        "query_total_timeout_ms": d.query_total_timeout_ms,
        "max_udp_packet_size": d.max_udp_packet_size,
    })
}

/// A JSON array of strings or, for the CLI, one comma-separated string.
fn string_list(p: &Value, key: &str, example: &str) -> Result<Option<Vec<String>>> {
    Ok(Some(match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_owned())
                    .ok_or_else(|| EngineError::bad(key, "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(key, format!("must be a list, e.g. {example}")));
        }
    }))
}

/// `allowed_from`: interface lists that exist, and prefixes.
fn allowed_from(s: &Session, p: &Value) -> Result<Option<Vec<String>>> {
    let Some(raw) = string_list(p, "allowed_from", "[\"LAN\", \"10.0.0.0/8\"]")? else {
        return Ok(None);
    };
    if raw.len() > MAX_ALLOWED_FROM {
        return Err(EngineError::bad(
            "allowed_from",
            format!("at most {MAX_ALLOWED_FROM} items"),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let shown: String = item.chars().take(64).collect();
        let canonical = match AllowedFrom::parse(&item) {
            Ok(AllowedFrom::Net(n)) => n.to_string(),
            Ok(AllowedFrom::List(l)) => {
                if s.store().candidate().interface_lists.get(&l).is_none() {
                    return Err(EngineError::bad(
                        "allowed_from",
                        format!("no interface list '{shown}' (see interface.list.list)"),
                    ));
                }
                l
            }
            Err(_) => {
                return Err(EngineError::bad(
                    "allowed_from",
                    format!("'{shown}' is neither a prefix (192.168.88.0/24) nor an interface list"),
                ));
            }
        };
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(Some(out))
}

/// A JSON array of addresses or, for the CLI, one comma-separated string.
fn servers(p: &Value) -> Result<Option<Vec<IpAddr>>> {
    let raw: Vec<String> = match p.get("servers") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("servers", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                "servers",
                "must be a list of addresses, e.g. [\"1.1.1.1\", \"2606:4700:4700::1111\"]",
            ));
        }
    };
    if raw.len() > MAX_SERVERS {
        return Err(EngineError::bad(
            "servers",
            format!("at most {MAX_SERVERS} servers"),
        ));
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for s in raw {
        let shown: String = s.chars().take(64).collect();
        let ip: IpAddr = s.parse().map_err(|_| {
            EngineError::bad(
                "servers",
                format!("'{shown}' is not an IP address (servers are addresses, not names)"),
            )
        })?;
        if !usable_server(ip) {
            return Err(EngineError::bad(
                "servers",
                format!("{ip} cannot be a DNS server (unspecified, multicast or broadcast)"),
            ));
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(Some(out))
}

fn ranged(p: &Value, key: &str, range: std::ops::RangeInclusive<u32>) -> Result<Option<u32>> {
    let Some(v) = opt_u32(p, key)? else {
        return Ok(None);
    };
    if range.contains(&v) {
        Ok(Some(v))
    } else {
        Err(EngineError::bad(
            key,
            format!("must be {}..={}", range.start(), range.end()),
        ))
    }
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let servers = servers(p)?;
    let remote = opt_bool(p, "allow_remote_requests")?;
    let allowed = allowed_from(s, p)?;
    let per_client = ranged(p, "max_queries_per_client", QUERIES_PER_CLIENT)?;
    let selection: Option<ServerSelection> = opt_parse(p, "server_selection")?;
    let stale = ranged(p, "serve_stale_secs", SERVE_STALE_SECS)?;
    let concurrent = ranged(p, "max_concurrent_queries", CONCURRENCY)?;
    let tcp_sessions = ranged(p, "max_concurrent_tcp_sessions", CONCURRENCY)?;
    let extra = ranged(p, "address_list_extra_time_secs", 0..=MAX_TTL_SECS)?;
    let cache_size = ranged(p, "cache_size", CACHE_SIZE_KIB)?;
    let max_ttl = ranged(p, "cache_max_ttl_secs", 0..=MAX_TTL_SECS)?;
    let server_to = ranged(p, "query_server_timeout_ms", SERVER_TIMEOUT_MS)?;
    let total_to = ranged(p, "query_total_timeout_ms", TOTAL_TIMEOUT_MS)?;
    let udp = ranged(
        p,
        "max_udp_packet_size",
        u32::from(*UDP_PACKET_SIZE.start())..=u32::from(*UDP_PACKET_SIZE.end()),
    )?;
    let mut d = s.store().candidate().ip.dns.clone();
    if let Some(list) = servers {
        d.servers = list;
    }
    if let Some(v) = remote {
        d.allow_remote_requests = v;
    }
    if let Some(v) = allowed {
        d.allowed_from = v;
    }
    if let Some(v) = per_client {
        d.max_queries_per_client = v;
    }
    if let Some(v) = selection {
        d.server_selection = v;
    }
    if let Some(v) = stale {
        d.serve_stale_secs = v;
    }
    if let Some(v) = concurrent {
        d.max_concurrent_queries = v;
    }
    if let Some(v) = tcp_sessions {
        d.max_concurrent_tcp_sessions = v;
    }
    if let Some(v) = extra {
        d.address_list_extra_time_secs = v;
    }
    if let Some(v) = cache_size {
        d.cache_size = v;
    }
    if let Some(v) = max_ttl {
        d.cache_max_ttl_secs = v;
    }
    if let Some(v) = server_to {
        d.query_server_timeout_ms = v;
    }
    if let Some(v) = total_to {
        d.query_total_timeout_ms = v;
    }
    if let Some(v) = udp {
        d.max_udp_packet_size = u16::try_from(v).unwrap_or(u16::MAX);
    }
    if let Some(why) = d.problem() {
        let key = if total_to.is_some() || server_to.is_some() {
            "query_total_timeout_ms"
        } else {
            "servers"
        };
        return Err(EngineError::bad(key, why));
    }
    let out = settings_json(&d);
    s.store_mut().candidate_mut().ip.dns = d;
    Ok(out)
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings_json(&s.store().candidate().ip.dns);
    let backend = s.dns_backend();
    if let Some(o) = out.as_object_mut() {
        o.insert("dynamic_servers".into(), json!(s.dns_dynamic_servers()));
        // RouterOS `cache-used`, in KiB.
        let used = backend.as_ref().map_or(0, |b| b.cache_used_bytes().div_ceil(1024));
        o.insert("cache_used".into(), json!(used));
        o.insert(
            "resolver".into(),
            json!(if backend.is_some() { "router" } else { "simulated" }),
        );
        let nets = s.dns_allowed_networks(s.store().candidate());
        o.insert("allowed_networks".into(), json!(nets));
        let upstream: Vec<Value> = backend
            .map(|b| b.server_stats())
            .unwrap_or_default()
            .into_iter()
            .map(|(ip, st)| {
                json!({"server": ip, "srtt_ms": st.srtt_ms, "answers": st.answers,
                    "failures": st.failures, "down": st.down_until_ms > 0})
            })
            .collect();
        o.insert("upstream".into(), json!(upstream));
    }
    Ok(out)
}

fn cache_print(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "name")?.map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase());
    let qtype = opt_str(p, "type")?.map(|t| t.trim().to_ascii_uppercase());
    let rows = s.dns_backend().map(|b| b.cache_rows()).unwrap_or_default();
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|r| filter.as_ref().is_none_or(|f| r.name.contains(f.as_str())))
        .filter(|r| qtype.as_ref().is_none_or(|t| r.qtype == *t))
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    Ok(Value::Array(rows))
}

fn cache_flush(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(b) = s.dns_backend() else {
        return Ok(json!({"flushed": 0}));
    };
    let n = b.cache_rows().len();
    b.flush();
    Ok(json!({"flushed": n}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get() {
        let mut s = Session::virtual_lab();
        let out = s
            .execute(
                "ip.dns.set",
                &json!({"servers": "1.1.1.1, 2606:4700:4700::1111,1.1.1.1", "cache_size": 4096}),
            )
            .unwrap();
        assert_eq!(out["servers"], json!(["1.1.1.1", "2606:4700:4700::1111"]));
        let got = s.execute("ip.dns.get", &json!({})).unwrap();
        assert_eq!(got["cache_size"], 4096);
        assert_eq!(got["query_server_timeout_ms"], 2000);
        assert_eq!(got["dynamic_servers"], json!([]));
        assert_eq!(got["resolver"], "simulated");
        assert_eq!(s.dns_settings().servers.len(), 2);
        assert_eq!(got["allowed_from"], json!(["LAN"]), "never an open resolver");
        assert_eq!(got["allowed_networks"], json!([]), "LAN has no members yet");
        let out = s
            .execute(
                "ip.dns.set",
                &json!({"allow_remote_requests": true, "allowed_from": "LAN, 10.9.8.7/16",
                    "max_queries_per_client": 50, "server_selection": "sequential",
                    "serve_stale_secs": 0, "max_concurrent_queries": 10}),
            )
            .unwrap();
        assert_eq!(out["allowed_from"], json!(["LAN", "10.9.0.0/16"]));
        assert_eq!(out["server_selection"], "sequential");
        let got = s.execute("ip.dns.get", &json!({})).unwrap();
        assert_eq!(got["allowed_networks"], json!(["10.9.0.0/16"]));
    }

    #[test]
    fn bad_values_are_refused_and_nothing_changes() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"servers": ["uol.com.br"]}),
            json!({"servers": ["0.0.0.0"]}),
            json!({"servers": 5}),
            json!({"servers": (1..=9).map(|i| format!("192.0.2.{i}")).collect::<Vec<_>>()}),
            json!({"query_server_timeout_ms": 50}),
            json!({"query_total_timeout_ms": 1000}),
            json!({"max_udp_packet_size": 100}),
            json!({"cache_size": 2_000_000}),
            json!({"allowed_from": ["NOPE"]}),
            json!({"allowed_from": "10.0.0.0/33"}),
            json!({"server_selection": "random"}),
            json!({"max_concurrent_queries": 0}),
            json!({"serve_stale_secs": 9_999_999}),
        ] {
            let err = s.execute("ip.dns.set", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(s.store().candidate().ip.dns.is_default());
    }

    #[test]
    fn rollback_restores_the_servers() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        s.execute("ip.dns.set", &json!({"servers": ["192.0.2.53"]}))
            .unwrap();
        assert_eq!(s.store().candidate().ip.dns.servers.len(), 1);
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.dns.servers.is_empty());
    }

    #[test]
    fn cache_without_a_daemon_is_empty() {
        let mut s = Session::virtual_lab();
        assert_eq!(s.execute("ip.dns.cache.print", &json!({})).unwrap(), json!([]));
        assert_eq!(
            s.execute("ip.dns.cache.flush", &json!({})).unwrap()["flushed"],
            0
        );
    }
}

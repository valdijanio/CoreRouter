//! /ip dns (G4.1a): the router's resolver settings and its cache.

use std::net::IpAddr;

use corerouter_model::dns::{
    CACHE_SIZE_KIB, Dns, MAX_SERVERS, MAX_TTL_SECS, SERVER_TIMEOUT_MS, TOTAL_TIMEOUT_MS,
    UDP_PACKET_SIZE, usable_server,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.set",
        "DNS",
        ["IP", "DNS"],
        None,
        "{servers?: [ip], allow_remote_requests?: bool, cache_size?: int 0..1048576, cache_max_ttl_secs?: int, query_server_timeout_ms?: int 100..60000, query_total_timeout_ms?: int 100..600000, max_udp_packet_size?: int 512..65507} → {servers, allow_remote_requests, cache_size, cache_max_ttl_secs, query_server_timeout_ms, query_total_timeout_ms, max_udp_packet_size}",
        always,
        set
    ),
    cmd!(query "ip.dns.get", "DNS", [], None,
        "{} → {servers, dynamic_servers, allow_remote_requests, cache_size, cache_max_ttl_secs, query_server_timeout_ms, query_total_timeout_ms, max_udp_packet_size, cache_used, resolver: router|simulated}",
        always, get),
    cmd!(query "ip.dns.cache.print", "DNS Cache", [], None,
        "{name?: string} → [{name, type: A|AAAA, kind: addresses|nx-domain|no-data, addresses?, canonical?, ttl, server}]",
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
        "cache_size": d.cache_size,
        "cache_max_ttl_secs": d.cache_max_ttl_secs,
        "query_server_timeout_ms": d.query_server_timeout_ms,
        "query_total_timeout_ms": d.query_total_timeout_ms,
        "max_udp_packet_size": d.max_udp_packet_size,
    })
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
    }
    Ok(out)
}

fn cache_print(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "name")?.map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase());
    let rows = s.dns_backend().map(|b| b.cache_rows()).unwrap_or_default();
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|r| filter.as_ref().is_none_or(|f| r.name.contains(f.as_str())))
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

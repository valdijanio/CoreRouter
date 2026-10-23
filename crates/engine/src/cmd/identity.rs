//! ip.identity.lookup (G0.25): who an address is, by the names the router
//! already has (`crate::identity`), for the subscriber chip of the GUI's
//! address tables. A public address with a port goes through CGNAT first
//! (the RFC 7422 mapping of G2.3, at the time asked), and `at` asks the
//! DHCP lease history (G4.2b) who held the address then.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use corerouter_proto_dhcp::server::history::{Entry, Query, parse_time};
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::identity::{IdentityCache, MAX_ADDRESSES, Name, Source, clean};
use crate::{EngineError, Result, Session};

/// Up to this many addresses with `at`, the history is asked one address
/// at a time; more, and it is read once for everyone bound at that time.
const ONE_BY_ONE: usize = 32;

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.identity.lookup", "Subscriber Identity", [], None,
    "{addresses: [string] | string (1..4096 addresses: 100.64.3.7, 2001:db8::7, or a public address with its port, 203.0.113.5:40001, which goes through CGNAT to the subscriber), at?: time (who held the address then, from the DHCP lease history and the CGNAT history: 2026-10-03T14:02:00-03:00, a date, or Unix seconds; default now), sources?: [string] | string (the order to try and which to use; default pppoe, dhcp-static, dhcp-dynamic, address, address-list, dns-ptr)} → [{address, at? (as given), ip (the address named), cgnat? {public, port, subscriber, via}, cgnat_error? (a port given, but the address is in no CGNAT pool: named as itself), primary? {source, name, ref}, more (other names than the primary's), all: [{source, name, detail?, ref {window, tab?, id, zone?}}], error? (not an address)}]",
    always, lookup)];

fn time(p: &Value) -> Result<Option<u64>> {
    let bad = || EngineError::bad("at", "a time: 2026-10-03T14:02:00-03:00, 2026-10-03 (UTC midnight) or Unix seconds");
    match p.get("at") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(bad),
        Some(Value::String(t)) if t.trim().is_empty() => Ok(None),
        Some(Value::String(t)) => parse_time(t).map(Some).ok_or_else(bad),
        Some(_) => Err(bad()),
    }
}

/// A list given as an array or as comma-separated text.
fn list(p: &Value, key: &str, max: usize) -> Result<Option<Vec<String>>> {
    let items: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => {
            if s.len() > max * 48 {
                return Err(EngineError::bad(key, format!("at most {max} items")));
            }
            s.split([',', ' ']).filter(|t| !t.is_empty()).map(str::to_owned).collect()
        }
        Some(Value::Array(a)) => {
            if a.len() > max {
                return Err(EngineError::bad(key, format!("at most {max} items")));
            }
            a.iter()
                .map(|v| v.as_str().map(|t| t.trim().to_owned()).ok_or_else(|| EngineError::bad(key, "a list of strings")))
                .collect::<Result<_>>()?
        }
        Some(_) => return Err(EngineError::bad(key, "a list of strings")),
    };
    if items.len() > max {
        return Err(EngineError::bad(key, format!("at most {max} items")));
    }
    Ok(Some(items))
}

fn sources(p: &Value) -> Result<Vec<Source>> {
    let Some(names) = list(p, "sources", Source::ALL.len())? else {
        return Ok(Source::ALL.to_vec());
    };
    let mut out = Vec::new();
    for n in names {
        let s = Source::parse(&n).ok_or_else(|| {
            let shown: String = n.chars().take(32).collect();
            let all: Vec<&str> = Source::ALL.iter().map(|s| s.as_str()).collect();
            EngineError::bad("sources", format!("'{shown}': one of {}", all.join(", ")))
        })?;
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// `100.64.3.7`, `2001:db8::7`, `203.0.113.5:40001`, `[2001:db8::7]:443`.
fn parse_address(t: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some((ip, None));
    }
    t.parse::<SocketAddr>().ok().map(|s| (s.ip(), Some(s.port())))
}

fn item_value(n: &Name) -> Value {
    let mut v = json!({"source": n.source.as_str(), "name": n.name, "ref": n.item});
    if let (Some(o), Some(d)) = (v.as_object_mut(), &n.detail) {
        o.insert("detail".into(), json!(d));
    }
    v
}

fn lease_ref(ip: Ipv4Addr) -> Value {
    json!({"window": "dhcp-server", "tab": "leases", "id": ip.to_string()})
}

/// Who held each address at `at` by the lease history: (MAC, host name).
fn held_at(s: &Session, ips: &[Ipv4Addr], at: u64) -> HashMap<Ipv4Addr, ([u8; 6], String)> {
    let Some(h) = s.dhcp_lease_history() else {
        return HashMap::new();
    };
    let pick = |e: &Entry| (e.address, (e.mac, e.host_name.clone()));
    if ips.len() <= ONE_BY_ONE {
        return ips
            .iter()
            .filter_map(|ip| {
                let q = Query { address: Some(*ip), at: Some(at), ..Default::default() };
                h.query(&q, 1).first().map(|e| pick(e))
            })
            .collect();
    }
    let q = Query { at: Some(at), ..Default::default() };
    let mut out: HashMap<Ipv4Addr, ([u8; 6], String)> = HashMap::new();
    // Newest first: the first entry of an address is the one in force.
    let all = h.query(&q, usize::MAX);
    let cut = all.len() >= corerouter_proto_dhcp::server::history::MAX_ROWS;
    for e in all {
        out.entry(e.address).or_insert_with(|| pick(e).1);
    }
    if cut {
        // More bound then than one read returns: ask for the rest by address.
        let missing: Vec<Ipv4Addr> = ips.iter().filter(|ip| !out.contains_key(ip)).copied().collect();
        for ip in &missing {
            let q = Query { address: Some(*ip), at: Some(at), ..Default::default() };
            if let Some(e) = h.query(&q, 1).first() {
                out.insert(e.address, pick(e).1);
            }
        }
    }
    out
}

/// The PPPoE login of the session that has `ip` (G4.3). There is no PPPoE
/// server yet: this is where its active sessions (`/ppp active` name, the
/// RADIUS User-Name, RFC 2865 §5.1) come in, first in the default order.
fn pppoe(_s: &Session, _ip: IpAddr, _at: Option<u64>) -> Vec<Name> {
    Vec::new()
}

fn lookup(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = list(p, "addresses", MAX_ADDRESSES)?.ok_or_else(|| EngineError::bad("addresses", "is required"))?;
    if raw.is_empty() {
        return Err(EngineError::bad("addresses", "at least one address"));
    }
    let at = time(p)?;
    let order = sources(p)?;

    // CGNAT first: a public address with its port is a subscriber's.
    struct Ask {
        shown: String,
        ip: Option<IpAddr>,
        cgnat: Option<Value>,
        cgnat_error: Option<String>,
        error: Option<String>,
    }
    let mut asks = Vec::with_capacity(raw.len());
    for t in &raw {
        let shown: String = t.chars().take(48).collect();
        let Some((ip, port)) = parse_address(t) else {
            asks.push(Ask { shown, ip: None, cgnat: None, cgnat_error: None, error: Some("not an address".into()) });
            continue;
        };
        let mut ask = Ask { shown, ip: Some(ip), cgnat: None, cgnat_error: None, error: None };
        if let (IpAddr::V4(public), Some(port)) = (ip, port) {
            match s.cgnat_who_was(public, port, at) {
                Ok(w) => {
                    ask.ip = Some(IpAddr::V4(w.subscriber));
                    ask.cgnat = Some(json!({"public": public, "port": port, "subscriber": w.subscriber, "via": w.via}));
                }
                // Not a CGNAT address: it is named as itself.
                Err(e) => ask.cgnat_error = Some(clean(&e)),
            }
        }
        asks.push(ask);
    }

    let v4: Vec<Ipv4Addr> = asks
        .iter()
        .filter_map(|a| match a.ip {
            Some(IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
        .collect();
    let history = at.map(|t| held_at(s, &v4, t));
    let mut cache = s.ext_mut::<IdentityCache>().map(std::mem::take).unwrap_or_default();
    let cfg = s.store().running();
    let leases = s.dhcp_server().map(|c| c.leases());

    let mut out = Vec::with_capacity(asks.len());
    for a in asks {
        let mut v = json!({"address": a.shown, "all": [], "more": 0});
        // The instant asked, as given, so a caller with several can tell
        // the answers apart.
        if let (Some(o), Some(t)) = (v.as_object_mut(), at.and(p.get("at"))) {
            o.insert("at".into(), t.clone());
        }
        let Some(o) = v.as_object_mut() else {
            continue;
        };
        if let Some(e) = a.error {
            o.insert("error".into(), json!(e));
        }
        let Some(ip) = a.ip else {
            out.push(v);
            continue;
        };
        o.insert("ip".into(), json!(ip));
        if let Some(c) = a.cgnat {
            o.insert("cgnat".into(), c);
        }
        if let Some(e) = a.cgnat_error {
            o.insert("cgnat_error".into(), json!(e));
        }
        let config = cache.config_names(cfg, ip);
        // Who held it then (history) or holds it now (the lease table).
        let holder: Option<([u8; 6], String)> = match (ip, &history, leases) {
            (IpAddr::V4(ip4), Some(h), _) => h.get(&ip4).cloned(),
            (IpAddr::V4(ip4), None, Some(l)) => l.get(ip4).filter(|l| l.state.active()).map(|l| (l.mac, l.host_name.clone())),
            _ => None,
        };
        let mut names: Vec<Name> = Vec::new();
        for src in &order {
            match src {
                Source::Pppoe => names.extend(pppoe(s, ip, at)),
                Source::DhcpDynamic => {
                    if let (IpAddr::V4(ip4), Some((mac, host))) = (ip, &holder) {
                        let name = clean(host);
                        if !name.is_empty() {
                            names.push(Name {
                                source: Source::DhcpDynamic,
                                name,
                                detail: Some(corerouter_model::MacAddr(*mac).to_string()),
                                item: lease_ref(ip4),
                            });
                        }
                    }
                }
                Source::DhcpStatic => {
                    // With `at`, a static lease names the address only if
                    // its client is the one the history says held it.
                    let same_client = |n: &&Name| match (&holder, &n.detail) {
                        (Some((mac, _)), Some(d)) => corerouter_model::MacAddr(*mac).to_string() == *d,
                        _ => true,
                    };
                    names.extend(
                        config
                            .iter()
                            .filter(|n| n.source == Source::DhcpStatic)
                            .filter(|n| history.is_none() || same_client(n))
                            .cloned(),
                    );
                }
                other => names.extend(config.iter().filter(|n| n.source == *other).cloned()),
            }
        }
        if let Some(first) = names.first() {
            let distinct: Vec<String> = names.iter().map(|n| n.name.to_lowercase()).collect();
            let main = first.name.to_lowercase();
            let mut others: Vec<&String> = distinct.iter().filter(|n| **n != main).collect();
            others.sort();
            others.dedup();
            o.insert("primary".into(), json!({"source": first.source.as_str(), "name": first.name, "ref": first.item}));
            o.insert("more".into(), json!(others.len()));
        }
        o.insert("all".into(), Value::Array(names.iter().map(item_value).collect()));
        out.push(v);
    }
    if let Some(slot) = s.ext_mut::<IdentityCache>() {
        *slot = cache;
    }
    Ok(Value::Array(out))
}

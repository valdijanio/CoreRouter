//! /ip dns forwarders (G4.1d, RouterOS 7.17): named groups of upstream
//! servers — plain, DoH or DoT — that a static FWD entry sends its names
//! to (`ip.dns.static.add type=FWD forward_to=<name>`).

use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::dns::{MAX_SERVERS, usable_server};
use corerouter_model::dns_forwarders::{ForwarderEntry, MAX_DOH_SERVERS, MAX_GROUPS, name_ok};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.forwarders.add",
        "Add DNS Forwarder",
        ["IP", "DNS"],
        None,
        "{name: string (what a static FWD entry's forward_to names), dns_servers?: [ip] (plain DNS), doh_servers?: [url] (https://host/path DoH or tls://host[#name] DoT, up to 4), verify_doh_cert?: bool (default yes), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.dns.forwarders.set",
        "Set DNS Forwarder",
        [],
        None,
        "{id: *hex, name?: string, dns_servers?: [ip], doh_servers?: [url], verify_doh_cert?: bool, disabled?: bool, comment?: string} → {id}",
        has_groups,
        set
    ),
    cmd!(
        "ip.dns.forwarders.remove",
        "Remove DNS Forwarder",
        [],
        None,
        "{id: *hex} → {id}",
        has_groups,
        remove
    ),
    cmd!(query "ip.dns.forwarders.print", "DNS Forwarders", ["IP", "DNS"], None,
        "{} → [{id, name, dns_servers?, doh_servers?, verify_doh_cert, disabled?, comment?, used_by (static FWD entries naming it), flags (X disabled)}]",
        always, print),
];

fn has_groups(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_forwarders.entries.is_empty() {
        Err("there are no DNS forwarders".into())
    } else {
        Ok(())
    }
}

fn position(s: &Session, id: ItemId) -> Result<usize> {
    s.store()
        .candidate()
        .ip
        .dns_forwarders
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no DNS forwarder {id}")))
}

/// A list of strings: JSON array, or one comma-separated string (CLI).
fn list(p: &Value, key: &str, max: usize) -> Result<Option<Vec<String>>> {
    let items: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_owned())
                    .ok_or_else(|| EngineError::bad(key, "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad(key, "must be a list")),
    };
    if items.len() > max {
        return Err(EngineError::bad(key, format!("at most {max} items")));
    }
    Ok(Some(items))
}

fn apply(e: &mut ForwarderEntry, p: &Value) -> Result<()> {
    if let Some(n) = opt_str(p, "name")? {
        let n = n.trim();
        if !name_ok(n) {
            let shown: String = n.chars().take(64).collect();
            return Err(EngineError::bad(
                "name",
                format!("'{shown}': letters, digits, - _ and ., 1..=64, with a letter (not an address)"),
            ));
        }
        n.clone_into(&mut e.name);
    }
    if let Some(items) = list(p, "dns_servers", MAX_SERVERS)? {
        let mut out: Vec<IpAddr> = Vec::new();
        for it in items {
            let shown: String = it.chars().take(64).collect();
            let ip: IpAddr = it
                .parse()
                .map_err(|_| EngineError::bad("dns_servers", format!("'{shown}' is not an IP address")))?;
            if !usable_server(ip) {
                return Err(EngineError::bad("dns_servers", format!("{ip} cannot be a DNS server")));
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        e.dns_servers = out;
    }
    if let Some(items) = list(p, "doh_servers", MAX_DOH_SERVERS)? {
        for u in &items {
            corerouter_proto_dns::check_secure(u).map_err(|why| EngineError::bad("doh_servers", why))?;
        }
        e.doh_servers = items;
    }
    if let Some(v) = opt_bool(p, "verify_doh_cert")? {
        e.verify_doh_cert = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        e.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        e.comment = v;
    }
    if let Some(why) = e.problem() {
        let key = if why.starts_with("name") {
            "name"
        } else if why.contains("doh") {
            "doh_servers"
        } else {
            "dns_servers"
        };
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

fn taken(s: &Session, name: &str, except: Option<ItemId>) -> Result<()> {
    let fw = &s.store().candidate().ip.dns_forwarders;
    match fw.get(name) {
        Some(o) if Some(o.id) != except => Err(EngineError::bad(
            "name",
            format!("forwarder {} is already named '{name}'", o.id),
        )),
        _ => Ok(()),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    if s.store().candidate().ip.dns_forwarders.entries.len() >= MAX_GROUPS {
        return Err(EngineError::bad("name", format!("at most {MAX_GROUPS} forwarders")));
    }
    let mut e = ForwarderEntry::new(ItemId(0));
    apply(&mut e, p)?;
    taken(s, &e.name, None)?;
    let fw = &mut s.store_mut().candidate_mut().ip.dns_forwarders;
    e.id = fw.next_id();
    let id = e.id;
    fw.entries.push(e);
    Ok(json!({ "id": id }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id)?;
    let Some(mut e) = s.store().candidate().ip.dns_forwarders.entries.get(i).cloned() else {
        return Err(EngineError::bad("id", format!("no DNS forwarder {id}")));
    };
    let old = e.name.clone();
    apply(&mut e, p)?;
    taken(s, &e.name, Some(id))?;
    let ip = &mut s.store_mut().candidate_mut().ip;
    // A rename follows into the static entries that name it.
    if e.name != old {
        for st in ip.dns_static.entries.iter_mut().filter(|st| st.forwarder == old) {
            st.forwarder.clone_from(&e.name);
        }
    }
    if let Some(slot) = ip.dns_forwarders.entries.get_mut(i) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id)?;
    let cfg = s.store().candidate();
    let name = cfg.ip.dns_forwarders.entries.get(i).map(|e| e.name.clone()).unwrap_or_default();
    if let Some(st) = cfg.ip.dns_static.entries.iter().find(|st| st.forwarder == name) {
        return Err(EngineError::bad(
            "id",
            format!("static entry {} forwards to '{name}': change or remove it first", st.id),
        ));
    }
    s.store_mut().candidate_mut().ip.dns_forwarders.entries.remove(i);
    Ok(json!({ "id": id }))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let rows: Vec<Value> = cfg
        .ip
        .dns_forwarders
        .entries
        .iter()
        .filter_map(|e| {
            let mut v = serde_json::to_value(e).ok()?;
            let o = v.as_object_mut()?;
            o.insert("verify_doh_cert".into(), json!(e.verify_doh_cert));
            let used: Vec<String> = cfg
                .ip
                .dns_static
                .entries
                .iter()
                .filter(|st| st.forwarder == e.name)
                .map(|st| if st.regexp.is_empty() { st.name.clone() } else { st.regexp.clone() })
                .collect();
            o.insert("used_by".into(), json!(used));
            o.insert("flags".into(), json!(if e.disabled { "X" } else { "" }));
            Some(v)
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_use_rename_and_remove() {
        let mut s = Session::virtual_lab();
        let g = s
            .execute(
                "ip.dns.forwarders.add",
                &json!({"name": "corp", "dns_servers": "10.0.0.53, 10.0.0.54",
                        "doh_servers": ["https://dns.corp.example/dns-query"]}),
            )
            .unwrap();
        s.execute(
            "ip.dns.static.add",
            &json!({"name": "corp.example", "type": "FWD", "forward_to": "corp", "match_subdomain": true}),
        )
        .unwrap();
        let st = s.execute("ip.dns.static.print", &json!({})).unwrap();
        assert_eq!(st[0]["forward_to"], json!(["corp"]), "RouterOS: the group as forward-to");
        assert!(st[0].get("forwarder").is_none());
        assert_eq!(st[0]["data"], "corp");
        let rows = s.execute("ip.dns.forwarders.print", &json!({})).unwrap();
        assert_eq!(rows[0]["dns_servers"], json!(["10.0.0.53", "10.0.0.54"]));
        assert_eq!(rows[0]["used_by"], json!(["corp.example"]));
        assert_eq!(rows[0]["verify_doh_cert"], true);
        // In use: not removed. Renamed: the entry follows.
        let err = s.execute("ip.dns.forwarders.remove", &json!({"id": g["id"]})).unwrap_err();
        assert!(err.to_string().contains("corp.example") || err.to_string().contains("forwards"), "{err}");
        s.execute("ip.dns.forwarders.set", &json!({"id": g["id"], "name": "office"})).unwrap();
        assert_eq!(s.store().candidate().ip.dns_static.entries.get(0).unwrap().forwarder, "office");
        // Back to plain servers; then the group can go.
        s.execute("ip.dns.static.set", &json!({"id": "*1", "forward_to": "10.9.9.9"})).unwrap();
        assert!(s.store().candidate().ip.dns_static.entries.get(0).unwrap().forwarder.is_empty());
        s.execute("ip.dns.forwarders.remove", &json!({"id": g["id"]})).unwrap();
        assert!(s.store().candidate().ip.dns_forwarders.entries.is_empty());
    }

    #[test]
    fn bad_groups_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("ip.dns.forwarders.add", &json!({"name": "g", "dns_servers": ["9.9.9.9"]}))
            .unwrap();
        for p in [
            json!({"name": "g", "dns_servers": ["1.1.1.1"]}),
            json!({"name": "x"}),
            json!({"name": "1.2.3.4", "dns_servers": ["1.1.1.1"]}),
            json!({"name": "x", "dns_servers": ["0.0.0.0"]}),
            json!({"name": "x", "dns_servers": ["not-ip"]}),
            json!({"name": "x", "doh_servers": ["http://plain.example/"]}),
            json!({"name": "x", "doh_servers": ["tls://h/path"]}),
            json!({"name": "x", "doh_servers": ["https://a/", "https://b/", "https://c/", "https://d/", "https://e/"]}),
        ] {
            let err = s.execute("ip.dns.forwarders.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        // A FWD to a group that does not exist fails validation.
        let err = s
            .execute("ip.dns.static.add", &json!({"name": "a.lan", "type": "FWD", "forward_to": "nope"}))
            .unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
        let err = s
            .execute("ip.dns.set", &json!({"use_doh_server": "ftp://x"}))
            .unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }), "{err}");
        s.execute("ip.dns.set", &json!({"use_doh_server": "https://1.1.1.1/dns-query", "verify_doh_cert": false}))
            .unwrap();
        let got = s.execute("ip.dns.get", &json!({})).unwrap();
        assert_eq!(got["use_doh_server"], "https://1.1.1.1/dns-query");
        assert_eq!(got["verify_doh_cert"], false);
        assert_eq!(s.dns_settings().secure.len(), 1);
    }

    #[test]
    fn rollback_drops_the_group() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ip.dns.forwarders.add", &json!({"name": "g", "dns_servers": ["9.9.9.9"]}))
            .unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.dns_forwarders.entries.is_empty());
    }
}

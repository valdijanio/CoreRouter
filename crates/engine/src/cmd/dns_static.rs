//! /ip dns static (G4.1b): names the router answers itself (RouterOS v7).
//! How they match is in `proto-dns` (`server/stage/statics.rs`).

use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::dns::{MAX_TTL_SECS, usable_server};
use corerouter_model::dns_static::{
    MAX_ENTRIES, MAX_FORWARD_TO, MAX_REGEXP_LEN, MAX_TEXT_LEN, StaticEntry, StaticType,
    host_name_ok,
};
use corerouter_model::firewall::Name;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.static.add",
        "Add Static DNS Entry",
        ["IP", "DNS"],
        None,
        "{name?: string (the name answered), regexp?: string (instead of name; regexp entries are tried first), type?: A | AAAA | CNAME | FWD | MX | NS | NXDOMAIN | SRV | TXT (default A), address?: ip (A, AAAA), cname?: name, forward_to?: [ip] (FWD: ask these servers), mx_exchange?: name, mx_preference?: int 0..65535, ns?: name, srv_target?: name, srv_port?: int 0..65535, srv_priority?: int 0..65535, srv_weight?: int 0..65535, text?: string (TXT), ttl_secs?: int (default 86400), match_subdomain?: bool (also every name under it), address_list?: name (answered addresses go into this firewall list for their TTL), disabled?: bool, comment?: string, place_before?: *hex} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.dns.static.set",
        "Set Static DNS Entry",
        [],
        None,
        "{id: *hex, name?: string, regexp?: string, type?: A | AAAA | CNAME | FWD | MX | NS | NXDOMAIN | SRV | TXT, address?: ip, cname?: name, forward_to?: [ip], mx_exchange?: name, mx_preference?: int, ns?: name, srv_target?: name, srv_port?: int, srv_priority?: int, srv_weight?: int, text?: string, ttl_secs?: int, match_subdomain?: bool, address_list?: name, disabled?: bool, comment?: string} → {id} (\"\" clears a field)",
        has_entries,
        set
    ),
    cmd!(
        "ip.dns.static.remove",
        "Remove Static DNS Entry",
        [],
        None,
        "{id: *hex} → {id}",
        has_entries,
        remove
    ),
    cmd!(
        "ip.dns.static.move",
        "Move Static DNS Entry",
        [],
        None,
        "{id: *hex, place_before?: *hex (absent: to the end)} → {id, position}",
        has_entries,
        move_entry
    ),
    cmd!(query "ip.dns.static.print", "DNS Static", ["IP", "DNS"], None,
        "{name?: string} → [{id, position, name?, regexp?, type, address?, cname?, forward_to?, mx_exchange?, mx_preference?, ns?, srv_target?, srv_port?, srv_priority?, srv_weight?, text?, ttl_secs, match_subdomain?, address_list?, disabled?, comment?, data, flags (X disabled)}]",
        always, print),
];

fn has_entries(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_static.entries.is_empty() {
        Err("there are no static DNS entries".into())
    } else {
        Ok(())
    }
}

fn position(s: &Session, id: ItemId, key: &str) -> Result<usize> {
    s.store()
        .candidate()
        .ip
        .dns_static
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| EngineError::bad(key, format!("no static DNS entry {id}")))
}

/// A host name field: lowercase, without the final dot; "" clears it.
fn host(p: &Value, key: &str) -> Result<Option<String>> {
    let Some(v) = opt_str(p, key)? else {
        return Ok(None);
    };
    let v = v.trim().trim_end_matches('.').to_ascii_lowercase();
    if !v.is_empty() && !host_name_ok(&v) {
        let shown: String = v.chars().take(64).collect();
        return Err(EngineError::bad(
            key,
            format!("'{shown}' is not a DNS name (letters, digits, - and _ in labels of 1..=63)"),
        ));
    }
    Ok(Some(v))
}

fn port(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| u16::try_from(v).map_err(|_| EngineError::bad(key, "must be 0..=65535")))
        .transpose()
}

fn forward_to(p: &Value) -> Result<Option<Vec<IpAddr>>> {
    let raw: Vec<String> = match p.get("forward_to") {
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
                    .ok_or_else(|| EngineError::bad("forward_to", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("forward_to", "must be a list of addresses")),
    };
    if raw.len() > MAX_FORWARD_TO {
        return Err(EngineError::bad(
            "forward_to",
            format!("at most {MAX_FORWARD_TO} servers (groups of forwarders: G4.1d)"),
        ));
    }
    let mut out = Vec::new();
    for s in raw {
        let shown: String = s.chars().take(64).collect();
        let ip: IpAddr = s
            .parse()
            .map_err(|_| EngineError::bad("forward_to", format!("'{shown}' is not an IP address")))?;
        if !usable_server(ip) {
            return Err(EngineError::bad(
                "forward_to",
                format!("{ip} cannot be a DNS server"),
            ));
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(Some(out))
}

/// Applies the fields given in `p` to `e`.
fn apply(e: &mut StaticEntry, p: &Value) -> Result<()> {
    if let Some(v) = host(p, "name")? {
        e.name = v;
    }
    if let Some(v) = opt_str(p, "regexp")? {
        if v.len() > MAX_REGEXP_LEN {
            return Err(EngineError::bad(
                "regexp",
                format!("at most {MAX_REGEXP_LEN} characters"),
            ));
        }
        if !v.is_empty() {
            corerouter_proto_dns::check_regexp(v).map_err(|why| EngineError::bad("regexp", why))?;
        }
        v.clone_into(&mut e.regexp);
    }
    if let Some(t) = opt_parse::<StaticType>(p, "type")? {
        e.rtype = t;
    }
    match opt_str(p, "address")? {
        Some("") => e.address = None,
        Some(_) => e.address = opt_parse(p, "address")?,
        None => {}
    }
    if let Some(v) = host(p, "cname")? {
        e.cname = v;
    }
    if let Some(v) = forward_to(p)? {
        e.forward_to = v;
    }
    if let Some(v) = host(p, "mx_exchange")? {
        e.mx_exchange = v;
    }
    if let Some(v) = port(p, "mx_preference")? {
        e.mx_preference = v;
    }
    if let Some(v) = host(p, "ns")? {
        e.ns = v;
    }
    if let Some(v) = host(p, "srv_target")? {
        e.srv_target = v;
    }
    if let Some(v) = port(p, "srv_port")? {
        e.srv_port = v;
    }
    if let Some(v) = port(p, "srv_priority")? {
        e.srv_priority = v;
    }
    if let Some(v) = port(p, "srv_weight")? {
        e.srv_weight = v;
    }
    if let Some(v) = opt_text(p, "text", MAX_TEXT_LEN)? {
        e.text = v;
    }
    if let Some(v) = opt_u32(p, "ttl_secs")? {
        if v > MAX_TTL_SECS {
            return Err(EngineError::bad(
                "ttl_secs",
                format!("must be at most {MAX_TTL_SECS} (RFC 2181 §8)"),
            ));
        }
        e.ttl_secs = v;
    }
    if let Some(v) = opt_bool(p, "match_subdomain")? {
        e.match_subdomain = v;
    }
    match opt_str(p, "address_list")? {
        Some("") => e.address_list.clear(),
        Some(_) => e.address_list = req_parse::<Name>(p, "address_list")?.as_str().to_owned(),
        None => {}
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        e.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        e.comment = v;
    }
    if let Some(why) = e.problem() {
        let key = if why.contains("name") && !why.contains("needs") {
            "name"
        } else {
            "type"
        };
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let at = match before {
        Some(id) => Some(position(s, id, "place_before")?),
        None => None,
    };
    if s.store().candidate().ip.dns_static.entries.len() >= MAX_ENTRIES {
        return Err(EngineError::bad(
            "name",
            format!("at most {MAX_ENTRIES} static DNS entries"),
        ));
    }
    let mut e = StaticEntry::new(ItemId(0));
    apply(&mut e, p)?;
    let st = &mut s.store_mut().candidate_mut().ip.dns_static;
    e.id = st.next_id();
    let id = e.id;
    match at {
        Some(i) => st.entries.insert(i, e),
        None => st.entries.push(e),
    }
    Ok(json!({ "id": id }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id, "id")?;
    let Some(mut e) = s.store().candidate().ip.dns_static.entries.get(i).cloned() else {
        return Err(EngineError::bad("id", format!("no static DNS entry {id}")));
    };
    apply(&mut e, p)?;
    if let Some(slot) = s.store_mut().candidate_mut().ip.dns_static.entries.get_mut(i) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id, "id")?;
    s.store_mut().candidate_mut().ip.dns_static.entries.remove(i);
    Ok(json!({ "id": id }))
}

fn move_entry(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let from = position(s, id, "id")?;
    if let Some(b) = before {
        position(s, b, "place_before")?;
    }
    let entries = &mut s.store_mut().candidate_mut().ip.dns_static.entries;
    let e = entries.remove(from);
    let to = before
        .and_then(|b| entries.iter().position(|x| x.id == b))
        .unwrap_or(entries.len());
    entries.insert(to, e);
    Ok(json!({ "id": id, "position": to }))
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "name")?.map(|n| n.trim().to_ascii_lowercase());
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dns_static
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            filter
                .as_ref()
                .is_none_or(|f| e.name.contains(f.as_str()) || e.regexp.contains(f.as_str()))
        })
        .filter_map(|(i, e)| {
            let mut v = serde_json::to_value(e).ok()?;
            let o = v.as_object_mut()?;
            o.insert("position".into(), json!(i));
            o.insert("data".into(), json!(e.data()));
            o.insert("flags".into(), json!(if e.disabled { "X" } else { "" }));
            Some(v)
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    #[test]
    fn add_set_move_remove() {
        let mut s = Session::virtual_lab();
        let a = run(
            &mut s,
            "ip.dns.static.add",
            json!({"name": "NAS.lan.", "address": "192.168.88.2"}),
        )
        .unwrap();
        let b = run(
            &mut s,
            "ip.dns.static.add",
            json!({"regexp": "^ads\\.", "type": "NXDOMAIN", "place_before": a["id"]}),
        )
        .unwrap();
        let rows = run(&mut s, "ip.dns.static.print", json!({})).unwrap();
        assert_eq!(rows[0]["id"], b["id"], "placed before");
        assert_eq!(rows[1]["name"], "nas.lan", "lowercase, no final dot");
        assert_eq!(rows[1]["data"], "192.168.88.2");
        assert_eq!(rows[1]["ttl_secs"], 86_400);
        run(
            &mut s,
            "ip.dns.static.set",
            json!({"id": a["id"], "type": "CNAME", "address": "", "cname": "files.lan", "disabled": true}),
        )
        .unwrap();
        let rows = run(&mut s, "ip.dns.static.print", json!({"name": "nas"})).unwrap();
        assert_eq!(rows[0]["type"], "CNAME");
        assert_eq!(rows[0]["flags"], "X");
        assert!(rows[0].get("address").is_none());
        run(&mut s, "ip.dns.static.move", json!({"id": b["id"]})).unwrap();
        let rows = run(&mut s, "ip.dns.static.print", json!({})).unwrap();
        assert_eq!(rows[1]["id"], b["id"], "moved to the end");
        run(&mut s, "ip.dns.static.remove", json!({"id": b["id"]})).unwrap();
        assert_eq!(s.store().candidate().ip.dns_static.entries.len(), 1);
    }

    #[test]
    fn bad_entries_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"address": "192.168.88.2"}),
            json!({"name": "a.lan", "regexp": ".*", "address": "192.168.88.2"}),
            json!({"name": "a.lan", "address": "2001:db8::1"}),
            json!({"name": "a.lan", "type": "AAAA", "address": "192.168.88.2"}),
            json!({"name": "bad name", "address": "192.168.88.2"}),
            json!({"regexp": "(unclosed", "type": "NXDOMAIN"}),
            json!({"name": "a.lan", "type": "FWD"}),
            json!({"name": "a.lan", "type": "FWD", "forward_to": "0.0.0.0"}),
            json!({"name": "a.lan", "type": "MX"}),
            json!({"name": "a.lan", "type": "BOGUS"}),
            json!({"name": "a.lan", "address": "192.168.88.2", "ttl_secs": 4_000_000_000u32}),
            json!({"name": "a.lan", "address": "192.168.88.2", "address_list": "bad list!"}),
            json!({"name": "a.lan", "address": "192.168.88.2", "place_before": "*99"}),
        ] {
            let err = s.execute("ip.dns.static.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(s.store().candidate().ip.dns_static.entries.is_empty());
    }

    #[test]
    fn rollback_drops_the_entry() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        s.execute(
            "ip.dns.static.add",
            &json!({"name": "x.lan", "type": "TXT", "text": "hello"}),
        )
        .unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.dns_static.entries.is_empty());
    }
}

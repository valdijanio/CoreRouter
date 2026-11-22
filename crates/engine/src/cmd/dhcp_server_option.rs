//! /ip dhcp-server option, option sets and matcher (G4.2a): extra options
//! in RouterOS' value syntax, grouped in sets, and chosen per server,
//! network, static lease, or by what the client sends (the v7 matcher:
//! its vendor class, say). Precedence when two give the same option:
//! lease > matcher > network > server.

use corerouter_model::dhcp_server::{Matcher, MatchingType, OptionDef, OptionSet};
use corerouter_proto_dhcp::server::checks::option_bytes;
use corerouter_proto_dhcp::v4::hex;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32};
use super::dhcp_server::{find, opt_ref, opt_strings, verdict};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-server.option.add",
        "Add DHCP Option",
        ["IP", "DHCP Server"],
        None,
        "{name: string, code: u32 (1..=254; not the server's own: 51, 53, 54, 58, 59, 61, 82), value: string (0x0a0b | 'text' | s'text' | '10.0.0.1' | '10' | $(HOSTNAME) | $(CLIENT_MAC), concatenated), force?: bool (send it even when the client did not ask, option 55), comment?: string} → {id, raw_value}",
        always,
        option_add
    ),
    cmd!(
        "ip.dhcp-server.option.set",
        "Set DHCP Option",
        [],
        None,
        "{id: *hex | name, name?: string, code?: u32, value?: string, force?: bool, comment?: string} → {id, raw_value}",
        has_options,
        option_set
    ),
    cmd!(
        "ip.dhcp-server.option.remove",
        "Remove DHCP Option",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_options,
        option_remove
    ),
    cmd!(query "ip.dhcp-server.option.print", "DHCP Options", [], None,
        "{} → [{id, name, code, value, raw_value (the bytes sent, 0x…; $(…) shown for a placeholder client), force, comment?, used_by}]",
        always, option_print),
    cmd!(
        "ip.dhcp-server.option-set.add",
        "Add Option Set",
        ["IP", "DHCP Server"],
        None,
        "{name: string, options: [string] | string (option names), comment?: string} → {id}",
        always,
        set_add
    ),
    cmd!(
        "ip.dhcp-server.option-set.set",
        "Set Option Set",
        [],
        None,
        "{id: *hex | name, name?: string, options?: [string] | string, comment?: string} → {id}",
        has_sets,
        set_set
    ),
    cmd!(
        "ip.dhcp-server.option-set.remove",
        "Remove Option Set",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_sets,
        set_remove
    ),
    cmd!(query "ip.dhcp-server.option-set.print", "DHCP Option Sets", [], None,
        "{} → [{id, name, options, comment?}]",
        always, set_print),
    cmd!(
        "ip.dhcp-server.matcher.add",
        "Add Matcher",
        ["IP", "DHCP Server"],
        None,
        "{name: string, server?: string (all, the default, or a server), code: u32 (the client's option to look at: 60 vendor class, 61, 12…), value: string (RouterOS option syntax: 'MSFT 5.0', 0x…), matching_type?: exact | substring (default exact), option_set?: string, address_pool?: string (a pool for these clients), disabled?: bool, comment?: string} → {id, warnings}",
        always,
        matcher_add
    ),
    cmd!(
        "ip.dhcp-server.matcher.set",
        "Set Matcher",
        [],
        None,
        "{id: *hex | name, name?: string, server?: string, code?: u32, value?: string, matching_type?: exact | substring, option_set?: string, address_pool?: string, disabled?: bool, comment?: string} → {id, warnings}",
        has_matchers,
        matcher_set
    ),
    cmd!(
        "ip.dhcp-server.matcher.remove",
        "Remove Matcher",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_matchers,
        matcher_remove
    ),
    cmd!(query "ip.dhcp-server.matcher.print", "DHCP Matchers", [], None,
        "{} → [{id, name, server, code, value, matching_type, option_set?, address_pool?, disabled, comment?}]",
        always, matcher_print),
];

fn has_options(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.options.is_empty() {
        Err("there are no DHCP options".into())
    } else {
        Ok(())
    }
}

fn has_sets(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.option_sets.is_empty() {
        Err("there are no option sets".into())
    } else {
        Ok(())
    }
}

fn has_matchers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.matchers.is_empty() {
        Err("there are no matchers".into())
    } else {
        Ok(())
    }
}

fn code(p: &Value) -> Result<Option<u8>> {
    match opt_u32(p, "code")? {
        None => Ok(None),
        Some(c) => u8::try_from(c)
            .ok()
            .filter(|c| (1..=254).contains(c))
            .map(Some)
            .ok_or_else(|| EngineError::bad("code", "1..=254")),
    }
}

fn name(p: &Value, required: bool) -> Result<Option<String>> {
    match opt_text(p, "name", 63)? {
        Some(n) if corerouter_model::ip_pool::name_ok(n.trim()) => Ok(Some(n.trim().to_owned())),
        Some(_) => Err(EngineError::bad("name", "letters, digits, '-', '_' and '.'; 1..=63")),
        None if required => Err(EngineError::bad("name", "is required")),
        None => Ok(None),
    }
}

/// Who names option or set `n` (servers, networks, leases, sets, matchers).
fn users(s: &Session, n: &str, set: bool) -> Vec<String> {
    let d = &s.store().candidate().ip.dhcp_server;
    let mut out = Vec::new();
    let named = |opts: &[String], s: &Option<String>| {
        if set {
            s.as_deref() == Some(n)
        } else {
            opts.iter().any(|o| o == n)
        }
    };
    for x in &d.servers {
        if named(&[], &x.dhcp_option_set) {
            out.push(format!("server {}", x.name));
        }
    }
    for x in &d.networks {
        if named(&x.dhcp_option, &x.dhcp_option_set) {
            out.push(format!("network {}", x.address));
        }
    }
    for x in &d.leases {
        if named(&x.dhcp_option, &x.dhcp_option_set) {
            out.push(format!("lease {}", x.address));
        }
    }
    for x in &d.matchers {
        if set && x.option_set.as_deref() == Some(n) {
            out.push(format!("matcher {}", x.name));
        }
    }
    if !set {
        for x in &d.option_sets {
            if x.options.iter().any(|o| o == n) {
                out.push(format!("option set {}", x.name));
            }
        }
    }
    out
}

fn raw(value: &str) -> String {
    option_bytes(value).map_or_else(|e| format!("invalid: {e}"), |b| hex(&b))
}

// ---- options ---------------------------------------------------------

fn option_apply(o: &mut OptionDef, p: &Value) -> Result<()> {
    if let Some(n) = name(p, false)? {
        o.name = n;
    }
    if let Some(c) = code(p)? {
        o.code = c;
    }
    if let Some(v) = opt_text(p, "value", corerouter_model::dhcp_server::MAX_VALUE_TEXT)? {
        option_bytes(&v).map_err(|e| EngineError::bad("value", e))?;
        o.value = v;
    }
    if let Some(b) = opt_bool(p, "force")? {
        o.force = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        o.comment = c;
    }
    Ok(())
}

fn option_add(s: &mut Session, p: &Value) -> Result<Value> {
    let n = name(p, true)?.unwrap_or_default();
    let c = code(p)?.ok_or_else(|| EngineError::bad("code", "is required"))?;
    if opt_str(p, "value")?.is_none() {
        return Err(EngineError::bad("value", "is required"));
    }
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.option(&n).is_some() {
        return Err(EngineError::bad("name", format!("option '{n}' exists")));
    }
    if d.options.len() >= corerouter_model::dhcp_server::MAX_OPTIONS {
        return Err(EngineError::bad("name", "too many options"));
    }
    let mut o = OptionDef {
        id: d.next_id(),
        name: n,
        code: c,
        value: String::new(),
        force: false,
        comment: String::new(),
    };
    option_apply(&mut o, p)?;
    let (id, value) = (o.id, o.value.clone());
    d.options.push(o);
    verdict(s, "options", id)?;
    Ok(json!({"id": id, "raw_value": raw(&value)}))
}

fn option_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.dhcp_server.options, p, |x| x.id, |x| Some(x.name.as_str()), "option")
}

fn option_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = option_index(s, p)?;
    let Some(mut o) = s.store().candidate().ip.dhcp_server.options.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such option"));
    };
    let old = o.name.clone();
    option_apply(&mut o, p)?;
    if o.name != old && !users(s, &old, false).is_empty() {
        return Err(EngineError::bad("name", format!("{} use it by name", users(s, &old, false).join(", "))));
    }
    let (id, value) = (o.id, o.value.clone());
    if let Some(slot) = s.store_mut().candidate_mut().ip.dhcp_server.options.get_mut(i) {
        *slot = o;
    }
    verdict(s, "options", id)?;
    Ok(json!({"id": id, "raw_value": raw(&value)}))
}

fn option_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = option_index(s, p)?;
    let Some(o) = s.store().candidate().ip.dhcp_server.options.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such option"));
    };
    let used = users(s, &o.name, false);
    if !used.is_empty() {
        return Err(EngineError::bad("id", format!("in use by {}", used.join(", "))));
    }
    s.store_mut().candidate_mut().ip.dhcp_server.options.remove(i);
    Ok(json!({"id": o.id, "name": o.name}))
}

fn option_print(s: &mut Session, _: &Value) -> Result<Value> {
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dhcp_server
        .options
        .iter()
        .map(|o| {
            let mut v = json!({
                "id": o.id, "name": o.name, "code": o.code, "value": o.value,
                "raw_value": raw(&o.value), "force": o.force,
                "used_by": users(s, &o.name, false),
            });
            if !o.comment.is_empty()
                && let Some(m) = v.as_object_mut()
            {
                m.insert("comment".into(), json!(o.comment));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- option sets -------------------------------------------------------

fn set_apply(o: &mut OptionSet, p: &Value) -> Result<()> {
    if let Some(n) = name(p, false)? {
        o.name = n;
    }
    if let Some(v) = opt_strings(p, "options")? {
        o.options = v;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        o.comment = c;
    }
    Ok(())
}

fn set_add(s: &mut Session, p: &Value) -> Result<Value> {
    let n = name(p, true)?.unwrap_or_default();
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.option_set(&n).is_some() {
        return Err(EngineError::bad("name", format!("option set '{n}' exists")));
    }
    if d.option_sets.len() >= corerouter_model::dhcp_server::MAX_OPTION_SETS {
        return Err(EngineError::bad("name", "too many option sets"));
    }
    let mut o = OptionSet {
        id: d.next_id(),
        name: n,
        options: Vec::new(),
        comment: String::new(),
    };
    set_apply(&mut o, p)?;
    let id = o.id;
    d.option_sets.push(o);
    verdict(s, "option_sets", id)?;
    Ok(json!({"id": id}))
}

fn set_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.dhcp_server.option_sets, p, |x| x.id, |x| Some(x.name.as_str()), "option set")
}

fn set_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = set_index(s, p)?;
    let Some(mut o) = s.store().candidate().ip.dhcp_server.option_sets.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such option set"));
    };
    let old = o.name.clone();
    set_apply(&mut o, p)?;
    if o.name != old && !users(s, &old, true).is_empty() {
        return Err(EngineError::bad("name", format!("{} use it by name", users(s, &old, true).join(", "))));
    }
    let id = o.id;
    if let Some(slot) = s.store_mut().candidate_mut().ip.dhcp_server.option_sets.get_mut(i) {
        *slot = o;
    }
    verdict(s, "option_sets", id)?;
    Ok(json!({"id": id}))
}

fn set_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = set_index(s, p)?;
    let Some(o) = s.store().candidate().ip.dhcp_server.option_sets.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such option set"));
    };
    let used = users(s, &o.name, true);
    if !used.is_empty() {
        return Err(EngineError::bad("id", format!("in use by {}", used.join(", "))));
    }
    s.store_mut().candidate_mut().ip.dhcp_server.option_sets.remove(i);
    Ok(json!({"id": o.id, "name": o.name}))
}

fn set_print(s: &mut Session, _: &Value) -> Result<Value> {
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dhcp_server
        .option_sets
        .iter()
        .map(|o| {
            let mut v = json!({"id": o.id, "name": o.name, "options": o.options});
            if !o.comment.is_empty()
                && let Some(m) = v.as_object_mut()
            {
                m.insert("comment".into(), json!(o.comment));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- matchers --------------------------------------------------------

fn matcher_apply(m: &mut Matcher, p: &Value) -> Result<()> {
    if let Some(n) = name(p, false)? {
        m.name = n;
    }
    if let Some(sv) = opt_ref(p, "server", &["all"])? {
        m.server = sv;
    }
    if let Some(c) = code(p)? {
        m.code = c;
    }
    if let Some(v) = opt_text(p, "value", corerouter_model::dhcp_server::MAX_VALUE_TEXT)? {
        option_bytes(&v).map_err(|e| EngineError::bad("value", e))?;
        m.value = v;
    }
    if let Some(t) = opt_parse::<MatchingType>(p, "matching_type")? {
        m.matching_type = t;
    }
    if let Some(v) = opt_ref(p, "option_set", &["none"])? {
        m.option_set = v;
    }
    if let Some(v) = opt_ref(p, "address_pool", &["none", "static-only"])? {
        m.address_pool = v;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        m.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        m.comment = c;
    }
    Ok(())
}

fn matcher_add(s: &mut Session, p: &Value) -> Result<Value> {
    let n = name(p, true)?.unwrap_or_default();
    let c = code(p)?.ok_or_else(|| EngineError::bad("code", "is required"))?;
    if opt_str(p, "value")?.is_none() {
        return Err(EngineError::bad("value", "is required"));
    }
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.matchers.iter().any(|m| m.name == n) {
        return Err(EngineError::bad("name", format!("matcher '{n}' exists")));
    }
    if d.matchers.len() >= corerouter_model::dhcp_server::MAX_MATCHERS {
        return Err(EngineError::bad("name", "too many matchers"));
    }
    let mut m = Matcher {
        id: d.next_id(),
        name: n,
        server: None,
        code: c,
        value: String::new(),
        matching_type: MatchingType::Exact,
        option_set: None,
        address_pool: None,
        disabled: false,
        comment: String::new(),
    };
    matcher_apply(&mut m, p)?;
    let id = m.id;
    d.matchers.push(m);
    let warnings = verdict(s, "matchers", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn matcher_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.dhcp_server.matchers, p, |x| x.id, |x| Some(x.name.as_str()), "matcher")
}

fn matcher_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = matcher_index(s, p)?;
    let Some(mut m) = s.store().candidate().ip.dhcp_server.matchers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such matcher"));
    };
    matcher_apply(&mut m, p)?;
    let id = m.id;
    if let Some(slot) = s.store_mut().candidate_mut().ip.dhcp_server.matchers.get_mut(i) {
        *slot = m;
    }
    let warnings = verdict(s, "matchers", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn matcher_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = matcher_index(s, p)?;
    let m = s.store_mut().candidate_mut().ip.dhcp_server.matchers.remove(i);
    Ok(json!({"id": m.id, "name": m.name}))
}

fn matcher_print(s: &mut Session, _: &Value) -> Result<Value> {
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dhcp_server
        .matchers
        .iter()
        .map(|m| {
            let mut v = json!({
                "id": m.id, "name": m.name,
                "server": m.server.clone().unwrap_or_else(|| "all".into()),
                "code": m.code, "value": m.value, "matching_type": m.matching_type.as_str(),
                "disabled": m.disabled,
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(x) = &m.option_set {
                    o.insert("option_set".into(), json!(x));
                }
                if let Some(x) = &m.address_pool {
                    o.insert("address_pool".into(), json!(x));
                }
                if !m.comment.is_empty() {
                    o.insert("comment".into(), json!(m.comment));
                }
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

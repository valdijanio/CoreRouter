//! The modal previews of `/routing ospf instance`, `area`, `area range`
//! and `keychain` (G3.4c): the change applied to a copy of the candidate,
//! validated, with what it does (the interfaces that change area, the
//! adjacencies that drop). Never an error for bad input: it becomes a
//! check, as the list-window pattern wants (`docs/ui-style.md`, G0.24).
//! The interface templates have their own (`routing_ospf_template.rs`).

use corerouter_model::Config;
use corerouter_model::types::ItemId;
use corerouter_proto_ospf::impact;
use serde_json::{Value, json};

use super::routing_ospf::{Given, given, text};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "routing.ospf.instance.check", "Check OSPF Instance", [], None,
        "{id?: string (the instance being edited), name?: string, version?: u8 | string, vrf?: string, router_id?: string | null, redistribute?: [string] | string, out_filter_chain?: string | null, originate_default?: string, subscriber_pools?: bool | yes | no, stub_router?: bool | yes | no, stub_router_on_startup?: u32 | string | null, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, instance_check),
    cmd!(query "routing.ospf.area.check", "Check OSPF Area", [], None,
        "{id?: string (the area being edited), name?: string, instance?: string, area_id?: string, type?: string, no_summaries?: bool | yes | no, default_cost?: u32 | string | null, nssa_translate?: string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, area_check),
    cmd!(query "routing.ospf.keychain.check", "Check OSPF Key Chain", [], None,
        "{id?: string (the key chain being edited), name?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, keychain_check),
    cmd!(query "routing.ospf.area.range.check", "Check OSPF Area Range", [], None,
        "{id?: string (*N), area?: string, prefix?: string, advertise?: bool | yes | no, cost?: u32 | string | null, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, range_check),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum What {
    Instance,
    Area,
    Range,
}

impl What {
    fn commands(self) -> (&'static str, &'static str) {
        match self {
            What::Instance => ("routing.ospf.instance.add", "routing.ospf.instance.set"),
            What::Area => ("routing.ospf.area.add", "routing.ospf.area.set"),
            What::Range => ("routing.ospf.area.range.add", "routing.ospf.area.range.set"),
        }
    }
}

fn check(level: &str, what: &str, message: String, param: &str) -> Value {
    json!({"level": level, "check": what, "message": message, "param": param})
}

/// The form's texts as the commands want them (yes/no → bool).
fn normalize(raw: &Value, editing: bool) -> Value {
    let mut p = raw.clone();
    if let Some(o) = p.as_object_mut() {
        if !editing {
            o.remove("id");
        }
        for (k, v) in o.iter_mut() {
            if let Value::String(t) = v
                && matches!(k.as_str(), "disabled" | "no_summaries" | "subscriber_pools" | "stub_router" | "advertise")
            {
                *v = Value::Bool(t == "yes" || t == "true");
            }
        }
    }
    p
}

fn preview(s: &mut Session, raw: &Value, what: What) -> Result<Value> {
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let id = match given(raw, "id") {
        Given::Value(v) => text("id", v).ok().map(str::to_owned),
        _ => None,
    };
    let p = normalize(raw, id.is_some());
    let mut cfg: Config = s.store().candidate().clone();
    let applied = match what {
        What::Instance => super::routing_ospf::apply_instance(&mut cfg.routing, &p, id.as_deref()).map(|n| (format!("routing.ospf.instances.{n}"), n)),
        What::Area => super::routing_ospf::apply_area(&mut cfg.routing, &p, id.as_deref()).map(|n| (format!("routing.ospf.areas.{n}"), n)),
        What::Range => {
            let rid = id.as_deref().and_then(|i| i.parse::<ItemId>().ok());
            super::routing_ospf::apply_range(&mut cfg.routing, &p, rid).map(|i| (format!("routing.ospf.ranges[{i}]"), i.to_string()))
        }
    };
    let (prefix, name) = match applied {
        Ok(x) => x,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null}));
        }
    };
    for issue in corerouter_proto_ospf::validate(&cfg) {
        if let Some(rest) = issue.path.strip_prefix(&prefix) {
            checks.push(check("error", "validate", issue.message, rest.trim_start_matches('.')));
        }
    }
    let binds = corerouter_proto_ospf::bind::bindings(&cfg);
    match what {
        What::Instance => {
            let n = binds.iter().filter(|b| b.instance.name == name).count();
            computed.push(json!({"label": "Interfaces", "value": n.to_string()}));
            if let Some(i) = cfg.routing.ospf.instances.get(&name) {
                if i.router_id.is_none() {
                    checks.push(check("warning", "router-id", "no fixed router id: the daemon picks one, and it changes when that address does (every adjacency restarts); set one (RFC 2328 §C.1)".into(), "router_id"));
                }
                if i.subscriber_pools {
                    let p = corerouter_proto_ospf::pools::cidrs(&cfg);
                    computed.push(json!({"label": "Pools announced", "value": if p.is_empty() { "none".to_owned() } else { p.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ") }}));
                }
                stub_router_checks(s, &cfg, i, &binds, &mut computed, &mut checks);
            }
        }
        What::Area => {
            let ifs: Vec<String> = binds.iter().filter(|b| b.area.name == name).map(|b| b.interface.to_string()).collect();
            computed.push(json!({"label": "Interfaces", "value": if ifs.is_empty() { "none".to_owned() } else { ifs.join(", ") }}));
            if let Some(a) = cfg.routing.ospf.areas.get(&name) {
                computed.push(json!({"label": "Area ID", "value": format!("{} ({})", a.area_id, if a.area_id.is_backbone() { "backbone" } else { a.kind.name() })}));
            }
        }
        What::Range => {}
    }
    let changes = impact::changes(s.store().running(), &cfg);
    let dropping = impact::dropping(&changes);
    for c in changes.iter().filter(|c| !c.drops) {
        checks.push(check("info", c.what, c.message.clone(), ""));
    }
    let risk = (!dropping.is_empty()).then(|| {
        let msgs: Vec<&str> = changes.iter().filter(|c| c.drops).map(|c| c.message.as_str()).take(6).collect();
        format!(
            "the OSPF adjacencies on {} go down: {}. Use Safe Mode to roll back on its own if this cuts the session",
            dropping.join(", "),
            msgs.join("; ")
        )
    });
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    let (add, set) = what.commands();
    let mut params = p;
    if let Some(o) = params.as_object_mut()
        && id.as_deref() == o.get("name").and_then(Value::as_str)
    {
        o.remove("name");
    }
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": if id.is_some() { set } else { add }, "params": params})] } else { Vec::new() },
        "risk": risk,
    }))
}

/// G3.9c: what the stub router (RFC 6987) of instance `i` does and where
/// it does not do what the operator expects.
fn stub_router_checks(
    s: &Session,
    cfg: &Config,
    i: &corerouter_model::ospf::OspfInstance,
    binds: &[corerouter_proto_ospf::bind::Binding<'_>],
    computed: &mut Vec<Value>,
    checks: &mut Vec<Value>,
) {
    use corerouter_model::ospf::{NetworkType, Version};
    if !i.stub_router && i.stub_router_on_startup.is_none() {
        return;
    }
    let transit = binds.iter().filter(|b| b.instance.name == i.name && !b.template.passive).count();
    computed.push(json!({"label": "Stub router", "value": match (i.stub_router, i.stub_router_on_startup) {
        (true, _) if i.version == Version::V3 => format!("{transit} transit link(s) with the R-bit cleared (RFC 6987 §2.1): never transit, not even as the only path"),
        (true, None) => format!("{transit} transit link(s) at cost 65535 until stub_router is unset; loopback and passive networks keep their cost (RFC 6987 §2)"),
        (true, Some(t)) => format!("{transit} transit link(s) at cost 65535 until stub_router is unset (and {t} s after each start); loopback and passive networks keep their cost (RFC 6987 §2)"),
        (false, Some(t)) => format!("{transit} transit link(s) at cost 65535 for {t} s after each start of the instance"),
        (false, None) => String::new(),
    }}));
    // Errata 4685 (RFC 6987 §4): a virtual link whose path crosses a stub
    // router costs more than 0xFFFF and goes down.
    let vlinks = cfg.routing.ospf.templates.iter().filter(|t| {
        !t.disabled
            && t.kind == NetworkType::VirtualLink
            && t.vlink_transit_area
                .as_deref()
                .and_then(|a| cfg.routing.ospf.areas.get(a))
                .is_some_and(|a| a.instance == i.name)
    });
    if vlinks.count() > 0 {
        checks.push(check("warning", "virtual-link", "a virtual link of this instance crosses this router: while it is a stub router the path costs more than 65535 and the virtual link goes down (RFC 6987 errata 4685)".into(), "stub_router"));
    }
    // §4: MaxLinkMetric is not infinity: with no other path the router
    // still carries the transit.
    let (nbrs, _, _) = s.ospf_live();
    let full = nbrs.iter().filter(|n| n.instance == i.name && n.state.starts_with("Full")).count();
    if full < 2 {
        checks.push(check("info", "single-path", format!("{full} adjacency(ies) up: where this router is the only path, traffic still crosses it (cost 65535 is not infinity, RFC 6987 §4)"), "stub_router"));
    }
    // ospfd arms on-startup at each area's first router-LSA (FRR 10.7.1
    // `ospf_stub_router_check`): added to a running instance it waits for
    // the next start.
    let before = s.store().running().routing.ospf.instances.get(&i.name);
    if let (Some(t), Some(old)) = (i.stub_router_on_startup, before)
        && old.stub_router_on_startup.is_none()
        && !old.disabled
    {
        checks.push(check("info", "on-startup", format!("the instance already runs: the {t} s apply at its next start (reboot, FRR restart or disable/enable), not now; use stub_router to drain now"), "stub_router_on_startup"));
    }
}

fn instance_check(s: &mut Session, p: &Value) -> Result<Value> {
    preview(s, p, What::Instance)
}

fn area_check(s: &mut Session, p: &Value) -> Result<Value> {
    preview(s, p, What::Area)
}

fn range_check(s: &mut Session, p: &Value) -> Result<Value> {
    preview(s, p, What::Range)
}

/// A key chain is a name and a comment here (its keys have their own
/// commands): the name's shape, and who uses it.
fn keychain_check(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut checks = Vec::new();
    let id = match given(raw, "id") {
        Given::Value(v) => text("id", v).ok().map(str::to_owned),
        _ => None,
    };
    let name = match given(raw, "name") {
        Given::Value(v) => text("name", v).unwrap_or("").to_owned(),
        _ => id.clone().unwrap_or_default(),
    };
    let ospf = &s.store().candidate().routing.ospf;
    if !corerouter_proto_ospf::name_ok(&name) {
        checks.push(check("error", "params", "1..=48 characters of [A-Za-z0-9_.-]".into(), "name"));
    } else if id.as_deref() != Some(name.as_str()) && ospf.keychains.contains_key(&name) {
        checks.push(check("error", "params", format!("key chain {name:?} already exists"), "name"));
    }
    let users: Vec<String> = ospf
        .templates
        .iter()
        .filter(|t| id.is_some() && t.keychain.as_deref() == id.as_deref())
        .map(|t| t.id.to_string())
        .collect();
    let computed = vec![json!({"label": "Used by", "value": if users.is_empty() { "no template".to_owned() } else { users.join(", ") }})];
    if id.is_none() {
        checks.push(check("info", "keys", "add its keys with routing.ospf.keychain.key.add (sha256 by default)".into(), ""));
    }
    let ok = checks.iter().all(|c| c.get("level").and_then(Value::as_str) != Some("error"));
    let p = normalize(raw, id.is_some());
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": if id.is_some() { "routing.ospf.keychain.set" } else { "routing.ospf.keychain.add" }, "params": p})] } else { Vec::new() },
        "risk": null,
    }))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    use crate::Session;

    #[test]
    fn previews_say_what_changes() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        let c = s.execute("routing.ospf.instance.check", &json!({"name": "v2"})).unwrap();
        assert_eq!(c["commands"][0]["command"], "routing.ospf.instance.add");
        assert!(serde_json::to_string(&c["checks"]).unwrap().contains("router-id"));
        s.execute("routing.ospf.instance.add", &json!({"name": "v2", "router_id": "10.0.0.1"})).unwrap();
        let c = s.execute("routing.ospf.area.check", &json!({"name": "bb", "instance": "v2", "area_id": "0", "type": "stub"})).unwrap();
        assert_eq!(c["checks"][0]["level"], "error", "{c}");
        assert!(c["commands"].as_array().unwrap().is_empty());
        let c = s.execute("routing.ospf.area.check", &json!({"name": "bb", "instance": "nope", "area_id": "0"})).unwrap();
        assert_eq!(c["checks"][0]["param"], "instance");
        // Changing the router id drops every adjacency: a risk.
        s.execute("ip.address.add", &json!({"address": "10.0.1.1/24", "interface": "ether1"})).unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "bb", "instance": "v2", "area_id": "0"})).unwrap();
        s.execute("routing.ospf.interface-template.add", &json!({"area": "bb", "interfaces": "ether1", "auth_key": "k"})).unwrap();
        let c = s.execute("routing.ospf.instance.check", &json!({"id": "v2", "router_id": "10.0.0.2"})).unwrap();
        assert!(c["risk"].as_str().unwrap().contains("router id"), "{c}");
    }

    /// G3.9c: the stub router preview: what it changes, the single path,
    /// on-startup added to a running instance, a virtual link across it.
    #[test]
    fn stub_router_preview() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("ip.address.add", &json!({"address": "10.0.1.1/24", "interface": "ether1"})).unwrap();
        s.execute("routing.ospf.instance.add", &json!({"name": "v2", "router_id": "10.0.0.1"})).unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "bb", "instance": "v2", "area_id": "0"})).unwrap();
        s.execute("routing.ospf.interface-template.add", &json!({"area": "bb", "interfaces": "ether1"})).unwrap();
        let c = s.execute("routing.ospf.instance.check", &json!({"id": "v2", "stub_router": "yes"})).unwrap();
        let text = c.to_string();
        assert!(text.contains("1 transit link(s) at cost 65535"), "{c}");
        assert!(text.contains("RFC 6987 §4"), "{c}");
        assert!(!text.contains("next start"), "{c}");
        assert_eq!(c["commands"][0]["params"]["stub_router"], true, "{c}");
        let c = s.execute("routing.ospf.instance.check", &json!({"id": "v2", "stub_router_on_startup": "300"})).unwrap();
        assert!(c.to_string().contains("next start"), "{c}");
        // A new instance has no such note.
        let c = s.execute("routing.ospf.instance.check", &json!({"name": "v2b", "stub_router_on_startup": "300"})).unwrap();
        assert!(!c.to_string().contains("next start"), "{c}");
        s.execute("routing.ospf.area.add", &json!({"name": "a1", "instance": "v2", "area_id": "1"})).unwrap();
        s.execute("routing.ospf.interface-template.add", &json!({"area": "bb", "type": "virtual-link", "vlink_transit_area": "a1", "vlink_neighbor_id": "10.0.0.9"}))
            .unwrap();
        let c = s.execute("routing.ospf.instance.check", &json!({"id": "v2", "stub_router": true})).unwrap();
        assert!(c.to_string().contains("errata 4685"), "{c}");
        let c = s.execute("routing.ospf.instance.check", &json!({"id": "v2", "stub_router_on_startup": "2"})).unwrap();
        assert_eq!(c["checks"][0]["param"], "stub_router_on_startup", "{c}");
    }
}

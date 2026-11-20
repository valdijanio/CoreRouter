//! /routing management-guard (G3.4z): the networks the router is managed
//! from, which no learned route may cut into (`corerouter_model::mgmt_guard`;
//! the check of the open sessions is `crate::mgmt_guard`). The routing
//! daemon refuses, from every protocol, a prefix inside a network here and
//! longer than it (FRR zebra `ip protocol any route-map`); the window shows
//! what it refuses, read from the daemon's RIB.

use corerouter_model::mgmt_guard::{GuardNetwork, MAX_NETWORKS};
use corerouter_model::{Config, ItemId};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::lockout::take_force;
use crate::mgmt_guard::{RibView, by_protocol, protect_command, refused};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.management-guard.add", "Add Management Guard Network", ["Routing", "Management Guard"], None,
        "{network: cidr (a network the router is managed from; host bits are cleared; not a /32 or /128), disabled?: bool, comment?: string} → {id, network}",
        always, add),
    cmd!("routing.management-guard.set", "Set Management Guard Network", [], None,
        "{id: *hex, network?: cidr, disabled?: bool, comment?: string, force?: bool (takes away the guard of this session's own network all the same)} → {id, network}",
        has_networks, set),
    cmd!("routing.management-guard.remove", "Remove Management Guard Network", [], None,
        "{id: *hex, force?: bool (takes away the guard of this session's own network all the same)} → {id}",
        has_networks, remove),
    cmd!(query "routing.management-guard.list", "Management Guard", ["Routing", "Management Guard"], None,
        "{} → {watching: bool (the daemon looks up the open sessions' routes), rows: [{id, network, family (ipv4 | ipv6), interface? (the connected network's port), connected: bool, sessions (open management sessions whose peer is inside), covered (of them, whose replies a learned route takes now), refused?: u32 (learned routes inside and longer the daemon holds and keeps out of the kernel), refused_text?, installed?: u32 (of them, in the kernel: the guard is not in force), rib: ready | pending | unavailable, rib_error?, state (active | disabled | not-applied), disabled, comment}], findings: [{peer, route, protocol, interface?, gateway?, connected, connected_interface, sessions: [{via, user, peer}], guarded, text, fix?}]}",
        always, list),
    cmd!(query "routing.management-guard.suggest", "Management Networks", [], None,
        "{} → [{network, interface, sessions: [{via, user, peer}], covered: bool (a learned route takes the replies now), guarded: bool, command (what protects it)}]",
        always, suggest),
    cmd!(query "routing.management-guard.check", "Check Management Guard Network", [], None,
        "{id?: string (the network being edited), network?: string, disabled?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param?}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, check),
];

fn has_networks(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.management_guard.is_empty() {
        Err("no management guard network (routing.management-guard.add)".into())
    } else {
        Ok(())
    }
}

/// `network` as the guard keeps it, or why not.
fn parse_network(text: &str) -> std::result::Result<IpNet, String> {
    let net: IpNet = text
        .trim()
        .parse()
        .map_err(|_| format!("'{}' is not a network (192.168.0.0/24)", text.chars().take(64).collect::<String>()))?;
    if net.prefix_len() == net.max_prefix_len() {
        return Err(format!("{net} is one address: no route is more specific, there is nothing to guard"));
    }
    if net.prefix_len() == 0 {
        return Err("0.0.0.0/0 or ::/0 would refuse every learned route; name the management network".into());
    }
    Ok(net.trunc())
}

fn position(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.routing
        .management_guard
        .networks
        .iter()
        .position(|n| n.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no management guard network {id} (see routing.management-guard.list)")))
}

fn duplicate(cfg: &Config, net: &IpNet, except: Option<ItemId>) -> Result<()> {
    if let Some(n) = cfg
        .routing
        .management_guard
        .networks
        .iter()
        .find(|n| n.network == *net && Some(n.id) != except)
    {
        return Err(EngineError::bad("network", format!("{net} is already guarded ({})", n.id)));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let text: String = req_parse(p, "network")?;
    let net = parse_network(&text).map_err(|e| EngineError::bad("network", e))?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    duplicate(cfg, &net, None)?;
    let g = &mut cfg.routing.management_guard;
    if g.networks.len() >= MAX_NETWORKS {
        return Err(EngineError::bad("network", format!("at most {MAX_NETWORKS} guarded networks")));
    }
    g.next_id = g.next_id.saturating_add(1);
    let id = ItemId(g.next_id);
    g.networks.push(GuardNetwork { id, network: net, disabled, comment });
    Ok(json!({ "id": id, "network": net }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let net = match opt_parse::<String>(p, "network")? {
        Some(t) => Some(parse_network(&t).map_err(|e| EngineError::bad("network", e))?),
        None => None,
    };
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let at = position(cfg, id)?;
    if let Some(n) = &net {
        duplicate(cfg, n, Some(id))?;
    }
    let Some(entry) = cfg.routing.management_guard.networks.get_mut(at) else {
        return Err(EngineError::bad("id", format!("no management guard network {id}")));
    };
    if let Some(n) = net {
        entry.network = n;
    }
    if let Some(d) = disabled {
        entry.disabled = d;
    }
    if let Some(c) = comment {
        entry.comment = c;
    }
    let network = entry.network;
    Ok(json!({ "id": id, "network": network }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let at = position(cfg, id)?;
    cfg.routing.management_guard.networks.remove(at);
    Ok(json!({ "id": id }))
}

/// Whether the routing daemon runs `net`'s guard: the running config has
/// it active (a candidate not yet committed does not).
fn applied(s: &Session, net: &IpNet) -> bool {
    s.store().running().routing.management_guard.active().any(|n| n == net)
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let networks = s.store().candidate().routing.management_guard.networks.clone();
    let mgmt = s.mgmt_guard_networks();
    let findings = s.mgmt_guard_findings();
    let mut rows = Vec::with_capacity(networks.len());
    for n in &networks {
        let inside: Vec<_> = mgmt.iter().filter(|(c, _, _)| n.network.contains(c)).collect();
        let iface = mgmt
            .iter()
            .find(|(c, _, _)| *c == n.network)
            .map(|(_, i, _)| i.to_string())
            .or_else(|| connected_port(s.store().running(), &n.network));
        let sessions: usize = inside.iter().map(|(_, _, w)| w.len()).sum();
        let covered: usize = findings
            .iter()
            .filter(|f| n.network.contains(&f.peer))
            .map(|f| f.sessions.len())
            .sum();
        let state = if n.disabled {
            "disabled"
        } else if applied(s, &n.network) {
            "active"
        } else {
            "not-applied"
        };
        let mut row = json!({
            "id": n.id,
            "network": n.network,
            "family": if n.network.addr().is_ipv4() { "ipv4" } else { "ipv6" },
            "interface": iface,
            "connected": iface.is_some(),
            "sessions": sessions,
            "covered": covered,
            "state": state,
            "disabled": n.disabled,
            "comment": n.comment,
        });
        let view = if n.disabled { None } else { Some(s.mgmt_guard_rib(n.network)) };
        if let Some(o) = row.as_object_mut() {
            match view {
                Some(RibView::Ready(rib)) => {
                    let (hit, installed) = refused(&n.network, &rib);
                    o.insert("rib".into(), json!("ready"));
                    o.insert("refused".into(), json!(hit.len()));
                    o.insert("refused_text".into(), json!(by_protocol(&hit)));
                    o.insert("installed".into(), json!(installed));
                }
                Some(RibView::Pending) => {
                    o.insert("rib".into(), json!("pending"));
                }
                Some(RibView::Unavailable(e)) => {
                    o.insert("rib".into(), json!("unavailable"));
                    o.insert("rib_error".into(), json!(e));
                }
                None => {}
            }
        }
        rows.push(row);
    }
    Ok(json!({
        "watching": s.mgmt_guard_watching(),
        "rows": rows,
        "findings": crate::mgmt_guard::summary(s).as_array().cloned().unwrap_or_default(),
    }))
}

/// The port of the connected network `net` exactly (any table).
fn connected_port(cfg: &Config, net: &IpNet) -> Option<String> {
    cfg.ip
        .addresses
        .iter()
        .find(|a| a.from_pool.is_none() && a.address.trunc() == *net)
        .map(|a| a.interface.to_string())
}

fn suggest(s: &mut Session, _: &Value) -> Result<Value> {
    let guard = s.store().candidate().routing.management_guard.clone();
    let findings = s.mgmt_guard_findings();
    let rows: Vec<Value> = s
        .mgmt_guard_networks()
        .into_iter()
        .map(|(net, iface, who)| {
            json!({
                "network": net,
                "interface": iface,
                "covered": findings.iter().any(|f| f.connected == net),
                "guarded": guard.active().any(|g| g.contains(&net)),
                "command": protect_command(&net),
                "sessions": who,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn check(s: &mut Session, raw: &Value) -> Result<Value> {
    let text = |k: &str| raw.get(k).and_then(Value::as_str).map_or("", str::trim).to_owned();
    let (id, network, comment) = (text("id"), text("network"), text("comment"));
    let disabled = matches!(text("disabled").as_str(), "yes" | "true");
    let item = |level: &str, check: &str, message: String, param: Option<&str>| {
        let mut v = json!({"level": level, "check": check, "message": message});
        if let (Some(p), Some(o)) = (param, v.as_object_mut()) {
            o.insert("param".into(), json!(p));
        }
        v
    };
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    let editing: Option<ItemId> = if id.is_empty() { None } else { id.parse().ok() };
    let net = match parse_network(&network) {
        Ok(n) => n,
        Err(_) if network.is_empty() => {
            checks.push(item("error", "param", "type the network the router is managed from (192.168.0.0/24)".into(), Some("network")));
            return Ok(json!({"computed": computed, "checks": checks, "commands": commands}));
        }
        Err(e) => {
            checks.push(item("error", "param", e, Some("network")));
            return Ok(json!({"computed": computed, "checks": checks, "commands": commands}));
        }
    };
    let cfg = s.store().candidate();
    if let Some(n) = cfg.routing.management_guard.networks.iter().find(|n| n.network == net && Some(n.id) != editing) {
        checks.push(item("error", "duplicate", format!("{net} is already guarded ({})", n.id), Some("network")));
    }
    let last = match net {
        IpNet::V4(n) => n.broadcast().to_string(),
        IpNet::V6(n) => n.broadcast().to_string(),
    };
    computed.push(json!({"label": "Refuses", "value": format!("learned prefixes inside {net} longer than /{}", net.prefix_len())}));
    computed.push(json!({"label": "Range", "value": format!("{} – {last}", net.network())}));
    match connected_port(s.store().running(), &net) {
        Some(port) => computed.push(json!({"label": "Connected on", "value": port})),
        None => checks.push(item(
            "warning",
            "not-connected",
            format!("{net} is not a connected network of the router: the guard still refuses the learned routes inside it, which is what you want only for a management network reached through a static route"),
            Some("network"),
        )),
    }
    let mgmt = s.mgmt_guard_networks();
    let here: usize = mgmt.iter().filter(|(c, _, _)| net.contains(c)).map(|(_, _, w)| w.len()).sum();
    if here > 0 {
        checks.push(item("ok", "sessions", format!("{here} open management session(s) come from inside {net}"), None));
    }
    if s.mgmt_guard_findings().iter().any(|f| net.contains(&f.peer)) {
        checks.push(item("warning", "covered", format!("a learned route takes the replies to a session inside {net} now: this guard takes it out"), None));
    }
    if !disabled {
        match s.mgmt_guard_rib(net) {
            RibView::Ready(rib) => {
                let (hit, installed) = refused(&net, &rib);
                computed.push(json!({"label": "Learned routes refused now", "value": by_protocol(&hit)}));
                if installed > 0 {
                    let first: Vec<String> = hit.iter().filter(|r| r.installed).take(5).map(|r| format!("{} ({})", r.prefix, r.protocol)).collect();
                    checks.push(item("info", "installed", format!("{installed} of them in the kernel now, leaving it: {}", first.join(", ")), None));
                }
            }
            RibView::Pending => checks.push(item("pending", "rib", "reading the routing daemon's routes inside it…".into(), None)),
            RibView::Unavailable(e) => checks.push(item("info", "rib", format!("cannot count the learned routes it would refuse: {e}"), None)),
        }
    }
    let mut p = json!({"network": net.to_string()});
    if let Some(o) = p.as_object_mut() {
        if !comment.is_empty() {
            o.insert("comment".into(), json!(comment));
        }
        if disabled {
            o.insert("disabled".into(), json!(true));
        }
    }
    let command = match editing {
        Some(id) => {
            if let Some(o) = p.as_object_mut() {
                o.insert("id".into(), json!(id));
                o.insert("comment".into(), json!(comment));
                o.insert("disabled".into(), json!(disabled));
            }
            "routing.management-guard.set"
        }
        None => "routing.management-guard.add",
    };
    commands.push(json!({"command": command, "params": p}));
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

#[cfg(test)]
mod tests {
    use corerouter_model::mgmt_guard::RibRoute;
    use corerouter_model::routing_state::RoutingStatus;
    use serde_json::json;

    use crate::mgmt_guard::tests::{lab, learned, operator};
    use crate::Session;

    fn rows(s: &mut Session) -> Vec<serde_json::Value> {
        s.execute("routing.management-guard.list", &json!({})).unwrap()["rows"].as_array().unwrap().clone()
    }

    #[test]
    fn a_network_is_added_set_and_removed() {
        let mut s = lab();
        let a = s.execute("routing.management-guard.add", &json!({"network": "192.168.0.77/24", "comment": "casa"})).unwrap();
        assert_eq!(a["network"], "192.168.0.0/24", "host bits cleared");
        let r = rows(&mut s);
        assert_eq!((r[0]["state"].as_str(), r[0]["interface"].as_str(), r[0]["rib"].as_str()), (Some("active"), Some("ether1"), Some("unavailable")));
        s.execute("routing.management-guard.set", &json!({"id": a["id"], "disabled": true})).unwrap();
        assert_eq!(rows(&mut s)[0]["state"], "disabled");
        s.execute("routing.management-guard.remove", &json!({"id": a["id"]})).unwrap();
        assert!(rows(&mut s).is_empty());
        assert!(s.store().running().routing.management_guard.is_empty());
    }

    #[test]
    fn bad_networks_are_refused() {
        let mut s = lab();
        for (net, says) in [("192.168.0.1/32", "one address"), ("0.0.0.0/0", "every learned route"), ("x", "not a network"), ("2001:db8::1/128", "one address")] {
            let e = s.execute("routing.management-guard.add", &json!({"network": net})).unwrap_err().to_string();
            assert!(e.contains(says), "{net}: {e}");
        }
        s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24"})).unwrap();
        let e = s.execute("routing.management-guard.add", &json!({"network": "192.168.0.9/24"})).unwrap_err().to_string();
        assert!(e.contains("already guarded"), "{e}");
        let e = s.execute("routing.management-guard.remove", &json!({"id": "*9"})).unwrap_err().to_string();
        assert!(e.contains("no management guard network"), "{e}");
        assert!(s.execute("routing.management-guard.add", &json!({"network": "10.0.0.0/8", "bogus": 1})).is_err());
    }

    #[test]
    fn a_discarded_candidate_takes_the_network_away() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24"})).unwrap();
        assert_eq!(rows(&mut s)[0]["state"], "not-applied", "not committed yet");
        s.execute("config.discard", &json!({})).unwrap();
        assert!(rows(&mut s).is_empty());
        // And a commit's rollback brings it back out.
        s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24"})).unwrap();
        let before = s.store().current_revision();
        s.execute("config.commit", &json!({})).unwrap();
        s.execute("config.rollback", &json!({"revision": before})).unwrap();
        s.execute("config.commit", &json!({})).unwrap();
        assert!(s.store().running().routing.management_guard.is_empty());
    }

    #[test]
    fn suggest_names_the_network_of_the_open_sessions() {
        let mut s = lab();
        s.execute_as(&operator(3, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        let v = s.execute("routing.management-guard.suggest", &json!({})).unwrap();
        assert_eq!(v[0]["network"], "192.168.0.0/24", "{v}");
        assert_eq!(v[0]["command"], "routing.management-guard.add {\"network\":\"192.168.0.0/24\"}");
        assert_eq!(v[0]["guarded"], false);
        // The button runs the command it shows.
        s.execute("routing.management-guard.add", &json!({"network": v[0]["network"]})).unwrap();
        let v = s.execute("routing.management-guard.suggest", &json!({})).unwrap();
        assert_eq!(v[0]["guarded"], true);
        assert_eq!(rows(&mut s)[0]["sessions"], 1);
    }

    #[test]
    fn the_check_counts_what_it_would_refuse() {
        let mut s = lab();
        let c = s.execute("routing.management-guard.check", &json!({"network": "192.168.0.0/32"})).unwrap();
        assert_eq!(c["checks"][0]["level"], "error", "{c}");
        assert!(c["commands"].as_array().unwrap().is_empty());
        let c = s.execute("routing.management-guard.check", &json!({"network": "172.16.0.0/16"})).unwrap();
        assert!(c.to_string().contains("not-connected"), "{c}");
        // With a routing daemon: pending, then the count from its RIB.
        let _ = s.set_routing_status(RoutingStatus { backend: "frr 10.7.1".into(), ..Default::default() });
        let c = s.execute("routing.management-guard.check", &json!({"network": "192.168.0.0/24"})).unwrap();
        assert!(c.to_string().contains("pending"), "{c}");
        let wanted = s.mgmt_guard_rib_wanted();
        assert_eq!(wanted.len(), 1);
        let r = |p: &str, proto: &str, installed: bool| RibRoute { prefix: p.parse().unwrap(), protocol: proto.into(), installed, inactive: !installed, via: String::new() };
        s.mgmt_guard_set_rib(wanted[0], Ok(vec![r("192.168.0.0/24", "connected", true), r("192.168.0.2/32", "ospf", true), r("192.168.0.0/25", "bgp", true)]));
        let c = s.execute("routing.management-guard.check", &json!({"network": "192.168.0.0/24"})).unwrap();
        let text = c.to_string();
        assert!(text.contains("2 (bgp 1, ospf 1)") && text.contains("2 of them in the kernel"), "{c}");
        assert_eq!(c["commands"][0]["command"], "routing.management-guard.add");
    }

    #[test]
    fn taking_away_the_guard_of_ones_own_session_is_a_lockout() {
        let mut s = lab();
        let a = s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24"})).unwrap();
        let _ = s.set_routing_status(RoutingStatus { backend: "frr 10.7.1".into(), ..Default::default() });
        let _ = s.execute("routing.management-guard.list", &json!({}));
        let net = s.mgmt_guard_rib_wanted()[0];
        let route = |p: &str| RibRoute { prefix: p.parse().unwrap(), protocol: "ospf".into(), installed: false, inactive: true, via: String::new() };
        s.mgmt_guard_set_rib(net, Ok(vec![route("192.168.0.2/32")]));
        let me = operator(3, "192.168.0.2", "GUI");
        let e = s.execute_as(&me, "routing.management-guard.remove", &json!({"id": a["id"]})).unwrap_err().to_string();
        assert!(e.contains("lockout") && e.contains("192.168.0.2/32 (ospf)"), "{e}");
        let e = s.execute_as(&me, "routing.management-guard.set", &json!({"id": a["id"], "disabled": true})).unwrap_err().to_string();
        assert!(e.contains("lockout"), "{e}");
        assert_eq!(s.store().running().routing.management_guard.networks.len(), 1, "nothing changed");
        // Another peer is not cut; force does it all the same.
        let other = operator(4, "192.168.0.9", "GUI");
        s.execute_as(&other, "routing.management-guard.set", &json!({"id": a["id"], "comment": "x"})).unwrap();
        s.execute_as(&me, "routing.management-guard.remove", &json!({"id": a["id"], "force": true})).unwrap();
        assert!(s.store().running().routing.management_guard.is_empty());
        let _ = learned;
    }

    #[test]
    fn the_health_check_warns_and_says_how_to_fix() {
        let mut s = lab();
        s.execute_as(&operator(3, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        let pairs = s.mgmt_guard_probes();
        s.mgmt_guard_feed(pairs.iter().map(|p| (*p, Ok(learned("198.51.100.0/24", 188)))).collect());
        let h = s.execute("system.health.check", &json!({})).unwrap();
        let c = h["checks"].as_array().unwrap().iter().find(|c| c["key"] == "management.route").unwrap().clone();
        assert_eq!(c["severity"], "ok", "{c}");
        s.mgmt_guard_feed(pairs.iter().map(|p| (*p, Ok(learned("192.168.0.2/32", 188)))).collect());
        let h = s.execute("system.health.check", &json!({})).unwrap();
        let c = h["checks"].as_array().unwrap().iter().find(|c| c["key"] == "management.route").unwrap().clone();
        assert_eq!(c["severity"], "warning", "{c}");
        assert!(c["action"].as_str().unwrap().contains("routing.management-guard.add {\"network\":\"192.168.0.0/24\"}"), "{c}");
        let sum = s.inspect(None).unwrap();
        assert_eq!(sum["management_route"][0]["peer"], "192.168.0.2", "{sum}");
    }
}

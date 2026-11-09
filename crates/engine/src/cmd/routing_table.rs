//! /routing table (G1.27e): named kernel tables for policy routing. Routes
//! go in with `routing_table: <name>`; `/routing rule` and a mangle routing
//! mark of the same name send packets there. `routing.table.list` also shows
//! `main` and the VRFs, as RouterOS does (dynamic, not removable here).

use std::collections::BTreeMap;

use corerouter_model::firewall::Action;
use corerouter_model::route::{MAIN_TABLE_ID, free_table, is_vrf_table, tables_by_id};
use corerouter_model::routing_table::{MAX_TABLES, NamedTable, RESERVED};
use corerouter_model::{Config, IfName, RoutingTable};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.table.add", "Add Routing Table", ["Routing", "Tables"], None,
        "{name: string (1..=15 of A-Z a-z 0-9 - _ .), fib?: bool (RouterOS' flag: every table here is in the FIB, false is refused), comment?: string} → {name, table (kernel id)}",
        always, add),
    cmd!("routing.table.set", "Set Routing Table", [], None,
        "{name: string, comment?: string} → {name}",
        has_tables, set),
    cmd!("routing.table.remove", "Remove Routing Table", [], None,
        "{name: string (nothing may use it: routes, mangle routing marks, routing rules)} → {name}",
        has_tables, remove),
    cmd!(query "routing.table.list", "Routing Tables", ["Routing", "Tables"], None,
        "{} → [{name, table (kernel id), type (main | vrf | named), routes (static routes in it), marks (mangle rules that mark packets for it), rules (routing rules that look in it), dynamic (true: main and VRFs, not removable here), comment}]",
        always, list),
];

fn has_tables(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.tables.is_empty() {
        Err("there are no routing tables (routing.table.add)".into())
    } else {
        Ok(())
    }
}

fn existing(cfg: &Config, p: &Value) -> Result<IfName> {
    let name: IfName = req_parse(p, "name")?;
    if cfg.routing.tables.contains_key(&name) {
        return Ok(name);
    }
    let why = if name.as_str() == RoutingTable::MAIN {
        "'main' is the kernel's main table, it cannot change".to_owned()
    } else if is_vrf_table(cfg, &RoutingTable::Vrf(name.clone())) {
        format!("'{name}' is the table of a VRF: use ip.vrf.set or ip.vrf.remove")
    } else {
        format!("no routing table '{name}' (see routing.table.list)")
    };
    Err(EngineError::bad("name", why))
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    if opt_bool(p, "fib")? == Some(false) {
        return Err(EngineError::bad(
            "fib",
            "every table here is in the FIB; a table only for routing filters does not exist yet",
        ));
    }
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    if RESERVED.contains(&name.as_str()) {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is the name of a table of the kernel"),
        ));
    }
    let cfg = s.store_mut().candidate_mut();
    if cfg.routing.tables.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("routing table '{name}' already exists"),
        ));
    }
    if is_vrf_table(cfg, &RoutingTable::Vrf(name.clone())) {
        return Err(EngineError::bad(
            "name",
            format!("a VRF is already named '{name}'; its table takes that name"),
        ));
    }
    if cfg.routing.tables.len() >= MAX_TABLES {
        return Err(EngineError::bad(
            "name",
            format!("at most {MAX_TABLES} routing tables"),
        ));
    }
    let table = free_table(cfg)
        .ok_or_else(|| EngineError::bad("name", "no free routing table id left"))?;
    cfg.routing.tables.insert(
        name.clone(),
        NamedTable {
            name: name.clone(),
            table,
            comment,
        },
    );
    Ok(json!({ "name": name, "table": table }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let name = existing(cfg, p)?;
    if let (Some(t), Some(c)) = (cfg.routing.tables.get_mut(&name), comment) {
        t.comment = c;
    }
    Ok(json!({ "name": name }))
}

/// Mangle rules that mark packets for table `name`, by mark name.
fn marks_of(cfg: &Config) -> BTreeMap<&str, usize> {
    let mut out: BTreeMap<&str, usize> = BTreeMap::new();
    for r in cfg.ip.firewall.mangle.iter() {
        if let Action::MarkRouting {
            new_routing_mark, ..
        } = &r.action
        {
            *out.entry(new_routing_mark.as_str()).or_default() += 1;
        }
    }
    out
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let name = existing(cfg, p)?;
    let table = RoutingTable::Vrf(name.clone());
    let mut blockers = Vec::new();
    let routes: Vec<String> = cfg
        .ip
        .routes
        .iter()
        .filter(|r| r.routing_table == table)
        .take(8)
        .map(|r| r.id.to_string())
        .collect();
    if !routes.is_empty() {
        blockers.push(format!(
            "remove route {} of this table first (ip.route.remove)",
            routes.join(", ")
        ));
    }
    if let Some(n) = marks_of(cfg).get(name.as_str()) {
        blockers.push(format!(
            "{n} mangle rule(s) mark packets for it (ip.firewall.mangle.list)"
        ));
    }
    let rules: Vec<String> = cfg
        .routing
        .rules
        .iter()
        .filter(|r| r.action.looks_up() && r.table == table)
        .take(8)
        .map(|r| r.id.to_string())
        .collect();
    if !rules.is_empty() {
        blockers.push(format!(
            "routing rule {} looks in it (routing.rule.remove)",
            rules.join(", ")
        ));
    }
    if !blockers.is_empty() {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is in use: {}", blockers.join("; ")),
        ));
    }
    cfg.routing.tables.remove(&name);
    Ok(json!({ "name": name }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let mut routes: BTreeMap<&RoutingTable, usize> = BTreeMap::new();
    for r in &cfg.ip.routes {
        *routes.entry(&r.routing_table).or_default() += 1;
    }
    let marks = marks_of(cfg);
    let mut rules: BTreeMap<&RoutingTable, usize> = BTreeMap::new();
    for r in cfg.routing.rules.iter().filter(|r| r.action.looks_up()) {
        *rules.entry(&r.table).or_default() += 1;
    }
    let rows: Vec<Value> = tables_by_id(cfg)
        .into_iter()
        .map(|(id, table)| {
            let name = table.to_string();
            let named = match &table {
                RoutingTable::Main => None,
                RoutingTable::Vrf(n) => cfg.routing.tables.get(n),
            };
            let kind = match (id, named) {
                (MAIN_TABLE_ID, _) => "main",
                (_, Some(_)) => "named",
                (_, None) => "vrf",
            };
            json!({
                "name": name,
                "table": id,
                "type": kind,
                "routes": routes.get(&table).copied().unwrap_or(0),
                "marks": marks.get(name.as_str()).copied().unwrap_or(0),
                "rules": rules.get(&table).copied().unwrap_or(0),
                "dynamic": named.is_none(),
                "comment": named.map_or("", |t| t.comment.as_str()),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute(
            "ip.address.add",
            &json!({"address": "192.0.2.2/24", "interface": "ether1"}),
        )
        .unwrap();
        s
    }

    #[test]
    fn a_route_goes_in_a_named_table_through_main_networks() {
        let mut s = lab();
        let t = s
            .execute("routing.table.add", &json!({"name": "isp2", "fib": true}))
            .unwrap();
        assert_eq!(t["table"], 1000);
        s.execute(
            "ip.route.add",
            &json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.1", "routing_table": "isp2"}),
        )
        .unwrap();
        let v = s.execute("ip.route.list", &json!({"routing_table": "isp2"})).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{v}");
        assert_eq!(rows[0]["state"], "active");
        assert_eq!(rows[0]["interface"], "ether1");
        let l = s
            .execute("ip.route.lookup", &json!({"address": "8.8.8.8", "table": "isp2"}))
            .unwrap();
        assert_eq!(l["type"], "unicast");
        assert_eq!(l["kernel"]["same"], true, "{l}");
        let list = s.execute("routing.table.list", &json!({})).unwrap();
        let isp2 = list.as_array().unwrap().iter().find(|r| r["name"] == "isp2").unwrap();
        assert_eq!((isp2["routes"].as_u64(), isp2["dynamic"].as_bool()), (Some(1), Some(false)));
        let main = list.as_array().unwrap().iter().find(|r| r["name"] == "main").unwrap();
        assert_eq!(main["type"], "main");
    }

    #[test]
    fn bad_names_and_uses_are_refused() {
        let mut s = lab();
        for name in ["main", "local", "default"] {
            let e = s
                .execute("routing.table.add", &json!({"name": name}))
                .unwrap_err()
                .to_string();
            assert!(e.contains("kernel"), "{e}");
        }
        assert!(s.execute("routing.table.add", &json!({"name": "a b"})).is_err());
        let e = s
            .execute("routing.table.add", &json!({"name": "x", "fib": false}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("FIB"), "{e}");
        s.execute("routing.table.add", &json!({"name": "x"})).unwrap();
        assert!(s.execute("routing.table.add", &json!({"name": "x"})).is_err());
        let e = s
            .execute("ip.vrf.add", &json!({"name": "x"}))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(e.contains('x'), "{e}");
        s.execute("ip.vrf.add", &json!({"name": "blue"})).unwrap();
        assert!(s.execute("routing.table.add", &json!({"name": "blue"})).is_err());
        let e = s
            .execute("routing.table.remove", &json!({"name": "blue"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("VRF"), "{e}");
        // A gateway in a VRF does not resolve from a named table.
        s.execute(
            "ip.vrf.set",
            &json!({"name": "blue", "interfaces": ["ether2"]}),
        )
        .unwrap();
        let e = s
            .execute(
                "ip.route.add",
                &json!({"dst_address": "0.0.0.0/0", "gateway": "ether2", "routing_table": "x"}),
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("blue"), "{e}");
    }

    #[test]
    fn a_table_in_use_stays_and_a_vrf_takes_another_id() {
        let mut s = lab();
        s.execute("routing.table.add", &json!({"name": "isp2"})).unwrap();
        let vrf = s.execute("ip.vrf.add", &json!({"name": "blue"})).unwrap();
        assert_eq!(vrf["table"], 1001, "the VRF does not take the named table's id");
        let r = s
            .execute(
                "ip.route.add",
                &json!({"dst_address": "10.9.0.0/16", "gateway": "192.0.2.1", "routing_table": "isp2"}),
            )
            .unwrap();
        let e = s
            .execute("routing.table.remove", &json!({"name": "isp2"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("in use"), "{e}");
        s.execute("ip.route.remove", &json!({"id": r["id"]})).unwrap();
        s.execute(
            "ip.firewall.mangle.add",
            &json!({"chain": "prerouting", "action": "mark-routing", "new_routing_mark": "isp2"}),
        )
        .unwrap();
        let e = s
            .execute("routing.table.remove", &json!({"name": "isp2"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("mangle"), "{e}");
    }

    #[test]
    fn transactional_rollback_takes_the_table_away() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("routing.table.add", &json!({"name": "isp2"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        s.execute("config.mode.set", &json!({"mode": "immediate"})).unwrap();
        let list = s.execute("routing.table.list", &json!({})).unwrap();
        assert!(list.as_array().unwrap().iter().all(|r| r["name"] != "isp2"), "{list}");
    }

    #[test]
    fn set_changes_the_comment_only_on_named_tables() {
        let mut s = lab();
        s.execute("routing.table.add", &json!({"name": "isp2"})).unwrap();
        s.execute("routing.table.set", &json!({"name": "isp2", "comment": "via B"})).unwrap();
        let e = s
            .execute("routing.table.set", &json!({"name": "main", "comment": "x"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("main"), "{e}");
        let list = s.execute("routing.table.list", &json!({})).unwrap();
        let isp2 = list.as_array().unwrap().iter().find(|r| r["name"] == "isp2").unwrap();
        assert_eq!(isp2["comment"], "via B");
    }
}

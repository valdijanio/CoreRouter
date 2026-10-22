//! G2.1 — /ip firewall and /interface list commands: success, validation,
//! rollback, move, sections, dynamic address-list entries.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::{CommitMode, EngineError, Session};
use corerouter_hal::{DynamicChange, Features, Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use corerouter_model::firewall::DynamicAddress;
use serde_json::{Value, json};

fn lab() -> Session {
    Session::virtual_lab()
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, id: &str, p: Value) -> (String, String) {
    match s.execute(id, &p) {
        Err(EngineError::BadParam { param, reason }) => (param, reason),
        other => panic!("{id} {p}: expected a parameter error, got {other:?}"),
    }
}

fn ids(s: &mut Session, table: &str) -> Vec<String> {
    ok(s, &format!("ip.firewall.{table}.list"), Value::Null)
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn filter_rules_add_set_list_and_commit() {
    let mut s = lab();
    let rev = s.store().current_revision();
    let id = ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "connection_state": "related,established", "comment": "keep"}),
    )["id"]
        .clone();
    assert_eq!(id, "*1");
    assert_eq!(
        s.store().current_revision(),
        rev + 1,
        "immediate mode commits"
    );
    let row = &ok(&mut s, "ip.firewall.filter.list", Value::Null)[0];
    assert_eq!(row["connection_state"], "established,related");
    assert_eq!(row["action"], "accept");
    assert_eq!(row["flags"], "");
    assert_eq!(
        row["summary"],
        "chain=input action=accept connection-state=established,related"
    );

    // Change the action: the rule keeps its matchers.
    ok(
        &mut s,
        "ip.firewall.filter.set",
        json!({"id": "*1", "action": "reject", "reject_with": "icmp-admin-prohibited"}),
    );
    let row = &ok(&mut s, "ip.firewall.filter.list", Value::Null)[0];
    assert_eq!(row["action"], "reject");
    assert_eq!(row["reject_with"], "icmp-admin-prohibited");
    assert_eq!(row["connection_state"], "established,related");
    // "" clears a matcher; disabled flags X.
    ok(
        &mut s,
        "ip.firewall.filter.set",
        json!({"id": "*1", "connection_state": "", "disabled": true}),
    );
    let row = &ok(&mut s, "ip.firewall.filter.list", Value::Null)[0];
    assert!(row.get("connection_state").is_none());
    assert_eq!(row["flags"], "X");

    // The running config has it, and the lab recorded the ruleset.
    assert_eq!(s.store().running().ip.firewall.filter.len(), 1);
    let fw = s.inspect(Some("running.ip.firewall.filter")).unwrap();
    assert_eq!(fw[0]["action"]["type"], "reject");
}

#[test]
fn validation_errors_name_the_parameter_and_change_nothing() {
    let mut s = lab();
    let before = s.store().candidate().clone();
    let cases = [
        (json!({"dst_port": "22"}), "dst_port"),
        (json!({"protocol": "tcp", "dst_port": "99999"}), "dst_port"),
        (json!({"chain": "input", "action": "masquerade"}), "action"),
        (json!({"action": "jump"}), "jump_target"),
        (
            json!({"action": "accept", "jump_target": "x"}),
            "jump_target",
        ),
        (json!({"action": "teleport"}), "action"),
        (
            json!({"src_address": "10.0.0.1", "dst_address": "2001:db8::1"}),
            "dst_address",
        ),
        (json!({"in_interface": "ether99"}), "in_interface"),
        (json!({"in_interface_list": "DMZ"}), "in_interface_list"),
        (
            json!({"chain": "output", "in_interface": "ether1"}),
            "in_interface",
        ),
        (json!({"connection_state": "sleepy"}), "connection_state"),
        (json!({"section": "Title", "action": "drop"}), "action"),
        (json!({"place_before": "*99"}), "place_before"),
    ];
    for (p, field) in cases {
        let (param, reason) = bad(&mut s, "ip.firewall.filter.add", p.clone());
        assert_eq!(param, field, "{p}: {reason}");
    }
    let (param, _) = bad(
        &mut s,
        "ip.firewall.nat.add",
        json!({"chain": "srcnat", "action": "src-nat"}),
    );
    assert_eq!(param, "to_addresses");
    let (param, _) = bad(
        &mut s,
        "ip.firewall.mangle.add",
        json!({"chain": "forward", "action": "mark-routing", "new_routing_mark": "isp2"}),
    );
    assert_eq!(param, "action");
    assert_eq!(*s.store().candidate(), before, "nothing was added");
}

#[test]
fn move_and_place_before_follow_routeros() {
    let mut s = lab();
    for c in ["a", "b", "c"] {
        ok(&mut s, "ip.firewall.filter.add", json!({"comment": c}));
    }
    assert_eq!(ids(&mut s, "filter"), ["*1", "*2", "*3"]);
    ok(
        &mut s,
        "ip.firewall.filter.move",
        json!({"id": "*3", "destination": "*1"}),
    );
    assert_eq!(ids(&mut s, "filter"), ["*3", "*1", "*2"]);
    ok(&mut s, "ip.firewall.filter.move", json!({"id": "*3"}));
    assert_eq!(ids(&mut s, "filter"), ["*1", "*2", "*3"]);
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"section": "Router protection", "place_before": "*1"}),
    );
    assert_eq!(ids(&mut s, "filter"), ["*4", "*1", "*2", "*3"]);
    let row = &ok(&mut s, "ip.firewall.filter.list", Value::Null)[0];
    assert_eq!(row["section"], "Router protection");
    assert_eq!(row["comment"], "Router protection");
    assert_eq!(row["chain"], Value::Null);
    let (param, _) = bad(
        &mut s,
        "ip.firewall.filter.move",
        json!({"id": "*1", "destination": "*77"}),
    );
    assert_eq!(param, "destination");
    ok(&mut s, "ip.firewall.filter.remove", json!({"id": "*2"}));
    assert_eq!(ids(&mut s, "filter"), ["*4", "*1", "*3"]);
}

#[test]
fn transactional_mode_rolls_back_to_the_running_firewall() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"action": "drop", "comment": "one"}),
    );
    let rev = s.store().current_revision();
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    assert_eq!(s.mode(), CommitMode::Transactional);
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"action": "drop", "comment": "two"}),
    );
    assert_eq!(s.store().running().ip.firewall.filter.len(), 1);
    ok(&mut s, "config.commit", json!({}));
    assert_eq!(s.store().running().ip.firewall.filter.len(), 2);
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    // In transactional mode the rollback loads the candidate; commit applies it.
    assert_eq!(s.store().candidate().ip.firewall.filter.len(), 1);
    ok(&mut s, "config.commit", json!({}));
    assert_eq!(s.store().running().ip.firewall.filter.len(), 1);
}

/// A lab whose data plane refuses any firewall (e.g. no nftables).
struct NoFirewall(VirtualHal);

impl Hal for NoFirewall {
    fn describe(&self) -> String {
        "lab without nftables".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if to.ip.firewall != from.ip.firewall {
            return Err(HalError::Rejected("nftables refused the ruleset".into()));
        }
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn features(&self) -> Features {
        Features::default()
    }
}

#[test]
fn a_data_plane_refusal_rolls_the_candidate_back() {
    let mut s = Session::new(Box::new(NoFirewall(VirtualHal::new(2))));
    let before = s.store().candidate().clone();
    let err = s
        .execute("ip.firewall.filter.add", &json!({"action": "drop"}))
        .unwrap_err();
    assert!(matches!(err, EngineError::Hal(_)), "{err}");
    assert_eq!(*s.store().candidate(), before);
    assert!(s.store().running().ip.firewall.filter.is_empty());
}

#[test]
fn custom_chains_and_jump_loops() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "jump", "jump_target": "guard"}),
    );
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "guard", "action": "jump", "jump_target": "more"}),
    );
    // more → guard closes a loop: refused at commit.
    let err = s
        .execute(
            "ip.firewall.filter.add",
            &json!({"chain": "more", "action": "jump", "jump_target": "guard"}),
        )
        .unwrap_err();
    assert!(err.to_string().contains("loop"), "{err}");
    assert_eq!(s.store().candidate().ip.firewall.filter.len(), 2);
}

#[test]
fn nat_and_mangle_round_trip() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.firewall.nat.add",
        json!({"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst_port": "8080",
               "to_addresses": "10.0.0.20", "to_ports": "80", "in_interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.firewall.nat.add",
        json!({"chain": "srcnat", "action": "masquerade", "out_interface_list": "WAN"}),
    );
    ok(
        &mut s,
        "ip.firewall.mangle.add",
        json!({"chain": "prerouting", "action": "mark-connection",
               "new_connection_mark": "web", "passthrough": false}),
    );
    let nat = ok(&mut s, "ip.firewall.nat.list", json!({"chain": "dstnat"}));
    assert_eq!(nat.as_array().unwrap().len(), 1);
    assert_eq!(nat[0]["to_addresses"], "10.0.0.20");
    assert_eq!(nat[0]["family"], "both");
    let mangle = ok(&mut s, "ip.firewall.mangle.list", Value::Null);
    assert_eq!(mangle[0]["passthrough"], false);
    // A rule now naming the WAN list keeps the list from going away.
    let (param, reason) = bad(&mut s, "interface.list.remove", json!({"name": "WAN"}));
    assert_eq!(param, "name");
    assert!(reason.contains("nat *2"), "{reason}");
}

#[test]
fn interface_lists_and_members() {
    let mut s = lab();
    let lists = ok(&mut s, "interface.list.list", Value::Null);
    assert_eq!(lists[0]["name"], "LAN");
    assert_eq!(lists[1]["name"], "WAN");
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "LAN", "interface": "ether2"}),
    );
    let (param, _) = bad(
        &mut s,
        "interface.list.member.add",
        json!({"list": "LAN", "interface": "ether2"}),
    );
    assert_eq!(param, "interface");
    let (param, _) = bad(
        &mut s,
        "interface.list.member.add",
        json!({"list": "DMZ", "interface": "ether3"}),
    );
    assert_eq!(param, "list");
    let (param, _) = bad(&mut s, "interface.list.add", json!({"name": "all"}));
    assert_eq!(param, "name");
    ok(
        &mut s,
        "interface.list.add",
        json!({"name": "DMZ", "comment": "servers"}),
    );
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "DMZ", "interface": "ether3"}),
    );
    ok(
        &mut s,
        "interface.list.set",
        json!({"name": "DMZ", "new_name": "SRV"}),
    );
    let members = ok(&mut s, "interface.list.member.list", json!({"list": "SRV"}));
    assert_eq!(members[0]["interface"], "ether3");
    ok(&mut s, "interface.list.remove", json!({"name": "SRV"}));
    let members = ok(&mut s, "interface.list.member.list", Value::Null);
    assert_eq!(
        members.as_array().unwrap().len(),
        1,
        "members of SRV went too"
    );
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

struct Recording(VirtualHal, Recorder);

impl Hal for Recording {
    fn describe(&self) -> String {
        "recording lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
        let text = match change {
            DynamicChange::Add(DynamicAddress {
                list,
                address,
                timeout_secs,
            }) => format!("add {list} {address} {timeout_secs}"),
            DynamicChange::Remove(d) => format!("remove {} {}", d.list, d.address),
        };
        self.1.0.lock().unwrap().push(text);
        Ok(())
    }
}

#[test]
fn dynamic_entries_reach_the_data_plane_and_expire() {
    let rec = Recorder::default();
    let mut s = Session::new(Box::new(Recording(VirtualHal::new(2), rec.clone())));
    s.tick(1_000);
    let rev = s.store().current_revision();
    let r = ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bad", "address": "192.0.2.7", "timeout": "1m30s"}),
    );
    assert_eq!(r["dynamic"], true);
    assert_eq!(
        s.store().current_revision(),
        rev,
        "dynamic entries are not config"
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bad", "address": "2001:db8::/32"}),
    );
    let (param, _) = bad(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bad", "address": "192.0.2.7"}),
    );
    assert_eq!(param, "address", "duplicate");
    let rows = ok(
        &mut s,
        "ip.firewall.address-list.list",
        json!({"list": "bad"}),
    );
    assert_eq!(rows.as_array().unwrap().len(), 2);
    let dynamic = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["dynamic"] == true)
        .unwrap();
    assert_eq!(dynamic["timeout"], 90);
    assert_eq!(dynamic["flags"], "D");
    s.tick(1_060);
    let rows = ok(&mut s, "ip.firewall.address-list.list", Value::Null);
    let dynamic = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["dynamic"] == true)
        .unwrap();
    assert_eq!(dynamic["timeout"], 30);
    s.tick(1_091);
    let rows = ok(&mut s, "ip.firewall.address-list.list", Value::Null);
    assert_eq!(rows.as_array().unwrap().len(), 1, "expired");
    assert_eq!(
        *rec.0.lock().unwrap(),
        ["add bad 192.0.2.7 90", "remove bad 192.0.2.7"]
    );
    let (param, _) = bad(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "x", "address": "10.0.0.1", "timeout": "99d"}),
    );
    assert_eq!(param, "timeout");
}

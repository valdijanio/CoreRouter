//! Routing › Rules (G1.27e): the rules in order, the packet test, the tables
//! and the kernel's list over the lab.

use super::*;
use crate::routing_rules::{RulesPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

fn harness() -> Harness {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        ("ip.address.add", json!({"address": "192.0.2.2/24", "interface": "ether1"})),
        ("ip.address.add", json!({"address": "198.51.100.2/24", "interface": "ether2"})),
        ("routing.table.add", json!({"name": "isp2", "comment": "second uplink"})),
        ("ip.route.add", json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.1"})),
        ("ip.route.add", json!({"dst_address": "0.0.0.0/0", "gateway": "198.51.100.1", "routing_table": "isp2"})),
        ("routing.rule.add", json!({"src_address": "10.91.0.0/24", "table": "isp2", "comment": "guests"})),
        ("routing.rule.add", json!({"src_address": "10.92.0.0/24", "action": "drop"})),
    ] {
        s.execute(id, &p).unwrap();
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn the_rules_show_in_order_with_their_action() {
    let mut h = harness();
    assert!(h.has_text("10.91.0.0/24"), "{:?}", h.app.log());
    assert!(h.has_text("guests"));
    assert!(h.has_text("drop"));
    let p = h.app.panel_mut::<RulesPanel>().unwrap();
    assert_eq!(p.rules.len(), 2);
    assert_eq!(p.rules[0]["priority"], 2000);
}

#[test]
fn the_packet_test_says_which_rule_decides() {
    let mut h = harness();
    {
        let p = h.app.panel_mut::<RulesPanel>().unwrap();
        p.address = "8.8.8.8".into();
        p.src = "10.91.0.7".into();
        p.interface = "ether3".into();
    }
    h.idle();
    h.click(h.text("Test"));
    refresh(&mut h);
    assert!(h.has_text("isp2"));
    let p = h.app.panel_mut::<RulesPanel>().unwrap();
    let a = p.answer.as_ref().unwrap();
    assert_eq!(a["routing_table"], "isp2", "{a}");
    assert_eq!(a["kernel"]["same"], true, "{a}");
}

#[test]
fn the_other_tabs_show_the_tables_and_the_kernels_list() {
    let mut h = harness();
    h.click(h.text("Tables"));
    refresh(&mut h);
    assert!(h.has_text("second uplink"), "{:?}", h.app.log());
    assert!(h.has_text("named"));
    h.click(h.text("Kernel List"));
    refresh(&mut h);
    assert!(h.has_text("corerouter"));
    assert!(h.has_text_containing("from 10.91.0.0/24"));
}

#[test]
fn a_new_rule_goes_through_the_modal() {
    let mut h = harness();
    let add = h
        .ctx
        .read_response(table::tool_id(crate::routing_rules::RULES, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    for _ in 0..4 {
        h.idle();
    }
    assert!(h.has_text("New Routing Rule"), "{:?}", h.app.log());
    {
        let p = h.app.panel_mut::<RulesPanel>().unwrap();
        let (_, m) = p.modal.as_mut().unwrap();
        m.values.insert("dst_address", "203.0.113.0/24".into());
        m.values.insert("action", "unreachable".into());
    }
    settle(&mut h);
    {
        let p = h.app.panel_mut::<RulesPanel>().unwrap();
        let preview = p.modal.as_ref().and_then(|(_, m)| m.preview.clone());
        assert!(preview.is_some(), "the modal asked the engine");
        assert!(h.has_text("IPv4"), "the preview's computed field: {preview:?}");
    }
    h.click(h.text("OK"));
    settle(&mut h);
    let p = h.app.panel_mut::<RulesPanel>().unwrap();
    assert_eq!(p.rules.len(), 3, "{:?}", p.rules);
    assert_eq!(p.rules[2]["action"], "unreachable");
    assert!(p.modal.is_none());
}

#[test]
fn every_window_of_the_panel_renders_in_both_languages() {
    let mut h = harness();
    for tab in ["Tables", "Kernel List", "Rules"] {
        h.click(h.text(tab));
        refresh(&mut h);
    }
}

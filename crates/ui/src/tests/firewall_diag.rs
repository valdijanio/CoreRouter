//! G2.1c: the Firewall window's Test and Diff tabs and the live counters
//! of the rule tables, drawn headless over a lab session.

use super::*;
use crate::firewall::Tab;
use crate::firewall_diag::{NAME, Reply};
use corerouter_engine::firewall_diag::RuleCounter;
use corerouter_model::ItemId;
use corerouter_model::firewall::Table;

fn texts(h: &Harness) -> String {
    fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for s in &h.shapes {
        walk(&s.shape, &mut out);
    }
    out.join("\n")
}

fn router() -> Harness {
    let mut h = Harness::new();
    {
        let mut s = lock(&h.session);
        s.execute("ip.address.add", &json!({"address": "203.0.113.1/24", "interface": "ether1"}))
            .unwrap();
        for p in [
            json!({"chain": "input", "protocol": "tcp", "dst_port": "22", "action": "drop"}),
            json!({"chain": "input", "connection_state": "established,related"}),
        ] {
            s.execute("ip.firewall.filter.add", &p).unwrap();
        }
    }
    h.app.open.clear();
    h.app.open(Win::Firewall);
    h.app.cache.refreshed_at = None;
    h.idle();
    h
}

#[test]
fn the_test_tab_shows_the_way_and_the_deciding_rule() {
    let mut h = router();
    h.app.fw.tab = Tab::Test;
    h.idle();
    let screen = texts(&h);
    assert!(screen.contains("Trace real packets"), "{screen}");
    h.app.run_then(
        "ip.firewall.test",
        json!({"src": "198.51.100.9", "dst": "203.0.113.1", "dst_port": 22, "in_interface": "ether1"}),
        crate::panel::then(NAME, Reply::Test),
    );
    for _ in 0..4 {
        h.idle();
    }
    let screen = texts(&h);
    assert!(screen.contains("filter input"), "the chain chip: {screen}");
    assert!(screen.contains("route → local"), "{screen}");
    assert!(screen.contains("DROPPED"), "{screen}");
    assert!(screen.contains("dst-port=22"), "the deciding rule: {screen}");
    assert!(screen.contains("decides"), "{screen}");
}

#[test]
fn the_diff_tab_shows_what_the_commit_would_load() {
    let mut h = router();
    lock(&h.session)
        .execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    lock(&h.session)
        .execute("ip.firewall.raw.add", &json!({"action": "drop", "src_address": "192.0.2.0/24"}))
        .unwrap();
    h.app.fw.tab = Tab::Diff;
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    let screen = texts(&h);
    assert!(screen.contains("+ \tchain raw_prerouting") || screen.contains("+     chain raw_prerouting"), "{screen}");
    assert!(screen.contains("lines of nftables change"), "{screen}");
}

#[test]
fn rule_tables_show_live_counters() {
    let mut h = router();
    {
        let mut s = lock(&h.session);
        s.execute("ip.firewall.counters", &json!({})).unwrap();
        s.firewall_counters_feed(Ok(vec![RuleCounter {
            table: Table::Filter,
            id: ItemId(1),
            packets: 1500,
            bytes: 3 * 1024 * 1024,
        }]));
    }
    h.app.fw.tab = Tab::Filter;
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
    let screen = texts(&h);
    assert!(screen.contains("1.5 k"), "{screen}");
    assert!(screen.contains("3.0 MiB"), "{screen}");
    assert!(screen.contains("Reset All Counters"), "{screen}");
}

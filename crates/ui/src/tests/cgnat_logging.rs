//! CGNAT › Logging (G4.4j): the NAT log's switches and collectors, the
//! switches applied by `ip.traffic-flow.set`, "Add Collector" opening the
//! Traffic Flow target modal filled for IPFIX over TLS.

use super::*;
use crate::cgnat::{Cgnat, Tab, WIN};
use crate::traffic_flow::TrafficFlowPanel;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness() -> Harness {
    let mut s = Session::virtual_lab();
    s.tick(1_780_000_000);
    s.execute("ip.firewall.cgnat.pool.add", &json!({"name": "pba", "mode": "blocks", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"})).unwrap();
    s.execute("ip.traffic-flow.target.add", &json!({"dst_address": "192.0.2.20", "port": 4739, "transport": "sctp", "content": "nat", "nat_events_legacy": true})).unwrap();
    s.execute("ip.traffic-flow.target.add", &json!({"dst_address": "192.0.2.30", "content": "flows"})).unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<Cgnat>().unwrap().tab = Tab::Logging;
    refresh(&mut h);
    h
}

#[test]
fn the_logging_tab_lists_the_nat_collectors_only() {
    let h = harness();
    assert!(h.has_text("Logging"));
    assert!(h.has_text("192.0.2.20:4739"), "the NAT collector");
    assert!(!h.has_text("192.0.2.30:2055"), "a flows-only collector is not the NAT log's");
    assert!(h.has_text("sctp"));
    assert!(h.has_text("1/2 legacy"));
    assert!(h.has_text_containing("RFC 8158 §7"), "a plain collector: the warning to encrypt");
    assert!(h.has_text("Port Blocks") && h.has_text("Limits") && h.has_text("Sessions"));
}

#[test]
fn a_switch_is_one_command() {
    let mut h = harness();
    assert!(lock(&h.session).store().running().ip.traffic_flow.nat_port_blocks);
    // The checkbox's own text says what it adds.
    h.click(h.text("natEvent 16/17: one record per block, with pool, VLAN and login"));
    refresh(&mut h);
    assert!(!lock(&h.session).store().running().ip.traffic_flow.nat_port_blocks, "{:?}", h.app.log());
}

#[test]
fn add_collector_opens_the_traffic_flow_modal_for_tls() {
    let mut h = harness();
    h.click(h.text("Add Collector"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(crate::traffic_flow::WIN)));
    let p = h.app.panel_mut::<TrafficFlowPanel>().unwrap();
    assert_eq!(p.tab, crate::traffic_flow::Tab::Targets);
    let m = p.modal.as_ref().expect("the target modal");
    assert_eq!(m.values.get("transport").map(String::as_str), Some("tls"));
    assert_eq!(m.values.get("content").map(String::as_str), Some("nat"));
    assert_eq!(m.values.get("port").map(String::as_str), Some("4740"));
}

#[test]
fn every_label_has_an_explanation_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    for key in [
        "nat-log.exporter",
        "nat-log.queue",
        "nat-log.nat_port_blocks",
        "nat-log.nat_limits",
        "nat-log.nat_events",
        "nat-log.nat_events_destination",
        "nat-log.collectors",
        "traffic-flow.flows",
        "traffic-flow.nat_port_blocks",
        "traffic-flow.nat_limits",
        "traffic-flow.target.content",
        "traffic-flow.target.nat_events_legacy",
        "traffic-flow.target.server_name",
        "traffic-flow.target.certificate",
        "traffic-flow.target.private_key",
        "traffic-flow.target.ca_certificate",
    ] {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
}

//! Tools › IP Calculator (G6.9): a subnet with its numbers and the overlap
//! warning, split and summarize, IPv6 PD over a pool, the CGNAT planner
//! following its inputs, its export to the clipboard and the pool it
//! creates.

use super::*;
use crate::ip_calc::{IpCalc, Tab, WIN};

fn settle(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..8 {
        h.time += 0.1;
        h.idle();
    }
}

fn harness(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    settle(&mut h);
    h
}

fn calc(h: &mut Harness) -> &mut IpCalc {
    h.app.panel_mut::<IpCalc>().unwrap()
}

#[test]
fn a_subnet_shows_its_numbers_and_what_it_overlaps() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "192.168.88.1/24", "interface": "ether1"})).unwrap();
    let mut h = harness(s);
    assert!(h.has_text("Subnet") && h.has_text("IPv6 PD") && h.has_text("CGNAT planner"));
    calc(&mut h).address = "192.168.88.77/25".into();
    h.idle();
    h.click(h.text("Calculate"));
    settle(&mut h);
    assert!(h.has_text("192.168.88.0/25"), "{:?}", h.app.log());
    assert!(h.has_text("192.168.88.127") && h.has_text("255.255.255.128") && h.has_text("0.0.0.127"));
    assert!(h.has_text("126"), "hosts");
    assert!(h.has_text("address") && h.has_text_containing("192.168.88.1/24 on ether1"), "overlap");
    // A bad address says why, in the window.
    calc(&mut h).address = "10.0.0.1/40".into();
    h.idle();
    h.click(h.text("Calculate"));
    settle(&mut h);
    assert!(matches!(calc(&mut h).subnet, Some(Err(_))));
}

#[test]
fn split_and_summarize() {
    let mut h = harness(Session::virtual_lab());
    {
        let c = calc(&mut h);
        c.address = "10.0.0.0/22".into();
        c.split_to = "/24".into();
        c.summarize = "10.0.0.0/24, 10.0.1.0/24".into();
    }
    h.idle();
    h.click(h.text("Split"));
    settle(&mut h);
    assert!(h.has_text("4 × /24"), "{:?}", h.app.log());
    assert!(h.has_text_containing("10.0.3.0/24"));
    h.click(h.text("Summarize"));
    settle(&mut h);
    assert!(h.has_text("10.0.0.0/23"));
}

#[test]
fn prefix_delegation_lists_the_pools_inside() {
    let mut s = Session::virtual_lab();
    s.execute("ipv6.pool.add", &json!({"name": "pd1", "prefix": "2001:db8:10::/44", "prefix_length": 56})).unwrap();
    let mut h = harness(s);
    h.click(h.text("IPv6 PD"));
    calc(&mut h).pd_prefix = "2001:db8::/40".into();
    h.idle();
    h.click(h.text("Calculate"));
    settle(&mut h);
    assert_eq!(calc(&mut h).tab, Tab::Pd);
    assert!(h.has_text("65536"), "{:?}", h.app.log());
    assert!(h.has_text_containing("2001:db8:0:100::/56"));
    assert!(h.has_text("pd1") && h.has_text("inside this prefix"), "the pool inside");
}

#[test]
fn the_planner_follows_its_inputs_and_creates_the_pool() {
    let mut h = harness(Session::virtual_lab());
    h.click(h.text("CGNAT planner"));
    h.idle();
    {
        let c = calc(&mut h);
        c.inside = "100.64.0.0/20".into();
        c.outside = "203.0.113.0/28".into();
    }
    settle(&mut h);
    assert!(h.has_text("does not fit"), "{:?}", h.app.log());
    assert!(h.has_text_containing("add 48 public addresses"), "the suggestion");
    calc(&mut h).outside = "203.0.113.0/26".into();
    settle(&mut h);
    assert!(h.has_text("fits"));
    assert!(h.has_text("Mapping preview"), "title");
    assert!(h.has_text("100.64.0.1"), "row");
    assert!(h.has_text("2024–3023"), "ports");
    h.click(h.text("Copy CSV"));
    settle(&mut h);
    assert!(calc(&mut h).note.as_deref().is_some_and(|n| n.contains("4096 rows")), "{:?}", calc(&mut h).note);
    h.click(h.text("View rules"));
    settle(&mut h);
    assert!(calc(&mut h).rules.as_deref().is_some_and(|r| r.contains("snat ip to ip saddr map")));
    h.click(h.text("Create CGNAT pool"));
    settle(&mut h);
    let pools = lock(&h.session).store().running().ip.cgnat.pools.clone();
    assert_eq!(pools.len(), 1, "{:?}", h.app.log());
    assert_eq!(pools[0].name, "cgnat1");
    assert_eq!(pools[0].ports_per_subscriber, 1000);
}

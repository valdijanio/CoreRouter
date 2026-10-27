//! IP › ARP (G1.27d): the neighbor table over the lab (hosts 1–12 and
//! 254 of each subnet answer, any other gateway stays incomplete), the
//! state chips that filter, Make Static from a learned row, the Settings
//! tab, and IPv6 › Neighbors opening on ND.

use super::*;
use crate::arp::{ArpPanel, WIN, WIN6};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness() -> Harness {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        ("ip.address.add", json!({"address": "10.0.0.1/24", "interface": "ether1"})),
        ("ip.address.add", json!({"address": "2001:db8:1::1/64", "interface": "ether1"})),
        ("ip.route.add", json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.254"})),
        ("ip.route.add", json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.0.77"})),
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
fn the_table_shows_states_and_the_chips_filter() {
    let mut h = harness();
    assert!(h.has_text("10.0.0.254"), "{:?}", h.app.log());
    assert!(h.has_text("10.0.0.77"));
    assert!(h.has_text("incomplete 1"), "the state chip with the table's count");
    assert!(h.has_text_containing("kernel table 13 / gc_thresh3 1024"));
    h.click(h.text("incomplete 1"));
    refresh(&mut h);
    let p = h.app.panel_mut::<ArpPanel>().unwrap();
    let rows = p.v4.page.as_ref().unwrap()["rows"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["address"], "10.0.0.77");
}

#[test]
fn make_static_from_a_learned_row() {
    let mut h = harness();
    let key = "ether1|10.0.0.5".to_owned();
    {
        let p = h.app.panel_mut::<ArpPanel>().unwrap();
        p.v4.table.select_only(&key);
    }
    h.idle();
    h.click(h.text("Make Static"));
    refresh(&mut h);
    let entries = lock(&h.session).store().running().ip.arp.entries.clone();
    assert_eq!(entries.len(), 1, "{:?}", h.app.log());
    assert_eq!(entries[0].address.to_string(), "10.0.0.5");
    assert!(h.has_text("static"));
}

#[test]
fn settings_and_the_ipv6_window() {
    let mut h = harness();
    h.click(h.text("Settings"));
    refresh(&mut h);
    assert!(h.has_text("gc_thresh3"));
    assert!(h.has_text("enabled"), "ether1's mode");
    h.app.open.clear();
    h.app.open(Win::Panel(WIN6));
    refresh(&mut h);
    assert!(h.has_text("2001:db8:1::2"), "{:?}", h.app.log());
    assert!(h.has_text("router"), "fe80::1 says it is a router");
}

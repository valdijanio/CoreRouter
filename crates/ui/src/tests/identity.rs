//! Subscriber identity (G0.25): the chip next to the source in Connections
//! and in its top subscribers, "+N", the click that opens the lease, the
//! Settings section (off, order, places) and its stored preference.

use super::*;
use crate::connections::Connections;
use crate::identity::Identity;

fn refresh(h: &mut Harness) {
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle();
    }
}

/// The chip's text: the icon and the name (the name alone while the icon
/// font is not active yet).
fn chip_at(h: &Harness, name: &str) -> Option<egui::Pos2> {
    h.find_text(&format!("{}{name}", crate::icons::IDENTIFICATION_BADGE))
        .or_else(|| h.find_text(name))
}

/// The lab's conntrack table comes from a CGNAT pool over 100.64.0.0/22;
/// each /24 has a name by address list, and the busiest subscriber a
/// static lease too.
fn harness() -> (Harness, String) {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    )
    .unwrap();
    for (i, name) in ["Bloco A", "Bloco B", "Bloco C", "Bloco D"].iter().enumerate() {
        s.execute(
            "ip.firewall.address-list.add",
            &json!({"list": "clientes", "address": format!("100.64.{i}.0/24"), "comment": name}),
        )
        .unwrap();
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Firewall);
    refresh(&mut h);
    h.click(h.text("Connections"));
    refresh(&mut h);
    let top = h.app.panel_mut::<Connections>().unwrap().top[0]["subscriber"]
        .as_str()
        .unwrap()
        .to_owned();
    h.session
        .lock()
        .unwrap()
        .execute(
            "ip.dhcp-server.lease.add",
            &json!({"address": top, "mac_address": "02:00:00:00:00:01", "comment": "Maria Souza"}),
        )
        .unwrap();
    // Names are kept a while: forget them, as a change of order would.
    if let Some(p) = h.app.panel_mut::<Identity>() {
        p.order.swap(0, 0);
    }
    h.app.apply_prefs(&h.app.prefs());
    refresh(&mut h);
    (h, top)
}

#[test]
fn connections_show_the_name_next_to_the_source() {
    let (mut h, _) = harness();
    assert!(chip_at(&h, "Maria Souza").is_some(), "the lease comment first");
    assert!(h.has_text("+1"), "the list's name is the other one");
    assert!(
        ["Bloco A", "Bloco B", "Bloco C", "Bloco D"].iter().any(|n| chip_at(&h, n).is_some()),
        "the other subscribers by their list"
    );

    // Hover: the tooltip names every source.
    let at = chip_at(&h, "Maria Souza").unwrap();
    h.hover(at);
    assert!(h.has_text("Static lease comment"), "tooltip");
    assert!(h.has_text("Address list comment"));
    assert!(h.has_text_containing("02:00:00:00:00:01"), "the detail");

    // Click: the DHCP Server window opens on that lease.
    h.click(at);
    assert!(h.app.open.contains(&Win::Panel(crate::dhcp_server::WIN)));
    let p = h.app.panel_mut::<crate::dhcp_server::DhcpServerPanel>().unwrap();
    assert_eq!(p.tab, crate::dhcp_server::Tab::Leases);
}

#[test]
fn settings_turn_it_off_reorder_and_pick_places() {
    let (mut h, top) = harness();
    // Lists first: the /24's name leads, the lease is the +1.
    let p = h.app.panel_mut::<Identity>().unwrap();
    let list = p.order.iter().position(|(s, _)| *s == "address-list").unwrap();
    let lease = p.order.iter().position(|(s, _)| *s == "dhcp-static").unwrap();
    p.order.swap(list, lease);
    h.app.apply_prefs(&h.app.prefs());
    refresh(&mut h);
    let block = format!("Bloco {}", ["A", "B", "C", "D"][top.split('.').nth(2).unwrap().parse::<usize>().unwrap()]);
    let filter = h.app.panel_mut::<Connections>().unwrap();
    filter.filters.subscriber = top.clone();
    refresh(&mut h);
    assert!(chip_at(&h, &block).is_some(), "{block} leads now");

    // Not in Connections: no chip there.
    let stored = h.app.prefs();
    assert!(stored.contains(r#""identity":{"#), "{stored}");
    let p = h.app.panel_mut::<Identity>().unwrap();
    p.places.remove("connections");
    refresh(&mut h);
    assert!(chip_at(&h, &block).is_none());
    assert!(chip_at(&h, "Maria Souza").is_none());

    // The stored preference brings back the order and the places.
    let mut fresh = Harness::with_session(Session::virtual_lab());
    fresh.app.apply_prefs(&h.app.prefs());
    let p = fresh.app.panel_mut::<Identity>().unwrap();
    assert!(!p.places.contains("connections"));
    assert!(p.places.contains("torch"));
    assert_eq!(p.order[lease].0, "address-list");
    p.enabled = false;
    let off = fresh.app.prefs();
    let mut again = Harness::with_session(Session::virtual_lab());
    again.app.apply_prefs(&off);
    assert!(!again.app.panel_mut::<Identity>().unwrap().enabled);
}

#[test]
fn the_settings_window_has_the_section_with_explanations() {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(crate::settings::WIN));
    h.idle();
    h.idle();
    assert!(h.has_text("Subscriber identity"));
    assert!(h.has_text("Sources, in order"));
    assert!(h.has_text("Static lease comment"));
    assert!(h.has_text("CGNAT › Who Was"));
    // Unticking a source keeps it in the order, unused.
    h.click(h.text("Lease host name"));
    let p = h.app.panel_mut::<Identity>().unwrap();
    assert!(p.order.iter().any(|(s, on)| *s == "dhcp-dynamic" && !on));
    assert!(h.app.prefs().contains(r#""off":["dhcp-dynamic"]"#));
    // Portuguese labels.
    h.app.lang.labels = crate::i18n::Lang::Pt;
    h.idle();
    h.idle();
    assert!(h.has_text("Identidade do assinante"));
    assert!(h.has_text("CGNAT › Quem era?"));
}

#[test]
fn hostile_or_unknown_rows_draw_nothing() {
    use crate::identity::{cell_chips, is_chip};
    assert!(cell_chips(None).is_empty());
    assert!(cell_chips(Some(&json!({"address": "x", "all": [], "more": 0}))).is_empty());
    let chips = cell_chips(Some(&json!({"primary": {"name": "Ana"}, "more": 3})));
    assert_eq!(chips.len(), 2);
    assert_eq!(chips[1].0, "+3");
    assert!(is_chip(&chips[0].0) && is_chip("+3"));
    assert!(!is_chip("c1") && !is_chip("+") && !is_chip("+x"));
}

#[test]
fn cgnat_who_was_names_the_subscriber_at_that_time() {
    use crate::cgnat::{Cgnat, WIN};
    let mut s = Session::virtual_lab();
    s.tick(1_780_000_000);
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    )
    .unwrap();
    s.execute(
        "ip.dhcp-server.lease.add",
        &json!({"address": "100.64.0.65", "mac_address": "02:00:00:00:00:65", "comment": "Pedro"}),
    )
    .unwrap();
    s.tick(1_780_000_001);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h.click(h.text("Who Was"));
    {
        let c = h.app.panel_mut::<Cgnat>().unwrap();
        c.who.public = "203.0.113.1".into();
        c.who.port = "2500".into();
    }
    h.idle();
    h.click(h.text("Find"));
    refresh(&mut h);
    assert!(h.has_text("100.64.0.65"), "{:?}", h.app.log());
    let at = chip_at(&h, "Pedro").expect("the name next to the subscriber");
    h.hover(at);
    assert!(h.has_text("Static lease comment"));
}

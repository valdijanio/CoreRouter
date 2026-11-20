//! Routing › Management Guard (G3.4z): the top bar's chip while a learned
//! route covers a management session, the Protect button, and the list.

use super::*;
use corerouter_engine::{Caller, Link, Principal};
use corerouter_hal::route_get::{FibEntry, RouteKind};

use crate::management_guard::{GuardPanel, WIN};

/// Every text on screen.
fn texts(h: &Harness) -> Vec<String> {
    fn walk(s: &egui::Shape, out: &mut Vec<(String, egui::Pos2)>) {
        match s {
            egui::Shape::Text(t) => out.push((t.galley.text().to_owned(), t.visual_bounding_rect().center())),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    h.shapes.iter().for_each(|s| walk(&s.shape, &mut out));
    out.into_iter().map(|(t, _)| t).collect()
}

/// Centre of a text that contains `needle`.
fn containing(h: &Harness, needle: &str) -> Option<egui::Pos2> {
    fn walk(s: &egui::Shape, needle: &str, out: &mut Option<egui::Pos2>) {
        match s {
            egui::Shape::Text(t) if t.galley.text().contains(needle) => *out = Some(t.visual_bounding_rect().center()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, needle, out)),
            _ => {}
        }
    }
    let mut out = None;
    h.shapes.iter().for_each(|s| walk(&s.shape, needle, &mut out));
    out
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

/// The lab with an operator at 192.168.0.2 on ether1 and the OSPF /32
/// of phase C taking its replies to ether2.
fn covered() -> Session {
    let mut s = Session::virtual_lab();
    s.bootstrap_admin(false);
    s.execute("ip.address.add", &json!({"address": "192.168.0.1/24", "interface": "ether1"})).unwrap();
    s.execute("ip.address.add", &json!({"address": "10.0.1.1/30", "interface": "ether2"})).unwrap();
    let mut gui = Caller::new(41, "tcp 192.168.0.2:50000")
        .with_principal(Principal::User("admin".into()))
        .with_link(Link { peer: "192.168.0.2:50000".parse().unwrap(), local: "192.168.0.1:8729".parse().unwrap() });
    gui.via = Some("GUI");
    s.execute_as(&gui, "system.identity.get", &json!({})).unwrap();
    let pairs = s.mgmt_guard_probes();
    let entry = FibEntry {
        kind: RouteKind::Unicast,
        prefix: Some("192.168.0.2/32".parse().unwrap()),
        protocol: 188,
        interface: Some("ether2".parse().unwrap()),
        gateway: Some("10.0.1.2".parse().unwrap()),
    };
    s.mgmt_guard_feed(pairs.into_iter().map(|p| (p, Ok(entry.clone()))).collect());
    s
}

#[test]
fn the_top_bar_names_the_covered_session_and_opens_the_window() {
    let mut h = Harness::with_session(covered());
    h.app.open.clear();
    refresh(&mut h);
    let chip = containing(&h, "mgmt route: 192.168.0.2").unwrap_or_else(|| panic!("{:?}", texts(&h)));
    h.click(chip);
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)), "the chip opens Routing › Management Guard");
    assert!(containing(&h, "192.168.0.2/32 (ospf, via 10.0.1.2 ether2)").is_some(), "{:?}", texts(&h));
}

#[test]
fn protect_guards_the_network_and_the_list_shows_it() {
    let mut h = Harness::with_session(covered());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text("Protect 192.168.0.0/24"), "{:?}", texts(&h));
    h.click(h.text("Protect 192.168.0.0/24"));
    refresh(&mut h);
    let p = h.app.panel_mut::<GuardPanel>().unwrap();
    let rows = p.list["rows"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 1, "{:?}", h.app.log());
    assert_eq!(rows[0]["network"], "192.168.0.0/24");
    assert_eq!(rows[0]["state"], "active");
    assert_eq!(rows[0]["interface"], "ether1");
    assert!(h.has_text("192.168.0.0/24"));
    // Guarded now: no second button for it.
    assert!(!h.has_text("Protect 192.168.0.0/24"));
}

#[test]
fn an_empty_list_says_what_to_do() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "192.168.0.1/24", "interface": "ether1"})).unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(containing(&h, "No network guarded").is_some(), "{:?}", texts(&h));
    assert!(containing(&h, "mgmt route").is_none(), "nothing covered: no chip");
}

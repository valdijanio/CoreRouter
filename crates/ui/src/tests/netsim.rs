//! Tools › Network Simulator (G3.7b), a panel over `tool.netsim.*`.

use super::*;
use crate::netsim::{NetsimPanel, Sel, WIN, clock_text, convergence_text, describe};

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
}

fn converged_square() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("tool.netsim.new", &json!({})).unwrap();
    while s.execute("tool.netsim.advance", &json!({"ms": 60_000})).unwrap()["done"] != true {}
    s
}

#[test]
fn netsim_window_draws_the_square_with_the_badge_and_the_timeline() {
    let mut h = open(converged_square());
    assert!(h.has_text("Network Simulator"));
    assert!(h.has_text("simulation — not the real network"), "the badge is always on screen");
    assert!(h.has_text("t = 1 min 00.000 s"));
    let lines = h.app.panel_mut::<NetsimPanel>().unwrap().timeline.len();
    assert!(lines > 10, "timeline: {lines}");
    // A router: its routes and sessions.
    h.app.panel_mut::<NetsimPanel>().unwrap().selected = Some(Sel::Node("R2".into()));
    refresh(&mut h);
    assert!(h.has_text("198.51.100.0/24"));
    assert!(h.has_text("established"));
    // A link: Cut goes to the engine, the summary follows.
    h.app.panel_mut::<NetsimPanel>().unwrap().selected = Some(Sel::Link(0));
    refresh(&mut h);
    h.click(h.text("Cut"));
    refresh(&mut h);
    lock(&h.session).execute("tool.netsim.advance", &json!({"ms": 5_000})).unwrap();
    refresh(&mut h);
    let v = lock(&h.session).execute("tool.netsim.get", &json!({})).unwrap();
    assert_eq!(v["links"][0]["state"], "cut", "{:?}", h.app.log());
    assert!(h.has_text_containing("link-cut: detected +0."), "convergence summary");
}

#[test]
fn netsim_window_without_a_simulation_offers_new() {
    let mut h = open(Session::virtual_lab());
    assert!(h.has_text("No simulation. Pick a preset and press New."));
    assert!(h.has_text("simulation — not the real network"));
    h.click(h.text("New"));
    refresh(&mut h);
    let v = lock(&h.session).execute("tool.netsim.get", &json!({})).unwrap();
    assert_eq!(v["loaded"], true);
    assert_eq!(v["nodes"].as_array().unwrap().len(), 4);
}

#[test]
fn netsim_texts() {
    assert_eq!(clock_text(5_250.0), "5.250 s");
    assert_eq!(clock_text(65_250.0), "1 min 05.250 s");
    let c = json!({"fault": {"kind": "link-cut", "link": 0}, "detected_after_ms": 794.6, "igp_after_ms": 795.6,
                   "bgp_after_ms": null, "bgp_prefixes_before": 12, "bgp_prefixes_now": 10});
    assert_eq!(convergence_text(&c).unwrap(), "link-cut: detected +0.79 s, OSPF +0.80 s, 2 prefixes lost");
    assert_eq!(describe(&json!({"type": "bfd-down", "link": 3})), "BFD down (link 3)");
}

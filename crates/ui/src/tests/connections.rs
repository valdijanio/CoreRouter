//! IP › Firewall › Connections (G2.2): the tab shows the lab's table made
//! from a CGNAT pool, its usage, the top subscribers; a filter narrows it,
//! a click on a top subscriber filters by them, Kill removes the selected.

use super::*;
use crate::connections::Connections;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness() -> Harness {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Firewall);
    refresh(&mut h);
    h.click(h.text("Connections"));
    refresh(&mut h);
    h
}

#[test]
fn the_tab_shows_the_table_its_usage_and_the_top_subscribers() {
    let mut h = harness();
    let c = h.app.panel_mut::<Connections>().unwrap();
    let total = c.list["total"].as_u64().unwrap();
    assert!(total > 1000, "{total}");
    assert_eq!(c.list["rows"].as_array().unwrap().len() as u64, crate::connections::PAGE);
    assert!(!c.top.is_empty());
    assert!(h.has_text("Top subscribers"));
    assert!(h.has_text("Tracking…"));
    assert!(h.has_text(&format!("1–500 of {total}")), "page");
    assert!(h.has_text("software") || h.has_text("hardware"), "Via chips");
    assert!(h.has_text("c1"), "pool chip on the source");
}

#[test]
fn a_top_subscriber_click_filters_and_kill_removes() {
    let mut h = harness();
    let first = h.app.panel_mut::<Connections>().unwrap().top[0]["subscriber"].as_str().unwrap().to_owned();
    h.click(h.text(&first));
    refresh(&mut h);
    let c = h.app.panel_mut::<Connections>().unwrap();
    assert_eq!(c.filters.subscriber, first);
    let mine = c.list["total"].as_u64().unwrap();
    assert!(mine > 0 && mine < 2000, "{mine}");
    assert!(c.list["rows"].as_array().unwrap().iter().all(|r| r["src"].as_str().unwrap().starts_with(&first)));
    // Kill matching asks first, then removes them all.
    h.click(h.text(&format!("Kill matching ({mine})")));
    h.idle();
    assert!(h.app.panel_mut::<Connections>().unwrap().confirm_kill.is_some());
    // The modal's button is painted last: the topmost "Kill".
    h.click(h.text("Kill"));
    refresh(&mut h);
    let left = h.app.panel_mut::<Connections>().unwrap().list["total"].clone();
    assert_eq!(left, 0, "{:?}", h.app.log());
}

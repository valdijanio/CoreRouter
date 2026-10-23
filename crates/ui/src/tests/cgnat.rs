//! CGNAT (G2.3d): the window's tabs over a lab with a pool, the pool
//! dialog creating one, "who was" answering from the formula, the mapping
//! page, the blocks and alerts of a blocks-mode pool.

use super::*;
use crate::cgnat::{Cgnat, Tab, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness(pools: &[Value]) -> Harness {
    let mut s = Session::virtual_lab();
    s.tick(1_780_000_000);
    for p in pools {
        s.execute("ip.firewall.cgnat.pool.add", p).unwrap();
    }
    s.tick(1_780_000_001);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn pool() -> Value {
    json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"})
}

#[test]
fn the_pools_tab_shows_the_numbers() {
    let h = harness(&[pool()]);
    assert!(h.has_text("c1"));
    assert!(h.has_text("deterministic"));
    assert!(h.has_text("16/16 IPs"), "capacity chip");
    assert!(h.has_text("Who Was") && h.has_text("Mapping") && h.has_text("Alerts"));
    assert!(!h.has_text("Blocks"), "no blocks tab without a blocks pool");
    assert!(h.has_text_containing("365 days"), "history kept");
}

#[test]
fn the_modal_adds_a_pool_after_its_preview() {
    let mut h = harness(&[]);
    h.click(h.ctx.read_response(table::tool_id("cgnat-pools", table::Icon::Add)).unwrap().rect.center());
    {
        let c = h.app.panel_mut::<Cgnat>().unwrap();
        let (_, m) = c.modal.as_mut().expect("the modal opened");
        for (k, v) in [("name", "p2"), ("inside", "100.65.0.0/24"), ("outside", "198.51.100.0/30"), ("ports_per_subscriber", "500")] {
            m.values.insert(k, v.into());
        }
    }
    // The preview answers (numbers, checks, the command), then OK.
    for _ in 0..30 {
        h.time += 0.1;
        h.idle();
    }
    assert!(h.has_text("129"), "per public address, from the preview");
    assert!(h.has_text_containing("ip firewall cgnat pool add"), "the command shown");
    h.click(h.text("OK"));
    refresh(&mut h);
    let pools = lock(&h.session).store().running().ip.cgnat.pools.clone();
    assert_eq!(pools.len(), 1, "{:?}", h.app.log());
    assert_eq!(pools[0].ports_per_subscriber, 500);
    assert!(h.app.panel_mut::<Cgnat>().unwrap().modal.is_none());
}

#[test]
fn the_bar_disables_and_enables_a_pool() {
    let mut h = harness(&[pool()]);
    h.click(h.text("c1"));
    h.click(h.ctx.read_response(table::tool_id("cgnat-pools", table::Icon::Disable)).unwrap().rect.center());
    refresh(&mut h);
    assert!(lock(&h.session).store().running().ip.cgnat.pools[0].disabled, "{:?}", h.app.log());
    h.click(h.ctx.read_response(table::tool_id("cgnat-pools", table::Icon::Enable)).unwrap().rect.center());
    refresh(&mut h);
    assert!(!lock(&h.session).store().running().ip.cgnat.pools[0].disabled);
}

#[test]
fn who_was_answers_from_the_formula() {
    let mut h = harness(&[pool()]);
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
    assert!(h.has_text("203.0.113.1  2024–3023"));
}

#[test]
fn the_mapping_tab_pages_the_table() {
    let mut h = harness(&[pool()]);
    h.click(h.text("Mapping"));
    refresh(&mut h);
    assert_eq!(h.app.panel_mut::<Cgnat>().unwrap().tab, Tab::Mapping);
    assert!(h.has_text("1–500 of 1024"));
    assert!(h.has_text("100.64.0.5"));
    {
        let c = h.app.panel_mut::<Cgnat>().unwrap();
        c.mapping_find = "203.0.113.2".into();
    }
    refresh(&mut h);
    assert!(h.has_text("1–64 of 64"), "one public address: its 64 subscribers");
}

#[test]
fn blocks_and_alerts_of_a_blocks_pool() {
    let mut h = harness(&[json!({"name": "pba", "mode": "blocks", "inside": "100.64.0.0/22", "outside": "203.0.113.0/30", "alert_percent": 50, "max_blocks": 1})]);
    h.click(h.text("Blocks"));
    refresh(&mut h);
    assert!(h.has_text("40 blocks in use"), "the lab's online subscribers");
    assert!(h.has_text("Block log"));
    h.click(h.text("Alerts"));
    refresh(&mut h);
    let alerts = h.app.panel_mut::<Cgnat>().unwrap().alerts.clone();
    assert!(!alerts["rows"].as_array().unwrap().is_empty(), "heavy users at their one block: {alerts}");
}

//! Routing › OSPF (G3.4c): the tabs over the virtual lab's sample (the
//! neighbors with their state selos and the Diagnose, the lists with the
//! modal fed by the engine's preview, the LSDB, the routes with "Why this
//! path?", the topology), the ⓘ of every label, and the topology's frame
//! time with 500 routers.

use super::*;
use crate::ospf::{OspfPanel, Tab, What};
use crate::ospf_topology::{View, paint};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (a, i) in [("10.0.1.1/24", "ether1"), ("10.0.2.1/30", "ether2")] {
        s.execute("ip.address.add", &json!({"address": a, "interface": i})).unwrap();
    }
    s.execute("routing.ospf.instance.add", &json!({"name": "v2", "router_id": "10.255.0.1", "redistribute": "connected"})).unwrap();
    s.execute("routing.ospf.area.add", &json!({"name": "backbone", "instance": "v2", "area_id": "0.0.0.0"})).unwrap();
    s.execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "networks": "10.0.0.0/16", "auth_key": "S3cretKey"}))
        .unwrap();
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ospf::WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

fn panel(h: &mut Harness) -> &mut OspfPanel {
    h.app.panel_mut::<OspfPanel>().unwrap()
}

fn tab(h: &mut Harness, t: Tab) {
    panel(h).tab = t;
    refresh(h);
    refresh(h);
}

#[test]
fn neighbors_show_the_state_and_the_diagnose() {
    let mut h = open(lab());
    for t in ["Neighbors", "Full · DR", "ExStart", "10.250.0.1", "ether1", "ether2", "0.0.0.0 backbone", "virtual lab sample", "2 neighbors", "1 full"] {
        assert!(h.has_text(t), "{t}");
    }
    h.click(h.text("ExStart"));
    h.idle();
    h.click(h.text("Diagnose"));
    refresh(&mut h);
    settle(&mut h);
    assert!(h.has_text("RFC 2328 §10.6"), "{:?}", panel(&mut h).diagnose);
    assert_eq!(panel(&mut h).diagnose["findings"][0]["check"], "stuck-exstart");
}

#[test]
fn lists_lsdb_routes_and_topology() {
    let mut h = open(lab());
    tab(&mut h, Tab::Instances);
    for t in ["v2", "v2 IPv4", "10.255.0.1", "connected", "1 instances"] {
        assert!(h.has_text(t), "{t}");
    }
    tab(&mut h, Tab::Areas);
    for t in ["backbone", "0.0.0.0 backbone", "default", "ether1, ether2"] {
        assert!(h.has_text(t), "{t}");
    }
    tab(&mut h, Tab::Templates);
    for t in ["10.0.0.0/16", "sha256", "ether1, ether2", "1 warning"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(!h.has_text("S3cretKey"), "the key is never shown");
    tab(&mut h, Tab::Lsdb);
    let total = panel(&mut h).lsas["total"].as_u64().unwrap();
    for t in ["router", "self", "10.255.0.1", "80000005", &format!("{total} LSAs")] {
        assert!(h.has_text(t), "{t}");
    }
    tab(&mut h, Tab::Routes);
    assert!(h.has_text("172.16.0.0/24"), "routes");
    panel(&mut h).path_to = "172.16.0.9".into();
    panel(&mut h).path_asked = Some("172.16.0.9".into());
    refresh(&mut h);
    for t in ["Why this path?", "Σ 21", "agrees"] {
        assert!(h.has_text(t), "{t}: {}", panel(&mut h).path);
    }
    tab(&mut h, Tab::Topology);
    assert!(panel(&mut h).topo.nodes.len() >= 5, "{:?}", panel(&mut h).topology);
    assert!(panel(&mut h).topo.nodes.iter().any(|n| n.me));
}

#[test]
fn the_modal_adds_an_area_through_the_preview_and_warns_of_drops() {
    let mut h = open(lab());
    tab(&mut h, Tab::Areas);
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<OspfPanel, _>(|p, app| {
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| p.add_for_test(app, What::Area, ui));
            out.textures_delta.clear();
        })
        .unwrap();
    h.idle();
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("name", "edge".into());
    m.values.insert("instance", "v2".into());
    m.values.insert("area_id", "0.0.0.1".into());
    m.values.insert("type", "stub".into());
    settle(&mut h);
    assert!(panel(&mut h).modal.is_some());
    h.click(h.text("OK"));
    settle(&mut h);
    let rows = lock(&h.session).execute("routing.ospf.area.list", &json!({})).unwrap();
    assert!(rows.as_array().unwrap().iter().any(|r| r["name"] == "edge" && r["type"] == "stub"), "{:?}", h.app.log());
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in OspfPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}

/// The topology of 500 routers, painted: the frame must fit 60 fps.
#[test]
fn five_hundred_routers_paint_within_a_frame() {
    let n = 500usize;
    let nodes: Vec<serde_json::Value> = (0..n)
        .map(|i| {
            let a = i as f64 / n as f64 * std::f64::consts::TAU;
            json!({"key": format!("r:{i}"), "kind": "router", "id": i.to_string(), "label": format!("10.255.{}.{}", i / 256, i % 256),
                   "x": 0.5 + 0.45 * a.cos(), "y": 0.5 + 0.45 * a.sin(), "abr": i % 50 == 0, "asbr": false, "self": i == 0})
        })
        .collect();
    let edges: Vec<serde_json::Value> = (0..n).map(|i| json!({"a": format!("r:{i}"), "b": format!("r:{}", (i + 1) % n), "cost": 10})).collect();
    let mut v = View::default();
    v.arrived(&json!({"nodes": nodes, "edges": edges, "areas": ["0.0.0.0"], "area": "0.0.0.0"}));
    let ctx = egui::Context::default();
    let path: Vec<String> = (0..20).map(|i| format!("r:{i}")).collect();
    let mut times = Vec::new();
    for _ in 0..20 {
        let start = std::time::Instant::now();
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            let rect = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1000.0, 700.0));
            let _ = paint(ui, rect, &v, &path, None, Some(egui::pos2(500.0, 350.0)));
        });
        // The whole frame: the shapes and their tessellation into triangles.
        let meshes = ctx.tessellate(std::mem::take(&mut out.shapes), out.pixels_per_point);
        times.push(start.elapsed());
        assert!(!meshes.is_empty());
        out.textures_delta.clear();
    }
    times.sort();
    let median = times[times.len() / 2];
    eprintln!("ospf topology, 500 routers: frame (paint + tessellate) {median:?}, median of 20");
    // 16.7 ms is a 60 fps frame: the bar for an optimized build. A debug
    // build on a shared CI machine varies several times over, so it only
    // catches a large regression (AGENTS.md: the CI does not fail on a
    // benchmark, only on a large regression).
    let limit = if cfg!(debug_assertions) { 100 } else { 16 };
    assert!(median < std::time::Duration::from_millis(limit), "{median:?} (limit {limit} ms)");
}

#[test]
fn a_click_on_a_tab_switches_it() {
    let mut h = open(lab());
    h.click(h.text("Key Chains"));
    refresh(&mut h);
    assert_eq!(panel(&mut h).tab, Tab::Keychains);
}

/// G3.9c: the Stub Router column and the Drain / Undrain button of the
/// Instances tab run `stub_router` on the selected instance.
#[test]
fn drain_and_undrain_an_instance() {
    let mut h = open(lab());
    tab(&mut h, Tab::Instances);
    assert!(h.has_text("Stub Router"));
    assert!(!h.has_text("administrative"));
    h.click(h.text("10.255.0.1"));
    h.idle();
    h.click(h.text("Drain"));
    settle(&mut h);
    refresh(&mut h);
    assert!(lock(&h.session).store().running().routing.ospf.instances["v2"].stub_router);
    assert!(h.has_text("administrative"), "{:?}", panel(&mut h).instances);
    h.click(h.text("Undrain"));
    settle(&mut h);
    refresh(&mut h);
    assert!(!lock(&h.session).store().running().routing.ospf.instances["v2"].stub_router);
    assert!(h.has_text("Drain"));
}

/// G3.4n: on a network read from the daemon (`engine::perf::ospf_scale`),
/// Routes comes a page at a time with the total and the counts, the search
/// runs on the router over every route, and the map held is kept when the
/// router answers `unchanged`.
#[test]
fn routes_page_on_the_router_and_the_map_is_not_sent_again() {
    let mut h = open(corerouter_engine::perf::ospf_scale(200, 50, 100, 1_000, 3_000));
    panel(&mut h).instance = "v2".into();
    tab(&mut h, Tab::Routes);
    assert_eq!(panel(&mut h).routes["rows"].as_array().unwrap().len(), 200);
    for t in ["3000 routes", "2000 intra-area", "1000 external", "1–200 of 3000"] {
        assert!(h.has_text(t), "{t}");
    }
    h.click(h.text(">"));
    refresh(&mut h);
    assert!(h.has_text("201–400 of 3000"));
    let second = panel(&mut h).routes["rows"][0]["prefix"].clone();
    assert_eq!(second, format!("{}/24", std::net::Ipv4Addr::from(0x1400_0000u32 + 200 * 256)));
    // A search goes to the router and starts at the first page.
    panel(&mut h).route_table.filter = "20.0.1.".into();
    refresh(&mut h);
    refresh(&mut h);
    assert_eq!(panel(&mut h).route_page, 0);
    assert_eq!(panel(&mut h).routes["total"], 1);
    assert!(!h.has_text("of 1"), "one page: no pager");
    tab(&mut h, Tab::Topology);
    let nodes = panel(&mut h).topo.nodes.len();
    assert!(nodes >= 100, "{nodes}");
    let token = panel(&mut h).topo.token.clone();
    assert!(!token.is_empty());
    refresh(&mut h);
    // The second answer was `unchanged`: the map and its token stay.
    assert_eq!((panel(&mut h).topo.nodes.len(), panel(&mut h).topo.token.clone()), (nodes, token));
    assert!(panel(&mut h).topology["nodes"].as_array().is_some_and(|n| n.len() == nodes));
}

/// G3.4r: the LSDB column (the count against the limit), the modal's LSDB
/// Protection page (its fields and what the database holds now) and
/// Clear LSDB Protection, greyed while nothing is held down.
#[test]
fn lsdb_protection_column_page_and_clear() {
    let mut h = open(lab());
    tab(&mut h, Tab::Instances);
    assert!(h.has_text("LSDB"));
    lock(&h.session).execute("routing.ospf.instance.set", &json!({"id": "v2", "max_lsa": 50_000})).unwrap();
    refresh(&mut h);
    assert!(h.has_text_containing("0 / 50 000"), "{:?}", panel(&mut h).instances);
    assert!(h.has_text("Clear LSDB Protection"));
    // Selected, it stays greyed: the lab's protection is normal.
    h.click(h.text("10.255.0.1"));
    h.idle();
    h.click(h.text("Clear LSDB Protection"));
    settle(&mut h);
    assert!(!h.app.log().iter().any(|l| l.command.contains("clear-lsdb-protection")), "{:?}", h.app.log());
    // The edit modal: General first; LSDB Protection shows the fields.
    h.click(h.text("10.255.0.1"));
    h.click(h.text("10.255.0.1"));
    settle(&mut h);
    assert!(panel(&mut h).modal.is_some());
    assert!(h.has_text("Router ID") && !h.has_text("Ignore Count"));
    h.click(h.text("LSDB Protection"));
    settle(&mut h);
    assert!(h.has_text("Ignore Count") && h.has_text("Warning Threshold"));
    assert!(h.has_text_containing("Now: 0 LSAs of other routers"), "{:?}", panel(&mut h).instances);
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    assert_eq!(m.values["max_lsa"], "50000");
    m.values.insert("max_lsa_ignore_time", "60".into());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let m = lock(&h.session).store().running().routing.ospf.instances["v2"].max_lsa.unwrap();
    assert_eq!((m.limit, m.ignore_time), (50_000, 60), "{:?}", h.app.log());
}

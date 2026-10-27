//! IP › Routes read and diagnosed (G1.27a): state and origin chips, the
//! gateway in parts, the reason in the explanations' language, ECMP groups
//! that open on a click, the filters, the footer counts and the lookup bar.

use super::*;
use crate::i18n::Lang;
use crate::routes::{Family, Route, View, age, counts, rows_of};

fn route(v: Value) -> Route {
    Route::from_row(&v)
}

fn sample() -> Vec<Route> {
    vec![
        route(json!({"key": "*1", "id": "*1", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1",
            "gateway_address": "10.0.0.1", "gateway_status": "reachable", "interface": "ether1",
            "distance": 1, "routing_table": "main", "state": "active", "active": true,
            "origin": "static", "ecmp": 2, "changed_secs": 75})),
        route(json!({"key": "*2", "id": "*2", "dst_address": "0.0.0.0/0", "gateway": "10.0.1.1",
            "gateway_address": "10.0.1.1", "gateway_status": "reachable", "interface": "ether2",
            "distance": 1, "routing_table": "main", "state": "active", "active": true,
            "origin": "static", "ecmp": 2})),
        route(json!({"key": "*3", "id": "*3", "dst_address": "0.0.0.0/0", "gateway": "10.0.1.9",
            "gateway_address": "10.0.1.9", "gateway_status": "reachable", "interface": "ether2",
            "distance": 5, "routing_table": "main", "state": "standby", "origin": "static",
            "reason": "loses to distance 1 (route *1 via 10.0.0.1%ether1)",
            "reason_id": "loses-distance",
            "reason_args": {"distance": "1", "route": "*1", "via": "10.0.0.1%ether1"}})),
        route(json!({"key": "connected main 10.0.0.0/24 ether1", "id": null,
            "dst_address": "10.0.0.0/24", "gateway": "ether1", "gateway_interface": "ether1",
            "distance": 0, "routing_table": "main", "state": "active", "active": true,
            "origin": "connected", "dynamic": true})),
        route(json!({"key": "*4", "id": "*4", "dst_address": "::/0", "gateway": "2001:db8::1",
            "gateway_address": "2001:db8::1", "gateway_status": "unreachable", "distance": 1,
            "routing_table": "blue", "state": "inactive", "origin": "static",
            "reason": "interface 'ether3' has no link", "reason_id": "interface-down",
            "reason_args": {"interface": "ether3"}})),
    ]
}

fn langs(help: Lang) -> i18n::Langs {
    i18n::Langs {
        labels: Lang::En,
        help,
    }
}

#[test]
fn an_ecmp_group_is_one_line_until_opened() {
    let routes = sample();
    let mut view = View::default();
    let rows = rows_of(&routes, &view, langs(Lang::En));
    let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(
        keys,
        ["ecmp main 0.0.0.0/0", "*3", "connected main 10.0.0.0/24 ether1", "*4"]
    );
    assert!(rows[0].cells[2].starts_with("+ 2 next-hops"), "{:?}", rows[0].cells);
    view.open.insert("ecmp main 0.0.0.0/0".into());
    let rows = rows_of(&routes, &view, langs(Lang::En));
    let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys[..3], ["ecmp main 0.0.0.0/0", "*1", "*2"]);
    assert!(rows[0].cells[2].starts_with("- 2 next-hops"));
}

#[test]
fn filters_by_family_origin_state_and_table() {
    let routes = sample();
    let shown = |view: &View| -> Vec<String> {
        rows_of(&routes, view, langs(Lang::En))
            .into_iter()
            .map(|r| r.key)
            .collect()
    };
    let mut v = View {
        family: Family::V6,
        ..View::default()
    };
    assert_eq!(shown(&v), ["*4"]);
    v.family = Family::V4;
    v.origins.insert("connected".into());
    assert_eq!(shown(&v), ["connected main 10.0.0.0/24 ether1"]);
    let v = View {
        state: Some("standby"),
        ..View::default()
    };
    assert_eq!(shown(&v), ["*3"]);
    let v = View {
        table: Some("blue".into()),
        ..View::default()
    };
    assert_eq!(shown(&v), ["*4"]);
}

#[test]
fn cells_carry_chips_and_the_reason_is_translated() {
    let routes = sample();
    let rows = rows_of(&routes, &View::default(), langs(Lang::Pt));
    let standby = rows.iter().find(|r| r.key == "*3").unwrap();
    let (_, state) = chip::split(&standby.cells[0]);
    assert_eq!(state, vec![(chip::Kind::Amber, "standby")]);
    let (gw, chips) = chip::split(&standby.cells[2]);
    assert_eq!(gw, "10.0.1.9");
    assert_eq!(
        chips,
        vec![(chip::Kind::Neutral, "ether2"), (chip::Kind::Green, "reachable")]
    );
    assert_eq!(
        standby.cells[6],
        "perde para a distância 1 (rota *1 via 10.0.0.1%ether1)"
    );
    let (_, table) = chip::split(&standby.cells[4]);
    assert_eq!(table, vec![(chip::Kind::Hashed(chip::name_hue("main")), "main")]);
    let english = rows_of(&routes, &View::default(), langs(Lang::En));
    let down = english.iter().find(|r| r.key == "*4").unwrap();
    assert_eq!(down.cells[6], "interface 'ether3' has no link");
    let (_, chips) = chip::split(&down.cells[2]);
    assert!(chips.contains(&(chip::Kind::Red, "unreachable")));
}

#[test]
fn footer_counts_and_ages() {
    let c = counts(&sample());
    assert_eq!(
        (c.total, c.active, c.standby, c.inactive, c.v4, c.v6),
        (5, 3, 1, 1, 4, 1)
    );
    assert_eq!(age(None), "–");
    assert_eq!(age(Some(42)), "42s");
    assert_eq!(age(Some(75)), "1m");
    assert_eq!(age(Some(7_200)), "2h");
    assert_eq!(age(Some(200_000)), "2d");
}

/// The highest text painted exactly as `needle` (a filter chip, above the
/// rows that repeat its word).
fn topmost(h: &Harness, needle: &str) -> egui::Pos2 {
    fn walk(shape: &egui::Shape, needle: &str, out: &mut Vec<egui::Pos2>) {
        match shape {
            egui::Shape::Text(t) if t.galley.text() == needle => {
                out.push(t.visual_bounding_rect().center());
            }
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, needle, out)),
            _ => {}
        }
    }
    let mut all = Vec::new();
    for s in &h.shapes {
        walk(&s.shape, needle, &mut all);
    }
    all.into_iter()
        .min_by(|a, b| a.y.total_cmp(&b.y))
        .unwrap_or_else(|| panic!("no {needle}"))
}

/// The window over the lab: ether1 10.0.0.2/24, ether2 10.0.1.2/24, two
/// equal default routes and a backup.
fn lab() -> Harness {
    let mut h = Harness::routes();
    {
        let mut s = lock(&h.session);
        s.execute(
            "ip.address.add",
            &json!({"address": "10.0.1.2/24", "interface": "ether2"}),
        )
        .unwrap();
        for (gw, d) in [("10.0.0.1", 1), ("10.0.1.1", 1), ("10.0.1.9", 5)] {
            s.execute(
                "ip.route.add",
                &json!({"dst_address": "0.0.0.0/0", "gateway": gw, "distance": d}),
            )
            .unwrap();
        }
    }
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h
}

#[test]
fn the_window_shows_states_groups_and_reasons() {
    let mut h = lab();
    for t in ["active", "standby", "ECMP", "+ 2 next-hops", "static", "connected", "main"] {
        assert!(h.has_text(t), "{t} not on screen");
    }
    assert!(h.has_text("perde para a distância 1 (rota *1 via 10.0.0.1%ether1)"));
    assert!(h.has_text("5 routes"), "footer");
    // A click on the group opens it: its two paths appear.
    h.click(h.route_row("ecmp main 0.0.0.0/0"));
    assert!(h.has_text("- 2 next-hops"));
    assert!(h.has_text("10.0.1.1"));
    h.click(h.route_row("*2"));
    assert!(h.route_tool(table::Icon::Disable).enabled());
    // A filter chip (the topmost "standby") hides the rest.
    h.click(topmost(&h, "standby"));
    assert!(!h.has_text("- 2 next-hops"));
    assert!(h.has_text("10.0.1.9"));
}

#[test]
fn the_lookup_bar_answers_with_the_kernel_check() {
    let mut h = lab();
    h.click(h.text("8.8.8.8"));
    h.type_text("10.0.1.77");
    h.click(h.text("Lookup"));
    h.idle();
    for t in ["10.0.1.77:", "10.0.1.0/24", "connected", "src 10.0.1.2", "kernel agrees"] {
        assert!(h.has_text(t), "{t} not in the answer");
    }
    h.click(h.text("10.0.1.77"));
    h.key(egui::Key::A, CTRL);
    h.type_text("nope");
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    h.idle();
    assert!(h.has_text_containing("address"), "the error is shown");
}

#[test]
fn the_selected_route_shows_its_detail() {
    let mut h = lab();
    h.click(h.route_row("*3"));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    for t in ["Source", "static route", "Chosen", "Check gateway", "Changes (24 h)", "Kernel", "matches the config"] {
        assert!(h.has_text(t), "{t} not in the detail");
    }
    assert!(h.has_text_containing("rev "), "the creating revision");
    assert!(h.has_text_containing("perde para a distância 1"), "translated");
    // An ECMP group's line shows its first path.
    h.click(h.route_row("ecmp main 0.0.0.0/0"));
    h.idle();
    h.idle();
    assert!(h.has_text_containing("divide o tráfego com mais 1 caminho(s)"));
    // Nothing selected: no detail.
    h.app.tables.routes.clear();
    h.idle();
    assert!(!h.has_text("Chosen"));
}

// ---- G1.27c: a full table, page by page ----

/// The Routes window over a table of `n` routes (no connected ones but
/// ether1's two networks).
fn big(n: usize) -> Harness {
    let s = corerouter_engine::perf::with_running(corerouter_engine::perf::full_table(n));
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Routes);
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h
}

#[test]
fn a_big_table_comes_a_page_at_a_time() {
    let mut h = big(1_200);
    assert_eq!(h.app.cache.routes.len(), crate::routes::PAGE, "one page only");
    assert!(h.has_text_containing("1–500 of 1202"), "the pager");
    assert!(h.has_text("1202 routes"), "the counts are the whole table's");
    h.click(h.text(">"));
    h.idle();
    assert_eq!(h.app.route_view.page, Some((1202, 500)), "{:?}", h.app.route_view.offset);
    assert!(h.has_text_containing("501–1000 of 1202"));
    assert_eq!(h.app.route_view.offset, 500);
    // A filter goes back to the first page.
    h.click(topmost(&h, "IPv6"));
    h.idle();
    assert_eq!(h.app.route_view.offset, 0);
    assert!(h.app.cache.routes.iter().all(|r| r["family"] == "ipv6"));
}

#[test]
fn aggregate_lines_open_on_a_click() {
    let mut h = big(600);
    h.click(h.text("aggregate /16"));
    h.idle();
    assert!(h.app.cache.routes.iter().any(|r| r["bucket"] == true));
    // 11.0.0.0/16: its /24s folded (the route 11.0.0.0/16 itself stays).
    let bucket = "bucket main 11.0.0.0/16";
    assert!(h.has_text_containing("routes"), "the bucket says how many");
    h.click(h.route_row(bucket));
    h.idle();
    assert_eq!(h.app.route_view.prefix, "11.0.0.0/16");
    assert!(!h.app.route_view.aggregate);
    assert!(h.app.cache.routes.iter().all(|r| r["dst_address"]
        .as_str()
        .unwrap()
        .starts_with("11.0.")));
    // Clearing the search goes back to the aggregated view.
    h.click(h.text("x"));
    h.idle();
    assert!(h.app.route_view.aggregate && h.app.route_view.prefix.is_empty());
}

#[test]
fn the_prefix_search_asks_the_router() {
    let mut h = big(600);
    h.click(h.text("10.0.0.0/8"));
    h.type_text("11.0.2.0/24");
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    h.idle();
    let dsts: Vec<&str> = h
        .app
        .cache
        .routes
        .iter()
        .filter_map(|r| r["dst_address"].as_str())
        .collect();
    assert_eq!(dsts, ["11.0.2.0/24"]);
    // What contains it: the /16 and the /24.
    h.click(topmost(&h, "contains"));
    h.idle();
    assert_eq!(h.app.cache.routes.len(), 2, "{:?}", h.app.cache.routes);
    // A typo is not sent (the table keeps its rows).
    assert!(!crate::routes::valid_prefix("11.0.1.0/33"));
    assert!(crate::routes::valid_prefix("2001:db8::/32"));
    assert!(crate::routes::valid_prefix(" 8.8.8.8 "));
}

#[test]
fn a_gateway_that_does_not_resolve_shows_an_amber_incomplete_chip() {
    // G1.27d: routed, but nothing answers ARP/ND for the gateway.
    let r = route(json!({"key": "*9", "id": "*9", "dst_address": "192.0.2.0/24",
        "gateway": "10.0.0.77", "gateway_address": "10.0.0.77", "gateway_status": "incomplete",
        "interface": "ether1", "distance": 1, "routing_table": "main", "state": "active",
        "active": true, "origin": "static"}));
    let cell = r.gateway_cell();
    let (text, chips) = crate::chip::split(&cell);
    assert_eq!(text, "10.0.0.77");
    assert!(chips.contains(&(crate::chip::Kind::Amber, "incomplete")), "{chips:?}");
}

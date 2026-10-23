//! Tools › Graphs (G4.5): the window reads the router's history
//! (`system.graph.query`), shows the statistics the router computed, switches
//! range, compares, exports CSV, changes what is kept; the Interfaces window
//! shows a mini graph per kept interface.

use super::*;
use crate::graphs::{Graphs, Range};
use crate::spark::Spark;

const T0: u64 = 1_800_000_000;

fn refresh(h: &mut Harness) {
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
}

/// A lab with `secs` seconds of history.
fn harness(secs: u64) -> Harness {
    let mut s = Session::virtual_lab();
    for t in 0..secs {
        s.tick(T0 + t);
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::graphs::WIN));
    refresh(&mut h);
    h
}

fn graphs(h: &mut Harness) -> &mut Graphs {
    h.app.panel_mut::<Graphs>().unwrap()
}

#[test]
fn the_window_shows_the_routers_numbers() {
    let mut h = harness(400);
    let g = graphs(&mut h);
    assert_eq!(g.series, "ether1", "the first interface is picked");
    let data = g.data.clone().expect("the query came back");
    assert_eq!(data["resolution"], 1);
    let p95 = data["series"][0]["stats"]["rx_bps"]["p95"].as_f64().unwrap();
    assert!(p95 > 0.0);
    for t in ["Current", "Average", "Maximum", "95th pct", "Total", "p95 billing", "resolution 1 s"] {
        assert!(h.has_text(t), "{t}");
    }
    // The router's number, formatted, is on screen.
    assert!(h.has_text(&crate::graphs::rate(p95, "bps")), "{p95}");
}

#[test]
fn range_compare_and_system() {
    let mut h = harness(200);
    h.click(h.text("Day"));
    refresh(&mut h);
    assert_eq!(graphs(&mut h).range, Range::Day);
    assert_eq!(graphs(&mut h).data.as_ref().unwrap()["resolution"], 60);

    graphs(&mut h).compare.push("ether2".into());
    graphs(&mut h).range = Range::Hour;
    refresh(&mut h);
    let data = graphs(&mut h).data.clone().unwrap();
    let names: Vec<&str> = data["series"].as_array().unwrap().iter().map(|s| s["series"].as_str().unwrap()).collect();
    assert_eq!(names, ["interface:ether1", "interface:ether2"]);
    assert!(h.has_text("ether2 Rx"));

    graphs(&mut h).series = "system".into();
    refresh(&mut h);
    for t in ["CPU", "Memory", "Conntrack"] {
        assert!(h.has_text(t), "{t}");
    }
    let cpu = graphs(&mut h).data.clone().unwrap()["series"][0]["stats"]["cpu"]["avg"].as_f64().unwrap();
    assert!(cpu > 0.0 && cpu <= 100.0, "{cpu}");
}

#[test]
fn csv_has_every_point() {
    let mut h = harness(200);
    let g = graphs(&mut h);
    let csv = g.csv().unwrap();
    let mut lines = csv.lines();
    let head = lines.next().unwrap();
    assert!(head.starts_with("time_utc,unix,series,"), "{head}");
    assert!(head.contains("rx_bps") && head.contains("tx_bps_max"), "{head}");
    let points = g.data.as_ref().unwrap()["points"].as_u64().unwrap();
    assert_eq!(lines.clone().count() as u64, points);
    let last = csv.lines().last().unwrap();
    assert!(last.contains(",ether1,"), "{last}");
    // No saver in tests: the CSV goes to the clipboard.
    h.click(h.text("CSV"));
    h.idle();
    assert_eq!(graphs(&mut h).status, Some(Ok("copied to the clipboard".into())));
}

#[test]
fn settings_change_what_is_kept() {
    let mut h = harness(5);
    h.click(h.text("Settings…"));
    h.idle();
    assert!(h.has_text("Max Memory (MiB)"));
    let d = graphs(&mut h).settings.as_mut().unwrap();
    d.switches[3] = true; // VLANs
    d.fields[2] = "128".into();
    assert_eq!(
        Graphs::settings_params(d),
        json!({"vlans": true, "max_memory_mib": 128})
    );
    h.click(h.text("OK"));
    refresh(&mut h);
    let g = lock(&h.session).store().running().system.graphing.clone();
    assert!(g.vlans);
    assert_eq!(g.max_memory_mib, 128);
    assert!(graphs(&mut h).settings.is_none(), "closed once accepted");
}

#[test]
fn interfaces_show_a_mini_graph() {
    let mut h = harness(120);
    h.app.open.clear();
    h.app.open(Win::Interfaces);
    refresh(&mut h);
    let cells = h.app.panel_mut::<Spark>().unwrap().cells.clone();
    let e1 = cells.get("ether1").expect("ether1 has a sparkline");
    assert!(e1.starts_with(crate::spark::SEP));
    assert!(crate::spark::tip(e1).unwrap().starts_with("5 min: Rx "));
    assert!(h.has_text("Traffic"), "the column");
}

#[test]
fn numbers_read_well() {
    use crate::graphs::rate;
    assert_eq!(rate(12_500_000.0, "bps"), "12.5 Mbps");
    assert_eq!(rate(227_900.0, "entries"), "227.9 k");
    assert_eq!(rate(5.0, "entries"), "5.00");
    assert_eq!(rate(41.26, "%"), "41.3 %");
    assert_eq!(rate(f64::NAN, "bps"), "–");
}

#[test]
fn spark_cells_scale_to_the_top_and_mark_holes() {
    let c = crate::spark::cell(&[Some(0.0), Some(50.0), None, Some(100.0)], &[Some(100.0), None]);
    let body = c.strip_prefix(crate::spark::SEP).unwrap();
    assert!(body.starts_with("08-f/f-/"), "{body}");
}

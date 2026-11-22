//! System › OS Log (G4.8b), a panel: the lab's OS log with level and
//! source chips, find, repeats folded with a count, the detail pane with
//! "O que significa" and the buttons to the window that fixes it; the tab
//! Resources draws; 100 000 lines through the table.

use super::*;
use crate::os_log::{MAX_ROWS, OsLogPanel, WIN, repeated};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open() -> Harness {
    let mut s = Session::virtual_lab();
    s.tick(1_792_843_200); // 2026-10-24 12:00:00 UTC
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn panel(h: &mut Harness) -> &mut OsLogPanel {
    h.app.panel_mut::<OsLogPanel>().unwrap()
}

/// The text of the `error N` chip.
fn error_chip(h: &mut Harness) -> String {
    format!("error {}", panel(h).counts[0])
}

#[test]
fn os_log_window_shows_rows_chips_and_sources() {
    let mut h = open();
    for t in ["Time", "Level", "Source", "Message", "kernel", "services", "auth", "lab"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(h.has_text_containing("error "), "the error chip has its count");
    assert!(h.has_text("37×"), "37 drops are one row");
    assert!(h.has_text("Anel de recepção da placa cheio"), "known message chip");
    assert!(h.has_text("r8169"));
    assert!(h.has_text_containing("Failed password"));
    assert!(h.has_text("11:59:00"), "time of the day only, today");
    let n = panel(&mut h).shown.len();
    assert!(n > 15, "{n}");
    // Labels in Portuguese when chosen.
    h.app.lang.labels = crate::i18n::Lang::Pt;
    h.idle();
    for t in ["Hora", "Nível", "Origem", "Mensagem", "Fontes:"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn a_row_opens_its_detail_and_the_action_opens_tuning_on_the_port() {
    let mut h = open();
    h.click(h.text("37×"));
    assert!(panel(&mut h).selected.is_some());
    h.idle();
    for t in ["Details", "Driver / unit", "Device", "Priority", "this boot", "What it means"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(h.has_text("repetido 37× em 9 min"));
    assert!(h.has_text("warning (4)"));
    assert!(h.has_text_containing("anel (ring) de recepção"));
    assert!(h.has_text("Ver no gráfico"));
    h.click(h.text("Abrir Tuning › ether2"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(crate::tuning::WIN)));
    let t = h.app.panel_mut::<crate::tuning::TuningPanel>().unwrap();
    assert_eq!(t.tab, crate::tuning::Tab::Interfaces);
    assert_eq!(t.port.as_deref(), Some("ether2"));
    // The graph button opens Graphs.
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.idle();
    h.click(h.text("Ver no gráfico"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(crate::graphs::WIN)));
    // Click again: unselected; Esc clears the selection too.
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.idle();
    h.click(h.text("37×"));
    h.idle();
    assert!(panel(&mut h).selected.is_none());
}

#[test]
fn chips_and_find_filter_at_once() {
    let mut h = open();
    let all = panel(&mut h).shown.len();
    let chip = error_chip(&mut h);
    h.click(h.text(&chip));
    h.idle();
    h.idle();
    let p = panel(&mut h);
    let errors = p.shown.clone();
    assert!(!errors.is_empty() && errors.len() < all);
    assert!(errors.iter().all(|id| p.row(*id).unwrap().severity <= 3));
    h.click(h.text(&chip));
    panel(&mut h).sources = [false, false, true];
    h.idle();
    h.idle();
    let p = panel(&mut h);
    assert!(p.shown.iter().all(|id| p.row(*id).unwrap().source == "auth"));
    p.sources = [false; 3];
    p.find = "ETHER3".into();
    h.idle();
    h.idle();
    assert_eq!(panel(&mut h).shown.len(), 2, "Link Down and Link Up");
    panel(&mut h).find = "2211".into();
    h.idle();
    h.idle();
    assert!(!panel(&mut h).shown.is_empty(), "by PID");
    panel(&mut h).find = "nothing like this".into();
    h.idle();
    h.idle();
    assert!(h.has_text("No line passes the filters."));
}

#[test]
fn new_rows_arrive_incrementally_and_a_repeat_moves_its_row() {
    let mut h = open();
    let before = panel(&mut h).len();
    let p = panel(&mut h);
    let ring = p
        .shown
        .iter()
        .copied()
        .find(|id| p.row(*id).unwrap().count == 37)
        .unwrap();
    // The lab adds a drop every fifth ask.
    for _ in 0..6 {
        refresh(&mut h);
    }
    let p = panel(&mut h);
    assert_eq!(p.len(), before, "the repeat folds into its row");
    assert_eq!(p.row(ring).unwrap().count, 38);
    assert_eq!(p.shown.last(), Some(&ring), "the newest at the end");
}

#[test]
fn resources_tab_draws_the_same_view_and_asks_for_rows() {
    let mut s = Session::virtual_lab();
    s.tick(1_792_843_200);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    // Drawn as a tab (no OS Log window open): it still asks for rows.
    for _ in 0..4 {
        h.app.cache.refreshed_at = None;
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, h.screen)),
            time: Some(h.time),
            ..Default::default()
        };
        h.time += 0.02;
        let app = &mut h.app;
        let mut out = h.ctx.run_ui(raw, |ui| {
            app.ui(ui);
            egui::Window::new("Resources").show(ui.ctx(), |ui| crate::os_log::tab(app, ui));
        });
        out.textures_delta.clear();
    }
    assert!(panel(&mut h).len() > 15);
}

#[test]
fn repeated_says_how_often_and_over_how_long() {
    assert_eq!(repeated(1, 0, 0), "uma vez");
    assert_eq!(repeated(37, 1000, 1540), "repetido 37× em 9 min");
    assert_eq!(repeated(2, 10, 40), "repetido 2× em 30 s");
    assert_eq!(repeated(500, 0, 7500), "repetido 500× em 2 h 5 min");
}

#[test]
fn hostile_and_odd_replies_do_not_break_the_panel() {
    let mut h = open();
    let p = panel(&mut h);
    for v in [
        json!(null),
        json!([]),
        json!({"entries": "x"}),
        json!({"entries": [{"no": "id"}, {"id": "7"}, {"id": 1, "severity": 99, "message": "\u{202E}x".repeat(9000)}]}),
        json!({"counts": {"error": -1}, "sources": [{"name": 5}]}),
    ] {
        p.take(&v);
    }
    h.idle();
    h.idle();
    // Restart: the router's numbering went back, the panel starts over.
    let p = panel(&mut h);
    p.take(&json!({"last": 0, "entries": []}));
    assert_eq!(p.len(), 0);
}

/// 100 000 lines in 2000-row replies: the panel keeps [`MAX_ROWS`], and a
/// frame draws only the rows in view.
#[test]
fn hundred_thousand_lines_through_the_table() {
    let mut h = open();
    let started = std::time::Instant::now();
    let p = panel(&mut h);
    let base = 1_792_800_000_000_000u64;
    for batch in 0..50u64 {
        let entries: Vec<Value> = (0..2000u64)
            .map(|i| {
                let n = batch * 2000 + i + 1_000_000;
                let k = usize::try_from(n % 3).unwrap();
                let (level, severity, source) = [("error", 3, "kernel"), ("warning", 4, "services"), ("info", 6, "auth")][k];
                json!({
                    "id": n, "seq": n, "time_us": base + n * 1000, "first": 0,
                    "level": level, "severity": severity, "source": source,
                    "unit": "r8169", "device": "ether2", "pid": n % 30000,
                    "message": format!("r8169 0000:03:00.0 ether2: line {n} with some words after it"),
                    "count": 1 + n % 5, "boot": "b", "this_boot": true, "known": null,
                })
            })
            .collect();
        p.take(&json!({"entries": entries, "last": batch * 2000 + 2000 + 1_000_000}));
    }
    let fed = started.elapsed();
    assert_eq!(panel(&mut h).len(), MAX_ROWS);
    h.idle();
    let frames = 30;
    let t = std::time::Instant::now();
    for _ in 0..frames {
        h.idle();
    }
    let per_frame = t.elapsed() / frames;
    // Filter change: the 20 000 rows are filtered again once.
    panel(&mut h).find = "line 1099".into();
    let t = std::time::Instant::now();
    h.idle();
    let refilter = t.elapsed();
    eprintln!(
        "os_log table: 100000 lines fed in {fed:?}, {MAX_ROWS} rows held, {per_frame:?}/frame, refilter {refilter:?}"
    );
    assert!(!panel(&mut h).shown.is_empty());
    // A loose bound (debug build, shared machines): drawing must not grow
    // with the rows held.
    assert!(per_frame < std::time::Duration::from_millis(400), "{per_frame:?}");
}

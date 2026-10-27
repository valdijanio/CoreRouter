//! Hooks for `benches/frames.rs`: the real UI drawing big lists, so the
//! per-frame cost of a table, the firewall rules tab or a terminal shows up
//! in numbers (docs/perf.md). Not part of the API.
//!
//! The lists are put in the UI's cache as the router would send them (not
//! added through the engine: 10 000 adds would measure the engine), and the
//! UI clock stays put so no refresh replaces them between frames.

use corerouter_engine::{Session, shared};
use serde_json::{Value, json};

use crate::{CoreRouterUi, RequestId, Win, table};

/// One UI and the egui context it draws into.
pub struct Frames {
    ctx: egui::Context,
    app: CoreRouterUi,
    /// UI time: fixed, so no refresh runs between measured frames.
    time: f64,
}

impl Frames {
    fn with(session: Session, win: Option<Win>) -> Self {
        let mut app = CoreRouterUi::new(shared(session));
        app.open.clear();
        if let Some(w) = win {
            app.open(w);
        }
        let mut me = Self {
            ctx: egui::Context::default(),
            app,
            time: 0.0,
        };
        // Load every list (the local backend answers within the frame).
        me.frame();
        me.frame();
        me
    }

    /// IP › Addresses over `n` addresses whose comments are `comment_len`
    /// characters long; `select_all` selects every row first (Ctrl+A).
    pub fn addresses(n: usize, comment_len: usize, select_all: bool) -> Self {
        let mut me = Self::with(Session::virtual_lab(), Some(Win::Addresses));
        let comment = "c".repeat(comment_len);
        me.app.cache.addresses = (0..n)
            .map(|i| {
                json!({
                    "id": format!("*{:x}", i + 1),
                    "flags": "",
                    "address": format!("10.{}.{}.1/32", i / 256 % 256, i % 256),
                    "network": format!("10.{}.{}.1", i / 256 % 256, i % 256),
                    "interface": "ether1",
                    "origin": "static",
                    "comment": comment,
                })
            })
            .collect();
        if select_all {
            let rows: Vec<table::Row> = me
                .app
                .cache
                .addresses
                .iter()
                .map(|r| table::Row {
                    key: r.get("id").map(crate::value_text).unwrap_or_default(),
                    cells: Vec::new(),
                    dimmed: false,
                    section: false,
                    tint: None,
                })
                .collect();
            me.app.tables.addresses.select_all(&rows);
        }
        me.frame();
        me
    }

    /// IP › Firewall (Filter Rules) over `n` rules; every one after the
    /// first is shadowed by it (flag S, the "NUNCA CASA" description).
    pub fn firewall(n: usize) -> Self {
        let mut me = Self::with(Session::virtual_lab(), Some(Win::Firewall));
        let rules: Vec<Value> = (0..n)
            .map(|i| {
                json!({
                    "id": format!("*{:x}", i + 1),
                    "position": i,
                    "chain": "forward",
                    "family": "ip",
                    "action": "accept",
                    "flags": if i == 0 { "" } else { "S" },
                    "disabled": false,
                    "shadowed_by": if i == 0 { Value::Null } else { json!("*1") },
                    "section": null,
                    "src_address": format!("10.{}.{}.0/24", i / 256 % 256, i % 256),
                    "in_interface_list": "LAN",
                    "description": "aceita tudo que chega",
                    "comment": format!("rule {i}"),
                })
            })
            .collect();
        me.app
            .fw_arrived(crate::firewall::Feed::Filter, RequestId::MAX, rules);
        me.frame();
        me
    }

    /// IP › Routes over a full table of `n` routes (G1.27c): a session
    /// holding them, which the window asks for a page at a time (before
    /// G1.27c it received and drew the whole list each frame: 4.47 s per
    /// frame for a million, **medido**).
    pub fn routes(n: usize) -> Self {
        let mut me = Self::with(
            corerouter_engine::perf::with_running(corerouter_engine::perf::full_table(n)),
            Some(Win::Routes),
        );
        // Answers within the frame (local backend): let the page arrive.
        me.app.cache.refreshed_at = None;
        me.frame();
        me.frame();
        me
    }

    /// Rows the Routes window holds now (the page it received).
    pub fn routes_shown(&self) -> usize {
        self.app.cache.routes.len()
    }

    /// A terminal window holding `lines` output lines of `len` characters.
    pub fn terminal(lines: usize, len: usize) -> Self {
        let mut me = Self::with(Session::virtual_lab(), None);
        me.app.new_terminal();
        let line = "x ".repeat(len / 2);
        if let Some(t) = me.app.terminals.first_mut() {
            t.print((0..lines).map(|_| corerouter_shell::Line::plain(&line)));
        }
        me.frame();
        me
    }

    /// The window of panel `id` open (G4.8a: System › Resources on the
    /// lab, its Overview with the four cards, links and checks).
    pub fn panel(id: &'static str) -> Self {
        let mut me = Self::with(Session::virtual_lab(), Some(Win::Panel(id)));
        // Its queries went out with the first frames; one more draws them.
        me.app.cache.refreshed_at = None;
        me.time += 2.0;
        me.frame();
        me.frame();
        me
    }

    /// The "Queue <name>" modal (G4.9g) open on Traffic (`traffic`, the
    /// 15-minute window full: 900 points) or Statistics, over the Queues
    /// window, with the lab's simulated counters; `None`: the window alone.
    pub fn queue_view(traffic: Option<bool>) -> Self {
        use crate::queue_view::{Page, Point};
        let mut s = Session::virtual_lab();
        let _ = s.execute(
            "queue.simple.add",
            &json!({"name": "cliente", "target": "10.0.0.5", "max_limit": "10M/50M", "burst_limit": "20M/80M"}),
        );
        for t in 0..3 {
            s.tick(1_800_000_000 + t);
            s.queue_sync();
        }
        let mut me = Self::with(s, Some(Win::Panel(crate::queues::WIN)));
        me.app.cache.refreshed_at = None;
        me.time += 2.0;
        me.frame();
        me.frame();
        if let Some(traffic) = traffic
            && let Some(p) = me.app.panel_mut::<crate::queues::QueuesPanel>()
        {
            let row = p
                .simple
                .get("rows")
                .and_then(|r| r.get(0))
                .cloned()
                .unwrap_or_default();
            let mut panel = std::mem::take(p);
            panel.open_view(&mut me.app, &row);
            if let Some(v) = panel.view.as_mut() {
                v.page = if traffic {
                    Page::Traffic
                } else {
                    Page::Statistics
                };
                v.live.window = 900;
                for t in 0..900u64 {
                    let wave = (t % 120) as f64 / 120.0;
                    v.live.ring.push_back(Point {
                        t: 1_800_000_000 + t,
                        up: 8e6 * wave,
                        down: 45e6 * wave,
                        delay: 3.0,
                        drops: 1.0,
                    });
                }
            }
            if let Some(p) = me.app.panel_mut::<crate::queues::QueuesPanel>() {
                *p = panel;
            }
        }
        me.app.cache.refreshed_at = None;
        me.time += 2.0;
        me.frame();
        me.frame();
        me
    }

    /// Draw one frame of a 1400×900 screen.
    pub fn frame(&mut self) {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 900.0),
            )),
            time: Some(self.time),
            ..Default::default()
        };
        let app = &mut self.app;
        self.ctx
            .run_ui(raw, |ui| app.ui(ui))
            .drop_without_applying_deltas();
    }
}

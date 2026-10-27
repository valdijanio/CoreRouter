//! The "Queue <name>" modal (G4.9g), opened by a double click on any
//! queue of the Queues window — fixed, PPPoE, IPoE, DHCP lease or network,
//! PCQ — with WinBox's tabs:
//!
//! - **General / Advanced**: a fixed queue's edit form (the list modal's
//!   fields, split in two); a dynamic queue's settings, read only, with
//!   where to change them;
//! - **Traffic**: the last 1, 5 or 15 minutes at a 1 s step, download and
//!   upload with the max-limit dashed, and cards for the rates (% of the
//!   limit), the queue delay (now and p95) and drops per second, with an
//!   "at limit" chip; pause, CSV and shortcuts to Torch and Sniffer;
//! - **Statistics**: per direction, rates, totals, drops (%), the wait now
//!   and its p95, at-limit time and the burst (state, average against the
//!   threshold, time left), and PCQ's active addresses;
//! - **History**: hour, day and week from the router's traffic history
//!   (`system.graph.query` of `queue:<name>`), with the p95, when the
//!   queue's history is kept (`queue.simple.graph` turns it on).
//!
//! The live data is `queue.simple.stats` of this one queue, asked once a
//! second while the modal is open (the router keeps the second-by-second
//! ring and its sums); the graph's points also live here, in a ring of the
//! longest window. Nothing is decided here.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;

use egui::{Color32, Grid, RichText, Ui};
use egui_plot::{HLine, Legend, Line, LineStyle, Plot, PlotPoints};
use serde_json::{Value, json};

use crate::chip::{self, AMBER, GREEN};
use crate::dialog::{self, Buttons, Footer, Press, Status};
use crate::export::{self, Export};
use crate::graphs::rate;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list_modal::{Modal, Spec};
use crate::{CoreRouterUi, Win};

const SCOPE: &str = "queues";
pub(crate) const STATS: &str = "queue.simple.stats";
pub(crate) const GRAPH: &str = "queue.simple.graph";
pub(crate) const HISTORY: &str = "system.graph.query";
/// Points kept: the longest window, one a second.
pub(crate) const RING: usize = 900;
const DOWN: Color32 = Color32::from_rgb(40, 120, 220);
const UP: Color32 = Color32::from_rgb(220, 60, 60);

/// The fields of each form page (the rest of the list modal's are not
/// shown: `name`… are all on one of the two).
pub(crate) const GENERAL: &[&str] = &["name", "target", "max_limit", "burst_limit", "burst_threshold", "burst_time", "comment", "disabled"];
pub(crate) const ADVANCED: &[&str] = &["limit_at", "priority", "bucket_size", "queue", "graph"];

/// The tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    General,
    Advanced,
    Traffic,
    Statistics,
    History,
}

const PAGES: [(Page, &str, &str); 5] = [
    (Page::General, "General", "queues.view.general"),
    (Page::Advanced, "Advanced", "queues.view.advanced"),
    (Page::Traffic, "Traffic", "queues.view.traffic"),
    (Page::Statistics, "Statistics", "queues.view.statistics"),
    (Page::History, "History", "queues.view.history"),
];

/// The History tab's ranges: what `system.graph.query` takes, and how many
/// refreshes (one a second) between two asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Span {
    Hour,
    Day,
    Week,
}

const SPANS: [(Span, &str, &str, u32); 3] = [(Span::Hour, "Hour", "hour", 5), (Span::Day, "Day", "day", 60), (Span::Week, "Week", "week", 300)];

impl Span {
    fn param(self) -> &'static str {
        SPANS.iter().find(|s| s.0 == self).map_or("hour", |s| s.2)
    }

    fn every(self) -> u32 {
        SPANS.iter().find(|s| s.0 == self).map_or(5, |s| s.3)
    }
}

/// One second of the Traffic graph.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Point {
    pub t: u64,
    pub up: f64,
    pub down: f64,
    /// Download wait, ms.
    pub delay: f64,
    pub drops: f64,
}

/// What the modal asks the panel to do with the app (it has no `app` while
/// it draws).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ask {
    Torch,
    Sniffer,
    Keep(bool),
    Csv,
}

/// One open "Queue <name>" modal.
pub(crate) struct QueueView {
    pub id: u64,
    /// The queue's key (`*5`, `ppp:…`, `dhcp:…`).
    pub key: String,
    pub name: String,
    pub page: Page,
    /// A fixed queue's form.
    pub form: Option<Modal>,
    /// Its list row (a dynamic queue's settings).
    pub row: Value,
    pub live: Live,
    status: Status,
}

/// The live pages' state.
pub(crate) struct Live {
    pub stats: Option<Value>,
    pub ring: VecDeque<Point>,
    /// Seconds shown.
    pub window: u64,
    /// Frozen at this second (the ring still fills).
    pub paused: Option<u64>,
    pub span: Span,
    pub history: Option<Value>,
    pub history_tick: std::cell::Cell<u32>,
    pub help: Option<HelpView>,
    pub note: Option<Result<String, String>>,
    pub ask: Option<Ask>,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            stats: None,
            ring: VecDeque::new(),
            window: 300,
            paused: None,
            span: Span::Hour,
            history: None,
            history_tick: std::cell::Cell::new(0),
            help: None,
            note: None,
            ask: None,
        }
    }
}

fn arr(v: Option<&Value>, i: usize) -> Option<f64> {
    v?.as_array()?.get(i)?.as_f64()
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(crate::value_text).unwrap_or_default()
}

impl QueueView {
    pub(crate) fn open(app: &mut CoreRouterUi, row: &Value, form: Option<Modal>) -> Self {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        let dynamic = row.get("dynamic").and_then(Value::as_bool).unwrap_or(false);
        Self {
            id: app.next_dialog,
            key: s(row, "id"),
            name: s(row, "name"),
            page: if dynamic { Page::Traffic } else { Page::General },
            form,
            row: row.clone(),
            live: Live::default(),
            status: Status::default(),
        }
    }

    /// The stats query: the samples the router kept too, while the ring is
    /// empty (a modal opened again draws its graph at once).
    pub(crate) fn stats_params(&self) -> Value {
        json!({"id": self.key, "recent": self.live.ring.is_empty()})
    }

    /// The History query, when its page is open and the history is kept;
    /// every few refreshes.
    pub(crate) fn history_params(&self) -> Option<Value> {
        if self.page != Page::History {
            return None;
        }
        let st = self.live.stats.as_ref()?;
        if st.get("kept").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        let series = st.get("series").and_then(Value::as_str)?;
        let n = self.live.history_tick.get();
        self.live.history_tick.set(n.wrapping_add(1));
        if !n.is_multiple_of(self.live.span.every()) {
            return None;
        }
        Some(json!({"series": series, "range": self.live.span.param(), "stats": true, "max": true}))
    }

    /// A `queue.simple.stats` reply.
    pub(crate) fn arrived(&mut self, v: Value) {
        if v.get("id").and_then(Value::as_str) != Some(self.key.as_str()) {
            return;
        }
        let live = &mut self.live;
        if let Some(rows) = v.get("recent").and_then(Value::as_array) {
            for r in rows {
                let n = |i: usize| r.get(i).and_then(Value::as_f64).unwrap_or(f64::NAN);
                live.push(Point { t: n(0) as u64, up: n(1), down: n(2), delay: n(3) / 1000.0, drops: n(4) });
            }
        }
        if v.get("counted").and_then(Value::as_bool) == Some(true)
            && let Some(t) = v.get("time").and_then(Value::as_u64)
        {
            let drops = v.get("drops_ps").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_f64).sum());
            live.push(Point {
                t,
                up: arr(v.get("rate_bps"), 0).unwrap_or(f64::NAN),
                down: arr(v.get("rate_bps"), 1).unwrap_or(f64::NAN),
                delay: arr(v.get("queued_us"), 1).map_or(f64::NAN, |x| x / 1000.0),
                drops: drops.unwrap_or(f64::NAN),
            });
        }
        live.stats = Some(v);
    }

    /// The modal's tabs; a dynamic queue has no form, so its General and
    /// Advanced are read only.
    fn tabs(page: &mut Page, ui: &mut Ui, l: Lang, help: &mut Option<HelpView>, id: egui::Id) {
        ui.horizontal(|ui| {
            for (p, label, key) in PAGES {
                if ui.selectable_label(*page == p, tr_in(SCOPE, l, label)).clicked() {
                    *page = p;
                }
                if help::info_button(ui, id.with(("tab", key)), tr_in(SCOPE, l, label)).clicked() {
                    *help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
                }
            }
        });
        ui.separator();
    }

    /// Draw it. Returns `false` once closed.
    pub(crate) fn show(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect, spec: &Spec) -> bool {
        let l = app.lang.labels;
        let wid = dialog_id(self.id);
        if self.live.paused.is_none() && self.page == Page::Traffic {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
        let open = match self.form.as_mut() {
            Some(form) => {
                form.other_page = !matches!(self.page, Page::General | Page::Advanced);
                let (page, live, row) = (&mut self.page, &mut self.live, &self.row);
                form.show_paged(app, ctx, area, spec, &|_| Vec::new(), &mut |ui| {
                    let id = egui::Id::unique("queue-view");
                    Self::tabs(page, ui, l, &mut live.help, id);
                    match *page {
                        Page::General => Some(GENERAL),
                        Page::Advanced => Some(ADVANCED),
                        p => {
                            live.page(ui, p, l, row);
                            None
                        }
                    }
                })
            }
            None => {
                let title = format!("{} <{}>", tr_in(SCOPE, l, "Queue"), self.name);
                let head = dialog::Head {
                    id: wid,
                    title: &title,
                    dirty: false,
                    pos: cascade(area, self.id),
                    parent: Some(crate::win_id(Win::Panel(crate::queues::WIN))),
                };
                let (page, live, row) = (&mut self.page, &mut self.live, &self.row);
                let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut self.status, |ui, _| {
                    ui.set_min_width(420.0);
                    let id = egui::Id::unique("queue-view");
                    Self::tabs(page, ui, l, &mut live.help, id);
                    live.page(ui, *page, l, row);
                    Footer::<()> {
                        buttons: Buttons::View,
                        ok: Ok(()),
                        extra: Vec::new(),
                        pressed: None,
                    }
                });
                match pressed {
                    Some(Press::Cancel | Press::Ok) => {
                        app.floats.forget(wid);
                        false
                    }
                    _ => true,
                }
            }
        };
        help::modal(ctx, app.lang, &mut self.live.help);
        if let Some(a) = self.live.ask.take() {
            self.act(app, ctx, a);
        }
        open
    }

    fn act(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, a: Ask) {
        let st = self.live.stats.clone().unwrap_or(Value::Null);
        let address = st.get("address").and_then(Value::as_str).unwrap_or_default().to_owned();
        let interface = st.get("interface").and_then(Value::as_str).unwrap_or_default().to_owned();
        match a {
            Ask::Torch => {
                if let Some(t) = app.panel_mut::<crate::torch::TorchPanel>() {
                    if !interface.is_empty() {
                        t.interface = interface;
                    }
                    t.src = address;
                }
                if !app.open.insert(Win::Panel(crate::torch::WIN)) {
                    app.floats.raise(crate::win_id(Win::Panel(crate::torch::WIN)));
                }
            }
            Ask::Sniffer => {
                if let Some(t) = app.panel_mut::<crate::sniffer::SnifferPanel>() {
                    if !interface.is_empty() {
                        t.interface = interface;
                    }
                    t.src = address;
                }
                if !app.open.insert(Win::Panel(crate::sniffer::WIN)) {
                    app.floats.raise(crate::win_id(Win::Panel(crate::sniffer::WIN)));
                }
            }
            Ask::Keep(on) => {
                app.run(GRAPH, json!({"id": self.key, "graph": on}));
                self.live.note = Some(Ok(if on { "history kept from now on".into() } else { "history no longer kept".into() }));
            }
            Ask::Csv => {
                let name = format!("queue-{}.csv", self.name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.', "_"));
                self.live.note = Some(export::save(ctx, &name, Export::Text(self.live.csv())));
            }
        }
    }
}

impl Live {
    fn push(&mut self, p: Point) {
        if self.ring.back().is_some_and(|b| b.t >= p.t) {
            return;
        }
        self.ring.push_back(p);
        while self.ring.len() > RING {
            self.ring.pop_front();
        }
    }

    /// The points of the window shown.
    pub(crate) fn shown(&self) -> Vec<Point> {
        let end = self.paused.or_else(|| self.ring.back().map(|p| p.t)).unwrap_or(0);
        self.ring.iter().filter(|p| p.t <= end && end - p.t < self.window).copied().collect()
    }

    /// The window shown as CSV.
    pub(crate) fn csv(&self) -> String {
        let mut out = "time_utc,unix,upload_bps,download_bps,delay_ms,drops_per_s\n".to_owned();
        let f = |v: f64| if v.is_finite() { format!("{v}") } else { String::new() };
        for p in self.shown() {
            let _ = writeln!(
                out,
                "{},{},{},{},{},{}",
                crate::ntp_client::utc(p.t).trim_end_matches(" UTC"),
                p.t,
                f(p.up),
                f(p.down),
                f(p.delay),
                f(p.drops)
            );
        }
        out
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str) {
        if help::info_button(ui, egui::Id::unique("queue-view").with(("queue-view-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(format!("queues.view.{key}"), tr_in(SCOPE, l, title)));
        }
    }

    /// A label with its ⓘ.
    fn label(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str) {
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, title));
            self.info(ui, l, key, title);
        });
    }

    fn page(&mut self, ui: &mut Ui, page: Page, l: Lang, row: &Value) {
        match page {
            Page::General => self.settings(ui, l, row, true),
            Page::Advanced => self.settings(ui, l, row, false),
            Page::Traffic => self.traffic(ui, l),
            Page::Statistics => self.statistics(ui, l),
            Page::History => self.history_page(ui, l),
        }
        if let Some(n) = &self.note {
            match n {
                Ok(m) => ui.weak(m.as_str()),
                Err(e) => ui.colored_label(ui.visuals().error_fg_color, e.as_str()),
            };
        }
    }

    /// A dynamic queue's settings, read only.
    fn settings(&mut self, ui: &mut Ui, l: Lang, row: &Value, general: bool) {
        let fields: &[(&str, &'static str, &str)] = if general {
            &[
                ("name", "Name", "queues.simple.name"),
                ("target", "Target", "queues.simple.target"),
                ("max_limit", "Max Limit", "queues.simple.max_limit"),
                ("burst_limit", "Burst Limit", "queues.simple.burst_limit"),
                ("burst_threshold", "Burst Threshold", "queues.simple.burst_threshold"),
                ("burst_time", "Burst Time", "queues.simple.burst_time"),
                ("origin", "Origin", "queues.simple.origin"),
            ]
        } else {
            &[
                ("limit_at", "Limit At", "queues.simple.limit_at"),
                ("priority", "Priority", "queues.simple.priority"),
                ("bucket_size", "Bucket Size", "queues.simple.bucket_size"),
                ("queue", "Queue Type", "queues.simple.queue"),
                ("download_mode", "Download Mode", "queues.view.download_mode"),
            ]
        };
        Grid::new(egui::Id::unique("queue-view").with(("queue-view-settings", general))).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            for (k, title, help_key) in fields {
                ui.horizontal(|ui| {
                    ui.label(tr_in(SCOPE, l, title));
                    if help::info_button(ui, egui::Id::unique("queue-view").with(("settings-help", *k)), tr_in(SCOPE, l, title)).clicked() {
                        self.help = Some(HelpView::new(*help_key, tr_in(SCOPE, l, title)));
                    }
                });
                ui.label(s(row, k));
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        ui.weak(tr_in(SCOPE, l, "A dynamic queue comes from a session, a DHCP lease or a DHCP network: change its rate there."));
        if !general {
            ui.add_space(6.0);
            self.keep_toggle(ui, l);
        }
    }

    /// "Keep history" of this queue.
    fn keep_toggle(&mut self, ui: &mut Ui, l: Lang) {
        let marked = self.stats.as_ref().and_then(|v| v.get("graph")).and_then(Value::as_bool).unwrap_or(false);
        ui.horizontal(|ui| {
            let mut on = marked;
            if ui.checkbox(&mut on, tr_in(SCOPE, l, "Keep History")).changed() {
                self.ask = Some(Ask::Keep(on));
            }
            self.info(ui, l, "keep", "Keep History");
        });
    }

    fn card(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str, body: impl FnOnce(&mut Ui)) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(138.0);
            ui.set_min_height(64.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.weak(tr_in(SCOPE, l, title));
                    self.info(ui, l, key, title);
                });
                body(ui);
            });
        });
    }

    fn traffic(&mut self, ui: &mut Ui, l: Lang) {
        ui.set_min_width(640.0);
        let st = self.stats.clone().unwrap_or(Value::Null);
        let limit = |i| arr(st.get("max_limit"), i).unwrap_or(0.0);
        let now = |k: &str, i| arr(st.get(k), i);
        let at_limit = |i| st.get("at_limit").and_then(Value::as_array).and_then(|a| a.get(i)).and_then(Value::as_bool) == Some(true);
        let visuals = ui.visuals().clone();
        if st.get("counted").and_then(Value::as_bool) == Some(false) {
            let note = st.get("note").and_then(Value::as_str).unwrap_or("nothing counts this queue yet");
            ui.label(RichText::new(note).color(ui.visuals().warn_fg_color));
        }
        ui.horizontal_wrapped(|ui| {
            for (i, key, title) in [(1usize, "download", "Download"), (0, "upload", "Upload")] {
                self.card(ui, l, key, title, |ui| {
                    let r = now("rate_bps", i).unwrap_or(0.0);
                    ui.label(RichText::new(rate(r, "bps")).size(18.0).strong());
                    let lim = limit(i);
                    if lim > 0.0 {
                        ui.weak(format!("{:.0} % {} {}", r * 100.0 / lim, tr_in(SCOPE, l, "of"), rate(lim, "bps")));
                    } else {
                        ui.weak(tr_in(SCOPE, l, "no limit"));
                    }
                    if at_limit(i) {
                        chip::chip(ui, tr_in(SCOPE, l, "at limit"), AMBER.tone(&visuals));
                    }
                });
            }
            self.card(ui, l, "delay", "Queue Delay", |ui| {
                let d = now("queued_us", 1).unwrap_or(0.0) / 1000.0;
                ui.label(RichText::new(format!("{d:.1} ms")).size(18.0).strong());
                let p = arr(st.get("queued_p95_us"), 1).unwrap_or(0.0) / 1000.0;
                ui.weak(format!("p95 {p:.1} ms"));
            });
            self.card(ui, l, "drops", "Drops/s", |ui| {
                let d: f64 = st.get("drops_ps").and_then(Value::as_array).map_or(0.0, |a| a.iter().filter_map(Value::as_f64).sum());
                ui.label(RichText::new(format!("{d:.0}")).size(18.0).strong());
                let total: f64 = st.get("dropped").and_then(Value::as_array).map_or(0.0, |a| a.iter().filter_map(Value::as_f64).sum());
                ui.weak(format!("{} {}", rate(total, ""), tr_in(SCOPE, l, "in total")));
                if at_limit(0) || at_limit(1) {
                    chip::chip(ui, tr_in(SCOPE, l, "at limit"), AMBER.tone(&visuals));
                }
            });
        });
        ui.horizontal(|ui| {
            let label = if self.paused.is_some() { "Resume" } else { "Pause" };
            if ui.selectable_label(self.paused.is_some(), tr_in(SCOPE, l, label)).clicked() {
                self.paused = match self.paused {
                    Some(_) => None,
                    None => Some(self.ring.back().map_or(0, |p| p.t)),
                };
            }
            self.info(ui, l, "pause", "Pause");
            ui.separator();
            for (secs, label) in [(60, "1 min"), (300, "5 min"), (900, "15 min")] {
                if ui.selectable_label(self.window == secs, label).clicked() {
                    self.window = secs;
                }
            }
            self.info(ui, l, "window", "Window");
            ui.separator();
            if ui.button(tr_in(SCOPE, l, "CSV")).clicked() {
                self.ask = Some(Ask::Csv);
            }
            self.info(ui, l, "csv", "CSV");
            if ui.button(tr_in(SCOPE, l, "Torch")).clicked() {
                self.ask = Some(Ask::Torch);
            }
            if ui.button(tr_in(SCOPE, l, "Sniffer")).clicked() {
                self.ask = Some(Ask::Sniffer);
            }
            self.info(ui, l, "tools", "Torch");
        });
        let pts = self.shown();
        let end = pts.last().map_or(0.0, |p| p.t as f64);
        let start = end - self.window as f64;
        let line = |f: &dyn Fn(&Point) -> f64| -> Vec<Vec<[f64; 2]>> {
            let mut runs: Vec<Vec<[f64; 2]>> = Vec::new();
            let mut cur: Vec<[f64; 2]> = Vec::new();
            let mut last = None;
            for p in &pts {
                let v = f(p);
                // A missing second is a hole, not a straight line across.
                if !v.is_finite() || last.is_some_and(|t| p.t > t + 2) {
                    if cur.len() > 1 {
                        runs.push(std::mem::take(&mut cur));
                    }
                    cur.clear();
                }
                if v.is_finite() {
                    cur.push([p.t as f64, v]);
                }
                last = Some(p.t);
            }
            if !cur.is_empty() {
                runs.push(cur);
            }
            runs
        };
        let (down_runs, up_runs) = (line(&|p| p.down), line(&|p| p.up));
        let (lim_down, lim_up) = (limit(1), limit(0));
        // The dashed limit stays inside the frame, not on its edge.
        let top = pts.iter().map(|p| p.down.max(p.up)).filter(|v| v.is_finite()).fold(lim_down.max(lim_up), f64::max) * 1.1;
        let (down_label, up_label) = (tr_in(SCOPE, l, "Download"), tr_in(SCOPE, l, "Upload"));
        let max_label = tr_in(SCOPE, l, "max-limit");
        Plot::new(egui::Id::unique("queue-view").with("queue-view-traffic"))
            .height((ui.available_height() - 8.0).clamp(180.0, 320.0))
            .width(ui.available_width().max(600.0))
            .legend(Legend::default().position(egui_plot::Corner::LeftTop))
            .include_y(0.0)
            .include_y(top)
            .include_x(start)
            .include_x(end)
            .y_axis_formatter(|m, _| rate(m.value, "bps"))
            .x_axis_formatter(|m, _| crate::ntp_client::utc(m.value.max(0.0) as u64).get(11..19).unwrap_or("").to_owned())
            .allow_scroll(false)
            .show(ui, |p| {
                for (lim, color, label) in [(lim_down, DOWN, down_label), (lim_up, UP, up_label)] {
                    if lim > 0.0 {
                        p.hline(HLine::new(format!("{label} {max_label}"), lim).color(color).width(1.2).style(LineStyle::dashed_dense()));
                    }
                }
                for run in down_runs {
                    p.line(Line::new(down_label, PlotPoints::from(run)).color(DOWN).width(1.6));
                }
                for run in up_runs {
                    p.line(Line::new(up_label, PlotPoints::from(run)).color(UP).width(1.6));
                }
            });
    }

    fn statistics(&mut self, ui: &mut Ui, l: Lang) {
        let st = self.stats.clone().unwrap_or(Value::Null);
        let two = |k: &str, f: &dyn Fn(f64) -> String| -> [String; 2] { [0, 1].map(|i| arr(st.get(k), i).map_or("–".into(), f)) };
        let rows: Vec<(&str, &'static str, [String; 2])> = vec![
            ("rate", "Rate", two("rate_bps", &|v| rate(v, "bps"))),
            ("pps", "Packet Rate", two("pps", &|v| rate(v, "pps"))),
            ("bytes", "Bytes", two("bytes", &crate::graphs::bytes)),
            ("packets", "Packets", two("packets", &|v| rate(v, ""))),
            (
                "dropped",
                "Dropped",
                [0, 1].map(|i| {
                    let d = arr(st.get("dropped"), i).unwrap_or(0.0);
                    let p = arr(st.get("packets"), i).unwrap_or(0.0);
                    if d + p > 0.0 { format!("{} ({:.2} %)", rate(d, ""), d * 100.0 / (d + p)) } else { "0".into() }
                }),
            ),
            ("queued", "Queued", two("queued_us", &|v| format!("{:.1} ms", v / 1000.0))),
            ("queued_p95", "Queued p95", two("queued_p95_us", &|v| format!("{:.1} ms", v / 1000.0))),
            ("at_limit", "At Limit", two("at_limit_s", &|v| if v > 0.0 { format!("{v:.0} s") } else { "–".into() })),
        ];
        let burst = |i: usize| st.get("burst").and_then(|b| b.get(i)).cloned().unwrap_or(Value::Null);
        let visuals = ui.visuals().clone();
        Grid::new(egui::Id::unique("queue-view").with("queue-view-stats")).num_columns(3).striped(true).spacing([18.0, 4.0]).show(ui, |ui| {
            ui.label("");
            for (key, title) in [("upload", "Upload"), ("download", "Download")] {
                ui.horizontal(|ui| {
                    ui.strong(tr_in(SCOPE, l, title));
                    self.info(ui, l, key, title);
                });
            }
            ui.end_row();
            for (key, title, v) in &rows {
                self.label(ui, l, key, title);
                for x in v {
                    ui.label(x.as_str());
                }
                ui.end_row();
            }
            self.label(ui, l, "burst_state", "Burst");
            for i in [0, 1] {
                let b = burst(i);
                let state = b.get("state").and_then(Value::as_str).unwrap_or("off");
                let (word, tone) = match state {
                    "bursting" => ("bursting", GREEN.tone(&visuals)),
                    "ready" => ("ready", chip::BLUE.tone(&visuals)),
                    "spent" => ("spent", AMBER.tone(&visuals)),
                    _ => ("off", chip::neutral_tone(&visuals)),
                };
                ui.horizontal(|ui| {
                    chip::chip(ui, tr_in(SCOPE, l, word), tone);
                    if let Some(left) = b.get("left_s").and_then(Value::as_u64) {
                        ui.weak(format!("{left} s {}", tr_in(SCOPE, l, "left")));
                    }
                });
            }
            ui.end_row();
            self.label(ui, l, "burst_average", "Burst Average");
            for i in [0, 1] {
                let b = burst(i);
                let n = |k: &str| b.get(k).and_then(Value::as_f64);
                ui.label(match (n("average_bps"), n("threshold_bps")) {
                    (Some(a), Some(t)) => {
                        let warm = match (n("known_s"), n("window_s")) {
                            (Some(k), Some(w)) if k < w => format!(" ({k:.0}/{w:.0} s)"),
                            _ => String::new(),
                        };
                        format!("{} / {}{warm}", rate(a, "bps"), rate(t, "bps"))
                    }
                    _ => "–".into(),
                });
            }
            ui.end_row();
            self.label(ui, l, "pcq", "PCQ Addresses");
            ui.label(st.get("pcq_queues").and_then(Value::as_u64).map_or("–".into(), |n| if n == 0 { "–".into() } else { n.to_string() }));
            ui.label("");
            ui.end_row();
        });
    }

    fn history_page(&mut self, ui: &mut Ui, l: Lang) {
        ui.set_min_width(640.0);
        let st = self.stats.clone().unwrap_or(Value::Null);
        let kept = st.get("kept").and_then(Value::as_bool) == Some(true);
        let marked = st.get("graph").and_then(Value::as_bool) == Some(true);
        ui.horizontal(|ui| {
            for (span, label, _, _) in SPANS {
                if ui.selectable_label(self.span == span, tr_in(SCOPE, l, label)).clicked() && self.span != span {
                    self.span = span;
                    self.history = None;
                    self.history_tick.set(0);
                }
            }
            self.info(ui, l, "span", "Hour");
            ui.separator();
            self.keep_toggle(ui, l);
        });
        if !kept {
            let why = if st.get("refused").and_then(Value::as_bool) == Some(true) {
                "Not kept: the history would pass the graphing memory cap (Graphs → Settings)."
            } else if marked {
                "Kept from now on: the first points come within a minute."
            } else {
                "This queue's history is not kept. Turn on Keep History to record it (the live Traffic tab works without it)."
            };
            ui.label(RichText::new(tr_in(SCOPE, l, why)).color(ui.visuals().warn_fg_color));
            return;
        }
        let Some(data) = self.history.clone() else {
            ui.weak(tr_in(SCOPE, l, "Waiting for the router…"));
            return;
        };
        let series = data.get("series").and_then(|s| s.get(0)).cloned().unwrap_or(Value::Null);
        let stat = |f: &str, k: &str| series.get("stats").and_then(|s| s.get(f)).and_then(|s| s.get(k)).and_then(Value::as_f64);
        Grid::new(egui::Id::unique("queue-view").with("queue-view-history-stats")).num_columns(5).striped(true).spacing([16.0, 2.0]).show(ui, |ui| {
            ui.label("");
            for (k, t) in [("current", "Current"), ("avg", "Average"), ("max", "Maximum"), ("p95", "95th pct")] {
                ui.horizontal(|ui| {
                    ui.strong(tr_in(SCOPE, l, t));
                    self.info(ui, l, &format!("history.{k}"), t);
                });
            }
            ui.end_row();
            for (f, key, t, unit) in [("down_bps", "download", "Download", "bps"), ("up_bps", "upload", "Upload", "bps"), ("delay", "delay", "Queue Delay", "ms"), ("drops", "drops", "Drops/s", "/s")] {
                self.label(ui, l, key, t);
                for k in ["current", "avg", "max", "p95"] {
                    ui.label(stat(f, k).map_or("–".into(), |v| if unit == "ms" { format!("{v:.1} ms") } else { rate(v, unit) }));
                }
                ui.end_row();
            }
        });
        let start = data.get("start").and_then(Value::as_f64).unwrap_or(0.0);
        let end = data.get("end").and_then(Value::as_f64).unwrap_or(0.0);
        let step = data.get("step").and_then(Value::as_f64).unwrap_or(1.0);
        let runs = |field: &str| -> Vec<Vec<[f64; 2]>> {
            let mut out: Vec<Vec<[f64; 2]>> = Vec::new();
            let mut cur = Vec::new();
            for (i, v) in series.get("data").and_then(|d| d.get(field)).and_then(Value::as_array).into_iter().flatten().enumerate() {
                match v.as_f64() {
                    Some(y) => cur.push([start + i as f64 * step + step / 2.0, y]),
                    None if !cur.is_empty() => out.push(std::mem::take(&mut cur)),
                    None => {}
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
            out
        };
        let p95_down = stat("down_bps", "p95");
        let limit = arr(st.get("max_limit"), 1).unwrap_or(0.0);
        let (down_label, up_label) = (tr_in(SCOPE, l, "Download"), tr_in(SCOPE, l, "Upload"));
        let span = self.span;
        let visuals = ui.visuals().clone();
        let ui_visuals = &visuals;
        Plot::new(egui::Id::unique("queue-view").with("queue-view-history"))
            .height((ui.available_height() - 8.0).clamp(160.0, 300.0))
            .width(ui.available_width().max(600.0))
            .legend(Legend::default().position(egui_plot::Corner::LeftTop))
            .include_y(0.0)
            .include_x(start)
            .include_x(end)
            .y_axis_formatter(|m, _| rate(m.value, "bps"))
            .x_axis_formatter(move |m, _| {
                let t = crate::ntp_client::utc(m.value.max(0.0) as u64);
                match span {
                    Span::Week => format!("{} {}h", t.get(5..10).unwrap_or(""), t.get(11..13).unwrap_or("")),
                    _ => t.get(11..16).unwrap_or("").to_owned(),
                }
            })
            .allow_scroll(false)
            .show(ui, |p| {
                if limit > 0.0 {
                    p.hline(HLine::new(format!("{down_label} max-limit"), limit).color(DOWN).width(1.2).style(LineStyle::dashed_dense()));
                }
                if let Some(v) = p95_down {
                    p.hline(HLine::new(format!("p95 {down_label}"), v).color(AMBER.tone(ui_visuals).ink).width(1.2).style(LineStyle::dashed_loose()));
                }
                for (field, color, label) in [("down_bps", DOWN, down_label), ("up_bps", UP, up_label)] {
                    for run in runs(field) {
                        p.line(Line::new(label, PlotPoints::from(run)).color(color).width(1.5));
                    }
                    for run in runs(&format!("{field}_max")) {
                        p.line(Line::new(format!("{label} max"), PlotPoints::from(run)).color(color.gamma_multiply(0.35)).width(1.0));
                    }
                }
            });
    }
}

/// A fixed queue's form values from its list row.
pub(crate) fn form_values(r: &Value) -> BTreeMap<&'static str, String> {
    let yes = |b: bool| if b { "yes" } else { "no" }.to_owned();
    BTreeMap::from([
        ("name", s(r, "name")),
        ("target", s(r, "target")),
        ("max_limit", s(r, "max_limit")),
        ("limit_at", s(r, "limit_at")),
        ("burst_limit", s(r, "burst_limit")),
        ("burst_threshold", s(r, "burst_threshold")),
        ("burst_time", s(r, "burst_time")),
        ("bucket_size", s(r, "bucket_size")),
        ("priority", s(r, "priority")),
        ("queue", s(r, "queue")),
        ("comment", s(r, "comment")),
        ("disabled", yes(r.get("disabled").and_then(Value::as_bool).unwrap_or(false))),
        ("graph", yes(r.get("graph").and_then(Value::as_bool).unwrap_or(true))),
    ])
}

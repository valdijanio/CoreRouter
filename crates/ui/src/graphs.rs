//! Tools › Graphs (G4.5, RouterOS `/tool graphing`): the traffic history
//! the router keeps (`system.graph.*`), by interface or of the router
//! itself, for the last hour, day, week, month or year.
//!
//! - One series, or several interfaces compared on the same chart (each
//!   in the colour of its name, receive solid and transmit dashed).
//! - Current, average, maximum, 95th percentile and total of the range,
//!   all computed by the router (`system.graph.query`): the UI only draws.
//!   The billing p95 (the larger direction) and its sum variant under the
//!   table; a chip says when the p95 comes from 1 h averages.
//! - CSV of the points and PNG of the chart, saved by the app
//!   (`export.rs`) or copied when it cannot save (the browser).
//!
//! Times are UTC (the router's clock); the hour range refreshes every two
//! seconds, longer ranges every minute or more.

use std::cell::Cell;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use egui::{Color32, ComboBox, Grid, Id, RichText, TextEdit, Ui};
use egui_plot::{HLine, Legend, Line, LineStyle, Plot, PlotPoints};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, AMBER};
use crate::dialog::{self, Footer, Press, Status};
use crate::export::{self, Export};
use crate::help::{self, HelpView};
use crate::i18n::tr;
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "graphs";
pub(crate) const WIN: &str = "graphs";
pub(crate) const QUERY: &str = "system.graph.query";
pub(crate) const PRINT: &str = "system.graph.print";
pub(crate) const SET: &str = "system.graph.set";
/// Most interfaces compared on one chart.
pub(crate) const MAX_COMPARE: usize = 6;
/// Refreshes between two asks for the list of series.
const PRINT_EVERY: u32 = 15;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "Graphs",
        size: [900.0, 660.0],
        escape: false,
    }],
    new: || Box::<Graphs>::default(),
};

/// Receive and transmit, as in the Interface window's Traffic tab.
const RX: Color32 = Color32::from_rgb(40, 120, 220);
const TX: Color32 = Color32::from_rgb(220, 60, 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Range {
    #[default]
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl Range {
    pub(crate) const ALL: [Range; 5] = [Range::Hour, Range::Day, Range::Week, Range::Month, Range::Year];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Range::Hour => "Hour",
            Range::Day => "Day",
            Range::Week => "Week",
            Range::Month => "Month",
            Range::Year => "Year",
        }
    }

    fn param(self) -> &'static str {
        match self {
            Range::Hour => "hour",
            Range::Day => "day",
            Range::Week => "week",
            Range::Month => "month",
            Range::Year => "year",
        }
    }

    /// UI refreshes (one a second) between two queries: about a point.
    fn every(self) -> u32 {
        match self {
            Range::Hour => 2,
            Range::Day => 30,
            Range::Week => 60,
            Range::Month | Range::Year => 300,
        }
    }
}

/// What the interface chart shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum View {
    #[default]
    Traffic,
    Packets,
    Errors,
}

impl View {
    const ALL: [View; 3] = [View::Traffic, View::Packets, View::Errors];

    fn label(self) -> &'static str {
        match self {
            View::Traffic => "Traffic",
            View::Packets => "Packets",
            View::Errors => "Errors",
        }
    }

    /// The two values drawn: (field, row label, unit).
    fn fields(self) -> [(&'static str, &'static str, &'static str); 2] {
        match self {
            View::Traffic => [("rx_bps", "Rx", "bps"), ("tx_bps", "Tx", "bps")],
            View::Packets => [("rx_pps", "Rx", "pps"), ("tx_pps", "Tx", "pps")],
            View::Errors => [("errors", "Errors", "/s"), ("drops", "Drops", "/s")],
        }
    }

    /// The totals of the two fields.
    fn totals(self) -> [&'static str; 2] {
        match self {
            View::Traffic => ["rx_bytes", "tx_bytes"],
            View::Packets => ["rx_packets", "tx_packets"],
            View::Errors => ["errors", "drops"],
        }
    }
}

/// The router's own series: (field, label, unit).
const SYSTEM_FIELDS: [(&str, &str, &str); 3] = [
    ("cpu", "CPU", "%"),
    ("memory", "Memory", "B"),
    ("conntrack", "Conntrack", "entries"),
];

#[derive(Default)]
pub(crate) struct Graphs {
    /// The series shown: an interface name or `system`.
    pub(crate) series: String,
    /// Interfaces drawn next to it.
    pub(crate) compare: Vec<String>,
    pub(crate) range: Range,
    pub(crate) view: View,
    /// Series keys the router keeps (`system`, `interface:ether1`).
    pub(crate) kept: Vec<String>,
    pub(crate) refused: Vec<String>,
    /// The last `system.graph.query` answer, and what it was asked for.
    pub(crate) data: Option<Value>,
    asked: Option<Value>,
    /// Refreshes counted by `queries` (it only reads the state).
    tick: Cell<u32>,
    pub(crate) help: Option<HelpView>,
    /// What the last export did.
    pub(crate) status: Option<Result<String, String>>,
    /// A PNG export waiting for its screenshot.
    shot: Arc<Mutex<Option<Result<String, String>>>>,
    plot_rect: Option<egui::Rect>,
    /// The last `system.graph.print` (settings and disk status).
    pub(crate) print: Value,
    pub(crate) settings: Option<SettingsDialog>,
}

/// The switches of `system.graph.set`: (key, label).
pub(crate) const SWITCHES: [(&str, &str); 6] = [
    ("enabled", "Enabled"),
    ("physical", "Physical"),
    ("bridges", "Bridges"),
    ("vlans", "VLANs"),
    ("tunnels", "Tunnels"),
    ("resources", "Resources"),
];
/// Its text fields: (key, label, hint).
pub(crate) const FIELDS: [(&str, &str, &str); 4] = [
    ("include", "Include", "lo, vlan100"),
    ("exclude", "Exclude", "ether8"),
    ("max_memory_mib", "Max Memory (MiB)", "64"),
    ("store_every", "Store Every (s)", "300"),
];

pub(crate) struct SettingsDialog {
    id: u64,
    pub(crate) switches: [bool; 6],
    orig_switches: [bool; 6],
    pub(crate) fields: [String; 4],
    orig_fields: [String; 4],
    status: Status,
}

struct Saved(u64);

/// `interface:ether1` → `ether1`; `system` stays.
pub(crate) fn short(key: &str) -> &str {
    key.strip_prefix("interface:").unwrap_or(key)
}

impl Graphs {
    fn is_system(&self) -> bool {
        self.series == "system"
    }

    /// The series asked for: the shown one and the compared ones.
    pub(crate) fn wanted(&self) -> Vec<String> {
        let mut v = vec![self.series.clone()];
        if !self.is_system() {
            v.extend(self.compare.iter().filter(|c| **c != self.series).cloned());
        }
        v
    }

    pub(crate) fn params(&self) -> Value {
        json!({"series": self.wanted(), "range": self.range.param()})
    }

    fn knows(&self, name: &str) -> bool {
        self.kept.iter().any(|k| short(k) == name)
    }

    /// Ask again at the next refresh.
    fn changed(&mut self) {
        self.asked = None;
        self.tick.set(0);
    }
}

impl PanelState for Graphs {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(QUERY) {
            return Vec::new();
        }
        let n = self.tick.get();
        self.tick.set(n.wrapping_add(1));
        let mut out = Vec::new();
        if self.kept.is_empty() || n.is_multiple_of(PRINT_EVERY) {
            out.push(Query {
                key: "print",
                command: PRINT,
                params: json!({}),
            });
        }
        let params = self.params();
        let fresh = self.asked.as_ref() == Some(&params);
        let ready = !self.series.is_empty() && self.wanted().iter().all(|s| self.knows(s));
        if ready && (!fresh || n.is_multiple_of(self.range.every())) {
            out.push(Query {
                key: "query",
                command: QUERY,
                params,
            });
        }
        out
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "print" => {
                self.print = value.clone();
                self.kept = value
                    .get("series")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.get("series").and_then(Value::as_str))
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                self.refused = value
                    .get("refused")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default();
                if self.series.is_empty() || !self.knows(&self.series.clone()) {
                    self.series = self
                        .kept
                        .iter()
                        .find(|k| k.starts_with("interface:"))
                        .or_else(|| self.kept.first())
                        .map(|k| short(k).to_owned())
                        .unwrap_or_default();
                    self.changed();
                }
                let kept = self.kept.clone();
                self.compare.retain(|c| kept.iter().any(|k| short(k) == c));
            }
            "query" => {
                // The answer to what is asked now (an older one is dropped).
                self.asked = Some(self.params());
                self.data = Some(value);
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _: &'static str, ui: &mut Ui) {
        if !app.has_command(QUERY) {
            ui.weak(tr(app.lang.labels, "This router keeps no traffic history (system.graph.query)."));
            return;
        }
        self.toolbar(app, ui);
        ui.separator();
        if self.series.is_empty() {
            ui.weak(tr(app.lang.labels, "No series kept yet: Settings… chooses which interfaces."));
            return;
        }
        let Some(data) = self.data.clone() else {
            ui.weak(tr(app.lang.labels, "Loading…"));
            return;
        };
        // The PNG is this report: chips, numbers and chart with its axes.
        let report = ui
            .scope(|ui| {
                self.chips(app, ui, &data);
                if self.is_system() {
                    self.system_view(app, ui, &data);
                } else {
                    self.stats(app, ui, &data);
                    ui.add_space(4.0);
                    self.chart(app, ui, &data);
                }
            })
            .response
            .rect;
        self.plot_rect = Some(report);
        self.shot_result();
        // Always one line (the chart takes the height left above it, so a
        // line appearing later would grow the window): the file name, the
        // whole path on hover.
        let (text, full, bad) = match &self.status {
            Some(Ok(m)) => (short_path(m), m.clone(), false),
            Some(Err(e)) => (short_path(e), e.clone(), true),
            None => (String::new(), String::new(), false),
        };
        let line = if bad {
            RichText::new(text).color(ui.visuals().error_fg_color)
        } else {
            RichText::new(text).weak()
        };
        let r = ui.add(egui::Label::new(line).truncate());
        if !full.is_empty() {
            r.on_hover_text(full);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.settings_dialog(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: crate::panel::PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Saved>()
            && let Some(d) = self.settings.as_mut().filter(|d| d.id == r.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.settings = None;
        }
        // The new settings and what they keep.
        self.tick.set(0);
        self.kept.clear();
    }
}

impl Graphs {
    fn info(&mut self, app: &CoreRouterUi, ui: &mut Ui, key: &'static str, title: &'static str) {
        let l = app.lang.labels;
        if help::info_button(ui, Id::unique(("graphs-help", key)), tr(l, title)).clicked() {
            self.help = Some(HelpView::new(format!("graphs.{key}"), tr(l, title)));
        }
    }

    fn open_settings(&mut self, app: &mut CoreRouterUi) {
        if let Some(d) = &mut self.settings {
            d.status.bring_to_front();
            return;
        }
        let p = &self.print;
        let switches = SWITCHES.map(|(k, _)| p.get(k).and_then(Value::as_bool).unwrap_or(false));
        let fields = FIELDS.map(|(k, _, _)| match p.get(k) {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        });
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.settings = Some(SettingsDialog {
            id: app.next_dialog,
            switches,
            orig_switches: switches,
            fields: fields.clone(),
            orig_fields: fields,
            status: Status::default(),
        });
    }

    /// What OK sends: only what changed.
    pub(crate) fn settings_params(d: &SettingsDialog) -> Value {
        let mut m = serde_json::Map::new();
        for (i, (k, _)) in SWITCHES.iter().enumerate() {
            if d.switches.get(i) != d.orig_switches.get(i) {
                m.insert((*k).into(), json!(d.switches.get(i).copied().unwrap_or(false)));
            }
        }
        for (i, (k, _, _)) in FIELDS.iter().enumerate() {
            let (Some(v), Some(o)) = (d.fields.get(i), d.orig_fields.get(i)) else { continue };
            if v == o {
                continue;
            }
            let t = v.trim();
            let val = match *k {
                "include" | "exclude" => json!(t.split(',').map(str::trim).filter(|x| !x.is_empty()).collect::<Vec<_>>()),
                _ => t.parse::<u64>().map_or_else(|_| json!(t), |n| json!(n)),
            };
            m.insert((*k).into(), val);
        }
        Value::Object(m)
    }

    fn settings_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.settings.take() else { return };
        let l = app.lang.labels;
        let wid = dialog_id(d.id);
        let can = app.can();
        let head = dialog::Head {
            id: wid,
            title: tr(l, "Graphing"),
            dirty: d.switches != d.orig_switches || d.fields != d.orig_fields,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let print = self.print.clone();
        let mut info: Option<(&str, &str)> = None;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, _f| {
            Grid::new("graphs-settings").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                for ((key, label), on) in SWITCHES.iter().zip(d.switches.iter_mut()) {
                    ui.label(tr(l, label));
                    ui.checkbox(on, "");
                    if help::info_button(ui, Id::unique(("graphs-set-help", *key)), tr(l, label)).clicked() {
                        info = Some((key, label));
                    }
                    ui.end_row();
                }
                for ((key, label, hint), value) in FIELDS.iter().zip(d.fields.iter_mut()) {
                    ui.label(tr(l, label));
                    let h = ui.spacing().interact_size.y;
                    ui.add_sized([180.0, h], TextEdit::singleline(value).hint_text(*hint));
                    if help::info_button(ui, Id::unique(("graphs-set-help", *key)), tr(l, label)).clicked() {
                        info = Some((key, label));
                    }
                    ui.end_row();
                }
            });
            ui.separator();
            let mem = print.get("memory_bytes").and_then(Value::as_f64).unwrap_or(0.0);
            let cap = print.get("max_memory_bytes").and_then(Value::as_f64).unwrap_or(0.0);
            let n = print.get("series").and_then(Value::as_array).map_or(0, Vec::len);
            let mib = |b: f64| format!("{:.1} MiB", b / 1_048_576.0);
            ui.label(format!("{n} {}: {} / {}", tr(l, "series kept"), mib(mem), mib(cap)));
            let disk = print.get("disk").cloned().unwrap_or(Value::Null);
            match disk.get("dir").and_then(Value::as_str) {
                Some(dir) => {
                    let last = disk.get("last_store").and_then(Value::as_u64).map_or("–".into(), crate::ntp_client::utc);
                    ui.weak(format!("{} {dir}, {} {last}", tr(l, "On disk in"), tr(l, "last store")));
                    if let Some(e) = disk.get("last_error").and_then(Value::as_str) {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                    }
                }
                None => {
                    ui.weak(tr(l, "In memory only: no daemon with --config-dir stores it."));
                }
            }
            Footer::<()>::edit(false, can.check(SET))
        });
        if let Some((key, label)) = info {
            self.help = Some(HelpView::new(format!("graphs.set.{key}"), tr(l, label)));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(SET, Self::settings_params(&d), crate::panel::then(NAME, Saved(d.id)));
            }
            _ => {}
        }
        self.settings = Some(d);
    }

    fn toolbar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(l, "Series"));
            self.info(app, ui, "series", "Series");
            let before = self.series.clone();
            ComboBox::from_id_salt("graphs-series")
                .selected_text(if self.series == "system" { tr(l, "System").to_owned() } else { self.series.clone() })
                .show_ui(ui, |ui| {
                    for k in &self.kept {
                        let name = short(k).to_owned();
                        let text = if name == "system" { tr(l, "System").to_owned() } else { name.clone() };
                        ui.selectable_value(&mut self.series, name, text);
                    }
                });
            if self.series != before {
                self.compare.retain(|c| *c != before);
                self.changed();
            }
            if !self.is_system() {
                let others: Vec<String> = self
                    .kept
                    .iter()
                    .filter(|k| k.starts_with("interface:") && short(k) != self.series)
                    .map(|k| short(k).to_owned())
                    .collect();
                let mut changed = false;
                ui.menu_button(format!("{} ({})", tr(l, "Compare"), self.compare.len()), |ui| {
                    for name in others {
                        let mut on = self.compare.contains(&name);
                        let full = self.compare.len() >= MAX_COMPARE && !on;
                        let r = ui.add_enabled(!full, egui::Checkbox::new(&mut on, &name));
                        if r.changed() {
                            changed = true;
                            if on {
                                self.compare.push(name.clone());
                            } else {
                                self.compare.retain(|c| *c != name);
                            }
                        }
                    }
                });
                self.info(app, ui, "compare", "Compare");
                if changed {
                    self.changed();
                }
            }
            ui.separator();
            for r in Range::ALL {
                if ui.selectable_label(self.range == r, tr(l, r.label())).clicked() && self.range != r {
                    self.range = r;
                    self.changed();
                }
            }
            self.info(app, ui, "range", "Range");
            if !self.is_system() {
                ui.separator();
                for v in View::ALL {
                    if ui.selectable_label(self.view == v, tr(l, v.label())).clicked() {
                        self.view = v;
                    }
                }
            }
            ui.separator();
            if ui.button("CSV").on_hover_text(tr(l, "Save the points of the range as CSV")).clicked() {
                self.status = Some(self.save_csv(ui.ctx()));
            }
            if ui.button("PNG").on_hover_text(tr(l, "Save the chart as an image")).clicked() {
                self.save_png(ui.ctx());
            }
            self.info(app, ui, "export", "Export");
            ui.separator();
            let can = app.can().check(SET);
            let r = ui
                .add_enabled(can.is_ok() && self.print.is_object(), egui::Button::new(tr(l, "Settings…")))
                .on_hover_text(tr(l, "What the router keeps: system.graph.set"));
            if r.clicked() {
                self.open_settings(app);
            }
        });
        if !self.refused.is_empty() {
            ui.horizontal(|ui| {
                chip::chip(ui, &format!("{} {}", self.refused.len(), tr(l, "not kept")), AMBER.tone(ui.visuals()))
                    .on_hover_text(format!("{}: {}", tr(l, "Over max-memory"), self.refused.join(", ")));
            });
        }
    }

    /// Resolution, coverage and the p95's source, as chips.
    fn chips(&mut self, app: &CoreRouterUi, ui: &mut Ui, data: &Value) {
        let l = app.lang.labels;
        let first = data.get("series").and_then(|s| s.get(0));
        ui.horizontal(|ui| {
            let res = data.get("resolution").and_then(Value::as_u64).unwrap_or(0);
            let step = data.get("step").and_then(Value::as_u64).unwrap_or(0);
            chip::chip(
                ui,
                &format!("{} {}", tr(l, "resolution"), duration(res)),
                chip::neutral_tone(ui.visuals()),
            )
            .on_hover_text(format!("{} {}", tr(l, "One point every"), duration(step)));
            self.info(app, ui, "resolution", "Resolution");
            if let Some(c) = first.and_then(|s| s.get("coverage")).and_then(Value::as_f64)
                && c < 0.95
            {
                chip::chip(
                    ui,
                    &format!("{:.0} % {}", c * 100.0, tr(l, "known")),
                    AMBER.tone(ui.visuals()),
                )
                .on_hover_text(tr(l, "Part of the range has no data (the router was off, or the series is new)"));
                self.info(app, ui, "coverage", "Coverage");
            }
            if first.and_then(|s| s.get("p95_approximate")).and_then(Value::as_bool) == Some(true) {
                chip::chip(ui, tr(l, "p95 of 1 h averages"), AMBER.tone(ui.visuals()))
                    .on_hover_text(tr(l, "Billing uses 5-minute samples, kept for a week"));
            }
            if let Some(end) = data.get("end").and_then(Value::as_u64) {
                ui.weak(format!("{} {}", tr(l, "until"), crate::ntp_client::utc(end)));
            }
        });
    }

    /// Current, average, maximum, p95 and total of each line drawn.
    fn stats(&mut self, app: &CoreRouterUi, ui: &mut Ui, data: &Value) {
        let l = app.lang.labels;
        let series = data.get("series").and_then(Value::as_array).cloned().unwrap_or_default();
        let fields = self.view.fields();
        let totals = self.view.totals();
        let traffic = self.view == View::Traffic;
        Grid::new("graphs-stats").striped(true).spacing([16.0, 2.0]).show(ui, |ui| {
            ui.label("");
            for (key, title) in [
                ("current", "Current"),
                ("avg", "Average"),
                ("max", "Maximum"),
                ("p95", "95th pct"),
                ("total", "Total"),
            ] {
                ui.horizontal(|ui| {
                    ui.strong(tr(l, title));
                    self.info(app, ui, key, title);
                });
            }
            ui.end_row();
            for s in &series {
                let name = s.get("series").and_then(Value::as_str).map(short).unwrap_or("");
                for (i, (field, label, unit)) in fields.iter().enumerate() {
                    let st = s.get("stats").and_then(|x| x.get(field));
                    let n = |k: &str| st.and_then(|x| x.get(k)).and_then(Value::as_f64);
                    let ink = if series.len() > 1 { line_color(ui, name) } else if i == 0 { RX } else { TX };
                    let head = if series.len() > 1 { format!("{name} {}", tr(l, label)) } else { tr(l, label).to_owned() };
                    ui.label(RichText::new(head).color(ink));
                    for k in ["current", "avg", "max", "p95"] {
                        ui.label(n(k).map_or("–".into(), |v| rate(v, unit)));
                    }
                    let total = totals
                        .get(i)
                        .and_then(|t| s.get("totals").and_then(|x| x.get(t)))
                        .and_then(Value::as_f64);
                    ui.label(total.map_or("–".into(), |v| if traffic { bytes(v) } else { count(v) }));
                    ui.end_row();
                }
            }
        });
        if traffic {
            ui.horizontal_wrapped(|ui| {
                for s in &series {
                    let name = s.get("series").and_then(Value::as_str).map(short).unwrap_or("");
                    let get = |k: &str| s.get(k).and_then(Value::as_f64);
                    if series.len() > 1 {
                        ui.label(format!("{name}:"));
                    }
                    ui.label(tr(l, "p95 billing"));
                    ui.strong(get("p95_billing").map_or("–".into(), |v| rate(v, "bps")));
                    ui.label(tr(l, "p95 of Rx+Tx"));
                    ui.strong(get("p95_sum").map_or("–".into(), |v| rate(v, "bps")));
                }
                self.info(app, ui, "billing", "p95 billing");
            });
        }
    }

    fn chart(&mut self, app: &CoreRouterUi, ui: &mut Ui, data: &Value) {
        let l = app.lang.labels;
        let series = data.get("series").and_then(Value::as_array).cloned().unwrap_or_default();
        let fields = self.view.fields();
        let unit = fields[0].2;
        let range = self.range;
        let one = series.len() == 1;
        let (x0, x1) = span(data);
        let colors: Vec<Color32> = series
            .iter()
            .map(|s| line_color(ui, s.get("series").and_then(Value::as_str).map(short).unwrap_or("")))
            .collect();
        Plot::new("graphs-chart")
            .height((ui.available_height() - ui.spacing().interact_size.y - 8.0).max(160.0))
            .legend(Legend::default().position(egui_plot::Corner::LeftTop))
            .include_y(0.0)
            .include_x(x0)
            .include_x(x1)
            .y_axis_formatter(move |m, _| rate(m.value, unit))
            .x_axis_formatter(move |m, _| time_label(m.value, range))
            .label_formatter(move |h| hover(h, unit))
            .allow_scroll(false)
            .show(ui, |p| {
                for (si, s) in series.iter().enumerate() {
                    let name = s.get("series").and_then(Value::as_str).map(short).unwrap_or("");
                    for (fi, (field, label, _)) in fields.iter().enumerate() {
                        let color = if one { [RX, TX].get(fi).copied().unwrap_or(RX) } else { colors.get(si).copied().unwrap_or(RX) };
                        let style = if one || fi == 0 { LineStyle::Solid } else { LineStyle::dashed_loose() };
                        let title = if one { tr(l, label).to_owned() } else { format!("{name} {}", tr(l, label)) };
                        for run in runs(s, data, field) {
                            p.line(Line::new(title.clone(), PlotPoints::from(run)).color(color).width(1.5).style(style));
                        }
                        if one {
                            let max = format!("{field}_max");
                            for run in runs(s, data, &max) {
                                p.line(
                                    Line::new(format!("{} max", tr(l, label)), PlotPoints::from(run))
                                        .color(color.gamma_multiply(0.35))
                                        .width(1.0),
                                );
                            }
                            if let Some(v) = s
                                .get("stats")
                                .and_then(|x| x.get(field))
                                .and_then(|x| x.get("p95"))
                                .and_then(Value::as_f64)
                            {
                                p.hline(
                                    HLine::new(format!("p95 {}", tr(l, label)), v)
                                        .color(color.gamma_multiply(0.7))
                                        .style(LineStyle::dashed_dense()),
                                );
                            }
                        }
                    }
                }
            });
    }

    /// CPU, memory and conntrack, one small chart each.
    fn system_view(&mut self, app: &CoreRouterUi, ui: &mut Ui, data: &Value) {
        let l = app.lang.labels;
        let Some(s) = data.get("series").and_then(|v| v.get(0)).cloned() else {
            return;
        };
        Grid::new("graphs-system-stats").striped(true).spacing([16.0, 2.0]).show(ui, |ui| {
            ui.label("");
            for (key, title) in [("current", "Current"), ("avg", "Average"), ("max", "Maximum"), ("p95", "95th pct")] {
                ui.horizontal(|ui| {
                    ui.strong(tr(l, title));
                    self.info(app, ui, key, title);
                });
            }
            ui.end_row();
            for (field, label, unit) in SYSTEM_FIELDS {
                let st = s.get("stats").and_then(|x| x.get(field));
                let n = |k: &str| st.and_then(|x| x.get(k)).and_then(Value::as_f64);
                ui.horizontal(|ui| {
                    ui.label(tr(l, label));
                    self.info(app, ui, field, label);
                });
                for k in ["current", "avg", "max", "p95"] {
                    ui.label(n(k).map_or("–".into(), |v| rate(v, unit)));
                }
                ui.end_row();
            }
        });
        let range = self.range;
        let (x0, x1) = span(data);
        let h = ((ui.available_height() - ui.spacing().interact_size.y - 24.0) / 3.0).max(90.0);
        for (i, (field, label, unit)) in SYSTEM_FIELDS.iter().enumerate() {
            let unit: &'static str = unit;
            let color = chip::palette_tone(ui.visuals(), i * 3).ink;
            Plot::new(("graphs-system", *field))
                .height(h)
                .include_y(0.0)
                .include_x(x0)
                .include_x(x1)
                .y_axis_formatter(move |m, _| rate(m.value, unit))
                .x_axis_formatter(move |m, _| time_label(m.value, range))
                .label_formatter(move |h| hover(h, unit))
                .allow_scroll(false)
                .legend(Legend::default().position(egui_plot::Corner::LeftTop))
                .show(ui, |p| {
                    for run in runs(&s, data, field) {
                        p.line(Line::new(tr(l, label), PlotPoints::from(run)).color(color).width(1.5));
                    }
                });
        }
    }

    /// The points of the range as CSV: one line per point and series.
    pub(crate) fn csv(&self) -> Option<String> {
        let data = self.data.as_ref()?;
        let start = data.get("start").and_then(Value::as_u64)?;
        let step = data.get("step").and_then(Value::as_u64)?;
        let series = data.get("series").and_then(Value::as_array)?;
        let fields: Vec<String> = series
            .first()
            .and_then(|s| s.get("data"))
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut out = format!("time_utc,unix,series,{}\n", fields.join(","));
        for s in series {
            let name = s.get("series").and_then(Value::as_str).map(short).unwrap_or("");
            let cols: Vec<&[Value]> = fields
                .iter()
                .map(|f| {
                    s.get("data")
                        .and_then(|d| d.get(f))
                        .and_then(Value::as_array)
                        .map_or(&[][..], Vec::as_slice)
                })
                .collect();
            let n = cols.iter().map(|c| c.len()).max().unwrap_or(0);
            for i in 0..n {
                let t = start + i as u64 * step;
                let _ = write!(out, "{},{t},{name}", crate::ntp_client::utc(t).trim_end_matches(" UTC"));
                for c in &cols {
                    match c.get(i).and_then(Value::as_f64) {
                        Some(v) => {
                            let _ = write!(out, ",{v}");
                        }
                        None => out.push(','),
                    }
                }
                out.push('\n');
            }
        }
        Some(out)
    }

    fn file_name(&self, ext: &str) -> String {
        let who: String = self
            .wanted()
            .iter()
            .map(|s| s.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.', "_"))
            .collect::<Vec<_>>()
            .join("+");
        format!("graph-{who}-{}.{ext}", self.range.param())
    }

    fn save_csv(&self, ctx: &egui::Context) -> Result<String, String> {
        let text = self.csv().ok_or("nothing to export yet")?;
        export::save(ctx, &self.file_name("csv"), Export::Text(text))
    }

    fn save_png(&mut self, ctx: &egui::Context) {
        let Some(rect) = self.plot_rect else {
            self.status = Some(Err("nothing to export yet".into()));
            return;
        };
        let name = self.file_name("png");
        let slot = Arc::clone(&self.shot);
        let saver = export::saver(ctx);
        let ppp = ctx.pixels_per_point();
        let ctx2 = ctx.clone();
        ctx.request_screenshot(move |img| {
            let part = export::crop(&img, rect, ppp);
            let out = match saver {
                Some(f) => f(&name, Export::Image(part)),
                None => {
                    ctx2.copy_image(part);
                    Ok("copied to the clipboard".into())
                }
            };
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(out);
            ctx2.request_repaint();
        });
        ctx.request_repaint();
        self.status = Some(Ok("taking the picture…".into()));
    }

    fn shot_result(&mut self) {
        if let Some(r) = self.shot.lock().unwrap_or_else(PoisonError::into_inner).take() {
            self.status = Some(r);
        }
    }
}

/// The label next to the pointer: the line, the time and the value.
fn hover(h: &egui_plot::HoverPosition<'_>, unit: &str) -> Option<String> {
    match h {
        egui_plot::HoverPosition::NearDataPoint { plot_name, position, .. } => Some(format!(
            "{plot_name}\n{}\n{}",
            crate::ntp_client::utc(position.x.max(0.0) as u64),
            rate(position.y, unit)
        )),
        egui_plot::HoverPosition::Elsewhere { .. } => None,
    }
}

/// The colour of a compared interface: the palette entry of its name.
fn line_color(ui: &Ui, name: &str) -> Color32 {
    chip::palette_tone(ui.visuals(), chip::name_hue(name)).ink
}

/// The whole range on the time axis (an hour of which one minute is known
/// still reads as an hour).
fn span(data: &Value) -> (f64, f64) {
    let n = |k: &str| data.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    (n("start"), n("end"))
}

/// The known points of `field`, split where values are unknown (a hole in
/// the line, not a dive to zero).
fn runs(s: &Value, data: &Value, field: &str) -> Vec<Vec<[f64; 2]>> {
    let start = data.get("start").and_then(Value::as_f64).unwrap_or(0.0);
    let step = data.get("step").and_then(Value::as_f64).unwrap_or(1.0);
    let mut out: Vec<Vec<[f64; 2]>> = Vec::new();
    let mut cur: Vec<[f64; 2]> = Vec::new();
    let empty = Vec::new();
    let col = s.get("data").and_then(|d| d.get(field)).and_then(Value::as_array).unwrap_or(&empty);
    for (i, v) in col.iter().enumerate() {
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
}

/// `12:30` for an hour or a day, `10-21 12h` for a week, `10-21` beyond.
fn time_label(x: f64, range: Range) -> String {
    if x < 0.0 {
        return String::new();
    }
    let s = crate::ntp_client::utc(x as u64);
    let pick = |a: usize, b: usize| s.get(a..b).unwrap_or("").to_owned();
    match range {
        Range::Hour | Range::Day => pick(11, 16),
        Range::Week => format!("{} {}h", pick(5, 10), pick(11, 13)),
        Range::Month | Range::Year => pick(5, 10),
    }
}

/// `saved /home/x/Downloads/graph.png` → `saved graph.png`.
fn short_path(m: &str) -> String {
    match m.split_once(' ') {
        Some((verb, path)) if path.contains('/') || path.contains('\\') => {
            let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
            format!("{verb} {name}")
        }
        _ => m.to_owned(),
    }
}

/// `1 s`, `5 min`, `1 h`.
pub(crate) fn duration(secs: u64) -> String {
    match secs {
        0 => "–".into(),
        s if s % 3600 == 0 => format!("{} h", s / 3600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// A rate or level with SI prefixes: `12.5 Mbps`, `830 pps`, `41 %`.
pub(crate) fn rate(v: f64, unit: &str) -> String {
    if !v.is_finite() {
        return "–".into();
    }
    if unit == "%" {
        return format!("{v:.1} %");
    }
    if unit == "B" {
        return bytes(v);
    }
    // A count: `227.9 k`, not `227.9 kentries`.
    let unit = if unit == "entries" { "" } else { unit };
    let a = v.abs();
    let (n, p) = if a >= 1e9 {
        (v / 1e9, "G")
    } else if a >= 1e6 {
        (v / 1e6, "M")
    } else if a >= 1e3 {
        (v / 1e3, "k")
    } else {
        let s = if a >= 10.0 || a == 0.0 { format!("{v:.0} {unit}") } else { format!("{v:.2} {unit}") };
        return s.trim_end().to_owned();
    };
    format!("{n:.1} {p}{unit}").trim_end().to_owned()
}

/// Bytes in decimal units (the totals: `12.34 GB`).
pub(crate) fn bytes(v: f64) -> String {
    let a = v.abs();
    if a >= 1e12 {
        format!("{:.2} TB", v / 1e12)
    } else if a >= 1e9 {
        format!("{:.2} GB", v / 1e9)
    } else if a >= 1e6 {
        format!("{:.1} MB", v / 1e6)
    } else if a >= 1e3 {
        format!("{:.1} kB", v / 1e3)
    } else {
        format!("{v:.0} B")
    }
}

fn count(v: f64) -> String {
    rate(v, "").trim_end().to_owned()
}

//! IP › Firewall › Connections (G2.2): the conntrack table as RouterOS'
//! `/ip firewall connection`, a tab of the Firewall window (parts of a
//! window are tabs, `docs/ui-style.md`).
//!
//! - How full the table is (`nf_conntrack_max`, a Tuning parameter: the
//!   bar opens System › Tuning) and its trouble counters as chips.
//! - Filters (protocol, source, destination, subscriber, state, Via) sent
//!   to `ip.firewall.connection.list`, which pages: the window holds one
//!   page (≤ 500 rows), so a million connections never reach the GUI.
//! - The subscribers with the most connections, with how full their CGNAT
//!   slot is; a click filters by one.
//! - Kill: the selected rows, or everything the filter matches.
//! - Tracking…: the timeouts of `/ip firewall connection tracking`, with an
//!   ⓘ per field.
//!
//! A panel with no window of its own: `firewall.rs` draws it in its tab.

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query};
use crate::table::{self, Menu, Row, TableState, action, col, num, weak};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "connections";
const TABLE: &str = "fw-connections";
const TOP_TABLE: &str = "fw-connections-top";
/// Rows of one page.
pub(crate) const PAGE: u64 = 500;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::<Connections>::default(),
};

const COLUMNS: [table::Column; 9] = [
    col("Protocol"),
    col("Src. Address"),
    col("Dst. Address"),
    col("NAT"),
    col("State"),
    col("Via"),
    num("Timeout"),
    num("Bytes"),
    weak("Flags"),
];
const TOP_COLUMNS: [table::Column; 3] = [col("Subscriber"), num("Conns"), col("Ports")];

/// The tracking parameters: key, label, unit (RouterOS names).
pub(crate) const TRACKING: &[(&str, &str)] = &[
    ("tcp_established_timeout", "TCP Established Timeout"),
    ("tcp_syn_sent_timeout", "TCP SYN Sent Timeout"),
    ("tcp_syn_received_timeout", "TCP SYN Received Timeout"),
    ("tcp_fin_wait_timeout", "TCP FIN Wait Timeout"),
    ("tcp_close_wait_timeout", "TCP Close Wait Timeout"),
    ("tcp_time_wait_timeout", "TCP Time Wait Timeout"),
    ("udp_timeout", "UDP Timeout"),
    ("udp_stream_timeout", "UDP Stream Timeout"),
    ("icmp_timeout", "ICMP Timeout"),
    ("generic_timeout", "Generic Timeout"),
    ("max_entries", "Max Entries"),
];

#[derive(Default, Clone, PartialEq)]
pub(crate) struct Filters {
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub subscriber: String,
    pub state: String,
    pub via: String,
}

impl Filters {
    fn params(&self) -> Map<String, Value> {
        let mut m = Map::new();
        for (k, v) in [
            ("protocol", &self.protocol),
            ("src", &self.src),
            ("dst", &self.dst),
            ("subscriber", &self.subscriber),
            ("state", &self.state),
            ("via", &self.via),
        ] {
            if !v.trim().is_empty() {
                m.insert(k.into(), json!(v.trim()));
            }
        }
        m
    }

    fn any(&self) -> bool {
        !self.params().is_empty()
    }
}

#[derive(Default)]
pub(crate) struct Connections {
    pub(crate) filters: Filters,
    pub(crate) offset: u64,
    pub(crate) paused: bool,
    /// The last `ip.firewall.connection.list` answer.
    pub(crate) list: Value,
    pub(crate) top: Vec<Value>,
    pub(crate) tracking: Value,
    /// The filter's error (a prefix that does not parse).
    pub(crate) error: Option<String>,
    table: TableState,
    top_table: TableState,
    pub(crate) dialog: Option<TrackingDialog>,
    pub(crate) help: Option<HelpView>,
    /// Kill everything the filter matches: waiting for the confirmation.
    pub(crate) confirm_kill: Option<u64>,
}

pub(crate) struct TrackingDialog {
    id: u64,
    values: Vec<String>,
    orig: Vec<String>,
    status: Status,
}

struct Reply(u64);
struct Killed;

/// Whether the Connections tab is on screen.
fn showing(app: &CoreRouterUi) -> bool {
    app.open.contains(&Win::Firewall) && app.firewall_tab_is_connections()
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).map(value_text).unwrap_or_default()
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS.get(u).copied().unwrap_or("B"))
    }
}

/// `1d02:03:04`, as RouterOS prints a timeout.
pub(crate) fn secs(n: u64) -> String {
    let (d, h, m, s) = (n / 86_400, n / 3600 % 24, n / 60 % 60, n % 60);
    if d > 0 {
        format!("{d}d{h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

fn via_kind(via: &str) -> Kind {
    match via {
        "hardware" => Kind::Green,
        "software" => Kind::Blue,
        _ => Kind::Neutral,
    }
}

pub(crate) fn row(r: &Value) -> Row {
    let total = r.get("orig_bytes").and_then(Value::as_u64).unwrap_or(0)
        + r.get("repl_bytes").and_then(Value::as_u64).unwrap_or(0);
    let via = text(r, "via");
    let state = text(r, "state");
    let state_kind = match state.as_str() {
        "established" | "stream" => Kind::Green,
        "time-wait" | "close" | "fin-wait" | "close-wait" | "last-ack" => Kind::Neutral,
        _ => Kind::Amber,
    };
    let src = text(r, "src");
    let src_cell = match r.get("pool") {
        Some(p) => chip::cell(&src, &[(value_text(p).as_str(), Kind::Hashed(chip::name_hue(&value_text(p))))]),
        None => src,
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "protocol"),
            src_cell,
            text(r, "dst"),
            text(r, "nat"),
            chip::cell("", &[(state.as_str(), state_kind)]),
            chip::cell("", &[(via.as_str(), via_kind(&via))]),
            secs(r.get("timeout").and_then(Value::as_u64).unwrap_or(0)),
            bytes(total),
            text(r, "flags"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn top_row(r: &Value) -> Row {
    let ports = match (r.get("ports_used").and_then(Value::as_u64), r.get("ports").and_then(Value::as_u64)) {
        (Some(u), Some(p)) => {
            let pct = r.get("percent").and_then(Value::as_u64).unwrap_or(0);
            let kind = if pct >= 90 {
                Kind::Red
            } else if pct >= 70 {
                Kind::Amber
            } else {
                Kind::Green
            };
            chip::cell(&format!("{u}/{p}"), &[(format!("{pct} %").as_str(), kind)])
        }
        _ => "–".into(),
    };
    Row {
        key: text(r, "subscriber"),
        cells: vec![text(r, "subscriber"), text(r, "connections"), ports],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl Connections {
    fn list_params(&self) -> Value {
        let mut m = self.filters.params();
        m.insert("offset".into(), json!(self.offset));
        m.insert("count".into(), json!(PAGE));
        Value::Object(m)
    }

    fn total(&self) -> u64 {
        self.list.get("total").and_then(Value::as_u64).unwrap_or(0)
    }

    /// The usage bar: count / max, the trouble counters, Tracking….
    fn usage(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let t = self.list.get("table").cloned().unwrap_or(Value::Null);
        let count = t.get("count").and_then(Value::as_u64).unwrap_or(0);
        let max = t.get("max").and_then(Value::as_u64).unwrap_or(0);
        let pct = t.get("percent").and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            ui.label(tr(l, "Table"));
            let frac = if max == 0 { 0.0 } else { count as f32 / max as f32 };
            let bar = egui::ProgressBar::new(frac.clamp(0.0, 1.0))
                .desired_width(220.0)
                .text(format!("{count} / {max} ({pct} %)"));
            let tone = if pct >= 90 {
                chip::RED
            } else if pct >= 70 {
                chip::AMBER
            } else {
                chip::GREEN
            };
            let fill = tone.tone(ui.visuals()).fill;
            if ui
                .add(bar.fill(fill))
                .on_hover_text(tr(l, "nf_conntrack_max: change it in System › Tuning"))
                .clicked()
            {
                app.open(Win::Panel(crate::tuning::WIN));
            }
            if help::info_button(ui, Id::unique("conn-help-table"), tr(l, "Table")).clicked() {
                self.help = Some(HelpView::new("connections.table", tr(l, "Connection table")));
            }
            for (key, label) in [
                ("insert_failed", "insert failed"),
                ("drop", "dropped"),
                ("early_drop", "early drop"),
            ] {
                let n = t.get(key).and_then(Value::as_u64).unwrap_or(0);
                if n > 0 {
                    chip::chip(ui, &format!("{label} {n}"), chip::RED.tone(ui.visuals()))
                        .on_hover_text(tr(l, "Since boot: connections the kernel could not create or kept out"));
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can = app.can();
                let enabled = can.check("ip.firewall.connection.tracking.set");
                if ui
                    .add_enabled(enabled.is_ok(), egui::Button::new(tr(l, "Tracking…")))
                    .on_disabled_hover_text(enabled.err().unwrap_or_default())
                    .clicked()
                    && self.dialog.is_none()
                {
                    app.next_dialog = app.next_dialog.wrapping_add(1);
                    let values: Vec<String> = TRACKING
                        .iter()
                        .map(|(k, _)| self.tracking.get(*k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default())
                        .collect();
                    self.dialog = Some(TrackingDialog {
                        id: app.next_dialog,
                        orig: values.clone(),
                        values,
                        status: Status::default(),
                    });
                }
                ui.checkbox(&mut self.paused, tr(l, "Pause"));
            });
        });
    }

    fn filters(&mut self, ui: &mut Ui, l: Lang) -> bool {
        let before = self.filters.clone();
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(l, "Protocol"));
            ComboBox::from_id_salt("conn-proto")
                .width(70.0)
                .selected_text(if self.filters.protocol.is_empty() { tr(l, "any") } else { self.filters.protocol.as_str() })
                .show_ui(ui, |ui| {
                    for p in ["", "tcp", "udp", "icmp", "gre"] {
                        let shown = if p.is_empty() { tr(l, "any") } else { p };
                        ui.selectable_value(&mut self.filters.protocol, p.to_owned(), shown);
                    }
                });
            for (label, field, hint, w) in [
                ("Src.", &mut self.filters.src, "100.64.0.0/10", 120.0),
                ("Dst.", &mut self.filters.dst, "0.0.0.0/0", 120.0),
                ("Subscriber", &mut self.filters.subscriber, "100.64.0.9", 110.0),
            ] {
                ui.label(tr(l, label));
                ui.add(TextEdit::singleline(field).hint_text(hint).desired_width(w));
            }
            ui.label(tr(l, "State"));
            ComboBox::from_id_salt("conn-state")
                .width(90.0)
                .selected_text(if self.filters.state.is_empty() { tr(l, "any") } else { self.filters.state.as_str() })
                .show_ui(ui, |ui| {
                    for s in ["", "established", "stream", "new", "syn-sent", "time-wait", "close"] {
                        let shown = if s.is_empty() { tr(l, "any") } else { s };
                        ui.selectable_value(&mut self.filters.state, s.to_owned(), shown);
                    }
                });
            ui.label(tr(l, "Via"));
            ComboBox::from_id_salt("conn-via")
                .width(80.0)
                .selected_text(if self.filters.via.is_empty() { tr(l, "any") } else { self.filters.via.as_str() })
                .show_ui(ui, |ui| {
                    for v in ["", "rules", "software", "hardware"] {
                        let shown = if v.is_empty() { tr(l, "any") } else { v };
                        ui.selectable_value(&mut self.filters.via, v.to_owned(), shown);
                    }
                });
            if help::info_button(ui, Id::unique("conn-help-via"), tr(l, "Via")).clicked() {
                self.help = Some(HelpView::new("connections.via", tr(l, "Via")));
            }
            if self.filters.any() && ui.small_button(tr(l, "Clear")).clicked() {
                self.filters = Filters::default();
            }
        });
        if self.filters != before {
            self.offset = 0;
            true
        } else {
            false
        }
    }
}

impl PanelState for Connections {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !showing(app) || self.paused || !app.has_command("ip.firewall.connection.list") {
            return Vec::new();
        }
        let mut out = vec![
            Query {
                key: "list",
                command: "ip.firewall.connection.list",
                params: self.list_params(),
            },
            Query {
                key: "top",
                command: "ip.firewall.connection.top",
                params: json!({"count": 12}),
            },
        ];
        if app.has_command("ip.firewall.connection.tracking.info") {
            out.push(Query {
                key: "tracking",
                command: "ip.firewall.connection.tracking.info",
                params: json!({}),
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "list" => {
                self.error = None;
                self.list = value;
            }
            "top" => {
                if let Value::Array(a) = value {
                    self.top = a;
                }
            }
            "tracking" => self.tracking = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.usage(app, ui, l);
        if self.filters(ui, l) {
            app.cache.refreshed_at = None;
        }
        let total = self.total();
        let rows: Vec<Row> = self
            .list
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(row).collect())
            .unwrap_or_default();
        let selection = self.table.selection(&rows);
        let can = app.can();
        let mut kill_selected = false;
        let mut kill_filtered = false;
        let mut pick_subscriber: Option<String> = None;
        ui.horizontal(|ui| {
            let picked = if selection.is_empty() {
                Err(tr(l, "Select connections first").to_owned())
            } else {
                Ok(())
            };
            kill_selected = ui
                .add_enabled(
                    can.and("ip.firewall.connection.kill", picked.clone()).is_ok(),
                    egui::Button::new(tr(l, "Kill")),
                )
                .on_hover_text(tr(l, "Remove the selected connections from the table"))
                .clicked();
            let filtered = if self.filters.any() { Ok(()) } else { Err(tr(l, "Set a filter first").to_owned()) };
            kill_filtered = ui
                .add_enabled(
                    can.and("ip.firewall.connection.kill", filtered).is_ok() && total > 0,
                    egui::Button::new(format!("{} ({total})", tr(l, "Kill matching"))),
                )
                .clicked();
            ui.separator();
            let first = if total == 0 { 0 } else { self.offset + 1 };
            let last = (self.offset + PAGE).min(total);
            if ui.add_enabled(self.offset > 0, egui::Button::new("‹")).clicked() {
                self.offset = self.offset.saturating_sub(PAGE);
                app.cache.refreshed_at = None;
            }
            ui.label(format!("{first}–{last} {} {total}", tr(l, "of")));
            if ui.add_enabled(last < total, egui::Button::new("›")).clicked() {
                self.offset += PAGE;
                app.cache.refreshed_at = None;
            }
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
        });
        ui.separator();
        let side = 310.0_f32.min(ui.available_width() * 0.4);
        ui.horizontal_top(|ui| {
            let main_w = (ui.available_width() - side - 8.0).max(200.0);
            let size = egui::vec2(main_w, ui.available_height());
            ui.allocate_ui_with_layout(size, egui::Layout::top_down(egui::Align::Min), |ui| {
                let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| {
                    if let Menu::Rows(sel) = menu {
                        if action(ui, tr(l, "Kill"), can.check("ip.firewall.connection.kill")) {
                            kill_selected = true;
                        }
                        if let Some(first) = sel.first()
                            && let Some(r) = self
                                .list
                                .get("rows")
                                .and_then(Value::as_array)
                                .and_then(|a| a.iter().find(|r| text(r, "id") == *first))
                            && action(ui, tr(l, "Filter by this source"), Ok(()))
                        {
                            let src = text(r, "src");
                            let addr = src.split([' ', ':']).next().unwrap_or("").to_owned();
                            pick_subscriber = Some(addr);
                        }
                    }
                });
                let _ = out;
            });
            ui.vertical(|ui| {
                ui.set_width(side);
                ui.horizontal(|ui| {
                    ui.strong(tr(l, "Top subscribers"));
                    if help::info_button(ui, Id::unique("conn-help-top"), tr(l, "Top subscribers")).clicked() {
                        self.help = Some(HelpView::new("connections.top", tr(l, "Top subscribers")));
                    }
                });
                let rows: Vec<Row> = self.top.iter().map(top_row).collect();
                let out = table::show(ui, TOP_TABLE, 0.0, &mut self.top_table, &TOP_COLUMNS, &rows, |_, _| {});
                if let Some(k) = out.clicked.or(out.opened) {
                    pick_subscriber = Some(k);
                }
            });
        });
        if let Some(sub) = pick_subscriber {
            self.filters.subscriber = sub;
            self.offset = 0;
            app.cache.refreshed_at = None;
        }
        if kill_selected && !selection.is_empty() {
            for id in &selection {
                if let Ok(n) = id.parse::<u64>() {
                    app.run_then("ip.firewall.connection.kill", json!({"id": n}), crate::panel::then(NAME, Killed));
                }
            }
        }
        if kill_filtered {
            self.confirm_kill = Some(total);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        let l = app.lang.labels;
        if let Some(n) = self.confirm_kill {
            let mut answer = None;
            egui::Modal::new(Id::unique("conn-kill-confirm")).show(ctx, |ui| {
                ui.label(format!("{} {n} {}", tr(l, "Kill"), tr(l, "connections matching the filter?")));
                ui.weak(tr(l, "Their traffic stops until the hosts open new connections."));
                ui.horizontal(|ui| {
                    if ui.button(tr(l, "Kill")).clicked() {
                        answer = Some(true);
                    }
                    if ui.button(tr(l, "Cancel")).clicked() {
                        answer = Some(false);
                    }
                });
            });
            match answer {
                Some(true) => {
                    app.run_then(
                        "ip.firewall.connection.kill",
                        Value::Object(self.filters.params()),
                        crate::panel::then(NAME, Killed),
                    );
                    self.confirm_kill = None;
                }
                Some(false) => self.confirm_kill = None,
                None => {}
            }
        }
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let can = app.can();
        let head = dialog::Head {
            id: wid,
            title: tr(l, "Connection Tracking"),
            dirty: d.values != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Firewall)),
        };
        let mut info: Option<(&str, &str)> = None;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, _f| {
            Grid::new("conn-tracking").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                for ((key, label), value) in TRACKING.iter().zip(d.values.iter_mut()) {
                    ui.label(tr(l, label));
                    let h = ui.spacing().interact_size.y;
                    ui.add_sized([110.0, h], TextEdit::singleline(value).hint_text("1d, 5m, 30"));
                    if help::info_button(ui, Id::unique(("conn-tracking-help", *key)), tr(l, label)).clicked() {
                        info = Some((key, label));
                    }
                    ui.end_row();
                }
            });
            ui.weak(tr(l, "Seconds or 1d, 5m. Kept as System › Tuning parameters."));
            Footer::<()>::edit(false, can.check("ip.firewall.connection.tracking.set"))
        });
        if let Some((key, label)) = info {
            self.help = Some(HelpView::new(format!("connections.{key}"), tr(l, label)));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = Map::new();
                for (((key, _), v), o) in TRACKING.iter().zip(&d.values).zip(&d.orig) {
                    if v != o && !v.trim().is_empty() {
                        let t = v.trim();
                        let val = t.parse::<u64>().map_or_else(|_| json!(t), |n| json!(n));
                        p.insert((*key).into(), val);
                    }
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(
                    "ip.firewall.connection.tracking.set",
                    Value::Object(p),
                    crate::panel::then(NAME, Reply(d.id)),
                );
            }
            _ => {}
        }
        self.dialog = Some(d);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        match then.downcast::<Reply>() {
            Ok(r) => {
                if let Some(d) = self.dialog.as_mut().filter(|d| d.id == r.0)
                    && d.status.replied(result)
                {
                    app.floats.forget(dialog_id(d.id));
                    self.dialog = None;
                }
            }
            Err(other) => {
                if other.downcast::<Killed>().is_ok()
                    && let Err(e) = result
                {
                    self.error = Some(e.clone());
                }
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (TOP_TABLE, &self.top_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table), (TOP_TABLE, &mut self.top_table)]
    }
}

impl CoreRouterUi {
    /// Draw the Connections tab of the Firewall window.
    pub(crate) fn connections_tab(&mut self, ui: &mut Ui) {
        self.with_panel(NAME, |p, app| p.window(app, "fw-connections", ui));
    }
}

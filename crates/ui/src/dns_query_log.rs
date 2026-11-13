//! IP › DNS › Query Log (G4.1zd): the queries the LAN forwarder answered,
//! from the log on the router's disk (`ip.dns.log.*`).
//!
//! - On top, what the log is doing in a chip and a line: on or off, how
//!   clients are written, the disk it takes against its ceiling, the oldest
//!   query kept, and the law (Marco Civil art. 14, LGPD) with its ⓘ.
//! - The filters (period, client, name, type, response code, who answered)
//!   and Find; a page of rows, newest first, with Older / Newer; Export
//!   (CSV or JSON lines) of what the filters keep.
//! - **Settings…**: the dialog of `ip.dns.log.set`, with the estimate the
//!   engine makes (GB a day at the current rate, the retention the ceiling
//!   gives, disk wear a year) and, to turn the log on, the box that
//!   acknowledges the law (sent as `acknowledge`).
//! - **Clear…**: everything, before a time, or one client (LGPD art. 18).
//!
//! The first page refreshes itself every few seconds; older pages stay as
//! they are. Nothing is filtered here: the engine searches the files.

use std::cell::Cell;

use egui::{Grid, Id, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, GREEN, RED, chip, neutral_tone};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Head, Press, Status};
use crate::export::{self, Export};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::list::filter_chip;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, action, col, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-query-log";
pub(crate) const WIN: &str = "dns-query-log";
const TABLE: &str = "dns-query-log";
const SCOPE: &str = "dns_query_log";
const GET: &str = "ip.dns.log.get";
const PRINT: &str = "ip.dns.log.print";
const SET: &str = "ip.dns.log.set";
const EXPORT: &str = "ip.dns.log.export";
const CLEAR: &str = "ip.dns.log.clear";
/// Rows a page asks for.
const PAGE: u32 = 200;
/// Rows an export asks for.
const EXPORT_ROWS: u32 = 100_000;
/// The first page is asked again every this many refreshes (seconds).
const LIVE_EVERY: u32 = 5;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Query Log",
        size: [980.0, 640.0],
        escape: true,
    }],
    new: || Box::new(QueryLogPanel::default()),
};

const COLUMNS: [table::Column; 7] = [
    col("Time (UTC)").help("dns_query_log.time"),
    col("Client").help("dns_query_log.client"),
    col("Name").help("dns_query_log.name"),
    col("Type").help("dns_query_log.type"),
    col("Rcode").help("dns_query_log.rcode"),
    col("Answered by").help("dns_query_log.answered_by"),
    num("ms").help("dns_query_log.latency"),
];

/// The period filter: (label, seconds; 0 = everything kept).
const PERIODS: [(&str, u32); 5] =
    [("Last 15 min", 900), ("Last hour", 3600), ("Last 6 h", 21_600), ("Last 24 h", 86_400), ("Everything kept", 0)];
const RCODES: [(&str, &str); 5] = [
    ("noerror", "NOERROR"),
    ("nxdomain", "NXDOMAIN"),
    ("servfail", "SERVFAIL"),
    ("refused", "REFUSED"),
    ("dropped", "Dropped"),
];
const ANSWERED: [&str; 7] = ["cache", "upstream", "stale", "static", "adlist", "refused", "limit"];
const CLIENT_ADDRESS: [(&str, &str); 4] = [
    ("truncated", "Truncated"),
    ("hashed", "Hashed"),
    ("none", "None"),
    ("full", "Full address"),
];

/// Every explanation the window opens (a test checks both languages).
#[cfg(test)]
pub(crate) const HELP_KEYS: &[&str] = &[
    "dns_query_log.answered_by",
    "dns_query_log.clear",
    "dns_query_log.client",
    "dns_query_log.client_address",
    "dns_query_log.enabled",
    "dns_query_log.estimate",
    "dns_query_log.except_from",
    "dns_query_log.exclude",
    "dns_query_log.export",
    "dns_query_log.latency",
    "dns_query_log.law",
    "dns_query_log.max_age",
    "dns_query_log.max_size",
    "dns_query_log.name",
    "dns_query_log.only_from",
    "dns_query_log.prefixes",
    "dns_query_log.rcode",
    "dns_query_log.salt_rotation",
    "dns_query_log.time",
    "dns_query_log.type",
    "dns_query_log.window",
];

#[derive(Default)]
pub(crate) struct QueryLogPanel {
    /// `ip.dns.log.get`.
    pub(crate) get: Option<Value>,
    /// The page shown (`ip.dns.log.print`).
    pub(crate) page: Option<Value>,
    pub(crate) error: Option<String>,
    pub(crate) period: usize,
    pub(crate) client: String,
    pub(crate) name: String,
    pub(crate) qtype: String,
    pub(crate) rcode: Option<&'static str>,
    pub(crate) by: Option<&'static str>,
    /// The cursor of the page shown (`None`: the newest) and those of the
    /// newer pages, for Newer.
    cursor: Option<String>,
    newer: Vec<Option<String>>,
    /// Ask for the page in the next refresh.
    fetch: Cell<bool>,
    tick: Cell<u32>,
    /// An export to save, and what saving it said.
    to_save: Option<(String, String)>,
    pub(crate) note: Option<String>,
    table: TableState,
    help: Option<HelpView>,
    pub(crate) settings: Option<SettingsDialog>,
    pub(crate) clear: Option<ClearDialog>,
}

/// The fields of `ip.dns.log.set`, as typed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SettingsForm {
    pub enabled: bool,
    pub acknowledged: bool,
    pub client_address: String,
    pub ipv4_prefix: String,
    pub ipv6_prefix: String,
    pub salt_rotation_hours: String,
    pub max_size_mib: String,
    pub max_age_hours: String,
    pub exclude: String,
    pub only_from: String,
    pub except_from: String,
}

fn joined(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

fn list(s: &str) -> Vec<String> {
    s.split([',', '\n']).map(str::trim).filter(|x| !x.is_empty()).map(str::to_owned).collect()
}

impl SettingsForm {
    pub(crate) fn of(g: &Value) -> Self {
        Self {
            enabled: g.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            acknowledged: false,
            client_address: text(g, "client_address"),
            ipv4_prefix: text(g, "ipv4_prefix"),
            ipv6_prefix: text(g, "ipv6_prefix"),
            salt_rotation_hours: text(g, "salt_rotation_hours"),
            max_size_mib: text(g, "max_size_mib"),
            max_age_hours: text(g, "max_age_hours"),
            exclude: joined(g, "exclude"),
            only_from: joined(g, "only_from"),
            except_from: joined(g, "except_from"),
        }
    }

    /// The parameters of what changed from `base` (`None`: nothing).
    pub(crate) fn params(&self, base: &Self) -> Option<Value> {
        let mut p = Map::new();
        if self.enabled != base.enabled {
            p.insert("enabled".into(), json!(self.enabled));
            if self.enabled && self.acknowledged {
                p.insert("acknowledge".into(), json!("marco-civil-art14"));
            }
        }
        if self.client_address != base.client_address {
            p.insert("client_address".into(), json!(self.client_address));
        }
        for (k, v, b) in [
            ("ipv4_prefix", &self.ipv4_prefix, &base.ipv4_prefix),
            ("ipv6_prefix", &self.ipv6_prefix, &base.ipv6_prefix),
            ("salt_rotation_hours", &self.salt_rotation_hours, &base.salt_rotation_hours),
            ("max_size_mib", &self.max_size_mib, &base.max_size_mib),
            ("max_age_hours", &self.max_age_hours, &base.max_age_hours),
        ] {
            if v.trim() != b.trim() {
                // A number when it is one; the engine says what is wrong
                // otherwise.
                let val = v.trim().parse::<u64>().map_or_else(|_| json!(v.trim()), |n| json!(n));
                p.insert(k.into(), val);
            }
        }
        for (k, v, b) in [
            ("exclude", &self.exclude, &base.exclude),
            ("only_from", &self.only_from, &base.only_from),
            ("except_from", &self.except_from, &base.except_from),
        ] {
            if list(v) != list(b) {
                p.insert(k.into(), json!(list(v)));
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

pub(crate) struct SettingsDialog {
    pub form: SettingsForm,
    pub base: SettingsForm,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ClearWhat {
    #[default]
    Client,
    Before,
    All,
}

#[derive(Default)]
pub(crate) struct ClearDialog {
    pub what: ClearWhat,
    pub client: String,
    pub hours: String,
    pub status: Status,
    pub done: Option<String>,
}

enum Reply {
    Page { cursor: Option<String> },
    Settings,
    Export(String),
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearButton {}

impl PanelState for QueryLogPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(GET) {
            return Vec::new();
        }
        let mut out = vec![Query { key: "get", command: GET, params: Value::Null }];
        let n = self.tick.get();
        self.tick.set(n.wrapping_add(1));
        let live = self.cursor.is_none() && n.is_multiple_of(LIVE_EVERY);
        if app.has_command(PRINT) && (self.page.is_none() || self.fetch.get() || live) {
            self.fetch.set(false);
            out.push(Query { key: "print", command: PRINT, params: self.params(self.cursor.clone(), PAGE) });
        }
        out
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "get" if value.is_object() => self.get = Some(value),
            "print" if value.is_object() => {
                self.page = Some(value);
                self.error = None;
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _: &'static str, ui: &mut Ui) {
        if let Some((name, t)) = self.to_save.take() {
            self.note = Some(match export::save(ui.ctx(), &name, Export::Text(t)) {
                Ok(m) | Err(m) => m,
            });
        }
        self.draw(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        self.settings_dialog(app, ctx, area);
        self.clear_dialog(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else { return };
        match *r {
            Reply::Page { cursor } => match result {
                Ok(v) => {
                    self.page = Some(v.clone());
                    self.cursor = cursor;
                    self.error = None;
                }
                Err(e) => self.error = Some(e.clone()),
            },
            Reply::Settings => {
                if let Some(d) = &mut self.settings
                    && d.status.replied(result)
                {
                    self.settings = None;
                }
                self.fetch.set(true);
            }
            Reply::Export(name) => match result {
                Ok(v) => {
                    self.to_save = Some((name, text(v, "text")));
                }
                Err(e) => self.note = Some(e.clone()),
            },
            Reply::Clear => {
                if let Some(d) = &mut self.clear {
                    d.status.replied(result);
                    if let Ok(v) = result {
                        d.done = Some(format!(
                            "{} {} · {}",
                            v.get("queries").and_then(Value::as_u64).unwrap_or(0),
                            tr_in(SCOPE, app.lang.labels, "queries deleted"),
                            bytes(v.get("bytes").and_then(Value::as_u64).unwrap_or(0))
                        ));
                    }
                }
                self.fetch.set(true);
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _: &'static str) -> bool {
        self.table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table)]
    }
}

fn info(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, text: &'static str) {
    if help::info_button(ui, ui.scope_id().with(("dns-query-log-help", key, text)), tr_in(SCOPE, l, text)).clicked() {
        *help = Some(HelpView::new(key, tr_in(SCOPE, l, text)));
    }
}

/// A label with its ⓘ.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        info(ui, help, l, key, text);
    });
}

/// `1.2 GiB`, `340 MiB`, `12 KiB`.
pub(crate) fn bytes(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{:.1} GiB", b as f64 / f64::from(1u32 << 30)),
        b if b >= 1 << 20 => format!("{} MiB", b >> 20),
        b => format!("{} KiB", b.div_ceil(1024)),
    }
}

/// `2026-11-12 16:14:03.120`.
pub(crate) fn time(ms: u64) -> String {
    let s = crate::ntp_client::utc(ms / 1000);
    let s = s.strip_suffix(" UTC").unwrap_or(&s).to_owned();
    format!("{s}.{:03}", ms % 1000)
}

pub(crate) fn row(r: &Value, i: usize) -> Row {
    let rcode = text(r, "rcode");
    let rcode_kind = match rcode.as_str() {
        "noerror" => crate::chip::Kind::Green,
        "nxdomain" => crate::chip::Kind::Neutral,
        "dropped" | "refused" => crate::chip::Kind::Amber,
        _ => crate::chip::Kind::Red,
    };
    let rcode_label = if rcode == "dropped" { "dropped".to_owned() } else { rcode.to_uppercase() };
    let by = text(r, "answered_by");
    let mut name = text(r, "name");
    if let Some(e) = r.get("ede_name").and_then(Value::as_str) {
        name = format!("{name}  ({e})");
    }
    let latency = r.get("latency_ms").and_then(Value::as_f64).unwrap_or(0.0);
    Row {
        key: format!("{}-{i}", r.get("time").and_then(Value::as_u64).unwrap_or(0)),
        cells: vec![
            time(r.get("time").and_then(Value::as_u64).unwrap_or(0)),
            text(r, "client"),
            name,
            text(r, "type"),
            crate::chip::cell("", &[(rcode_label.as_str(), rcode_kind)]),
            crate::chip::cell("", &[(by.as_str(), crate::chip::Kind::Neutral)]),
            if latency < 0.1 { "<0.1".into() } else if latency < 10.0 { format!("{latency:.1}") } else { format!("{latency:.0}") },
        ],
        dimmed: rcode == "dropped",
        section: false,
        tint: None,
    }
}

impl QueryLogPanel {
    /// The filters as `ip.dns.log.print` / `export` take them.
    pub(crate) fn params(&self, cursor: Option<String>, limit: u32) -> Value {
        let mut p = Map::new();
        if let Some((_, secs)) = PERIODS.get(self.period)
            && *secs > 0
        {
            p.insert("last_secs".into(), json!(secs));
        }
        for (k, v) in [("client", &self.client), ("name", &self.name), ("type", &self.qtype)] {
            if !v.trim().is_empty() {
                p.insert(k.into(), json!(v.trim()));
            }
        }
        if let Some(r) = self.rcode {
            p.insert("rcode".into(), json!(r));
        }
        if let Some(b) = self.by {
            p.insert("answered_by".into(), json!(b));
        }
        p.insert("limit".into(), json!(limit));
        if let Some(c) = cursor {
            p.insert("cursor".into(), json!(c));
        }
        Value::Object(p)
    }

    fn find(&mut self, app: &mut CoreRouterUi) {
        self.newer.clear();
        self.go(app, None);
    }

    fn go(&mut self, app: &mut CoreRouterUi, cursor: Option<String>) {
        let p = self.params(cursor.clone(), PAGE);
        app.run_then(PRINT, p, crate::panel::then(NAME, Reply::Page { cursor }));
    }

    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let g = self.get.clone().unwrap_or(Value::Null);
        self.banner(app, ui, &g);
        ui.separator();
        let can = app.can();
        let mut find = false;
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut self.help, l, "dns_query_log.time", "Period");
            let shown = PERIODS.get(self.period).map_or("", |p| p.0);
            egui::ComboBox::from_id_salt("dns-query-log-period")
                .selected_text(tr_in(SCOPE, l, shown))
                .show_ui(ui, |ui| {
                    for (i, (t, _)) in PERIODS.iter().enumerate() {
                        if ui.selectable_value(&mut self.period, i, tr_in(SCOPE, l, t)).changed() {
                            find = true;
                        }
                    }
                });
            for (key, help_key, title, value, hint, width) in [
                ("client", "dns_query_log.client", "Client", &mut self.client, "100.64.12.0/24", 150.0),
                ("name", "dns_query_log.name", "Name", &mut self.name, "*.example.com", 170.0),
                ("type", "dns_query_log.type", "Type", &mut self.qtype, "AAAA", 60.0),
            ] {
                label(ui, &mut self.help, l, help_key, title);
                let r = ui.add(TextEdit::singleline(value).id_salt(("dns-query-log", key)).hint_text(hint).desired_width(width));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    find = true;
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut self.help, l, "dns_query_log.rcode", "Rcode");
            for (v, t) in RCODES {
                if filter_chip(ui, t, self.rcode == Some(v)) {
                    self.rcode = if self.rcode == Some(v) { None } else { Some(v) };
                    find = true;
                }
            }
            ui.separator();
            label(ui, &mut self.help, l, "dns_query_log.answered_by", "Answered by");
            for v in ANSWERED {
                if filter_chip(ui, v, self.by == Some(v)) {
                    self.by = if self.by == Some(v) { None } else { Some(v) };
                    find = true;
                }
            }
        });
        let mut export_as = None;
        let mut open_settings = false;
        let mut open_clear = false;
        ui.horizontal(|ui| {
            if action(ui, tr_in(SCOPE, l, "Find"), can.check(PRINT)) {
                find = true;
            }
            for f in ["csv", "jsonl"] {
                let t = if f == "csv" { "Export CSV" } else { "Export JSON" };
                if action(ui, tr_in(SCOPE, l, t), can.check(EXPORT)) {
                    export_as = Some(f);
                }
            }
            info(ui, &mut self.help, l, "dns_query_log.export", "Export CSV");
            ui.separator();
            if action(ui, tr_in(SCOPE, l, "Settings…"), can.check(SET)) {
                open_settings = true;
            }
            if action(ui, tr_in(SCOPE, l, "Clear…"), can.check(CLEAR)) {
                open_clear = true;
            }
            info(ui, &mut self.help, l, "dns_query_log.clear", "Clear…");
        });
        if let Some(n) = &self.note {
            ui.weak(n.as_str());
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        if !can.check(PRINT).is_ok() {
            ui.weak(tr_in(SCOPE, l, "No daemon: the query log is written by the router daemon (run it with --config-dir)."));
        }
        let page = self.page.clone().unwrap_or(Value::Null);
        let rows: Vec<Row> = page
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| a.iter().enumerate().map(|(i, r)| row(r, i)).collect())
            .unwrap_or_default();
        let shown = rows.len();
        let out = table::show(ui, TABLE, 28.0, &mut self.table, &COLUMNS, &rows, |ui, menu: Menu<'_>| {
            let _ = (ui, menu);
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        let next = page.get("next").and_then(Value::as_str).map(str::to_owned);
        let mut go: Option<Option<String>> = None;
        ui.horizontal(|ui| {
            let scanned = page.get("scanned").and_then(Value::as_u64).unwrap_or(0);
            ui.label(format!("{shown} {} · {scanned} {}", tr_in(SCOPE, l, "rows"), tr_in(SCOPE, l, "looked at")));
            if page.get("partial").and_then(Value::as_bool) == Some(true) {
                chip(ui, tr_in(SCOPE, l, "partial: Older goes on"), AMBER.tone(ui.visuals()));
            }
            if self.cursor.is_none() {
                ui.weak(tr_in(SCOPE, l, "newest first, refreshed every 5 s"));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(next.is_some(), egui::Button::new(tr_in(SCOPE, l, "Older"))).clicked() {
                    self.newer.push(self.cursor.clone());
                    go = Some(next.clone());
                }
                if ui.add_enabled(!self.newer.is_empty(), egui::Button::new(tr_in(SCOPE, l, "Newer"))).clicked() {
                    go = Some(self.newer.pop().flatten());
                }
            });
        });
        if find {
            self.find(app);
        } else if let Some(c) = go {
            self.go(app, c);
        }
        if let Some(f) = export_as {
            let name = format!("dns-query-log.{f}");
            let mut p = self.params(None, EXPORT_ROWS);
            if let Some(o) = p.as_object_mut() {
                o.insert("format".into(), json!(f));
            }
            self.note = Some(tr_in(SCOPE, l, "Exporting…").to_owned());
            app.run_then(EXPORT, p, crate::panel::then(NAME, Reply::Export(name)));
        }
        if open_settings && self.settings.is_none() {
            let form = SettingsForm::of(&g);
            self.settings = Some(SettingsDialog { form: form.clone(), base: form, status: Status::default() });
        }
        if open_clear && self.clear.is_none() {
            self.clear = Some(ClearDialog { hours: "24".into(), client: self.client.clone(), ..ClearDialog::default() });
        }
    }

    /// The state of the log and the law, on top.
    fn banner(&mut self, app: &CoreRouterUi, ui: &mut Ui, g: &Value) {
        let l = app.lang.labels;
        let on = g.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        ui.horizontal_wrapped(|ui| {
            let v = ui.visuals().clone();
            if g.is_null() {
                chip(ui, tr_in(SCOPE, l, "no data"), neutral_tone(&v));
            } else if on {
                let writing = g.get("writer").and_then(|w| w.get("writing")).and_then(Value::as_bool).unwrap_or(false);
                let tone = if writing { AMBER.tone(&v) } else { RED.tone(&v) };
                chip(ui, tr_in(SCOPE, l, if writing { "logging" } else { "on, not writing" }), tone);
            } else {
                chip(ui, tr_in(SCOPE, l, "off"), GREEN.tone(&v));
            }
            let mode = text(g, "client_address");
            if !mode.is_empty() {
                let shown = match mode.as_str() {
                    "truncated" => format!("{} /{} · /{}", tr_in(SCOPE, l, "clients truncated"), text(g, "ipv4_prefix"), text(g, "ipv6_prefix")),
                    "hashed" => format!("{} ({} h)", tr_in(SCOPE, l, "clients hashed"), text(g, "salt_rotation_hours")),
                    "none" => tr_in(SCOPE, l, "no clients").to_owned(),
                    _ => tr_in(SCOPE, l, "whole client addresses").to_owned(),
                };
                ui.label(shown);
            }
            if let Some(w) = g.get("writer").filter(|w| w.is_object()) {
                let used = w.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                let cap = w.get("budget_bytes").and_then(Value::as_u64).unwrap_or(0);
                ui.label(format!("· {} / {}", bytes(used), bytes(cap)));
                if let Some(o) = w.get("oldest").and_then(Value::as_u64) {
                    ui.label(format!("· {} {}", tr_in(SCOPE, l, "since"), time(o)));
                }
                let dropped = w.get("dropped_queue").and_then(Value::as_u64).unwrap_or(0)
                    + w.get("dropped_disk").and_then(Value::as_u64).unwrap_or(0);
                if dropped > 0 {
                    chip(ui, &format!("{dropped} {}", tr_in(SCOPE, l, "not written")), AMBER.tone(&v));
                }
            }
            ui.label("·");
            ui.label(RichText::new(tr_in(SCOPE, l, "Marco Civil art. 14 · LGPD")).strong());
            info(ui, &mut self.help, l, "dns_query_log.law", "Marco Civil art. 14 · LGPD");
            info(ui, &mut self.help, l, "dns_query_log.window", "DNS Query Log");
        });
        if let Some(ws) = g.get("warnings").and_then(Value::as_array) {
            for w in ws {
                if text(w, "key") == "law" {
                    continue;
                }
                let color = if text(w, "severity") == "error" { ui.visuals().error_fg_color } else { ui.visuals().warn_fg_color };
                ui.colored_label(color, text(w, "text"));
            }
        }
    }

    fn settings_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.settings.take() else { return };
        let l = app.lang.labels;
        let g = self.get.clone().unwrap_or(Value::Null);
        let can = app.can();
        let help = &mut self.help;
        let id = Id::unique("dns-query-log-settings");
        let head = Head {
            id,
            title: tr_in(SCOPE, l, "DNS Query Log Settings"),
            dirty: d.form.params(&d.base).is_some(),
            pos: area.center() - egui::vec2(240.0, 260.0),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let turning_on = d.form.enabled && !d.base.enabled;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            let form = &mut d.form;
            ui.horizontal(|ui| {
                ui.checkbox(&mut form.enabled, tr_in(SCOPE, l, "Enabled"));
                info(ui, help, l, "dns_query_log.enabled", "Enabled");
            });
            if turning_on {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.colored_label(ui.visuals().warn_fg_color, tr_in(SCOPE, l, "A log of which client asked which name and when is, at a connection provider, the application access record Marco Civil art. 14 forbids keeping, and personal data under the LGPD."));
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut form.acknowledged, tr_in(SCOPE, l, "I read this and turn it on anyway"));
                        info(ui, help, l, "dns_query_log.law", "Marco Civil art. 14 · LGPD");
                    });
                });
            }
            Grid::new("dns-query-log-settings-grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                label(ui, help, l, "dns_query_log.client_address", "Client Address");
                let shown = CLIENT_ADDRESS.iter().find(|c| c.0 == form.client_address).map_or("", |c| c.1);
                egui::ComboBox::from_id_salt("dns-query-log-client-address")
                    .selected_text(tr_in(SCOPE, l, shown))
                    .show_ui(ui, |ui| {
                        for (v, t) in CLIENT_ADDRESS {
                            ui.selectable_value(&mut form.client_address, v.to_owned(), tr_in(SCOPE, l, t));
                        }
                    });
                ui.end_row();
                for (key, help_key, title, value, hint) in [
                    ("ipv4_prefix", "dns_query_log.prefixes", "IPv4 Prefix", &mut form.ipv4_prefix, "24"),
                    ("ipv6_prefix", "dns_query_log.prefixes", "IPv6 Prefix", &mut form.ipv6_prefix, "56"),
                    ("salt_rotation_hours", "dns_query_log.salt_rotation", "Salt Rotation (h)", &mut form.salt_rotation_hours, "24"),
                    ("max_size_mib", "dns_query_log.max_size", "Max Size (MiB)", &mut form.max_size_mib, "1024"),
                    ("max_age_hours", "dns_query_log.max_age", "Max Age (h)", &mut form.max_age_hours, "24"),
                    ("exclude", "dns_query_log.exclude", "Exclude", &mut form.exclude, "example.com, arpa"),
                    ("only_from", "dns_query_log.only_from", "Only From", &mut form.only_from, "100.64.0.0/10"),
                    ("except_from", "dns_query_log.except_from", "Except From", &mut form.except_from, "10.0.0.0/8"),
                ] {
                    label(ui, help, l, help_key, title);
                    f.field(ui, key, value, hint);
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(tr_in(SCOPE, l, "Estimate"));
                info(ui, help, l, "dns_query_log.estimate", "Estimate");
            });
            let e = g.get("estimate").cloned().unwrap_or(Value::Null);
            match e.get("queries_per_sec").and_then(Value::as_f64) {
                Some(qps) => {
                    let num = |k: &str| e.get(k).and_then(Value::as_f64).unwrap_or(0.0);
                    ui.label(format!(
                        "{qps:.0} {} × {:.1} B = {:.1} GB/{}",
                        tr_in(SCOPE, l, "queries/s"),
                        num("bytes_per_query"),
                        num("gb_per_day"),
                        tr_in(SCOPE, l, "day")
                    ));
                    let limited = if text(&e, "limited_by") == "size" { tr_in(SCOPE, l, "by the size") } else { tr_in(SCOPE, l, "by the age") };
                    ui.label(format!(
                        "{} {:.1} h ({limited}) · {} {:.1} {}",
                        tr_in(SCOPE, l, "keeps"),
                        num("retention_hours"),
                        tr_in(SCOPE, l, "disk wear"),
                        num("wear_tb_per_year"),
                        tr_in(SCOPE, l, "TB a year")
                    ));
                }
                None => {
                    ui.weak(tr_in(SCOPE, l, "No query rate yet (the forwarder answers nothing or there is no daemon)."));
                }
            }
            if let Some(p) = form.params(&d.base) {
                ui.separator();
                ui.weak(format!("{SET} {p}"));
            }
            let ok = if turning_on && !form.acknowledged {
                Err(tr_in(SCOPE, l, "Tick the box above to turn the log on").to_owned())
            } else {
                can.check(SET)
            };
            Footer::<ClearButton>::edit(true, ok)
        });
        let keep = match pressed {
            None => true,
            Some(Press::Cancel) => false,
            Some(b) => match d.form.params(&d.base) {
                Some(p) => {
                    d.status.close_on_success = b == Press::Ok;
                    d.status.sent();
                    let applied = d.form.clone();
                    app.run_then(SET, p, crate::panel::then(NAME, Reply::Settings));
                    d.base = SettingsForm { acknowledged: false, ..applied };
                    true
                }
                None => b != Press::Ok,
            },
        };
        if keep {
            self.settings = Some(d);
        } else {
            app.floats.forget(id);
        }
    }

    fn clear_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.clear.take() else { return };
        let l = app.lang.labels;
        let can = app.can();
        let help = &mut self.help;
        let id = Id::unique("dns-query-log-clear");
        let head = Head {
            id,
            title: tr_in(SCOPE, l, "Clear DNS Query Log"),
            dirty: false,
            pos: area.center() - egui::vec2(200.0, 120.0),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, _| {
            ui.horizontal(|ui| {
                ui.label(tr_in(SCOPE, l, "Delete from the router's disk; this cannot be undone."));
                info(ui, help, l, "dns_query_log.clear", "Clear…");
            });
            ui.radio_value(&mut d.what, ClearWhat::Client, tr_in(SCOPE, l, "The queries of one client"));
            if d.what == ClearWhat::Client {
                ui.add(TextEdit::singleline(&mut d.client).hint_text("100.64.12.34 · h:…").desired_width(220.0));
            }
            ui.radio_value(&mut d.what, ClearWhat::Before, tr_in(SCOPE, l, "Queries older than (hours)"));
            if d.what == ClearWhat::Before {
                ui.add(TextEdit::singleline(&mut d.hours).desired_width(80.0));
            }
            ui.radio_value(&mut d.what, ClearWhat::All, tr_in(SCOPE, l, "Everything"));
            if let Some(done) = &d.done {
                ui.colored_label(ui.visuals().widgets.active.fg_stroke.color, done.as_str());
            }
            Footer::<ClearButton>::edit(false, can.check(CLEAR))
        });
        let keep = match pressed {
            None => true,
            Some(Press::Cancel) => false,
            Some(_) => {
                let p = match d.what {
                    ClearWhat::All => json!({"all": true}),
                    ClearWhat::Client => json!({"client": d.client.trim()}),
                    ClearWhat::Before => {
                        let hours: u64 = d.hours.trim().parse().unwrap_or(24);
                        json!({"older_than_secs": hours.saturating_mul(3600).min(u64::from(u32::MAX))})
                    }
                };
                d.status.sent();
                d.done = None;
                app.run_then(CLEAR, p, crate::panel::then(NAME, Reply::Clear));
                true
            }
        };
        if keep {
            self.clear = Some(d);
        } else {
            app.floats.forget(id);
        }
    }
}

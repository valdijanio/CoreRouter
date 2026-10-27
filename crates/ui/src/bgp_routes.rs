//! Routing › BGP › Routes (G3.2c, G3.3): the routes one connection received
//! and advertised, a page at a time like IP › Routes, searched by prefix,
//! AS path, community and RPKI state, with the RPKI badge of each route
//! and the share of each state; the flap history of the sessions; and the
//! "Why this route?" modal (`routing.bgp.route.explain`), which IP › Routes
//! and the BGP session detail open too; and the session detail's RPKI
//! share and links (the approved mockup). A panel without a window of its
//! own: `bgp.rs` draws it in its Routes tab. `routing.bgp.route.*`
//! decides; this only shows.

use egui::{Id, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::panel::{Panel, PanelState, Query};
use crate::table::{self, Row, TableState, col, num};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "bgp-routes";
const SCOPE: &str = "bgp_routes";
const TABLE: &str = "bgp-routes-table";
const HISTORY: &str = "bgp-history-table";
const EXPLAIN: &str = "bgp-explain-table";
/// Rows per page (the engine allows 5 000).
pub(crate) const PAGE: usize = 500;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::<RoutesPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Received,
    Advertised,
    History,
}

const TABS: [(Tab, &str, &str); 3] = [
    (Tab::Received, "Received", "bgp_routes.tab.received"),
    (Tab::Advertised, "Advertised", "bgp_routes.tab.advertised"),
    (Tab::History, "History", "bgp_routes.tab.history"),
];

const COLUMNS: [table::Column; 10] = [
    col("Prefix").help("bgp_routes.prefix"),
    col("RPKI").help("bgp_routes.rpki"),
    col("Status").help("bgp_routes.status"),
    col("Origin AS").help("bgp_routes.origin_as"),
    col("AS Path").help("bgp_routes.as_path"),
    col("Next Hop").help("bgp_routes.next_hop"),
    num("Local Pref").help("bgp_routes.local_pref"),
    num("MED").help("bgp_routes.med"),
    col("Origin").help("bgp_routes.origin"),
    col("Communities").help("bgp_routes.communities"),
];

const HISTORY_COLUMNS: [table::Column; 5] = [
    col("Time").help("bgp_routes.history.time"),
    col("Connection").help("bgp_routes.history.connection"),
    col("Event").help("bgp_routes.history.event"),
    num("Was Up").help("bgp_routes.history.uptime"),
    col("Reason").help("bgp_routes.history.reason"),
];

const EXPLAIN_COLUMNS: [table::Column; 11] = [
    col("Path").help("bgp_routes.explain.path"),
    col("Lost At").help("bgp_routes.explain.lost_at"),
    num("Weight").help("bgp_routes.step.weight"),
    num("Local Pref").help("bgp_routes.step.local-pref"),
    col("AS Path").help("bgp_routes.step.as-path-length"),
    col("Origin").help("bgp_routes.step.origin"),
    num("MED").help("bgp_routes.step.med"),
    col("Peer").help("bgp_routes.step.peer-type"),
    num("IGP").help("bgp_routes.step.igp-metric"),
    col("Router ID").help("bgp_routes.step.router-id"),
    col("RPKI").help("bgp_routes.rpki"),
];

/// The search as typed, and as last sent.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Search {
    pub prefix: String,
    pub as_path: String,
    pub community: String,
    pub rpki: String,
    pub filtered: bool,
}

/// An open "Why this route?".
pub(crate) struct Explain {
    pub prefix: String,
    /// The field, while typed (the prefix asked is `prefix`).
    pub typed: String,
    pub answer: Option<Value>,
    table: TableState,
}

impl Explain {
    pub(crate) fn new(prefix: &str) -> Self {
        Explain {
            prefix: prefix.trim().to_owned(),
            typed: prefix.trim().to_owned(),
            answer: None,
            table: TableState::default(),
        }
    }

    fn ready(&self) -> bool {
        self.answer.as_ref().is_some_and(|a| a.get("state").and_then(Value::as_str) == Some("ready"))
    }
}

#[derive(Default)]
pub(crate) struct RoutesPanel {
    pub(crate) tab: Tab,
    pub(crate) connection: String,
    pub(crate) connections: Vec<String>,
    pub(crate) typed: Search,
    pub(crate) sent: Search,
    pub(crate) offset: usize,
    pub(crate) answer: Option<Value>,
    pub(crate) history: Vec<Value>,
    table: TableState,
    history_table: TableState,
    pub(crate) explain: Option<Explain>,
    help: Option<HelpView>,
    /// `routing.backend.get`: whether a routing daemon is attached.
    pub(crate) attached: Option<bool>,
    /// The BGP window shows this panel's tab now.
    pub(crate) active: bool,
    /// `routing.bgp.route.summary`: the RPKI share of each table read.
    pub(crate) summary: Vec<Value>,
    /// Connections whose table the session detail asked to read.
    pub(crate) wanted: Vec<String>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn u(r: &Value, k: &str) -> Option<u64> {
    r.get(k).and_then(Value::as_u64)
}

fn dash(v: Option<u64>) -> String {
    v.map_or_else(|| "–".to_owned(), |n| n.to_string())
}

/// The badge of an RPKI state (RFC 6811, RouterOS names).
pub(crate) fn rpki_kind(state: &str) -> Kind {
    match state {
        "valid" => Kind::Green,
        "invalid" => Kind::Red,
        "unknown" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

fn as_chip(asn: Option<u64>) -> String {
    match asn {
        Some(a) => cell("", &[(&format!("AS{a}"), Kind::Hashed(chip::hashed(a)))]),
        None => "–".into(),
    }
}

fn route_row(i: usize, r: &Value) -> Row {
    let status = if r.get("filtered").and_then(Value::as_bool) == Some(true) {
        cell("", &[("filtered", Kind::Red)])
    } else if r.get("best").and_then(Value::as_bool) == Some(true) {
        cell("", &[("best", Kind::Green)])
    } else {
        String::new()
    };
    let rpki = s(r, "rpki");
    let communities: Vec<String> = ["communities", "large_communities"]
        .iter()
        .filter_map(|k| r.get(*k).and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Row {
        key: format!("{i}:{}", s(r, "prefix")),
        cells: vec![
            s(r, "prefix"),
            cell("", &[(rpki.as_str(), rpki_kind(&rpki))]),
            status,
            as_chip(u(r, "origin_as")),
            s(r, "as_path"),
            s(r, "next_hop"),
            dash(u(r, "local_pref")),
            dash(u(r, "med")),
            s(r, "origin"),
            communities.join(" "),
        ],
        dimmed: r.get("filtered").and_then(Value::as_bool) == Some(true),
        section: false,
        tint: None,
    }
}

fn history_row(i: usize, r: &Value, l: crate::i18n::Lang, now: u64) -> Row {
    let (event, kind) = match s(r, "event").as_str() {
        "up" => ("up", Kind::Green),
        "down" => ("down", Kind::Red),
        _ => ("flap", Kind::Amber),
    };
    let at = u(r, "at").map_or_else(|| "–".into(), |t| crate::system_log::short_time(t, now / 86_400));
    Row {
        key: format!("{i}"),
        cells: vec![
            at,
            {
                let c = s(r, "connection");
                if c.is_empty() { s(r, "remote_address") } else { c }
            },
            cell("", &[(tr_in(SCOPE, l, event), kind)]),
            u(r, "uptime_secs").map_or_else(|| "–".into(), crate::neighbors::uptime_text),
            s(r, "reason"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// Open "Why this route?" for `prefix` (IP › Routes and the BGP session
/// detail call this).
pub(crate) fn open_explain(app: &mut CoreRouterUi, prefix: &str) {
    if let Some(p) = app.panel_mut::<RoutesPanel>() {
        p.explain = Some(Explain::new(prefix));
    }
    app.cache.refreshed_at = None;
}

/// Show `connection`'s routes in the BGP window's Routes tab (the caller
/// inside `bgp.rs` switches the tab itself).
pub(crate) fn open_routes(app: &mut CoreRouterUi, connection: &str, tab: Tab) {
    if let Some(p) = app.panel_mut::<RoutesPanel>() {
        if p.connection != connection {
            p.answer = None;
            p.offset = 0;
        }
        p.connection = connection.to_owned();
        p.tab = tab;
    }
    if let Some(b) = app.panel_mut::<crate::bgp::BgpPanel>() {
        b.tab = crate::bgp::Tab::Routes;
    }
    if !app.open.insert(Win::Bgp) {
        app.floats.raise(crate::win_id(Win::Bgp));
    }
    app.cache.refreshed_at = None;
}

/// Which of the BGP window's G3.2c tabs is shown (their queries go out
/// only then).
pub(crate) fn show_tabs(app: &mut CoreRouterUi, rpki: bool, routes: bool) {
    let mut changed = false;
    if let Some(p) = app.panel_mut::<RoutesPanel>() {
        changed |= p.active != routes;
        p.active = routes;
    }
    if let Some(p) = app.panel_mut::<crate::rpki::RpkiPanel>() {
        changed |= p.active != rpki;
        p.active = rpki;
    }
    // A tab just shown asks at once, not at the next refresh.
    if changed {
        app.cache.refreshed_at = None;
    }
}

/// Draw panel `name` inside the BGP window.
pub(crate) fn draw(app: &mut CoreRouterUi, name: &'static str, ui: &mut Ui) {
    app.with_panel(name, |p, app| p.window(app, "bgp", ui));
}

/// The session detail's "RPKI In": three badges with the share of each
/// state among the routes it sent, once its table was read; else a link
/// that reads it.
pub(crate) fn session_rpki(app: &mut CoreRouterUi, ui: &mut Ui, connection: &str) {
    let l = app.lang.labels;
    let Some(p) = app.panel_mut::<RoutesPanel>() else { return };
    let row = p
        .summary
        .iter()
        .find(|r| s(r, "connection") == connection && s(r, "direction") == "received")
        .cloned();
    let v = ui.visuals().clone();
    match row {
        Some(r) if s(&r, "state") == "ready" => {
            let n = r.get("rpki").cloned().unwrap_or_default();
            let parts = [("valid", chip::GREEN.tone(&v)), ("unknown", chip::AMBER.tone(&v)), ("invalid", chip::RED.tone(&v))];
            let total: u64 = ["valid", "unknown", "invalid", "unverified"].iter().map(|k| u(&n, k).unwrap_or(0)).sum();
            if u(&n, "unverified").unwrap_or(0) == total && total > 0 {
                chip::chip(ui, tr_in(SCOPE, l, "unverified"), chip::neutral_tone(&v))
                    .on_hover_text(tr_in(SCOPE, l, "No validator in sync when the routes were read."));
                return;
            }
            for (k, tone) in parts {
                let c = u(&n, k).unwrap_or(0);
                let pct = c as f64 * 100.0 / total.max(1) as f64;
                chip::chip(ui, &format!("{} {pct:.0}%", tr_in(SCOPE, l, k)), tone).on_hover_text(format!("{c} {}", tr_in(SCOPE, l, "routes")));
            }
        }
        Some(r) if s(&r, "state") == "loading" => {
            ui.spinner();
        }
        _ => {
            let reading = p.wanted.iter().any(|w| w == connection);
            if !reading && ui.link(tr_in(SCOPE, l, "read the routes")).on_hover_text(tr_in(SCOPE, l, "Read this neighbor's routes from the routing daemon (a full table takes a few seconds)")).clicked() {
                p.wanted.push(connection.to_owned());
                app.cache.refreshed_at = None;
            }
        }
    }
}

/// The session detail's links: received · advertised · history · why this
/// route?. Returns the Routes tab to show, if one was clicked.
pub(crate) fn session_links(app: &mut CoreRouterUi, ui: &mut Ui, _connection: &str) -> Option<Tab> {
    let l = app.lang.labels;
    let mut go = None;
    ui.horizontal(|ui| {
        for (i, (label, tab)) in [("received routes", Tab::Received), ("advertised", Tab::Advertised), ("history", Tab::History)].into_iter().enumerate() {
            if i > 0 {
                ui.weak("·");
            }
            if ui.link(tr_in(SCOPE, l, label)).clicked() {
                go = Some(tab);
            }
        }
    });
    if ui.link(tr_in(SCOPE, l, "why this route?")).clicked() {
        open_explain(app, "");
    }
    go
}

impl RoutesPanel {
    fn params(&self, refresh: bool) -> Value {
        let mut p = json!({
            "connection": self.connection,
            "direction": if self.tab == Tab::Advertised { "advertised" } else { "received" },
            "offset": self.offset,
            "limit": PAGE,
        });
        if let Some(o) = p.as_object_mut() {
            let q = &self.sent;
            for (k, v) in [("prefix", &q.prefix), ("as_path", &q.as_path), ("community", &q.community), ("rpki", &q.rpki)] {
                if !v.trim().is_empty() {
                    o.insert(k.into(), json!(v.trim()));
                }
            }
            if q.filtered {
                o.insert("filtered".into(), json!(true));
            }
            if refresh {
                o.insert("refresh".into(), json!(true));
            }
        }
        p
    }

    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("bgp-routes-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn header(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Connection"));
            let before = self.connection.clone();
            egui::ComboBox::from_id_salt("bgp-routes-connection")
                .selected_text(if self.connection.is_empty() { tr_in(SCOPE, l, "choose…").to_owned() } else { self.connection.clone() })
                .show_ui(ui, |ui| {
                    for c in &self.connections {
                        ui.selectable_value(&mut self.connection, c.clone(), c);
                    }
                });
            if self.connection != before {
                self.answer = None;
                self.offset = 0;
                app.cache.refreshed_at = None;
            }
            ui.separator();
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() && self.tab != tab {
                    self.tab = tab;
                    self.answer = None;
                    self.offset = 0;
                    app.cache.refreshed_at = None;
                }
                self.info(ui, l, key, label);
                ui.add_space(4.0);
            }
            ui.separator();
            let can = if self.connection.is_empty() { Err("choose a connection".to_owned()) } else { app.can().check("routing.bgp.route.list") };
            if self.tab != Tab::History && table::action(ui, tr_in(SCOPE, l, "Read Again"), can) {
                app.run("routing.bgp.route.list", self.params(true));
                self.answer = None;
            }
            if let Some(a) = &self.answer {
                let age = u(a, "age_secs");
                let ms = u(a, "load_ms");
                if let (Some(age), Some(ms)) = (age, ms) {
                    ui.weak(format!("{} {age} s · {ms} ms", tr_in(SCOPE, l, "read")));
                }
            }
        });
    }

    fn search(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let mut go = false;
        ui.horizontal(|ui| {
            let field = |ui: &mut Ui, text: &mut String, hint: &str, w: f32| {
                let r = ui.add(TextEdit::singleline(text).hint_text(hint).desired_width(w));
                r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
            };
            go |= field(ui, &mut self.typed.prefix, tr_in(SCOPE, l, "prefix or address"), 150.0);
            go |= field(ui, &mut self.typed.as_path, "^64500 … 13335$", 130.0);
            go |= field(ui, &mut self.typed.community, "65000:100", 100.0);
            self.info(ui, l, "bgp_routes.search", "Search");
            for state in ["valid", "invalid", "unknown"] {
                let on = self.typed.rpki == state;
                if ui.selectable_label(on, tr_in(SCOPE, l, state)).clicked() {
                    self.typed.rpki = if on { String::new() } else { state.to_owned() };
                    go = true;
                }
            }
            if self.tab == Tab::Received && ui.checkbox(&mut self.typed.filtered, tr_in(SCOPE, l, "filtered only")).changed() {
                go = true;
            }
            if ui.button(tr_in(SCOPE, l, "Search")).clicked() {
                go = true;
            }
        });
        if go && self.typed != self.sent {
            self.sent = self.typed.clone();
            self.offset = 0;
            app.cache.refreshed_at = None;
        }
    }

    /// Counts and the share of each RPKI state, as a bar.
    fn summary(&mut self, ui: &mut Ui, l: crate::i18n::Lang) {
        let Some(sm) = self.answer.as_ref().and_then(|a| a.get("summary")).filter(|v| v.is_object()).cloned() else {
            return;
        };
        let r = sm.get("rpki").cloned().unwrap_or_default();
        let parts = [
            ("valid", u(&r, "valid").unwrap_or(0)),
            ("invalid", u(&r, "invalid").unwrap_or(0)),
            ("unknown", u(&r, "unknown").unwrap_or(0)),
            ("unverified", u(&r, "unverified").unwrap_or(0)),
        ];
        let total = parts.iter().map(|p| p.1).sum::<u64>().max(1);
        ui.horizontal(|ui| {
            let v = ui.visuals().clone();
            chip::chip(ui, &format!("{} {}", u(&sm, "total").unwrap_or(0), tr_in(SCOPE, l, "routes")), chip::neutral_tone(&v));
            let filtered = u(&sm, "filtered").unwrap_or(0);
            if filtered > 0 {
                chip::chip(ui, &format!("{filtered} {}", tr_in(SCOPE, l, "filtered")), chip::RED.tone(&v));
            }
            ui.separator();
            for (state, n) in parts {
                if n == 0 && state == "unverified" {
                    continue;
                }
                let pct = n as f64 * 100.0 / total as f64;
                let tone = match state {
                    "valid" => chip::GREEN.tone(&v),
                    "invalid" => chip::RED.tone(&v),
                    "unknown" => chip::AMBER.tone(&v),
                    _ => chip::neutral_tone(&v),
                };
                chip::chip(ui, &format!("{} {pct:.1}%", tr_in(SCOPE, l, state)), tone)
                    .on_hover_text(format!("{n} {}", tr_in(SCOPE, l, "routes")));
            }
            // The bar: one rectangle per state, as wide as its share.
            let (rect, _) = ui.allocate_exact_size(egui::vec2(180.0, 10.0), egui::Sense::hover());
            let mut x = rect.left();
            for (state, n) in parts {
                let w = rect.width() * n as f32 / total as f32;
                let fill = match state {
                    "valid" => chip::GREEN.tone(&v).fill,
                    "invalid" => chip::RED.tone(&v).fill,
                    "unknown" => chip::AMBER.tone(&v).fill,
                    _ => chip::neutral_tone(&v).fill,
                };
                ui.painter()
                    .rect_filled(egui::Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(w, rect.height())), 2.0, fill);
                x += w;
            }
            self.info(ui, l, "bgp_routes.rpki_share", "RPKI");
        });
    }

    fn pager(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, total: usize) {
        if total <= PAGE && self.offset == 0 {
            return;
        }
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            let last = (self.offset + PAGE).min(total);
            ui.weak(format!("{}–{last} {} {total}", self.offset + 1, tr_in(SCOPE, l, "of")));
            let mut to = None;
            if ui.add_enabled(self.offset > 0, egui::Button::new("<")).clicked() {
                to = Some(self.offset.saturating_sub(PAGE));
            }
            if ui.add_enabled(last < total, egui::Button::new(">")).clicked() {
                to = Some(last);
            }
            if let Some(o) = to {
                self.offset = o;
                app.cache.refreshed_at = None;
            }
        });
    }

    fn routes_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        self.search(app, ui);
        self.summary(ui, l);
        ui.separator();
        if self.connection.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Choose a BGP connection to see its routes."));
            return;
        }
        if self.attached == Some(false) {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                tr_in(SCOPE, l, "No routing daemon is attached (the virtual lab, or the daemon runs without --frr): BGP routes are read from FRR."),
            );
            return;
        }
        let answer = self.answer.clone().unwrap_or(Value::Null);
        match answer.get("state").and_then(Value::as_str) {
            Some("ready") => {}
            Some("failed") => {
                ui.colored_label(ui.visuals().error_fg_color, s(&answer, "error"));
                return;
            }
            _ => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak(tr_in(SCOPE, l, "Reading the routes from the routing daemon… a full table takes a few seconds."));
                });
                return;
            }
        }
        if answer.get("pre_policy").and_then(Value::as_bool) == Some(false) && self.tab == Tab::Received {
            ui.weak(tr_in(SCOPE, l, "Accepted routes only: this neighbor keeps no Adj-RIB-In (no RPKI drop on it), so refused routes are not known."));
        }
        for w in answer.get("warnings").and_then(Value::as_array).into_iter().flatten() {
            ui.colored_label(ui.visuals().warn_fg_color, value_text(w));
        }
        let rows: Vec<Row> = answer
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| a.iter().enumerate().map(|(i, r)| route_row(self.offset + i, r)).collect())
            .unwrap_or_default();
        let total = usize::try_from(u(&answer, "total").unwrap_or(0)).unwrap_or(0);
        let footer = ui.spacing().interact_size.y * 2.0 + 8.0;
        let mut explain = None;
        let out = table::show(ui, TABLE, footer, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let table::Menu::Rows(sel) = menu
                && let Some(k) = sel.first()
                && ui.button(tr_in(SCOPE, l, "Why this route?")).clicked()
            {
                explain = k.split_once(':').map(|(_, p)| p.to_owned());
                ui.close();
            }
        });
        if let Some(k) = out.opened {
            explain = k.split_once(':').map(|(_, p)| p.to_owned());
        }
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if let Some(p) = explain {
            self.explain = Some(Explain::new(&p));
            app.cache.refreshed_at = None;
        }
        self.pager(app, ui, total);
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No route matches."));
        }
    }

    fn history_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let now = self.history.iter().filter_map(|r| u(r, "at")).max().unwrap_or(0);
        let rows: Vec<Row> = self.history.iter().enumerate().map(|(i, r)| history_row(i, r, l, now)).collect();
        let out = table::show(ui, HISTORY, 0.0, &mut self.history_table, &HISTORY_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = HISTORY_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No session went down since the daemon started."));
        }
    }

    fn explain_window(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(e) = self.explain.as_mut() else { return };
        let l = app.lang.labels;
        let mut open = true;
        let mut help = None;
        let mut again = false;
        egui::Window::new(format!("{} {}", tr_in(SCOPE, l, "Why this route?"), e.prefix).trim().to_owned())
            .id(Id::unique("bgp-explain"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([900.0, 360.0])
            .constrain_to(area)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if help::info_button(ui, Id::unique("bgp-explain-title"), tr_in(SCOPE, l, "Why this route?")).clicked() {
                        help = Some(("bgp_routes.explain", "Why this route?"));
                    }
                    let r = ui.add(TextEdit::singleline(&mut e.typed).hint_text(tr_in(SCOPE, l, "prefix or address")).desired_width(180.0));
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button(tr_in(SCOPE, l, "Explain")).clicked() || enter) && !e.typed.trim().is_empty() {
                        e.prefix = e.typed.trim().to_owned();
                        again = true;
                    }
                    if !e.prefix.is_empty() && ui.button(tr_in(SCOPE, l, "Ask Again")).clicked() {
                        again = true;
                    }
                });
                if e.prefix.is_empty() {
                    ui.weak(tr_in(SCOPE, l, "Type a prefix or an address: every BGP path to it and why the best one won."));
                    return;
                }
                let a = e.answer.clone().unwrap_or(Value::Null);
                match a.get("state").and_then(Value::as_str) {
                    Some("ready") => {}
                    Some("failed") => {
                        ui.colored_label(ui.visuals().error_fg_color, s(&a, "error"));
                        return;
                    }
                    _ => {
                        ui.spinner();
                        return;
                    }
                }
                let paths = a.get("paths").and_then(Value::as_array).cloned().unwrap_or_default();
                if paths.is_empty() {
                    ui.weak(tr_in(SCOPE, l, "BGP has no path to this prefix."));
                    return;
                }
                let best = paths.iter().find(|p| p.get("best").and_then(Value::as_bool) == Some(true));
                if let Some(b) = best {
                    let who = { let c = s(b, "connection"); if c.is_empty() { s(b, "peer") } else { c } };
                    let won = b.get("won_at").filter(|w| w.is_object());
                    let line = match won {
                        Some(w) => format!(
                            "{} {who}: {} ({} {} {})",
                            tr_in(SCOPE, l, "Chosen"),
                            tr_in(SCOPE, l, step_name(&s(w, "step"))),
                            s(w, "winner_value"),
                            tr_in(SCOPE, l, "against"),
                            s(w, "loser_value")
                        ),
                        None => format!("{} {who}", tr_in(SCOPE, l, "Chosen")),
                    };
                    ui.label(RichText::new(line).strong());
                }
                if a.get("agrees").and_then(Value::as_bool) == Some(false) {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        tr_in(SCOPE, l, "The daemon chose differently from this step-by-step comparison (an option such as deterministic-med or multipath decided)."),
                    );
                }
                let rows: Vec<Row> = paths.iter().map(|p| explain_row(p, l)).collect();
                let out = table::show(ui, EXPLAIN, 30.0, &mut e.table, &EXPLAIN_COLUMNS, &rows, |_, _| {});
                if let Some(key) = out.help {
                    let title = EXPLAIN_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
                    help = Some((key, title));
                }
                // A click on a "lost at" badge explains that step.
                if out.chip_clicked
                    && let Some((row, 1, _)) = out.chip.as_ref()
                    && let Some(step) = paths
                        .get(row.parse::<usize>().unwrap_or(usize::MAX))
                        .and_then(|p| p.get("lost_at"))
                        .map(|w| s(w, "step"))
                {
                    help = STEP_KEYS.iter().find(|(k, _)| *k == step).map(|(_, h)| (*h, "Lost At"));
                }
                // The order the steps are compared in.
                ui.horizontal_wrapped(|ui| {
                    ui.weak(tr_in(SCOPE, l, "Order:"));
                    let decided: Vec<String> = paths.iter().filter_map(|p| p.get("lost_at")).map(|w| s(w, "step")).collect();
                    let v = ui.visuals().clone();
                    for (k, h) in STEP_KEYS {
                        let tone = if decided.iter().any(|d| d == k) { chip::AMBER.tone(&v) } else { chip::neutral_tone(&v) };
                        if chip::chip(ui, tr_in(SCOPE, l, k), tone).clicked() {
                            help = Some((h, k));
                        }
                    }
                });
            });
        if let Some((key, title)) = help {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if again && let Some(e) = self.explain.as_mut() {
            e.answer = None;
            app.cache.refreshed_at = None;
        }
        if !open {
            self.explain = None;
        }
    }
}

/// Each step's key (as the engine names it) and its explanation.
const STEP_KEYS: [(&str, &str); 15] = [
    ("not-usable", "bgp_routes.step.not-usable"),
    ("weight", "bgp_routes.step.weight"),
    ("local-pref", "bgp_routes.step.local-pref"),
    ("local-route", "bgp_routes.step.local-route"),
    ("as-path-length", "bgp_routes.step.as-path-length"),
    ("origin", "bgp_routes.step.origin"),
    ("med", "bgp_routes.step.med"),
    ("peer-type", "bgp_routes.step.peer-type"),
    ("igp-metric", "bgp_routes.step.igp-metric"),
    ("confed-peer-type", "bgp_routes.step.confed-peer-type"),
    ("older-path", "bgp_routes.step.older-path"),
    ("router-id", "bgp_routes.step.router-id"),
    ("cluster-length", "bgp_routes.step.cluster-length"),
    ("stale", "bgp_routes.step.stale"),
    ("neighbor-address", "bgp_routes.step.neighbor-address"),
];

/// The step's name as a static text (the label catalog's key).
fn step_name(step: &str) -> &'static str {
    STEP_KEYS.iter().find(|(k, _)| *k == step).map_or("equal", |(k, _)| *k)
}

fn explain_row(p: &Value, l: crate::i18n::Lang) -> Row {
    let who = {
        let c = s(p, "connection");
        if c.is_empty() { s(p, "peer") } else { c }
    };
    let best = p.get("best").and_then(Value::as_bool) == Some(true);
    let path = if best { cell(&who, &[("best", Kind::Green)]) } else { who };
    let lost = match p.get("lost_at").filter(|w| w.is_object()) {
        Some(w) => {
            let step = s(w, "step");
            let k = if p.get("unexplained").and_then(Value::as_bool) == Some(true) { Kind::Red } else { Kind::Amber };
            let detail = format!("{} {} {}", s(w, "winner_value"), tr_in(SCOPE, l, "against"), s(w, "loser_value"));
            cell(detail.trim(), &[(tr_in(SCOPE, l, step_name(&step)), k)])
        }
        None => String::new(),
    };
    let rpki = s(p, "rpki");
    Row {
        key: s(p, "index"),
        cells: vec![
            path,
            lost,
            dash(u(p, "weight")),
            dash(u(p, "local_pref")),
            s(p, "as_path"),
            s(p, "origin"),
            dash(u(p, "med")),
            s(p, "peer_kind"),
            dash(u(p, "igp_metric")),
            {
                let o = s(p, "originator_id");
                if o.is_empty() { s(p, "router_id") } else { format!("{o} (originator)") }
            },
            cell("", &[(rpki.as_str(), rpki_kind(&rpki))]),
        ],
        dimmed: p.get("valid").and_then(Value::as_bool) == Some(false),
        section: false,
        tint: None,
    }
}

impl PanelState for RoutesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if let Some(e) = &self.explain
            && !e.prefix.is_empty()
            && !e.ready()
            && app.has_command("routing.bgp.route.explain")
        {
            out.push(Query {
                key: "explain",
                command: "routing.bgp.route.explain",
                params: json!({"prefix": e.prefix}),
            });
        }
        if !app.open.contains(&Win::Bgp) {
            return out;
        }
        if app.has_command("routing.bgp.route.summary") {
            out.push(Query {
                key: "summary",
                command: "routing.bgp.route.summary",
                params: json!({}),
            });
        }
        // Tables the session detail asked for, until the summary has them.
        for c in self.wanted.iter().filter(|c| !self.summary.iter().any(|r| s(r, "connection") == **c)) {
            if app.has_command("routing.bgp.route.list") {
                out.push(Query {
                    key: "wanted",
                    command: "routing.bgp.route.list",
                    params: json!({"connection": c, "limit": 1}),
                });
            }
        }
        if !self.active {
            return out;
        }
        if app.has_command("routing.backend.get") {
            out.push(Query {
                key: "backend",
                command: "routing.backend.get",
                params: json!({}),
            });
        }
        if app.has_command("routing.bgp.connection.list") {
            out.push(Query {
                key: "connections",
                command: "routing.bgp.connection.list",
                params: json!({}),
            });
        }
        match self.tab {
            Tab::History => {
                if app.has_command("routing.bgp.session.history") {
                    let p = if self.connection.is_empty() { json!({}) } else { json!({"connection": self.connection}) };
                    out.push(Query {
                        key: "history",
                        command: "routing.bgp.session.history",
                        params: p,
                    });
                }
            }
            _ if !self.connection.is_empty() && app.has_command("routing.bgp.route.list") => {
                out.push(Query {
                    key: "routes",
                    command: "routing.bgp.route.list",
                    params: self.params(false),
                });
            }
            _ => {}
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "connections" => {
                self.connections = value
                    .as_array()
                    .map(|a| a.iter().map(|c| s(c, "name")).filter(|n| !n.is_empty()).collect())
                    .unwrap_or_default();
                if self.connection.is_empty()
                    && let Some(first) = self.connections.first()
                {
                    self.connection = first.clone();
                }
            }
            "routes" => {
                // An answer for another connection or tab (sent before a
                // click) is not this view's.
                let dir = if self.tab == Tab::Advertised { "advertised" } else { "received" };
                if s(&value, "connection") == self.connection && s(&value, "direction") == dir {
                    self.answer = Some(value);
                }
            }
            "history" => self.history = value.as_array().cloned().unwrap_or_default(),
            "backend" => self.attached = value.get("attached").and_then(Value::as_bool),
            "summary" => self.summary = value.as_array().cloned().unwrap_or_default(),
            "explain" => {
                if let Some(e) = self.explain.as_mut() {
                    e.answer = Some(value);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.header(app, ui);
        ui.separator();
        match self.tab {
            Tab::History => self.history_tab(app, ui),
            _ => self.routes_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.explain_window(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::History => self.history_table.escape(),
            _ => self.table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (HISTORY, &self.history_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table), (HISTORY, &mut self.history_table)]
    }
}

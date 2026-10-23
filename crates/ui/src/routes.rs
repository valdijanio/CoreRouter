//! The IP › Routes window, WinBox style: every route the router knows
//! (static, connected, from a DHCP lease or a Router Advertisement), with
//! the toolbar, context menus, "New Route" and "Route <dst>" windows of
//! the G1.9 table, and what G1.27 adds to read it: a state chip
//! (active / standby / inactive) and an origin chip instead of RouterOS'
//! flag letters, the gateway split into address, interface and
//! reachability, the table as a chip coloured by its name, quick filters,
//! the counts, how long ago each route changed, why a route is standby or
//! inactive, ECMP groups that open on a click, and a route lookup.
//!
//! All of it comes from `ip.route.list` and `ip.route.lookup`: the engine
//! decides states and reasons. Every change goes through
//! `CoreRouterUi::run`.

use std::collections::{BTreeMap, BTreeSet};

use egui::{Grid, Sense, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Buttons, Footer, Form, Head, Press, Status};
use crate::i18n::{self, Lang, tr};
use crate::interfaces::{cascade, dialog_id, opt_text};
use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment, num, weak};
use crate::{CoreRouterUi, Then, Win, form_number, value_text};

pub(crate) const TABLE: &str = "routes";
/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;
const MAIN: &str = "main";
/// Height of the detail under the table (G1.27b).
const DETAIL_H: f32 = 150.0;
/// State changes the detail lists (the newest).
const DETAIL_CHANGES: usize = 4;
/// Key prefix of an ECMP group's own line.
const GROUP: &str = "ecmp ";

const COLUMNS: [table::Column; 8] = [
    col("State"),
    col("Dst. Address"),
    col("Gateway"),
    num("Distance"),
    col("Routing Table"),
    num("Changed"),
    weak("Reason"),
    comment(),
];

/// One row of `ip.route.list`, as the window needs it.
#[derive(Clone, Default)]
pub(crate) struct Route {
    /// Table key: the engine's `key` (the id of a static route).
    pub key: String,
    /// `*N` of a static or DHCP route; `None` for a connected route.
    pub id: Option<String>,
    pub dst: String,
    /// The gateway as configured.
    pub gateway: String,
    pub gateway_address: Option<String>,
    pub gateway_interface: Option<String>,
    /// `reachable` | `unreachable`; `None` for a connected route.
    pub gateway_status: Option<String>,
    /// check-gateway: (method, `up` | `down`, misses).
    pub check: Option<(String, String, u64)>,
    pub distance: String,
    pub table: String,
    pub flags: String,
    /// `active` | `standby` | `inactive`.
    pub state: String,
    pub active: bool,
    /// `connected` | `static` | `dhcp` | `ra`.
    pub origin: String,
    pub ipv6: bool,
    /// From a DHCP client's lease (G4.7) or connected: not the operator's.
    pub dynamic: bool,
    pub disabled: bool,
    pub immediate: Option<String>,
    /// Outgoing interface when usable.
    pub interface: Option<String>,
    pub ecmp: u64,
    pub reason: Option<String>,
    pub reason_id: Option<String>,
    pub reason_args: Vec<(String, String)>,
    pub changed_secs: Option<u64>,
    pub comment: String,
}

impl Route {
    pub(crate) fn from_row(row: &Value) -> Self {
        let text = |k: &str| row.get(k).map(value_text).unwrap_or_default();
        let opt = |k: &str| row.get(k).filter(|v| !v.is_null()).map(value_text);
        let flag = |k: &str| row.get(k).and_then(Value::as_bool).unwrap_or(false);
        let id = opt("id");
        // An older daemon sends no key: make one as it used to.
        let key = opt("key").or_else(|| id.clone()).unwrap_or_else(|| {
            format!(
                "connected {} {} {}",
                text("routing_table"),
                text("dst_address"),
                text("gateway")
            )
        });
        let active = flag("active");
        let check = row.get("check_gateway").filter(|v| v.is_object()).map(|c| {
            (
                c.get("method").map(value_text).unwrap_or_default(),
                c.get("state").map(value_text).unwrap_or_default(),
                c.get("misses").and_then(Value::as_u64).unwrap_or(0),
            )
        });
        let reason_args = row
            .get("reason_args")
            .and_then(Value::as_object)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), value_text(v))).collect())
            .unwrap_or_default();
        let dst = text("dst_address");
        Self {
            key,
            id,
            ipv6: dst.contains(':'),
            dst,
            gateway: text("gateway"),
            gateway_address: opt("gateway_address"),
            gateway_interface: opt("gateway_interface"),
            gateway_status: opt("gateway_status"),
            check,
            distance: text("distance"),
            table: text("routing_table"),
            flags: text("flags"),
            state: opt("state").unwrap_or_else(|| {
                if active { "active" } else { "inactive" }.to_owned()
            }),
            active,
            origin: opt("origin").unwrap_or_default(),
            dynamic: flag("dynamic"),
            disabled: flag("disabled"),
            immediate: opt("immediate_gw"),
            interface: opt("interface"),
            ecmp: row.get("ecmp").and_then(Value::as_u64).unwrap_or(1),
            reason: opt("reason"),
            reason_id: opt("reason_id"),
            reason_args,
            changed_secs: row.get("changed_secs").and_then(Value::as_u64),
            comment: text("comment"),
        }
    }

    /// The operator's own route (not connected, not from a DHCP lease).
    fn is_static(&self) -> bool {
        self.id.is_some() && !self.dynamic
    }

    fn status(&self) -> String {
        match (&self.reason, self.active) {
            (_, true) => "active".into(),
            (Some(why), false) => why.clone(),
            (None, false) => "inactive".into(),
        }
    }

    /// Why it is standby or inactive, in the explanations' language.
    fn why(&self, lang: Lang) -> String {
        let Some(english) = &self.reason else {
            return String::new();
        };
        let Some(id) = &self.reason_id else {
            return english.clone();
        };
        let args: Vec<(&str, &str)> = self
            .reason_args
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        i18n::template(lang, &format!("route.{id}"), &args, english)
    }

    fn state_chip(&self) -> (&'static str, Kind) {
        if self.disabled {
            return ("disabled", Kind::Neutral);
        }
        match self.state.as_str() {
            "active" => ("active", Kind::Green),
            "standby" => ("standby", Kind::Amber),
            _ => ("inactive", Kind::Red),
        }
    }

    /// Address, then the interface and reachability as chips.
    fn gateway_cell(&self) -> String {
        let link = self.interface.as_ref().or(self.gateway_interface.as_ref());
        let mut chips: Vec<(&str, Kind)> = Vec::new();
        let text = match (&self.gateway_address, link) {
            (Some(a), Some(l)) => {
                chips.push((l.as_str(), Kind::Neutral));
                a.clone()
            }
            (Some(a), None) => a.clone(),
            (None, Some(l)) => l.clone(),
            (None, None) => self.gateway.clone(),
        };
        match self.gateway_status.as_deref() {
            Some("reachable") => chips.push(("reachable", Kind::Green)),
            Some("unreachable") if !self.disabled => chips.push(("unreachable", Kind::Red)),
            _ => {}
        }
        let check;
        if let Some((method, state, _)) = &self.check {
            check = format!("check {method}");
            chips.push((
                &check,
                if state == "down" { Kind::Red } else { Kind::Blue },
            ));
        }
        cell(&text, &chips)
    }
}

/// "5s", "3m", "2h", "4d"; "–" when unknown (seen before watching began).
pub(crate) fn age(secs: Option<u64>) -> String {
    match secs {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3_600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3_600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

/// Address family filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Family {
    #[default]
    All,
    V4,
    V6,
}

/// The window's own state (G1.27): filters, lookup, open ECMP groups.
#[derive(Default)]
pub(crate) struct View {
    pub family: Family,
    /// Origins shown; empty: all.
    pub origins: BTreeSet<String>,
    /// `active` | `standby` | `inactive`; `None`: all.
    pub state: Option<&'static str>,
    /// Routing table shown; `None`: all.
    pub table: Option<String>,
    /// ECMP groups open (their group key).
    pub open: BTreeSet<String>,
    /// The address typed in the lookup field.
    pub lookup: String,
    /// The last lookup's answer (or error).
    pub found: Option<Result<Value, String>>,
    /// The one route selected, whose detail shows under the table (G1.27b).
    pub selected: Option<String>,
}

impl View {
    fn shows(&self, r: &Route) -> bool {
        let family = match self.family {
            Family::All => true,
            Family::V4 => !r.ipv6,
            Family::V6 => r.ipv6,
        };
        family
            && (self.origins.is_empty() || self.origins.contains(&r.origin))
            && self.state.is_none_or(|s| s == r.state)
            && self.table.as_ref().is_none_or(|t| *t == r.table)
    }
}

/// The counts of the footer.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub total: usize,
    pub active: usize,
    pub standby: usize,
    pub inactive: usize,
    pub v4: usize,
    pub v6: usize,
}

pub(crate) fn counts(routes: &[Route]) -> Counts {
    let mut c = Counts::default();
    for r in routes {
        c.total += 1;
        match r.state.as_str() {
            "active" => c.active += 1,
            "standby" => c.standby += 1,
            _ => c.inactive += 1,
        }
        if r.ipv6 {
            c.v6 += 1;
        } else {
            c.v4 += 1;
        }
    }
    c
}

/// Key of the ECMP group of `r` (its active paths share it).
fn group_key(r: &Route) -> Option<String> {
    (r.ecmp > 1 && r.state == "active").then(|| format!("{GROUP}{} {}", r.table, r.dst))
}

/// The table's rows: the routes `view` shows, an ECMP group as one line
/// "N next-hops" followed by its paths when open.
pub(crate) fn rows_of(routes: &[Route], view: &View, lang: i18n::Langs) -> Vec<Row> {
    let mut groups: BTreeMap<String, Vec<&Route>> = BTreeMap::new();
    for r in routes.iter().filter(|r| view.shows(r)) {
        if let Some(g) = group_key(r) {
            groups.entry(g).or_default().push(r);
        }
    }
    let mut out = Vec::with_capacity(routes.len());
    let mut done: BTreeSet<&str> = BTreeSet::new();
    for r in routes.iter().filter(|r| view.shows(r)) {
        let Some(g) = group_key(r) else {
            out.push(route_row(r, lang, false));
            continue;
        };
        if !done.insert(groups.get_key_value(&g).map_or("", |(k, _)| k.as_str())) {
            continue;
        }
        let paths = groups.get(&g).map_or(&[][..], Vec::as_slice);
        let open = view.open.contains(&g);
        out.push(group_row(&g, r, paths.len(), open, lang));
        if open {
            out.extend(paths.iter().map(|p| route_row(p, lang, true)));
        }
    }
    out
}

fn group_row(key: &str, first: &Route, paths: usize, open: bool, lang: i18n::Langs) -> Row {
    // The default fonts lack ▸/▾ (i18n MISSING_GLYPHS).
    let arrow = if open { "-" } else { "+" };
    Row {
        key: key.to_owned(),
        cells: vec![
            cell("", &[("active", Kind::Green)]),
            cell(&first.dst, &[(origin_label(&first.origin), origin_kind(&first.origin))]),
            cell(
                &format!("{arrow} {paths} {}", tr(lang.labels, "next-hops")),
                &[("ECMP", Kind::Blue)],
            ),
            first.distance.clone(),
            cell("", &[(&first.table, Kind::Hashed(chip::name_hue(&first.table)))]),
            age(first.changed_secs),
            String::new(),
            String::new(),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn origin_label(o: &str) -> &str {
    match o {
        "" => "?",
        o => o,
    }
}

fn origin_kind(o: &str) -> Kind {
    match o {
        "dhcp" | "ra" => Kind::Blue,
        _ => Kind::Neutral,
    }
}

fn route_row(r: &Route, lang: i18n::Langs, path: bool) -> Row {
    let (state, kind) = r.state_chip();
    let dst = if path {
        format!("      {}", r.dst)
    } else {
        r.dst.clone()
    };
    Row {
        key: r.key.clone(),
        cells: vec![
            cell("", &[(state, kind)]),
            cell(&dst, &[(origin_label(&r.origin), origin_kind(&r.origin))]),
            r.gateway_cell(),
            r.distance.clone(),
            cell("", &[(&r.table, Kind::Hashed(chip::name_hue(&r.table)))]),
            age(r.changed_secs),
            r.why(lang.help),
            r.comment.clone(),
        ],
        dimmed: r.disabled,
        section: false,
        tint: None,
    }
}

/// The keys of the routes `selection` stands for (an ECMP group's line
/// stands for its paths), in order.
fn paths_of(selection: &[String], routes: &[Route]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(selection.len());
    for k in selection {
        if k.starts_with(GROUP) {
            for r in routes.iter().filter(|r| group_key(r).as_deref() == Some(k.as_str())) {
                if !out.contains(&r.key) {
                    out.push(r.key.clone());
                }
            }
        } else if !out.contains(k) {
            out.push(k.clone());
        }
    }
    out
}

fn lookup_id() -> egui::Id {
    egui::Id::unique("corerouter-route-lookup")
}

/// The footer: how many routes, in which state and family.
fn footer(ui: &mut Ui, c: &Counts, l: Lang) {
    ui.horizontal(|ui| {
        let v = ui.visuals().clone();
        for (n, label, tone) in [
            (c.total, "routes", chip::neutral_tone(&v)),
            (c.active, "active", chip::GREEN.tone(&v)),
            (c.standby, "standby", chip::AMBER.tone(&v)),
            (c.inactive, "inactive", chip::RED.tone(&v)),
            (c.v4, "IPv4", chip::neutral_tone(&v)),
            (c.v6, "IPv6", chip::neutral_tone(&v)),
        ] {
            chip::chip(ui, &format!("{n} {}", tr(l, label)), tone);
        }
    });
}

/// One line with the lookup's answer.
fn lookup_answer(ui: &mut Ui, found: &Result<Value, String>, l: Lang) {
    let v = ui.visuals().clone();
    let r = match found {
        Err(e) => {
            ui.colored_label(chip::RED.tone(&v).ink, e);
            return;
        }
        Ok(r) => r,
    };
    let s = |k: &str| r.get(k).filter(|x| !x.is_null()).map(value_text);
    let kind = s("type").unwrap_or_default();
    ui.label(format!("{}:", s("address").unwrap_or_default()));
    match kind.as_str() {
        "unreachable" => {
            chip::chip(ui, tr(l, "unreachable"), chip::RED.tone(&v));
        }
        "local" => {
            chip::chip(ui, tr(l, "local"), chip::BLUE.tone(&v));
            if let Some(i) = s("interface") {
                chip::chip(ui, &i, chip::neutral_tone(&v));
            }
        }
        _ => {
            ui.label(s("prefix").unwrap_or_default());
            if let Some(o) = r.pointer("/route/origin").map(value_text) {
                chip::chip(ui, &o, chip::neutral_tone(&v));
            }
            let hops = r.get("nexthops").and_then(Value::as_array).cloned().unwrap_or_default();
            for h in &hops {
                let gw = h.get("gateway").filter(|g| !g.is_null()).map(value_text);
                if let Some(g) = gw {
                    ui.label(format!("via {g}"));
                }
                if let Some(i) = h.get("interface").map(value_text) {
                    chip::chip(ui, &i, chip::neutral_tone(&v));
                }
            }
            if hops.len() > 1 {
                chip::chip(ui, "ECMP", chip::BLUE.tone(&v));
            }
            if let Some(src) = s("src") {
                ui.label(format!("src {src}"));
            }
        }
    }
    if let Some(t) = s("routing_table") {
        chip::chip(ui, &t, chip::palette_tone(&v, chip::name_hue(&t)));
    }
    let kernel = r.get("kernel");
    let same = kernel.and_then(|k| k.get("same")).and_then(Value::as_bool);
    let resp = match same {
        Some(true) => chip::chip(ui, tr(l, "kernel agrees"), chip::GREEN.tone(&v)),
        Some(false) => chip::chip(ui, tr(l, "kernel differs"), chip::AMBER.tone(&v)),
        None => chip::chip(ui, tr(l, "kernel not checked"), chip::neutral_tone(&v)),
    };
    let tip = match same {
        Some(false) => kernel
            .and_then(|k| k.get("differences"))
            .and_then(Value::as_array)
            .map(|d| d.iter().map(value_text).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default(),
        Some(true) => String::new(),
        None => kernel
            .and_then(|k| k.get("reason"))
            .map(value_text)
            .unwrap_or_default(),
    };
    let rule = s("rule").unwrap_or_default();
    resp.on_hover_text(if tip.is_empty() { rule } else { format!("{tip}\n{rule}") });
}

fn state_tone(v: &egui::Visuals, state: &str) -> chip::Tone {
    match state {
        "active" => chip::GREEN.tone(v),
        "standby" => chip::AMBER.tone(v),
        _ => chip::RED.tone(v),
    }
}

/// An engine text in the explanations' language: the template `id`
/// (`prefix.<id>` when `prefix` is given) filled with `args`, else the
/// English `text`.
fn localized(v: &Value, text: &str, id: &str, args: &str, prefix: Option<&str>, lang: Lang) -> String {
    let english = v.get(text).map(value_text).unwrap_or_default();
    let Some(id) = v.get(id).and_then(Value::as_str) else {
        return english;
    };
    let key = match prefix {
        Some(p) => format!("{p}.{id}"),
        None => id.to_owned(),
    };
    let args: Vec<(String, String)> = v
        .get(args)
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), value_text(v))).collect())
        .unwrap_or_default();
    let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    i18n::template(lang, &key, &args, &english)
}

/// "rev 7 · ip.route.add · 3m ago".
fn revision_text(r: &Value) -> Option<String> {
    let n = r.get("revision")?.as_u64()?;
    let mut t = format!("rev {n} · {}", r.get("command").map(value_text).unwrap_or_default());
    if let Some(a) = r.get("ago_secs").and_then(Value::as_u64) {
        t.push_str(&format!(" · {} ago", age(Some(a))));
    }
    Some(t)
}

/// The detail of the selected route (`ip.route.detail`).
fn detail(ui: &mut Ui, d: Option<&Value>, langs: i18n::Langs) {
    let l = langs.labels;
    let Some(d) = d else {
        ui.weak(tr(l, "Loading the route's detail…"));
        return;
    };
    let v = ui.visuals().clone();
    egui::ScrollArea::vertical()
        .id_salt("route-detail")
        .max_height(DETAIL_H - 12.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            Grid::new("route-detail-grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    let src = &d["source"];
                    ui.label(tr(l, "Source"));
                    ui.horizontal(|ui| {
                        ui.label(src.get("text").map(value_text).unwrap_or_default());
                        // "changed" only when it is not the creation.
                        let same = src["changed"].get("revision") == src["created"].get("revision");
                        for k in ["created", "changed"] {
                            if k == "changed" && same {
                                continue;
                            }
                            if let Some(t) = src.get(k).and_then(revision_text) {
                                let t = format!("{} {t}", tr(l, k));
                                chip::chip(ui, &t, chip::neutral_tone(&v));
                            }
                        }
                    });
                    ui.end_row();

                    ui.label(tr(l, "Chosen"));
                    ui.horizontal_wrapped(|ui| {
                        ui.label(localized(d, "chosen", "chosen_id", "chosen_args", None, langs.help));
                        let others = d["competitors"].as_array().cloned().unwrap_or_default();
                        if others.len() > 1 {
                            for c in &others {
                                let state = c.get("state").map(value_text).unwrap_or_default();
                                let name = c
                                    .get("id")
                                    .filter(|i| !i.is_null())
                                    .map_or_else(|| "connected".to_owned(), value_text);
                                let text = format!(
                                    "{name} d{} {}",
                                    c.get("distance").map(value_text).unwrap_or_default(),
                                    c.get("gateway").map(value_text).unwrap_or_default()
                                );
                                let resp = chip::chip(ui, &text, state_tone(&v, &state));
                                if c.get("reason").is_some_and(|r| !r.is_null()) {
                                    resp.on_hover_text(localized(
                                        c,
                                        "reason",
                                        "reason_id",
                                        "reason_args",
                                        Some("route"),
                                        langs.help,
                                    ));
                                }
                            }
                        }
                    });
                    ui.end_row();

                    ui.label(tr(l, "Check gateway"));
                    match d.get("check_gateway").filter(|c| c.is_object()) {
                        Some(c) => {
                            ui.horizontal(|ui| {
                                let s = |k: &str| c.get(k).map(value_text).unwrap_or_default();
                                ui.label(format!(
                                    "{}, every {} s, {} {}",
                                    s("method"),
                                    s("interval_secs"),
                                    s("misses"),
                                    tr(l, "misses")
                                ));
                                let up = s("state") == "up";
                                let tone = if up { chip::GREEN.tone(&v) } else { chip::RED.tone(&v) };
                                chip::chip(ui, &s("state"), tone);
                                if let Some(secs) = c.get("down_secs").and_then(Value::as_u64).filter(|_| !up) {
                                    ui.weak(format!("{} {}", tr(l, "down for"), age(Some(secs))));
                                }
                            });
                        }
                        None => {
                            ui.weak(tr(l, "none"));
                        }
                    }
                    ui.end_row();

                    ui.label(tr(l, "Changes (24 h)"));
                    let changes = d["history"].as_array().cloned().unwrap_or_default();
                    ui.vertical(|ui| {
                        if changes.is_empty() {
                            ui.weak(tr(l, "no change seen"));
                        }
                        for c in changes.iter().take(DETAIL_CHANGES) {
                            ui.horizontal(|ui| {
                                let s = |k: &str| c.get(k).map(value_text).unwrap_or_default();
                                ui.weak(format!(
                                    "{} {}",
                                    age(c.get("ago_secs").and_then(Value::as_u64)),
                                    tr(l, "ago")
                                ));
                                chip::chip(ui, &s("from"), state_tone(&v, &s("from")));
                                ui.label("->");
                                chip::chip(ui, &s("to"), state_tone(&v, &s("to")));
                                if c.get("reason").is_some_and(|r| !r.is_null()) {
                                    ui.weak(localized(
                                        c,
                                        "reason",
                                        "reason_id",
                                        "reason_args",
                                        Some("route"),
                                        langs.help,
                                    ));
                                }
                            });
                        }
                        if changes.len() > DETAIL_CHANGES {
                            ui.weak(format!("+{} {}", changes.len() - DETAIL_CHANGES, tr(l, "more")));
                        }
                    });
                    ui.end_row();

                    ui.label(tr(l, "Kernel"));
                    let k = &d["kernel"];
                    ui.horizontal_wrapped(|ui| match k.get("same").and_then(Value::as_bool) {
                        Some(true) => {
                            chip::chip(ui, tr(l, "matches the config"), chip::GREEN.tone(&v));
                        }
                        Some(false) => {
                            chip::chip(ui, tr(l, "differs from the config"), chip::AMBER.tone(&v));
                            for (what, key) in [("missing", "missing"), ("not ours", "extra")] {
                                for r in k[key].as_array().into_iter().flatten() {
                                    ui.weak(format!("{}: {}", tr(l, what), value_text(r)));
                                }
                            }
                        }
                        None => {
                            ui.weak(k.get("note").map(value_text).unwrap_or_default());
                        }
                    });
                    ui.end_row();
                });
        });
}

/// A filter chip: blue when on. Returns whether it was clicked.
fn filter_chip(ui: &mut Ui, text: &str, on: bool) -> bool {
    let tone = if on {
        chip::BLUE.tone(ui.visuals())
    } else {
        chip::neutral_tone(ui.visuals())
    };
    chip::chip(ui, text, tone)
        .interact(Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// Toolbar, menus and shortcuts all end up as one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

/// The editable fields of a route, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RouteForm {
    pub dst: String,
    pub gateway: String,
    pub distance: String,
    pub table: String,
    pub comment: String,
    pub disabled: bool,
}

impl RouteForm {
    /// A blank "New Route" form.
    fn new() -> Self {
        Self {
            table: MAIN.into(),
            ..Self::default()
        }
    }

    fn of(r: &Route) -> Self {
        Self {
            dst: r.dst.clone(),
            gateway: r.gateway.clone(),
            distance: r.distance.clone(),
            table: r.table.clone(),
            comment: r.comment.clone(),
            disabled: r.disabled,
        }
    }

    /// `ip.route.add` params; blank optional fields are left to the engine.
    fn add_params(&self) -> Value {
        json!({
            "dst_address": self.dst.trim(),
            "gateway": self.gateway.trim(),
            "distance": form_number(&self.distance),
            "routing_table": opt_text(self.table.trim()),
            "comment": opt_text(&self.comment),
        })
    }

    /// `ip.route.set` params for what differs from `base`; `None` if nothing.
    fn set_params(&self, id: &str, base: &RouteForm) -> Option<Value> {
        let mut p = Map::new();
        if self.dst.trim() != base.dst {
            p.insert("dst_address".into(), json!(self.dst.trim()));
        }
        if self.gateway.trim() != base.gateway {
            p.insert("gateway".into(), json!(self.gateway.trim()));
        }
        if self.distance.trim() != base.distance {
            p.insert("distance".into(), form_number(&self.distance));
        }
        if self.table.trim() != base.table {
            p.insert("routing_table".into(), json!(self.table.trim()));
        }
        if self.comment != base.comment {
            p.insert("comment".into(), json!(self.comment));
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("id".into(), json!(id));
        Some(Value::Object(p))
    }
}

pub(crate) enum RouteDialog {
    New(RouteForm),
    /// "Route <dst>" of a static route; `base` is what the engine has.
    Props {
        id: String,
        form: RouteForm,
        base: RouteForm,
    },
    /// A connected route: read only, it follows its address.
    Connected(String),
    Comment {
        targets: Vec<String>,
        text: String,
        /// The text when the dialog opened.
        base: String,
    },
}

impl RouteDialog {
    /// Edits not saved yet (the dot in the title).
    fn dirty(&self) -> bool {
        match self {
            RouteDialog::New(form) => *form != RouteForm::new(),
            RouteDialog::Props { id, form, base } => form.set_params(id, base).is_some(),
            RouteDialog::Connected(_) => false,
            RouteDialog::Comment { text, base, .. } => text != base,
        }
    }
}

pub(crate) struct RouteDialogWin {
    pub id: u64,
    pub dialog: RouteDialog,
    pub status: Status,
}

/// What a dialog's command changes in the dialog when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    /// "New Route" + Apply: open the created route's window.
    OpenCreated,
    /// The form sent by OK/Apply is the engine's now.
    Applied(RouteForm),
    /// Enable/Disable button.
    Toggled(bool),
    /// The answer of the lookup bar (`ip.route.lookup`).
    Lookup,
}

/// The buttons of a "Route <dst>" window besides OK/Cancel/Apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
}

impl CoreRouterUi {
    /// The route whose detail the Routes window shows (G1.27b).
    pub(crate) fn route_selected(&self) -> Option<&str> {
        self.route_view.selected.as_deref()
    }

    fn route_rows(&self) -> Vec<Route> {
        self.cache.routes.iter().map(Route::from_row).collect()
    }

    fn route(&self, key: &str) -> Option<Route> {
        self.route_rows().into_iter().find(|r| r.key == key)
    }

    /// `main` plus every VRF, for the Routing Table field.
    fn tables(&self) -> Vec<String> {
        std::iter::once(MAIN.to_owned())
            .chain(self.interface_names(Some("vrf")))
            .collect()
    }

    pub(crate) fn routes(&mut self, ui: &mut Ui) {
        let langs = self.lang;
        let routes = self.route_rows();
        let rows = rows_of(&routes, &self.route_view, langs);
        let selection = self.tables.routes.selection(&rows);
        let keys = paths_of(&selection, &routes);
        let picked: Vec<&Route> = routes
            .iter()
            .filter(|r| keys.contains(&r.key))
            .collect();
        let mut act: Option<Act> = None;
        let can = self.can();
        // One row selected (an ECMP group: its first path): its detail.
        let single = match selection.as_slice() {
            [one] => paths_of(std::slice::from_ref(one), &routes).into_iter().next(),
            _ => None,
        };
        if single != self.route_view.selected {
            self.route_view.selected = single.clone();
            // Ask for its detail now, not at the next refresh.
            if single.is_some() {
                self.cache.refreshed_at = None;
            }
        }

        ui.horizontal(|ui| {
            if table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.route.add")).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and("ip.route.remove", only_static(&picked)),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and("ip.route.set", can_enable(&picked, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and("ip.route.set", can_enable(&picked, false)),
                ),
                (
                    Icon::Comment,
                    "Comment",
                    can.and("ip.route.set", only_static(&picked)),
                ),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = keys.clone();
                    act = Some(match icon {
                        Icon::Remove => Act::Remove(sel),
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        Icon::Add | Icon::Comment => Act::Comment(sel),
                    });
                }
            }
            table::find_field(ui, TABLE, &mut self.tables.routes);
        });
        let tables = self.tables();
        self.route_filters(ui, &tables);
        self.route_lookup_bar(ui, &can);
        ui.separator();

        // A static route's key is its id.
        self.tables.routes.open = self
            .route_dialogs
            .iter()
            .filter_map(|d| match &d.dialog {
                RouteDialog::Props { id, .. } => Some(id.clone()),
                RouteDialog::Connected(k) => Some(k.clone()),
                _ => None,
            })
            .collect();
        let line = ui.spacing().interact_size.y + ui.spacing().item_spacing.y;
        let footer_h = line + if single.is_some() { DETAIL_H } else { 0.0 };
        let out = table::show(
            ui,
            TABLE,
            footer_h,
            &mut self.tables.routes,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => row_menu(ui, &mut act, &routes, sel, &can),
                Menu::Empty => {
                    if action(ui, "Add Route…", can.check("ip.route.add")) {
                        act = Some(Act::New);
                    }
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                    if ui.button("Refresh").clicked() {
                        act = Some(Act::Refresh);
                    }
                }
            },
        );
        footer(ui, &counts(&routes), langs.labels);
        if let Some(key) = &single {
            let shown = self
                .panel_mut::<crate::route_detail::Detail>()
                .and_then(|d| d.shown.clone())
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v);
            ui.separator();
            detail(ui, shown.as_ref(), langs);
        }
        // A click on an ECMP group's line opens or closes it.
        if let Some(key) = out.clicked.filter(|k| k.starts_with(GROUP))
            && !self.route_view.open.remove(&key)
        {
            self.route_view.open.insert(key);
        }
        if let Some(key) = out.opened.filter(|k| !k.starts_with(GROUP)) {
            act = Some(Act::Open(vec![key]));
        }
        // Double click on an inline comment: only static routes have one.
        if let Some(key) = out.comment {
            act = Some(Act::Comment(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = paths_of(&self.tables.routes.selection(&rows), &routes);
            let picked: Vec<&Route> = routes.iter().filter(|r| sel.contains(&r.key)).collect();
            // Shortcuts on connected routes do nothing, like a greyed button.
            let allowed = match s {
                Shortcut::Remove | Shortcut::Comment => only_static(&picked).is_ok(),
                Shortcut::Enable => can_enable(&picked, true).is_ok(),
                Shortcut::Disable => can_enable(&picked, false).is_ok(),
                Shortcut::Open => !sel.is_empty(),
            };
            if allowed {
                act = Some(match s {
                    Shortcut::Remove => Act::Remove(sel),
                    Shortcut::Enable => Act::Enable(sel),
                    Shortcut::Disable => Act::Disable(sel),
                    Shortcut::Comment => Act::Comment(sel),
                    Shortcut::Open => Act::Open(sel),
                });
            }
        }
        if let Some(a) = act {
            self.route_act(a, &rows);
        }
    }

    /// The quick filters: family, origin, state and table, as chips.
    fn route_filters(&mut self, ui: &mut Ui, tables: &[String]) {
        let l = self.lang.labels;
        let v = &mut self.route_view;
        ui.horizontal_wrapped(|ui| {
            for (f, label) in [(Family::All, "All"), (Family::V4, "IPv4"), (Family::V6, "IPv6")] {
                if filter_chip(ui, tr(l, label), v.family == f) {
                    v.family = f;
                }
            }
            ui.separator();
            for o in ["connected", "static", "dhcp", "ra"] {
                if filter_chip(ui, o, v.origins.contains(o)) && !v.origins.remove(o) {
                    v.origins.insert(o.to_owned());
                }
            }
            ui.separator();
            for s in ["active", "standby", "inactive"] {
                if filter_chip(ui, s, v.state == Some(s)) {
                    v.state = if v.state == Some(s) { None } else { Some(s) };
                }
            }
            // Tables only when there is more than main.
            if tables.len() > 1 {
                ui.separator();
                for t in tables {
                    if filter_chip(ui, t, v.table.as_ref() == Some(t)) {
                        v.table = if v.table.as_ref() == Some(t) {
                            None
                        } else {
                            Some(t.clone())
                        };
                    }
                }
            }
        });
    }

    /// "Lookup": which route a packet to an address takes, and its answer.
    fn route_lookup_bar(&mut self, ui: &mut Ui, can: &Avail) {
        let l = self.lang.labels;
        let mut go = false;
        ui.horizontal(|ui| {
            ui.label(tr(l, "Route Lookup"));
            let resp = ui.add(
                TextEdit::singleline(&mut self.route_view.lookup)
                    .id(lookup_id())
                    .hint_text("8.8.8.8")
                    .desired_width(160.0),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                go = true;
            }
            let allowed = can.check("ip.route.lookup");
            let button = ui.add_enabled(allowed.is_ok(), egui::Button::new(tr(l, "Lookup")));
            let button = match &allowed {
                Ok(()) => button,
                Err(why) => button.on_disabled_hover_text(why),
            };
            if button.clicked() {
                go = true;
            }
            if let Some(found) = &self.route_view.found {
                lookup_answer(ui, found, l);
            }
        });
        let address = self.route_view.lookup.trim().to_owned();
        if go && !address.is_empty() {
            let p = match &self.route_view.table {
                Some(t) => json!({ "address": address, "table": t }),
                None => json!({ "address": address }),
            };
            self.run_then(
                "ip.route.lookup",
                p,
                Then::Route {
                    id: 0,
                    effect: Effect::Lookup,
                },
            );
        }
    }

    fn route_act(&mut self, act: Act, rows: &[Row]) {
        match act {
            Act::Enable(keys) => self.set_routes_disabled(&keys, false),
            Act::Disable(keys) => self.set_routes_disabled(&keys, true),
            Act::Remove(keys) => {
                for id in self.static_ids(&keys) {
                    self.run("ip.route.remove", json!({ "id": id }));
                }
            }
            Act::Comment(keys) => {
                let targets = self.static_ids(&keys);
                let text = match targets.as_slice() {
                    [one] => self.route(one).map(|r| r.comment).unwrap_or_default(),
                    _ => String::new(),
                };
                if !targets.is_empty() {
                    self.open_route_dialog(RouteDialog::Comment {
                        targets,
                        base: text.clone(),
                        text,
                    });
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_route(k);
                }
            }
            Act::New => self.open_route_dialog(RouteDialog::New(RouteForm::new())),
            Act::SelectAll => self.tables.routes.select_all(rows),
            Act::Refresh => self.cache.refreshed_at = None,
        }
    }

    /// Ids of the static routes among `keys` (connected ones have none).
    fn static_ids(&self, keys: &[String]) -> Vec<String> {
        let routes = self.route_rows();
        keys.iter()
            .filter_map(|k| {
                routes
                    .iter()
                    .find(|r| r.key == *k)
                    .filter(|r| r.is_static())?
                    .id
                    .clone()
            })
            .collect()
    }

    fn set_routes_disabled(&mut self, keys: &[String], disabled: bool) {
        for id in self.static_ids(keys) {
            self.run("ip.route.set", json!({ "id": id, "disabled": disabled }));
        }
    }

    fn open_route_dialog(&mut self, dialog: RouteDialog) {
        self.next_dialog = self.next_dialog.wrapping_add(1);
        self.route_dialogs.push(RouteDialogWin {
            id: self.next_dialog,
            dialog,
            status: Status::default(),
        });
    }

    /// "Route <dst>"; an already open one comes to the front.
    pub(crate) fn open_route(&mut self, key: &str) {
        let Some(r) = self.route(key) else { return };
        let open = self.route_dialogs.iter_mut().find(|d| match &d.dialog {
            RouteDialog::Props { id, .. } => r.id.as_deref() == Some(id.as_str()),
            RouteDialog::Connected(k) => *k == r.key,
            _ => false,
        });
        if let Some(d) = open {
            d.status.bring_to_front();
            return;
        }
        let dialog = match &r.id {
            Some(id) if r.is_static() => RouteDialog::Props {
                id: id.clone(),
                form: RouteForm::of(&r),
                base: RouteForm::of(&r),
            },
            _ => RouteDialog::Connected(r.key.clone()),
        };
        self.open_route_dialog(dialog);
    }

    /// Draw every open route dialog as its own floating window.
    pub(crate) fn route_dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let routes = self.route_rows();
        let tables = self.tables();
        let mut dialogs = std::mem::take(&mut self.route_dialogs);
        dialogs.retain_mut(|d| {
            // A route window whose route is gone closes itself.
            let id = dialog_id(d.id);
            let gone = match &d.dialog {
                RouteDialog::Props { id, .. } => {
                    !routes.iter().any(|r| r.id.as_deref() == Some(id.as_str()))
                }
                RouteDialog::Connected(k) => !routes.iter().any(|r| r.key == *k),
                _ => false,
            };
            if gone {
                self.floats.forget(id);
                return false;
            }
            let title = dialog_title(&d.dialog, &routes);
            let can = self.can();
            let head = Head {
                id,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Routes)),
            };
            let pressed =
                dialog::show(&mut self.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(ui, f, &mut d.dialog, &routes, &tables, &can)
                });
            let keep = pressed.is_none_or(|b| self.route_button(d, b, &routes));
            if !keep {
                self.floats.forget(id);
            }
            keep
        });
        dialogs.append(&mut self.route_dialogs);
        self.route_dialogs = dialogs;
    }

    /// Send what a button means. Returns whether the dialog stays open now;
    /// closing on success is decided when the replies arrive.
    fn route_button(&mut self, d: &mut RouteDialogWin, b: Press<Button>, routes: &[Route]) -> bool {
        if b == Press::Cancel {
            return false;
        }
        let (sends, close): (Vec<(&str, Value, Effect)>, bool) = match &d.dialog {
            RouteDialog::New(form) => {
                let effect = if b == Press::Apply {
                    Effect::OpenCreated
                } else {
                    Effect::None
                };
                (vec![("ip.route.add", form.add_params(), effect)], true)
            }
            RouteDialog::Props { id, form, base } => match b {
                Press::Ok | Press::Apply => match form.set_params(id, base) {
                    Some(p) => (
                        vec![("ip.route.set", p, Effect::Applied(form.clone()))],
                        b == Press::Ok,
                    ),
                    // OK with nothing changed just closes.
                    None => return b != Press::Ok,
                },
                Press::Other(Button::Toggle) => {
                    let now = routes
                        .iter()
                        .find(|r| r.id.as_deref() == Some(id.as_str()))
                        .is_some_and(|r| r.disabled);
                    (
                        vec![(
                            "ip.route.set",
                            json!({"id": id, "disabled": !now}),
                            Effect::Toggled(!now),
                        )],
                        false,
                    )
                }
                Press::Other(Button::Remove) => (
                    vec![("ip.route.remove", json!({ "id": id }), Effect::None)],
                    true,
                ),
                Press::Cancel => return false,
            },
            RouteDialog::Connected(_) => return false,
            RouteDialog::Comment { targets, text, .. } => (
                targets
                    .iter()
                    .map(|t| {
                        (
                            "ip.route.set",
                            json!({"id": t, "comment": text}),
                            Effect::None,
                        )
                    })
                    .collect(),
                true,
            ),
        };
        d.status.close_on_success = close;
        for (cmd, params, effect) in sends {
            d.status.sent();
            self.run_then(cmd, params, Then::Route { id: d.id, effect });
        }
        true
    }

    /// A reply to a route dialog's command: an error stays in the dialog.
    pub(crate) fn route_dialog_reply(
        &mut self,
        id: u64,
        effect: Effect,
        result: &Result<Value, String>,
    ) {
        if effect == Effect::Lookup {
            self.route_view.found = Some(result.clone());
            return;
        }
        let Some(pos) = self.route_dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut created = None;
        let close = match self.route_dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, effect, &mut d.dialog) {
                    (Err(_), _, _) => {}
                    (Ok(r), Effect::OpenCreated, _) => {
                        created = r.get("id").and_then(Value::as_str).map(str::to_owned);
                    }
                    (Ok(_), Effect::Applied(sent), RouteDialog::Props { base, form, .. }) => {
                        // The engine stores what it parsed: trimmed text.
                        *base = RouteForm {
                            dst: sent.dst.trim().to_owned(),
                            gateway: sent.gateway.trim().to_owned(),
                            distance: sent.distance.trim().to_owned(),
                            table: sent.table.trim().to_owned(),
                            ..sent
                        };
                        form.disabled = base.disabled;
                    }
                    (Ok(_), Effect::Toggled(now), RouteDialog::Props { base, form, .. }) => {
                        base.disabled = now;
                        form.disabled = now;
                    }
                    (Ok(_), _, _) => {}
                }
                close
            }
        };
        if close {
            self.route_dialogs.remove(pos);
            self.floats.forget(dialog_id(id));
        }
        if let Some(route) = created {
            // Opens when an `ip.route.list` that has it arrives.
            let list = self.reload();
            self.open_route_after.push((list, route));
        }
    }
}

fn some(picked: &[&Route]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more routes first".into())
    } else {
        Ok(())
    }
}

fn only_static(picked: &[&Route]) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| !r.is_static()) {
        Err(
            "Connected routes come from IP addresses, dynamic ones from a DHCP client: \
             change those instead"
                .into(),
        )
    } else {
        Ok(())
    }
}

fn can_enable(picked: &[&Route], enable: bool) -> Result<(), String> {
    only_static(picked)?;
    if picked.iter().any(|r| r.disabled == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

fn row_menu(ui: &mut Ui, act: &mut Option<Act>, routes: &[Route], sel: &table::Selection, can: &Avail) {
    let keys = paths_of(sel, routes);
    let picked: Vec<&Route> = routes.iter().filter(|r| keys.contains(&r.key)).collect();
    let owned = || keys.clone();
    if action(
        ui,
        "Enable",
        can.and("ip.route.set", can_enable(&picked, true)),
    ) {
        *act = Some(Act::Enable(owned()));
    }
    if action(
        ui,
        "Disable",
        can.and("ip.route.set", can_enable(&picked, false)),
    ) {
        *act = Some(Act::Disable(owned()));
    }
    if action(
        ui,
        "Remove",
        can.and("ip.route.remove", only_static(&picked)),
    ) {
        *act = Some(Act::Remove(owned()));
    }
    if action(
        ui,
        "Comment…",
        can.and("ip.route.set", only_static(&picked)),
    ) {
        *act = Some(Act::Comment(owned()));
    }
    if action(ui, "Properties…", some(&picked)) {
        *act = Some(Act::Open(owned()));
    }
    ui.separator();
    if action(ui, "Add Route…", can.check("ip.route.add")) {
        *act = Some(Act::New);
    }
}

fn dialog_title(d: &RouteDialog, routes: &[Route]) -> String {
    let dst_of = |pred: &dyn Fn(&Route) -> bool| {
        routes
            .iter()
            .find(|r| pred(r))
            .map(|r| r.dst.clone())
            .unwrap_or_default()
    };
    match d {
        RouteDialog::New(_) => "New Route".into(),
        RouteDialog::Props { id, .. } => {
            format!(
                "Route <{}>",
                dst_of(&|r| r.id.as_deref() == Some(id.as_str()))
            )
        }
        RouteDialog::Connected(k) => format!("Route <{}>", dst_of(&|r| r.key == *k)),
        RouteDialog::Comment { targets, .. } => match targets.as_slice() {
            [one] => format!(
                "Comment for Route <{}>",
                dst_of(&|r| r.id.as_deref() == Some(one.as_str()))
            ),
            many => format!("Comment for {} Routes", many.len()),
        },
    }
}

fn form_fields(ui: &mut Ui, f: &Form, r: &mut RouteForm, tables: &[String], with_disabled: bool) {
    f.text(ui, "Dst. Address", "dst_address", &mut r.dst, "0.0.0.0/0");
    f.text(
        ui,
        "Gateway",
        "gateway",
        &mut r.gateway,
        "10.0.0.1 or ether1",
    );
    f.text(ui, "Distance", "distance", &mut r.distance, "1");
    ui.label("Routing Table");
    crate::windows::combo(ui, "route-table", MAIN, &mut r.table, tables);
    ui.end_row();
    f.text(ui, "Comment", "comment", &mut r.comment, "");
    if with_disabled {
        ui.label("Disabled");
        ui.checkbox(&mut r.disabled, "");
        ui.end_row();
    }
}

fn read_only(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.add_enabled(
        false,
        TextEdit::singleline(&mut value.to_owned()).desired_width(180.0),
    );
    ui.end_row();
}

/// The fields of one dialog, and the buttons it has under them.
fn dialog_body(
    ui: &mut Ui,
    f: &Form,
    d: &mut RouteDialog,
    routes: &[Route],
    tables: &[String],
    can: &Avail,
) -> Footer<Button> {
    let mut toggle_label = None;
    let mut view_only = false;
    let mut from_dhcp = false;
    Grid::new("fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| match &mut *d {
            RouteDialog::New(form) => form_fields(ui, f, form, tables, false),
            RouteDialog::Props { id, form, .. } => {
                form_fields(ui, f, form, tables, true);
                if let Some(r) = routes.iter().find(|r| r.id.as_deref() == Some(id.as_str())) {
                    read_only(
                        ui,
                        "Immediate Gateway",
                        r.immediate.as_deref().unwrap_or(""),
                    );
                    read_only(ui, "Flags", &r.flags);
                    ui.label("Status");
                    ui.weak(r.status());
                    ui.end_row();
                    toggle_label = Some(if r.disabled { "Enable" } else { "Disable" });
                }
            }
            RouteDialog::Connected(k) => {
                view_only = true;
                if let Some(r) = routes.iter().find(|r| r.key == *k) {
                    read_only(ui, "Dst. Address", &r.dst);
                    read_only(ui, "Gateway", &r.gateway);
                    read_only(ui, "Distance", &r.distance);
                    read_only(ui, "Routing Table", &r.table);
                    read_only(ui, "Flags", &r.flags);
                    from_dhcp = r.id.is_some();
                    ui.label("Status");
                    let kind = if from_dhcp { "dynamic" } else { "connected" };
                    ui.weak(format!("{kind}, {}", r.status()));
                    ui.end_row();
                }
            }
            RouteDialog::Comment { text, .. } => f.text(ui, "Comment", "comment", text, ""),
        });
    if view_only {
        ui.weak(if from_dhcp {
            "Dynamic routes come with a DHCP client's lease (IP › DHCP Client)."
        } else {
            "Connected routes follow their IP address (IP › Addresses)."
        });
        return Footer {
            buttons: Buttons::View,
            ok: Ok(()),
            extra: Vec::new(),
            pressed: None,
        };
    }
    // What OK / Apply send.
    let ok = can.check(match d {
        RouteDialog::New(_) => "ip.route.add",
        _ => "ip.route.set",
    });
    let mut footer = Footer::edit(!matches!(d, RouteDialog::Comment { .. }), ok);
    if let Some(t) = toggle_label {
        footer.extra = vec![
            (t, Button::Toggle, can.check("ip.route.set")),
            ("Remove", Button::Remove, can.check("ip.route.remove")),
        ];
    }
    footer
}

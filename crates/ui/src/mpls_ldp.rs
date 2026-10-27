//! MPLS › LDP (G3.5), RouterOS v7 `/mpls ldp`: the approved mockup's three
//! tabs — Neighbors (sessions, configured and discovered), Interfaces
//! (where LDP runs, with its state, IGP sync and the MTU check) and
//! Settings (the instance and `/mpls settings`). `mpls.ldp.*` decides; this
//! only shows and sends.

use std::collections::BTreeMap;

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "mpls-ldp";
pub(crate) const WIN: &str = "mpls-ldp";
const SCOPE: &str = "mpls";
const NEIGHBORS: &str = "mpls-ldp-neighbors";
const INTERFACES: &str = "mpls-ldp-interfaces";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "MPLS",
        title: "LDP",
        size: [900.0, 460.0],
        escape: true,
    }],
    new: || Box::<LdpPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Neighbors,
    Interfaces,
    Settings,
}

const TABS: [(Tab, &str, &str); 3] = [
    (Tab::Neighbors, "Neighbors", "mpls.tab.neighbors"),
    (Tab::Interfaces, "Interfaces", "mpls.tab.interfaces"),
    (Tab::Settings, "Settings", "mpls.tab.settings"),
];

const NBR_CMDS: Cmds = Cmds {
    add: "mpls.ldp.neighbor.add",
    remove: "mpls.ldp.neighbor.remove",
    set: Some("mpls.ldp.neighbor.set"),
    what: "neighbors",
};

const IF_CMDS: Cmds = Cmds {
    add: "mpls.ldp.interface.add",
    remove: "mpls.ldp.interface.remove",
    set: Some("mpls.ldp.interface.set"),
    what: "interfaces",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input, edit: bool) -> Field {
    Field { param, label, help, input, edit }
}

const NBR_FIELDS: &[Field] = &[
    field("lsr_id", "LSR ID", "mpls.nbr.lsr_id", Input::Text("10.255.0.2"), false),
    field("targeted", "Targeted", "mpls.nbr.targeted", Input::Text("address for targeted Hellos (optional)"), true),
    field("password", "Password", "mpls.nbr.password", Input::Secret("TCP MD5 key (optional)"), true),
    field("keepalive_hold", "Keepalive Hold", "mpls.nbr.keepalive_hold", Input::Text("180 s"), true),
    field("disabled", "Disabled", "mpls.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

const IF_FIELDS: &[Field] = &[
    field("interface", "Interface", "mpls.if.interface", Input::Choice, false),
    field("hello_interval", "Hello Interval", "mpls.if.hello_interval", Input::Text("5 s"), true),
    field("hold_time", "Hold Time", "mpls.if.hold_time", Input::Text("15 s"), true),
    field("afi", "AFI", "mpls.afi", Input::Choice, true),
    field("disabled", "Disabled", "mpls.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

const NBR_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New LDP Neighbor",
    edit_title: "LDP Neighbor",
    help: "mpls.nbr",
    fields: NBR_FIELDS,
    preview: "mpls.ldp.neighbor.preview",
};

const IF_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New LDP Interface",
    edit_title: "LDP Interface",
    help: "mpls.if",
    fields: IF_FIELDS,
    preview: "mpls.ldp.interface.preview",
};

const NBR_COLUMNS: [table::Column; 9] = [
    col("State").help("mpls.nbr.state"),
    col("LSR ID").help("mpls.nbr.lsr_id"),
    col("Transport").help("mpls.nbr.transport"),
    col("AFI").help("mpls.afi"),
    col("Uptime").help("mpls.nbr.uptime"),
    num("Labels").help("mpls.nbr.labels"),
    num("In Use").help("mpls.nbr.in_use"),
    col("Flags").help("mpls.nbr.flags"),
    comment(),
];

const IF_COLUMNS: [table::Column; 9] = [
    col("State").help("mpls.if.state"),
    col("Interface").help("mpls.if.interface"),
    num("Hello").help("mpls.if.hello_interval"),
    num("Hold").help("mpls.if.hold_time"),
    num("Adjacencies").help("mpls.if.adjacencies"),
    col("Sync IGP").help("mpls.sync"),
    col("MTU").help("mpls.mtu"),
    col("AFI").help("mpls.afi"),
    comment(),
];

/// The Settings tab's form: (param, label, help, hint); `None` hint: a
/// checkbox.
const SETTINGS: &[(&str, &str, &str, Option<&str>)] = &[
    ("lsr_id", "LSR ID", "mpls.lsr_id", Some("10.255.0.1 (the loopback)")),
    ("afi", "AFI", "mpls.afi", Some("ip | ipv6 | ip,ipv6")),
    ("transport_addresses", "Transport Addresses", "mpls.transport", Some("the LSR ID; IPv6 needs one")),
    ("preferred_afi", "Preferred AFI", "mpls.preferred_afi", Some("ipv6 (RFC 7552)")),
    ("use_explicit_null", "Use Explicit Null", "mpls.explicit_null", None),
    ("igp_sync", "IGP Sync", "mpls.sync", None),
    ("igp_sync_holddown", "IGP Sync Holddown", "mpls.sync_holddown", Some("wait for LDP (s; empty: no limit)")),
    ("gtsm", "GTSM", "mpls.gtsm", None),
    ("disabled", "Disabled", "mpls.disabled", None),
];

const MPLS_SETTINGS: &[(&str, &str, &str, Option<&str>)] = &[
    ("dynamic_label_range", "Dynamic Label Range", "mpls.range", Some("16-1048575")),
    ("propagate_ttl", "Propagate TTL", "mpls.propagate_ttl", None),
    ("payload_mtu", "Payload MTU", "mpls.payload_mtu", Some("1500")),
];

#[derive(Default)]
pub(crate) struct LdpPanel {
    pub(crate) tab: Tab,
    pub(crate) instances: Vec<Value>,
    pub(crate) neighbors: Vec<Value>,
    pub(crate) interfaces: Vec<Value>,
    pub(crate) settings: Value,
    pub(crate) ifaces: Vec<String>,
    nbr_table: TableState,
    if_table: TableState,
    nbr_modal: Option<Modal>,
    if_modal: Option<Modal>,
    /// The Settings tab's fields, as typed; `None` until loaded.
    pub(crate) form: Option<BTreeMap<&'static str, String>>,
    help: Option<HelpView>,
    pub(crate) error: Option<String>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn yes(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool) == Some(true)
}

fn list_text(r: &Value, k: &str) -> String {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_text).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

fn state_kind(state: &str) -> Kind {
    match state {
        "operational" | "active" => Kind::Green,
        "disabled" | "no daemon" | "unknown" => Kind::Neutral,
        "down" | "not found" => Kind::Red,
        _ => Kind::Amber,
    }
}

fn nbr_row(r: &Value) -> Row {
    let state = s(r, "state");
    let mut flags: Vec<(&str, Kind)> = Vec::new();
    if yes(r, "dynamic") {
        flags.push(("dynamic", Kind::Neutral));
    }
    if !s(r, "targeted").is_empty() {
        flags.push(("targeted", Kind::Blue));
    }
    if yes(r, "password") {
        flags.push(("MD5", Kind::Blue));
    }
    let dash = |k: &str| r.get(k).and_then(Value::as_u64).map_or_else(|| "–".into(), |n| n.to_string());
    Row {
        key: s(r, "lsr_id"),
        cells: vec![
            cell("", &[(state.as_str(), state_kind(&state))]),
            s(r, "lsr_id"),
            s(r, "transport"),
            s(r, "afi"),
            s(r, "uptime"),
            dash("labels"),
            dash("in_use"),
            cell("", &flags),
            s(r, "comment"),
        ],
        dimmed: yes(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn if_row(r: &Value) -> Row {
    let state = s(r, "state");
    let sync = s(r, "igp_sync");
    let sync_cell = match sync.as_str() {
        "achieved" => cell("", &[("achieved", Kind::Green)]),
        "waiting" => cell("", &[("waiting for LDP", Kind::Amber)]),
        _ => String::new(),
    };
    let mtu = s(r, "mtu");
    let mtu_cell = match r.get("mtu_warning").and_then(Value::as_str) {
        // The mockup: "MTU 1500 < 1504" in a red chip, the rest in the tooltip.
        Some(w) => cell(&mtu, &[(w.split(':').next().unwrap_or(w), Kind::Red)]),
        None => mtu,
    };
    Row {
        key: s(r, "interface"),
        cells: vec![
            cell("", &[(state.as_str(), state_kind(&state))]),
            s(r, "interface"),
            s(r, "hello_interval"),
            s(r, "hold_time"),
            s(r, "adjacencies"),
            sync_cell,
            mtu_cell,
            list_text(r, "afi"),
            s(r, "comment"),
        ],
        dimmed: yes(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn values_of(fields: &[Field], r: &Value) -> BTreeMap<&'static str, String> {
    fields
        .iter()
        .map(|f| {
            let v = match (f.param, f.input) {
                (_, Input::Check) => if yes(r, f.param) { "yes" } else { "no" }.to_owned(),
                (_, Input::Secret(_)) => String::new(),
                ("afi", _) => list_text(r, "afi"),
                (p, _) => s(r, p),
            };
            (f.param, v)
        })
        .collect()
}

impl LdpPanel {
    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("mpls-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                self.info(ui, l, key, label);
                ui.add_space(6.0);
            }
        });
    }

    /// Instance state on top of every tab: running, which daemon, the
    /// commands' reason when the kernel has no MPLS.
    fn banner(&mut self, app: &CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        ui.horizontal_wrapped(|ui| {
            if self.settings.get("available").and_then(Value::as_bool) == Some(false) {
                chip::chip(ui, tr_in(SCOPE, l, "no MPLS in the kernel"), chip::RED.tone(&v));
                ui.weak(s(&self.settings, "why"));
                return;
            }
            match self.instances.first() {
                None => {
                    chip::chip(ui, tr_in(SCOPE, l, "off"), chip::neutral_tone(&v));
                    ui.weak(tr_in(SCOPE, l, "No LDP instance: set the LSR ID in the Settings tab."));
                }
                Some(i) => {
                    let st = s(i, "state");
                    let tone = match st.as_str() {
                        "running" => chip::GREEN.tone(&v),
                        "error" => chip::RED.tone(&v),
                        _ => chip::neutral_tone(&v),
                    };
                    chip::chip(ui, tr_in(SCOPE, l, match st.as_str() {
                        "running" => "running",
                        "disabled" => "disabled",
                        "error" => "error",
                        _ => "no daemon",
                    }), tone);
                    ui.label(format!("LSR ID {}", s(i, "lsr_id")));
                    if yes(i, "igp_sync") {
                        chip::chip(ui, "IGP sync", chip::BLUE.tone(&v)).on_hover_text("RFC 5443");
                    }
                    if yes(i, "gtsm") {
                        chip::chip(ui, "GTSM", chip::BLUE.tone(&v)).on_hover_text("RFC 6720");
                    }
                    if st == "no daemon" {
                        ui.weak(tr_in(SCOPE, l, "LDP runs in FRR's ldpd: start the daemon with --frr to see sessions."));
                    }
                    if let Some(e) = i.get("error").and_then(Value::as_str) {
                        ui.colored_label(v.error_fg_color, e);
                    }
                }
            }
        });
    }

    fn neighbors_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows: Vec<Row> = self.neighbors.iter().map(nbr_row).collect();
        let selection = self.nbr_table.selection(&rows);
        let picked: Vec<Item> = self
            .neighbors
            .iter()
            .filter(|r| selection.contains(&s(r, "lsr_id")))
            .map(|r| Item::of(r, "lsr_id", "discovered by Hello; add it to set a password or targeted Hellos"))
            .collect();
        let tools = Tools::new(&app.can(), &NBR_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, NEIGHBORS, &tools, &selection, l);
            table::find_field(ui, NEIGHBORS, &mut self.nbr_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 12.0;
        let out = table::show(ui, NEIGHBORS, footer_h, &mut self.nbr_table, &NBR_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Neighbor…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &NBR_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.neighbors.len(), "neighbors", chip::neutral_tone(&v)),
                (self.neighbors.iter().filter(|r| yes(r, "operational")).count(), "operational", chip::GREEN.tone(&v)),
                (
                    self.neighbors.iter().filter(|r| !yes(r, "operational") && !matches!(s(r, "state").as_str(), "disabled" | "no daemon")).count(),
                    "down",
                    chip::RED.tone(&v),
                ),
            ],
            l,
        );
        if self.neighbors.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No neighbor yet: LDP finds them by Hello on its interfaces; + adds one for a password or targeted Hellos."));
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows, true);
        }
    }

    fn interfaces_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows: Vec<Row> = self.interfaces.iter().map(if_row).collect();
        let selection = self.if_table.selection(&rows);
        let picked: Vec<Item> = self
            .interfaces
            .iter()
            .filter(|r| selection.contains(&s(r, "interface")))
            .map(|r| Item::of(r, "interface", ""))
            .collect();
        let tools = Tools::new(&app.can(), &IF_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, INTERFACES, &tools, &selection, l);
            table::find_field(ui, INTERFACES, &mut self.if_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 12.0;
        let out = table::show(ui, INTERFACES, footer_h, &mut self.if_table, &IF_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Interface…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &IF_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.interfaces.len(), "interfaces", chip::neutral_tone(&v)),
                (list::count(&self.interfaces, "state", "active"), "active", chip::GREEN.tone(&v)),
                (self.interfaces.iter().filter(|r| s(r, "igp_sync") == "waiting").count(), "waiting for LDP", chip::AMBER.tone(&v)),
                (self.interfaces.iter().filter(|r| r.get("mtu_warning").is_some_and(|w| !w.is_null())).count(), "MTU too small", chip::RED.tone(&v)),
            ],
            l,
        );
        if self.interfaces.is_empty() {
            ui.weak(tr_in(SCOPE, l, "LDP runs on no interface yet: + adds the links towards the other LSRs."));
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows, false);
        }
    }

    fn form(&mut self) -> &mut BTreeMap<&'static str, String> {
        let inst = self.instances.first().cloned().unwrap_or(Value::Null);
        let st = self.settings.clone();
        self.form.get_or_insert_with(|| {
            let mut f = BTreeMap::new();
            for (p, _, _, hint) in SETTINGS {
                let v = match (*p, hint) {
                    ("afi" | "transport_addresses", _) => list_text(&inst, p),
                    (_, None) => {
                        // RFC 5443 and RFC 6720 on by default.
                        let default = matches!(*p, "igp_sync" | "gtsm");
                        let on = inst.get(*p).and_then(Value::as_bool).unwrap_or(default);
                        if on { "yes" } else { "no" }.to_owned()
                    }
                    _ => s(&inst, p),
                };
                f.insert(*p, v);
            }
            for (p, _, _, hint) in MPLS_SETTINGS {
                let v = if hint.is_none() {
                    if st.get(*p).and_then(Value::as_bool).unwrap_or(true) { "yes" } else { "no" }.to_owned()
                } else {
                    s(&st, p)
                };
                f.insert(*p, v);
            }
            f
        })
    }

    fn settings_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let has = !self.instances.is_empty();
        let mut helps: Vec<(&'static str, &'static str)> = Vec::new();
        let form = self.form().clone();
        let mut edited = form.clone();
        for (title, rows, grid) in [("LDP", SETTINGS, "mpls-ldp-settings"), ("MPLS", MPLS_SETTINGS, "mpls-settings")] {
            ui.strong(title);
            Grid::new(grid).num_columns(3).spacing([8.0, 4.0]).show(ui, |ui| {
                for (p, label, key, hint) in rows {
                    ui.label(tr_in(SCOPE, l, label));
                    if help::info_button(ui, Id::unique(("mpls-set", *p)), tr_in(SCOPE, l, label)).clicked() {
                        helps.push((key, label));
                    }
                    let v = edited.entry(*p).or_default();
                    match hint {
                        None => {
                            let mut on = v == "yes";
                            if ui.checkbox(&mut on, "").changed() {
                                *v = if on { "yes" } else { "no" }.to_owned();
                            }
                        }
                        Some(h) => {
                            ui.add(TextEdit::singleline(v).hint_text(tr_in(SCOPE, l, h)).desired_width(240.0));
                        }
                    }
                    ui.end_row();
                }
            });
            ui.add_space(6.0);
        }
        if let Some((key, label)) = helps.pop() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
        }
        self.form = Some(edited.clone());
        let ldp_cmd = if has { "mpls.ldp.set" } else { "mpls.ldp.add" };
        let ready = !edited.get("lsr_id").is_none_or(|v| v.trim().is_empty());
        let can = if ready { app.can().check(ldp_cmd) } else { Err("type the LSR ID".to_owned()) };
        ui.horizontal(|ui| {
            if table::action(ui, tr_in(SCOPE, l, "Apply"), can) {
                let steps = settings_steps(&edited, has);
                self.error = None;
                app.run_steps(steps, crate::panel::then(NAME, SettingsApplied));
            }
            if has && table::action(ui, tr_in(SCOPE, l, "Remove LDP"), app.can().check("mpls.ldp.remove")) {
                app.run_then("mpls.ldp.remove", json!({}), crate::panel::then(NAME, SettingsApplied));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
    }

    fn column_help(&mut self, l: crate::i18n::Lang, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], nbr: bool) {
        let (data, key, cmds, fields) = if nbr {
            (&self.neighbors, "lsr_id", &NBR_CMDS, NBR_FIELDS)
        } else {
            (&self.interfaces, "interface", &IF_CMDS, IF_FIELDS)
        };
        let row_of = |k: &str| data.iter().find(|r| s(r, key) == k).cloned();
        let modal = if nbr { &mut self.nbr_modal } else { &mut self.if_modal };
        match act {
            Act::Add => {
                if modal.is_none() {
                    let mut values = BTreeMap::new();
                    values.insert("disabled", "no".to_owned());
                    *modal = Some(Modal::open(app, None, values));
                }
            }
            Act::Edit(k) => {
                if let Some(m) = modal {
                    m.status.bring_to_front();
                } else if let Some(r) = row_of(&k) {
                    // A discovered neighbor opens as a new one with its id.
                    let item = if nbr && yes(&r, "dynamic") { None } else { Some((k.clone(), k)) };
                    *modal = Some(Modal::open(app, item, values_of(fields, &r)));
                }
            }
            Act::Comment(keys) => {
                if let (Some(k), None) = (keys.into_iter().next(), modal.as_ref())
                    && let Some(r) = row_of(&k)
                {
                    *modal = Some(Modal::open(app, Some((k.clone(), k)), values_of(fields, &r)));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                let to = matches!(act, Act::Disable(_));
                let set = cmds.set.unwrap_or_default();
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": set, "params": {"id": k, "disabled": to}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys
                    .iter()
                    .filter_map(|k| row_of(k))
                    .map(|r| {
                        let mut p = serde_json::Map::new();
                        for f in fields.iter().filter(|f| !matches!(f.input, Input::Secret(_))) {
                            if let Some(v) = r.get(f.param).filter(|v| !v.is_null()) {
                                p.insert(f.param.into(), v.clone());
                            }
                        }
                        Value::Object(p)
                    })
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }
}

/// The commands of the Settings tab: the instance (add or set) and
/// `/mpls settings`, in one transaction.
pub(crate) fn settings_steps(f: &BTreeMap<&'static str, String>, has: bool) -> Vec<Value> {
    let get = |k: &str| f.get(k).map(|v| v.trim().to_owned()).unwrap_or_default();
    let mut ldp = serde_json::Map::new();
    for (p, _, _, hint) in SETTINGS {
        let v = get(p);
        let val = match (*p, hint) {
            (_, None) => json!(v == "yes"),
            ("igp_sync_holddown", _) if v.is_empty() => Value::Null,
            ("igp_sync_holddown", _) => v.trim_end_matches(" s").parse::<u64>().map_or_else(|_| json!(v), |n| json!(n)),
            ("preferred_afi", _) if v.is_empty() => Value::Null,
            ("transport_addresses", _) if v.is_empty() => json!([]),
            (_, _) if v.is_empty() => continue,
            _ => json!(v),
        };
        if !has && val.is_null() {
            continue;
        }
        ldp.insert((*p).into(), val);
    }
    let mut set = serde_json::Map::new();
    for (p, _, _, hint) in MPLS_SETTINGS {
        let v = get(p);
        match (*p, hint) {
            (_, None) => {
                set.insert((*p).into(), json!(v == "yes"));
            }
            (_, _) if v.is_empty() => {}
            ("payload_mtu", _) => {
                set.insert((*p).into(), v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n)));
            }
            _ => {
                set.insert((*p).into(), json!(v));
            }
        }
    }
    vec![
        json!({"command": "mpls.settings.set", "params": set}),
        json!({"command": if has { "mpls.ldp.set" } else { "mpls.ldp.add" }, "params": ldp}),
    ]
}

/// The reply of the Settings tab's Apply.
struct SettingsApplied;

impl PanelState for LdpPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut q = vec![("instances", "mpls.ldp.list"), ("settings", "mpls.settings.get")];
        match self.tab {
            Tab::Neighbors => q.push(("neighbors", "mpls.ldp.neighbor.list")),
            Tab::Interfaces => {
                q.push(("interfaces", "mpls.ldp.interface.list"));
                q.push(("ifaces", "interface.list"));
            }
            Tab::Settings => {}
        }
        q.into_iter()
            .filter(|(_, c)| app.has_command(c))
            .map(|(key, command)| Query { key, command, params: json!({}) })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let arr = |v: &Value| v.as_array().cloned().unwrap_or_default();
        match key {
            list_modal::PREVIEW => {
                for m in [&mut self.nbr_modal, &mut self.if_modal].into_iter().flatten() {
                    m.arrived(value.clone());
                }
            }
            "instances" => self.instances = arr(&value),
            "settings" => self.settings = value,
            "neighbors" => self.neighbors = arr(&value),
            "interfaces" => self.interfaces = arr(&value),
            "ifaces" => {
                self.ifaces = arr(&value).iter().map(|r| s(r, "name")).filter(|n| !n.is_empty()).collect();
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        self.banner(app, ui);
        ui.separator();
        match self.tab {
            Tab::Neighbors => self.neighbors_tab(app, ui),
            Tab::Interfaces => self.interfaces_tab(app, ui),
            Tab::Settings => self.settings_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.nbr_modal
            && !m.show(app, ctx, area, &NBR_SPEC, &|_| Vec::new())
        {
            self.nbr_modal = None;
        }
        let ifaces = self.ifaces.clone();
        let options = move |p: &str| -> Vec<String> {
            match p {
                "interface" => ifaces.clone(),
                "afi" => ["", "ip", "ipv6", "ip,ipv6"].iter().map(|x| (*x).to_owned()).collect(),
                _ => Vec::new(),
            }
        };
        if let Some(m) = &mut self.if_modal
            && !m.show(app, ctx, area, &IF_SPEC, &options)
        {
            self.if_modal = None;
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<SettingsApplied>().is_some() {
            match result {
                Ok(_) => {
                    self.error = None;
                    // Read the form again from the router.
                    self.form = None;
                }
                Err(e) => self.error = Some(e.clone()),
            }
            app.cache.refreshed_at = None;
            return;
        }
        if let Some(a) = then.downcast_ref::<Applied>() {
            for slot in [&mut self.nbr_modal, &mut self.if_modal] {
                if slot.as_mut().is_some_and(|m| m.id == a.0 && m.replied(app, result)) {
                    *slot = None;
                }
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Neighbors => self.nbr_table.escape(),
            Tab::Interfaces => self.if_table.escape(),
            Tab::Settings => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(NEIGHBORS, &self.nbr_table), (INTERFACES, &self.if_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(NEIGHBORS, &mut self.nbr_table), (INTERFACES, &mut self.if_table)]
    }
}

#[cfg(test)]
impl LdpPanel {
    /// Every explanation key the window uses (the test checks both languages).
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut k: Vec<&'static str> = vec!["menu.mpls-ldp", NBR_SPEC.help, IF_SPEC.help];
        k.extend(TABS.iter().map(|t| t.2));
        k.extend(NBR_FIELDS.iter().chain(IF_FIELDS).map(|f| f.help).filter(|h| !h.is_empty()));
        k.extend(NBR_COLUMNS.iter().chain(&IF_COLUMNS).map(|c| c.help).filter(|h| !h.is_empty()));
        k.extend(SETTINGS.iter().chain(MPLS_SETTINGS).map(|s| s.2));
        k
    }
}

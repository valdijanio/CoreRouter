//! Routing › RPKI (G3.2c), RouterOS v7 `/routing rpki`: the RTR validators
//! in the list window pattern (G0.24) with their live sessions (state,
//! protocol version, serial, VRPs), what the policy does on each BGP
//! connection (reject or accept invalid routes, and the eBGP ones that wait
//! for a policy), and `rpki-check` for one prefix and origin.
//! `routing.rpki.*` decides; this only shows and sends.

use std::collections::BTreeMap;

use egui::{Id, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::bgp_routes::rpki_kind;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};


pub(crate) const NAME: &str = "rpki";
pub(crate) const WIN: &str = "rpki";
const SCOPE: &str = "rpki";
const TABLE: &str = "rpki-validators";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Routing",
        title: "RPKI",
        size: [960.0, 560.0],
        escape: true,
    }],
    new: || Box::<RpkiPanel>::default(),
};

const CMDS: Cmds = Cmds {
    add: "routing.rpki.add",
    remove: "routing.rpki.remove",
    set: Some("routing.rpki.set"),
    what: "validators",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input) -> Field {
    Field {
        param,
        label,
        help,
        input,
        edit: true,
    }
}

const FIELDS: &[Field] = &[
    field("name", "Name", "rpki.name", Input::Text("routinator1")),
    field("address", "Address", "rpki.address", Input::Text("192.0.2.10")),
    field("port", "Port", "rpki.port", Input::Text("323")),
    field("group", "Group", "rpki.group", Input::Text("default")),
    field("refresh_interval", "Refresh Interval", "rpki.refresh_interval", Input::Text("the validator's (s)")),
    field("retry_interval", "Retry Interval", "rpki.retry_interval", Input::Text("the validator's (s)")),
    field("expire_interval", "Expire Interval", "rpki.expire_interval", Input::Text("the validator's (s)")),
    field("preference", "Preference", "rpki.preference", Input::Text("higher wins (0..254)")),
    field("disabled", "Disabled", "rpki.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New RPKI Validator",
    edit_title: "RPKI Validator",
    help: "rpki",
    fields: FIELDS,
    preview: "routing.rpki.preview",
};

const COLUMNS: [table::Column; 10] = [
    col("State").help("rpki.state"),
    col("Name").help("rpki.name"),
    col("Address").help("rpki.address"),
    col("Group").help("rpki.group"),
    num("Version").help("rpki.version"),
    num("Serial").help("rpki.serial"),
    num("IPv4 VRPs").help("rpki.vrps"),
    num("IPv6 VRPs").help("rpki.vrps"),
    col("Error").help("rpki.error"),
    comment(),
];

#[derive(Default)]
pub(crate) struct RpkiPanel {
    pub(crate) validators: Vec<Value>,
    pub(crate) sessions: Value,
    table: TableState,
    pub(crate) modal: Option<Modal>,
    pub(crate) prefix: String,
    pub(crate) origin: String,
    pub(crate) check: Option<Value>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn dash(r: &Value, k: &str) -> String {
    r.get(k).and_then(Value::as_u64).map_or_else(|| "–".into(), |n| n.to_string())
}

fn state_kind(state: &str) -> Kind {
    match state {
        "sync" => Kind::Green,
        "error" => Kind::Red,
        "disabled" | "unknown" => Kind::Neutral,
        _ => Kind::Amber,
    }
}

fn row(r: &Value) -> Row {
    let state = s(r, "state");
    let shown = if state == "unknown" { "no daemon".to_owned() } else { state.clone() };
    Row {
        key: s(r, "name"),
        cells: vec![
            cell("", &[(shown.as_str(), state_kind(&state))]),
            s(r, "name"),
            format!("{}:{}", s(r, "address"), s(r, "port")),
            s(r, "group"),
            dash(r, "version"),
            dash(r, "serial"),
            dash(r, "ipv4"),
            dash(r, "ipv6"),
            s(r, "error"),
            s(r, "comment"),
        ],
        dimmed: state == "disabled",
        section: false,
        tint: None,
    }
}

fn values_of(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in FIELDS {
        let text = match f.param {
            "disabled" => if r.get("disabled").and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned(),
            p => s(r, p),
        };
        v.insert(f.param, text);
    }
    v
}

impl RpkiPanel {
    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("rpki-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    /// What the policy does now, on top: on or off, and on which connections.
    fn policy(&mut self, ui: &mut Ui, l: crate::i18n::Lang) {
        let p = self.sessions.get("policy").cloned().unwrap_or_default();
        let names = |k: &str| -> Vec<String> {
            p.get(k)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default()
        };
        let v = ui.visuals().clone();
        ui.horizontal_wrapped(|ui| {
            self.info(ui, l, "rpki.policy", "Policy");
            if p.get("active").and_then(Value::as_bool) == Some(true) {
                chip::chip(ui, tr_in(SCOPE, l, "on: invalid routes rejected"), chip::GREEN.tone(&v));
            } else {
                chip::chip(ui, tr_in(SCOPE, l, "off: no validator"), chip::AMBER.tone(&v));
                ui.weak(tr_in(SCOPE, l, "Add a validator to reject routes whose origin a ROA contradicts."));
            }
            for (key, label, tone) in [
                ("rejecting", "reject", chip::GREEN.tone(&v)),
                ("accepting", "accept", chip::AMBER.tone(&v)),
                ("ebgp_waiting", "waits for a policy", chip::neutral_tone(&v)),
            ] {
                let n = names(key);
                if !n.is_empty() {
                    chip::chip(ui, &format!("{} {}", n.len(), tr_in(SCOPE, l, label)), tone).on_hover_text(n.join(", "));
                }
            }
        });
        if let Some(frr) = self.sessions.get("frr").and_then(Value::as_str).map(str::to_owned) {
            ui.horizontal(|ui| {
                ui.weak(tr_in(SCOPE, l, "FRR bgpd:"));
                ui.label(RichText::new(frr.as_str()).small());
                self.info(ui, l, "rpki.frr", "FRR");
            });
        }
    }

    fn check_box(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr_in(SCOPE, l, "RPKI Check")).strong());
            self.info(ui, l, "rpki.check", "RPKI Check");
            ui.add(TextEdit::singleline(&mut self.prefix).hint_text("192.0.2.0/24").desired_width(150.0));
            ui.add(TextEdit::singleline(&mut self.origin).hint_text(tr_in(SCOPE, l, "origin AS or AS path")).desired_width(150.0));
            let ready = !self.prefix.trim().is_empty() && !self.origin.trim().is_empty();
            let can = if ready { app.can().check("routing.rpki.check") } else { Err("type a prefix and an origin AS".to_owned()) };
            if table::action(ui, tr_in(SCOPE, l, "Check"), can) {
                let origin = self.origin.trim();
                let origin = origin.parse::<u64>().map_or_else(|_| json!(origin), |n| json!(n));
                app.run_then(
                    "routing.rpki.check",
                    json!({"prefix": self.prefix.trim(), "origin_as": origin}),
                    crate::panel::then(NAME, Checked),
                );
            }
        });
        if let Some(c) = &self.check {
            ui.horizontal_wrapped(|ui| {
                let state = s(c, "state");
                ui.label(cell("", &[]));
                let v = ui.visuals().clone();
                let tone = match rpki_kind(&state) {
                    Kind::Green => chip::GREEN.tone(&v),
                    Kind::Red => chip::RED.tone(&v),
                    Kind::Amber => chip::AMBER.tone(&v),
                    _ => chip::neutral_tone(&v),
                };
                chip::chip(ui, tr_in(SCOPE, l, match state.as_str() {
                    "valid" => "valid",
                    "invalid" => "invalid",
                    "unverified" => "unverified",
                    _ => "unknown",
                }), tone);
                ui.label(s(c, "reason"));
            });
            for vrp in c.get("covering").and_then(Value::as_array).into_iter().flatten().take(20) {
                let ok = vrp.get("matches").and_then(Value::as_bool) == Some(true);
                ui.horizontal(|ui| {
                    ui.monospace(format!("{}-{} AS{}", s(vrp, "prefix"), s(vrp, "max_length"), s(vrp, "asn")));
                    if ok {
                        ui.weak(tr_in(SCOPE, l, "matches"));
                    }
                });
            }
        }
    }

    fn edit(&mut self, app: &mut CoreRouterUi, k: String) {
        if let Some(m) = &mut self.modal {
            m.status.bring_to_front();
        } else if let Some(r) = self.validators.iter().find(|r| s(r, "name") == k).cloned() {
            self.modal = Some(Modal::open(app, Some((k.clone(), k)), values_of(&r)));
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        let row_of = |k: &str| self.validators.iter().find(|r| s(r, "name") == k).cloned();
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut values = BTreeMap::new();
                    values.insert("port", "323".to_owned());
                    values.insert("group", "default".to_owned());
                    values.insert("disabled", "no".to_owned());
                    self.modal = Some(Modal::open(app, None, values));
                }
            }
            Act::Edit(k) => self.edit(app, k),
            Act::Comment(keys) => {
                if let Some(k) = keys.into_iter().next() {
                    self.edit(app, k);
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": CMDS.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                let to = matches!(act, Act::Disable(_));
                let steps: Vec<Value> = keys
                    .iter()
                    .map(|k| json!({"command": "routing.rpki.set", "params": {"id": k, "disabled": to}}))
                    .collect();
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
                        let mut p = json!({});
                        if let Some(o) = p.as_object_mut() {
                            for k in ["name", "address", "port", "group", "refresh_interval", "retry_interval", "expire_interval", "preference", "disabled", "comment"] {
                                if let Some(v) = r.get(k).filter(|v| !v.is_null()) {
                                    o.insert(k.into(), v.clone());
                                }
                            }
                        }
                        p
                    })
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &refs, syntax));
            }
        }
    }
}

/// The reply of a `routing.rpki.check`.
struct Checked;

impl PanelState for RpkiPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        [("validators", "routing.rpki.list"), ("sessions", "routing.rpki.session.list")]
            .into_iter()
            .filter(|(_, c)| app.has_command(c))
            .map(|(key, command)| Query {
                key,
                command,
                params: json!({}),
            })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            "validators" => self.validators = value.as_array().cloned().unwrap_or_default(),
            "sessions" => self.sessions = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.policy(ui, l);
        ui.separator();
        let rows: Vec<Row> = self.validators.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<Item> = self
            .validators
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 4.0 + 24.0;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Validator…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let vrps: u64 = self
            .validators
            .iter()
            .filter(|r| s(r, "state") == "sync")
            .map(|r| r.get("ipv4").and_then(Value::as_u64).unwrap_or(0) + r.get("ipv6").and_then(Value::as_u64).unwrap_or(0))
            .max()
            .unwrap_or(0);
        list::footer(
            ui,
            &[
                (self.validators.len(), "validators", chip::neutral_tone(&v)),
                (list::count(&self.validators, "state", "sync"), "in sync", chip::GREEN.tone(&v)),
                (list::count(&self.validators, "state", "error"), "error", chip::RED.tone(&v)),
                (usize::try_from(vrps).unwrap_or(0), "VRPs", chip::BLUE.tone(&v)),
            ],
            l,
        );
        if self.validators.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No validator yet: + adds one (Routinator, rpki-client, StayRTR, FORT…)."));
        }
        ui.separator();
        self.check_box(app, ui);
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.modal
            && !m.show(app, ctx, area, &SPEC, &|_| Vec::new())
        {
            self.modal = None;
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Checked>().is_some() {
            self.check = Some(match result {
                Ok(v) => v.clone(),
                Err(e) => json!({"state": "unknown", "reason": e}),
            });
            return;
        }
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table)]
    }
}

//! IP › Services (G1.6p), WinBox `/ip service` style: `www-ssl`, `www` and
//! `metrics`, one row each, with status, port, address, `available_from`,
//! refused clients and the last error. There is nothing to add or remove,
//! as in RouterOS; ✓ ✗ turn a service on and off, a double click edits it.
//!
//! The engine decides: `ip.service.print` says which row carries this
//! session, `ip.service.check` is the modal's preview and a change that would
//! lose the next login comes back as `lockout:`, which the app's window asks
//! about (Safe Mode, Apply anyway, Cancel; `lockout.rs`).

use std::collections::BTreeMap;

use egui::Ui;
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Syntax, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{self, Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "ip-services";
pub(crate) const WIN: &str = "ip-services";
const TABLE: &str = "ip-services";
const SCOPE: &str = "ip_services";
const PRINT: &str = "ip.service.print";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef { id: WIN, group: "IP", title: "IP Services", size: [860.0, 300.0], escape: true }],
    new: || Box::new(ServicesPanel::default()),
};

/// `add` and `remove` name no command: the buttons are grey, with [`FIXED`].
const CMDS: Cmds = Cmds { add: "", remove: "", set: Some("ip.service.www-ssl.set"), what: "services" };
const FIXED: &str = "the services are fixed, as in RouterOS: turn one on or off, or edit it";

const FIELDS: &[Field] = &[
    Field { param: "enabled", label: "Enabled", help: "ip_services.enabled", input: Input::Check, edit: true },
    Field { param: "address", label: "Address", help: "ip_services.address", input: Input::Text(":: (every address)"), edit: true },
    Field { param: "port", label: "Port", help: "ip_services.port", input: Input::Text("443"), edit: true },
    Field { param: "available_from", label: "Available From", help: "ip_services.available_from", input: Input::Text("192.0.2.0/24, 2001:db8::/32"), edit: true },
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "IP Service",
    edit_title: "IP Service",
    help: "menu.ip-services",
    fields: FIELDS,
    preview: "ip.service.check",
};

const COLUMNS: [table::Column; 7] = [
    col("Name").help("ip_services.name"),
    col("Status").help("ip_services.status"),
    col("Address").help("ip_services.address"),
    num("Port").help("ip_services.port"),
    col("Available From").help("ip_services.available_from"),
    num("Refused").help("ip_services.refused"),
    col("Last Error").help("ip_services.last_error"),
];

#[derive(Default)]
pub(crate) struct ServicesPanel {
    pub(crate) rows: Vec<Value>,
    table: TableState,
    pub(crate) modal: Option<Modal>,
    help: Option<HelpView>,
    notice: Option<String>,
    error: Option<String>,
}

/// The reply of ✓ or ✗ on a service.
struct Toggled(String);

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(crate::value_text).unwrap_or_default()
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn from_list(r: &Value) -> String {
    r.get("available_from")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

fn status_kind(status: &str) -> Kind {
    match status {
        "listening" => Kind::Green,
        "error" => Kind::Red,
        _ => Kind::Neutral,
    }
}

/// `::` and `0.0.0.0` read as what they mean.
fn address_text(r: &Value) -> String {
    let a = s(r, "address");
    if a == "::" || a == "0.0.0.0" { format!("{a} (all)") } else { a }
}

pub(crate) fn row(r: &Value, l: crate::i18n::Lang) -> Row {
    let status = s(r, "status");
    let name_chips: Vec<(&str, Kind)> =
        if flag(r, "this_session") { vec![(tr_in(SCOPE, l, "this session"), Kind::Blue)] } else { Vec::new() };
    let from = from_list(r);
    let dash = |text: String| if text.is_empty() { "–".to_owned() } else { text };
    Row {
        key: s(r, "name"),
        cells: vec![
            cell(&s(r, "name"), &name_chips),
            cell("", &[(status.as_str(), status_kind(&status))]),
            address_text(r),
            s(r, "port"),
            if from.is_empty() { tr_in(SCOPE, l, "everyone").to_owned() } else { from },
            s(r, "refused"),
            dash(r.get("last_error").and_then(Value::as_str).unwrap_or("").to_owned()),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn values_of(r: &Value) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("enabled", if flag(r, "enabled") { "yes" } else { "no" }.to_owned()),
        ("address", s(r, "address")),
        ("port", s(r, "port")),
        ("available_from", from_list(r)),
    ])
}

fn set_of(name: &str) -> String {
    format!("ip.service.{name}.set")
}

impl ServicesPanel {
    fn row_of(&self, name: &str) -> Option<&Value> {
        self.rows.iter().find(|r| s(r, "name") == name)
    }

    fn tools(&self, app: &CoreRouterUi, picked: &[Item]) -> Tools {
        let mut tools = Tools::new(&app.can(), &CMDS, picked);
        tools.add = Err(FIXED.to_owned());
        tools.remove = Err(FIXED.to_owned());
        tools.comment = Err("a service has no comment".to_owned());
        tools
    }

    /// One command per service: the lockout window asks about a single one.
    fn toggle(&mut self, app: &mut CoreRouterUi, keys: &[String], enabled: bool) {
        self.notice = None;
        self.error = None;
        for k in keys {
            app.run_then(&set_of(k), json!({"enabled": enabled}), panel::then(NAME, Toggled(k.clone())));
        }
        app.cache.refreshed_at = None;
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        match act {
            Act::Enable(keys) => self.toggle(app, &keys, true),
            Act::Disable(keys) => self.toggle(app, &keys, false),
            Act::Edit(k) => {
                if let Some(m) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = self.row_of(&k) {
                    let values = values_of(r);
                    self.modal = Some(Modal::open(app, Some((k.clone(), k)), values));
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => ui.ctx().copy_text(self.commands(app, &keys, syntax)),
            Act::Add | Act::Remove(_) | Act::Comment(_) => {}
        }
    }

    /// The `set` of each service, as it stands.
    fn commands(&self, app: &CoreRouterUi, keys: &[String], syntax: Syntax) -> String {
        keys.iter()
            .filter_map(|k| self.row_of(k).map(|r| list::copy_commands(app, &set_of(k), &[r], syntax)))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl PanelState for ServicesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) && app.has_command(PRINT) {
            vec![Query { key: "print", command: PRINT, params: json!({}) }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some(m) = &mut self.modal {
                m.arrived(value);
            }
        } else if key == "print"
            && let Some(rows) = value.as_array()
        {
            self.rows = rows.clone();
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.rows.clone();
        let rows: Vec<Row> = all.iter().map(|r| row(r, l)).collect();
        let selection = self.table.selection(&rows);
        let pick = |sel: &[String]| -> Vec<Item> {
            all.iter()
                .filter(|r| sel.contains(&s(r, "name")))
                .map(|r| Item::of(r, "name", ""))
                .collect()
        };
        let tools = self.tools(app, &pick(selection.as_slice()));
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            let title = tr_in(SCOPE, l, "IP Services");
            if help::info_button(ui, egui::Id::unique("ip-services-help"), title).clicked() {
                self.help = Some(HelpView::new("menu.ip-services", title));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        if let Some(r) = all.iter().find(|r| flag(r, "this_session")) {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!(
                    "{} {}. {}",
                    tr_in(SCOPE, l, "This window reaches the router through"),
                    s(r, "name"),
                    tr_in(SCOPE, l, "Turning it off, moving it or leaving your address out of Available From blocks your next login."),
                ),
            );
        }
        if let Some(n) = &self.notice {
            ui.weak(n);
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let can = app.can();
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu {
                let picked = pick(sel.as_slice());
                let mut tools = Tools::new(&can, &CMDS, &picked);
                tools.add = Err(FIXED.to_owned());
                tools.remove = Err(FIXED.to_owned());
                tools.comment = Err("a service has no comment".to_owned());
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        let act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "services", chip::neutral_tone(&v)),
                (list::count(&all, "status", "listening"), "listening", chip::GREEN.tone(&v)),
                (list::count(&all, "status", "error"), "error", chip::RED.tone(&v)),
            ],
            l,
        );
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
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        if let Some(t) = then.downcast_ref::<Toggled>() {
            match result {
                Ok(v) => self.notice = v.get("warning").and_then(Value::as_str).map(str::to_owned),
                Err(e) => self.error = Some(format!("{}: {}", t.0, e.chars().take(300).collect::<String>())),
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        false
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table)]
    }
}

#[cfg(test)]
impl ServicesPanel {
    /// What a button of the bar or a double click does.
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, act: Act) {
        match act {
            Act::Enable(keys) => self.toggle(app, &keys, true),
            Act::Disable(keys) => self.toggle(app, &keys, false),
            Act::Edit(k) => {
                let values = self.row_of(&k).map(values_of).unwrap_or_default();
                self.modal = Some(Modal::open(app, Some((k.clone(), k)), values));
            }
            _ => {}
        }
    }
}

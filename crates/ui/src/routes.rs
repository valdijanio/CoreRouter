//! The IP › Routes window, WinBox style: static routes and the connected
//! routes the router derives from its addresses, with the toolbar, context
//! menus, "New Route" and "Route <dst>" windows of the G1.9 table.
//!
//! Flags and the "reachable"/"unreachable" hints come from `ip.route.list`;
//! the engine decides them. Every change goes through `CoreRouterUi::run`.

use egui::{Grid, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::dialog::{self, Buttons, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id, opt_text};
use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment, num};
use crate::{CoreRouterUi, Then, form_number, value_text};

pub(crate) const TABLE: &str = "routes";
/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;
const MAIN: &str = "main";

const COLUMNS: [table::Column; 6] = [
    col(""),
    col("Dst. Address"),
    col("Gateway"),
    num("Distance"),
    col("Routing Table"),
    comment(),
];

/// One row of `ip.route.list`, as the window needs it.
#[derive(Clone, Default)]
pub(crate) struct Route {
    /// Table key: the static route id, or a made-up key for a connected one.
    pub key: String,
    /// `*N` of a static route; `None` for a connected route.
    pub id: Option<String>,
    pub dst: String,
    pub gateway: String,
    pub distance: String,
    pub table: String,
    pub flags: String,
    pub active: bool,
    pub disabled: bool,
    pub immediate: Option<String>,
    pub reason: Option<String>,
    pub comment: String,
}

impl Route {
    fn from_row(row: &Value) -> Self {
        let text = |k: &str| row.get(k).map(value_text).unwrap_or_default();
        let opt = |k: &str| row.get(k).filter(|v| !v.is_null()).map(value_text);
        let flag = |k: &str| row.get(k).and_then(Value::as_bool).unwrap_or(false);
        let id = opt("id");
        let key = id.clone().unwrap_or_else(|| {
            format!(
                "connected {} {} {}",
                text("routing_table"),
                text("dst_address"),
                text("gateway")
            )
        });
        Self {
            key,
            id,
            dst: text("dst_address"),
            gateway: text("gateway"),
            distance: text("distance"),
            table: text("routing_table"),
            flags: text("flags"),
            active: flag("active"),
            disabled: flag("disabled"),
            immediate: opt("immediate_gw"),
            reason: opt("reason"),
            comment: text("comment"),
        }
    }

    fn is_static(&self) -> bool {
        self.id.is_some()
    }

    /// WinBox's gateway column: "10.0.0.1 reachable ether1".
    fn gateway_text(&self) -> String {
        match &self.immediate {
            Some(via) => {
                let link = via.rsplit('%').next().unwrap_or(via);
                if link == self.gateway {
                    self.gateway.clone()
                } else {
                    format!("{} reachable {link}", self.gateway)
                }
            }
            None if self.disabled || !self.is_static() => self.gateway.clone(),
            None => format!("{} unreachable", self.gateway),
        }
    }

    fn status(&self) -> String {
        match (&self.reason, self.active) {
            (_, true) => "active".into(),
            (Some(why), false) => why.clone(),
            (None, false) => "inactive".into(),
        }
    }
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
}

/// The buttons of a "Route <dst>" window besides OK/Cancel/Apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
}

impl CoreRouterUi {
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
        let routes = self.route_rows();
        let rows: Vec<Row> = routes.iter().map(route_row).collect();
        let selection = self.tables.routes.selection(&rows);
        let picked: Vec<&Route> = routes
            .iter()
            .filter(|r| selection.contains(&r.key))
            .collect();
        let mut act: Option<Act> = None;

        ui.horizontal(|ui| {
            if table::tool(ui, TABLE, Icon::Add, "Add", Ok(())).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (Icon::Remove, "Remove", only_static(&picked)),
                (Icon::Enable, "Enable", can_enable(&picked, true)),
                (Icon::Disable, "Disable", can_enable(&picked, false)),
                (Icon::Comment, "Comment", only_static(&picked)),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
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
        ui.separator();

        let out = table::show(
            ui,
            TABLE,
            0.0,
            &mut self.tables.routes,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => row_menu(ui, &mut act, &routes, sel),
                Menu::Empty => {
                    if ui.button("Add Route…").clicked() {
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
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        // Double click on an inline comment: only static routes have one.
        if let Some(key) = out.comment {
            act = Some(Act::Comment(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.tables.routes.selection(&rows);
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
            .filter_map(|k| routes.iter().find(|r| r.key == *k)?.id.clone())
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

    /// "Route <dst>"; an already open one is not duplicated.
    pub(crate) fn open_route(&mut self, key: &str) {
        let Some(r) = self.route(key) else { return };
        let open = self.route_dialogs.iter().any(|d| match &d.dialog {
            RouteDialog::Props { id, .. } => r.id.as_deref() == Some(id.as_str()),
            RouteDialog::Connected(k) => *k == r.key,
            _ => false,
        });
        if open {
            return;
        }
        let dialog = match &r.id {
            Some(id) => RouteDialog::Props {
                id: id.clone(),
                form: RouteForm::of(&r),
                base: RouteForm::of(&r),
            },
            None => RouteDialog::Connected(r.key.clone()),
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
            let head = Head {
                id,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
            };
            let pressed =
                dialog::show(&mut self.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(ui, f, &mut d.dialog, &routes, &tables)
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

fn route_row(r: &Route) -> Row {
    Row {
        key: r.key.clone(),
        cells: vec![
            r.flags.clone(),
            r.dst.clone(),
            r.gateway_text(),
            r.distance.clone(),
            r.table.clone(),
            r.comment.clone(),
        ],
        dimmed: r.disabled,
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
        Err("Connected routes come from IP addresses: change the address instead".into())
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

fn row_menu(ui: &mut Ui, act: &mut Option<Act>, routes: &[Route], sel: &[String]) {
    let picked: Vec<&Route> = routes.iter().filter(|r| sel.contains(&r.key)).collect();
    let owned = || sel.to_vec();
    if action(ui, "Enable", can_enable(&picked, true)) {
        *act = Some(Act::Enable(owned()));
    }
    if action(ui, "Disable", can_enable(&picked, false)) {
        *act = Some(Act::Disable(owned()));
    }
    if action(ui, "Remove", only_static(&picked)) {
        *act = Some(Act::Remove(owned()));
    }
    if action(ui, "Comment…", only_static(&picked)) {
        *act = Some(Act::Comment(owned()));
    }
    if action(ui, "Properties…", some(&picked)) {
        *act = Some(Act::Open(owned()));
    }
    ui.separator();
    if ui.button("Add Route…").clicked() {
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
) -> Footer<Button> {
    let mut toggle_label = None;
    let mut view_only = false;
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
                    ui.label("Status");
                    ui.weak(format!("connected, {}", r.status()));
                    ui.end_row();
                }
            }
            RouteDialog::Comment { text, .. } => f.text(ui, "Comment", "comment", text, ""),
        });
    if view_only {
        ui.weak("Connected routes follow their IP address (IP › Addresses).");
        return Footer {
            buttons: Buttons::View,
            extra: Vec::new(),
            pressed: None,
        };
    }
    let mut footer = Footer::edit(!matches!(d, RouteDialog::Comment { .. }));
    if let Some(t) = toggle_label {
        footer.extra = vec![(t, Button::Toggle), ("Remove", Button::Remove)];
    }
    footer
}

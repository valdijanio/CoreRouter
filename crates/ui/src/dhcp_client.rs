//! The IP › DHCP Client window (G4.7), WinBox style: one client per
//! interface with its status and lease, the toolbar, menus and keys of the
//! G1.9 table, and "New DHCP Client" / "DHCP Client <iface>" windows with
//! the tabs DHCP, Status, Advanced and Options (what the server sent).
//!
//! Status, lease and routes come from `ip.dhcp-client.list` / `.options`;
//! the engine decides them. Every change goes through `CoreRouterUi::run`.
//! The clients' history (`ip.dhcp-client.history`) feeds the Log window.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use std::collections::BTreeMap;

use egui::{Grid, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment};
use crate::{CoreRouterUi, LogLine, Win, form_number, value_text};

const NAME: &str = "dhcp-client";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "dhcp-client";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DHCP Client",
        size: [760.0, 260.0],
        escape: true,
    }],
    new: || Box::new(DhcpPanel::default()),
};

/// IP › DHCP Client: rows, dialogs and table, kept here.
#[derive(Default)]
pub(crate) struct DhcpPanel {
    /// `ip.dhcp-client.list`, while the window or a dialog is open.
    clients: Vec<Value>,
    /// `ip.dhcp-client.options` replies by client id.
    options: BTreeMap<String, Value>,
    /// Last history event logged (`None` before the first look).
    seq: Option<u64>,
    pub(crate) dialogs: Vec<DhcpDialogWin>,
    /// Clients to open once a list sent after this request arrives.
    open_after: Vec<(RequestId, String)>,
    pub(crate) table: TableState,
}

/// What a dialog's command changes when it is answered.
struct Reply {
    id: u64,
    effect: Effect,
}

impl PanelState for DhcpPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if app.open.contains(&crate::Win::Panel(WIN)) || !self.dialogs.is_empty() {
            out.push(Query {
                key: "list",
                command: "ip.dhcp-client.list",
                params: Value::Null,
            });
        }
        for c in self.dialogs.iter().filter_map(|d| d.dialog.options_of()) {
            out.push(Query {
                key: "options",
                command: "ip.dhcp-client.options",
                params: json!({ "id": c }),
            });
        }
        // Only a router known to have it (an older daemon has not).
        if app.has_command("ip.dhcp-client.history") {
            out.push(Query {
                key: "history",
                command: "ip.dhcp-client.history",
                params: json!({ "after_seq": self.seq.unwrap_or(0) }),
            });
        }
        out
    }

    fn arrived(&mut self, app: &mut CoreRouterUi, key: &'static str, id: RequestId, value: Value) {
        match key {
            "list" => {
                self.clients = match value {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open_after)
                    .into_iter()
                    .partition(|(req, _)| *req <= id);
                self.open_after = later;
                for (_, c) in ready {
                    self.open_dhcp(app, &c);
                }
            }
            "options" => {
                if let Some(c) = value.get("id").and_then(Value::as_str) {
                    self.options.insert(c.to_owned(), value.clone());
                }
            }
            "history" => self.dhcp_history_arrived(app, &value),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut egui::Ui) {
        self.clients_window(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.draw_dialogs(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>() {
            self.dhcp_dialog_reply(app, r.id, r.effect, result);
        }
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

pub(crate) const TABLE: &str = "dhcp-client";
/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;
const MODES: [&str; 3] = ["yes", "no", "special-classless"];
/// Events logged from the history on the first look (older ones stay in
/// `ip.dhcp-client.history`).
const FIRST_LOOK: usize = 20;

const COLUMNS: [table::Column; 8] = [
    col(""),
    col("Interface"),
    col("Use Peer DNS"),
    col("Add Default Route"),
    col("IP Address"),
    col("Expires After"),
    col("Status"),
    comment(),
];

pub(crate) fn text(row: &Value, k: &str) -> String {
    match row.get(k) {
        None | Some(Value::Null) => String::new(),
        Some(Value::Array(a)) => a.iter().map(value_text).collect::<Vec<_>>().join(", "),
        Some(v) => value_text(v),
    }
}

pub(crate) fn flag(row: &Value, k: &str) -> bool {
    row.get(k).and_then(Value::as_bool).unwrap_or(false)
}

pub(crate) fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

/// The editable fields of a client, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DhcpForm {
    pub interface: String,
    pub use_peer_dns: bool,
    pub use_peer_ntp: bool,
    pub add_default_route: String,
    pub distance: String,
    /// Empty: the interface's table.
    pub table: String,
    pub comment: String,
    pub disabled: bool,
    pub host_name: String,
    pub client_id: String,
    pub vendor_class: String,
    /// `code:value, code:value`.
    pub extra_options: String,
    /// `ip-or-mac, …`.
    pub allowed_servers: String,
}

impl DhcpForm {
    /// A blank "New DHCP Client" form with RouterOS' defaults.
    pub(crate) fn new() -> Self {
        Self {
            interface: String::new(),
            use_peer_dns: true,
            use_peer_ntp: true,
            add_default_route: "yes".into(),
            distance: "1".into(),
            table: String::new(),
            comment: String::new(),
            disabled: false,
            host_name: String::new(),
            client_id: String::new(),
            vendor_class: String::new(),
            extra_options: String::new(),
            allowed_servers: String::new(),
        }
    }

    fn of(row: &Value) -> Self {
        Self {
            interface: text(row, "interface"),
            use_peer_dns: flag(row, "use_peer_dns"),
            use_peer_ntp: flag(row, "use_peer_ntp"),
            add_default_route: text(row, "add_default_route"),
            distance: text(row, "default_route_distance"),
            table: text(row, "default_route_table"),
            comment: text(row, "comment"),
            disabled: flag(row, "disabled"),
            host_name: text(row, "host_name"),
            client_id: text(row, "client_id"),
            vendor_class: text(row, "vendor_class"),
            extra_options: text(row, "extra_options"),
            allowed_servers: text(row, "allowed_servers"),
        }
    }

    /// `ip.dhcp-client.add` params; what equals the default is left out.
    fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("interface".into(), json!(self.interface));
        let base = Self::new();
        if let Some(Value::Object(diff)) = self.diff(&base) {
            p.extend(diff);
        }
        Value::Object(p)
    }

    /// The keys that differ from `base`, as `ip.dhcp-client.set` takes them.
    fn diff(&self, base: &DhcpForm) -> Option<Value> {
        let mut p = Map::new();
        let mut put = |k: &str, v: Value| {
            p.insert(k.into(), v);
        };
        if self.interface.trim() != base.interface {
            put("interface", json!(self.interface.trim()));
        }
        if self.use_peer_dns != base.use_peer_dns {
            put("use_peer_dns", json!(self.use_peer_dns));
        }
        if self.use_peer_ntp != base.use_peer_ntp {
            put("use_peer_ntp", json!(self.use_peer_ntp));
        }
        if self.add_default_route != base.add_default_route {
            put("add_default_route", json!(self.add_default_route));
        }
        if self.distance.trim() != base.distance {
            put("default_route_distance", form_number(&self.distance));
        }
        if self.table.trim() != base.table {
            put("default_route_table", json!(self.table.trim()));
        }
        if self.comment != base.comment {
            put("comment", json!(self.comment));
        }
        if self.disabled != base.disabled {
            put("disabled", json!(self.disabled));
        }
        for (k, now, was) in [
            ("host_name", &self.host_name, &base.host_name),
            ("client_id", &self.client_id, &base.client_id),
            ("vendor_class", &self.vendor_class, &base.vendor_class),
            ("extra_options", &self.extra_options, &base.extra_options),
            (
                "allowed_servers",
                &self.allowed_servers,
                &base.allowed_servers,
            ),
        ] {
            if now.trim() != was.trim() {
                put(k, json!(now.trim()));
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }

    fn set_params(&self, id: &str, base: &DhcpForm) -> Option<Value> {
        let mut p = self.diff(base)?;
        if let Value::Object(o) = &mut p {
            o.insert("id".into(), json!(id));
        }
        Some(p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    Dhcp,
    Status,
    Advanced,
    Options,
}

pub(crate) enum DhcpDialog {
    New {
        form: DhcpForm,
        /// The form as it opened (with the interface picked for it).
        base: DhcpForm,
        tab: Tab,
    },
    /// "DHCP Client <iface>"; `base` is what the engine has.
    Props {
        id: String,
        form: DhcpForm,
        base: DhcpForm,
        tab: Tab,
    },
    Comment {
        targets: Vec<String>,
        text: String,
        base: String,
    },
}

impl DhcpDialog {
    fn dirty(&self) -> bool {
        match self {
            DhcpDialog::New { form, base, .. } => form != base,
            DhcpDialog::Props { id, form, base, .. } => form.set_params(id, base).is_some(),
            DhcpDialog::Comment { text, base, .. } => text != base,
        }
    }

    /// The client a properties window shows, with its Options tab open.
    pub(crate) fn options_of(&self) -> Option<&str> {
        match self {
            DhcpDialog::Props {
                id,
                tab: Tab::Options,
                ..
            } => Some(id),
            _ => None,
        }
    }
}

pub(crate) struct DhcpDialogWin {
    pub id: u64,
    pub dialog: DhcpDialog,
    pub status: Status,
}

/// What a dialog's command changes in the dialog when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    OpenCreated,
    Applied(Box<DhcpForm>),
    Toggled(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
    Release,
    Renew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    Renew(Vec<String>),
    Release(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more DHCP clients first".into())
    } else {
        Ok(())
    }
}

fn can_enable(picked: &[&Value], enable: bool) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| flag(r, "disabled") == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

fn running(picked: &[&Value]) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| flag(r, "disabled")) {
        Err("A disabled client does not run: enable it first".into())
    } else {
        Ok(())
    }
}

fn client_row(r: &Value) -> Row {
    let peer = yes_no(flag(r, "use_peer_dns"));
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "interface"),
            peer,
            text(r, "add_default_route"),
            text(r, "address"),
            text(r, "expires_after"),
            text(r, "status"),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

impl DhcpPanel {
    fn dhcp_row(&self, id: &str) -> Option<&Value> {
        self.clients.iter().find(|r| text(r, "id") == id)
    }

    fn clients_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let clients = self.clients.clone();
        let rows: Vec<Row> = clients.iter().map(client_row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<&Value> = clients
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let mut act: Option<Act> = None;
        let can = app.can();

        ui.horizontal(|ui| {
            let add = can.check("ip.dhcp-client.add");
            if table::tool(ui, TABLE, Icon::Add, "Add", add).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and("ip.dhcp-client.remove", some(&picked)),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and("ip.dhcp-client.set", can_enable(&picked, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and("ip.dhcp-client.set", can_enable(&picked, false)),
                ),
                (
                    Icon::Comment,
                    "Comment",
                    can.and("ip.dhcp-client.set", some(&picked)),
                ),
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
            ui.separator();
            let renew = can.and("ip.dhcp-client.renew", running(&picked));
            if action(ui, "Renew", renew) {
                act = Some(Act::Renew(selection.clone()));
            }
            let release = can.and("ip.dhcp-client.release", running(&picked));
            if action(ui, "Release", release) {
                act = Some(Act::Release(selection.clone()));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();

        self.table.open = self
            .dialogs
            .iter()
            .filter_map(|d| match &d.dialog {
                DhcpDialog::Props { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        let out = table::show(
            ui,
            TABLE,
            0.0,
            &mut self.table,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<&Value> = clients
                        .iter()
                        .filter(|r| sel.contains(&text(r, "id")))
                        .collect();
                    let owned = || sel.to_vec();
                    let items = [
                        (
                            "Enable",
                            "ip.dhcp-client.set",
                            can_enable(&picked, true),
                            Act::Enable(owned()),
                        ),
                        (
                            "Disable",
                            "ip.dhcp-client.set",
                            can_enable(&picked, false),
                            Act::Disable(owned()),
                        ),
                        (
                            "Remove",
                            "ip.dhcp-client.remove",
                            some(&picked),
                            Act::Remove(owned()),
                        ),
                        (
                            "Comment…",
                            "ip.dhcp-client.set",
                            some(&picked),
                            Act::Comment(owned()),
                        ),
                        (
                            "Renew",
                            "ip.dhcp-client.renew",
                            running(&picked),
                            Act::Renew(owned()),
                        ),
                        (
                            "Release",
                            "ip.dhcp-client.release",
                            running(&picked),
                            Act::Release(owned()),
                        ),
                    ];
                    for (label, cmd, ok, a) in items {
                        if action(ui, label, can.and(cmd, ok)) {
                            act = Some(a);
                        }
                    }
                    if action(ui, "Properties…", some(&picked)) {
                        act = Some(Act::Open(owned()));
                    }
                    ui.separator();
                    if action(ui, "Add DHCP Client…", can.check("ip.dhcp-client.add")) {
                        act = Some(Act::New);
                    }
                }
                Menu::Empty => {
                    if action(ui, "Add DHCP Client…", can.check("ip.dhcp-client.add")) {
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
        if let Some(key) = out.comment {
            act = Some(Act::Comment(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.table.selection(&rows);
            let picked: Vec<&Value> = clients
                .iter()
                .filter(|r| sel.contains(&text(r, "id")))
                .collect();
            let allowed = match s {
                Shortcut::Remove | Shortcut::Comment | Shortcut::Open => some(&picked).is_ok(),
                Shortcut::Enable => can_enable(&picked, true).is_ok(),
                Shortcut::Disable => can_enable(&picked, false).is_ok(),
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
            self.dhcp_act(app, a, &rows);
        }
    }

    fn dhcp_act(&mut self, app: &mut CoreRouterUi, act: Act, rows: &[Row]) {
        let each = |app: &mut CoreRouterUi, keys: &[String], cmd: &str, extra: Value| {
            for id in keys {
                let mut p = json!({ "id": id });
                if let (Value::Object(o), Value::Object(e)) = (&mut p, &extra) {
                    o.extend(e.clone());
                }
                app.run(cmd, p);
            }
        };
        match act {
            Act::Enable(keys) => each(
                app,
                &keys,
                "ip.dhcp-client.set",
                json!({"disabled": false}),
            ),
            Act::Disable(keys) => {
                each(app, &keys, "ip.dhcp-client.set", json!({"disabled": true}))
            }
            Act::Remove(keys) => each(app, &keys, "ip.dhcp-client.remove", json!({})),
            Act::Renew(keys) => each(app, &keys, "ip.dhcp-client.renew", json!({})),
            Act::Release(keys) => each(app, &keys, "ip.dhcp-client.release", json!({})),
            Act::Comment(keys) => {
                let text = match keys.as_slice() {
                    [one] => self
                        .dhcp_row(one)
                        .map(|r| crate::dhcp_client::text(r, "comment"))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                if !keys.is_empty() {
                    self.open_dhcp_dialog(app, DhcpDialog::Comment {
                        targets: keys,
                        base: text.clone(),
                        text,
                    });
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_dhcp(app, k);
                }
            }
            Act::New => {
                let mut form = DhcpForm::new();
                // The first interface without a client, as a start.
                let taken: Vec<String> = self.clients
                    .iter()
                    .map(|r| text(r, "interface"))
                    .collect();
                if let Some(free) = app.interface_names(None)
                    .into_iter()
                    .find(|n| !taken.contains(n) && n != "lo")
                {
                    form.interface = free;
                }
                self.open_dhcp_dialog(app, DhcpDialog::New {
                    base: form.clone(),
                    form,
                    tab: Tab::Dhcp,
                });
            }
            Act::SelectAll => self.table.select_all(rows),
            Act::Refresh => app.cache.refreshed_at = None,
        }
    }

    fn open_dhcp_dialog(&mut self, app: &mut CoreRouterUi, dialog: DhcpDialog) {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.dialogs.push(DhcpDialogWin {
            id: app.next_dialog,
            dialog,
            status: Status::default(),
        });
        app.cache.refreshed_at = None;
    }

    /// "DHCP Client <iface>"; an already open one comes to the front.
    pub(crate) fn open_dhcp(&mut self, app: &mut CoreRouterUi, id: &str) {
        let Some(row) = self.dhcp_row(id).cloned() else {
            return;
        };
        let open = self
            .dialogs
            .iter_mut()
            .find(|d| matches!(&d.dialog, DhcpDialog::Props { id: i, .. } if i == id));
        if let Some(d) = open {
            d.status.bring_to_front();
            return;
        }
        let form = DhcpForm::of(&row);
        self.open_dhcp_dialog(app, DhcpDialog::Props {
            id: id.to_owned(),
            base: form.clone(),
            form,
            tab: Tab::Dhcp,
        });
    }

    /// Draw every open DHCP client dialog.
    fn draw_dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let clients = self.clients.clone();
        let names = app.interface_names(None);
        let mut tables = vec![String::new(), "main".to_owned()];
        tables.extend(app.interface_names(Some("vrf")));
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            let row = match &d.dialog {
                DhcpDialog::Props { id, .. } => {
                    let row = clients.iter().find(|r| text(r, "id") == *id);
                    // A window whose client is gone closes itself.
                    if row.is_none() && !self.clients.is_empty() {
                        app.floats.forget(wid);
                        return false;
                    }
                    row.cloned()
                }
                _ => None,
            };
            let title = match &d.dialog {
                DhcpDialog::New { .. } => "New DHCP Client".to_owned(),
                DhcpDialog::Props { form, .. } => {
                    format!(
                        "DHCP Client <{}>",
                        row.as_ref()
                            .map_or(form.interface.clone(), |r| text(r, "interface"))
                    )
                }
                DhcpDialog::Comment { targets, .. } => match targets.as_slice() {
                    [one] => format!(
                        "Comment for DHCP Client <{}>",
                        clients
                            .iter()
                            .find(|r| text(r, "id") == *one)
                            .map(|r| text(r, "interface"))
                            .unwrap_or_default()
                    ),
                    many => format!("Comment for {} DHCP Clients", many.len()),
                },
            };
            let can = app.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Panel(WIN))),
            };
            let options = row
                .as_ref()
                .and_then(|r| self.options.get(&text(r, "id")))
                .cloned();
            let pressed =
                dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(
                        ui,
                        f,
                        &mut d.dialog,
                        row.as_ref(),
                        options.as_ref(),
                        &names,
                        &tables,
                        &can,
                    )
                });
            let keep = pressed.is_none_or(|b| self.dhcp_button(app, d, b, row.as_ref()));
            if !keep {
                app.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    fn dhcp_button(
        &mut self,
        app: &mut CoreRouterUi,
        d: &mut DhcpDialogWin,
        b: Press<Button>,
        row: Option<&Value>,
    ) -> bool {
        if b == Press::Cancel {
            return false;
        }
        let (sends, close): (Vec<(&str, Value, Effect)>, bool) = match &d.dialog {
            DhcpDialog::New { form, .. } => {
                let effect = if b == Press::Apply {
                    Effect::OpenCreated
                } else {
                    Effect::None
                };
                (
                    vec![("ip.dhcp-client.add", form.add_params(), effect)],
                    true,
                )
            }
            DhcpDialog::Props { id, form, base, .. } => match b {
                Press::Ok | Press::Apply => match form.set_params(id, base) {
                    Some(p) => (
                        vec![(
                            "ip.dhcp-client.set",
                            p,
                            Effect::Applied(Box::new(form.clone())),
                        )],
                        b == Press::Ok,
                    ),
                    None => return b != Press::Ok,
                },
                Press::Other(Button::Toggle) => {
                    let now = row.is_some_and(|r| flag(r, "disabled"));
                    (
                        vec![(
                            "ip.dhcp-client.set",
                            json!({"id": id, "disabled": !now}),
                            Effect::Toggled(!now),
                        )],
                        false,
                    )
                }
                Press::Other(Button::Remove) => (
                    vec![("ip.dhcp-client.remove", json!({ "id": id }), Effect::None)],
                    true,
                ),
                Press::Other(Button::Renew) => (
                    vec![("ip.dhcp-client.renew", json!({ "id": id }), Effect::None)],
                    false,
                ),
                Press::Other(Button::Release) => (
                    vec![("ip.dhcp-client.release", json!({ "id": id }), Effect::None)],
                    false,
                ),
                Press::Cancel => return false,
            },
            DhcpDialog::Comment { targets, text, .. } => (
                targets
                    .iter()
                    .map(|t| {
                        (
                            "ip.dhcp-client.set",
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
            app.run_then(cmd, params, crate::panel::then(NAME, Reply { id: d.id, effect }));
        }
        true
    }

    /// A reply to a DHCP dialog's command: an error stays in the dialog.
    fn dhcp_dialog_reply(
        &mut self,
        app: &mut CoreRouterUi,
        id: u64,
        effect: Effect,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut created = None;
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, effect, &mut d.dialog) {
                    (Err(_), _, _) => {}
                    (Ok(r), Effect::OpenCreated, _) => {
                        created = r.get("id").and_then(Value::as_str).map(str::to_owned);
                    }
                    (Ok(_), Effect::Applied(sent), DhcpDialog::Props { base, form, .. }) => {
                        let mut sent = *sent;
                        for s in [
                            &mut sent.interface,
                            &mut sent.distance,
                            &mut sent.table,
                            &mut sent.host_name,
                            &mut sent.client_id,
                            &mut sent.vendor_class,
                            &mut sent.extra_options,
                            &mut sent.allowed_servers,
                        ] {
                            *s = s.trim().to_owned();
                        }
                        *base = sent;
                        form.disabled = base.disabled;
                    }
                    (Ok(_), Effect::Toggled(now), DhcpDialog::Props { base, form, .. }) => {
                        base.disabled = now;
                        form.disabled = now;
                    }
                    (Ok(_), _, _) => {}
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            app.floats.forget(dialog_id(id));
        }
        app.cache.refreshed_at = None;
        if let Some(c) = created {
            let list = app.reload();
            self.open_after.push((list, c));
        }
    }

    /// `ip.dhcp-client.history` arrived: new events go to the Log.
    fn dhcp_history_arrived(&mut self, app: &mut CoreRouterUi, value: &Value) {
        let last = value.get("last_seq").and_then(Value::as_u64).unwrap_or(0);
        let events = value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let first_look = self.seq.is_none();
        let skip = if first_look {
            events.len().saturating_sub(FIRST_LOOK)
        } else {
            0
        };
        for e in events.iter().skip(skip) {
            let kind = text(e, "event");
            let bad = matches!(
                kind.as_str(),
                "lost" | "nak" | "refused" | "declined" | "error"
            );
            app.push_log(LogLine {
                ok: !bad,
                command: "dhcp-client".into(),
                message: format!("{}: {}", text(e, "interface"), text(e, "message")),
            });
        }
        // A restarted daemon counts from 0 again.
        self.seq = Some(last);
    }
}

#[allow(clippy::too_many_arguments)]
fn dialog_body(
    ui: &mut Ui,
    f: &Form,
    d: &mut DhcpDialog,
    row: Option<&Value>,
    options: Option<&Value>,
    names: &[String],
    tables: &[String],
    can: &Avail,
) -> Footer<Button> {
    let props = matches!(d, DhcpDialog::Props { .. });
    match d {
        DhcpDialog::Comment { text, .. } => {
            Grid::new("dhcp-comment").num_columns(2).show(ui, |ui| {
                f.text(ui, "Comment", "comment", text, "");
            });
            return Footer::edit(false, can.check("ip.dhcp-client.set"));
        }
        DhcpDialog::New { form, tab, .. } | DhcpDialog::Props { form, tab, .. } => {
            ui.horizontal(|ui| {
                ui.selectable_value(tab, Tab::Dhcp, "DHCP");
                if props {
                    ui.selectable_value(tab, Tab::Status, "Status");
                }
                ui.selectable_value(tab, Tab::Advanced, "Advanced");
                if props {
                    ui.selectable_value(tab, Tab::Options, "Options");
                }
            });
            ui.separator();
            match tab {
                Tab::Dhcp => dhcp_tab(ui, f, form, names, tables, props),
                Tab::Advanced => advanced_tab(ui, f, form),
                Tab::Status => status_tab(ui, row),
                Tab::Options => options_tab(ui, row, options),
            }
        }
    }
    let ok = can.check(if props {
        "ip.dhcp-client.set"
    } else {
        "ip.dhcp-client.add"
    });
    let mut footer = Footer::edit(true, ok);
    if let Some(r) = row {
        let disabled = flag(r, "disabled");
        let run = if disabled {
            Err("A disabled client does not run: enable it first".to_owned())
        } else {
            Ok(())
        };
        footer.extra = vec![
            (
                if disabled { "Enable" } else { "Disable" },
                Button::Toggle,
                can.check("ip.dhcp-client.set"),
            ),
            ("Remove", Button::Remove, can.check("ip.dhcp-client.remove")),
            (
                "Release",
                Button::Release,
                can.and("ip.dhcp-client.release", run.clone()),
            ),
            ("Renew", Button::Renew, can.and("ip.dhcp-client.renew", run)),
        ];
    }
    footer
}

fn dhcp_tab(
    ui: &mut Ui,
    f: &Form,
    form: &mut DhcpForm,
    names: &[String],
    tables: &[String],
    props: bool,
) {
    Grid::new("dhcp-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Interface");
            crate::windows::combo(ui, "dhcp-iface", "interface", &mut form.interface, names);
            ui.end_row();
            ui.label("Use Peer DNS");
            ui.checkbox(&mut form.use_peer_dns, "");
            ui.end_row();
            ui.label("Use Peer NTP");
            ui.checkbox(&mut form.use_peer_ntp, "");
            ui.end_row();
            ui.label("Add Default Route");
            egui::ComboBox::from_id_salt("dhcp-adr")
                .selected_text(form.add_default_route.as_str())
                .show_ui(ui, |ui| {
                    for m in MODES {
                        ui.selectable_value(&mut form.add_default_route, m.to_owned(), m);
                    }
                });
            ui.end_row();
            f.text(
                ui,
                "Default Route Distance",
                "default_route_distance",
                &mut form.distance,
                "1",
            );
            ui.label("Default Route Table");
            egui::ComboBox::from_id_salt("dhcp-table")
                .selected_text(if form.table.is_empty() {
                    "(interface's)"
                } else {
                    form.table.as_str()
                })
                .show_ui(ui, |ui| {
                    for t in tables {
                        let label = if t.is_empty() {
                            "(interface's)"
                        } else {
                            t.as_str()
                        };
                        ui.selectable_value(&mut form.table, t.clone(), label);
                    }
                });
            ui.end_row();
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            if props {
                ui.label("Disabled");
                ui.checkbox(&mut form.disabled, "");
                ui.end_row();
            }
        });
}

fn advanced_tab(ui: &mut Ui, f: &Form, form: &mut DhcpForm) {
    Grid::new("dhcp-advanced")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(
                ui,
                "Host Name",
                "host_name",
                &mut form.host_name,
                "(system identity)",
            );
            f.text(
                ui,
                "Client ID",
                "client_id",
                &mut form.client_id,
                "(0x01 + MAC)",
            );
            f.text(
                ui,
                "Vendor Class ID",
                "vendor_class",
                &mut form.vendor_class,
                "",
            );
            f.text(
                ui,
                "DHCP Options",
                "extra_options",
                &mut form.extra_options,
                "77:'wan', 224:0x01",
            );
            f.text(
                ui,
                "Allowed Servers",
                "allowed_servers",
                &mut form.allowed_servers,
                "(any) 192.0.2.1, AA:BB:…",
            );
        });
    ui.weak(
        "Options: code:value, value as 0x0a0b, 'text', s'text', '10.0.0.1', '10', $(HOSTNAME).",
    );
}

fn status_tab(ui: &mut Ui, row: Option<&Value>) {
    let Some(r) = row else {
        ui.weak("Not created yet.");
        return;
    };
    Grid::new("dhcp-status")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for (label, key) in [
                ("Status", "status"),
                ("IP Address", "address"),
                ("Gateway", "gateway"),
                ("DHCP Server", "dhcp_server"),
                ("Primary DNS", "primary_dns"),
                ("Secondary DNS", "secondary_dns"),
                ("Primary NTP", "primary_ntp"),
                ("Secondary NTP", "secondary_ntp"),
                ("Domain", "domain"),
                ("Lease Time", "lease_time"),
                ("Expires After", "expires_after"),
                ("Routes Table", "routes_table"),
            ] {
                ui.label(label);
                ui.add_enabled(
                    false,
                    TextEdit::singleline(&mut text(r, key)).desired_width(220.0),
                );
                ui.end_row();
            }
        });
    let routes = r.get("routes").and_then(Value::as_array);
    if let Some(routes) = routes.filter(|a| !a.is_empty()) {
        ui.label("Routes");
        for route in routes {
            ui.monospace(format!("  {}", value_text(route)));
        }
    }
    for n in r
        .get("notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        ui.colored_label(ui.visuals().warn_fg_color, value_text(n));
    }
    let error = text(r, "error");
    if !error.is_empty() {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
}

fn options_tab(ui: &mut Ui, row: Option<&Value>, options: Option<&Value>) {
    let bound = row.is_some_and(|r| {
        matches!(
            text(r, "status").as_str(),
            "bound" | "renewing" | "rebinding"
        )
    });
    let list = options
        .and_then(|o| o.get("options"))
        .and_then(Value::as_array)
        .filter(|_| bound);
    let Some(list) = list else {
        ui.weak("No lease: the options the server sends show here.");
        return;
    };
    ui.weak(format!(
        "Sent by {}",
        options.map(|o| text(o, "dhcp_server")).unwrap_or_default()
    ));
    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
        Grid::new("dhcp-options")
            .num_columns(3)
            .striped(true)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for h in ["Code", "Name", "Value"] {
                    ui.strong(h);
                }
                ui.end_row();
                for o in list {
                    ui.label(text(o, "code"));
                    ui.label(text(o, "name"));
                    ui.label(RichText::new(text(o, "value")).monospace())
                        .on_hover_text(text(o, "hex"));
                    ui.end_row();
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_send_only_what_changed() {
        let mut f = DhcpForm::new();
        f.interface = "ether1".into();
        assert_eq!(f.add_params(), json!({"interface": "ether1"}));
        f.add_default_route = "special-classless".into();
        f.distance = "5".into();
        f.allowed_servers = " 192.0.2.1 ".into();
        assert_eq!(
            f.add_params(),
            json!({"interface": "ether1", "add_default_route": "special-classless",
                   "default_route_distance": 5, "allowed_servers": "192.0.2.1"})
        );
        let base = f.clone();
        assert_eq!(f.set_params("*1", &base), None);
        f.use_peer_dns = false;
        assert_eq!(
            f.set_params("*1", &base),
            Some(json!({"id": "*1", "use_peer_dns": false}))
        );
        let row = json!({"id": "*1", "interface": "ether1", "use_peer_dns": true,
            "use_peer_ntp": true, "add_default_route": "yes", "default_route_distance": 1,
            "default_route_table": "", "allowed_servers": ["192.0.2.1", "AA:BB:CC:DD:EE:FF"],
            "extra_options": ["77:'wan'"]});
        let of = DhcpForm::of(&row);
        assert_eq!(of.allowed_servers, "192.0.2.1, AA:BB:CC:DD:EE:FF");
        assert_eq!(of.extra_options, "77:'wan'");
        assert_eq!(of.distance, "1");
    }
}

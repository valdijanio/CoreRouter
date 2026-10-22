//! IP › DNS Forwarders (G4.1d), WinBox `/ip dns forwarders` style: named
//! groups of upstream servers (plain, DoH, DoT) with the static FWD
//! entries that use each, Add / Remove / Enable / Disable, and a dialog
//! per group. Opened from the Forwarders button of IP › DNS.
//!
//! The engine validates (`ip.dns.forwarders.*`); the window only shows and
//! sends.

use egui::{Grid, RichText, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-forwarders";
pub(crate) const WIN: &str = "dns-forwarders";
pub(crate) const TABLE: &str = "dns-forwarders";
const MAX_OPEN: usize = 8;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Forwarders",
        size: [760.0, 280.0],
        escape: true,
    }],
    new: || Box::new(ForwardersPanel::default()),
};

const COLUMNS: [table::Column; 6] = [
    col(""),
    col("Name"),
    col("DNS Servers"),
    col("DoH Servers"),
    col("Used By"),
    comment(),
];

#[derive(Default)]
pub(crate) struct ForwardersPanel {
    /// `ip.dns.forwarders.print`.
    pub(crate) lists: Vec<Value>,
    pub(crate) table: TableState,
    pub(crate) dialogs: Vec<DialogWin>,
}

/// One group's fields, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwarderForm {
    pub name: String,
    /// One per line (commas also separate).
    pub dns_servers: String,
    pub doh_servers: String,
    pub verify_doh_cert: bool,
    pub disabled: bool,
    pub comment: String,
}

impl Default for ForwarderForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            dns_servers: String::new(),
            doh_servers: String::new(),
            verify_doh_cert: true,
            disabled: false,
            comment: String::new(),
        }
    }
}

fn split(s: &str) -> Vec<String> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn lines(r: &Value, k: &str) -> String {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

impl ForwarderForm {
    fn of(r: &Value) -> Self {
        Self {
            name: text(r, "name"),
            dns_servers: lines(r, "dns_servers"),
            doh_servers: lines(r, "doh_servers"),
            verify_doh_cert: r.get("verify_doh_cert").and_then(Value::as_bool).unwrap_or(true),
            disabled: flag(r, "disabled"),
            comment: text(r, "comment"),
        }
    }

    pub(crate) fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("name".into(), json!(self.name.trim()));
        for (k, v) in [("dns_servers", &self.dns_servers), ("doh_servers", &self.doh_servers)] {
            if !split(v).is_empty() {
                p.insert(k.into(), json!(split(v)));
            }
        }
        if !self.comment.trim().is_empty() {
            p.insert("comment".into(), json!(self.comment.trim()));
        }
        if !self.verify_doh_cert {
            p.insert("verify_doh_cert".into(), json!(false));
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        Value::Object(p)
    }

    pub(crate) fn set_params(&self, id: &str, base: &Self) -> Option<Value> {
        let mut p = Map::new();
        if self.name.trim() != base.name.trim() {
            p.insert("name".into(), json!(self.name.trim()));
        }
        for (k, v, b) in [
            ("dns_servers", &self.dns_servers, &base.dns_servers),
            ("doh_servers", &self.doh_servers, &base.doh_servers),
        ] {
            if split(v) != split(b) {
                p.insert(k.into(), json!(split(v)));
            }
        }
        if self.comment.trim() != base.comment.trim() {
            p.insert("comment".into(), json!(self.comment.trim()));
        }
        if self.verify_doh_cert != base.verify_doh_cert {
            p.insert("verify_doh_cert".into(), json!(self.verify_doh_cert));
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

pub(crate) enum Dialog {
    New(Box<ForwarderForm>),
    Props {
        id: String,
        form: Box<ForwarderForm>,
        base: Box<ForwarderForm>,
    },
}

impl Dialog {
    fn dirty(&self) -> bool {
        match self {
            Self::New(f) => **f != ForwarderForm::default(),
            Self::Props { id, form, base } => form.set_params(id, base).is_some(),
        }
    }
}

pub(crate) struct DialogWin {
    pub id: u64,
    pub dialog: Dialog,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Remove,
}

enum Reply {
    Dialog { id: u64, applied: Option<ForwarderForm> },
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Open(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more forwarders first".into())
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

pub(crate) fn row(r: &Value) -> Row {
    let used = text(r, "used_by");
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "name"),
            text(r, "dns_servers"),
            text(r, "doh_servers"),
            if used.is_empty() { "–".into() } else { used },
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

impl PanelState for ForwardersPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let open = app.open.contains(&Win::Panel(WIN)) || !self.dialogs.is_empty();
        if open && app.has_command("ip.dns.forwarders.print") {
            vec![Query {
                key: "groups",
                command: "ip.dns.forwarders.print",
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "groups"
            && let Value::Array(a) = value
        {
            self.lists = a;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.list_window(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.draw_dialogs(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        if let Reply::Dialog { id, applied } = *r {
            self.dialog_reply(app, id, applied, result);
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

impl ForwardersPanel {
    fn list_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lists = self.lists.clone();
        let rows: Vec<Row> = lists.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<&Value> = lists
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let can = app.can();
        let mut act = None;
        ui.horizontal(|ui| {
            if table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.dns.forwarders.add")).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (Icon::Remove, "Remove", can.and("ip.dns.forwarders.remove", some(&picked))),
                (Icon::Enable, "Enable", can.and("ip.dns.forwarders.set", can_enable(&picked, true))),
                (Icon::Disable, "Disable", can.and("ip.dns.forwarders.set", can_enable(&picked, false))),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        _ => Act::Remove(sel),
                    });
                }
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        self.table.open = self
            .dialogs
            .iter()
            .filter_map(|d| match &d.dialog {
                Dialog::Props { id, .. } => Some(id.clone()),
                Dialog::New(_) => None,
            })
            .collect();
        let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let picked: Vec<&Value> = lists
                    .iter()
                    .filter(|r| sel.contains(&text(r, "id")))
                    .collect();
                let owned = || sel.to_vec();
                for (label, cmd, ok, a) in [
                    ("Enable", "ip.dns.forwarders.set", can_enable(&picked, true), Act::Enable(owned())),
                    ("Disable", "ip.dns.forwarders.set", can_enable(&picked, false), Act::Disable(owned())),
                    ("Remove", "ip.dns.forwarders.remove", some(&picked), Act::Remove(owned())),
                ] {
                    if action(ui, label, can.and(cmd, ok)) {
                        act = Some(a);
                    }
                }
                if action(ui, "Properties…", some(&picked)) {
                    act = Some(Act::Open(owned()));
                }
            }
            Menu::Empty => {
                if action(ui, "Add Forwarder…", can.check("ip.dns.forwarders.add")) {
                    act = Some(Act::New);
                }
                if ui.button("Select All").clicked() {
                    act = Some(Act::SelectAll);
                }
                if ui.button("Refresh").clicked() {
                    act = Some(Act::Refresh);
                }
            }
        });
        if lists.is_empty() {
            ui.label(
                RichText::new(
                    "No forwarders. A group of servers (plain, DoH or DoT) that a static FWD \
                     entry sends its names to: /ip dns static add name=corp.example type=FWD \
                     forward-to=<group>.",
                )
                .weak()
                .small(),
            );
        }
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.table.selection(&rows);
            let picked: Vec<&Value> = lists
                .iter()
                .filter(|r| sel.contains(&text(r, "id")))
                .collect();
            act = match s {
                Shortcut::Remove if some(&picked).is_ok() => Some(Act::Remove(sel)),
                Shortcut::Open if some(&picked).is_ok() => Some(Act::Open(sel)),
                Shortcut::Enable if can_enable(&picked, true).is_ok() => Some(Act::Enable(sel)),
                Shortcut::Disable if can_enable(&picked, false).is_ok() => Some(Act::Disable(sel)),
                _ => act,
            };
        }
        if let Some(a) = act {
            self.act(app, a, &rows);
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, rows: &[Row]) {
        let done = || crate::panel::then(NAME, Reply::Done);
        match act {
            Act::Enable(keys) => {
                for id in keys {
                    app.run_then("ip.dns.forwarders.set", json!({"id": id, "disabled": false}), done());
                }
            }
            Act::Disable(keys) => {
                for id in keys {
                    app.run_then("ip.dns.forwarders.set", json!({"id": id, "disabled": true}), done());
                }
            }
            Act::Remove(keys) => {
                for id in keys {
                    app.run_then("ip.dns.forwarders.remove", json!({ "id": id }), done());
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_props(app, k);
                }
            }
            Act::New => self.open_dialog(app, Dialog::New(Box::default())),
            Act::SelectAll => self.table.select_all(rows),
            Act::Refresh => app.cache.refreshed_at = None,
        }
    }

    fn open_dialog(&mut self, app: &mut CoreRouterUi, dialog: Dialog) {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.dialogs.push(DialogWin {
            id: app.next_dialog,
            dialog,
            status: Status::default(),
        });
        app.cache.refreshed_at = None;
    }

    fn open_props(&mut self, app: &mut CoreRouterUi, id: &str) {
        let Some(row) = self.lists.iter().find(|r| text(r, "id") == id).cloned() else {
            return;
        };
        if let Some(d) = self
            .dialogs
            .iter_mut()
            .find(|d| matches!(&d.dialog, Dialog::Props { id: i, .. } if i == id))
        {
            d.status.bring_to_front();
            return;
        }
        let form = Box::new(ForwarderForm::of(&row));
        self.open_dialog(app, Dialog::Props {
            id: id.to_owned(),
            base: form.clone(),
            form,
        });
    }

    fn draw_dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let lists = self.lists.clone();
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            let (title, status) = match &d.dialog {
                Dialog::New(_) => ("New DNS Forwarder".to_owned(), None),
                Dialog::Props { id, form, .. } => {
                    let Some(r) = lists.iter().find(|r| text(r, "id") == *id) else {
                        if !lists.is_empty() {
                            // Removed elsewhere: the window goes too.
                            app.floats.forget(wid);
                            return false;
                        }
                        return true;
                    };
                    (format!("DNS Forwarder <{}>", form.name), Some(r.clone()))
                }
            };
            let can = app.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Panel(WIN))),
            };
            let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
                body(ui, f, &mut d.dialog, status.as_ref(), &can)
            });
            let keep = pressed.is_none_or(|b| self.button(app, d, b));
            if !keep {
                app.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    fn button(&mut self, app: &mut CoreRouterUi, d: &mut DialogWin, b: Press<Button>) -> bool {
        let (cmd, params, applied, close) = match (&d.dialog, b) {
            (_, Press::Cancel) => return false,
            (Dialog::New(form), _) => ("ip.dns.forwarders.add", form.add_params(), None, true),
            (Dialog::Props { id, .. }, Press::Other(Button::Remove)) => {
                ("ip.dns.forwarders.remove", json!({ "id": id }), None, true)
            }
            (Dialog::Props { id, form, base }, b) => match form.set_params(id, base) {
                Some(p) => ("ip.dns.forwarders.set", p, Some((**form).clone()), b == Press::Ok),
                None => return b != Press::Ok,
            },
        };
        d.status.close_on_success = close;
        d.status.sent();
        app.run_then(cmd, params, crate::panel::then(NAME, Reply::Dialog { id: d.id, applied }));
        true
    }

    fn dialog_reply(
        &mut self,
        app: &mut CoreRouterUi,
        id: u64,
        applied: Option<ForwarderForm>,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                if let (Ok(_), Some(sent), Dialog::Props { base, .. }) = (result, applied, &mut d.dialog) {
                    **base = sent;
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            app.floats.forget(dialog_id(id));
        }
    }
}

fn body(ui: &mut Ui, f: &Form, d: &mut Dialog, status: Option<&Value>, can: &Avail) -> Footer<Button> {
    let props = matches!(d, Dialog::Props { .. });
    let form = match d {
        Dialog::New(form) | Dialog::Props { form, .. } => form,
    };
    Grid::new("dns-forwarder-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(ui, "Name", "name", &mut form.name, "corp");
            ui.label("DNS Servers").on_hover_text("Plain DNS, one per line.");
            ui.add(egui::TextEdit::multiline(&mut form.dns_servers).hint_text("10.0.0.53").desired_rows(2).desired_width(260.0));
            ui.end_row();
            ui.label("DoH Servers").on_hover_text(
                "Encrypted, one per line: https://host/path (DoH) or tls://host[#name] (DoT).",
            );
            ui.add(
                egui::TextEdit::multiline(&mut form.doh_servers)
                    .hint_text("https://dns.example/dns-query")
                    .desired_rows(2)
                    .desired_width(260.0),
            );
            ui.end_row();
            ui.label("Verify DoH Certificate");
            ui.checkbox(&mut form.verify_doh_cert, "");
            ui.end_row();
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            ui.label("Disabled");
            ui.checkbox(&mut form.disabled, "");
            ui.end_row();
            if let Some(r) = status {
                ui.label("Used By");
                ui.label(row(r).cells.get(4).cloned().unwrap_or_default());
                ui.end_row();
            }
        });
    ui.label(
        RichText::new(
            "Disabled or missing: the static FWD entries naming it use the usual servers.",
        )
        .weak()
        .small(),
    );
    let ok = can.check(if props { "ip.dns.forwarders.set" } else { "ip.dns.forwarders.add" });
    let mut footer = Footer::edit(true, ok);
    if props {
        footer.extra = vec![("Remove", Button::Remove, can.check("ip.dns.forwarders.remove"))];
    }
    footer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_send_only_what_changed() {
        let f = ForwarderForm {
            name: " corp ".into(),
            dns_servers: "10.0.0.53\n10.0.0.54, ".into(),
            ..ForwarderForm::default()
        };
        assert_eq!(
            f.add_params(),
            json!({"name": "corp", "dns_servers": ["10.0.0.53", "10.0.0.54"]})
        );
        let base = ForwarderForm::of(&json!({"id": "*1", "name": "corp",
            "doh_servers": ["https://a/q"], "verify_doh_cert": true}));
        assert_eq!(base.doh_servers, "https://a/q");
        assert_eq!(base.set_params("*1", &base), None);
        let mut f = base.clone();
        f.verify_doh_cert = false;
        assert_eq!(f.set_params("*1", &base), Some(json!({"id": "*1", "verify_doh_cert": false})));
        let r = row(&json!({"id": "*1", "name": "corp", "used_by": []}));
        assert_eq!(r.cells[4], "–");
    }
}

//! IP › DNS Adlist (G4.1d), WinBox `/ip dns adlist` style: the block lists
//! with how many names each loaded and how many queries it blocked, Add /
//! Remove / Enable / Disable / Reload, and a dialog per list (URL or
//! File, SSL Verify, Comment). Opened from the Adlist button of IP › DNS.
//!
//! The engine validates (`ip.dns.adlist.*`); the daemon downloads. The
//! window only shows and sends.

use egui::{Grid, RichText, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-adlist";
pub(crate) const WIN: &str = "dns-adlist";
pub(crate) const TABLE: &str = "dns-adlist";
const MAX_OPEN: usize = 8;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Adlist",
        size: [760.0, 300.0],
        escape: true,
    }],
    new: || Box::new(AdlistPanel::default()),
};

const COLUMNS: [table::Column; 7] = [
    col(""),
    col("Source"),
    col("State"),
    num("Names"),
    num("Matches"),
    col("Loaded"),
    comment(),
];

#[derive(Default)]
pub(crate) struct AdlistPanel {
    /// `ip.dns.adlist.print`.
    pub(crate) lists: Vec<Value>,
    pub(crate) table: TableState,
    pub(crate) dialogs: Vec<DialogWin>,
}

/// One list's fields, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdlistForm {
    pub url: String,
    pub file: String,
    pub ssl_verify: bool,
    pub disabled: bool,
    pub comment: String,
}

impl Default for AdlistForm {
    fn default() -> Self {
        Self {
            url: String::new(),
            file: String::new(),
            ssl_verify: true,
            disabled: false,
            comment: String::new(),
        }
    }
}

impl AdlistForm {
    fn of(r: &Value) -> Self {
        Self {
            url: text(r, "url"),
            file: text(r, "file"),
            ssl_verify: r.get("ssl_verify").and_then(Value::as_bool).unwrap_or(true),
            disabled: flag(r, "disabled"),
            comment: text(r, "comment"),
        }
    }

    pub(crate) fn add_params(&self) -> Value {
        let mut p = Map::new();
        for (k, v) in [("url", &self.url), ("file", &self.file), ("comment", &self.comment)] {
            if !v.trim().is_empty() {
                p.insert(k.into(), json!(v.trim()));
            }
        }
        if !self.ssl_verify {
            p.insert("ssl_verify".into(), json!(false));
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        Value::Object(p)
    }

    pub(crate) fn set_params(&self, id: &str, base: &Self) -> Option<Value> {
        let mut p = Map::new();
        for (k, v, b) in [
            ("url", &self.url, &base.url),
            ("file", &self.file, &base.file),
            ("comment", &self.comment, &base.comment),
        ] {
            if v.trim() != b.trim() {
                p.insert(k.into(), json!(v.trim()));
            }
        }
        if self.ssl_verify != base.ssl_verify {
            p.insert("ssl_verify".into(), json!(self.ssl_verify));
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
    New(Box<AdlistForm>),
    Props {
        id: String,
        form: Box<AdlistForm>,
        base: Box<AdlistForm>,
    },
}

impl Dialog {
    fn dirty(&self) -> bool {
        match self {
            Self::New(f) => **f != AdlistForm::default(),
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
    Reload,
}

enum Reply {
    Dialog { id: u64, applied: Option<AdlistForm> },
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Reload(Vec<String>),
    ReloadAll,
    Open(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more lists first".into())
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

/// `3 min`, `2 h`: how long ago a list loaded.
pub(crate) fn ago(secs: Option<u64>) -> String {
    match secs {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s} s ago"),
        Some(s) if s < 3600 => format!("{} min ago", s / 60),
        Some(s) if s < 172_800 => format!("{} h ago", s / 3600),
        Some(s) => format!("{} d ago", s / 86_400),
    }
}

pub(crate) fn row(r: &Value) -> Row {
    let source = match text(r, "url") {
        u if u.is_empty() => format!("file: {}", text(r, "file")),
        u => u,
    };
    let state = text(r, "state");
    let state = match r.get("error").and_then(Value::as_str) {
        Some(e) if state == "failed" => format!("failed: {e}"),
        Some(e) => format!("{state} ({e})"),
        None => state,
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            source,
            state,
            text(r, "name_count"),
            text(r, "match_count"),
            ago(r.get("loaded_secs_ago").and_then(Value::as_u64)),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

impl PanelState for AdlistPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let open = app.open.contains(&Win::Panel(WIN)) || !self.dialogs.is_empty();
        if open && app.has_command("ip.dns.adlist.print") {
            vec![Query {
                key: "lists",
                command: "ip.dns.adlist.print",
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "lists"
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

impl AdlistPanel {
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
            if table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.dns.adlist.add")).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (Icon::Remove, "Remove", can.and("ip.dns.adlist.remove", some(&picked))),
                (Icon::Enable, "Enable", can.and("ip.dns.adlist.set", can_enable(&picked, true))),
                (Icon::Disable, "Disable", can.and("ip.dns.adlist.set", can_enable(&picked, false))),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Enable => Act::Enable(sel.into_vec()),
                        Icon::Disable => Act::Disable(sel.into_vec()),
                        _ => Act::Remove(sel.into_vec()),
                    });
                }
            }
            if action(ui, "Reload", can.check("ip.dns.adlist.reload")) {
                act = Some(if selection.is_empty() {
                    Act::ReloadAll
                } else {
                    Act::Reload(selection.to_vec())
                });
            }
            ui.separator();
            let names: u64 = lists
                .iter()
                .filter_map(|r| r.get("name_count").and_then(Value::as_u64))
                .sum();
            let hits: u64 = lists
                .iter()
                .filter_map(|r| r.get("match_count").and_then(Value::as_u64))
                .sum();
            ui.weak(format!("{names} names, {hits} blocked"));
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
                    ("Enable", "ip.dns.adlist.set", can_enable(&picked, true), Act::Enable(owned())),
                    ("Disable", "ip.dns.adlist.set", can_enable(&picked, false), Act::Disable(owned())),
                    ("Reload", "ip.dns.adlist.reload", some(&picked), Act::Reload(owned())),
                    ("Remove", "ip.dns.adlist.remove", some(&picked), Act::Remove(owned())),
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
                if action(ui, "Add Adlist…", can.check("ip.dns.adlist.add")) {
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
                    "No lists. Add a hosts file or a domain list by URL, e.g. \
                     https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts; \
                     listed names get 0.0.0.0 / ::. A static FWD entry lets a name through.",
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
                Shortcut::Remove if some(&picked).is_ok() => Some(Act::Remove(sel.into_vec())),
                Shortcut::Open if some(&picked).is_ok() => Some(Act::Open(sel.into_vec())),
                Shortcut::Enable if can_enable(&picked, true).is_ok() => Some(Act::Enable(sel.into_vec())),
                Shortcut::Disable if can_enable(&picked, false).is_ok() => Some(Act::Disable(sel.into_vec())),
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
                    app.run_then("ip.dns.adlist.set", json!({"id": id, "disabled": false}), done());
                }
            }
            Act::Disable(keys) => {
                for id in keys {
                    app.run_then("ip.dns.adlist.set", json!({"id": id, "disabled": true}), done());
                }
            }
            Act::Remove(keys) => {
                for id in keys {
                    app.run_then("ip.dns.adlist.remove", json!({ "id": id }), done());
                }
            }
            Act::Reload(keys) => {
                for id in keys {
                    app.run_then("ip.dns.adlist.reload", json!({ "id": id }), done());
                }
            }
            Act::ReloadAll => {
                app.run_then("ip.dns.adlist.reload", json!({}), done());
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
        let form = Box::new(AdlistForm::of(&row));
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
                Dialog::New(_) => ("New DNS Adlist".to_owned(), None),
                Dialog::Props { id, form, .. } => {
                    let Some(r) = lists.iter().find(|r| text(r, "id") == *id) else {
                        if !lists.is_empty() {
                            // Removed elsewhere: the window goes too.
                            app.floats.forget(wid);
                            return false;
                        }
                        return true;
                    };
                    let src = if form.url.is_empty() { &form.file } else { &form.url };
                    let short: String = src.chars().take(48).collect();
                    (format!("DNS Adlist <{short}>"), Some(r.clone()))
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
            (Dialog::New(form), _) => ("ip.dns.adlist.add", form.add_params(), None, true),
            (Dialog::Props { id, .. }, Press::Other(Button::Remove)) => {
                ("ip.dns.adlist.remove", json!({ "id": id }), None, true)
            }
            (Dialog::Props { id, .. }, Press::Other(Button::Reload)) => {
                ("ip.dns.adlist.reload", json!({ "id": id }), None, false)
            }
            (Dialog::Props { id, form, base }, b) => match form.set_params(id, base) {
                Some(p) => ("ip.dns.adlist.set", p, Some((**form).clone()), b == Press::Ok),
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
        applied: Option<AdlistForm>,
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
    Grid::new("dns-adlist-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(ui, "URL", "url", &mut form.url, "https://…/hosts");
            f.text(ui, "File", "file", &mut form.file, "instead of URL (in --adlist-dir)");
            ui.label("SSL Verify")
                .on_hover_text("Check the HTTPS server's certificate (Mozilla roots).");
            ui.checkbox(&mut form.ssl_verify, "");
            ui.end_row();
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            ui.label("Disabled");
            ui.checkbox(&mut form.disabled, "");
            ui.end_row();
            if let Some(r) = status {
                ui.label("State");
                ui.label(row(r).cells.get(2).cloned().unwrap_or_default());
                ui.end_row();
                ui.label("Names");
                ui.label(text(r, "name_count"));
                ui.end_row();
                ui.label("Matches");
                ui.label(text(r, "match_count"));
                ui.end_row();
                ui.label("Skipped Lines")
                    .on_hover_text("Lines that held no usable name (adblock rules with paths or options, bad names).");
                ui.label(text(r, "skipped"));
                ui.end_row();
            }
        });
    ui.label(
        RichText::new(
            "Hosts files (0.0.0.0 name), one domain per line, or ||domain^ (with its \
             subdomains). Fetched again every 4 hours.",
        )
        .weak()
        .small(),
    );
    let ok = can.check(if props { "ip.dns.adlist.set" } else { "ip.dns.adlist.add" });
    let mut footer = Footer::edit(true, ok);
    if props {
        footer.extra = vec![
            ("Reload", Button::Reload, can.check("ip.dns.adlist.reload")),
            ("Remove", Button::Remove, can.check("ip.dns.adlist.remove")),
        ];
    }
    footer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_send_only_what_changed() {
        let f = AdlistForm {
            url: " https://lists.example/hosts ".into(),
            ssl_verify: false,
            ..AdlistForm::default()
        };
        assert_eq!(
            f.add_params(),
            json!({"url": "https://lists.example/hosts", "ssl_verify": false})
        );
        let base = AdlistForm::of(&json!({"id": "*1", "url": "https://a/x", "ssl_verify": true}));
        assert_eq!(base.set_params("*1", &base), None);
        let mut f = base.clone();
        f.url.clear();
        f.file = "local.txt".into();
        assert_eq!(
            f.set_params("*1", &base),
            Some(json!({"id": "*1", "url": "", "file": "local.txt"}))
        );
    }

    #[test]
    fn rows_show_state_and_age() {
        let r = row(&json!({"id": "*1", "file": "a.txt", "state": "failed", "error": "a.txt: not found",
            "name_count": 0, "match_count": 0, "flags": "X", "disabled": true}));
        assert_eq!(r.cells[1], "file: a.txt");
        assert_eq!(r.cells[2], "failed: a.txt: not found");
        assert!(r.dimmed);
        assert_eq!(ago(Some(7200)), "2 h ago");
        assert_eq!(ago(None), "–");
    }
}

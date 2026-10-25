//! The System › Logging window (G4.6e), WinBox `/system logging` style:
//! the tabs Rules (topics → action, with prefix) and Actions (remote
//! syslog targets and the built-in `memory`, the router's own Log window,
//! of which only the number of lines changes; G4.6d), each a G1.9 table with its toolbar, menus and keys,
//! and "New Logging Rule" / "Logging Rule <id>" / "New Logging Action" /
//! "Logging Action <name>" windows.
//!
//! The engine checks topics, addresses and that an action in use stays
//! (`system.logging.*`); the window offers its known topics as buttons so
//! a typo is rare, and shows the engine's refusal in the dialog.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use egui::{ComboBox, Grid, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "logging";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "logging";
pub(crate) const RULES: &str = "logging-rules";
pub(crate) const ACTIONS: &str = "logging-actions";
/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Logging",
        size: [720.0, 280.0],
        escape: true,
    }],
    new: || Box::new(LogPanel::default()),
};

/// The topics an event can carry (`corerouter_model::logging::TOPICS`,
/// which a test keeps in step; the engine refuses any other).
pub(crate) const TOPICS: [&str; 17] = [
    "account",
    "cgnat",
    "critical",
    "debug",
    "dhcp",
    "dns",
    "error",
    "firewall",
    "info",
    "interface",
    "ntp",
    "ppp",
    "radius",
    "route",
    "system",
    "tool",
    "warning",
];
/// RFC 5424 §6.2.1 order (`Facility::ALL`, kept in step by a test).
pub(crate) const FACILITIES: [&str; 21] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];
const SEVERITIES: [&str; 9] = [
    "auto",
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
];

const RULE_COLUMNS: [table::Column; 4] = [col(""), col("Topics"), col("Prefix"), col("Action")];
const ACTION_COLUMNS: [table::Column; 9] = [
    col("Name"),
    col("Type"),
    num("Lines"),
    col("Remote Address"),
    num("Remote Port"),
    col("Src. Address"),
    col("Facility"),
    col("Severity"),
    comment(),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    Rules,
    Actions,
}

/// System › Logging: rows, dialogs and tables, kept here.
#[derive(Default)]
pub(crate) struct LogPanel {
    pub(crate) tab: Tab,
    /// `system.logging.list` and `.action.list`, while open.
    rules: Vec<Value>,
    actions: Vec<Value>,
    pub(crate) dialogs: Vec<LogDialogWin>,
    pub(crate) rules_table: TableState,
    pub(crate) actions_table: TableState,
}

/// A rule as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleForm {
    /// Comma-separated, `!` excludes: `ntp,!debug`.
    pub topics: String,
    pub prefix: String,
    pub action: String,
    pub disabled: bool,
}

impl RuleForm {
    fn of(row: &Value) -> Self {
        Self {
            topics: text(row, "topics"),
            prefix: text(row, "prefix"),
            action: text(row, "action"),
            disabled: flag(row, "disabled"),
        }
    }

    fn topic_list(&self) -> Vec<String> {
        self.topics
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Add `t` (or `!t`), or take it out if it is there already.
    fn toggle(&mut self, t: &str) {
        let mut list = self.topic_list();
        if let Some(i) = list.iter().position(|x| x == t) {
            list.remove(i);
        } else {
            list.push(t.to_owned());
        }
        self.topics = list.join(", ");
    }

    fn add_params(&self) -> Value {
        json!({
            "topics": self.topic_list(),
            "action": self.action,
            "prefix": self.prefix,
            "disabled": self.disabled,
        })
    }

    fn set_params(&self, id: &str, base: &RuleForm) -> Option<Value> {
        let mut p = Map::new();
        if self.topic_list() != base.topic_list() {
            p.insert("topics".into(), json!(self.topic_list()));
        }
        if self.prefix != base.prefix {
            p.insert("prefix".into(), json!(self.prefix));
        }
        if self.action != base.action {
            p.insert("action".into(), json!(self.action));
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

/// An action as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionForm {
    pub name: String,
    /// The built-in `memory` action: only `memory_lines` applies.
    pub memory: bool,
    /// The built-in `analytics` action (G4.4f): nothing to edit here.
    pub analytics: bool,
    pub memory_lines: String,
    pub remote: String,
    pub remote_port: String,
    /// Empty: the router picks.
    pub src_address: String,
    pub facility: String,
    pub severity: String,
    pub comment: String,
}

impl ActionForm {
    /// RouterOS' defaults: port 514 (RFC 5426 §3.3), daemon, auto.
    fn new() -> Self {
        Self {
            name: String::new(),
            memory: false,
            analytics: false,
            memory_lines: String::new(),
            remote: String::new(),
            remote_port: "514".into(),
            src_address: String::new(),
            facility: "daemon".into(),
            severity: "auto".into(),
            comment: String::new(),
        }
    }

    fn of(row: &Value) -> Self {
        Self {
            name: text(row, "name"),
            memory: text(row, "target") == "memory",
            analytics: text(row, "target") == "analytics",
            memory_lines: text(row, "memory_lines"),
            remote: text(row, "remote"),
            remote_port: text(row, "remote_port"),
            src_address: text(row, "src_address"),
            facility: text(row, "syslog_facility"),
            severity: text(row, "syslog_severity"),
            comment: text(row, "comment"),
        }
    }

    /// The keys that differ from `base`, as add/set take them.
    fn diff(&self, base: &ActionForm) -> Map<String, Value> {
        let mut p = Map::new();
        if self.analytics {
            return p;
        }
        if self.memory {
            if self.memory_lines.trim() != base.memory_lines {
                p.insert("memory_lines".into(), form_number(&self.memory_lines));
            }
            return p;
        }
        if self.remote.trim() != base.remote {
            p.insert("remote".into(), json!(self.remote.trim()));
        }
        if self.remote_port.trim() != base.remote_port {
            p.insert("remote_port".into(), form_number(&self.remote_port));
        }
        if self.src_address.trim() != base.src_address {
            p.insert("src_address".into(), json!(self.src_address.trim()));
        }
        if self.facility != base.facility {
            p.insert("syslog_facility".into(), json!(self.facility));
        }
        if self.severity != base.severity {
            p.insert("syslog_severity".into(), json!(self.severity));
        }
        if self.comment != base.comment {
            p.insert("comment".into(), json!(self.comment));
        }
        p
    }

    fn add_params(&self) -> Value {
        let mut p = self.diff(&Self::new());
        p.insert("name".into(), json!(self.name.trim()));
        p.insert("remote".into(), json!(self.remote.trim()));
        Value::Object(p)
    }

    fn set_params(&self, base: &ActionForm) -> Option<Value> {
        let mut p = self.diff(base);
        if p.is_empty() {
            return None;
        }
        p.insert("name".into(), json!(base.name));
        Some(Value::Object(p))
    }
}

pub(crate) enum LogDialog {
    NewRule {
        form: RuleForm,
        base: RuleForm,
    },
    /// "Logging Rule <id>"; `base` is what the engine has.
    Rule {
        id: String,
        form: RuleForm,
        base: RuleForm,
    },
    NewAction {
        form: ActionForm,
        base: ActionForm,
    },
    /// "Logging Action <name>".
    Action {
        form: ActionForm,
        base: ActionForm,
    },
}

impl LogDialog {
    fn dirty(&self) -> bool {
        match self {
            LogDialog::NewRule { form, base } => form != base,
            LogDialog::Rule { id, form, base } => form.set_params(id, base).is_some(),
            LogDialog::NewAction { form, base } => form != base,
            LogDialog::Action { form, base } => form.set_params(base).is_some(),
        }
    }

    pub(crate) fn title(&self) -> String {
        match self {
            LogDialog::NewRule { .. } => "New Logging Rule".into(),
            LogDialog::Rule { id, .. } => format!("Logging Rule <{id}>"),
            LogDialog::NewAction { .. } => "New Logging Action".into(),
            LogDialog::Action { base, .. } => format!("Logging Action <{}>", base.name),
        }
    }

    /// The row this window shows: (table, key).
    fn shows(&self) -> Option<(&'static str, &str)> {
        match self {
            LogDialog::Rule { id, .. } => Some((RULES, id)),
            LogDialog::Action { base, .. } => Some((ACTIONS, &base.name)),
            LogDialog::NewRule { .. } | LogDialog::NewAction { .. } => None,
        }
    }
}

pub(crate) struct LogDialogWin {
    pub id: u64,
    pub dialog: LogDialog,
    pub status: Status,
}

/// What a dialog's command changes when it succeeds.
enum Applied {
    None,
    Rule(RuleForm),
    Action(ActionForm),
}

struct Reply {
    id: u64,
    applied: Applied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
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

fn some(sel: &[String], what: &str) -> Result<(), String> {
    if sel.is_empty() {
        Err(format!("Select one or more {what} first"))
    } else {
        Ok(())
    }
}

fn can_enable(rules: &[Value], sel: &table::Selection, enable: bool) -> Result<(), String> {
    some(sel, "rules")?;
    let any = rules
        .iter()
        .filter(|r| sel.contains(&text(r, "id")))
        .any(|r| flag(r, "disabled") == enable);
    if any {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

fn rule_row(r: &Value) -> Row {
    let disabled = flag(r, "disabled");
    Row {
        key: text(r, "id"),
        cells: vec![
            if disabled { "X" } else { "" }.into(),
            text(r, "topics"),
            text(r, "prefix"),
            text(r, "action"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

fn action_row(a: &Value) -> Row {
    Row {
        key: text(a, "name"),
        cells: vec![
            text(a, "name"),
            text(a, "target"),
            text(a, "memory_lines"),
            text(a, "remote"),
            text(a, "remote_port"),
            text(a, "src_address"),
            text(a, "syslog_facility"),
            text(a, "syslog_severity"),
            text(a, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl PanelState for LogPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) && self.dialogs.is_empty() {
            return Vec::new();
        }
        vec![
            Query {
                key: "rules",
                command: "system.logging.list",
                params: Value::Null,
            },
            Query {
                key: "actions",
                command: "system.logging.action.list",
                params: Value::Null,
            },
        ]
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let rows = match value {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        match key {
            "rules" => self.rules = rows,
            "actions" => self.actions = rows,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Rules, "Rules");
            ui.selectable_value(&mut self.tab, Tab::Actions, "Actions");
        });
        ui.separator();
        self.list(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.draw_dialogs(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>() {
            self.dialog_reply(app, *r, result);
        }
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Rules => self.rules_table.escape(),
            Tab::Actions => self.actions_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(RULES, &self.rules_table), (ACTIONS, &self.actions_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (RULES, &mut self.rules_table),
            (ACTIONS, &mut self.actions_table),
        ]
    }
}

impl LogPanel {
    /// The table of the open tab, its toolbar, menus and keys.
    fn list(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let rules_tab = self.tab == Tab::Rules;
        let (salt, columns, rows, add_cmd, set_cmd, remove_cmd, what): (
            &str,
            &[table::Column],
            Vec<Row>,
            &str,
            &str,
            &str,
            &str,
        ) = if rules_tab {
            (
                RULES,
                &RULE_COLUMNS,
                self.rules.iter().map(rule_row).collect(),
                "system.logging.add",
                "system.logging.set",
                "system.logging.remove",
                "rules",
            )
        } else {
            (
                ACTIONS,
                &ACTION_COLUMNS,
                self.actions.iter().map(action_row).collect(),
                "system.logging.action.add",
                "system.logging.action.set",
                "system.logging.action.remove",
                "actions",
            )
        };
        let rules = self.rules.clone();
        let open: std::collections::BTreeSet<String> = self
            .dialogs
            .iter()
            .filter_map(|d| d.dialog.shows())
            .filter(|(t, _)| *t == salt)
            .map(|(_, k)| k.to_owned())
            .collect();
        let state = if rules_tab {
            &mut self.rules_table
        } else {
            &mut self.actions_table
        };
        let selection = state.selection(&rows);
        let mut act: Option<Act> = None;
        let can = app.can();
        let add_label = if rules_tab {
            "Add Rule…"
        } else {
            "Add Action…"
        };

        ui.horizontal(|ui| {
            if table::tool(ui, salt, Icon::Add, "Add", can.check(add_cmd)).clicked() {
                act = Some(Act::New);
            }
            let remove = can.and(remove_cmd, some(&selection, what));
            if table::tool(ui, salt, Icon::Remove, "Remove", remove).clicked() {
                act = Some(Act::Remove(selection.to_vec()));
            }
            if rules_tab {
                let tools = [
                    (Icon::Enable, "Enable", true),
                    (Icon::Disable, "Disable", false),
                ];
                for (icon, tip, enable) in tools {
                    let ok = can.and(set_cmd, can_enable(&rules, &selection, enable));
                    if table::tool(ui, salt, icon, tip, ok).clicked() {
                        act = Some(if enable {
                            Act::Enable(selection.to_vec())
                        } else {
                            Act::Disable(selection.to_vec())
                        });
                    }
                }
            }
            table::find_field(ui, salt, state);
        });
        ui.separator();

        state.open = open;
        let out = table::show(ui, salt, 0.0, state, columns, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let owned = || sel.to_vec();
                if rules_tab {
                    if action(
                        ui,
                        "Enable",
                        can.and(set_cmd, can_enable(&rules, sel, true)),
                    ) {
                        act = Some(Act::Enable(owned()));
                    }
                    if action(
                        ui,
                        "Disable",
                        can.and(set_cmd, can_enable(&rules, sel, false)),
                    ) {
                        act = Some(Act::Disable(owned()));
                    }
                }
                if action(ui, "Remove", can.and(remove_cmd, some(sel, what))) {
                    act = Some(Act::Remove(owned()));
                }
                if action(ui, "Properties…", some(sel, what)) {
                    act = Some(Act::Open(owned()));
                }
                ui.separator();
                if action(ui, add_label, can.check(add_cmd)) {
                    act = Some(Act::New);
                }
            }
            Menu::Empty => {
                if action(ui, add_label, can.check(add_cmd)) {
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
        if let Some(key) = out.opened.or(out.comment) {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = state.selection(&rows);
            let allowed = match s {
                Shortcut::Remove | Shortcut::Comment | Shortcut::Open => some(&sel, what).is_ok(),
                Shortcut::Enable => rules_tab && can_enable(&rules, &sel, true).is_ok(),
                Shortcut::Disable => rules_tab && can_enable(&rules, &sel, false).is_ok(),
            };
            if allowed {
                act = Some(match s {
                    Shortcut::Remove => Act::Remove(sel.into_vec()),
                    Shortcut::Enable => Act::Enable(sel.into_vec()),
                    Shortcut::Disable => Act::Disable(sel.into_vec()),
                    Shortcut::Comment | Shortcut::Open => Act::Open(sel.into_vec()),
                });
            }
        }
        if let Some(a) = act {
            self.act(app, a, &rows);
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, rows: &[Row]) {
        let rules_tab = self.tab == Tab::Rules;
        let key = if rules_tab { "id" } else { "name" };
        match act {
            // Actions have no enable/disable.
            Act::Enable(_) | Act::Disable(_) if !rules_tab => {}
            Act::Enable(keys) => {
                for k in keys {
                    app.run("system.logging.set", json!({"id": k, "disabled": false}));
                }
            }
            Act::Disable(keys) => {
                for k in keys {
                    app.run("system.logging.set", json!({"id": k, "disabled": true}));
                }
            }
            Act::Remove(keys) => {
                let cmd = if rules_tab {
                    "system.logging.remove"
                } else {
                    "system.logging.action.remove"
                };
                for k in keys {
                    app.run(cmd, json!({ key: k }));
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_row(app, k);
                }
            }
            Act::New => {
                let dialog = if rules_tab {
                    let form = RuleForm {
                        topics: "info".into(),
                        action: self
                            .actions
                            .first()
                            .map(|a| text(a, "name"))
                            .unwrap_or_default(),
                        ..RuleForm::default()
                    };
                    LogDialog::NewRule {
                        base: form.clone(),
                        form,
                    }
                } else {
                    let taken: Vec<String> = self.actions.iter().map(|a| text(a, "name")).collect();
                    let name = (1..)
                        .map(|i| format!("remote{i}"))
                        .find(|n| !taken.contains(n))
                        .unwrap_or_default();
                    let form = ActionForm {
                        name,
                        ..ActionForm::new()
                    };
                    LogDialog::NewAction {
                        base: form.clone(),
                        form,
                    }
                };
                self.open_dialog(app, dialog);
            }
            Act::SelectAll => match self.tab {
                Tab::Rules => self.rules_table.select_all(rows),
                Tab::Actions => self.actions_table.select_all(rows),
            },
            Act::Refresh => app.cache.refreshed_at = None,
        }
    }

    fn open_dialog(&mut self, app: &mut CoreRouterUi, dialog: LogDialog) {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.dialogs.push(LogDialogWin {
            id: app.next_dialog,
            dialog,
            status: Status::default(),
        });
        app.cache.refreshed_at = None;
    }

    /// The properties window of row `key` in the open tab; an already open
    /// one comes to the front.
    pub(crate) fn open_row(&mut self, app: &mut CoreRouterUi, key: &str) {
        let salt = match self.tab {
            Tab::Rules => RULES,
            Tab::Actions => ACTIONS,
        };
        if let Some(d) = self
            .dialogs
            .iter_mut()
            .find(|d| d.dialog.shows() == Some((salt, key)))
        {
            d.status.bring_to_front();
            return;
        }
        let dialog = match self.tab {
            Tab::Rules => {
                let Some(r) = self.rules.iter().find(|r| text(r, "id") == key) else {
                    return;
                };
                let form = RuleForm::of(r);
                LogDialog::Rule {
                    id: key.to_owned(),
                    base: form.clone(),
                    form,
                }
            }
            Tab::Actions => {
                let Some(a) = self.actions.iter().find(|a| text(a, "name") == key) else {
                    return;
                };
                let form = ActionForm::of(a);
                LogDialog::Action {
                    base: form.clone(),
                    form,
                }
            }
        };
        self.open_dialog(app, dialog);
    }

    fn draw_dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let rules = self.rules.clone();
        let actions = self.actions.clone();
        let names: Vec<String> = actions.iter().map(|a| text(a, "name")).collect();
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            // A window whose row is gone closes itself.
            let row = match d.dialog.shows() {
                Some((RULES, id)) => rules.iter().find(|r| text(r, "id") == id),
                Some((_, name)) => actions.iter().find(|a| text(a, "name") == name),
                None => None,
            };
            let gone = match d.dialog.shows() {
                Some((RULES, _)) => !rules.is_empty() && row.is_none(),
                Some(_) => !actions.is_empty() && row.is_none(),
                None => false,
            };
            if gone {
                app.floats.forget(wid);
                return false;
            }
            let row = row.cloned();
            let title = d.dialog.title();
            let can = app.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Panel(WIN))),
            };
            let pressed =
                dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(ui, f, &mut d.dialog, row.as_ref(), &names, &can)
                });
            let keep = pressed.is_none_or(|b| self.button(app, d, b, row.as_ref()));
            if !keep {
                app.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    fn button(
        &mut self,
        app: &mut CoreRouterUi,
        d: &mut LogDialogWin,
        b: Press<Button>,
        row: Option<&Value>,
    ) -> bool {
        let ok = b == Press::Ok;
        let (cmd, params, applied, close) = match (&d.dialog, b) {
            (_, Press::Cancel) => return false,
            (LogDialog::NewRule { form, .. }, _) => {
                ("system.logging.add", form.add_params(), Applied::None, true)
            }
            (LogDialog::NewAction { form, .. }, _) => (
                "system.logging.action.add",
                form.add_params(),
                Applied::None,
                true,
            ),
            (LogDialog::Rule { id, form, base }, Press::Ok | Press::Apply) => {
                match form.set_params(id, base) {
                    Some(p) => ("system.logging.set", p, Applied::Rule(form.clone()), ok),
                    None => return !ok,
                }
            }
            (LogDialog::Action { form, base }, Press::Ok | Press::Apply) => {
                match form.set_params(base) {
                    Some(p) => (
                        "system.logging.action.set",
                        p,
                        Applied::Action(form.clone()),
                        ok,
                    ),
                    None => return !ok,
                }
            }
            (LogDialog::Rule { id, .. }, Press::Other(Button::Toggle)) => {
                let now = row.is_some_and(|r| flag(r, "disabled"));
                (
                    "system.logging.set",
                    json!({"id": id, "disabled": !now}),
                    Applied::None,
                    false,
                )
            }
            (LogDialog::Rule { id, .. }, Press::Other(Button::Remove)) => (
                "system.logging.remove",
                json!({ "id": id }),
                Applied::None,
                true,
            ),
            (LogDialog::Action { base, .. }, Press::Other(_)) => (
                "system.logging.action.remove",
                json!({ "name": base.name }),
                Applied::None,
                true,
            ),
        };
        d.status.close_on_success = close;
        d.status.sent();
        app.run_then(
            cmd,
            params,
            crate::panel::then(NAME, Reply { id: d.id, applied }),
        );
        true
    }

    /// A reply to a dialog's command: an error stays in the dialog.
    fn dialog_reply(&mut self, app: &mut CoreRouterUi, r: Reply, result: &Result<Value, String>) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == r.id) else {
            return;
        };
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, r.applied, &mut d.dialog) {
                    (Ok(_), Applied::Rule(sent), LogDialog::Rule { base, .. }) => *base = sent,
                    (Ok(_), Applied::Action(sent), LogDialog::Action { base, .. }) => *base = sent,
                    _ => {}
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            app.floats.forget(dialog_id(r.id));
        }
        app.cache.refreshed_at = None;
    }
}

fn combo(ui: &mut Ui, label: &str, salt: &str, value: &mut String, options: &[&str]) {
    ui.label(label);
    ComboBox::from_id_salt(salt)
        .selected_text(value.as_str())
        .show_ui(ui, |ui| {
            for o in options {
                ui.selectable_value(value, (*o).to_owned(), *o);
            }
        });
    ui.end_row();
}

/// The topic buttons under the Topics field: click adds, click again
/// takes out; right click adds the `!` (exclude) form.
fn topic_buttons(ui: &mut Ui, form: &mut RuleForm) {
    ui.label("");
    let list = form.topic_list();
    Grid::new("logging-topics").num_columns(4).show(ui, |ui| {
        for (i, t) in TOPICS.into_iter().enumerate() {
            let neg = format!("!{t}");
            let on = list.iter().any(|x| x == t);
            let off = list.contains(&neg);
            let label = if off { neg.clone() } else { t.to_owned() };
            let resp = ui
                .selectable_label(on || off, label)
                .on_hover_text("Click: match this topic. Right click: exclude it (!).");
            if resp.clicked() {
                if off {
                    form.toggle(&neg);
                }
                form.toggle(t);
            } else if resp.secondary_clicked() {
                if on {
                    form.toggle(t);
                }
                form.toggle(&neg);
            }
            if i % 4 == 3 {
                ui.end_row();
            }
        }
    });
    ui.end_row();
}

fn dialog_body(
    ui: &mut Ui,
    f: &Form,
    d: &mut LogDialog,
    row: Option<&Value>,
    actions: &[String],
    can: &Avail,
) -> Footer<Button> {
    let (ok_cmd, rule) = match d {
        LogDialog::NewRule { .. } => ("system.logging.add", true),
        LogDialog::Rule { .. } => ("system.logging.set", true),
        LogDialog::NewAction { .. } => ("system.logging.action.add", false),
        LogDialog::Action { .. } => ("system.logging.action.set", false),
    };
    let props = row.is_some();
    Grid::new("logging-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| match d {
            LogDialog::NewRule { form, .. } | LogDialog::Rule { form, .. } => {
                f.text(ui, "Topics", "topics", &mut form.topics, "info");
                topic_buttons(ui, form);
                f.text(ui, "Prefix", "prefix", &mut form.prefix, "");
                ui.label("Action");
                ComboBox::from_id_salt("logging-action")
                    .selected_text(form.action.as_str())
                    .show_ui(ui, |ui| {
                        for a in actions {
                            ui.selectable_value(&mut form.action, a.clone(), a.as_str());
                        }
                    });
                ui.end_row();
                if actions.is_empty() {
                    ui.label("");
                    ui.weak("No action yet: add one on the Actions tab");
                    ui.end_row();
                }
                if props {
                    ui.label("Disabled");
                    ui.checkbox(&mut form.disabled, "");
                    ui.end_row();
                }
            }
            LogDialog::NewAction { form, .. } | LogDialog::Action { form, .. } => {
                if props {
                    ui.label("Name");
                    ui.label(form.name.as_str());
                    ui.end_row();
                } else {
                    f.text(ui, "Name", "name", &mut form.name, "remote1");
                }
                ui.label("Type");
                ui.label(if form.memory {
                    "memory"
                } else if form.analytics {
                    "analytics"
                } else {
                    "remote"
                });
                ui.end_row();
                if form.analytics {
                    ui.label("");
                    ui.weak("The ClickHouse exporter's logs table: set it up in System › Analytics");
                    ui.end_row();
                    return;
                }
                if form.memory {
                    f.text(ui, "Lines", "memory_lines", &mut form.memory_lines, "1000");
                    ui.label("");
                    ui.weak("The router's own log (Log window): the newest lines kept");
                    ui.end_row();
                    return;
                }
                f.text(ui, "Remote Address", "remote", &mut form.remote, "192.0.2.10");
                f.text(ui, "Remote Port", "remote_port", &mut form.remote_port, "514");
                f.text(
                    ui,
                    "Src. Address",
                    "src_address",
                    &mut form.src_address,
                    "(chosen by the route)",
                );
                combo(
                    ui,
                    "Syslog Facility",
                    "logging-facility",
                    &mut form.facility,
                    &FACILITIES,
                );
                combo(
                    ui,
                    "Syslog Severity",
                    "logging-severity",
                    &mut form.severity,
                    &SEVERITIES,
                );
                f.text(ui, "Comment", "comment", &mut form.comment, "");
            }
        });
    let mut footer = Footer::edit(true, can.check(ok_cmd));
    if let Some(r) = row {
        if rule {
            let disabled = flag(r, "disabled");
            footer.extra = vec![
                (
                    if disabled { "Enable" } else { "Disable" },
                    Button::Toggle,
                    can.check("system.logging.set"),
                ),
                ("Remove", Button::Remove, can.check("system.logging.remove")),
            ];
        } else if text(r, "target") == "remote" {
            footer.extra = vec![(
                "Remove",
                Button::Remove,
                can.check("system.logging.action.remove"),
            )];
        }
    }
    footer
}

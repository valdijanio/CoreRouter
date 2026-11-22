//! Routing › Rules (G1.27e), RouterOS v7 `/routing rule` and `/routing table`:
//! the policy rules in order, in the list window pattern (G0.24); the named
//! tables; the kernel's whole rule list with who wrote each line; and a
//! packet test that says which rule decides. `routing.rule.*`,
//! `routing.table.*` and `ip.route.lookup` decide; this only shows and sends.

use std::collections::BTreeMap;

use egui::{Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell, name_hue};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "routing-rules";
pub(crate) const WIN: &str = "routing-rules";
const SCOPE: &str = "routing_rules";
pub(crate) const RULES: &str = "routing-rules-table";
const TABLES: &str = "routing-tables-table";
const KERNEL: &str = "routing-kernel-table";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Routing",
        title: "Rules",
        size: [1100.0, 620.0],
        escape: true,
    }],
    new: || Box::<RulesPanel>::default(),
};

const RULE_CMDS: Cmds = Cmds {
    add: "routing.rule.add",
    remove: "routing.rule.remove",
    set: Some("routing.rule.set"),
    what: "rules",
};

const TABLE_CMDS: Cmds = Cmds {
    add: "routing.table.add",
    remove: "routing.table.remove",
    set: Some("routing.table.set"),
    what: "tables",
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

const RULE_FIELDS: &[Field] = &[
    field("src_address", "Src. Address", "rules.src_address", Input::Text("10.91.0.0/24")),
    field("dst_address", "Dst. Address", "rules.dst_address", Input::Text("any")),
    field("interface", "Interface", "rules.interface", Input::Choice),
    field("routing_mark", "Routing Mark", "rules.routing_mark", Input::Text("set by the mangle")),
    field("action", "Action", "rules.action", Input::Choice),
    field("table", "Table", "rules.table", Input::Choice),
    field("min_prefix", "Min. Prefix", "rules.min_prefix", Input::Text("0 hides the default route")),
    field("disabled", "Disabled", "rules.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const RULE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Routing Rule",
    edit_title: "Routing Rule",
    help: "rules",
    fields: RULE_FIELDS,
    preview: "routing.rule.preview",
};

const TABLE_FIELDS: &[Field] = &[
    Field {
        param: "name",
        label: "Name",
        help: "tables.name",
        input: Input::Text("isp2"),
        edit: false,
    },
    field("comment", "Comment", "", Input::Text("")),
];

const TABLE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Routing Table",
    edit_title: "Routing Table",
    help: "tables",
    fields: TABLE_FIELDS,
    preview: "routing.table.preview",
};

const RULE_COLUMNS: [table::Column; 10] = [
    num("#").help("rules.order"),
    col("State").help("rules.state"),
    col("Src. Address").help("rules.src_address"),
    col("Dst. Address").help("rules.dst_address"),
    col("Interface").help("rules.interface"),
    col("Routing Mark").help("rules.routing_mark"),
    col("Action").help("rules.action"),
    col("Table").help("rules.table"),
    num("Min. Prefix").help("rules.min_prefix"),
    comment(),
];

const TABLE_COLUMNS: [table::Column; 7] = [
    col("Name").help("tables.name"),
    col("Type").help("tables.type"),
    num("Kernel Table").help("tables.table"),
    num("Routes").help("tables.routes"),
    num("Rules").help("tables.rules"),
    num("Marks").help("tables.marks"),
    comment(),
];

const KERNEL_COLUMNS: [table::Column; 8] = [
    num("Priority").help("kernel.priority"),
    col("Family").help("rules.family"),
    col("Owner").help("kernel.owner"),
    col("Match").help("kernel.match"),
    col("Action").help("rules.action"),
    col("Table").help("rules.table"),
    col("Rule").help("kernel.rule"),
    col("What").help("kernel.what"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Rules,
    Tables,
    Kernel,
}

/// Which list an open modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Editing {
    Rule,
    Table,
}

#[derive(Default)]
pub(crate) struct RulesPanel {
    tab: Tab,
    pub(crate) rules: Vec<Value>,
    pub(crate) tables: Vec<Value>,
    pub(crate) kernel: Value,
    rule_table: TableState,
    table_table: TableState,
    kernel_table: TableState,
    pub(crate) modal: Option<(Editing, Modal)>,
    pub(crate) address: String,
    pub(crate) src: String,
    pub(crate) interface: String,
    pub(crate) mark: String,
    pub(crate) answer: Option<Value>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn action_kind(action: &str) -> Kind {
    match action {
        "drop" | "unreachable" => Kind::Red,
        "lookup-only-in-table" => Kind::Amber,
        _ => Kind::Blue,
    }
}

fn table_cell(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    cell("", &[(name, Kind::Hashed(name_hue(name)))])
}

fn rule_row(r: &Value) -> Row {
    let disabled = r.get("disabled").and_then(Value::as_bool) == Some(true);
    let notices = r.get("notices").and_then(Value::as_array).map_or(0, Vec::len);
    let state: &[(&str, Kind)] = match (disabled, notices) {
        (true, _) => &[("disabled", Kind::Neutral)],
        (false, 0) => &[("active", Kind::Green)],
        (false, _) => &[("active", Kind::Green), ("warning", Kind::Amber)],
    };
    let action = s(r, "action");
    let iface = s(r, "interface");
    Row {
        key: s(r, "id"),
        cells: vec![
            r.get("position").and_then(Value::as_u64).map_or_else(String::new, |p| p.to_string()),
            cell("", state),
            s(r, "src_address"),
            s(r, "dst_address"),
            table_cell(&iface),
            s(r, "routing_mark"),
            cell("", &[(action.as_str(), action_kind(&action))]),
            table_cell(&s(r, "table")),
            s(r, "min_prefix"),
            s(r, "comment"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

fn table_row(r: &Value) -> Row {
    let name = s(r, "name");
    let kind = s(r, "type");
    Row {
        key: name.clone(),
        cells: vec![
            table_cell(&name),
            cell("", &[(kind.as_str(), Kind::Neutral)]),
            s(r, "table"),
            s(r, "routes"),
            s(r, "rules"),
            s(r, "marks"),
            s(r, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn kernel_row(r: &Value, i: usize) -> Row {
    let owner = s(r, "owner");
    let owner_kind = match owner.as_str() {
        "corerouter" => Kind::Blue,
        "foreign" => Kind::Amber,
        _ => Kind::Neutral,
    };
    let mut matches: Vec<String> = Vec::new();
    for (key, label) in [("src", "from"), ("dst", "to"), ("iif", "iif"), ("fwmark", "fwmark")] {
        let v = s(r, key);
        if !v.is_empty() {
            matches.push(format!("{label} {v}"));
        }
    }
    if r.get("l3mdev").and_then(Value::as_bool) == Some(true) {
        matches.push("l3mdev".to_owned());
    }
    let action = s(r, "action");
    Row {
        key: i.to_string(),
        cells: vec![
            s(r, "priority"),
            s(r, "family"),
            cell("", &[(owner.as_str(), owner_kind)]),
            matches.join(" "),
            cell("", &[(action.as_str(), action_kind(&action))]),
            table_cell(&s(r, "table")),
            s(r, "rule"),
            s(r, "what"),
        ],
        dimmed: owner == "kernel",
        section: false,
        tint: None,
    }
}

fn rule_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in RULE_FIELDS {
        let text = match f.param {
            "disabled" => if r.get("disabled").and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned(),
            p => s(r, p),
        };
        v.insert(f.param, text);
    }
    v
}

/// What `routing.rule.add` takes of a row, to copy it as a command.
fn rule_params(r: &Value) -> Value {
    let mut p = Map::new();
    for k in ["src_address", "dst_address", "interface", "routing_mark", "action", "table", "min_prefix", "disabled", "comment"] {
        if let Some(v) = r.get(k).filter(|v| !v.is_null() && **v != json!("") && **v != json!(false)) {
            p.insert(k.into(), v.clone());
        }
    }
    Value::Object(p)
}

/// The reply of a packet test.
struct Tested;

impl RulesPanel {
    fn help_for(&mut self, key: &'static str, title: &str) {
        self.help = Some(HelpView::new(key, title.to_owned()));
    }

    fn tabs(&mut self, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            for (tab, label, key) in [
                (Tab::Rules, "Rules", "rules"),
                (Tab::Tables, "Tables", "tables"),
                (Tab::Kernel, "Kernel List", "kernel"),
            ] {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                }
                if help::info_button(ui, Id::unique(("routing-rules-tab", key)), tr_in(SCOPE, l, label)).clicked() {
                    self.help_for(key, tr_in(SCOPE, l, label));
                }
            }
        });
    }

    fn open_rule(&mut self, app: &mut CoreRouterUi, id: &str) {
        if let Some(r) = self.rules.iter().find(|r| s(r, "id") == id) {
            let m = Modal::open(app, Some((id.to_owned(), s(r, "summary"))), rule_values(r));
            self.modal = Some((Editing::Rule, m));
        }
    }

    fn act_rule(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut values = BTreeMap::new();
                    values.insert("action", "lookup".to_owned());
                    values.insert("table", "main".to_owned());
                    values.insert("disabled", "no".to_owned());
                    self.modal = Some((Editing::Rule, Modal::open(app, None, values)));
                }
            }
            Act::Edit(k) => self.open_rule(app, &k),
            Act::Comment(keys) => {
                if let Some(k) = keys.into_iter().next() {
                    self.open_rule(app, &k);
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": RULE_CMDS.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                let to = matches!(act, Act::Disable(_));
                let steps: Vec<Value> = keys
                    .iter()
                    .map(|k| json!({"command": "routing.rule.set", "params": {"id": k, "disabled": to}}))
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
                    .filter_map(|k| self.rules.iter().find(|r| s(r, "id") == *k))
                    .map(rule_params)
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, RULE_CMDS.add, &refs, syntax));
            }
        }
    }

    fn rules_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.rules.iter().map(rule_row).collect();
        let selection = self.rule_table.selection(&rows);
        let picked: Vec<Item> = self
            .rules
            .iter()
            .filter(|r| selection.contains(&s(r, "id")))
            .map(|r| Item::of(r, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &RULE_CMDS, &picked);
        let mut act = None;
        // Moving one rule at a time: the order is what decides.
        let one = selection.iter().next().filter(|_| selection.len() == 1).cloned();
        let at = one.as_ref().and_then(|k| self.rules.iter().position(|r| s(r, "id") == *k));
        let can_move = |ok: bool| {
            let why = if one.is_none() { "select one rule" } else { "it is already there" };
            app.can().and("routing.rule.move", if one.is_some() && ok { Ok(()) } else { Err(why.to_owned()) })
        };
        let up = can_move(at.is_some_and(|p| p > 0));
        let down = can_move(at.is_some_and(|p| p + 1 < self.rules.len()));
        let mut moved: Option<Value> = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, RULES, &tools, &selection, l);
            if table::action(ui, tr_in(SCOPE, l, "Move Up"), up)
                && let (Some(k), Some(p)) = (&one, at)
            {
                let before = self.rules.get(p.saturating_sub(1)).map(|r| s(r, "id"));
                moved = Some(json!({"id": k, "place_before": before}));
            }
            if table::action(ui, tr_in(SCOPE, l, "Move Down"), down)
                && let (Some(k), Some(p)) = (&one, at)
            {
                let before = self.rules.get(p + 2).map(|r| s(r, "id"));
                moved = Some(match before {
                    Some(b) => json!({"id": k, "place_before": b}),
                    None => json!({"id": k}),
                });
            }
            table::find_field(ui, RULES, &mut self.rule_table);
        });
        if let Some(p) = moved {
            app.run_steps(vec![json!({"command": "routing.rule.move", "params": p})], Then::Nothing);
        }
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 6.0 + 40.0;
        let out = table::show(ui, RULES, footer_h, &mut self.rule_table, &RULE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Rule…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = RULE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help_for(key, tr_in(SCOPE, l, title));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let warnings = self
            .rules
            .iter()
            .filter(|r| r.get("notices").and_then(Value::as_array).is_some_and(|n| !n.is_empty()))
            .count();
        list::footer(
            ui,
            &[
                (self.rules.len(), "rules", chip::neutral_tone(&v)),
                (list::count(&self.rules, "disabled", "true"), "disabled", chip::neutral_tone(&v)),
                (warnings, "with a warning", chip::AMBER.tone(&v)),
            ],
            l,
        );
        // Why the rows in amber are so.
        for r in &self.rules {
            for n in r.get("notices").and_then(Value::as_array).into_iter().flatten() {
                ui.horizontal(|ui| {
                    chip::chip(ui, &s(r, "id"), chip::AMBER.tone(&v));
                    ui.label(s(n, "text"));
                });
            }
        }
        if self.rules.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No rule yet: every packet uses the main table. + adds one."));
        }
        ui.separator();
        self.test_box(app, ui, l);
        if let Some(a) = act {
            self.act_rule(app, a, ui, &rows);
        }
    }

    /// "Which rule decides for this packet?": `ip.route.lookup`.
    fn test_box(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Test a Packet"));
            if help::info_button(ui, Id::unique("routing-rules-test"), tr_in(SCOPE, l, "Test a Packet")).clicked() {
                self.help_for("rules.test", tr_in(SCOPE, l, "Test a Packet"));
            }
            for (text, hint) in [
                (&mut self.address, "to: 8.8.8.8"),
                (&mut self.src, "from: 10.91.0.7"),
                (&mut self.interface, "in: ether3"),
                (&mut self.mark, "routing mark"),
            ] {
                ui.add(TextEdit::singleline(text).hint_text(tr_in(SCOPE, l, hint)).desired_width(120.0));
            }
            let ready = !self.address.trim().is_empty();
            let can = if ready {
                app.can().check("ip.route.lookup")
            } else {
                Err("type a destination".to_owned())
            };
            if table::action(ui, tr_in(SCOPE, l, "Test"), can) {
                let mut p = Map::new();
                p.insert("address".into(), json!(self.address.trim()));
                for (key, text) in [("src", &self.src), ("interface", &self.interface), ("routing_mark", &self.mark)] {
                    if !text.trim().is_empty() {
                        p.insert(key.into(), json!(text.trim()));
                    }
                }
                app.run_then("ip.route.lookup", Value::Object(p), crate::panel::then(NAME, Tested));
            }
        });
        let Some(a) = &self.answer else {
            return;
        };
        let v = ui.visuals().clone();
        if let Some(e) = a.get("error") {
            ui.colored_label(v.error_fg_color, value_text(e));
            return;
        }
        ui.horizontal_wrapped(|ui| {
            let kind = s(a, "type");
            let tone = match kind.as_str() {
                "unicast" | "local" => chip::GREEN.tone(&v),
                _ => chip::RED.tone(&v),
            };
            chip::chip(ui, &kind, tone);
            let table = s(a, "routing_table");
            chip::chip(ui, &table, chip::palette_tone(&v, name_hue(&table)));
            let hop = s(a, "gateway");
            let out = s(a, "interface");
            if !out.is_empty() {
                ui.label(if hop.is_empty() { out } else { format!("{hop} %{out}") });
            }
            ui.weak(s(a, "rule"));
            if a.get("kernel").and_then(|k| k.get("same")).and_then(Value::as_bool) == Some(false) {
                let diff = a.get("kernel").and_then(|k| k.get("differences")).map(value_text).unwrap_or_default();
                chip::chip(ui, tr_in(SCOPE, l, "kernel differs"), chip::AMBER.tone(&v)).on_hover_text(diff);
            }
        });
        for step in a.get("trace").and_then(Value::as_array).into_iter().flatten() {
            ui.horizontal(|ui| {
                ui.monospace(s(step, "priority"));
                ui.label(s(step, "what"));
                ui.weak(s(step, "result"));
            });
        }
    }

    fn tables_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.tables.iter().map(table_row).collect();
        let selection = self.table_table.selection(&rows);
        let picked: Vec<Item> = self
            .tables
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", "main and the VRFs are not removed here"))
            .collect();
        let tools = Tools::new(&app.can(), &TABLE_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLES, &tools, &selection, l);
            table::find_field(ui, TABLES, &mut self.table_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let out = table::show(ui, TABLES, 0.0, &mut self.table_table, &TABLE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Table…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = TABLE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help_for(key, tr_in(SCOPE, l, title));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let open = |me: &mut Self, app: &mut CoreRouterUi, k: &str| {
            let Some(r) = me.tables.iter().find(|r| s(r, "name") == k) else {
                return;
            };
            if r.get("dynamic").and_then(Value::as_bool) == Some(true) {
                return;
            }
            let mut values = BTreeMap::new();
            values.insert("name", s(r, "name"));
            values.insert("comment", s(r, "comment"));
            let m = Modal::open(app, Some((k.to_owned(), k.to_owned())), values);
            me.modal = Some((Editing::Table, m));
        };
        match act {
            Some(Act::Add) => {
                if self.modal.is_none() {
                    self.modal = Some((Editing::Table, Modal::open(app, None, BTreeMap::new())));
                }
            }
            Some(Act::Edit(k)) => open(self, app, &k),
            Some(Act::Comment(keys)) => {
                if let Some(k) = keys.into_iter().next() {
                    open(self, app, &k);
                }
            }
            Some(Act::Remove(keys)) => {
                let steps: Vec<Value> = keys
                    .iter()
                    .map(|k| json!({"command": TABLE_CMDS.remove, "params": {"name": k}}))
                    .collect();
                app.run_steps(steps, Then::Nothing);
            }
            Some(Act::Copy(keys)) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Some(Act::CopyAs(keys, syntax)) => {
                let picked: Vec<Value> = keys.iter().map(|k| json!({"name": k})).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, TABLE_CMDS.add, &refs, syntax));
            }
            Some(Act::Enable(_) | Act::Disable(_)) | None => {}
        }
    }

    fn kernel_tab(&mut self, ui: &mut Ui, l: Lang) {
        let v = ui.visuals().clone();
        let rows_json = self.kernel.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
        if self.kernel.get("available").and_then(Value::as_bool) == Some(false) {
            ui.colored_label(v.warn_fg_color, s(&self.kernel, "reason"));
        }
        for line in self.kernel.get("drift").and_then(Value::as_array).into_iter().flatten() {
            ui.horizontal(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, "drift"), chip::AMBER.tone(&v));
                ui.label(value_text(line));
            });
        }
        let marks: Vec<String> = self
            .kernel
            .get("marks_without_table")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_text).collect())
            .unwrap_or_default();
        if !marks.is_empty() {
            ui.horizontal(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, "marks without a table"), chip::AMBER.tone(&v));
                ui.label(marks.join(", "));
                if help::info_button(ui, Id::unique("routing-rules-marks"), tr_in(SCOPE, l, "marks without a table")).clicked() {
                    self.help_for("kernel.marks", tr_in(SCOPE, l, "marks without a table"));
                }
            });
        }
        let rows: Vec<Row> = rows_json.iter().enumerate().map(|(i, r)| kernel_row(r, i)).collect();
        let out = table::show(ui, KERNEL, 0.0, &mut self.kernel_table, &KERNEL_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = KERNEL_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help_for(key, tr_in(SCOPE, l, title));
        }
    }
}

impl PanelState for RulesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        [
            ("rules", "routing.rule.list"),
            ("tables", "routing.table.list"),
            ("kernel", "routing.rule.kernel"),
        ]
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
                if let Some((_, m)) = &mut self.modal {
                    m.arrived(value);
                }
            }
            "rules" => self.rules = value.as_array().cloned().unwrap_or_default(),
            "tables" => self.tables = value.as_array().cloned().unwrap_or_default(),
            "kernel" => self.kernel = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.tabs(ui, l);
        ui.separator();
        match self.tab {
            Tab::Rules => self.rules_tab(app, ui, l),
            Tab::Tables => self.tables_tab(app, ui, l),
            Tab::Kernel => self.kernel_tab(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let tables: Vec<String> = self.tables.iter().map(|r| s(r, "name")).collect();
        let names = app.interface_names(None);
        let options = move |param: &str| -> Vec<String> {
            match param {
                "action" => ["lookup", "lookup-only-in-table", "drop", "unreachable"].map(str::to_owned).to_vec(),
                "table" => tables.clone(),
                "interface" => names.clone(),
                _ => Vec::new(),
            }
        };
        if let Some((what, m)) = &mut self.modal {
            let spec = match what {
                Editing::Rule => &RULE_SPEC,
                Editing::Table => &TABLE_SPEC,
            };
            if !m.show(app, ctx, area, spec, &options) {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Tested>().is_some() {
            self.answer = Some(match result {
                Ok(v) => v.clone(),
                Err(e) => json!({"error": e}),
            });
            return;
        }
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Rules => self.rule_table.escape(),
            Tab::Tables => self.table_table.escape(),
            Tab::Kernel => self.kernel_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (RULES, &self.rule_table),
            (TABLES, &self.table_table),
            (KERNEL, &self.kernel_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (RULES, &mut self.rule_table),
            (TABLES, &mut self.table_table),
            (KERNEL, &mut self.kernel_table),
        ]
    }
}

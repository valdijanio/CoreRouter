//! Routing › Management Guard (G3.4z): the networks the router is managed
//! from, which no learned route may cut into, in the list window pattern
//! (G0.24); above the list, the sessions a learned route covers now and
//! the management networks not guarded yet, each with its Protect button
//! (`routing.management-guard.*` decides; this only shows and sends).

use std::collections::BTreeMap;

use egui::{Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell, name_hue};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "management-guard";
pub(crate) const WIN: &str = "management-guard";
pub(crate) const SCOPE: &str = "management_guard";
const TABLE: &str = "management-guard-table";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Routing",
        title: "Management Guard",
        size: [980.0, 560.0],
        escape: true,
    }],
    new: || Box::<GuardPanel>::default(),
};

const CMDS: Cmds = Cmds {
    add: "routing.management-guard.add",
    remove: "routing.management-guard.remove",
    set: Some("routing.management-guard.set"),
    what: "networks",
};

const FIELDS: &[Field] = &[
    Field {
        param: "network",
        label: "Network",
        help: "management_guard.network",
        input: Input::Text("192.168.0.0/24"),
        edit: true,
    },
    Field {
        param: "disabled",
        label: "Disabled",
        help: "management_guard.disabled",
        input: Input::Check,
        edit: true,
    },
    Field {
        param: "comment",
        label: "Comment",
        help: "",
        input: Input::Text(""),
        edit: true,
    },
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Guarded Network",
    edit_title: "Guarded Network",
    help: "management_guard",
    fields: FIELDS,
    preview: "routing.management-guard.check",
};

const COLUMNS: [table::Column; 6] = [
    col("Network").help("management_guard.network"),
    col("Interface").help("management_guard.interface"),
    num("Sessions").help("management_guard.sessions"),
    col("Refused").help("management_guard.refused"),
    col("State").help("management_guard.state"),
    comment(),
];

#[derive(Default)]
pub(crate) struct GuardPanel {
    pub(crate) list: Value,
    pub(crate) suggest: Vec<Value>,
    table: TableState,
    pub(crate) modal: Option<Modal>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn rows_of(list: &Value) -> Vec<Value> {
    list.get("rows").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn row(r: &Value) -> Row {
    let disabled = r.get("disabled").and_then(Value::as_bool) == Some(true);
    let state = s(r, "state");
    let mut chips: Vec<(&str, Kind)> = vec![(
        state.as_str(),
        match state.as_str() {
            "active" => Kind::Green,
            "not-applied" => Kind::Amber,
            _ => Kind::Neutral,
        },
    )];
    let covered = r.get("covered").and_then(Value::as_u64).unwrap_or(0);
    if covered > 0 {
        chips.push(("covered", Kind::Red));
    }
    let installed = r.get("installed").and_then(Value::as_u64).unwrap_or(0);
    if installed > 0 {
        chips.push(("in kernel", Kind::Amber));
    }
    let refused = match s(r, "rib").as_str() {
        "ready" => s(r, "refused_text"),
        "pending" => "…".to_owned(),
        _ => "–".to_owned(),
    };
    let iface = s(r, "interface");
    Row {
        key: s(r, "id"),
        cells: vec![
            s(r, "network"),
            if iface.is_empty() { String::new() } else { cell("", &[(iface.as_str(), Kind::Hashed(name_hue(&iface)))]) },
            s(r, "sessions"),
            refused,
            cell("", &chips),
            s(r, "comment"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

fn values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    v.insert("network", s(r, "network"));
    v.insert("disabled", if r.get("disabled").and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned());
    v.insert("comment", s(r, "comment"));
    v
}

/// "GUI admin 192.168.0.2; MCP admin 192.168.0.9".
pub(crate) fn sessions_text(who: &Value) -> String {
    who.as_array()
        .into_iter()
        .flatten()
        .take(4)
        .map(|w| {
            let closed = if w.get("open").and_then(Value::as_bool) == Some(false) { " (closed)" } else { "" };
            format!("{} {} {}{closed}", s(w, "via"), s(w, "user"), s(w, "peer"))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Ask the router to guard `network` (the Protect buttons).
pub(crate) fn protect(app: &mut CoreRouterUi, network: &str) {
    app.run_steps(
        vec![json!({"command": CMDS.add, "params": {"network": network}})],
        Then::Nothing,
    );
}

/// Open the window (the top bar's chip).
pub(crate) fn open(app: &mut CoreRouterUi) {
    if !app.open.insert(Win::Panel(WIN)) {
        app.floats.raise(crate::win_id(Win::Panel(WIN)));
    }
    app.cache.refreshed_at = None;
}

impl GuardPanel {
    fn help_for(&mut self, key: &'static str, title: &str) {
        self.help = Some(HelpView::new(key, title.to_owned()));
    }

    /// The sessions a learned route covers now, and the networks to guard.
    fn alerts(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let v = ui.visuals().clone();
        let can = app.can().check(CMDS.add);
        let findings = self.list.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
        for f in &findings {
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, "covered"), chip::RED.tone(&v));
                ui.label(s(f, "text"));
                let net = s(f, "connected");
                if f.get("guarded").and_then(Value::as_bool) != Some(true)
                    && table::action(ui, &format!("{} {net}", tr_in(SCOPE, l, "Protect")), can.clone())
                {
                    protect(app, &net);
                }
            });
        }
        // A network a finding above already offers is not repeated.
        let offered: Vec<String> = findings.iter().map(|f| s(f, "connected")).collect();
        let open: Vec<Value> = self
            .suggest
            .iter()
            .filter(|n| n.get("guarded").and_then(Value::as_bool) != Some(true))
            .filter(|n| !offered.contains(&s(n, "network")))
            .cloned()
            .collect();
        if !open.is_empty() {
            ui.horizontal(|ui| {
                ui.strong(tr_in(SCOPE, l, "Management networks not guarded"));
                if help::info_button(ui, Id::unique("mgmt-guard-suggest"), tr_in(SCOPE, l, "Management networks not guarded")).clicked() {
                    self.help_for("management_guard.suggest", tr_in(SCOPE, l, "Management networks not guarded"));
                }
            });
        }
        for n in &open {
            ui.horizontal_wrapped(|ui| {
                let net = s(n, "network");
                ui.monospace(&net);
                let iface = s(n, "interface");
                chip::chip(ui, &iface, chip::palette_tone(&v, name_hue(&iface)));
                if n.get("covered").and_then(Value::as_bool) == Some(true) {
                    chip::chip(ui, tr_in(SCOPE, l, "covered"), chip::RED.tone(&v));
                }
                ui.weak(sessions_text(&n["sessions"])).on_hover_text(s(n, "command"));
                if table::action(ui, &format!("{} {net}", tr_in(SCOPE, l, "Protect")), can.clone()) {
                    protect(app, &net);
                }
            });
        }
        if self.list.get("watching").and_then(Value::as_bool) == Some(false) {
            ui.weak(tr_in(SCOPE, l, "Nobody looks at the routes of the sessions here (the virtual lab): the guard is kept in the config only."));
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], data: &[Value]) {
        let find = |k: &str| data.iter().find(|r| s(r, "id") == k);
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut v = BTreeMap::new();
                    v.insert("disabled", "no".to_owned());
                    if let Some(n) = self.suggest.iter().find(|n| n.get("guarded").and_then(Value::as_bool) != Some(true)) {
                        v.insert("network", s(n, "network"));
                    }
                    self.modal = Some(Modal::open(app, None, v));
                }
            }
            Act::Edit(k) => {
                if let Some(r) = find(&k) {
                    self.modal = Some(Modal::open(app, Some((k.clone(), s(r, "network"))), values(r)));
                }
            }
            Act::Comment(keys) => {
                if let Some(k) = keys.into_iter().next()
                    && let Some(r) = find(&k)
                {
                    self.modal = Some(Modal::open(app, Some((k.clone(), s(r, "network"))), values(r)));
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
                    .map(|k| json!({"command": "routing.management-guard.set", "params": {"id": k, "disabled": to}}))
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
                    .filter_map(|k| find(k))
                    .map(|r| {
                        let mut p = json!({"network": s(r, "network")});
                        if let Some(o) = p.as_object_mut() {
                            if !s(r, "comment").is_empty() {
                                o.insert("comment".into(), json!(s(r, "comment")));
                            }
                            if r.get("disabled").and_then(Value::as_bool) == Some(true) {
                                o.insert("disabled".into(), json!(true));
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

impl PanelState for GuardPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        [("list", "routing.management-guard.list"), ("suggest", "routing.management-guard.suggest")]
            .into_iter()
            .filter(|(_, c)| app.has_command(c))
            .map(|(key, command)| Query { key, command, params: json!({}) })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            "list" => self.list = value,
            "suggest" => self.suggest = value.as_array().cloned().unwrap_or_default(),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.alerts(app, ui, l);
        let data = rows_of(&self.list);
        let rows: Vec<Row> = data.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<Item> = data
            .iter()
            .filter(|r| selection.contains(&s(r, "id")))
            .map(|r| Item::of(r, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 16.0;
        self.table.empty = tr_in(SCOPE, l, "No network guarded: a learned route more specific than the management network can still take the replies to your session. + adds one, or Protect above.").to_owned();
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Network…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help_for(key, tr_in(SCOPE, l, title));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let refused: u64 = data.iter().filter_map(|r| r.get("refused").and_then(Value::as_u64)).sum();
        list::footer(
            ui,
            &[
                (data.len(), "networks", chip::neutral_tone(&v)),
                (list::count(&data, "disabled", "true"), "disabled", chip::neutral_tone(&v)),
                (usize::try_from(refused).unwrap_or(usize::MAX), "routes refused", chip::BLUE.tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, a, ui, &rows, &data);
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

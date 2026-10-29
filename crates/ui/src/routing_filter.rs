//! Routing › Filters (G3.2b), RouterOS v7 `/routing filter`: the rules in
//! their chains (what each tests and does, as chips), the prefix and
//! community lists, and the Preview tab ("which routes pass", against
//! the policy in force). Above the tabs, what needs the operator's eye:
//! eBGP connections without a chain (RFC 8212: nothing passes) and what
//! the pending changes do to the routes of each connection. A list window
//! (G0.24, `docs/ui-style.md`); `routing.filter.*` decides, this only
//! shows and sends.

use std::collections::BTreeMap;

use egui::{ComboBox, RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "routing-filter";
pub(crate) const WIN: &str = "routing-filters";
/// Labels' scope (`i18n/auto/routing_filter_*.rs`).
const SCOPE: &str = "routing_filter";
const RULES: &str = "filter-rules";
const PLISTS: &str = "filter-prefix-lists";
const CLISTS: &str = "filter-community-lists";
const PREVIEW: &str = "filter-preview";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Routing",
        title: "Filters",
        size: [1180.0, 480.0],
        escape: true,
    }],
    new: || Box::new(FilterPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Rules,
    PrefixLists,
    CommunityLists,
    Preview,
}

const TABS: [(Tab, &str, &str); 4] = [
    (Tab::Rules, "Rules", "filter.tab.rules"),
    (Tab::PrefixLists, "Prefix Lists", "filter.tab.prefix_lists"),
    (Tab::CommunityLists, "Community Lists", "filter.tab.community_lists"),
    (Tab::Preview, "Preview", "filter.tab.preview"),
];

const RULE_CMDS: Cmds = Cmds {
    add: "routing.filter.rule.add",
    remove: "routing.filter.rule.remove",
    set: Some("routing.filter.rule.set"),
    what: "rules",
};

const PLIST_CMDS: Cmds = Cmds {
    add: "routing.filter.prefix-list.add",
    remove: "routing.filter.prefix-list.remove",
    set: Some("routing.filter.prefix-list.set"),
    what: "prefix lists",
};

const CLIST_CMDS: Cmds = Cmds {
    add: "routing.filter.community-list.add",
    remove: "routing.filter.community-list.remove",
    set: Some("routing.filter.community-list.set"),
    what: "community lists",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input) -> Field {
    Field { param, label, help, input, edit: true }
}

const RULE_FIELDS: &[Field] = &[
    field("chain", "Chain", "filter.rule.chain", Input::Text("upstream-in")),
    field("rule", "Rule", "filter.rule.rule", Input::Text("if (dst in bogons) { reject }")),
    field("disabled", "Disabled", "filter.rule.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const PLIST_FIELDS: &[Field] = &[
    field("name", "Name", "filter.list.name", Input::Text("bogons")),
    field("entries", "Entries", "filter.prefix_list.entries", Input::Text("10.0.0.0/8 le 32, 192.168.0.0/16 le 32")),
    field("comment", "Comment", "", Input::Text("")),
];

const CLIST_FIELDS: &[Field] = &[
    field("name", "Name", "filter.list.name", Input::Text("blackhole")),
    field("communities", "Communities", "filter.community_list.communities", Input::Text("blackhole, 65000:666, 65000:1:2")),
    field("comment", "Comment", "", Input::Text("")),
];

pub(crate) const RULE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Filter Rule",
    edit_title: "Filter Rule",
    help: "filter.rule",
    fields: RULE_FIELDS,
    preview: "routing.filter.rule.check",
};

pub(crate) const PLIST_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Prefix List",
    edit_title: "Prefix List",
    help: "filter.prefix_list",
    fields: PLIST_FIELDS,
    preview: "routing.filter.prefix-list.check",
};

pub(crate) const CLIST_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Community List",
    edit_title: "Community List",
    help: "filter.community_list",
    fields: CLIST_FIELDS,
    preview: "routing.filter.community-list.check",
};

const RULE_COLUMNS: [table::Column; 6] = [
    num("#").help("filter.rule.position"),
    col("Chain").help("filter.rule.chain"),
    col("Rule").help("filter.rule.rule"),
    col("Matches").help("filter.rule.matches"),
    col("Actions").help("filter.rule.actions"),
    comment(),
];

const PLIST_COLUMNS: [table::Column; 6] = [
    col("Name").help("filter.list.name"),
    num("Entries").help("filter.prefix_list.entries"),
    num("IPv4").help("filter.prefix_list.entries"),
    num("IPv6").help("filter.prefix_list.entries"),
    col("Used By").help("filter.list.used_by"),
    comment(),
];

const CLIST_COLUMNS: [table::Column; 6] = [
    col("Name").help("filter.list.name"),
    col("Communities").help("filter.community_list.communities"),
    num("Normal").help("filter.community_list.communities"),
    num("Large").help("filter.community_list.communities"),
    col("Used By").help("filter.list.used_by"),
    comment(),
];

const PREVIEW_COLUMNS: [table::Column; 6] = [
    col("Verdict").help("filter.preview.verdict"),
    col("Prefix").help("filter.preview.prefix"),
    col("AS Path").help("filter.preview.as_path"),
    col("Communities").help("filter.community_list.communities"),
    col("Before").help("filter.preview.before"),
    col("Change").help("filter.preview.change"),
];

/// Which list a modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum What {
    Rule,
    PrefixList,
    CommunityList,
}

impl What {
    fn spec(self) -> &'static Spec {
        match self {
            What::Rule => &RULE_SPEC,
            What::PrefixList => &PLIST_SPEC,
            What::CommunityList => &CLIST_SPEC,
        }
    }

    fn cmds(self) -> Cmds {
        match self {
            What::Rule => RULE_CMDS,
            What::PrefixList => PLIST_CMDS,
            What::CommunityList => CLIST_CMDS,
        }
    }
}

#[derive(Default)]
pub(crate) struct FilterPanel {
    pub(crate) tab: Tab,
    pub(crate) rules: Vec<Value>,
    pub(crate) plists: Vec<Value>,
    pub(crate) clists: Vec<Value>,
    pub(crate) status: Value,
    pub(crate) impact: Vec<Value>,
    pub(crate) connections: Vec<Value>,
    rule_table: TableState,
    plist_table: TableState,
    clist_table: TableState,
    preview_table: TableState,
    pub(crate) modal: Option<(What, Modal)>,
    pub(crate) help: Option<HelpView>,
    /// The Preview tab's form: a connection (or a chain alone) and the
    /// direction.
    pub(crate) pv_connection: String,
    pub(crate) pv_chain: String,
    pub(crate) pv_out: bool,
    /// Ask for the preview in the next refresh (and again while FRR's
    /// routes are being read).
    pub(crate) pv_wanted: bool,
    pub(crate) preview: Option<Value>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(value_text).unwrap_or_default()
}

fn u(r: &Value, k: &str) -> u64 {
    r.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn strings(r: &Value, k: &str) -> Vec<String> {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A chain's chip, coloured by its name (the same chain has the same
/// colour everywhere).
fn chain_kind(name: &str) -> Kind {
    Kind::Hashed(chip::hashed(corerouter_fnv(name)))
}

/// FNV-1a of `s` (stable colours across runs and builds).
fn corerouter_fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

fn action_kind(a: &str) -> Kind {
    match a {
        "accept" => Kind::Green,
        "reject" => Kind::Red,
        a if a.starts_with("jump") || a == "return" => Kind::Neutral,
        _ => Kind::Blue,
    }
}

fn chips(items: &[(String, Kind)]) -> String {
    let c: Vec<(&str, Kind)> = items.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    cell("", &c)
}

pub(crate) fn rule_row(r: &Value) -> Row {
    let chain = s(r, "chain");
    let mut rule = s(r, "rule").replace(chip::SEP, " ");
    if rule.chars().count() > 120 {
        rule = rule.chars().take(119).collect::<String>() + "…";
    }
    let rule_cell = if r.get("error").is_some_and(|e| !e.is_null()) { cell(&rule, &[("error", Kind::Red)]) } else { rule };
    let matchers: Vec<(String, Kind)> = strings(r, "matchers").into_iter().map(|m| (m, Kind::Neutral)).collect();
    let actions: Vec<(String, Kind)> = strings(r, "actions")
        .into_iter()
        .map(|a| {
            let k = action_kind(&a);
            (a, k)
        })
        .collect();
    Row {
        key: s(r, "id"),
        cells: vec![
            s(r, "position"),
            cell("", &[(chain.as_str(), chain_kind(&chain))]),
            rule_cell,
            chips(&matchers),
            chips(&actions),
            s(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

fn used_by(r: &Value) -> String {
    let c: Vec<(String, Kind)> = strings(r, "used_by").into_iter().map(|c| {
        let k = chain_kind(&c);
        (c, k)
    }).collect();
    if c.is_empty() { "–".into() } else { chips(&c) }
}

fn plist_row(r: &Value) -> Row {
    Row {
        key: s(r, "name"),
        cells: vec![s(r, "name"), s(r, "count"), s(r, "ipv4"), s(r, "ipv6"), used_by(r), s(r, "comment")],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn clist_row(r: &Value) -> Row {
    let all = strings(r, "communities");
    let mut shown = all.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
    if all.len() > 6 {
        shown.push_str(&format!(" … (+{})", all.len() - 6));
    }
    Row {
        key: s(r, "name"),
        cells: vec![s(r, "name"), shown, s(r, "normal"), s(r, "large"), used_by(r), s(r, "comment")],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn verdict_cell(v: &str) -> String {
    match v {
        "accept" => cell("", &[("accept", Kind::Green)]),
        "reject" => cell("", &[("reject", Kind::Red)]),
        _ => "–".into(),
    }
}

fn preview_row(i: usize, r: &Value) -> Row {
    let comms = strings(r, "communities").join(" ");
    Row {
        key: format!("{i}"),
        cells: vec![
            verdict_cell(&s(r, "verdict")),
            s(r, "prefix"),
            s(r, "as_path"),
            comms,
            verdict_cell(&s(r, "before")),
            s(r, "change"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The modal's fields for an existing row.
fn values_of(r: &Value, what: What) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    match what {
        What::Rule => {
            out.insert("chain", s(r, "chain"));
            out.insert("rule", s(r, "rule"));
            out.insert("disabled", if r.get("disabled").and_then(Value::as_bool).unwrap_or(false) { "yes" } else { "no" }.to_owned());
            out.insert("comment", s(r, "comment"));
        }
        What::PrefixList => {
            out.insert("name", s(r, "name"));
            out.insert("entries", strings(r, "entries").join(", "));
            out.insert("comment", s(r, "comment"));
        }
        What::CommunityList => {
            out.insert("name", s(r, "name"));
            out.insert("communities", strings(r, "communities").join(", "));
            out.insert("comment", s(r, "comment"));
        }
    }
    out
}

/// The `add` parameters that recreate a row.
fn recreate(r: &Value, what: What) -> Value {
    match what {
        What::Rule => json!({"chain": s(r, "chain"), "rule": s(r, "rule"), "disabled": r.get("disabled").cloned().unwrap_or(json!(false)), "comment": s(r, "comment")}),
        What::PrefixList => json!({"name": s(r, "name"), "entries": strings(r, "entries"), "comment": s(r, "comment")}),
        What::CommunityList => json!({"name": s(r, "name"), "communities": strings(r, "communities"), "comment": s(r, "comment")}),
    }
}

impl FilterPanel {
    fn data(&self, what: What) -> &[Value] {
        match what {
            What::Rule => &self.rules,
            What::PrefixList => &self.plists,
            What::CommunityList => &self.clists,
        }
    }

    fn key_field(what: What) -> &'static str {
        if what == What::Rule { "id" } else { "name" }
    }

    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, egui::Id::unique(("filter-tab-help", key)), tr_in(SCOPE, l, label)).clicked() {
                    self.help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
                }
                ui.add_space(6.0);
            }
        });
    }

    /// What needs the operator's eye: RFC 8212 and the commit impact.
    fn banner(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let unprotected: Vec<Value> = self.status.get("rfc8212").and_then(Value::as_array).cloned().unwrap_or_default();
        let v = ui.visuals().clone();
        let mut help = None;
        for r in unprotected.iter().take(4) {
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, "RFC 8212", chip::AMBER.tone(&v));
                ui.label(s(r, "message"));
                if help::info_button(ui, egui::Id::unique(("filter-8212", s(r, "connection"))), "RFC 8212").clicked() {
                    help = Some(HelpView::new("filter.rfc8212", "RFC 8212"));
                }
            });
        }
        if unprotected.len() > 4 {
            ui.weak(format!("… +{}", unprotected.len() - 4));
        }
        // G3.9fg: a filter of an older build keeps its prepend count.
        let prepend = self.status.get("prepend_warning").and_then(Value::as_str).map(str::to_owned);
        if let Some(msg) = &prepend {
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, "Prepend count"), chip::AMBER.tone(&v));
                ui.label(msg);
                if ui.button(tr_in(SCOPE, l, "Use RouterOS count")).clicked() {
                    app.run("routing.filter.prepend.set", json!({"count": "routeros"}));
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, egui::Id::unique("filter-prepend"), tr_in(SCOPE, l, "Prepend count")).clicked() {
                    help = Some(HelpView::new("filter.prepend", tr_in(SCOPE, l, "Prepend count")));
                }
            });
        }
        for r in self.impact.iter().take(4) {
            ui.horizontal_wrapped(|ui| {
                let tone = if u(r, "withdrawn") > 0 { chip::RED.tone(&v) } else { chip::BLUE.tone(&v) };
                chip::chip(ui, tr_in(SCOPE, l, "Commit impact"), tone);
                ui.label(s(r, "message"));
                if help::info_button(ui, egui::Id::unique(("filter-impact", s(r, "connection"), s(r, "direction"))), tr_in(SCOPE, l, "Commit impact")).clicked() {
                    help = Some(HelpView::new("filter.impact", tr_in(SCOPE, l, "Commit impact")));
                }
            });
        }
        if help.is_some() {
            self.help = help;
        }
        if !unprotected.is_empty() || !self.impact.is_empty() || prepend.is_some() {
            ui.separator();
        }
    }

    fn column_help(&mut self, app: &CoreRouterUi, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, app.lang.labels, title)));
        }
    }

    fn list_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, what: What) {
        let l = app.lang.labels;
        let all: Vec<Value> = self.data(what).to_vec();
        let (rows, salt, columns): (Vec<Row>, &str, &[table::Column]) = match what {
            What::Rule => (all.iter().map(rule_row).collect(), RULES, &RULE_COLUMNS),
            What::PrefixList => (all.iter().map(plist_row).collect(), PLISTS, &PLIST_COLUMNS),
            What::CommunityList => (all.iter().map(clist_row).collect(), CLISTS, &CLIST_COLUMNS),
        };
        let key_field = Self::key_field(what);
        let state = match what {
            What::Rule => &mut self.rule_table,
            What::PrefixList => &mut self.plist_table,
            What::CommunityList => &mut self.clist_table,
        };
        let selection = state.selection(&rows);
        let picked: Vec<Item> = all.iter().filter(|r| selection.contains(&s(r, key_field))).map(|r| Item::of(r, key_field, "")).collect();
        let mut tools = Tools::new(&app.can(), &what.cmds(), &picked);
        if what != What::Rule {
            let none = Err("a list is not enabled or disabled: the rules that use it are".to_owned());
            tools.enable = none.clone();
            tools.disable = none;
        }
        let mut act = None;
        let mut moved: Option<(String, Option<String>)> = None;
        let mut preview_chain: Option<String> = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, salt, &tools, &selection, l);
            if what == What::Rule {
                let one = selection.first().filter(|_| selection.len() == 1).cloned();
                let pos = one.as_ref().and_then(|k| all.iter().position(|r| s(r, "id") == *k));
                let can_move = |ok: bool| app.can().and("routing.filter.rule.move", if ok { Ok(()) } else { Err("Select one rule".into()) });
                // Up: before the rule above it; Down: before the one two below.
                if button(ui, tr_in(SCOPE, l, "Up"), tr_in(SCOPE, l, "Move Up"), can_move(pos.is_some_and(|p| p > 0)))
                    && let (Some(k), Some(p)) = (&one, pos)
                {
                    moved = Some((k.clone(), all.get(p.saturating_sub(1)).map(|r| s(r, "id"))));
                }
                if button(ui, tr_in(SCOPE, l, "Down"), tr_in(SCOPE, l, "Move Down"), can_move(pos.is_some_and(|p| p + 1 < all.len())))
                    && let (Some(k), Some(p)) = (&one, pos)
                {
                    moved = Some((k.clone(), all.get(p + 2).map(|r| s(r, "id"))));
                }
                let chain = one.as_ref().and_then(|k| all.iter().find(|r| s(r, "id") == *k)).map(|r| s(r, "chain"));
                let why = chain.as_ref().map(|_| ()).ok_or_else(|| "Select a rule: its chain is previewed".to_owned());
                if button(ui, tr_in(SCOPE, l, "Preview"), tr_in(SCOPE, l, "Which routes the chain lets through"), why) {
                    preview_chain = chain;
                }
            }
            let state = match what {
                What::Rule => &mut self.rule_table,
                What::PrefixList => &mut self.plist_table,
                What::CommunityList => &mut self.clist_table,
            };
            table::find_field(ui, salt, state);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let new_label = match what {
            What::Rule => "New Rule…",
            What::PrefixList => "New Prefix List…",
            What::CommunityList => "New Community List…",
        };
        let state = match what {
            What::Rule => &mut self.rule_table,
            What::PrefixList => &mut self.plist_table,
            What::CommunityList => &mut self.clist_table,
        };
        let out = table::show(ui, salt, footer_h, state, columns, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, new_label), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(app, out.help, columns);
        act = act.or_else(|| list::from_shortcut(out.shortcut, &tools, &selection)).or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        match what {
            What::Rule => {
                let chains = self.status.get("chains").and_then(Value::as_array).map_or(0, Vec::len);
                list::footer(
                    ui,
                    &[
                        (all.len(), "rules", chip::neutral_tone(&v)),
                        (chains, "chains", chip::BLUE.tone(&v)),
                        (all.iter().filter(|r| r.get("disabled").and_then(Value::as_bool).unwrap_or(false)).count(), "disabled", chip::neutral_tone(&v)),
                        (all.iter().filter(|r| r.get("error").is_some_and(|e| !e.is_null())).count(), "with errors", chip::RED.tone(&v)),
                    ],
                    l,
                );
            }
            _ => {
                let used = all.iter().filter(|r| !strings(r, "used_by").is_empty()).count();
                list::footer(ui, &[(all.len(), "lists", chip::neutral_tone(&v)), (used, "in use", chip::BLUE.tone(&v))], l);
            }
        }
        if let Some((id, before)) = moved {
            let mut p = json!({"id": id});
            if let (Some(b), Some(o)) = (before, p.as_object_mut()) {
                o.insert("place_before".into(), json!(b));
            }
            app.run("routing.filter.rule.move", p);
        }
        if let Some(chain) = preview_chain {
            self.pv_chain = chain;
            self.pv_connection.clear();
            self.pv_wanted = true;
            self.preview = None;
            self.tab = Tab::Preview;
            app.cache.refreshed_at = None;
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows, what);
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], what: What) {
        let key_field = Self::key_field(what);
        let data = self.data(what).to_vec();
        let cmds = what.cmds();
        let row_of = |k: &str| data.iter().find(|r| s(r, key_field) == k).cloned();
        let title_of = |r: &Value| match what {
            What::Rule => format!("{} #{}", s(r, "chain"), s(r, "position")),
            _ => s(r, "name"),
        };
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut values = BTreeMap::new();
                    if what == What::Rule {
                        let chain = rows
                            .iter()
                            .find(|r| self.rule_table.selection(rows).contains(&r.key))
                            .and_then(|r| row_of(&r.key))
                            .map(|r| s(&r, "chain"))
                            .unwrap_or_default();
                        values.insert("chain", chain);
                        values.insert("disabled", "no".to_owned());
                    }
                    self.modal = Some((what, Modal::open(app, None, values)));
                }
            }
            Act::Edit(_) | Act::Comment(_) if self.modal.is_some() => {
                if let Some((_, m)) = &mut self.modal {
                    m.status.bring_to_front();
                }
            }
            Act::Edit(k) => {
                if let Some(r) = row_of(&k) {
                    self.modal = Some((what, Modal::open(app, Some((k.clone(), title_of(&r))), values_of(&r, what))));
                }
            }
            Act::Comment(keys) => {
                if let Some(k) = keys.first()
                    && let Some(r) = row_of(k)
                {
                    self.modal = Some((what, Modal::open(app, Some((k.clone(), title_of(&r))), values_of(&r, what))));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, crate::Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) if what == What::Rule => {
                let to = matches!(act, Act::Disable(_));
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": "routing.filter.rule.set", "params": {"id": k, "disabled": to}})).collect();
                app.run_steps(steps, crate::Then::Nothing);
            }
            Act::Enable(_) | Act::Disable(_) => {}
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| row_of(k)).map(|r| recreate(&r, what)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    fn preview_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let chains: Vec<String> = self
            .status
            .get("chains")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|c| s(c, "chain")).collect())
            .unwrap_or_default();
        let conns: Vec<String> = self.connections.iter().map(|c| s(c, "name")).collect();
        let mut help = None;
        let mut ask = false;
        ui.horizontal_wrapped(|ui| {
            ui.label(tr_in(SCOPE, l, "Connection"));
            if help::info_button(ui, egui::Id::unique("filter-pv-conn"), tr_in(SCOPE, l, "Connection")).clicked() {
                help = Some(HelpView::new("filter.preview.connection", tr_in(SCOPE, l, "Connection")));
            }
            let none = tr_in(SCOPE, l, "(chain only)").to_owned();
            ComboBox::from_id_salt("filter-pv-conn-box")
                .selected_text(if self.pv_connection.is_empty() { none.clone() } else { self.pv_connection.clone() })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.pv_connection, String::new(), none);
                    for c in &conns {
                        ui.selectable_value(&mut self.pv_connection, c.clone(), c);
                    }
                });
            ui.label(tr_in(SCOPE, l, "Chain"));
            ComboBox::from_id_salt("filter-pv-chain-box")
                .selected_text(if self.pv_chain.is_empty() { "–".to_owned() } else { self.pv_chain.clone() })
                .show_ui(ui, |ui| {
                    if !self.pv_connection.is_empty() {
                        ui.selectable_value(&mut self.pv_chain, String::new(), tr_in(SCOPE, l, "(the connection's)"));
                    }
                    for c in &chains {
                        ui.selectable_value(&mut self.pv_chain, c.clone(), c);
                    }
                });
            ui.label(tr_in(SCOPE, l, "Direction"));
            if help::info_button(ui, egui::Id::unique("filter-pv-dir"), tr_in(SCOPE, l, "Direction")).clicked() {
                help = Some(HelpView::new("filter.preview.direction", tr_in(SCOPE, l, "Direction")));
            }
            ui.selectable_value(&mut self.pv_out, false, tr_in(SCOPE, l, "in"));
            ui.selectable_value(&mut self.pv_out, true, tr_in(SCOPE, l, "out"));
            let ready = if self.pv_connection.is_empty() && self.pv_chain.is_empty() {
                Err("Pick a connection or a chain".to_owned())
            } else {
                app.can().check("routing.filter.preview")
            };
            if button(ui, tr_in(SCOPE, l, "Run Preview"), tr_in(SCOPE, l, "Which routes the chain lets through"), ready) {
                ask = true;
            }
        });
        if help.is_some() {
            self.help = help;
        }
        if ask {
            self.pv_wanted = true;
            self.preview = None;
            app.cache.refreshed_at = None;
        }
        ui.separator();
        let Some(pv) = self.preview.clone() else {
            ui.weak(tr_in(SCOPE, l, "Pick a connection or a chain and run the preview: it shows which routes pass, which are rejected and what changes against the policy in force."));
            return;
        };
        if let Some(e) = pv.get("error").and_then(Value::as_str) {
            ui.colored_label(chip::RED.tone(ui.visuals()).ink, e);
        }
        if pv.get("pending").and_then(Value::as_bool).unwrap_or(false) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr_in(SCOPE, l, "Reading the routes from FRR…"));
            });
            return;
        }
        let v = ui.visuals().clone();
        ui.horizontal_wrapped(|ui| {
            let source = s(&pv, "source");
            chip::chip(ui, &format!("{} {}", tr_in(SCOPE, l, "source"), source), chip::neutral_tone(&v));
            chip::chip(ui, &format!("{} {}", u(&pv, "total"), tr_in(SCOPE, l, "routes")), chip::neutral_tone(&v));
            chip::chip(ui, &format!("{} {}", u(&pv, "accepted"), tr_in(SCOPE, l, "accepted")), chip::GREEN.tone(&v));
            chip::chip(ui, &format!("{} {}", u(&pv, "rejected"), tr_in(SCOPE, l, "rejected")), chip::RED.tone(&v));
            if u(&pv, "modified") > 0 {
                chip::chip(ui, &format!("{} {}", u(&pv, "modified"), tr_in(SCOPE, l, "changed")), chip::BLUE.tone(&v));
            }
            if pv.get("compared").and_then(Value::as_bool).unwrap_or(false) {
                for (k, label, hue) in [
                    ("newly_rejected", "newly rejected", chip::AMBER),
                    ("newly_accepted", "newly accepted", chip::BLUE),
                    ("attrs_changed", "attributes change", chip::BLUE),
                ] {
                    if u(&pv, k) > 0 {
                        chip::chip(ui, &format!("{} {}", u(&pv, k), tr_in(SCOPE, l, label)), hue.tone(&v));
                    }
                }
            }
            ui.weak(format!("{:.1} ms, {} {}", u(&pv, "elapsed_us") as f64 / 1000.0, u(&pv, "threads"), tr_in(SCOPE, l, "threads")));
        });
        if u(&pv, "partial") > 0 {
            ui.weak(format!("{} {}", u(&pv, "partial"), tr_in(SCOPE, l, "routes came without their communities (FRR shows them only for accepted routes)")));
        }
        let rows: Vec<Row> = pv.get("rows").and_then(Value::as_array).map(|a| a.iter().enumerate().map(|(i, r)| preview_row(i, r)).collect()).unwrap_or_default();
        let out = table::show(ui, PREVIEW, 0.0, &mut self.preview_table, &PREVIEW_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &PREVIEW_COLUMNS);
    }

    /// Tests: act as the bar or the menu of a tab would.
    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, what: What, ui: &Ui) {
        let rows: Vec<Row> = match what {
            What::Rule => self.rules.iter().map(rule_row).collect(),
            What::PrefixList => self.plists.iter().map(plist_row).collect(),
            What::CommunityList => self.clists.iter().map(clist_row).collect(),
        };
        self.act(app, a, ui, &rows, what);
    }

    /// Every explanation key the window uses (the catalog test).
    #[cfg(test)]
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = TABS.iter().map(|(_, _, k)| *k).collect();
        out.extend(RULE_COLUMNS.iter().chain(&PLIST_COLUMNS).chain(&CLIST_COLUMNS).chain(&PREVIEW_COLUMNS).map(|c| c.help));
        out.extend(RULE_FIELDS.iter().chain(PLIST_FIELDS).chain(CLIST_FIELDS).map(|f| f.help));
        out.extend([
            RULE_SPEC.help,
            PLIST_SPEC.help,
            CLIST_SPEC.help,
            "filter.rfc8212",
            "filter.impact",
            "filter.prepend",
            "filter.preview.connection",
            "filter.preview.direction",
            "bgp.param.input_filter",
            "bgp.param.output_filter",
            "bgp.param.keep_received",
        ]);
        out.retain(|k| !k.is_empty());
        out
    }
}

/// A button with a tooltip; greyed with the reason when it cannot act.
fn button(ui: &mut Ui, text: &str, tip: &str, enabled: Result<(), String>) -> bool {
    match enabled {
        Ok(()) => ui.button(text).on_hover_text(tip).clicked(),
        Err(why) => {
            ui.add_enabled(false, egui::Button::new(text)).on_disabled_hover_text(why);
            false
        }
    }
}

impl PanelState for FilterPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (key, command) in [
            ("rules", "routing.filter.rule.list"),
            ("plists", "routing.filter.prefix-list.list"),
            ("clists", "routing.filter.community-list.list"),
            ("status", "routing.filter.status"),
            ("impact", "routing.filter.impact"),
            ("connections", "routing.bgp.connection.list"),
        ] {
            if app.has_command(command) {
                out.push(Query { key, command, params: json!({}) });
            }
        }
        if self.pv_wanted && app.has_command("routing.filter.preview") {
            let mut p = json!({"direction": if self.pv_out { "out" } else { "in" }, "limit": 100});
            if let Some(o) = p.as_object_mut() {
                if !self.pv_connection.is_empty() {
                    o.insert("connection".into(), json!(self.pv_connection));
                }
                if !self.pv_chain.is_empty() {
                    o.insert("chain".into(), json!(self.pv_chain));
                }
            }
            out.push(Query { key: "preview", command: "routing.filter.preview", params: p });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some((_, m)) = &mut self.modal {
                m.arrived(value);
            }
            return;
        }
        match (key, value) {
            ("status", v @ Value::Object(_)) => self.status = v,
            ("preview", v @ Value::Object(_)) => {
                // Asked again while FRR's routes are being read.
                self.pv_wanted = v.get("pending").and_then(Value::as_bool).unwrap_or(false);
                self.preview = Some(v);
            }
            ("rules", Value::Array(a)) => self.rules = a,
            ("plists", Value::Array(a)) => self.plists = a,
            ("clists", Value::Array(a)) => self.clists = a,
            ("impact", Value::Array(a)) => self.impact = a,
            ("connections", Value::Array(a)) => self.connections = a,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.banner(app, ui);
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Rules => self.list_tab(app, ui, What::Rule),
            Tab::PrefixLists => self.list_tab(app, ui, What::PrefixList),
            Tab::CommunityLists => self.list_tab(app, ui, What::CommunityList),
            Tab::Preview => self.preview_tab(app, ui),
        }
        if self.rules.is_empty() && self.tab == Tab::Rules {
            ui.add_space(6.0);
            ui.label(RichText::new(tr_in(SCOPE, app.lang.labels, "No rules yet. An eBGP connection without a chain accepts and sends nothing (RFC 8212): add rules, then set the connection's Input Filter and Output Filter.")).weak());
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some((what, m)) = &mut self.modal {
            let chains: Vec<String> = self.status.get("chains").and_then(Value::as_array).map(|a| a.iter().map(|c| s(c, "chain")).collect()).unwrap_or_default();
            let options = move |_: &str| chains.clone();
            if !m.show(app, ctx, area, what.spec(), &options) {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
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
            Tab::PrefixLists => self.plist_table.escape(),
            Tab::CommunityLists => self.clist_table.escape(),
            Tab::Preview => self.preview_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(RULES, &self.rule_table), (PLISTS, &self.plist_table), (CLISTS, &self.clist_table), (PREVIEW, &self.preview_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (RULES, &mut self.rule_table),
            (PLISTS, &mut self.plist_table),
            (CLISTS, &mut self.clist_table),
            (PREVIEW, &mut self.preview_table),
        ]
    }
}

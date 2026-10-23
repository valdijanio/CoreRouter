//! IP › Firewall (tabs Filter Rules / NAT / Mangle / Address Lists) and
//! Interfaces › Interface List (tabs Members / Lists), WinBox style (G2.1).
//!
//! The tables are the G1.9 ones (selection, menus, shortcuts, inline
//! comments, greyed actions with the reason) plus what order needs: ▲/▼
//! and drag and drop move a rule (`ip.firewall.<table>.move`), and section
//! headers group rules under a title. The rule window has the three WinBox
//! tabs General / Advanced / Action. Everything is a command through
//! `CoreRouterUi::run`; the engine validates (the error lands in the dialog,
//! on the field it names).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use egui::{Color32, Grid, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::dialog::{self, Buttons, Footer, Form, Head, Press, Status};
use crate::firewall_assist::{Wizard, WizardForm};
use crate::interfaces::{cascade, dialog_id};
use crate::chip;
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment};
use crate::{CoreRouterUi, RequestId, Then, Win, value_text};

/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;

/// The rule tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FwTable {
    Filter,
    Nat,
    Mangle,
}

impl FwTable {
    fn name(self) -> &'static str {
        match self {
            FwTable::Filter => "filter",
            FwTable::Nat => "nat",
            FwTable::Mangle => "mangle",
        }
    }

    fn label(self) -> &'static str {
        match self {
            FwTable::Filter => "Filter Rule",
            FwTable::Nat => "NAT Rule",
            FwTable::Mangle => "Mangle Rule",
        }
    }

    fn cmd(self, verb: &str) -> String {
        format!("ip.firewall.{}.{verb}", self.name())
    }

    pub(crate) fn salt(self) -> &'static str {
        match self {
            FwTable::Filter => "fw-filter",
            FwTable::Nat => "fw-nat",
            FwTable::Mangle => "fw-mangle",
        }
    }

    fn chains(self) -> &'static [&'static str] {
        match self {
            FwTable::Filter => &["input", "forward", "output"],
            FwTable::Nat => &["dstnat", "srcnat"],
            FwTable::Mangle => &["prerouting", "input", "forward", "output", "postrouting"],
        }
    }

    fn actions(self) -> &'static [&'static str] {
        match self {
            FwTable::Filter => &[
                "accept",
                "drop",
                "reject",
                "jump",
                "return",
                "log",
                "passthrough",
                "add-src-to-address-list",
                "add-dst-to-address-list",
            ],
            FwTable::Nat => &[
                "accept",
                "masquerade",
                "src-nat",
                "dst-nat",
                "jump",
                "return",
                "log",
                "passthrough",
                "add-src-to-address-list",
                "add-dst-to-address-list",
            ],
            FwTable::Mangle => &[
                "accept",
                "mark-connection",
                "mark-packet",
                "mark-routing",
                "jump",
                "return",
                "log",
                "passthrough",
                "add-src-to-address-list",
                "add-dst-to-address-list",
            ],
        }
    }

    fn feed(self) -> Feed {
        match self {
            FwTable::Filter => Feed::Filter,
            FwTable::Nat => Feed::Nat,
            FwTable::Mangle => Feed::Mangle,
        }
    }
}

/// One cached list of this module (a `Field` of the UI cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Feed {
    Filter,
    Nat,
    Mangle,
    Addr,
    Lists,
    Members,
    /// `ip.firewall.zone.list`: one object (zones, cells, rules).
    Zones,
}

impl Feed {
    pub(crate) const ALL: [Feed; 7] = [
        Feed::Filter,
        Feed::Nat,
        Feed::Mangle,
        Feed::Addr,
        Feed::Lists,
        Feed::Members,
        Feed::Zones,
    ];

    /// The query that fills it.
    pub(crate) fn query(self) -> &'static str {
        match self {
            Feed::Filter => "ip.firewall.filter.list",
            Feed::Nat => "ip.firewall.nat.list",
            Feed::Mangle => "ip.firewall.mangle.list",
            Feed::Addr => "ip.firewall.address-list.list",
            Feed::Lists => "interface.list.list",
            Feed::Members => "interface.list.member.list",
            Feed::Zones => "ip.firewall.zone.list",
        }
    }

    fn table(self) -> Option<FwTable> {
        match self {
            Feed::Filter => Some(FwTable::Filter),
            Feed::Nat => Some(FwTable::Nat),
            Feed::Mangle => Some(FwTable::Mangle),
            _ => None,
        }
    }

    /// `set` and `remove` of one item of this feed.
    fn set_cmd(self) -> String {
        match self {
            Feed::Addr => "ip.firewall.address-list.set".into(),
            Feed::Lists => "interface.list.set".into(),
            Feed::Members => "interface.list.member.set".into(),
            t => t.table().map(|t| t.cmd("set")).unwrap_or_default(),
        }
    }

    fn remove_cmd(self) -> String {
        match self {
            Feed::Addr => "ip.firewall.address-list.remove".into(),
            Feed::Lists => "interface.list.remove".into(),
            Feed::Members => "interface.list.member.remove".into(),
            t => t.table().map(|t| t.cmd("remove")).unwrap_or_default(),
        }
    }

    /// The parameter naming an item (`id`, or `name` for lists).
    fn key(self) -> &'static str {
        if self == Feed::Lists { "name" } else { "id" }
    }

    pub(crate) fn salt(self) -> &'static str {
        match self {
            Feed::Addr => "fw-addr",
            Feed::Lists => "if-lists",
            Feed::Members => "if-members",
            Feed::Zones => "fw-zones",
            t => t.table().map(FwTable::salt).unwrap_or(""),
        }
    }

    /// The list window its dialogs belong to (open over, close with).
    fn window(self) -> Win {
        match self {
            Feed::Lists | Feed::Members => Win::InterfaceList,
            _ => Win::Firewall,
        }
    }

    fn what(self) -> &'static str {
        match self {
            Feed::Addr => "Address List Entry",
            Feed::Lists => "Interface List",
            Feed::Members => "Interface List Member",
            Feed::Zones => "Zone",
            t => t.table().map(FwTable::label).unwrap_or(""),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Filter,
    Nat,
    Mangle,
    Addr,
    Zones,
    /// The conntrack table (G2.2, `connections.rs`).
    Connections,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum IfTab {
    #[default]
    Members,
    Lists,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RuleTab {
    #[default]
    General,
    Advanced,
    Action,
}

/// UI state of the two windows (never config).
#[derive(Default)]
pub(crate) struct State {
    pub tab: Tab,
    pub if_tab: IfTab,
    /// Chain filter of each rule table ("" = all).
    chain: [String; 3],
    /// Shared, so a frame borrows a list instead of copying every rule.
    rows: [Arc<Vec<Value>>; 7],
    pub dialogs: Vec<FwDialogWin>,
    /// Items to open once a list sent after this request arrives.
    open_after: Vec<(RequestId, Feed, String)>,
}

fn feed_index(f: Feed) -> usize {
    match f {
        Feed::Filter => 0,
        Feed::Nat => 1,
        Feed::Mangle => 2,
        Feed::Addr => 3,
        Feed::Lists => 4,
        Feed::Members => 5,
        Feed::Zones => 6,
    }
}

impl State {
    pub(crate) fn rows(&self, f: Feed) -> &[Value] {
        self.rows.get(feed_index(f)).map_or(&[], |r| r.as_slice())
    }

    /// The list of `f`, without copying it.
    pub(crate) fn shared(&self, f: Feed) -> Arc<Vec<Value>> {
        self.rows.get(feed_index(f)).cloned().unwrap_or_default()
    }

    /// A list arrived (request `id`). Returns items to open now.
    pub(crate) fn arrived(
        &mut self,
        f: Feed,
        id: RequestId,
        rows: Vec<Value>,
    ) -> Vec<(Feed, String)> {
        if let Some(slot) = self.rows.get_mut(feed_index(f)) {
            *slot = Arc::new(rows);
        }
        let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open_after)
            .into_iter()
            .partition(|(req, feed, _)| *feed == f && *req <= id);
        self.open_after = later;
        ready.into_iter().map(|(_, f, k)| (f, k)).collect()
    }
}

/// `p[k] = v` on a JSON object, without indexing.
fn put(p: &mut Value, k: &str, v: Value) {
    if let Some(o) = p.as_object_mut() {
        o.insert(k.to_owned(), v);
    }
}

fn text(row: &Value, k: &str) -> String {
    row.get(k).map(value_text).unwrap_or_default()
}

fn flag(row: &Value, k: &str) -> bool {
    row.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// A section header row (`section` holds its title).
fn is_section(row: &Value) -> bool {
    row.get("section").is_some_and(|v| v.is_string())
}

/// Key of a row: the rule/entry id, or the list name.
fn key_of(f: Feed, row: &Value) -> String {
    text(row, f.key())
}

/// All the fields of a rule, as typed in the rule window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleForm {
    /// Text of each parameter (`chain`, `action`, matchers, action fields).
    pub fields: Vec<(&'static str, String)>,
    pub passthrough: bool,
    pub disabled: bool,
    pub comment: String,
}

/// Every text parameter of a rule, in form order.
const RULE_FIELDS: [&str; 27] = [
    "chain",
    "family",
    "src_address",
    "dst_address",
    "protocol",
    "src_port",
    "dst_port",
    "in_interface",
    "out_interface",
    "in_interface_list",
    "out_interface_list",
    "connection_state",
    "connection_nat_state",
    "src_address_list",
    "dst_address_list",
    "icmp_options",
    "connection_mark",
    "packet_mark",
    "routing_mark",
    "action",
    "reject_with",
    "jump_target",
    "log_prefix",
    "to_addresses",
    "to_ports",
    "new_connection_mark",
    "new_packet_mark",
];
/// The fields that do not fit the array above.
const RULE_FIELDS_TAIL: [&str; 4] = [
    "new_routing_mark",
    "limit",
    "address_list",
    "address_list_timeout",
];

/// Fields only sent with these actions (so switching action does not send
/// stale parameters the engine would refuse).
fn action_field_owner(field: &str) -> Option<&'static [&'static str]> {
    Some(match field {
        "reject_with" => &["reject"],
        "jump_target" => &["jump"],
        "log_prefix" => &["log"],
        "to_addresses" => &["src-nat", "dst-nat"],
        "to_ports" => &["masquerade", "src-nat", "dst-nat"],
        "new_connection_mark" => &["mark-connection"],
        "new_packet_mark" => &["mark-packet"],
        "new_routing_mark" => &["mark-routing"],
        "address_list" | "address_list_timeout" => {
            &["add-src-to-address-list", "add-dst-to-address-list"]
        }
        _ => return None,
    })
}

impl RuleForm {
    fn new(table: FwTable) -> Self {
        let mut f = Self::of(&Value::Null);
        f.set("chain", table.chains().first().copied().unwrap_or(""));
        f.set("action", "accept");
        f.set("family", "both");
        f
    }

    fn of(row: &Value) -> Self {
        let fields = RULE_FIELDS
            .iter()
            .chain(RULE_FIELDS_TAIL.iter())
            .map(|k| (*k, text(row, k)))
            .collect();
        Self {
            fields,
            passthrough: row
                .get("passthrough")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            disabled: flag(row, "disabled"),
            comment: text(row, "comment"),
        }
    }

    pub(crate) fn get(&self, k: &str) -> &str {
        self.fields
            .iter()
            .find(|(f, _)| *f == k)
            .map_or("", |(_, v)| v.as_str())
    }

    pub(crate) fn set(&mut self, k: &str, v: &str) {
        if let Some((_, slot)) = self.fields.iter_mut().find(|(f, _)| *f == k) {
            *slot = v.to_owned();
        }
    }

    fn slot(&mut self, k: &str) -> Option<&mut String> {
        self.fields
            .iter_mut()
            .find(|(f, _)| *f == k)
            .map(|(_, v)| v)
    }

    fn applies(&self, k: &str) -> bool {
        action_field_owner(k).is_none_or(|owners| owners.contains(&self.get("action").trim()))
    }

    fn has_passthrough(&self) -> bool {
        self.get("action").starts_with("mark-")
    }

    /// `add` params: every filled field that applies.
    fn add_params(&self) -> Value {
        let mut p = Map::new();
        for (k, v) in &self.fields {
            let v = v.trim();
            if !v.is_empty() && self.applies(k) {
                p.insert((*k).into(), json!(v));
            }
        }
        if self.has_passthrough() && !self.passthrough {
            p.insert("passthrough".into(), json!(false));
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        if !self.comment.is_empty() {
            p.insert("comment".into(), json!(self.comment));
        }
        Value::Object(p)
    }

    /// `set` params for what differs from `base` (`""` clears); `None` if
    /// nothing changed.
    fn set_params(&self, id: &str, base: &RuleForm) -> Option<Value> {
        let mut p = Map::new();
        let action_changed = self.get("action").trim() != base.get("action");
        for (k, v) in &self.fields {
            let v = v.trim();
            if !self.applies(k) {
                continue;
            }
            // A new action takes its fields again (the old ones are gone).
            if v != base.get(k)
                || (action_changed && action_field_owner(k).is_some() && !v.is_empty())
            {
                p.insert((*k).into(), json!(v));
            }
        }
        if self.has_passthrough() && (self.passthrough != base.passthrough || action_changed) {
            p.insert("passthrough".into(), json!(self.passthrough));
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if self.comment != base.comment {
            p.insert("comment".into(), json!(self.comment));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("id".into(), json!(id));
        Some(Value::Object(p))
    }

    fn trimmed(&self) -> Self {
        let mut f = self.clone();
        for (_, v) in &mut f.fields {
            *v = v.trim().to_owned();
        }
        f
    }
}

/// Address-list entry fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AddrForm {
    pub list: String,
    pub address: String,
    pub timeout: String,
    pub comment: String,
    pub disabled: bool,
}

/// Member fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemberForm {
    pub list: String,
    pub interface: String,
    pub comment: String,
    pub disabled: bool,
}

/// Interface list fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListForm {
    pub name: String,
    pub comment: String,
}

/// The editable part of a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Edit {
    Rule {
        table: FwTable,
        form: RuleForm,
        base: RuleForm,
        tab: RuleTab,
    },
    Section {
        table: FwTable,
        title: String,
        base: String,
        disabled: bool,
    },
    Addr {
        form: AddrForm,
        base: AddrForm,
        dynamic: bool,
    },
    Member {
        form: MemberForm,
        base: MemberForm,
    },
    List {
        form: ListForm,
        base: ListForm,
    },
    Comment {
        feed: Feed,
        targets: Vec<String>,
        text: String,
        base: String,
    },
    /// An assistant (G2.1b): one command with what the form holds.
    Wizard {
        kind: Wizard,
        form: WizardForm,
    },
}

impl Edit {
    fn dirty(&self) -> bool {
        match self {
            Edit::Rule { form, base, .. } => form.trimmed() != *base,
            Edit::Section { title, base, .. } => title.trim() != base,
            Edit::Addr { form, base, .. } => form != base,
            Edit::Member { form, base } => form != base,
            Edit::List { form, base } => form != base,
            Edit::Comment { text, base, .. } => text != base,
            Edit::Wizard { .. } => false,
        }
    }

    fn feed(&self) -> Feed {
        match self {
            Edit::Rule { table, .. } | Edit::Section { table, .. } => table.feed(),
            Edit::Addr { .. } => Feed::Addr,
            Edit::Member { .. } => Feed::Members,
            Edit::List { .. } => Feed::Lists,
            Edit::Comment { feed, .. } => *feed,
            Edit::Wizard { kind, .. } => kind.feed(),
        }
    }

    /// What OK/Apply send: (command, params), or `None` when nothing changed.
    fn send(&self, item: Option<&str>) -> Option<(String, Value)> {
        let feed = self.feed();
        match (self, item) {
            (Edit::Rule { table, form, .. }, None) => Some((table.cmd("add"), form.add_params())),
            (Edit::Rule { form, base, .. }, Some(id)) => {
                form.set_params(id, base).map(|p| (feed.set_cmd(), p))
            }
            (Edit::Section { table, title, .. }, None) => {
                Some((table.cmd("add"), json!({ "section": title.trim() })))
            }
            (Edit::Section { title, base, .. }, Some(id)) => (title.trim() != base)
                .then(|| (feed.set_cmd(), json!({"id": id, "section": title.trim()}))),
            (Edit::Addr { form, .. }, None) => {
                let mut p = json!({"list": form.list.trim(), "address": form.address.trim()});
                if !form.timeout.trim().is_empty() {
                    put(&mut p, "timeout", json!(form.timeout.trim()));
                }
                if !form.comment.is_empty() {
                    put(&mut p, "comment", json!(form.comment));
                }
                if form.disabled {
                    put(&mut p, "disabled", json!(true));
                }
                Some(("ip.firewall.address-list.add".into(), p))
            }
            (Edit::Addr { form, base, .. }, Some(id)) => {
                let mut p = Map::new();
                if form.list.trim() != base.list {
                    p.insert("list".into(), json!(form.list.trim()));
                }
                if form.address.trim() != base.address {
                    p.insert("address".into(), json!(form.address.trim()));
                }
                if form.comment != base.comment {
                    p.insert("comment".into(), json!(form.comment));
                }
                if form.disabled != base.disabled {
                    p.insert("disabled".into(), json!(form.disabled));
                }
                (!p.is_empty()).then(|| {
                    p.insert("id".into(), json!(id));
                    (feed.set_cmd(), Value::Object(p))
                })
            }
            (Edit::Member { form, .. }, None) => {
                let mut p = json!({"list": form.list.trim(), "interface": form.interface.trim()});
                if !form.comment.is_empty() {
                    put(&mut p, "comment", json!(form.comment));
                }
                if form.disabled {
                    put(&mut p, "disabled", json!(true));
                }
                Some(("interface.list.member.add".into(), p))
            }
            (Edit::Member { form, base }, Some(id)) => {
                let mut p = Map::new();
                if form.list != base.list {
                    p.insert("list".into(), json!(form.list.trim()));
                }
                if form.interface != base.interface {
                    p.insert("interface".into(), json!(form.interface.trim()));
                }
                if form.comment != base.comment {
                    p.insert("comment".into(), json!(form.comment));
                }
                if form.disabled != base.disabled {
                    p.insert("disabled".into(), json!(form.disabled));
                }
                (!p.is_empty()).then(|| {
                    p.insert("id".into(), json!(id));
                    (feed.set_cmd(), Value::Object(p))
                })
            }
            (Edit::List { form, .. }, None) => {
                let mut p = json!({"name": form.name.trim()});
                if !form.comment.is_empty() {
                    put(&mut p, "comment", json!(form.comment));
                }
                Some(("interface.list.add".into(), p))
            }
            (Edit::List { form, base }, Some(name)) => {
                let mut p = Map::new();
                if form.name.trim() != base.name {
                    p.insert("new_name".into(), json!(form.name.trim()));
                }
                if form.comment != base.comment {
                    p.insert("comment".into(), json!(form.comment));
                }
                (!p.is_empty()).then(|| {
                    p.insert("name".into(), json!(name));
                    (feed.set_cmd(), Value::Object(p))
                })
            }
            (Edit::Comment { .. }, _) => None,
            (Edit::Wizard { kind, form }, _) => Some((kind.cmd().to_owned(), form.params())),
        }
    }

    /// After a successful OK/Apply: what was sent is what the router has.
    fn applied(&mut self) {
        match self {
            Edit::Rule { form, base, .. } => {
                *form = form.trimmed();
                *base = form.clone();
            }
            Edit::Section { title, base, .. } => {
                *title = title.trim().to_owned();
                *base = title.clone();
            }
            Edit::Addr { form, base, .. } => {
                form.list = form.list.trim().into();
                form.address = form.address.trim().into();
                *base = form.clone();
            }
            Edit::Member { form, base } => *base = form.clone(),
            Edit::List { form, base } => {
                form.name = form.name.trim().into();
                *base = form.clone();
            }
            Edit::Comment { text, base, .. } => *base = text.clone(),
            Edit::Wizard { .. } => {}
        }
    }
}

pub(crate) struct FwDialogWin {
    pub id: u64,
    /// The item it edits (rule/entry id, list name); `None` = "New …".
    pub item: Option<String>,
    pub edit: Edit,
    pub status: Status,
}

/// What a dialog's command does to the dialog when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    /// "New …" + Apply: the window becomes the created item's.
    OpenCreated,
    Applied,
    Toggled(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
}

/// Toolbar, menus, shortcuts and drops all end up as one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    New,
    NewSection,
    Up(String),
    Down(String),
    /// Move the first key above the second (`None`: to the end).
    Drop(String, Option<String>),
    SelectAll,
    Refresh,
    /// Open an assistant (G2.1b).
    Wizard(Wizard),
}

/// Colour of a rule by what it does (readable on both themes).
pub(crate) fn action_color(action: &str, dark: bool) -> Option<Color32> {
    let (d, l) = match action {
        "accept" => ((110, 200, 120), (25, 130, 50)),
        "drop" | "reject" => ((235, 110, 100), (190, 40, 30)),
        "masquerade" | "src-nat" | "dst-nat" => ((110, 165, 245), (30, 95, 200)),
        "mark-connection" | "mark-packet" | "mark-routing" => ((190, 140, 240), (125, 60, 185)),
        _ => return None,
    };
    let (r, g, b) = if dark { d } else { l };
    Some(Color32::from_rgb(r, g, b))
}

const RULE_COLUMNS: [table::Column; 13] = [
    col("#"),
    col(""),
    col("Chain"),
    col("Action"),
    col("Src. Address"),
    col("Dst. Address"),
    col("Proto."),
    col("Src. Port"),
    col("Dst. Port"),
    col("In. Interface"),
    col("Out. Interface"),
    col("Descrição"),
    comment(),
];

/// "10.0.0.0/8", "@blocked", or both.
fn join(a: String, b: String) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b,
        (_, true) => a,
        _ => format!("{a} {b}"),
    }
}

fn listed(row: &Value, k: &str, mark: &str) -> String {
    let v = text(row, k);
    if v.is_empty() {
        v
    } else if let Some(rest) = v.strip_prefix('!') {
        format!("!{mark}{rest}")
    } else {
        format!("{mark}{v}")
    }
}

/// An interface and/or an interface list in a cell: the list is a chip
/// coloured by its name (`LAN`, `!LAN` when negated), never `[LAN]`
/// (docs/ui-style.md).
fn iface_cell(row: &Value, iface: &str, list: &str) -> String {
    let name = text(row, iface);
    let list = text(row, list);
    if list.is_empty() {
        return name;
    }
    let hue = chip::name_hue(list.strip_prefix('!').unwrap_or(&list));
    chip::cell(&name, &[(&list, chip::Kind::Hashed(hue))])
}

pub(crate) fn arrow_id(salt: &str, up: bool) -> egui::Id {
    table::table_id(salt).with(("move", up))
}

/// ▲/▼ toolbar button, painted (the bundled fonts have no such glyphs).
fn arrow(ui: &mut Ui, salt: &str, up: bool, enabled: Result<(), String>) -> bool {
    let h = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(h * 1.5, h), egui::Sense::hover());
    let sense = if enabled.is_ok() {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let resp = ui.interact(rect, arrow_id(salt, up), sense);
    let (visuals, color) = match &enabled {
        Ok(()) => (
            *ui.style().interact(&resp),
            ui.visuals().strong_text_color(),
        ),
        Err(_) => (
            ui.visuals().widgets.noninteractive,
            ui.visuals().weak_text_color(),
        ),
    };
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            visuals.corner_radius,
            visuals.weak_bg_fill,
            visuals.bg_stroke,
            egui::StrokeKind::Inside,
        );
        let c = rect.center();
        let r = rect.height() * 0.25;
        let (tip, base) = if up { (-r, r * 0.7) } else { (r, -r * 0.7) };
        ui.painter().add(egui::Shape::convex_polygon(
            vec![
                c + egui::vec2(0.0, tip),
                c + egui::vec2(r, base),
                c + egui::vec2(-r, base),
            ],
            color,
            egui::Stroke::NONE,
        ));
    }
    let tip = if up { "Move Up" } else { "Move Down" };
    let resp = match enabled {
        Ok(()) => resp.on_hover_text(tip),
        Err(why) => resp.on_hover_text(format!("{tip}: {why}")),
    };
    resp.clicked()
}

/// Each rule's `#` (its `position`) by id, built once per frame so a
/// shadowed rule names its shadow without a search through every rule.
pub(crate) fn positions(all: &[Value]) -> HashMap<&str, &Value> {
    all.iter()
        .filter_map(|r| Some((r.get("id")?.as_str()?, r.get("position")?)))
        .collect()
}

/// The Portuguese description, with a warning in front when an earlier
/// rule takes every packet this one would see (named by its `#`, the
/// number the table shows).
pub(crate) fn description(r: &Value, positions: &HashMap<&str, &Value>) -> String {
    let d = text(r, "description");
    let Some(by) = r.get("shadowed_by").and_then(Value::as_str) else {
        return d;
    };
    let by = positions
        .get(by)
        .map_or_else(|| by.to_owned(), |p| format!("#{}", value_text(p)));
    format!("NUNCA CASA: a regra {by} acima já decide estes pacotes. {d}")
}

fn rule_row(r: &Value, positions: &HashMap<&str, &Value>, visuals: &egui::Visuals) -> Row {
    let section = is_section(r);
    let flags = text(r, "flags");
    let action = text(r, "action");
    let tint = if flags.contains('I') {
        Some(visuals.error_fg_color)
    } else if flags.contains('S') {
        // Shadowed: the warning colour, whatever the action.
        Some(visuals.warn_fg_color)
    } else {
        action_color(&action, visuals.dark_mode)
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "position"),
            flags,
            text(r, "chain"),
            action,
            join(text(r, "src_address"), listed(r, "src_address_list", "@")),
            join(text(r, "dst_address"), listed(r, "dst_address_list", "@")),
            text(r, "protocol"),
            text(r, "src_port"),
            text(r, "dst_port"),
            iface_cell(r, "in_interface", "in_interface_list"),
            iface_cell(r, "out_interface", "out_interface_list"),
            if section {
                String::new()
            } else {
                description(r, positions)
            },
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section,
        tint,
    }
}

const ADDR_COLUMNS: [table::Column; 6] = [
    col(""),
    col("List"),
    col("Address"),
    col("Family"),
    col("Timeout"),
    comment(),
];

fn addr_row(r: &Value) -> Row {
    let timeout = r
        .get("timeout")
        .and_then(Value::as_u64)
        .map(duration)
        .unwrap_or_default();
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "list"),
            text(r, "address"),
            text(r, "family"),
            timeout,
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// 3725 → "1h2m5s" (RouterOS style).
pub(crate) fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    for (n, u) in [(d, "d"), (h, "h"), (m, "m"), (s, "s")] {
        if n > 0 {
            out.push_str(&format!("{n}{u}"));
        }
    }
    if out.is_empty() { "0s".into() } else { out }
}

const MEMBER_COLUMNS: [table::Column; 4] = [col(""), col("List"), col("Interface"), comment()];

fn member_row(r: &Value) -> Row {
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "list"),
            text(r, "interface"),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

const LIST_COLUMNS: [table::Column; 4] = [col("Name"), col("Members"), col("Used by"), comment()];

fn list_row(r: &Value) -> Row {
    let names = |k: &str| {
        r.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_text).collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    };
    let mut name = text(r, "name");
    if flag(r, "default") {
        name.push_str(" (default)");
    }
    Row {
        key: text(r, "name"),
        cells: vec![name, names("members"), names("used_by"), text(r, "comment")],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// Rules the zone matrix generated change only through the matrix.
fn not_zone(rows: &[Value], sel: &table::Selection) -> Result<(), String> {
    let zone = rows
        .iter()
        .any(|r| flag(r, "zone") && sel.contains(&text(r, "id")));
    if zone {
        Err("Generated by the zone matrix: change it in the Zones tab".into())
    } else {
        Ok(())
    }
}

fn some(sel: &[String], what: &str) -> Result<(), String> {
    if sel.is_empty() {
        Err(format!("Select one or more {what} first"))
    } else {
        Ok(())
    }
}

/// Enable/Disable greyed when nothing selected would change.
fn can_toggle(rows: &[Value], f: Feed, sel: &table::Selection, enable: bool) -> Result<(), String> {
    some(sel, "items")?;
    not_zone(rows, sel)?;
    let picked: Vec<&Value> = rows
        .iter()
        .filter(|r| sel.contains(&key_of(f, r)))
        .collect();
    if f == Feed::Addr && picked.iter().all(|r| flag(r, "dynamic")) {
        return Err("Dynamic entries cannot be disabled".into());
    }
    if picked.iter().any(|r| flag(r, "disabled") == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

impl CoreRouterUi {
    pub(crate) fn fw_rows(&self, f: Feed) -> &[Value] {
        self.fw.rows(f)
    }

    fn fw_row(&self, f: Feed, key: &str) -> Option<Value> {
        self.fw_rows(f)
            .iter()
            .find(|r| key_of(f, r) == key)
            .cloned()
    }

    fn fw_table(&mut self, f: Feed) -> &mut TableState {
        match f {
            Feed::Filter => &mut self.tables.fw_filter,
            Feed::Nat => &mut self.tables.fw_nat,
            Feed::Mangle => &mut self.tables.fw_mangle,
            Feed::Addr => &mut self.tables.fw_addr,
            Feed::Lists => &mut self.tables.if_lists,
            Feed::Members => &mut self.tables.if_members,
            // The matrix is not a table; its rules are the filter table's.
            Feed::Zones => &mut self.tables.fw_filter,
        }
    }

    /// Names of the interface lists, for combos.
    fn list_names(&self) -> Vec<String> {
        self.fw_rows(Feed::Lists)
            .iter()
            .map(|r| text(r, "name"))
            .collect()
    }

    fn address_list_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .fw_rows(Feed::Addr)
            .iter()
            .map(|r| text(r, "list"))
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// IP › Firewall.
    pub(crate) fn firewall(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Filter, "Filter Rules"),
                (Tab::Nat, "NAT"),
                (Tab::Mangle, "Mangle"),
                (Tab::Addr, "Address Lists"),
                (Tab::Zones, "Zones"),
                (Tab::Connections, "Connections"),
            ] {
                ui.selectable_value(&mut self.fw.tab, tab, label);
            }
        });
        ui.separator();
        match self.fw.tab {
            Tab::Filter => self.rules_tab(ui, FwTable::Filter),
            Tab::Nat => self.rules_tab(ui, FwTable::Nat),
            Tab::Mangle => self.rules_tab(ui, FwTable::Mangle),
            Tab::Addr => self.simple_tab(ui, Feed::Addr),
            Tab::Zones => self.zones_tab(ui),
            Tab::Connections => self.connections_tab(ui),
        }
    }

    /// Whether the Firewall window shows its Connections tab (the
    /// Connections panel asks for the table only then).
    pub(crate) fn firewall_tab_is_connections(&self) -> bool {
        self.fw.tab == Tab::Connections
    }

    /// Interfaces › Interface List.
    pub(crate) fn interface_lists(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.fw.if_tab, IfTab::Members, "Members");
            ui.selectable_value(&mut self.fw.if_tab, IfTab::Lists, "Lists");
        });
        ui.separator();
        match self.fw.if_tab {
            IfTab::Members => self.simple_tab(ui, Feed::Members),
            IfTab::Lists => self.simple_tab(ui, Feed::Lists),
        }
    }

    fn rules_tab(&mut self, ui: &mut Ui, t: FwTable) {
        let f = t.feed();
        let visuals = ui.visuals().clone();
        let chain_ix = feed_index(f);
        let chain = self.fw.chain.get(chain_ix).cloned().unwrap_or_default();
        let all = self.fw.shared(f);
        let at = positions(&all);
        let shown: Vec<&Value> = all
            .iter()
            .filter(|r| chain.is_empty() || text(r, "chain") == chain)
            .collect();
        let rows: Vec<Row> = shown.iter().map(|r| rule_row(r, &at, &visuals)).collect();
        let order: Vec<String> = all.iter().map(|r| text(r, "id")).collect();
        self.fw_table(f).reorder = chain.is_empty();
        let selection = self.fw_table(f).selection(&rows);
        let can = self.can();
        let mut act: Option<Act> = None;
        let set = t.cmd("set");
        let one = match selection.as_slice() {
            [k] => not_zone(&all, &selection).map(|()| k.clone()),
            [] => Err("Select a rule first".to_owned()),
            _ => Err("Select one rule to move it".to_owned()),
        };
        let editable =
            |sel: &table::Selection, what: &str| some(sel, what).and_then(|()| not_zone(&all, sel));
        let up = one.clone().and_then(|k| {
            if order.first() == Some(&k) {
                Err("Already the first rule".into())
            } else {
                Ok(k)
            }
        });
        let down = one.and_then(|k| {
            if order.last() == Some(&k) {
                Err("Already the last rule".into())
            } else {
                Ok(k)
            }
        });

        ui.horizontal(|ui| {
            if table::tool(ui, t.salt(), Icon::Add, "Add", can.check(&t.cmd("add"))).clicked() {
                act = Some(Act::New);
            }
            let sel = || selection.clone();
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and(&t.cmd("remove"), editable(&selection, "rules")),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and(&set, can_toggle(&all, f, &selection, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and(&set, can_toggle(&all, f, &selection, false)),
                ),
                (
                    Icon::Comment,
                    "Comment",
                    can.and(&set, editable(&selection, "rules")),
                ),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, t.salt(), icon, tip, enabled).clicked() {
                    act = Some(match icon {
                        Icon::Remove => Act::Remove(sel().into_vec()),
                        Icon::Enable => Act::Enable(sel().into_vec()),
                        Icon::Disable => Act::Disable(sel().into_vec()),
                        Icon::Add | Icon::Comment => Act::Comment(sel().into_vec()),
                    });
                }
            }
            let mv = t.cmd("move");
            if arrow(ui, t.salt(), true, can.and(&mv, up.clone().map(|_| ()))) {
                act = up.clone().ok().map(Act::Up);
            }
            if arrow(ui, t.salt(), false, can.and(&mv, down.clone().map(|_| ()))) {
                act = down.clone().ok().map(Act::Down);
            }
            if action(ui, "Section", can.check(&t.cmd("add"))) {
                act = Some(Act::NewSection);
            }
            ui.menu_button("Templates", |ui| {
                for w in Wizard::ALL {
                    if action(ui, &format!("{}…", w.label()), can.check(w.cmd())) {
                        act = Some(Act::Wizard(w));
                    }
                }
            });
            let mut picked = chain.clone();
            let mut chains: Vec<String> = vec![String::new()];
            chains.extend(t.chains().iter().map(|c| (*c).to_owned()));
            for r in all.iter() {
                let c = text(r, "chain");
                if !c.is_empty() && !chains.contains(&c) {
                    chains.push(c);
                }
            }
            egui::ComboBox::from_id_salt((t.salt(), "chain"))
                .selected_text(if picked.is_empty() {
                    "all chains"
                } else {
                    picked.as_str()
                })
                .show_ui(ui, |ui| {
                    for c in &chains {
                        let label = if c.is_empty() {
                            "all chains"
                        } else {
                            c.as_str()
                        };
                        ui.selectable_value(&mut picked, c.clone(), label);
                    }
                });
            if picked != chain
                && let Some(slot) = self.fw.chain.get_mut(chain_ix)
            {
                *slot = picked;
            }
            table::find_field(ui, t.salt(), self.fw_table(f));
        });
        ui.separator();

        let open = self.fw_open(f);
        let state = match f {
            Feed::Filter => &mut self.tables.fw_filter,
            Feed::Nat => &mut self.tables.fw_nat,
            _ => &mut self.tables.fw_mangle,
        };
        state.open = open;
        let out = table::show(
            ui,
            t.salt(),
            0.0,
            state,
            &RULE_COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let owned = || sel.to_vec();
                    if action(ui, "Enable", can.and(&set, can_toggle(&all, f, sel, true))) {
                        act = Some(Act::Enable(owned()));
                    }
                    if action(
                        ui,
                        "Disable",
                        can.and(&set, can_toggle(&all, f, sel, false)),
                    ) {
                        act = Some(Act::Disable(owned()));
                    }
                    if action(
                        ui,
                        "Remove",
                        can.and(&t.cmd("remove"), editable(sel, "rules")),
                    ) {
                        act = Some(Act::Remove(owned()));
                    }
                    if action(ui, "Comment…", can.and(&set, editable(sel, "rules"))) {
                        act = Some(Act::Comment(owned()));
                    }
                    if action(ui, "Properties…", some(sel, "rules")) {
                        act = Some(Act::Open(owned()));
                    }
                    if action(
                        ui,
                        "Move Up",
                        can.and(&t.cmd("move"), up.clone().map(|_| ())),
                    ) {
                        act = up.clone().ok().map(Act::Up);
                    }
                    if action(
                        ui,
                        "Move Down",
                        can.and(&t.cmd("move"), down.clone().map(|_| ())),
                    ) {
                        act = down.clone().ok().map(Act::Down);
                    }
                    ui.separator();
                    if action(ui, &format!("Add {}…", t.label()), can.check(&t.cmd("add"))) {
                        act = Some(Act::New);
                    }
                    if action(ui, "Add Section…", can.check(&t.cmd("add"))) {
                        act = Some(Act::NewSection);
                    }
                }
                Menu::Empty => {
                    if action(ui, &format!("Add {}…", t.label()), can.check(&t.cmd("add"))) {
                        act = Some(Act::New);
                    }
                    if action(ui, "Add Section…", can.check(&t.cmd("add"))) {
                        act = Some(Act::NewSection);
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
        if let Some((k, target)) = out.dropped
            && can.check(&t.cmd("move")).is_ok()
        {
            act = Some(Act::Drop(k, target));
        }
        self.table_out(f, out.opened, out.comment, out.shortcut, &mut act, &rows);
        if let Some(a) = act {
            self.fw_act(f, a, &rows);
        }
    }

    /// Double click, comment double click and shortcuts, as actions.
    fn table_out(
        &mut self,
        f: Feed,
        opened: Option<String>,
        comment: Option<String>,
        shortcut: Option<Shortcut>,
        act: &mut Option<Act>,
        rows: &[Row],
    ) {
        if let Some(k) = opened {
            *act = Some(Act::Open(vec![k]));
        }
        if let Some(k) = comment {
            *act = Some(Act::Comment(vec![k]));
        }
        if let Some(s) = shortcut {
            let sel = self.fw_table(f).selection(rows);
            let all = self.fw.shared(f);
            let can = self.can();
            let allowed = match s {
                Shortcut::Remove => can.and(&f.remove_cmd(), some(&sel, "items")).is_ok(),
                Shortcut::Comment => can.and(&f.set_cmd(), some(&sel, "items")).is_ok(),
                Shortcut::Enable => can
                    .and(&f.set_cmd(), can_toggle(&all, f, &sel, true))
                    .is_ok(),
                Shortcut::Disable => can
                    .and(&f.set_cmd(), can_toggle(&all, f, &sel, false))
                    .is_ok(),
                Shortcut::Open => !sel.is_empty(),
            };
            if allowed && f != Feed::Lists || matches!(s, Shortcut::Open | Shortcut::Remove) {
                *act = Some(match s {
                    Shortcut::Remove => Act::Remove(sel.into_vec()),
                    Shortcut::Enable => Act::Enable(sel.into_vec()),
                    Shortcut::Disable => Act::Disable(sel.into_vec()),
                    Shortcut::Comment => Act::Comment(sel.into_vec()),
                    Shortcut::Open => Act::Open(sel.into_vec()),
                });
                if !allowed {
                    *act = None;
                }
            }
        }
    }

    /// Address lists, members, lists: same toolbar without ordering.
    fn simple_tab(&mut self, ui: &mut Ui, f: Feed) {
        let rows_v = self.fw.shared(f);
        let rows: Vec<Row> = rows_v
            .iter()
            .map(|r| match f {
                Feed::Addr => addr_row(r),
                Feed::Members => member_row(r),
                _ => list_row(r),
            })
            .collect();
        let columns: &[table::Column] = match f {
            Feed::Addr => &ADDR_COLUMNS,
            Feed::Members => &MEMBER_COLUMNS,
            _ => &LIST_COLUMNS,
        };
        let add = match f {
            Feed::Addr => "ip.firewall.address-list.add",
            Feed::Members => "interface.list.member.add",
            _ => "interface.list.add",
        };
        let selection = self.fw_table(f).selection(&rows);
        let can = self.can();
        let set = f.set_cmd();
        let toggles = f != Feed::Lists;
        let mut act: Option<Act> = None;
        ui.horizontal(|ui| {
            if table::tool(ui, f.salt(), Icon::Add, "Add", can.check(add)).clicked() {
                act = Some(Act::New);
            }
            let sel = || selection.clone();
            let mut tools = vec![(
                Icon::Remove,
                "Remove",
                can.and(&f.remove_cmd(), some(&selection, "items")),
            )];
            if toggles {
                tools.push((
                    Icon::Enable,
                    "Enable",
                    can.and(&set, can_toggle(&rows_v, f, &selection, true)),
                ));
                tools.push((
                    Icon::Disable,
                    "Disable",
                    can.and(&set, can_toggle(&rows_v, f, &selection, false)),
                ));
            }
            tools.push((
                Icon::Comment,
                "Comment",
                can.and(&set, some(&selection, "items")),
            ));
            for (icon, tip, enabled) in tools {
                if table::tool(ui, f.salt(), icon, tip, enabled).clicked() {
                    act = Some(match icon {
                        Icon::Remove => Act::Remove(sel().into_vec()),
                        Icon::Enable => Act::Enable(sel().into_vec()),
                        Icon::Disable => Act::Disable(sel().into_vec()),
                        Icon::Add | Icon::Comment => Act::Comment(sel().into_vec()),
                    });
                }
            }
            table::find_field(ui, f.salt(), self.fw_table(f));
        });
        ui.separator();
        let open = self.fw_open(f);
        let state = match f {
            Feed::Addr => &mut self.tables.fw_addr,
            Feed::Members => &mut self.tables.if_members,
            _ => &mut self.tables.if_lists,
        };
        state.open = open;
        let out = table::show(
            ui,
            f.salt(),
            0.0,
            state,
            columns,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let owned = || sel.to_vec();
                    if toggles {
                        if action(
                            ui,
                            "Enable",
                            can.and(&set, can_toggle(&rows_v, f, sel, true)),
                        ) {
                            act = Some(Act::Enable(owned()));
                        }
                        if action(
                            ui,
                            "Disable",
                            can.and(&set, can_toggle(&rows_v, f, sel, false)),
                        ) {
                            act = Some(Act::Disable(owned()));
                        }
                    }
                    if action(ui, "Remove", can.and(&f.remove_cmd(), some(sel, "items"))) {
                        act = Some(Act::Remove(owned()));
                    }
                    if action(ui, "Comment…", can.and(&set, some(sel, "items"))) {
                        act = Some(Act::Comment(owned()));
                    }
                    if action(ui, "Properties…", some(sel, "items")) {
                        act = Some(Act::Open(owned()));
                    }
                    ui.separator();
                    if action(ui, &format!("Add {}…", f.what()), can.check(add)) {
                        act = Some(Act::New);
                    }
                }
                Menu::Empty => {
                    if action(ui, &format!("Add {}…", f.what()), can.check(add)) {
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
        self.table_out(f, out.opened, out.comment, out.shortcut, &mut act, &rows);
        if let Some(a) = act {
            self.fw_act(f, a, &rows);
        }
    }

    fn fw_act(&mut self, f: Feed, act: Act, rows: &[Row]) {
        let key = f.key();
        let up = matches!(act, Act::Up(_));
        match act {
            Act::Enable(keys) | Act::Disable(keys) if f == Feed::Lists => {
                let _ = keys;
            }
            Act::Enable(keys) => {
                for k in keys {
                    self.run(&f.set_cmd(), json!({ key: k, "disabled": false }));
                }
            }
            Act::Disable(keys) => {
                for k in keys {
                    self.run(&f.set_cmd(), json!({ key: k, "disabled": true }));
                }
            }
            Act::Remove(keys) => {
                for k in keys {
                    self.run(&f.remove_cmd(), json!({ key: k }));
                }
            }
            Act::Comment(keys) => {
                let text = match keys.as_slice() {
                    [one] => self
                        .fw_row(f, one)
                        .map(|r| crate::firewall::text(&r, "comment"))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                if !keys.is_empty() {
                    self.open_fw_dialog(
                        None,
                        Edit::Comment {
                            feed: f,
                            targets: keys,
                            base: text.clone(),
                            text,
                        },
                    );
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_fw(f, k);
                }
            }
            Act::New => {
                let edit = match f {
                    Feed::Addr => Edit::Addr {
                        form: AddrForm::default(),
                        base: AddrForm::default(),
                        dynamic: false,
                    },
                    Feed::Members => Edit::Member {
                        form: MemberForm::default(),
                        base: MemberForm::default(),
                    },
                    Feed::Lists => Edit::List {
                        form: ListForm::default(),
                        base: ListForm::default(),
                    },
                    t => {
                        let Some(t) = t.table() else { return };
                        let form = RuleForm::new(t);
                        Edit::Rule {
                            table: t,
                            base: form.clone(),
                            form,
                            tab: RuleTab::General,
                        }
                    }
                };
                self.open_fw_dialog(None, edit);
            }
            Act::NewSection => {
                if let Some(t) = f.table() {
                    self.open_fw_dialog(
                        None,
                        Edit::Section {
                            table: t,
                            title: String::new(),
                            base: String::new(),
                            disabled: false,
                        },
                    );
                }
            }
            Act::Up(k) | Act::Down(k) => {
                let Some(t) = f.table() else { return };
                let order: Vec<String> = self.fw_rows(f).iter().map(|r| text(r, "id")).collect();
                let Some(i) = order.iter().position(|o| *o == k) else {
                    return;
                };
                let dest = if up {
                    i.checked_sub(1).and_then(|j| order.get(j)).cloned()
                } else {
                    // Above the row after the next one, or the end.
                    order.get(i + 2).cloned()
                };
                let mut p = json!({ "id": k });
                if let Some(d) = dest {
                    put(&mut p, "destination", json!(d));
                }
                self.run(&t.cmd("move"), p);
            }
            Act::Drop(k, target) => {
                let Some(t) = f.table() else { return };
                let mut p = json!({ "id": k });
                if let Some(d) = target {
                    put(&mut p, "destination", json!(d));
                }
                self.run(&t.cmd("move"), p);
            }
            Act::Wizard(w) => self.open_wizard(w),
            Act::SelectAll => self.fw_table(f).select_all(rows),
            Act::Refresh => self.cache.refreshed_at = None,
        }
    }

    /// Items of `f` whose window is open (marked in the table).
    fn fw_open(&self, f: Feed) -> BTreeSet<String> {
        self.fw
            .dialogs
            .iter()
            .filter(|d| d.edit.feed() == f && !matches!(d.edit, Edit::Comment { .. }))
            .filter_map(|d| d.item.clone())
            .collect()
    }

    /// The window of an assistant (one at a time per kind; asking again
    /// brings the open one to the front).
    pub(crate) fn open_wizard(&mut self, w: Wizard) {
        let open = self
            .fw
            .dialogs
            .iter_mut()
            .find(|d| matches!(&d.edit, Edit::Wizard { kind, .. } if *kind == w));
        if let Some(d) = open {
            d.status.bring_to_front();
        } else {
            self.open_fw_dialog(
                None,
                Edit::Wizard {
                    kind: w,
                    form: w.form(),
                },
            );
        }
    }

    fn open_fw_dialog(&mut self, item: Option<String>, edit: Edit) {
        self.next_dialog = self.next_dialog.wrapping_add(1);
        self.fw.dialogs.push(FwDialogWin {
            id: self.next_dialog,
            item,
            edit,
            status: Status::default(),
        });
    }

    /// The window of item `key`; an open one comes to the front.
    pub(crate) fn open_fw(&mut self, f: Feed, key: &str) {
        let Some(row) = self.fw_row(f, key) else {
            return;
        };
        let open = self.fw.dialogs.iter_mut().find(|d| {
            d.item.as_deref() == Some(key)
                && d.edit.feed() == f
                && !matches!(d.edit, Edit::Comment { .. })
        });
        if let Some(d) = open {
            d.status.bring_to_front();
            return;
        }
        let edit = match f {
            Feed::Addr => {
                let form = AddrForm {
                    list: text(&row, "list"),
                    address: text(&row, "address"),
                    timeout: String::new(),
                    comment: text(&row, "comment"),
                    disabled: flag(&row, "disabled"),
                };
                Edit::Addr {
                    base: form.clone(),
                    form,
                    dynamic: flag(&row, "dynamic"),
                }
            }
            Feed::Members => {
                let form = MemberForm {
                    list: text(&row, "list"),
                    interface: text(&row, "interface"),
                    comment: text(&row, "comment"),
                    disabled: flag(&row, "disabled"),
                };
                Edit::Member {
                    base: form.clone(),
                    form,
                }
            }
            Feed::Lists => {
                let form = ListForm {
                    name: text(&row, "name"),
                    comment: text(&row, "comment"),
                };
                Edit::List {
                    base: form.clone(),
                    form,
                }
            }
            t => {
                let Some(t) = t.table() else { return };
                if is_section(&row) {
                    let title = text(&row, "comment");
                    Edit::Section {
                        table: t,
                        base: title.clone(),
                        title,
                        disabled: flag(&row, "disabled"),
                    }
                } else {
                    let form = RuleForm::of(&row);
                    Edit::Rule {
                        table: t,
                        base: form.clone(),
                        form,
                        tab: RuleTab::General,
                    }
                }
            }
        };
        self.open_fw_dialog(Some(key.to_owned()), edit);
    }

    /// A list arrived: open the items waiting for it.
    pub(crate) fn fw_arrived(&mut self, f: Feed, id: RequestId, rows: Vec<Value>) {
        for (feed, key) in self.fw.arrived(f, id, rows) {
            self.open_fw(feed, &key);
        }
    }

    /// Draw every open firewall / interface-list dialog.
    pub(crate) fn fw_dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let mut dialogs = std::mem::take(&mut self.fw.dialogs);
        let lists = self.list_names();
        let addr_lists = self.address_list_names();
        let ifaces = self.interface_names(None);
        dialogs.retain_mut(|d| {
            let id = dialog_id(d.id);
            let feed = d.edit.feed();
            // A window whose item is gone closes itself.
            let row = d.item.as_ref().and_then(|k| self.fw_row(feed, k));
            let gone = d.item.is_some() && row.is_none() && !matches!(d.edit, Edit::Comment { .. });
            if gone {
                self.floats.forget(id);
                return false;
            }
            let title = title(&d.edit, d.item.as_deref(), row.as_ref());
            let can = self.can();
            let head = Head {
                id,
                title: &title,
                dirty: d.edit.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(feed.window())),
            };
            let pick = Picks {
                lists: &lists,
                addr_lists: &addr_lists,
                ifaces: &ifaces,
            };
            let item = d.item.clone();
            let pressed =
                dialog::show(&mut self.floats, ctx, area, head, &mut d.status, |ui, f| {
                    body(
                        ui,
                        f,
                        &mut d.edit,
                        item.as_deref(),
                        row.as_ref(),
                        &pick,
                        &can,
                    )
                });
            let keep = pressed.is_none_or(|b| self.fw_button(d, b, row.as_ref()));
            if !keep {
                self.floats.forget(id);
            }
            keep
        });
        dialogs.append(&mut self.fw.dialogs);
        self.fw.dialogs = dialogs;
    }

    fn fw_button(&mut self, d: &mut FwDialogWin, b: Press<Button>, row: Option<&Value>) -> bool {
        if b == Press::Cancel {
            return false;
        }
        let feed = d.edit.feed();
        let key = feed.key();
        let (sends, close): (Vec<(String, Value, Effect)>, bool) = match (&d.edit, &d.item, &b) {
            (
                Edit::Comment {
                    targets,
                    text,
                    feed,
                    ..
                },
                _,
                _,
            ) => (
                targets
                    .iter()
                    .map(|t| {
                        (
                            feed.set_cmd(),
                            json!({ feed.key(): t, "comment": text }),
                            Effect::None,
                        )
                    })
                    .collect(),
                true,
            ),
            (_, Some(item), Press::Other(Button::Toggle)) => {
                let now = row.is_some_and(|r| flag(r, "disabled"));
                (
                    vec![(
                        feed.set_cmd(),
                        json!({ key: item, "disabled": !now }),
                        Effect::Toggled(!now),
                    )],
                    false,
                )
            }
            (_, Some(item), Press::Other(Button::Remove)) => (
                vec![(feed.remove_cmd(), json!({ key: item }), Effect::None)],
                true,
            ),
            (edit, item, Press::Ok | Press::Apply) => match edit.send(item.as_deref()) {
                Some((cmd, p)) => {
                    let effect = match (item, &b) {
                        (None, Press::Apply) => Effect::OpenCreated,
                        (None, _) => Effect::None,
                        _ => Effect::Applied,
                    };
                    (vec![(cmd, p, effect)], b == Press::Ok)
                }
                // OK with nothing changed just closes.
                None => return b != Press::Ok,
            },
            _ => return true,
        };
        d.status.close_on_success = close;
        for (cmd, params, effect) in sends {
            d.status.sent();
            self.run_then(&cmd, params, Then::Fw { id: d.id, effect });
        }
        true
    }

    /// A reply to a dialog's command: an error stays in the dialog.
    pub(crate) fn fw_dialog_reply(
        &mut self,
        id: u64,
        effect: Effect,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.fw.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut created: Option<(Feed, String)> = None;
        let close = match self.fw.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, effect) {
                    (Err(_), _) => {}
                    (Ok(r), Effect::OpenCreated) => {
                        let feed = d.edit.feed();
                        created = r
                            .get(feed.key())
                            .and_then(Value::as_str)
                            .map(|k| (feed, k.to_owned()));
                        d.status.close_on_success = true;
                    }
                    (Ok(r), Effect::Applied) => {
                        d.edit.applied();
                        // A renamed list is known by its new name now.
                        if let (Edit::List { .. }, Some(n)) =
                            (&d.edit, r.get("name").and_then(Value::as_str))
                        {
                            d.item = Some(n.to_owned());
                        }
                    }
                    (Ok(_), Effect::Toggled(now)) => match &mut d.edit {
                        Edit::Rule { form, base, .. } => {
                            form.disabled = now;
                            base.disabled = now;
                        }
                        Edit::Section { disabled, .. } => *disabled = now,
                        Edit::Addr { form, base, .. } => {
                            form.disabled = now;
                            base.disabled = now;
                        }
                        Edit::Member { form, base } => {
                            form.disabled = now;
                            base.disabled = now;
                        }
                        _ => {}
                    },
                    (Ok(_), Effect::None) => {}
                }
                close || created.is_some()
            }
        };
        if close {
            self.fw.dialogs.remove(pos);
            self.floats.forget(dialog_id(id));
        }
        if let Some((feed, key)) = created {
            let req = self.reload();
            self.fw.open_after.push((req, feed, key));
        }
    }
}

/// Choices the dialogs offer in their combos.
struct Picks<'a> {
    lists: &'a [String],
    addr_lists: &'a [String],
    ifaces: &'a [String],
}

fn title(e: &Edit, item: Option<&str>, row: Option<&Value>) -> String {
    let new = item.is_none();
    match e {
        Edit::Rule { table, .. } if new => format!("New {}", table.label()),
        Edit::Rule { table, .. } => format!("{} <{}>", table.label(), item.unwrap_or("")),
        Edit::Section { .. } if new => "New Section".into(),
        Edit::Section { .. } => format!(
            "Section <{}>",
            row.map(|r| text(r, "comment")).unwrap_or_default()
        ),
        Edit::Addr { .. } if new => "New Firewall Address List".into(),
        Edit::Addr { .. } => format!(
            "Firewall Address List <{}>",
            row.map(|r| text(r, "address")).unwrap_or_default()
        ),
        Edit::Member { .. } if new => "New Interface List Member".into(),
        Edit::Member { .. } => format!(
            "Interface List Member <{}>",
            row.map(|r| format!("{} in {}", text(r, "interface"), text(r, "list")))
                .unwrap_or_default()
        ),
        Edit::List { .. } if new => "New Interface List".into(),
        Edit::List { .. } => format!("Interface List <{}>", item.unwrap_or("")),
        Edit::Comment { feed, targets, .. } => match targets.as_slice() {
            [one] => format!("Comment for {} <{one}>", feed.what()),
            many => format!("Comment for {} items", many.len()),
        },
        Edit::Wizard { kind, .. } => kind.label().to_owned(),
    }
}

/// An editable combo: pick from `options` or type.
fn combo_text(
    ui: &mut Ui,
    f: &Form,
    label: &str,
    param: &str,
    value: &mut String,
    options: &[String],
    hint: &str,
) {
    ui.label(label);
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(value)
                .id(dialog::field_id(f.window(), param))
                .hint_text(hint)
                .desired_width(150.0),
        );
        egui::ComboBox::from_id_salt((f.window(), param, "pick"))
            .selected_text("")
            .width(20.0)
            .show_ui(ui, |ui| {
                if ui.selectable_label(value.is_empty(), "(none)").clicked() {
                    value.clear();
                }
                for o in options {
                    if ui.selectable_label(value == o, o).clicked() {
                        value.clone_from(o);
                    }
                }
            });
    });
    ui.end_row();
}

fn rule_field(ui: &mut Ui, f: &Form, form: &mut RuleForm, label: &str, param: &str, hint: &str) {
    if let Some(v) = form.slot(param) {
        f.text(ui, label, param, v, hint);
    }
}

fn rule_combo(
    ui: &mut Ui,
    f: &Form,
    form: &mut RuleForm,
    label: &str,
    param: &str,
    options: &[String],
    hint: &str,
) {
    if let Some(v) = form.slot(param) {
        combo_text(ui, f, label, param, v, options, hint);
    }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn body(
    ui: &mut Ui,
    f: &Form,
    e: &mut Edit,
    item: Option<&str>,
    row: Option<&Value>,
    pick: &Picks<'_>,
    can: &Avail,
) -> Footer<Button> {
    if let Edit::Wizard { kind, form } = e {
        return crate::firewall_assist::body(ui, f, *kind, form, can);
    }
    let feed = e.feed();
    let mut toggle = None;
    match e {
        Edit::Rule {
            table, form, tab, ..
        } => {
            ui.set_min_width(340.0);
            ui.horizontal(|ui| {
                ui.selectable_value(tab, RuleTab::General, "General");
                ui.selectable_value(tab, RuleTab::Advanced, "Advanced");
                ui.selectable_value(tab, RuleTab::Action, "Action");
            });
            ui.separator();
            let t = *table;
            Grid::new("rule-fields")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| match tab {
                    RuleTab::General => {
                        rule_combo(ui, f, form, "Chain", "chain", &strings(t.chains()), "input");
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Family",
                            "family",
                            &strings(&["both", "ipv4", "ipv6"]),
                            "both",
                        );
                        rule_field(
                            ui,
                            f,
                            form,
                            "Src. Address",
                            "src_address",
                            "10.0.0.0/8, !192.0.2.1",
                        );
                        rule_field(
                            ui,
                            f,
                            form,
                            "Dst. Address",
                            "dst_address",
                            "IP, IP/prefix or IP-IP",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Protocol",
                            "protocol",
                            &strings(&["tcp", "udp", "icmp", "icmpv6", "gre", "sctp"]),
                            "any",
                        );
                        rule_field(ui, f, form, "Src. Port", "src_port", "1024-65535");
                        rule_field(ui, f, form, "Dst. Port", "dst_port", "22,80,443");
                        rule_combo(
                            ui,
                            f,
                            form,
                            "In. Interface",
                            "in_interface",
                            pick.ifaces,
                            "any",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Out. Interface",
                            "out_interface",
                            pick.ifaces,
                            "any",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "In. Interface List",
                            "in_interface_list",
                            pick.lists,
                            "LAN, !WAN",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Out. Interface List",
                            "out_interface_list",
                            pick.lists,
                            "WAN",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Connection State",
                            "connection_state",
                            &strings(&[
                                "established,related",
                                "established,related,untracked",
                                "new",
                                "invalid",
                            ]),
                            "established,related",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Connection NAT State",
                            "connection_nat_state",
                            &strings(&["srcnat", "dstnat", "!dstnat"]),
                            "dstnat",
                        );
                        f.text(ui, "Comment", "comment", &mut form.comment, "");
                    }
                    RuleTab::Advanced => {
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Src. Address List",
                            "src_address_list",
                            pick.addr_lists,
                            "name or !name",
                        );
                        rule_combo(
                            ui,
                            f,
                            form,
                            "Dst. Address List",
                            "dst_address_list",
                            pick.addr_lists,
                            "name or !name",
                        );
                        rule_field(
                            ui,
                            f,
                            form,
                            "ICMP Options",
                            "icmp_options",
                            "8:0 (type:code)",
                        );
                        rule_field(ui, f, form, "Connection Mark", "connection_mark", "name");
                        rule_field(ui, f, form, "Packet Mark", "packet_mark", "name");
                        rule_field(ui, f, form, "Routing Mark", "routing_mark", "name");
                        rule_field(ui, f, form, "Limit", "limit", "5/1s,10 (count/time,burst)");
                    }
                    RuleTab::Action => {
                        let actions = strings(t.actions());
                        ui.label("Action");
                        let mut a = form.get("action").to_owned();
                        crate::windows::combo(ui, "rule-action", "accept", &mut a, &actions);
                        ui.end_row();
                        form.set("action", &a);
                        let fields: &[(&str, &str, &str)] = &[
                            ("reject_with", "Reject With", "icmp-no-route"),
                            ("jump_target", "Jump Target", "chain name"),
                            ("log_prefix", "Log Prefix", "text"),
                            (
                                "to_addresses",
                                "To Addresses",
                                "10.0.0.2 or 10.0.0.2-10.0.0.9",
                            ),
                            ("to_ports", "To Ports", "80 or 1024-2048"),
                            ("new_connection_mark", "New Connection Mark", "name"),
                            ("new_packet_mark", "New Packet Mark", "name"),
                            ("new_routing_mark", "New Routing Mark", "name"),
                            ("address_list", "Address List", "name"),
                            (
                                "address_list_timeout",
                                "Timeout",
                                "none (until restart), 1m, 1d",
                            ),
                        ];
                        for (param, label, hint) in fields {
                            if !form.applies(param) {
                                continue;
                            }
                            if *param == "reject_with" {
                                rule_combo(
                                    ui,
                                    f,
                                    form,
                                    label,
                                    param,
                                    &strings(&[
                                        "icmp-no-route",
                                        "icmp-admin-prohibited",
                                        "icmp-address-unreachable",
                                        "icmp-port-unreachable",
                                        "tcp-reset",
                                    ]),
                                    hint,
                                );
                            } else if *param == "address_list" {
                                rule_combo(ui, f, form, label, param, pick.addr_lists, hint);
                            } else {
                                rule_field(ui, f, form, label, param, hint);
                            }
                        }
                        if form.has_passthrough() {
                            ui.label("Passthrough");
                            ui.checkbox(&mut form.passthrough, "");
                            ui.end_row();
                        }
                    }
                });
            if item.is_some() {
                toggle = Some(form.disabled);
                if let Some(r) = row {
                    let reason = text(r, "reason");
                    if !reason.is_empty() {
                        ui.colored_label(ui.visuals().error_fg_color, format!("invalid: {reason}"));
                    }
                    ui.weak(text(r, "summary"));
                }
            }
        }
        Edit::Section {
            title, disabled, ..
        } => {
            Grid::new("fields").num_columns(2).show(ui, |ui| {
                f.text(ui, "Title", "section", title, "Router protection");
            });
            ui.weak("A section header groups the rules below it; it matches nothing.");
            if item.is_some() {
                toggle = Some(*disabled);
            }
        }
        Edit::Addr { form, dynamic, .. } => {
            Grid::new("fields")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    combo_text(
                        ui,
                        f,
                        "List",
                        "list",
                        &mut form.list,
                        pick.addr_lists,
                        "blocked",
                    );
                    f.text(
                        ui,
                        "Address",
                        "address",
                        &mut form.address,
                        "IP, IP/prefix or IP-IP",
                    );
                    if item.is_none() {
                        f.text(
                            ui,
                            "Timeout",
                            "timeout",
                            &mut form.timeout,
                            "none (static), 1h, 30m",
                        );
                    } else if let Some(r) = row.filter(|_| *dynamic) {
                        ui.label("Timeout");
                        ui.weak(
                            r.get("timeout")
                                .and_then(Value::as_u64)
                                .map(duration)
                                .unwrap_or_default(),
                        );
                        ui.end_row();
                    }
                    f.text(ui, "Comment", "comment", &mut form.comment, "");
                });
            if *dynamic {
                ui.weak("Dynamic entry: it expires and is not saved; it can only be removed.");
            } else if item.is_some() {
                toggle = Some(form.disabled);
            }
        }
        Edit::Member { form, .. } => {
            Grid::new("fields")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("List");
                    crate::windows::combo(ui, "member-list", "LAN", &mut form.list, pick.lists);
                    ui.end_row();
                    ui.label("Interface");
                    crate::windows::combo(
                        ui,
                        "member-iface",
                        "ether1",
                        &mut form.interface,
                        pick.ifaces,
                    );
                    ui.end_row();
                    f.text(ui, "Comment", "comment", &mut form.comment, "");
                });
            if item.is_some() {
                toggle = Some(form.disabled);
            }
        }
        Edit::List { form, .. } => {
            Grid::new("fields")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    let param = if item.is_some() { "new_name" } else { "name" };
                    f.text(ui, "Name", param, &mut form.name, "DMZ");
                    f.text(ui, "Comment", "comment", &mut form.comment, "");
                });
            if let Some(r) = row {
                let used = r
                    .get("used_by")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                if used > 0 {
                    ui.weak(format!(
                        "Used by {used} firewall rule(s): rename or remove them first."
                    ));
                }
            }
        }
        Edit::Comment { text, .. } => {
            Grid::new("fields").num_columns(2).show(ui, |ui| {
                f.text(ui, "Comment", "comment", text, "");
            });
        }
        Edit::Wizard { .. } => {}
    }
    let new = item.is_none();
    let ok_cmd = match e {
        Edit::Rule { table, .. } | Edit::Section { table, .. } if new => table.cmd("add"),
        Edit::Addr { .. } if new => "ip.firewall.address-list.add".into(),
        Edit::Member { .. } if new => "interface.list.member.add".into(),
        Edit::List { .. } if new => "interface.list.add".into(),
        _ => feed.set_cmd(),
    };
    let comment_only = matches!(e, Edit::Comment { .. });
    let view_only = matches!(e, Edit::Addr { dynamic: true, .. });
    if view_only {
        return Footer {
            buttons: Buttons::View,
            ok: Ok(()),
            extra: vec![("Remove", Button::Remove, can.check(&feed.remove_cmd()))],
            pressed: None,
        };
    }
    let mut footer = Footer::edit(!comment_only, can.check(&ok_cmd));
    if !new && !comment_only {
        if let Some(disabled) = toggle {
            footer.extra.push((
                if disabled { "Enable" } else { "Disable" },
                Button::Toggle,
                can.check(&feed.set_cmd()),
            ));
        }
        footer
            .extra
            .push(("Remove", Button::Remove, can.check(&feed.remove_cmd())));
    }
    footer
}

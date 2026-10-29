//! IPv6 › ND (G3.9ha), RouterOS v7 `/ipv6 nd` and `/ipv6 nd prefix`: the
//! approved mockup (option A) — an Interfaces tab with the RA entries and,
//! under it, every interface the plan reaches (sending, waiting, failed,
//! or skipped with the reason: WAN, PPPoE server port, no prefix), and a
//! Prefixes tab with the static prefixes, the dynamic ones from the
//! interfaces' addresses and the deprecated ones still going out with
//! lifetimes 0. Both lists follow the list window pattern (G0.24), the
//! modals are fed by `ipv6.nd.check` / `ipv6.nd.prefix.check`.
//! `ipv6.nd.*` decides; this only shows and sends.

use std::collections::BTreeMap;

use egui::{Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell, name_hue};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "ipv6-nd";
pub(crate) const WIN: &str = "ipv6-nd";
pub(crate) const SCOPE: &str = "ipv6_nd";
const TABLE: &str = "ipv6-nd";
const PORTS: &str = "ipv6-nd-ports";
const PREFIXES: &str = "ipv6-nd-prefixes";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IPv6",
        title: "ND",
        size: [1000.0, 540.0],
        escape: true,
    }],
    new: || Box::<NdPanel>::default(),
};

const CMDS: Cmds = Cmds {
    add: "ipv6.nd.add",
    remove: "ipv6.nd.remove",
    set: Some("ipv6.nd.set"),
    what: "ND entries",
};

const PREFIX_CMDS: Cmds = Cmds {
    add: "ipv6.nd.prefix.add",
    remove: "ipv6.nd.prefix.remove",
    set: Some("ipv6.nd.prefix.set"),
    what: "ND prefixes",
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

const FIELDS: &[Field] = &[
    field("interface", "Interface", "ipv6_nd.interface", Input::Choice),
    field("ra_interval", "RA Interval", "ipv6_nd.ra_interval", Input::Text("3m20s-10m")),
    field("ra_delay", "RA Delay", "ipv6_nd.ra_delay", Input::Text("3s")),
    field("ra_lifetime", "RA Lifetime", "ipv6_nd.ra_lifetime", Input::Text("30m")),
    field("ra_preference", "RA Preference", "ipv6_nd.ra_preference", Input::Choice),
    field("hop_limit", "Hop Limit", "ipv6_nd.hop_limit", Input::Text("64")),
    field("mtu", "MTU", "ipv6_nd.mtu", Input::Text("unspecified")),
    field("reachable_time", "Reachable Time", "ipv6_nd.reachable_time", Input::Text("0 (unspecified, ms)")),
    field("retransmit_interval", "Retransmit Interval", "ipv6_nd.retransmit_interval", Input::Text("0 (unspecified, ms)")),
    field("managed_address_configuration", "Managed Address Configuration", "ipv6_nd.managed", Input::Check),
    field("other_configuration", "Other Configuration", "ipv6_nd.other", Input::Check),
    field("advertise_mac_address", "Advertise MAC Address", "ipv6_nd.advertise_mac_address", Input::Check),
    field("advertise_dns", "Advertise DNS", "ipv6_nd.advertise_dns", Input::Check),
    field("dns", "DNS Servers", "ipv6_nd.dns", Input::Text("automatic (comma-separated)")),
    field("dnssl", "DNS Search", "ipv6_nd.dnssl", Input::Text("isp.example")),
    field("disabled", "Disabled", "ipv6_nd.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const PREFIX_FIELDS: &[Field] = &[
    field("prefix", "Prefix", "ipv6_nd.prefix", Input::Text("2001:db8:1::/64")),
    field("interface", "Interface", "ipv6_nd.prefix_interface", Input::Choice),
    field("valid_lifetime", "Valid Lifetime", "ipv6_nd.valid_lifetime", Input::Text("4w2d")),
    field("preferred_lifetime", "Preferred Lifetime", "ipv6_nd.preferred_lifetime", Input::Text("1w")),
    field("on_link", "On Link", "ipv6_nd.on_link", Input::Check),
    field("autonomous", "Autonomous", "ipv6_nd.autonomous", Input::Check),
    field("disabled", "Disabled", "ipv6_nd.prefix_disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New ND Interface",
    edit_title: "ND Interface",
    help: "ipv6_nd",
    fields: FIELDS,
    preview: "ipv6.nd.check",
};

const PREFIX_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New ND Prefix",
    edit_title: "ND Prefix",
    help: "ipv6_nd.prefixes",
    fields: PREFIX_FIELDS,
    preview: "ipv6.nd.prefix.check",
};

const COLUMNS: [table::Column; 10] = [
    col("Interface").help("ipv6_nd.interface"),
    col("RA Interval").help("ipv6_nd.ra_interval"),
    col("RA Lifetime").help("ipv6_nd.ra_lifetime"),
    col("M / O").help("ipv6_nd.flags"),
    num("MTU").help("ipv6_nd.mtu"),
    num("Hop Limit").help("ipv6_nd.hop_limit"),
    col("Preference").help("ipv6_nd.ra_preference"),
    col("DNS").help("ipv6_nd.advertise_dns"),
    col("State").help("ipv6_nd.state"),
    comment(),
];

const PORT_COLUMNS: [table::Column; 7] = [
    col("Interface").help("ipv6_nd.port"),
    col("State").help("ipv6_nd.port_state"),
    col("Prefixes").help("ipv6_nd.prefixes"),
    col("DNS").help("ipv6_nd.rdnss"),
    num("RAs Sent").help("ipv6_nd.ra_sent"),
    num("RSs Received").help("ipv6_nd.rs_received"),
    col("Detail").help("ipv6_nd.detail"),
];

const PREFIX_COLUMNS: [table::Column; 7] = [
    col("Prefix").help("ipv6_nd.prefix"),
    col("Interface").help("ipv6_nd.prefix_interface"),
    col("Valid").help("ipv6_nd.valid_lifetime"),
    col("Preferred").help("ipv6_nd.preferred_lifetime"),
    col("Flags").help("ipv6_nd.prefix_flags"),
    col("Origin").help("ipv6_nd.origin"),
    comment(),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Interfaces,
    Prefixes,
}

/// What the open modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum What {
    Entry,
    Prefix,
}

#[derive(Default)]
pub(crate) struct NdPanel {
    pub(crate) list: Value,
    pub(crate) prefixes: Vec<Value>,
    pub(crate) tab: Tab,
    table: TableState,
    port_table: TableState,
    prefix_table: TableState,
    pub(crate) modal: Option<(What, Modal)>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn iface(name: &str) -> String {
    let shown = if name == "all" { "all interfaces" } else { name };
    cell("", &[(shown, Kind::Hashed(name_hue(name)))])
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

/// One `/ipv6 nd` entry, its state a chip per outcome.
fn entry_row(r: &Value) -> Row {
    let sending = arr(r, "advertising").len();
    let skipped = arr(r, "skipped").len();
    let warnings = arr(r, "warnings").len();
    let sending_text = format!("{sending} advertising");
    let skipped_text = format!("{skipped} skipped");
    let mut chips: Vec<(&str, Kind)> = Vec::new();
    if flag(r, "disabled") {
        chips.push(("disabled", Kind::Neutral));
    } else {
        chips.push((sending_text.as_str(), if sending > 0 { Kind::Green } else { Kind::Amber }));
        if skipped > 0 {
            chips.push((skipped_text.as_str(), Kind::Neutral));
        }
        if warnings > 0 {
            chips.push(("warning", Kind::Amber));
        }
    }
    let m = if flag(r, "managed_address_configuration") { "M" } else { "–" };
    let o = if flag(r, "other_configuration") { "O" } else { "–" };
    let lifetime = s(r, "ra_lifetime");
    let lifetime = if lifetime == "0s" { cell("0", &[("no gateway", Kind::Amber)]) } else { lifetime };
    let mtu = s(r, "mtu");
    Row {
        key: s(r, "id"),
        cells: vec![
            iface(&s(r, "interface")),
            s(r, "ra_interval"),
            lifetime,
            format!("{m} / {o}"),
            if mtu == "unspecified" { "–".into() } else { mtu },
            s(r, "hop_limit"),
            s(r, "ra_preference"),
            dns_cell(r),
            cell("", &chips),
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// `advertise_dns` with its own servers, or `auto`; `–` when off.
fn dns_cell(r: &Value) -> String {
    if !flag(r, "advertise_dns") {
        return "–".into();
    }
    let own: Vec<String> = arr(r, "dns").iter().map(value_text).collect();
    if own.is_empty() {
        cell("", &[("auto", Kind::Blue)])
    } else {
        own.join(", ")
    }
}

/// One interface the plan reaches.
fn port_row(r: &Value) -> Row {
    let state = s(r, "state");
    let kind = match state.as_str() {
        "sending" => Kind::Green,
        "failed" => Kind::Red,
        "skipped" => Kind::Neutral,
        _ => Kind::Amber,
    };
    let mut detail = [s(r, "reason"), s(r, "error"), s(r, "conflict")]
        .into_iter()
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>();
    detail.extend(arr(r, "warnings").iter().map(value_text));
    let conflict = !s(r, "conflict").is_empty();
    let state_cell = if conflict {
        cell("", &[(state.as_str(), kind), ("conflict", Kind::Amber)])
    } else {
        cell("", &[(state.as_str(), kind)])
    };
    let prefixes: Vec<String> = arr(r, "prefixes").iter().map(value_text).collect();
    Row {
        key: s(r, "interface"),
        cells: vec![
            iface(&s(r, "interface")),
            state_cell,
            if prefixes.is_empty() { "–".into() } else { prefixes.join(", ") },
            {
                let d: Vec<String> = arr(r, "rdnss").iter().map(value_text).collect();
                if d.is_empty() { "–".into() } else { d.join(", ") }
            },
            s(r, "ra_sent"),
            s(r, "rs_received"),
            detail.join("; "),
        ],
        dimmed: state == "skipped",
        section: false,
        tint: None,
    }
}

/// The key of a prefix row: the id of a static one, else prefix@interface.
fn prefix_key(r: &Value) -> String {
    let id = s(r, "id");
    if id.is_empty() {
        format!("{}@{}", s(r, "prefix"), s(r, "interface"))
    } else {
        id
    }
}

fn prefix_row(r: &Value) -> Row {
    let origin = s(r, "origin");
    let okind = match origin.as_str() {
        "static" => Kind::Neutral,
        "deprecated" => Kind::Amber,
        "dhcp-pd" => Kind::Green,
        _ => Kind::Blue,
    };
    let mut flags: Vec<(&str, Kind)> = Vec::new();
    if flag(r, "on_link") {
        flags.push(("L", Kind::Neutral));
    }
    if flag(r, "autonomous") {
        flags.push(("A", Kind::Neutral));
    }
    let mut origin_chips = vec![(origin.as_str(), okind)];
    if !flag(r, "advertised") && !flag(r, "disabled") {
        origin_chips.push(("not advertised", Kind::Amber));
    }
    Row {
        key: prefix_key(r),
        cells: vec![
            s(r, "prefix"),
            iface(&s(r, "interface")),
            s(r, "valid_lifetime"),
            s(r, "preferred_lifetime"),
            cell("", &flags),
            cell("", &origin_chips),
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled") || origin == "deprecated",
        section: false,
        tint: None,
    }
}

/// A prefix row as `Item`: only the static ones are configuration.
fn prefix_item(r: &Value) -> Item {
    Item {
        key: prefix_key(r),
        disabled: flag(r, "disabled"),
        fixed: s(r, "id").is_empty().then(|| match s(r, "origin").as_str() {
            "deprecated" => "a prefix that left the RA: it goes out with lifetimes 0 a few more times".to_owned(),
            "dhcp-pd" => "from the prefix DHCPv6-PD delegated (ip.address from_pool): its lifetimes follow the delegation".to_owned(),
            _ => "from a /64 address of the interface: add a static prefix to change or hide it".to_owned(),
        }),
    }
}

fn yes(b: bool) -> String {
    if b { "yes" } else { "no" }.to_owned()
}

fn entry_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in FIELDS {
        let t = match (f.input, f.param) {
            (Input::Check, _) => yes(flag(r, f.param)),
            (_, "dns" | "dnssl") => arr(r, f.param).iter().map(value_text).collect::<Vec<_>>().join(", "),
            _ => s(r, f.param),
        };
        v.insert(f.param, t);
    }
    v
}

fn prefix_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in PREFIX_FIELDS {
        let t = match f.input {
            Input::Check => yes(flag(r, f.param)),
            _ => s(r, f.param),
        };
        v.insert(f.param, t);
    }
    v
}

impl NdPanel {
    fn entries(&self) -> &[Value] {
        arr(&self.list, "entries")
    }

    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("ipv6-nd-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn column_help(&mut self, l: crate::i18n::Lang, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn open(&mut self, app: &mut CoreRouterUi, what: What, item: Option<(String, String)>, values: BTreeMap<&'static str, String>) {
        if let Some((_, m)) = &mut self.modal {
            m.status.bring_to_front();
        } else {
            self.modal = Some((what, Modal::open(app, item, values)));
        }
    }

    fn find(&self, what: What, k: &str) -> Option<Value> {
        match what {
            What::Entry => self.entries().iter().find(|r| s(r, "id") == k).cloned(),
            What::Prefix => self.prefixes.iter().find(|r| prefix_key(r) == k).cloned(),
        }
    }

    /// Opens row `k` in its modal; a dynamic prefix opens a new static one
    /// filled in with it (the way to change or hide it).
    fn edit_one(&mut self, app: &mut CoreRouterUi, what: What, k: &str) {
        let Some(r) = self.find(what, k) else { return };
        if what == What::Prefix && s(&r, "id").is_empty() {
            let mut v = prefix_values(&r);
            v.insert("disabled", "no".to_owned());
            self.open(app, what, None, v);
            return;
        }
        let (label, values) = match what {
            What::Entry => (s(&r, "interface"), entry_values(&r)),
            What::Prefix => (s(&r, "prefix"), prefix_values(&r)),
        };
        self.open(app, what, Some((k.to_owned(), label)), values);
    }

    fn act(&mut self, app: &mut CoreRouterUi, what: What, act: Act, ui: &Ui, rows: &[Row]) {
        let (cmds, enable, disable) = match what {
            What::Entry => (CMDS, "ipv6.nd.enable", "ipv6.nd.disable"),
            What::Prefix => (PREFIX_CMDS, "ipv6.nd.prefix.enable", "ipv6.nd.prefix.disable"),
        };
        match act {
            Act::Add => {
                let mut v = BTreeMap::new();
                match what {
                    What::Entry => {
                        v.insert("ra_preference", "medium".to_owned());
                        v.insert("advertise_mac_address", "yes".to_owned());
                    }
                    What::Prefix => {
                        v.insert("on_link", "yes".to_owned());
                        v.insert("autonomous", "yes".to_owned());
                    }
                }
                self.open(app, what, None, v);
            }
            Act::Edit(k) => self.edit_one(app, what, &k),
            Act::Comment(keys) => {
                if let Some(k) = keys.first() {
                    self.edit_one(app, what, k);
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                let command = if matches!(act, Act::Enable(_)) { enable } else { disable };
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": command, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let params: &[&str] = match what {
                    What::Entry => &["interface", "ra_interval", "ra_delay", "ra_lifetime", "ra_preference", "hop_limit", "mtu", "reachable_time", "retransmit_interval", "managed_address_configuration", "other_configuration", "advertise_mac_address", "advertise_dns", "dns", "dnssl", "disabled", "comment"],
                    What::Prefix => &["prefix", "interface", "valid_lifetime", "preferred_lifetime", "on_link", "autonomous", "disabled", "comment"],
                };
                let picked: Vec<Value> = keys
                    .iter()
                    .filter_map(|k| self.find(what, k))
                    .map(|r| {
                        let mut p = serde_json::Map::new();
                        for k in params {
                            if let Some(v) = r.get(*k).filter(|v| !v.is_null()) {
                                p.insert((*k).into(), v.clone());
                            }
                        }
                        Value::Object(p)
                    })
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    fn interfaces_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let entries = self.entries().to_vec();
        let rows: Vec<Row> = entries.iter().map(entry_row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<Item> = entries
            .iter()
            .filter(|r| selection.contains(&s(r, "id")))
            .map(|r| Item::of(r, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            let running = s(&self.list, "sender") == "running";
            let (t, tone) = if running {
                ("sender running", chip::GREEN.tone(&v))
            } else {
                ("sender stopped (virtual lab)", chip::neutral_tone(&v))
            };
            chip::chip(ui, tr_in(SCOPE, l, t), tone);
            self.info(ui, l, "ipv6_nd.sender", "Sender");
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        // The entries take what they need (a few rows), the interfaces
        // reached the rest.
        let row_h = ui.spacing().interact_size.y + 2.0;
        let want = row_h * (rows.len().max(2) as f32 + 1.5);
        let below = (ui.available_height() - want).max(ui.available_height() * 0.45);
        let out = table::show(ui, TABLE, below, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New ND Interface…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        if entries.is_empty() {
            ui.weak(tr_in(
                SCOPE,
                l,
                "No Router Advertisements yet: + adds an interface (or all, which leaves the WAN, PPPoE server ports and prefix-less interfaces out).",
            ));
        }
        // Every interface the entries reach, sending or not, and why.
        let ports = arr(&self.list, "interfaces").to_vec();
        let prow: Vec<Row> = ports.iter().map(port_row).collect();
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Interfaces reached"));
            self.info(ui, l, "ipv6_nd.ports", "Interfaces reached");
        });
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let pout = table::show(ui, PORTS, footer_h, &mut self.port_table, &PORT_COLUMNS, &prow, |_, _| {});
        self.column_help(l, pout.help, &PORT_COLUMNS);
        let sent: u64 = ports.iter().filter_map(|r| r.get("ra_sent").and_then(Value::as_u64)).sum();
        let rs: u64 = ports.iter().filter_map(|r| r.get("rs_received").and_then(Value::as_u64)).sum();
        list::footer(
            ui,
            &[
                (entries.len(), "entries", chip::neutral_tone(&v)),
                (list::count(&ports, "state", "sending"), "sending", chip::GREEN.tone(&v)),
                (list::count(&ports, "state", "waiting"), "waiting", chip::AMBER.tone(&v)),
                (list::count(&ports, "state", "skipped"), "skipped", chip::neutral_tone(&v)),
                (list::count(&ports, "state", "failed"), "failed", chip::RED.tone(&v)),
                (usize::try_from(sent).unwrap_or(0), "RAs sent", chip::BLUE.tone(&v)),
                (usize::try_from(rs).unwrap_or(0), "RSs answered", chip::BLUE.tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, What::Entry, a, ui, &rows);
        }
    }

    fn prefixes_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let data = self.prefixes.clone();
        let rows: Vec<Row> = data.iter().map(prefix_row).collect();
        let selection = self.prefix_table.selection(&rows);
        let picked: Vec<Item> = data.iter().filter(|r| selection.contains(&prefix_key(r))).map(prefix_item).collect();
        let tools = Tools::new(&app.can(), &PREFIX_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, PREFIXES, &tools, &selection, l);
            table::find_field(ui, PREFIXES, &mut self.prefix_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, PREFIXES, footer_h, &mut self.prefix_table, &PREFIX_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New ND Prefix…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &PREFIX_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        list::footer(
            ui,
            &[
                (data.len(), "prefixes", chip::neutral_tone(&v)),
                (list::count(&data, "origin", "address"), "from addresses", chip::BLUE.tone(&v)),
                (list::count(&data, "origin", "dhcp-pd"), "from DHCPv6-PD", chip::GREEN.tone(&v)),
                (list::count(&data, "origin", "static"), "static", chip::neutral_tone(&v)),
                (list::count(&data, "origin", "deprecated"), "deprecated", chip::AMBER.tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, What::Prefix, a, ui, &rows);
        }
    }

    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, what: What, act: Act, ui: &Ui) {
        self.act(app, what, act, ui, &[]);
    }

    /// Every explanation key the window uses (the catalog test).
    #[cfg(test)]
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = COLUMNS
            .iter()
            .chain(&PORT_COLUMNS)
            .chain(&PREFIX_COLUMNS)
            .map(|c| c.help)
            .filter(|k| !k.is_empty())
            .collect();
        out.extend(FIELDS.iter().chain(PREFIX_FIELDS).map(|f| f.help).filter(|k| !k.is_empty()));
        out.extend([SPEC.help, PREFIX_SPEC.help, "ipv6_nd.sender", "ipv6_nd.ports", "ipv6_nd.tab_interfaces", "ipv6_nd.tab_prefixes"]);
        out.sort_unstable();
        out.dedup();
        out
    }
}

impl PanelState for NdPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        [("list", "ipv6.nd.list"), ("prefixes", "ipv6.nd.prefix.list")]
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
            "list" => self.list = value,
            "prefixes" => self.prefixes = value.as_array().cloned().unwrap_or_default(),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, key) in [
                (Tab::Interfaces, "Interfaces", "ipv6_nd.tab_interfaces"),
                (Tab::Prefixes, "Prefixes", "ipv6_nd.tab_prefixes"),
            ] {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                }
                self.info(ui, l, key, label);
            }
        });
        ui.separator();
        match self.tab {
            Tab::Interfaces => self.interfaces_tab(app, ui),
            Tab::Prefixes => self.prefixes_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some((what, m)) = &mut self.modal {
            let mut names = app.interface_names(None);
            let spec = match what {
                What::Entry => {
                    names.insert(0, "all".to_owned());
                    &SPEC
                }
                What::Prefix => &PREFIX_SPEC,
            };
            let open = m.show(app, ctx, area, spec, &|p| match p {
                "interface" => names.clone(),
                "ra_preference" => vec!["low".into(), "medium".into(), "high".into()],
                _ => Vec::new(),
            });
            if !open {
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
            Tab::Interfaces => self.table.escape(),
            Tab::Prefixes => self.prefix_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (PORTS, &self.port_table), (PREFIXES, &self.prefix_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (TABLE, &mut self.table),
            (PORTS, &mut self.port_table),
            (PREFIXES, &mut self.prefix_table),
        ]
    }
}

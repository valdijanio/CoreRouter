//! Interfaces › WireGuard (G1.31a), the approved mockup's option A: a
//! window like WinBox's, with the tabs Interfaces and Peers in the list
//! pattern of G0.24 (`docs/ui-style.md`).
//!
//! - **Interfaces:** state, name, port, MTU, the public key (copied from
//!   the right-click menu), the peers and how many are up.
//! - **Peers:** the handshake state the engine works out (`up`, `idle`,
//!   `no-handshake`, `never`, `disabled`; `PeerState`), when the last one
//!   was, where the peer is (`roamed` when it moved), its prefixes and
//!   traffic; filters by interface and state; under the table, the hint
//!   for the selected peer ("no answer: check the public keys …").
//! - The modals take their checks from `interface.wireguard.preview` and
//!   `interface.wireguard.peers.preview` (port, input firewall, MTU, a
//!   prefix another peer has, a route loop to the endpoint) and show the
//!   commands OK sends.
//!
//! A WireGuard interface is an interface: it is in Interfaces too, with
//! its addresses, routes and firewall where those are. This window only
//! shows and sends; the engine decides.

use std::collections::BTreeMap;

use egui::{Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Filters, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "wireguard";
pub(crate) const WIN: &str = "wireguard";
const SCOPE: &str = "wireguard";
const IFACES: &str = "wireguard-interfaces";
const PEERS: &str = "wireguard-peers";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Interfaces",
        title: "WireGuard",
        size: [1120.0, 480.0],
        escape: true,
    }],
    new: || Box::<WireguardPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Interfaces,
    Peers,
}

const TABS: [(Tab, &str, &str); 2] = [
    (Tab::Interfaces, "Interfaces", "wireguard.tab.interfaces"),
    (Tab::Peers, "Peers", "wireguard.tab.peers"),
];

const IF_CMDS: Cmds = Cmds {
    add: "interface.wireguard.add",
    remove: "interface.wireguard.remove",
    set: Some("interface.wireguard.set"),
    what: "interfaces",
};

const PEER_CMDS: Cmds = Cmds {
    add: "interface.wireguard.peers.add",
    remove: "interface.wireguard.peers.remove",
    set: Some("interface.wireguard.peers.set"),
    what: "peers",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input, edit: bool) -> Field {
    Field { param, label, help, input, edit }
}

const IF_FIELDS: &[Field] = &[
    field("name", "Name", "wireguard.name", Input::Text("wireguard1 (empty: the first free)"), false),
    field("listen_port", "Listen Port", "wireguard.listen_port", Input::Text("13231 (empty: the first free)"), true),
    field("mtu", "MTU", "wireguard.mtu", Input::Text("1420"), true),
    field("private_key", "Private Key", "wireguard.private_key", Input::Secret("empty: made on the router, or kept"), true),
    field("disabled", "Disabled", "wireguard.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

const PEER_FIELDS: &[Field] = &[
    field("name", "Name", "wireguard.peer.name", Input::Text("peer1 (empty: the first free)"), true),
    field("interface", "Interface", "wireguard.peer.interface", Input::Choice, false),
    field("public_key", "Public Key", "wireguard.peer.public_key", Input::Text("the peer's key (empty: made here)"), true),
    field("preshared_key", "Preshared Key", "wireguard.peer.preshared_key", Input::Check, true),
    field("allowed_address", "Allowed Address", "wireguard.peer.allowed_address", Input::Text("10.9.0.2/32, fd00::2/128"), true),
    field("endpoint_address", "Endpoint", "wireguard.peer.endpoint_address", Input::Text("empty: waits for the peer"), true),
    field("endpoint_port", "Endpoint Port", "wireguard.peer.endpoint_port", Input::Text("13231"), true),
    field("persistent_keepalive", "Persistent Keepalive", "wireguard.peer.persistent_keepalive", Input::Text("25 s behind NAT (empty: off)"), true),
    field("responder", "Responder", "wireguard.peer.responder", Input::Check, true),
    field("disabled", "Disabled", "wireguard.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

const IF_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New WireGuard Interface",
    edit_title: "WireGuard Interface",
    help: "wireguard.interface",
    fields: IF_FIELDS,
    preview: "interface.wireguard.preview",
};

const PEER_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New WireGuard Peer",
    edit_title: "WireGuard Peer",
    help: "wireguard.peer",
    fields: PEER_FIELDS,
    preview: "interface.wireguard.peers.preview",
};

const IF_COLUMNS: [table::Column; 7] = [
    col("State").help("wireguard.state"),
    col("Name").help("wireguard.name"),
    num("Listen Port").help("wireguard.listen_port"),
    num("MTU").help("wireguard.mtu"),
    col("Public Key").help("wireguard.public_key"),
    col("Peers").help("wireguard.peers"),
    comment(),
];

const PEER_COLUMNS: [table::Column; 10] = [
    col("State").help("wireguard.peer.state"),
    col("Name").help("wireguard.peer.name"),
    col("Interface").help("wireguard.peer.interface"),
    col("Last Handshake").help("wireguard.peer.last_handshake"),
    col("Endpoint").help("wireguard.peer.endpoint_address"),
    col("Allowed Address").help("wireguard.peer.allowed_address"),
    num("Rx").help("wireguard.peer.rx"),
    num("Tx").help("wireguard.peer.tx"),
    col("Public Key").help("wireguard.peer.public_key"),
    comment(),
];

/// The peer states, in the order of the filters and the footer.
const STATES: [(&str, Kind); 5] = [
    ("up", Kind::Green),
    ("idle", Kind::Neutral),
    ("no-handshake", Kind::Red),
    ("never", Kind::Neutral),
    ("disabled", Kind::Neutral),
];

/// A question before a key change: every peer must get the new public key.
pub(crate) struct Confirm {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) peers: u64,
    status: Status,
}

struct Done(u64);

#[derive(Default)]
pub(crate) struct WireguardPanel {
    pub(crate) tab: Tab,
    pub(crate) interfaces: Vec<Value>,
    pub(crate) peers: Vec<Value>,
    pub(crate) filters: Filters,
    if_table: TableState,
    pub(crate) peer_table: TableState,
    pub(crate) if_modal: Option<Modal>,
    pub(crate) peer_modal: Option<Modal>,
    pub(crate) confirm: Option<Confirm>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn yes(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool) == Some(true)
}

fn n(r: &Value, k: &str) -> u64 {
    r.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn hashed(name: &str) -> Kind {
    Kind::Hashed(chip::name_hue(name))
}

/// `Hk3x…9xQ=`: enough to tell keys apart in a table.
fn short_key(k: &str) -> String {
    let head: String = k.chars().take(4).collect();
    let tail: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    if k.chars().count() <= 8 { k.to_owned() } else { format!("{head}…{tail}") }
}

fn list_text(r: &Value, k: &str) -> String {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_text).collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| s(r, k))
}

/// The state of an interface row: disabled, error (the push failed),
/// running, or not running (not committed yet, or the backend has none).
fn if_state(r: &Value) -> (&'static str, Kind) {
    if yes(r, "disabled") {
        ("disabled", Kind::Neutral)
    } else if !s(r, "error").is_empty() {
        ("error", Kind::Red)
    } else if yes(r, "running") {
        ("running", Kind::Green)
    } else {
        ("not running", Kind::Amber)
    }
}

pub(crate) fn if_row(r: &Value) -> Row {
    let name = s(r, "name");
    let (state, kind) = if_state(r);
    let peers = n(r, "peers");
    let up = n(r, "peers_up");
    let up_chip = format!("{up} up");
    let peers_cell = if peers == 0 {
        String::new()
    } else {
        let tone = if up == 0 { Kind::Neutral } else { Kind::Green };
        cell(&peers.to_string(), &[(up_chip.as_str(), tone)])
    };
    Row {
        key: name.clone(),
        cells: vec![
            cell("", &[(state, kind)]),
            cell("", &[(name.as_str(), hashed(&name))]),
            s(r, "listen_port"),
            s(r, "mtu"),
            short_key(&s(r, "public_key")),
            peers_cell,
            s(r, "comment"),
        ],
        dimmed: yes(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// When the last handshake was: "41 s ago", "never".
fn handshake(r: &Value) -> String {
    match r.get("last_handshake_secs").and_then(Value::as_u64) {
        Some(0..3) => "now".to_owned(),
        Some(secs) => format!("{} ago", crate::firewall::ago(secs)),
        None if s(r, "state") == "disabled" => String::new(),
        None => "never".to_owned(),
    }
}

/// Where the peer is: where its packets come from now (roaming), else the
/// configured endpoint, else nothing (it calls in).
fn endpoint(r: &Value) -> String {
    let at = |a: &str, p: &str| {
        let (a, p) = (s(r, a), s(r, p));
        match (a.is_empty(), a.contains(':')) {
            (true, _) => String::new(),
            (false, true) => format!("[{a}]:{p}"),
            (false, false) => format!("{a}:{p}"),
        }
    };
    let now = at("current_endpoint_address", "current_endpoint_port");
    let conf = at("endpoint_address", "endpoint_port");
    if yes(r, "roamed") {
        cell(&now, &[("roamed", Kind::Blue)])
    } else if !now.is_empty() {
        now
    } else {
        conf
    }
}

fn state_kind(state: &str) -> Kind {
    STATES.iter().find(|(s, _)| *s == state).map_or(Kind::Neutral, |(_, k)| *k)
}

pub(crate) fn peer_row(r: &Value) -> Row {
    let name = s(r, "name");
    let iface = s(r, "interface");
    let state = s(r, "state");
    let mut states: Vec<(&str, Kind)> = vec![(state.as_str(), state_kind(&state))];
    if yes(r, "responder") {
        states.push(("responder", Kind::Blue));
    }
    Row {
        key: name.clone(),
        cells: vec![
            cell("", &states),
            cell("", &[(name.as_str(), hashed(&name))]),
            cell("", &[(iface.as_str(), hashed(&iface))]),
            handshake(r),
            endpoint(r),
            list_text(r, "allowed_address"),
            crate::ppp::bytes(n(r, "rx")),
            crate::ppp::bytes(n(r, "tx")),
            short_key(&s(r, "public_key")),
            s(r, "comment"),
        ],
        dimmed: yes(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// The modal's fields for an interface row.
fn if_values(r: &Value) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("name", s(r, "name")),
        ("listen_port", s(r, "listen_port")),
        ("mtu", s(r, "mtu")),
        ("private_key", String::new()),
        ("disabled", if yes(r, "disabled") { "yes" } else { "no" }.to_owned()),
        ("comment", s(r, "comment")),
    ])
}

/// The modal's fields for a peer row.
fn peer_values(r: &Value) -> BTreeMap<&'static str, String> {
    let flag = |b: bool| if b { "yes" } else { "no" }.to_owned();
    let keepalive = n(r, "persistent_keepalive");
    BTreeMap::from([
        ("name", s(r, "name")),
        ("interface", s(r, "interface")),
        ("public_key", s(r, "public_key")),
        ("preshared_key", flag(!s(r, "preshared_key").is_empty())),
        ("allowed_address", list_text(r, "allowed_address")),
        ("endpoint_address", s(r, "endpoint_address")),
        ("endpoint_port", s(r, "endpoint_port")),
        ("persistent_keepalive", if keepalive == 0 { String::new() } else { keepalive.to_string() }),
        ("responder", flag(yes(r, "responder"))),
        ("disabled", flag(yes(r, "disabled"))),
        ("comment", s(r, "comment")),
    ])
}

/// What `add` takes of a row, to copy it as a command (never a key but
/// the peer's public one).
fn add_params(r: &Value, peer: bool) -> Value {
    let keys: &[&str] = if peer {
        &["interface", "name", "public_key", "allowed_address", "endpoint_address", "endpoint_port", "persistent_keepalive", "responder", "disabled", "comment"]
    } else {
        &["name", "listen_port", "mtu", "disabled", "comment"]
    };
    let mut p = serde_json::Map::new();
    for k in keys {
        match r.get(*k) {
            None | Some(Value::Null) => {}
            Some(Value::Bool(false)) => {}
            Some(Value::String(t)) if t.is_empty() => {}
            Some(Value::Number(x)) if *k == "persistent_keepalive" && x.as_u64() == Some(0) => {}
            Some(v) => {
                p.insert((*k).into(), v.clone());
            }
        }
    }
    Value::Object(p)
}

impl WireguardPanel {
    fn info(&mut self, ui: &mut Ui, l: Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("wireguard-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                self.info(ui, l, key, label);
                ui.add_space(6.0);
            }
        });
    }

    fn column_help(&mut self, l: Lang, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn interfaces_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows: Vec<Row> = self.interfaces.iter().map(if_row).collect();
        let selection = self.if_table.selection(&rows);
        let picked: Vec<Item> = self
            .interfaces
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &IF_CMDS, &picked);
        let mut act = None;
        let mut extra: Option<Extra> = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, IFACES, &tools, &selection, l);
            table::find_field(ui, IFACES, &mut self.if_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 12.0;
        self.if_table.empty = tr_in(
            SCOPE,
            l,
            "No WireGuard interface. + adds one: the router makes its key pair; then give it an address (IP › Addresses) and add its peers.",
        )
        .to_owned();
        let add_peer = app.can().check(PEER_CMDS.add);
        let set = app.can().check("interface.wireguard.set");
        let out = table::show(ui, IFACES, footer_h, &mut self.if_table, &IF_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let [one] = sel.as_slice() {
                    if ui.button(tr_in(SCOPE, l, "Copy Public Key")).clicked() {
                        extra = Some(Extra::CopyKey(one.clone()));
                        ui.close();
                    }
                    if table::action(ui, tr_in(SCOPE, l, "Add Peer…"), add_peer.clone()) {
                        extra = Some(Extra::AddPeer(one.clone()));
                    }
                    if table::action(ui, tr_in(SCOPE, l, "Regenerate Keys…"), set.clone()) {
                        extra = Some(Extra::NewKeys(one.clone()));
                    }
                    ui.separator();
                }
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New WireGuard Interface…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &IF_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let all = &self.interfaces;
        let total_peers: u64 = all.iter().map(|r| n(r, "peers")).sum();
        let up: u64 = all.iter().map(|r| n(r, "peers_up")).sum();
        let count = |f: &dyn Fn(&Value) -> bool| all.iter().filter(|r| f(r)).count();
        list::footer(
            ui,
            &[
                (all.len(), "interfaces", chip::neutral_tone(&v)),
                (count(&|r| if_state(r).0 == "running"), "running", chip::GREEN.tone(&v)),
                (count(&|r| if_state(r).0 == "error"), "error", chip::RED.tone(&v)),
                (count(&|r| yes(r, "disabled")), "disabled", chip::neutral_tone(&v)),
                (usize::try_from(total_peers).unwrap_or(usize::MAX), "peers", chip::neutral_tone(&v)),
                (usize::try_from(up).unwrap_or(usize::MAX), "up", chip::GREEN.tone(&v)),
            ],
            l,
        );
        // The push error of the selected interface (the state chip says
        // "error"; the why is here).
        if let Some(r) = selection.first().and_then(|k| all.iter().find(|r| s(r, "name") == *k))
            && !s(r, "error").is_empty()
        {
            ui.colored_label(v.error_fg_color, format!("{}: {}", s(r, "name"), s(r, "error")));
        }
        if let Some(e) = extra {
            self.extra(app, ui, e);
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows, false);
        }
    }

    fn peers_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.peers.clone();
        let shown: Vec<&Value> = all.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| peer_row(r)).collect();
        let selection = self.peer_table.selection(&rows);
        let picked: Vec<Item> = shown
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &PEER_CMDS, &picked);
        let mut act = None;
        let mut extra: Option<Extra> = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, PEERS, &tools, &selection, l);
            ui.separator();
            // The interfaces, then the states seen (or switched on).
            let names: Vec<String> = self.interfaces.iter().map(|r| s(r, "name")).collect();
            for name in &names {
                if list::filter_chip(ui, name, self.filters.is_on("interface", name)) {
                    self.filters.toggle("interface", name);
                }
            }
            ui.separator();
            for (st, _) in STATES {
                if (list::count(&all, "state", st) > 0 || self.filters.is_on("state", st))
                    && list::filter_chip(ui, tr_in(SCOPE, l, st), self.filters.is_on("state", st))
                {
                    self.filters.toggle("state", st);
                }
            }
            table::find_field(ui, PEERS, &mut self.peer_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 3.0 + 16.0;
        self.peer_table.empty = if self.interfaces.is_empty() {
            tr_in(SCOPE, l, "No WireGuard interface yet: add one in the Interfaces tab first.")
        } else {
            tr_in(SCOPE, l, "No peers. + adds one: paste the peer's public key, or leave it empty and the router makes the pair (for the client config).")
        }
        .to_owned();
        let out = table::show(ui, PEERS, footer_h, &mut self.peer_table, &PEER_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let [one] = sel.as_slice() {
                    if ui.button(tr_in(SCOPE, l, "Copy Public Key")).clicked() {
                        extra = Some(Extra::CopyPeerKey(one.clone()));
                        ui.close();
                    }
                    ui.separator();
                }
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New WireGuard Peer…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(l, out.help, &PEER_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let tone = |k: Kind| k.tone(&v);
        let mut counts = vec![(all.len(), "peers", chip::neutral_tone(&v))];
        counts.extend(STATES.iter().map(|(st, k)| (list::count(&all, "state", st), *st, tone(*k))));
        counts.push((all.iter().filter(|r| yes(r, "roamed")).count(), "roamed", chip::BLUE.tone(&v)));
        list::footer(ui, &counts, l);
        // The selected peer: why it is in that state.
        if let [one] = selection.as_slice()
            && let Some(r) = all.iter().find(|r| s(r, "name") == *one)
        {
            let hint = s(r, "hint");
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, one, chip::palette_tone(&v, chip::name_hue(one)));
                if hint.is_empty() {
                    ui.weak(format!("{} · {}", s(r, "state"), handshake(r)));
                } else {
                    ui.label(hint);
                }
            });
        }
        if let Some(e) = extra {
            self.extra(app, ui, e);
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows, true);
        }
    }

    fn extra(&mut self, app: &mut CoreRouterUi, ui: &Ui, e: Extra) {
        match e {
            Extra::CopyKey(k) => {
                if let Some(r) = self.interfaces.iter().find(|r| s(r, "name") == k) {
                    ui.ctx().copy_text(s(r, "public_key"));
                }
            }
            Extra::CopyPeerKey(k) => {
                if let Some(r) = self.peers.iter().find(|r| s(r, "name") == k) {
                    ui.ctx().copy_text(s(r, "public_key"));
                }
            }
            Extra::AddPeer(iface) => {
                if self.peer_modal.is_none() {
                    self.tab = Tab::Peers;
                    self.peer_modal = Some(Modal::open(app, None, new_peer_values(&iface)));
                }
            }
            Extra::NewKeys(name) => {
                if self.confirm.is_none() {
                    let peers = self.interfaces.iter().find(|r| s(r, "name") == name).map_or(0, |r| n(r, "peers"));
                    app.next_dialog = app.next_dialog.wrapping_add(1);
                    self.confirm = Some(Confirm { id: app.next_dialog, name, peers, status: Status::default() });
                }
            }
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], peer: bool) {
        let (data, cmds) = if peer { (&self.peers, &PEER_CMDS) } else { (&self.interfaces, &IF_CMDS) };
        let row_of = |k: &str| data.iter().find(|r| s(r, "name") == k).cloned();
        let values = |r: &Value| if peer { peer_values(r) } else { if_values(r) };
        // A new peer goes on the interface the filter shows alone, else on
        // the selected peer's, else on the first one.
        let names: Vec<String> = self.interfaces.iter().map(|r| s(r, "name")).collect();
        let filtered: Vec<&String> = names.iter().filter(|n| self.filters.is_on("interface", n)).collect();
        let selected = self
            .peers
            .iter()
            .find(|r| self.peer_table.is_selected(&s(r, "name")))
            .map(|r| s(r, "interface"));
        let first_iface = match filtered.as_slice() {
            [one] => (*one).clone(),
            _ => selected.or_else(|| names.first().cloned()).unwrap_or_default(),
        };
        let modal = if peer { &mut self.peer_modal } else { &mut self.if_modal };
        match act {
            Act::Add => {
                if modal.is_none() {
                    let v = if peer { new_peer_values(&first_iface) } else { BTreeMap::from([("disabled", "no".to_owned())]) };
                    *modal = Some(Modal::open(app, None, v));
                }
            }
            Act::Edit(k) => {
                if let Some(m) = modal {
                    m.status.bring_to_front();
                } else if let Some(r) = row_of(&k) {
                    *modal = Some(Modal::open(app, Some((k.clone(), k)), values(&r)));
                }
            }
            Act::Comment(keys) => {
                if let (Some(k), None) = (keys.into_iter().next(), modal.as_ref())
                    && let Some(r) = row_of(&k)
                {
                    *modal = Some(Modal::open(app, Some((k.clone(), k)), values(&r)));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"name": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                let to = matches!(act, Act::Disable(_));
                let set = cmds.set.unwrap_or_default();
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": set, "params": {"name": k, "disabled": to}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| row_of(k)).map(|r| add_params(&r, peer)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    fn confirm_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut c) = self.confirm.take() else { return };
        let wid = dialog_id(c.id);
        let l = app.lang.labels;
        let title = format!("{} <{}>", tr_in(SCOPE, l, "Regenerate Keys"), c.name);
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: false,
            pos: cascade(area, c.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let can = app.can();
        let message = tr_in(SCOPE, l, "The router makes a new key pair for this interface. Every peer must then get the new public key, and every tunnel handshakes again.");
        let peers = c.peers;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut c.status, |ui, _| {
            ui.set_max_width(420.0);
            ui.label(message);
            if peers > 0 {
                chip::chip(ui, &format!("{peers} {}", tr_in(SCOPE, l, "peers")), chip::AMBER.tone(ui.visuals()));
            }
            Footer::<()>::edit(false, can.check("interface.wireguard.set"))
        });
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                c.status.close_on_success = true;
                c.status.sent();
                app.run_then(
                    "interface.wireguard.set",
                    json!({"name": c.name, "private_key": "auto"}),
                    crate::panel::then(NAME, Done(c.id)),
                );
            }
            _ => {}
        }
        self.confirm = Some(c);
    }
}

/// What the right-click menu asked for, besides the list's own actions.
enum Extra {
    CopyKey(String),
    CopyPeerKey(String),
    AddPeer(String),
    NewKeys(String),
}

/// A new peer's fields on interface `iface`.
fn new_peer_values(iface: &str) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("interface", iface.to_owned()),
        ("preshared_key", "no".to_owned()),
        ("responder", "no".to_owned()),
        ("disabled", "no".to_owned()),
    ])
}

impl PanelState for WireguardPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        // The interfaces always (the peers' filter chips and modal list
        // them); the peers only on their tab: each listing reads the data
        // plane once per interface.
        let mut q = vec![("interfaces", "interface.wireguard.list")];
        if self.tab == Tab::Peers || self.peer_modal.is_some() {
            q.push(("peers", "interface.wireguard.peers.list"));
        }
        q.into_iter()
            .filter(|(_, c)| app.has_command(c))
            .map(|(key, command)| Query { key, command, params: json!({}) })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let arr = |v: &Value| v.as_array().cloned().unwrap_or_default();
        match key {
            list_modal::PREVIEW => {
                for m in [&mut self.if_modal, &mut self.peer_modal].into_iter().flatten() {
                    m.arrived(value.clone());
                }
            }
            "interfaces" => self.interfaces = arr(&value),
            "peers" => self.peers = arr(&value),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Interfaces => self.interfaces_tab(app, ui),
            Tab::Peers => self.peers_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.if_modal
            && !m.show(app, ctx, area, &IF_SPEC, &|_| Vec::new())
        {
            self.if_modal = None;
        }
        let names: Vec<String> = self.interfaces.iter().map(|r| s(r, "name")).collect();
        let options = move |p: &str| -> Vec<String> { if p == "interface" { names.clone() } else { Vec::new() } };
        if let Some(m) = &mut self.peer_modal
            && !m.show(app, ctx, area, &PEER_SPEC, &options)
        {
            self.peer_modal = None;
        }
        self.confirm_dialog(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(d) = then.downcast_ref::<Done>()
            && let Some(c) = self.confirm.as_mut().filter(|c| c.id == d.0)
            && c.status.replied(result)
        {
            app.floats.forget(dialog_id(c.id));
            self.confirm = None;
        }
        if let Some(a) = then.downcast_ref::<Applied>() {
            for slot in [&mut self.if_modal, &mut self.peer_modal] {
                if slot.as_mut().is_some_and(|m| m.id == a.0 && m.replied(app, result)) {
                    *slot = None;
                }
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Interfaces => self.if_table.escape(),
            Tab::Peers => self.peer_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(IFACES, &self.if_table), (PEERS, &self.peer_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(IFACES, &mut self.if_table), (PEERS, &mut self.peer_table)]
    }
}

#[cfg(test)]
impl WireguardPanel {
    /// Every explanation key the window uses (the test checks both languages).
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut k: Vec<&'static str> = vec!["menu.wireguard", IF_SPEC.help, PEER_SPEC.help];
        k.extend(TABS.iter().map(|t| t.2));
        k.extend(IF_FIELDS.iter().chain(PEER_FIELDS).map(|f| f.help).filter(|h| !h.is_empty()));
        k.extend(IF_COLUMNS.iter().chain(&PEER_COLUMNS).map(|c| c.help).filter(|h| !h.is_empty()));
        k
    }

    /// Tests: act as the bar or the menu would.
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, ui: &Ui, peer: bool) {
        let rows: Vec<Row> = if peer { self.peers.iter().map(peer_row).collect() } else { self.interfaces.iter().map(if_row).collect() };
        self.act(app, a, ui, &rows, peer);
    }

    /// Tests: the right-click "Regenerate Keys…" / "Add Peer…".
    pub(crate) fn new_keys_for_test(&mut self, app: &mut CoreRouterUi, ui: &Ui, name: &str) {
        self.extra(app, ui, Extra::NewKeys(name.to_owned()));
    }

    pub(crate) fn add_peer_for_test(&mut self, app: &mut CoreRouterUi, ui: &Ui, iface: &str) {
        self.extra(app, ui, Extra::AddPeer(iface.to_owned()));
    }
}

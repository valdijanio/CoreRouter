//! Routing › BFD (G3.6c): CoreRouter's own BFD (G3.6a) in three tabs.
//!
//! - **Sessions:** one row per session with who uses it (selos "BGP
//!   upstream-a", "OSPF ether1", "peer x"), its state (up, down, init,
//!   dampened, inactive), the timers in force, the detection time, the
//!   engine's transmit jitter p99 and the flaps of the last 24 h; the
//!   toolbar adds and removes explicit peers and puts BFD on BGP and OSPF
//!   with one click (`routing.bfd.attach`); the footer says how the engine
//!   runs (threads, CPU, steering).
//! - **Profiles:** the timers, dampening and auth BGP, OSPF and the peers
//!   share, in the list window pattern (G0.24) with the engine's preview.
//! - **History:** the state changes, newest first, with the diagnostic.
//!
//! `routing.bfd.*` decides; this only shows and sends.

use std::collections::BTreeMap;

use egui::{Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "bfd";
pub(crate) const WIN: &str = "bfd";
const SCOPE: &str = "bfd";
const SESSIONS: &str = "bfd-sessions";
const PROFILES: &str = "bfd-profiles";
const HISTORY: &str = "bfd-history";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Routing",
        title: "BFD",
        size: [1040.0, 560.0],
        escape: true,
    }],
    new: || Box::<BfdPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Sessions,
    Profiles,
    History,
}

const TABS: [(Tab, &str, &str); 3] = [
    (Tab::Sessions, "Sessions", "bfd.tab.sessions"),
    (Tab::Profiles, "Profiles", "bfd.tab.profiles"),
    (Tab::History, "History", "bfd.tab.history"),
];

/// Which list a modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum What {
    Peer,
    Profile,
}

const PEER_CMDS: Cmds = Cmds {
    add: "routing.bfd.peer.add",
    remove: "routing.bfd.peer.remove",
    set: Some("routing.bfd.peer.set"),
    what: "peers",
};

const PROFILE_CMDS: Cmds = Cmds {
    add: "routing.bfd.profile.add",
    remove: "routing.bfd.profile.remove",
    set: None,
    what: "profiles",
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

const PEER_FIELDS: &[Field] = &[
    field("address", "Address", "bfd.peer.address", Input::Text("192.0.2.2")),
    field("name", "Name", "bfd.peer.name", Input::Text("the address")),
    field("profile", "Profile", "bfd.peer.profile", Input::Choice),
    field("multihop", "Multihop", "bfd.peer.multihop", Input::Check),
    field("local_address", "Local Address", "bfd.peer.local_address", Input::Text("the route's source")),
    field("interface", "Interface", "bfd.peer.interface", Input::Text("any")),
    field("disabled", "Disabled", "bfd.peer.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const PROFILE_FIELDS: &[Field] = &[
    Field {
        param: "name",
        label: "Name",
        help: "bfd.profile.name",
        input: Input::Text("wan"),
        edit: false,
    },
    field("min_tx", "Min TX (ms)", "bfd.profile.min_tx", Input::Text("300")),
    field("min_rx", "Min RX (ms)", "bfd.profile.min_rx", Input::Text("300")),
    field("multiplier", "Multiplier", "bfd.profile.multiplier", Input::Text("3")),
    field("dampening", "Dampening", "bfd.profile.dampening", Input::Check),
    field("passive", "Passive", "bfd.profile.passive", Input::Check),
    field("auth", "Authentication", "bfd.profile.auth", Input::Choice),
    field("auth_key_id", "Key ID", "bfd.profile.auth_key_id", Input::Text("0")),
    field("auth_secret", "Key", "bfd.profile.auth_secret", Input::Secret("1..20 bytes, the same on both sides")),
    field("min_ttl", "Min TTL (multihop)", "bfd.profile.min_ttl", Input::Text("254")),
    field("comment", "Comment", "", Input::Text("")),
];

const PEER_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New BFD Peer",
    edit_title: "BFD Peer",
    help: "bfd.peer",
    fields: PEER_FIELDS,
    preview: "routing.bfd.peer.preview",
};

const PROFILE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New BFD Profile",
    edit_title: "BFD Profile",
    help: "bfd.profile",
    fields: PROFILE_FIELDS,
    preview: "routing.bfd.profile.preview",
};

const SESSION_COLUMNS: [table::Column; 7] = [
    col("Peer").help("bfd.session.peer"),
    col("Used by").help("bfd.session.users"),
    col("State").help("bfd.session.state"),
    num("Tx/Rx").help("bfd.session.txrx"),
    num("Detect Time").help("bfd.session.detect"),
    num("Jitter p99").help("bfd.session.jitter"),
    num("Flaps 24h").help("bfd.session.flaps"),
];

const PROFILE_COLUMNS: [table::Column; 8] = [
    col("Name").help("bfd.profile.name"),
    num("Min TX").help("bfd.profile.min_tx"),
    num("Min RX").help("bfd.profile.min_rx"),
    num("Multiplier").help("bfd.profile.multiplier"),
    num("Detect Time").help("bfd.profile.detect"),
    col("Options").help("bfd.profile.options"),
    col("Used by").help("bfd.profile.used_by"),
    comment(),
];

const HISTORY_COLUMNS: [table::Column; 6] = [
    col("Time").help("bfd.history.time"),
    col("Peer").help("bfd.session.peer"),
    col("Change").help("bfd.history.change"),
    col("Diagnostic").help("bfd.history.diag"),
    num("Detect Time").help("bfd.session.detect"),
    col("Used by").help("bfd.session.users"),
];

#[derive(Default)]
pub(crate) struct BfdPanel {
    pub(crate) tab: Tab,
    pub(crate) sessions: Value,
    pub(crate) profiles: Vec<Value>,
    pub(crate) peers: Vec<Value>,
    pub(crate) history: Vec<Value>,
    session_table: TableState,
    profile_table: TableState,
    history_table: TableState,
    pub(crate) modal: Option<(What, Modal)>,
    help: Option<HelpView>,
    /// What the last attach did ("BFD on 2 BGP connections").
    pub(crate) notice: Option<String>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn u(r: &Value, k: &str) -> Option<u64> {
    r.get(k).and_then(Value::as_u64)
}

fn strings(r: &Value, k: &str) -> Vec<String> {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Milliseconds from µs, short: `50 ms`, `0.07 ms`.
fn ms(us: u64) -> String {
    if us >= 10_000 || us.is_multiple_of(1000) {
        format!("{} ms", us / 1000)
    } else {
        format!("{:.2} ms", us as f64 / 1000.0)
    }
}

fn state_kind(state: &str) -> Kind {
    match state {
        "up" => Kind::Green,
        "down" => Kind::Red,
        "dampened" | "init" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

/// A user's chip: "BGP upstream-a", "OSPF ether1", "peer x", coloured by
/// the whole name (the same user, the same colour everywhere).
fn user_chips(users: &[String]) -> Vec<(&str, Kind)> {
    users.iter().map(|x| (x.as_str(), Kind::Hashed(chip::name_hue(x)))).collect()
}

/// The state shown: dampened over up (the clients see it down).
pub(crate) fn shown_state(r: &Value) -> String {
    if r.get("dampened").and_then(Value::as_bool) == Some(true) {
        "dampened".into()
    } else {
        s(r, "state")
    }
}

fn session_key(r: &Value) -> String {
    format!("{}{}", s(r, "peer"), if r.get("multihop").and_then(Value::as_bool) == Some(true) { "/mh" } else { "" })
}

fn session_row(r: &Value) -> Row {
    let state = shown_state(r);
    let mh = r.get("multihop").and_then(Value::as_bool) == Some(true);
    let peer = cell(&s(r, "peer"), if mh { &[("multihop", Kind::Blue)] } else { &[] });
    let users = strings(r, "users");
    // Before the peer spoke, its Min RX is the RFC's initial 1 µs: "–".
    let txrx = match (u(r, "tx_interval_us"), u(r, "remote_min_rx_us")) {
        (Some(t), Some(rx)) if state != "inactive" && rx > 1 => format!("{} / {}", ms(t), ms(rx)),
        (Some(t), _) if state != "inactive" => format!("{} / –", ms(t)),
        _ => "–".into(),
    };
    let detect = u(r, "detect_time_us").filter(|d| *d > 0).map_or_else(|| "–".into(), ms);
    let jitter = u(r, "tx_jitter_p99_us").map_or_else(|| "–".into(), ms);
    let flaps = u(r, "flaps_24h").map_or_else(|| "–".into(), |f| f.to_string());
    Row {
        key: session_key(r),
        cells: vec![
            peer,
            cell("", &user_chips(&users)),
            cell("", &[(state.as_str(), state_kind(&state))]),
            txrx,
            detect,
            jitter,
            flaps,
        ],
        dimmed: state == "inactive" || state == "admin-down",
        section: false,
        tint: None,
    }
}

fn profile_row(r: &Value) -> Row {
    let builtin = r.get("builtin").and_then(Value::as_bool) == Some(true);
    let flag = |k: &str| r.get(k).and_then(Value::as_bool) == Some(true);
    let mut opts: Vec<(&str, Kind)> = Vec::new();
    if flag("dampening") {
        opts.push(("dampening", Kind::Green));
    }
    if flag("passive") {
        opts.push(("passive", Kind::Neutral));
    }
    let auth = s(r, "auth");
    if auth != "none" && !auth.is_empty() {
        opts.push(("sha1", Kind::Blue));
    }
    let users = strings(r, "used_by");
    Row {
        key: s(r, "name"),
        cells: vec![
            cell(&s(r, "name"), if builtin { &[("built-in", Kind::Neutral)] } else { &[] }),
            format!("{} ms", s(r, "min_tx")),
            format!("{} ms", s(r, "min_rx")),
            s(r, "multiplier"),
            format!("{} ms", s(r, "detect_ms")),
            cell("", &opts),
            cell("", &user_chips(&users)),
            s(r, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn history_row(i: usize, r: &Value, today: u64) -> Row {
    let at = u(r, "at_ms").unwrap_or(0) / 1000;
    let (from, to) = (s(r, "from"), s(r, "to"));
    let to_shown = if to == "up" && r.get("dampened").and_then(Value::as_bool) == Some(true) { "dampened".to_owned() } else { to.clone() };
    let users = strings(r, "users");
    Row {
        key: format!("{i}"),
        cells: vec![
            crate::system_log::short_time(at, today),
            s(r, "peer"),
            cell("", &[(from.as_str(), state_kind(&from)), ("»", Kind::Neutral), (to_shown.as_str(), state_kind(&to_shown))]),
            s(r, "diag"),
            u(r, "detect_time_us").filter(|d| *d > 0).map_or_else(|| "–".into(), ms),
            cell("", &user_chips(&users)),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn peer_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in PEER_FIELDS {
        let text = match f.param {
            "disabled" | "multihop" => {
                if r.get(f.param).and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned()
            }
            p => s(r, p),
        };
        v.insert(f.param, text);
    }
    v
}

fn profile_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::new();
    for f in PROFILE_FIELDS {
        let text = match f.param {
            "dampening" | "passive" => {
                if r.get(f.param).and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned()
            }
            // Write-only: empty keeps the key.
            "auth_secret" => String::new(),
            p => s(r, p),
        };
        v.insert(f.param, text);
    }
    v
}

/// A command's reply the window reports.
struct Attached;

impl BfdPanel {
    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("bfd-help", key)), tr_in(SCOPE, l, title)).clicked() {
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

    fn column_help(&mut self, app: &CoreRouterUi, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, app.lang.labels, title)));
        }
    }

    fn session_rows(&self) -> Vec<Value> {
        self.sessions.get("sessions").and_then(Value::as_array).cloned().unwrap_or_default()
    }

    /// The explicit peer behind a session row, if it is one.
    fn peer_of(&self, key: &str) -> Option<&Value> {
        self.peers.iter().find(|p| {
            let mh = p.get("multihop").and_then(Value::as_bool) == Some(true);
            format!("{}{}", s(p, "address"), if mh { "/mh" } else { "" }) == key
        })
    }

    fn sessions_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let data = self.session_rows();
        let rows: Vec<Row> = data.iter().map(session_row).collect();
        let selection = self.session_table.selection(&rows);
        // Only explicit peers are removed here; a BGP/OSPF session goes with
        // its protocol's bfd setting.
        let picked: Vec<Item> = selection
            .iter()
            .map(|k| match self.peer_of(k) {
                Some(p) => Item::of(p, "name", ""),
                None => Item {
                    key: k.clone(),
                    disabled: false,
                    fixed: Some("asked for by BGP or OSPF: turn it off in the protocol (bfd profile)".into()),
                },
            })
            .collect();
        let tools = Tools::new(&app.can(), &PEER_CMDS, &picked);
        let mut act = None;
        let mut attach = false;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, SESSIONS, &tools, &selection, l);
            ui.separator();
            if table::action(ui, tr_in(SCOPE, l, "Use BFD Everywhere"), app.can().check("routing.bfd.attach")) {
                attach = true;
            }
            self.info(ui, l, "bfd.attach", "Use BFD Everywhere");
            table::find_field(ui, SESSIONS, &mut self.session_table);
        });
        if let Some(n) = &self.notice {
            ui.weak(n.as_str());
        }
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 14.0;
        let out = table::show(ui, SESSIONS, footer_h, &mut self.session_table, &SESSION_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Peer…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(app, out.help, &SESSION_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.map(Act::Edit));
        let v = ui.visuals().clone();
        let count = |st: &str| data.iter().filter(|r| shown_state(r) == st).count();
        list::footer(
            ui,
            &[
                (data.len(), "sessions", chip::neutral_tone(&v)),
                (count("up"), "up", chip::GREEN.tone(&v)),
                (count("down") + count("init"), "down", chip::RED.tone(&v)),
                (count("dampened"), "dampened", chip::AMBER.tone(&v)),
                (count("inactive"), "inactive", chip::neutral_tone(&v)),
            ],
            l,
        );
        self.engine_line(ui, l);
        if data.is_empty() {
            ui.weak(tr_in(
                SCOPE,
                l,
                "No BFD session: + adds a peer; Use BFD Everywhere puts the default profile on every BGP connection and OSPF interface.",
            ));
        }
        if attach {
            app.run_then("routing.bfd.attach", json!({}), crate::panel::then(NAME, Attached));
        }
        if let Some(a) = act {
            self.act(app, What::Peer, a, ui, &rows);
        }
    }

    /// How the engine runs: threads, their CPU, how packets reach them.
    fn engine_line(&mut self, ui: &mut Ui, l: crate::i18n::Lang) {
        let running = self.sessions.get("running").and_then(Value::as_bool) == Some(true);
        let v = ui.visuals().clone();
        ui.horizontal_wrapped(|ui| {
            if !running {
                chip::chip(ui, tr_in(SCOPE, l, "engine idle"), chip::neutral_tone(&v));
                ui.weak(tr_in(SCOPE, l, "The daemon starts the engine with the first session (none in a GUI without daemon)."));
            } else {
                let threads = self.sessions.get("threads").and_then(Value::as_array).cloned().unwrap_or_default();
                chip::chip(ui, &format!("{} {}", threads.len(), tr_in(SCOPE, l, "threads")), chip::BLUE.tone(&v));
                for t in &threads {
                    let cpu = t.get("cpu_percent").and_then(Value::as_f64).unwrap_or(0.0);
                    let tip = format!("{} sessions, {} in / {} out", s(t, "sessions"), s(t, "packets_in"), s(t, "packets_out"));
                    chip::chip(ui, &format!("bfd-{} {cpu:.1} %", s(t, "index")), chip::neutral_tone(&v)).on_hover_text(tip);
                }
                let steering = s(&self.sessions, "steering");
                if !steering.is_empty() {
                    ui.weak(steering);
                }
            }
            self.info(ui, l, "bfd.engine", "Engine");
        });
    }

    fn profiles_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows: Vec<Row> = self.profiles.iter().map(profile_row).collect();
        let selection = self.profile_table.selection(&rows);
        let picked: Vec<Item> = self
            .profiles
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &PROFILE_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, PROFILES, &tools, &selection, l);
            table::find_field(ui, PROFILES, &mut self.profile_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 10.0;
        let out = table::show(ui, PROFILES, footer_h, &mut self.profile_table, &PROFILE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Profile…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(app, out.help, &PROFILE_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.profiles.len(), "profiles", chip::neutral_tone(&v)),
                (list::count(&self.profiles, "dampening", "true"), "with dampening", chip::GREEN.tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, What::Profile, a, ui, &rows);
        }
    }

    fn history_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        // As the log: "today" is the newest event's day.
        let today = self.history.iter().filter_map(|r| u(r, "at_ms")).max().unwrap_or(0) / 1000 / 86_400;
        let rows: Vec<Row> = self.history.iter().enumerate().map(|(i, r)| history_row(i, r, today)).collect();
        ui.horizontal(|ui| {
            table::find_field(ui, HISTORY, &mut self.history_table);
        });
        ui.separator();
        let footer_h = ui.spacing().interact_size.y + 10.0;
        let out = table::show(ui, HISTORY, footer_h, &mut self.history_table, &HISTORY_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &HISTORY_COLUMNS);
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.history.len(), "changes", chip::neutral_tone(&v)),
                (list::count(&self.history, "to", "down"), "down", chip::RED.tone(&v)),
            ],
            l,
        );
        if self.history.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No state change yet."));
        }
    }

    fn open(&mut self, app: &mut CoreRouterUi, what: What, key: Option<String>) {
        if let Some((_, m)) = &mut self.modal {
            m.status.bring_to_front();
            return;
        }
        let modal = match (what, key) {
            (What::Peer, None) => {
                let mut v = BTreeMap::new();
                v.insert("profile", "default".to_owned());
                v.insert("multihop", "no".to_owned());
                v.insert("disabled", "no".to_owned());
                Modal::open(app, None, v)
            }
            (What::Profile, None) => {
                let mut v = BTreeMap::new();
                for (k, x) in [("min_tx", "300"), ("min_rx", "300"), ("multiplier", "3"), ("dampening", "yes"), ("passive", "no"), ("auth", "none"), ("min_ttl", "254")] {
                    v.insert(k, x.to_owned());
                }
                Modal::open(app, None, v)
            }
            (What::Peer, Some(k)) => {
                let Some(r) = self.peer_of(&k).or_else(|| self.peers.iter().find(|p| s(p, "name") == k)).cloned() else {
                    return;
                };
                let name = s(&r, "name");
                Modal::open(app, Some((name.clone(), name)), peer_values(&r))
            }
            (What::Profile, Some(k)) => {
                let Some(r) = self.profiles.iter().find(|p| s(p, "name") == k).cloned() else {
                    return;
                };
                Modal::open(app, Some((k.clone(), k)), profile_values(&r))
            }
        };
        self.modal = Some((what, modal));
    }

    fn act(&mut self, app: &mut CoreRouterUi, what: What, act: Act, ui: &Ui, rows: &[Row]) {
        let cmds = if what == What::Peer { &PEER_CMDS } else { &PROFILE_CMDS };
        // A session row's key is its address; the peer's id is its name.
        let id_of = |k: &str| match what {
            What::Peer => self.peer_of(k).map_or_else(|| k.to_owned(), |p| s(p, "name")),
            What::Profile => k.to_owned(),
        };
        match act {
            Act::Add => self.open(app, what, None),
            Act::Edit(k) => {
                if what == What::Profile || self.peer_of(&k).is_some() {
                    self.open(app, what, Some(k));
                }
            }
            Act::Comment(keys) => {
                if let Some(k) = keys.into_iter().next() {
                    self.open(app, what, Some(k));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": id_of(k)}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                if what == What::Peer {
                    let to = matches!(act, Act::Disable(_));
                    let steps: Vec<Value> = keys
                        .iter()
                        .map(|k| json!({"command": "routing.bfd.peer.set", "params": {"id": id_of(k), "disabled": to}}))
                        .collect();
                    app.run_steps(steps, Then::Nothing);
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let fields: &[&str] = match what {
                    What::Peer => &["name", "address", "local_address", "interface", "multihop", "profile", "disabled", "comment"],
                    What::Profile => &["name", "min_tx", "min_rx", "multiplier", "passive", "dampening", "half_life", "suppress", "reuse", "max_suppress", "auth", "auth_key_id", "min_ttl", "comment"],
                };
                let source: Vec<Value> = match what {
                    What::Peer => keys.iter().filter_map(|k| self.peer_of(k).cloned()).collect(),
                    What::Profile => self.profiles.iter().filter(|p| keys.contains(&s(p, "name"))).cloned().collect(),
                };
                let picked: Vec<Value> = source
                    .iter()
                    .map(|r| {
                        let mut p = json!({});
                        if let Some(o) = p.as_object_mut() {
                            for k in fields {
                                if let Some(v) = r.get(*k).filter(|v| !v.is_null()) {
                                    o.insert((*k).into(), v.clone());
                                }
                            }
                        }
                        p
                    })
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    /// Every explanation key the window uses (the catalog test).
    #[cfg(test)]
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = TABS.iter().map(|(_, _, k)| *k).collect();
        out.extend(SESSION_COLUMNS.iter().chain(&PROFILE_COLUMNS).chain(&HISTORY_COLUMNS).map(|c| c.help));
        out.extend(PEER_FIELDS.iter().chain(PROFILE_FIELDS).map(|f| f.help));
        out.extend([PEER_SPEC.help, PROFILE_SPEC.help, "bfd.attach", "bfd.engine", "menu.bfd"]);
        out.retain(|k| !k.is_empty());
        out.sort_unstable();
        out.dedup();
        out
    }

    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, what: What, a: Act, ui: &Ui) {
        self.act(app, what, a, ui, &[]);
    }
}

impl PanelState for BfdPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut q = vec![("sessions", "routing.bfd.session.list"), ("peers", "routing.bfd.peer.list"), ("profiles", "routing.bfd.profile.list")];
        if self.tab == Tab::History {
            q.push(("history", "routing.bfd.history.list"));
        }
        q.into_iter()
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
            "sessions" => self.sessions = value,
            "peers" => self.peers = value.as_array().cloned().unwrap_or_default(),
            "profiles" => self.profiles = value.as_array().cloned().unwrap_or_default(),
            "history" => self.history = value.as_array().cloned().unwrap_or_default(),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Sessions => self.sessions_tab(app, ui),
            Tab::Profiles => self.profiles_tab(app, ui),
            Tab::History => self.history_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let profiles: Vec<String> = self.profiles.iter().map(|p| s(p, "name")).collect();
        if let Some((what, m)) = &mut self.modal {
            let (spec, open) = match what {
                What::Peer => (&PEER_SPEC, m.show(app, ctx, area, &PEER_SPEC, &|p| if p == "profile" { profiles.clone() } else { Vec::new() })),
                What::Profile => (
                    &PROFILE_SPEC,
                    m.show(app, ctx, area, &PROFILE_SPEC, &|p| {
                        if p == "auth" {
                            ["none", "keyed-sha1", "meticulous-keyed-sha1"].iter().map(|x| (*x).to_owned()).collect()
                        } else {
                            Vec::new()
                        }
                    }),
                ),
            };
            let _ = spec;
            if !open {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Attached>().is_some() {
            self.notice = Some(match result {
                Ok(v) => {
                    let n = |k: &str| v.get(k).and_then(Value::as_array).map_or(0, Vec::len);
                    format!("BFD ({}) on {} BGP connections and {} OSPF templates", s(v, "profile"), n("bgp"), n("ospf"))
                }
                Err(e) => e.clone(),
            });
            app.cache.refreshed_at = None;
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
            Tab::Sessions => self.session_table.escape(),
            Tab::Profiles => self.profile_table.escape(),
            Tab::History => self.history_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(SESSIONS, &self.session_table), (PROFILES, &self.profile_table), (HISTORY, &self.history_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(SESSIONS, &mut self.session_table), (PROFILES, &mut self.profile_table), (HISTORY, &mut self.history_table)]
    }
}

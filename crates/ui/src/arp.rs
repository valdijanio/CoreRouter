//! IP › ARP (G1.27d): the neighbor tables, with the tabs ARP (IPv4), ND
//! (IPv6) and Settings; IPv6 › Neighbors opens the same window on ND.
//! A list window of the G0.24 pattern (`docs/ui-style.md`): the bar of
//! static entries (add, remove, enable, disable, comment) plus Make Static, ARP Ping and Flush;
//! state chips that filter with a click (the counts are the whole
//! table's, from the engine); interface chips by key; the subscriber
//! chip for the host name (DHCP lease, PTR of own zones: G0.25); a page
//! of 500 asked from the engine (`ip.arp.list`), the detail of the
//! selected neighbor under the table (`ip.arp.detail`) and a footer with
//! the kernel table against its ceiling (`gc_thresh3`).
//!
//! The engine decides everything; this only shows and sends.

use std::collections::{BTreeMap, BTreeSet};

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "arp";
pub(crate) const WIN: &str = "arp";
/// IPv6 › Neighbors: the same window, on the ND tab.
pub(crate) const WIN6: &str = "ipv6-neighbors";
const SCOPE: &str = "arp";
const TABLE: &str = "arp";
const TABLE6: &str = "arp-nd";
const SETTINGS_TABLE: &str = "arp-settings";
const TABLE6W: &str = "ipv6-neighbors";
/// Rows asked per page.
const PAGE: u32 = 500;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[
        WinDef {
            id: WIN,
            group: "IP",
            title: "ARP",
            size: [1040.0, 600.0],
            escape: true,
        },
        WinDef {
            id: WIN6,
            group: "IPv6",
            title: "Neighbors",
            size: [1040.0, 600.0],
            escape: true,
        },
    ],
    new: || Box::new(ArpPanel::default()),
};

const CMDS: Cmds = Cmds {
    add: "ip.arp.add",
    remove: "ip.arp.remove",
    set: Some("ip.arp.set"),
    what: "static ARP entries",
};

const LEARNED: &str = "Learned from the network: Make Static first to keep, change or remove it \
     (Flush forgets learned entries)";

const FIELDS: &[Field] = &[
    Field {
        param: "address",
        label: "Address",
        help: "arp.address",
        input: Input::Text("192.168.88.10"),
        edit: true,
    },
    Field {
        param: "mac_address",
        label: "MAC Address",
        help: "arp.mac_address",
        input: Input::Text("00:11:22:33:44:55"),
        edit: true,
    },
    Field {
        param: "interface",
        label: "Interface",
        help: "arp.interface",
        input: Input::Choice,
        edit: true,
    },
    Field {
        param: "published",
        label: "Published",
        help: "arp.published",
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
    Field {
        param: "disabled",
        label: "Disabled",
        help: "arp.disabled",
        input: Input::Check,
        edit: true,
    },
];

pub(crate) const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New ARP Entry",
    edit_title: "ARP Entry",
    help: "arp.static",
    fields: FIELDS,
    preview: "ip.arp.check",
};

const COLUMNS: [table::Column; 8] = [
    col("Address").help("arp.address"),
    col("MAC Address").help("arp.mac_address"),
    col("Interface").help("arp.interface"),
    col("State").help("arp.state"),
    col("Source").help("arp.source"),
    col("Vendor").help("arp.vendor"),
    col("Last Seen").help("arp.last_seen"),
    comment(),
];

const SETTINGS_COLUMNS: [table::Column; 6] = [
    col("Interface").help("arp.interface"),
    col("ARP").help("arp.mode"),
    col("ARP Timeout").help("arp.timeout"),
    col("Entries").help("arp.entries"),
    col("Unresolved").help("arp.unresolved"),
    col("Static").help("arp.static_count"),
];

/// Every state, in the order the chips show.
const STATES: [&str; 8] = [
    "reachable",
    "stale",
    "delay",
    "probe",
    "incomplete",
    "failed",
    "permanent",
    "noarp",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Arp,
    Nd,
    Settings,
}

/// What one family's list asks and holds.
#[derive(Default)]
pub(crate) struct Listing {
    pub(crate) search: String,
    pub(crate) states: BTreeSet<String>,
    pub(crate) interface: Option<String>,
    pub(crate) offset: u32,
    pub(crate) page: Option<Value>,
    pub(crate) table: TableState,
}

impl Listing {
    fn params(&self) -> Value {
        let mut p = json!({"offset": self.offset, "limit": PAGE});
        if let Some(o) = p.as_object_mut() {
            if !self.search.trim().is_empty() {
                o.insert("search".into(), json!(self.search.trim()));
            }
            if !self.states.is_empty() {
                let s: Vec<&str> = self.states.iter().map(String::as_str).collect();
                o.insert("state".into(), json!(s.join(",")));
            }
            if let Some(i) = &self.interface {
                o.insert("interface".into(), json!(i));
            }
        }
        p
    }

    fn rows(&self) -> Vec<Value> {
        self.page
            .as_ref()
            .and_then(|p| p.get("rows"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}

/// A question before a risky action: the command, and why.
pub(crate) struct Confirm {
    pub(crate) id: u64,
    pub(crate) message: String,
    pub(crate) command: &'static str,
    pub(crate) params: Value,
    pub(crate) status: Status,
}

/// Add the selected neighbors to a firewall address list.
pub(crate) struct ToList {
    pub(crate) id: u64,
    pub(crate) addresses: Vec<String>,
    pub(crate) list: String,
    pub(crate) status: Status,
}

struct Done(u64);

#[derive(Default)]
pub(crate) struct ArpPanel {
    pub(crate) tab: Tab,
    pub(crate) v4: Listing,
    pub(crate) v6: Listing,
    /// IPv6 › Neighbors' own list (both windows can be open at once).
    pub(crate) v6w: Listing,
    /// The window being drawn now.
    cur: &'static str,
    pub(crate) settings: Option<Value>,
    settings_table: TableState,
    /// The settings being edited, by interface: (arp, timeout).
    pub(crate) edits: BTreeMap<String, (String, String)>,
    /// The neighbor whose detail shows: (address, interface).
    pub(crate) picked: Option<(String, String)>,
    pub(crate) detail: Option<Value>,
    pub(crate) modal: Option<Modal>,
    pub(crate) confirm: Option<Confirm>,
    pub(crate) to_list: Option<ToList>,
    /// The ARP ping task (G1.27d) and its last poll.
    pub(crate) ping: Option<u64>,
    pub(crate) ping_poll: Option<Value>,
    pub(crate) help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(crate::value_text).unwrap_or_default()
}

fn key_of(r: &Value) -> String {
    format!("{}|{}", s(r, "interface"), s(r, "address"))
}

/// The chip tone of a state (RFC 4861 §7.3.2).
pub(crate) fn state_kind(state: &str) -> Kind {
    match state {
        "reachable" => Kind::Green,
        "stale" | "delay" | "probe" => Kind::Neutral,
        "incomplete" => Kind::Amber,
        "failed" => Kind::Red,
        _ => Kind::Blue,
    }
}

/// The interface's chip colour: a hash of its name (docs/ui-style.md).
fn iface_kind(name: &str) -> Kind {
    Kind::Hashed(chip::name_hue(name))
}

/// "5s", "3m", "2h", "4d"; "–" when unknown.
fn ago(secs: Option<u64>) -> String {
    crate::routes::age(secs)
}

pub(crate) fn row(r: &Value) -> Row {
    let state = s(r, "state");
    let mut states: Vec<(&str, Kind)> = Vec::new();
    if s(r, "disabled") == "true" {
        states.push(("disabled", Kind::Neutral));
    } else if s(r, "invalid") == "true" {
        states.push(("invalid", Kind::Red));
    } else if !state.is_empty() {
        states.push((state.as_str(), state_kind(&state)));
    }
    if s(r, "router") == "true" {
        states.push(("router", Kind::Blue));
    }
    let source = s(r, "source");
    let source_kind = match source.as_str() {
        "static" => Kind::Blue,
        // DHCP add-arp: the lease put it there.
        "dhcp" => Kind::Green,
        _ => Kind::Neutral,
    };
    let mut source_chips = vec![(source.as_str(), source_kind)];
    if s(r, "published") == "true" {
        source_chips.push(("published", Kind::Amber));
    }
    let iface = s(r, "interface");
    let mac = s(r, "mac_address");
    let vendor = s(r, "vendor");
    Row {
        key: key_of(r),
        cells: vec![
            s(r, "address"),
            if mac.is_empty() { "–".into() } else { mac },
            cell("", &[(iface.as_str(), iface_kind(&iface))]),
            cell("", &states),
            cell("", &source_chips),
            if vendor.is_empty() { "–".into() } else { vendor },
            ago(r.get("last_seen_secs").and_then(Value::as_u64)),
            s(r, "comment"),
        ],
        dimmed: s(r, "disabled") == "true",
        section: false,
        tint: None,
    }
}

fn settings_row(r: &Value) -> Row {
    let mode = s(r, "arp");
    let kind = match mode.as_str() {
        "enabled" => Kind::Green,
        "disabled" => Kind::Red,
        _ => Kind::Amber,
    };
    let iface = s(r, "interface");
    let unresolved = r.get("unresolved").and_then(Value::as_u64).unwrap_or(0);
    let unresolved_cell = if unresolved > 0 {
        cell("", &[(unresolved.to_string().as_str(), Kind::Amber)])
    } else {
        "0".into()
    };
    Row {
        key: iface.clone(),
        cells: vec![
            cell("", &[(iface.as_str(), iface_kind(&iface))]),
            cell("", &[(mode.as_str(), kind)]),
            s(r, "arp_timeout"),
            s(r, "entries"),
            unresolved_cell,
            s(r, "static"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn open_window(app: &mut CoreRouterUi, win: Win) {
    if !app.open.insert(win) {
        app.floats.raise(crate::win_id(win));
    }
    app.cache.refreshed_at = None;
}

impl ArpPanel {
    fn listing(&mut self) -> &mut Listing {
        if self.cur == WIN6 {
            &mut self.v6w
        } else if self.tab == Tab::Nd {
            &mut self.v6
        } else {
            &mut self.v4
        }
    }

    /// The tab drawn in the current window.
    fn tab_now(&self) -> Tab {
        if self.cur == WIN6 { Tab::Nd } else { self.tab }
    }

    fn info(&mut self, ui: &mut Ui, key: &'static str, title: &str) {
        if help::info_button(ui, Id::unique(("arp-help", self.cur, key)), title).clicked() {
            self.help = Some(HelpView::new(key, title));
        }
    }

    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            for (tab, label, key) in [
                (Tab::Arp, "ARP (IPv4)", "arp.tab.arp"),
                (Tab::Nd, "ND (IPv6)", "arp.tab.nd"),
                (Tab::Settings, "Settings", "arp.tab.settings"),
            ] {
                let text = tr_in(SCOPE, l, label);
                if ui.selectable_label(self.tab == tab, text).clicked() && self.tab != tab {
                    self.tab = tab;
                    self.picked = None;
                    self.detail = None;
                    app.cache.refreshed_at = None;
                }
                self.info(ui, key, text);
            }
        });
        ui.separator();
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        let all = self.v4.rows();
        let by_key = |k: &str| all.iter().find(|r| key_of(r) == k).cloned();
        let ids = |keys: &[String]| -> Vec<String> {
            keys.iter()
                .filter_map(|k| by_key(k))
                .map(|r| s(&r, "id"))
                .filter(|id| !id.is_empty())
                .collect()
        };
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    self.modal = Some(Modal::open(app, None, BTreeMap::new()));
                }
            }
            Act::Edit(k) => {
                if let Some(m) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = by_key(&k).filter(|r| s(r, "source") == "static") {
                    let values = BTreeMap::from([
                        ("address", s(&r, "address")),
                        ("mac_address", s(&r, "mac_address")),
                        ("interface", s(&r, "interface")),
                        ("published", if s(&r, "published") == "true" { "yes" } else { "no" }.to_owned()),
                        ("disabled", if s(&r, "disabled") == "true" { "yes" } else { "no" }.to_owned()),
                        ("comment", s(&r, "comment")),
                    ]);
                    self.modal = Some(Modal::open(app, Some((s(&r, "id"), s(&r, "address"))), values));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = ids(&keys)
                    .into_iter()
                    .map(|id| json!({"command": "ip.arp.remove", "params": {"id": id}}))
                    .collect();
                app.run_steps(steps, crate::Then::Nothing);
            }
            Act::Enable(keys) => Self::set_disabled(app, &ids(&keys), false),
            Act::Disable(keys) => Self::set_disabled(app, &ids(&keys), true),
            Act::Comment(keys) => {
                if let Some(k) = keys.first() {
                    self.act(app, Act::Edit(k.clone()), ui, rows);
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| by_key(k)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &refs, syntax));
            }
        }
    }

    fn set_disabled(app: &mut CoreRouterUi, ids: &[String], off: bool) {
        let steps: Vec<Value> = ids
            .iter()
            .map(|id| json!({"command": "ip.arp.set", "params": {"id": id, "disabled": off}}))
            .collect();
        app.run_steps(steps, crate::Then::Nothing);
    }

    fn make_static(app: &mut CoreRouterUi, rows: &[Value]) {
        let steps: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({"command": "ip.arp.make-static",
                    "params": {"address": s(r, "address"), "interface": s(r, "interface")}})
            })
            .collect();
        app.run_steps(steps, crate::Then::Nothing);
    }

    fn arp_ping(&mut self, app: &mut CoreRouterUi, r: &Value) {
        app.run_then(
            "ip.arp.ping",
            json!({"address": s(r, "address"), "interface": s(r, "interface"), "count": 4, "interval_ms": 500}),
            crate::panel::then(NAME, PingStarted),
        );
        self.ping_poll = None;
    }

    fn list_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let v6 = self.tab_now() == Tab::Nd;
        let salt = if self.cur == WIN6 {
            TABLE6W
        } else if v6 {
            TABLE6
        } else {
            TABLE
        };
        let all = self.listing().rows();
        let mut rows: Vec<Row> = all.iter().map(row).collect();
        for (r, v) in rows.iter_mut().zip(&all) {
            crate::identity::add_chips(app, ui, "arp", r, 0, &s(v, "address"));
        }
        let selection = self.listing().table.selection(&rows);
        let chosen: Vec<Value> = all
            .iter()
            .filter(|r| selection.contains(&key_of(r)))
            .cloned()
            .collect();
        let picked: Vec<Item> = chosen
            .iter()
            .map(|r| Item {
                key: key_of(r),
                disabled: s(r, "disabled") == "true",
                fixed: (s(r, "source") != "static").then(|| LEARNED.to_owned()),
            })
            .collect();
        let can = app.can();
        let tools = Tools::new(&can, &CMDS, &picked);
        let learned: Vec<Value> = chosen
            .iter()
            .filter(|r| s(r, "source") == "dynamic" && !s(r, "mac_address").is_empty())
            .cloned()
            .collect();
        let mut act = None;
        let mut flush = false;
        let counts = self
            .listing()
            .page
            .as_ref()
            .and_then(|p| p.get("counts"))
            .cloned()
            .unwrap_or(Value::Null);
        ui.horizontal(|ui| {
            if !v6 {
                act = list::toolbar(ui, salt, &tools, &selection, l);
                let make = if learned.is_empty() {
                    Err(tr_in(SCOPE, l, "Select learned neighbors first").to_owned())
                } else {
                    Ok(())
                };
                if ui
                    .add_enabled(can.and("ip.arp.make-static", make.clone()).is_ok(), egui::Button::new(tr_in(SCOPE, l, "Make Static")))
                    .on_disabled_hover_text(make.err().unwrap_or_default())
                    .clicked()
                {
                    Self::make_static(app, &learned);
                }
                let one = chosen.len() == 1 && chosen.first().is_some_and(|r| !s(r, "address").contains(':'));
                if ui
                    .add_enabled(one && can.check("ip.arp.ping").is_ok(), egui::Button::new(tr_in(SCOPE, l, "ARP Ping")))
                    .on_disabled_hover_text(tr_in(SCOPE, l, "Select one IPv4 neighbor"))
                    .clicked()
                    && let Some(r) = chosen.first().cloned()
                {
                    self.arp_ping(app, &r);
                }
            }
            let fl = if v6 { "ipv6.neighbor.flush" } else { "ip.arp.flush" };
            if ui
                .add_enabled(can.check(fl).is_ok(), egui::Button::new(tr_in(SCOPE, l, "Flush")))
                .on_hover_text(tr_in(SCOPE, l, "Forget the learned entries (never the gateway in use nor your management neighbor)"))
                .clicked()
            {
                flush = true;
            }
            self.info(ui, "arp.flush", tr_in(SCOPE, l, "Flush"));
        });
        // The chips on a line of their own: they never push the search out.
        ui.horizontal_wrapped(|ui| {
            // State chips: the whole table's counts; a click filters.
            let st = counts.get("states").cloned().unwrap_or(Value::Null);
            for name in STATES {
                let n = st.get(name).and_then(Value::as_u64).unwrap_or(0);
                let on = self.listing().states.contains(name);
                if (n > 0 || on) && list::filter_chip(ui, &format!("{name} {n}"), on) {
                    let lst = self.listing();
                    if !lst.states.remove(name) {
                        lst.states.insert(name.to_owned());
                    }
                    lst.offset = 0;
                    app.cache.refreshed_at = None;
                }
            }
            let ifs = counts.get("interfaces").and_then(Value::as_object).cloned().unwrap_or_default();
            if ifs.len() > 1 || self.listing().interface.is_some() {
                ui.separator();
                for (name, n) in &ifs {
                    let on = self.listing().interface.as_deref() == Some(name.as_str());
                    if list::filter_chip(ui, &format!("{name} {}", n.as_u64().unwrap_or(0)), on) {
                        let lst = self.listing();
                        lst.interface = if on { None } else { Some(name.clone()) };
                        lst.offset = 0;
                        app.cache.refreshed_at = None;
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let cur = self.cur;
                let lst = self.listing();
                let edit = ui.add(
                    TextEdit::singleline(&mut lst.search)
                        .id(Id::unique(("arp-search", cur, v6)))
                        .hint_text(tr_in(SCOPE, l, "IP, CIDR, MAC prefix or text"))
                        .desired_width(220.0),
                );
                if edit.changed() {
                    lst.offset = 0;
                    app.cache.refreshed_at = None;
                }
            });
        });
        if flush && self.confirm.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let iface = self.listing().interface.clone();
            let mut params = json!({});
            if let (Some(i), Some(o)) = (&iface, params.as_object_mut()) {
                o.insert("interface".into(), json!(i));
            }
            self.confirm = Some(Confirm {
                id: app.next_dialog,
                message: format!(
                    "{} {}",
                    tr_in(SCOPE, l, "Forget the learned neighbors"),
                    iface.map(|i| format!("({i})")).unwrap_or_default()
                ),
                command: if v6 { "ipv6.neighbor.flush" } else { "ip.arp.flush" },
                params,
                status: Status::default(),
            });
        }
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let detail_h = if self.detail.is_some() { 150.0 } else { 0.0 };
        let footer_h = ui.spacing().interact_size.y + 8.0 + detail_h;
        let mut to_list: Option<Vec<String>> = None;
        let lst = self.listing();
        let out = table::show(ui, salt, footer_h, &mut lst.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if !v6 && let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
                if table::action(ui, tr_in(SCOPE, l, "Add to Address List…"), can.check("ip.firewall.address-list.add")) {
                    to_list = Some(sel.iter().filter_map(|k| k.split('|').nth(1)).map(str::to_owned).collect());
                }
            }
            Menu::Empty => {
                if !v6 && table::action(ui, tr_in(SCOPE, l, "New ARP Entry…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        crate::identity::table_chip(app, ui, "arp", &out, &rows, |k| k.split('|').nth(1).map(str::to_owned));
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if let Some(k) = out.clicked.or(out.opened.clone()) {
            let mut parts = k.splitn(2, '|');
            if let (Some(i), Some(a)) = (parts.next(), parts.next()) {
                let now = Some((a.to_owned(), i.to_owned()));
                if self.picked != now {
                    self.picked = now;
                    self.detail = None;
                    app.cache.refreshed_at = None;
                }
            }
        }
        if !v6 {
            act = act
                .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
                .or_else(|| out.opened.filter(|k| all.iter().any(|r| key_of(r) == *k && s(r, "source") == "static")).map(Act::Edit));
        }
        if let Some(addresses) = to_list.filter(|a| !a.is_empty()) {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            self.to_list = Some(ToList {
                id: app.next_dialog,
                addresses,
                list: String::new(),
                status: Status::default(),
            });
        }
        if self.detail.is_some() {
            self.detail_view(app, ui, l);
        }
        self.footer(app, ui, l);
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    fn footer(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(p) = self.listing().page.clone() else {
            ui.weak(tr_in(SCOPE, l, "Reading…"));
            return;
        };
        let v = ui.visuals().clone();
        let n = |k: &str| p.get(k).and_then(Value::as_u64).unwrap_or(0);
        let t = p.get("table").cloned().unwrap_or(Value::Null);
        let fam = if self.tab_now() == Tab::Nd { "ipv6" } else { "ipv4" };
        let used = t.get(fam).and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal_wrapped(|ui| {
            let (total, matched, offset) = (n("total"), n("matched"), n("offset"));
            chip::chip(ui, &format!("{total} {}", tr_in(SCOPE, l, "neighbors")), chip::neutral_tone(&v));
            if matched != total {
                chip::chip(ui, &format!("{matched} {}", tr_in(SCOPE, l, "match")), chip::BLUE.tone(&v));
            }
            let sources = p.pointer("/counts/sources").cloned().unwrap_or(Value::Null);
            for (k, tone) in [
                ("static", chip::BLUE.tone(&v)),
                ("dhcp", chip::GREEN.tone(&v)),
                ("dynamic", chip::neutral_tone(&v)),
            ] {
                if let Some(c) = sources.get(k).and_then(Value::as_u64) {
                    chip::chip(ui, &format!("{c} {}", tr_in(SCOPE, l, k)), tone);
                }
            }
            if let Some(t3) = t.get("gc_thresh3").and_then(Value::as_u64) {
                let near = t.get("near_full").and_then(Value::as_bool).unwrap_or(false);
                let tone = if near { chip::AMBER.tone(&v) } else { chip::neutral_tone(&v) };
                let text = format!("{} {used} / gc_thresh3 {t3}", tr_in(SCOPE, l, "kernel table"));
                let r = chip::chip(ui, &text, tone);
                let tip = match t.get("suggest").and_then(Value::as_array) {
                    Some(s3) if near => format!(
                        "{} gc_thresh1={} gc_thresh2={} gc_thresh3={} (System › Tuning)",
                        tr_in(SCOPE, l, "Nearly full: new hosts will be refused. Suggested:"),
                        s3.first().map(crate::value_text).unwrap_or_default(),
                        s3.get(1).map(crate::value_text).unwrap_or_default(),
                        s3.get(2).map(crate::value_text).unwrap_or_default(),
                    ),
                    _ => tr_in(SCOPE, l, "Entries the kernel holds and its ceiling").to_owned(),
                };
                r.on_hover_text(tip);
            }
            if t.get("lost").and_then(Value::as_u64).unwrap_or(0) > 0 {
                chip::chip(ui, tr_in(SCOPE, l, "events lost: read again"), chip::AMBER.tone(&v));
            }
            if matched > u64::from(PAGE) {
                ui.separator();
                let last = (offset + u64::from(PAGE)).min(matched);
                if ui.add_enabled(offset > 0, egui::Button::new("◀")).clicked() {
                    let lst = self.listing();
                    lst.offset = lst.offset.saturating_sub(PAGE);
                    app.cache.refreshed_at = None;
                }
                ui.label(format!("{}–{last} / {matched}", offset + 1));
                if ui.add_enabled(last < matched, egui::Button::new("▶")).clicked() {
                    let lst = self.listing();
                    lst.offset = lst.offset.saturating_add(PAGE);
                    app.cache.refreshed_at = None;
                }
            }
            if let Some(poll) = &self.ping_poll {
                ui.separator();
                let sm = poll.get("summary").cloned().unwrap_or(Value::Null);
                let got = sm.get("received").and_then(Value::as_u64).unwrap_or(0);
                let sent = sm.get("sent").and_then(Value::as_u64).unwrap_or(0);
                let tone = if got > 0 { chip::GREEN.tone(&v) } else { chip::RED.tone(&v) };
                let avg = sm.get("avg_rtt_ms").and_then(Value::as_f64).map(|a| format!(" {a:.3} ms")).unwrap_or_default();
                chip::chip(ui, &format!("ARP ping {got}/{sent}{avg}"), tone);
            }
        });
    }

    fn detail_view(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(d) = self.detail.clone() else { return };
        let r = d.get("row").cloned().unwrap_or(Value::Null);
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(format!("{}  {}", s(&r, "address"), s(&r, "mac_address")));
            self.info(ui, "arp.detail", tr_in(SCOPE, l, "Neighbor"));
            let can = app.can();
            let v4 = !s(&r, "address").contains(':');
            if v4
                && s(&r, "source") == "dynamic"
                && ui.add_enabled(can.check("ip.arp.make-static").is_ok(), egui::Button::new(tr_in(SCOPE, l, "Make Static"))).clicked()
            {
                Self::make_static(app, std::slice::from_ref(&r));
            }
            if ui.add_enabled(can.check("ip.firewall.address-list.add").is_ok(), egui::Button::new(tr_in(SCOPE, l, "Add to Address List…"))).clicked() {
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.to_list = Some(ToList {
                    id: app.next_dialog,
                    addresses: vec![s(&r, "address")],
                    list: String::new(),
                    status: Status::default(),
                });
            }
            if v4 && ui.add_enabled(can.check("ip.arp.ping").is_ok(), egui::Button::new(tr_in(SCOPE, l, "ARP Ping"))).clicked() {
                self.arp_ping(app, &r);
            }
            if ui.button(tr_in(SCOPE, l, "Ping")).clicked() {
                app.ping.form.address = s(&r, "address");
                open_window(app, Win::Ping);
            }
            if ui.button(tr_in(SCOPE, l, "Torch")).clicked() {
                let iface = s(&r, "interface");
                app.with_panel(crate::torch::PANEL.name, |p, _| {
                    if let Some(t) = (p as &mut dyn std::any::Any).downcast_mut::<crate::torch::TorchPanel>() {
                        t.interface = iface;
                    }
                });
                open_window(app, Win::Panel(crate::torch::WIN));
            }
        });
        Grid::new("arp-detail").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label(tr_in(SCOPE, l, "History"));
            let hist: Vec<String> = d
                .get("history")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|h| format!("{} ({} {})", s(h, "mac_address"), ago(h.get("ago_secs").and_then(Value::as_u64)), tr_in(SCOPE, l, "ago")))
                .collect();
            if hist.is_empty() {
                ui.weak(tr_in(SCOPE, l, "same MAC since the router started watching"));
            } else {
                ui.label(hist.join("  →  "));
            }
            ui.end_row();
            ui.label(tr_in(SCOPE, l, "Routes through it"));
            let routes: Vec<String> = d
                .get("routes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|r| format!("{} ({})", s(r, "dst_address"), s(r, "state")))
                .collect();
            if routes.is_empty() {
                ui.weak(tr_in(SCOPE, l, "none"));
            } else {
                ui.label(routes.join(", "));
            }
            ui.end_row();
            ui.label(tr_in(SCOPE, l, "Router address"));
            ui.label(d.get("subnet").filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_else(|| "–".into()));
            ui.end_row();
        });
    }

    fn settings_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(p) = self.settings.clone() else {
            ui.weak(tr_in(SCOPE, l, "Reading…"));
            return;
        };
        let ifaces = p.get("interfaces").and_then(Value::as_array).cloned().unwrap_or_default();
        let rows: Vec<Row> = ifaces.iter().map(settings_row).collect();
        let sel = self.settings_table.selection(&rows);
        let footer_h = 150.0;
        let out = table::show(ui, SETTINGS_TABLE, footer_h, &mut self.settings_table, &SETTINGS_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = SETTINGS_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        ui.separator();
        let can = app.can();
        if let Some(name) = sel.first().cloned()
            && let Some(r) = ifaces.iter().find(|r| s(r, "interface") == name)
        {
            let (mut mode, mut timeout) = self
                .edits
                .get(&name)
                .cloned()
                .unwrap_or_else(|| (s(r, "arp"), s(r, "arp_timeout")));
            let mut apply = false;
            ui.horizontal(|ui| {
                ui.strong(&name);
                ui.label(tr_in(SCOPE, l, "ARP"));
                ComboBox::from_id_salt("arp-mode")
                    .selected_text(mode.clone())
                    .show_ui(ui, |ui| {
                        for m in ["enabled", "disabled", "reply-only", "proxy-arp", "local-proxy-arp"] {
                            ui.selectable_value(&mut mode, m.to_owned(), m);
                        }
                    });
                self.info(ui, "arp.mode", "ARP");
                ui.label(tr_in(SCOPE, l, "ARP Timeout"));
                ui.add(TextEdit::singleline(&mut timeout).desired_width(70.0).hint_text("auto"));
                self.info(ui, "arp.timeout", tr_in(SCOPE, l, "ARP Timeout"));
                let changed = mode != s(r, "arp") || timeout != s(r, "arp_timeout");
                apply = ui
                    .add_enabled(changed && can.check("ip.arp.settings.set").is_ok(), egui::Button::new(tr_in(SCOPE, l, "Apply")))
                    .clicked();
            });
            if apply {
                let params = json!({"interface": name, "arp": mode, "arp_timeout": timeout.trim()});
                let risky = matches!(mode.as_str(), "disabled" | "reply-only" | "proxy-arp") && mode != s(r, "arp");
                if risky {
                    app.next_dialog = app.next_dialog.wrapping_add(1);
                    let why = match mode.as_str() {
                        "disabled" => "Hosts without a static entry stop being reachable.",
                        "reply-only" => "Only static entries (and DHCP add-arp) reach hosts: the others stop being reachable.",
                        _ => "The router answers ARP for addresses it routes elsewhere (RFC 1027), which can pull traffic of the whole segment.",
                    };
                    let mut params = params;
                    if let Some(o) = params.as_object_mut() {
                        o.insert("confirm".into(), json!(true));
                    }
                    self.confirm = Some(Confirm {
                        id: app.next_dialog,
                        message: format!("arp={mode} {name}: {}", tr_in(SCOPE, l, why)),
                        command: "ip.arp.settings.set",
                        params,
                        status: Status::default(),
                    });
                } else {
                    app.run("ip.arp.settings.set", params);
                }
                self.edits.remove(&name);
            } else {
                self.edits.insert(name, (mode, timeout));
            }
        } else {
            ui.weak(tr_in(SCOPE, l, "Pick an interface to change its ARP mode"));
        }
        ui.separator();
        let v = ui.visuals().clone();
        Grid::new("arp-kernel").num_columns(5).spacing([16.0, 4.0]).show(ui, |ui| {
            ui.strong(tr_in(SCOPE, l, "Kernel table"));
            for k in ["gc_thresh1", "gc_thresh2", "gc_thresh3", "entries"] {
                ui.label(k);
            }
            ui.end_row();
            for fam in ["ipv4", "ipv6"] {
                let k = p.pointer(&format!("/kernel/{fam}")).cloned().unwrap_or(Value::Null);
                ui.label(if fam == "ipv4" { "IPv4" } else { "IPv6" });
                for f in ["gc_thresh1", "gc_thresh2", "gc_thresh3", "entries"] {
                    ui.label(k.get(f).map(crate::value_text).unwrap_or_else(|| "–".into()));
                }
                if k.get("near_full").and_then(Value::as_bool).unwrap_or(false) {
                    chip::chip(ui, tr_in(SCOPE, l, "nearly full"), chip::AMBER.tone(&v));
                }
                ui.end_row();
            }
        });
        ui.horizontal(|ui| {
            ui.weak(tr_in(SCOPE, l, "The limits are kernel parameters of System › Tuning."));
            self.info(ui, "arp.gc_thresh", "gc_thresh");
            if ui.button(tr_in(SCOPE, l, "Open Tuning")).clicked() {
                open_window(app, Win::Panel("tuning"));
            }
        });
    }

    fn confirm_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut c) = self.confirm.take() else { return };
        let wid = dialog_id(c.id);
        let l = app.lang.labels;
        let title = tr_in(SCOPE, l, "Confirm");
        let head = dialog::Head {
            id: wid,
            title,
            dirty: false,
            pos: cascade(area, c.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let can = app.can();
        let message = c.message.clone();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut c.status, |ui, _| {
            ui.label(&message);
            Footer::<()>::edit(false, can.check(c.command))
        });
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                c.status.close_on_success = true;
                c.status.sent();
                app.run_then(c.command, c.params.clone(), crate::panel::then(NAME, Done(c.id)));
            }
            _ => {}
        }
        self.confirm = Some(c);
    }

    fn address_list_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.to_list.take() else { return };
        let wid = dialog_id(d.id);
        let l = app.lang.labels;
        let title = tr_in(SCOPE, l, "Add to Address List");
        let head = dialog::Head {
            id: wid,
            title,
            dirty: !d.list.is_empty(),
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let can = app.can();
        let mut list = d.list.clone();
        let shown = d.addresses.join(", ");
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("arp-to-list").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label(tr_in(SCOPE, l, "Addresses"));
                ui.label(&shown);
                ui.end_row();
                f.text(ui, "List", "list", &mut list, "blocked");
            });
            Footer::<()>::edit(false, can.check("ip.firewall.address-list.add"))
        });
        d.list = list;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let steps: Vec<Value> = d
                    .addresses
                    .iter()
                    .map(|a| {
                        json!({"command": "ip.firewall.address-list.add",
                            "params": {"list": d.list.trim(), "address": a, "comment": "from IP › ARP"}})
                    })
                    .collect();
                d.status.close_on_success = true;
                d.status.sent();
                app.run_steps(steps, crate::panel::then(NAME, Done(d.id)));
            }
            _ => {}
        }
        self.to_list = Some(d);
    }
}

struct PingStarted;

impl PanelState for ArpPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let open4 = app.open.contains(&Win::Panel(WIN));
        let open6 = app.open.contains(&Win::Panel(WIN6));
        if !(open4 || open6) || !app.has_command("ip.arp.list") {
            return Vec::new();
        }
        let mut out = Vec::new();
        if open4 {
            out.push(match self.tab {
                Tab::Arp => Query { key: "v4", command: "ip.arp.list", params: self.v4.params() },
                Tab::Nd => Query { key: "v6", command: "ipv6.neighbor.list", params: self.v6.params() },
                Tab::Settings => Query { key: "settings", command: "ip.arp.settings.print", params: json!({}) },
            });
        }
        if open6 {
            out.push(Query { key: "v6w", command: "ipv6.neighbor.list", params: self.v6w.params() });
        }
        if let Some((a, i)) = &self.picked {
            out.push(Query { key: "detail", command: "ip.arp.detail", params: json!({"address": a, "interface": i}) });
        }
        if let Some(id) = self.ping {
            out.push(Query { key: "ping", command: "tool.task.poll", params: json!({"id": id}) });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "v4" => self.v4.page = Some(value),
            "v6" => self.v6.page = Some(value),
            "v6w" => self.v6w.page = Some(value),
            "settings" => self.settings = Some(value),
            "detail" => self.detail = value.is_object().then_some(value),
            "ping" => {
                if value.get("done").and_then(Value::as_bool).unwrap_or(false) {
                    self.ping = None;
                }
                self.ping_poll = Some(value);
            }
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.cur = win;
        if win == WIN6 {
            // IPv6 › Neighbors: the ND list alone.
            self.list_tab(app, ui, l);
        } else {
            self.tabs(app, ui, l);
            match self.tab {
                Tab::Arp | Tab::Nd => self.list_tab(app, ui, l),
                Tab::Settings => self.settings_tab(app, ui, l),
            }
        }
        self.cur = WIN;
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.modal {
            let names = app.interface_names(None);
            if !m.show(app, ctx, area, &SPEC, &|p| if p == "interface" { names.clone() } else { Vec::new() }) {
                self.modal = None;
            }
        }
        self.confirm_dialog(app, ctx, area);
        self.address_list_dialog(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        if let Some(d) = then.downcast_ref::<Done>() {
            if let Some(c) = self.confirm.as_mut().filter(|c| c.id == d.0)
                && c.status.replied(result)
            {
                app.floats.forget(dialog_id(c.id));
                self.confirm = None;
            }
            if let Some(t) = self.to_list.as_mut().filter(|t| t.id == d.0)
                && t.status.replied(result)
            {
                app.floats.forget(dialog_id(t.id));
                self.to_list = None;
            }
        }
        if then.downcast_ref::<PingStarted>().is_some()
            && let Ok(v) = result
        {
            self.ping = v.get("id").and_then(Value::as_u64);
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, win: &'static str) -> bool {
        if win == WIN6 {
            return self.v6w.table.escape();
        }
        match self.tab {
            Tab::Arp => self.v4.table.escape(),
            Tab::Nd => self.v6.table.escape(),
            Tab::Settings => self.settings_table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (TABLE, &self.v4.table),
            (TABLE6, &self.v6.table),
            (TABLE6W, &self.v6w.table),
            (SETTINGS_TABLE, &self.settings_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (TABLE, &mut self.v4.table),
            (TABLE6, &mut self.v6.table),
            (TABLE6W, &mut self.v6w.table),
            (SETTINGS_TABLE, &mut self.settings_table),
        ]
    }
}

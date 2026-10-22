//! The IPv6 menu (G4.7b), WinBox style:
//! - **DHCPv6 Client**: one client per interface with its status, address
//!   and delegated prefix; the G1.9 table, toolbar, menus and keys; "New
//!   DHCPv6 Client" / "DHCPv6 Client <iface>" windows with the tabs DHCP,
//!   Status, Advanced and Options (what the server sent), as in IP › DHCP
//!   Client;
//! - **IPv6 Pool**: the delegated prefixes and the addresses numbered from
//!   them (read-only: pools come from the clients);
//! - **IPv6 Settings**: which interfaces accept Router Advertisements, and
//!   why each one does or does not.
//!
//! Everything comes from `ipv6.*` queries and goes through
//! `CoreRouterUi::run`; the engine decides. The clients' history
//! (`ipv6.dhcp-client.history`) feeds the Log window.

use std::collections::BTreeMap;

use egui::{Grid, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment};
use crate::{CoreRouterUi, LogLine, Then, form_number, value_text};

pub(crate) const TABLE: &str = "dhcpv6-client";
pub(crate) const POOL_TABLE: &str = "ipv6-pool";
pub(crate) const RA_TABLE: &str = "ipv6-ra";
const MAX_OPEN: usize = 8;
const REQUESTS: [&str; 3] = ["address,prefix", "prefix", "address"];
const ACCEPT: [&str; 4] = ["auto", "yes", "no", "yes-if-forwarding-disabled"];
const FIRST_LOOK: usize = 20;

const COLUMNS: [table::Column; 8] = [
    col(""),
    col("Interface"),
    col("Request"),
    col("Pool"),
    col("Address"),
    col("Prefix"),
    col("Status"),
    comment(),
];

/// What the IPv6 windows read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Feed {
    Clients,
    Options,
    History,
    Pools,
    Settings,
}

#[derive(Default)]
pub(crate) struct State {
    pub clients: Vec<Value>,
    pub options: BTreeMap<String, Value>,
    pub pools: Vec<Value>,
    pub settings: Value,
    /// Last history event logged (`None` before the first look).
    pub seq: Option<u64>,
    pub dialogs: Vec<Dhcp6DialogWin>,
    /// Clients to open once a list sent after this request arrives.
    pub open_after: Vec<(RequestId, String)>,
}

/// The editable fields of a client, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dhcp6Form {
    pub interface: String,
    pub request: String,
    pub pool_name: String,
    pub prefix_hint: String,
    pub use_peer_dns: bool,
    pub add_default_route: bool,
    pub distance: String,
    pub comment: String,
    pub disabled: bool,
    pub rapid_commit: bool,
    pub accept_prefix_without_address: bool,
    pub custom_duid: String,
    pub allowed_servers: String,
}

impl Dhcp6Form {
    pub(crate) fn new() -> Self {
        Self {
            interface: String::new(),
            request: "address,prefix".into(),
            pool_name: String::new(),
            prefix_hint: String::new(),
            use_peer_dns: true,
            add_default_route: false,
            distance: "1".into(),
            comment: String::new(),
            disabled: false,
            rapid_commit: true,
            accept_prefix_without_address: true,
            custom_duid: String::new(),
            allowed_servers: String::new(),
        }
    }

    fn of(row: &Value) -> Self {
        Self {
            interface: text(row, "interface"),
            request: text(row, "request"),
            pool_name: text(row, "pool_name"),
            prefix_hint: text(row, "prefix_hint"),
            use_peer_dns: flag(row, "use_peer_dns"),
            add_default_route: flag(row, "add_default_route"),
            distance: text(row, "default_route_distance"),
            comment: text(row, "comment"),
            disabled: flag(row, "disabled"),
            rapid_commit: flag(row, "rapid_commit"),
            accept_prefix_without_address: flag(row, "accept_prefix_without_address"),
            custom_duid: text(row, "custom_duid"),
            allowed_servers: text(row, "allowed_servers"),
        }
    }

    /// `ipv6.dhcp-client.add` params; what equals the default is left out
    /// (`request` always goes: it is required).
    fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("interface".into(), json!(self.interface));
        p.insert("request".into(), json!(self.request));
        if let Some(Value::Object(diff)) = self.diff(&Self::new()) {
            p.extend(diff);
        }
        Value::Object(p)
    }

    fn diff(&self, base: &Dhcp6Form) -> Option<Value> {
        let mut p = Map::new();
        let mut put = |k: &str, v: Value| {
            p.insert(k.into(), v);
        };
        for (k, now, was) in [
            ("interface", &self.interface, &base.interface),
            ("request", &self.request, &base.request),
            ("pool_name", &self.pool_name, &base.pool_name),
            ("prefix_hint", &self.prefix_hint, &base.prefix_hint),
            ("custom_duid", &self.custom_duid, &base.custom_duid),
            (
                "allowed_servers",
                &self.allowed_servers,
                &base.allowed_servers,
            ),
        ] {
            if now.trim() != was.trim() {
                put(k, json!(now.trim()));
            }
        }
        for (k, now, was) in [
            ("use_peer_dns", self.use_peer_dns, base.use_peer_dns),
            (
                "add_default_route",
                self.add_default_route,
                base.add_default_route,
            ),
            ("disabled", self.disabled, base.disabled),
            ("rapid_commit", self.rapid_commit, base.rapid_commit),
            (
                "accept_prefix_without_address",
                self.accept_prefix_without_address,
                base.accept_prefix_without_address,
            ),
        ] {
            if now != was {
                put(k, json!(now));
            }
        }
        if self.distance.trim() != base.distance {
            put("default_route_distance", form_number(&self.distance));
        }
        if self.comment != base.comment {
            put("comment", json!(self.comment));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }

    fn set_params(&self, id: &str, base: &Dhcp6Form) -> Option<Value> {
        let mut p = self.diff(base)?;
        if let Value::Object(o) = &mut p {
            o.insert("id".into(), json!(id));
        }
        Some(p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    Dhcp,
    Status,
    Advanced,
    Options,
}

pub(crate) enum Dhcp6Dialog {
    New {
        form: Dhcp6Form,
        base: Dhcp6Form,
        tab: Tab,
    },
    Props {
        id: String,
        form: Dhcp6Form,
        base: Dhcp6Form,
        tab: Tab,
    },
    Comment {
        targets: Vec<String>,
        text: String,
        base: String,
    },
}

impl Dhcp6Dialog {
    fn dirty(&self) -> bool {
        match self {
            Self::New { form, base, .. } => form != base,
            Self::Props { id, form, base, .. } => form.set_params(id, base).is_some(),
            Self::Comment { text, base, .. } => text != base,
        }
    }

    pub(crate) fn options_of(&self) -> Option<&str> {
        match self {
            Self::Props {
                id,
                tab: Tab::Options,
                ..
            } => Some(id),
            _ => None,
        }
    }
}

pub(crate) struct Dhcp6DialogWin {
    pub id: u64,
    pub dialog: Dhcp6Dialog,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    OpenCreated,
    Applied(Box<Dhcp6Form>),
    Toggled(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
    Release,
    Renew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    Renew(Vec<String>),
    Release(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more DHCPv6 clients first".into())
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

fn running(picked: &[&Value]) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| flag(r, "disabled")) {
        Err("A disabled client does not run: enable it first".into())
    } else {
        Ok(())
    }
}

fn client_row(r: &Value) -> Row {
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "interface"),
            text(r, "request"),
            text(r, "pool_name"),
            text(r, "address"),
            text(r, "prefix"),
            text(r, "status"),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

impl CoreRouterUi {
    /// A query of the IPv6 windows arrived (request `id`).
    pub(crate) fn v6_arrived(&mut self, feed: Feed, id: RequestId, value: Value) {
        let arr = |v: Value| match v {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        match feed {
            Feed::Clients => {
                self.v6.clients = arr(value);
                let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.v6.open_after)
                    .into_iter()
                    .partition(|(req, _)| *req <= id);
                self.v6.open_after = later;
                for (_, c) in ready {
                    self.open_dhcp6(&c);
                }
            }
            Feed::Options => {
                if let Some(c) = value.get("id").and_then(Value::as_str) {
                    self.v6.options.insert(c.to_owned(), value.clone());
                }
            }
            Feed::History => self.dhcp6_history_arrived(&value),
            Feed::Pools => self.v6.pools = arr(value),
            Feed::Settings => self.v6.settings = value,
        }
    }

    /// The queries the open IPv6 windows need, as (feed, command, params).
    pub(crate) fn v6_queries(&self, history: bool) -> Vec<(Feed, &'static str, Value)> {
        let mut out = Vec::new();
        let open = |w| self.open.contains(&w);
        if open(crate::windows::Win::Dhcp6Client) || !self.v6.dialogs.is_empty() {
            out.push((Feed::Clients, "ipv6.dhcp-client.list", Value::Null));
        }
        for d in &self.v6.dialogs {
            if let Some(c) = d.dialog.options_of() {
                out.push((
                    Feed::Options,
                    "ipv6.dhcp-client.options",
                    json!({ "id": c }),
                ));
            }
        }
        if open(crate::windows::Win::Ipv6Pool) {
            out.push((Feed::Pools, "ipv6.pool.list", Value::Null));
        }
        if open(crate::windows::Win::Ipv6Settings) {
            out.push((Feed::Settings, "ipv6.settings.get", Value::Null));
        }
        if history {
            let after = self.v6.seq.unwrap_or(0);
            out.push((
                Feed::History,
                "ipv6.dhcp-client.history",
                json!({ "after_seq": after }),
            ));
        }
        out
    }

    fn dhcp6_row(&self, id: &str) -> Option<&Value> {
        self.v6.clients.iter().find(|r| text(r, "id") == id)
    }

    pub(crate) fn dhcp6_clients(&mut self, ui: &mut Ui) {
        let clients = self.v6.clients.clone();
        let rows: Vec<Row> = clients.iter().map(client_row).collect();
        let selection = self.tables.dhcp6.selection(&rows);
        let picked: Vec<&Value> = clients
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let mut act: Option<Act> = None;
        let can = self.can();
        ui.horizontal(|ui| {
            if table::tool(
                ui,
                TABLE,
                Icon::Add,
                "Add",
                can.check("ipv6.dhcp-client.add"),
            )
            .clicked()
            {
                act = Some(Act::New);
            }
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and("ipv6.dhcp-client.remove", some(&picked)),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and("ipv6.dhcp-client.set", can_enable(&picked, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and("ipv6.dhcp-client.set", can_enable(&picked, false)),
                ),
                (
                    Icon::Comment,
                    "Comment",
                    can.and("ipv6.dhcp-client.set", some(&picked)),
                ),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Remove => Act::Remove(sel),
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        Icon::Add | Icon::Comment => Act::Comment(sel),
                    });
                }
            }
            ui.separator();
            if action(
                ui,
                "Renew",
                can.and("ipv6.dhcp-client.renew", running(&picked)),
            ) {
                act = Some(Act::Renew(selection.clone()));
            }
            if action(
                ui,
                "Release",
                can.and("ipv6.dhcp-client.release", running(&picked)),
            ) {
                act = Some(Act::Release(selection.clone()));
            }
            table::find_field(ui, TABLE, &mut self.tables.dhcp6);
        });
        ui.separator();
        let out = table::show(
            ui,
            TABLE,
            0.0,
            &mut self.tables.dhcp6,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<&Value> = clients
                        .iter()
                        .filter(|r| sel.contains(&text(r, "id")))
                        .collect();
                    let owned = || sel.to_vec();
                    let items = [
                        (
                            "Enable",
                            "ipv6.dhcp-client.set",
                            can_enable(&picked, true),
                            Act::Enable(owned()),
                        ),
                        (
                            "Disable",
                            "ipv6.dhcp-client.set",
                            can_enable(&picked, false),
                            Act::Disable(owned()),
                        ),
                        (
                            "Remove",
                            "ipv6.dhcp-client.remove",
                            some(&picked),
                            Act::Remove(owned()),
                        ),
                        (
                            "Comment…",
                            "ipv6.dhcp-client.set",
                            some(&picked),
                            Act::Comment(owned()),
                        ),
                        (
                            "Renew",
                            "ipv6.dhcp-client.renew",
                            running(&picked),
                            Act::Renew(owned()),
                        ),
                        (
                            "Release",
                            "ipv6.dhcp-client.release",
                            running(&picked),
                            Act::Release(owned()),
                        ),
                    ];
                    for (label, cmd, ok, a) in items {
                        if action(ui, label, can.and(cmd, ok)) {
                            act = Some(a);
                        }
                    }
                    if action(ui, "Properties…", some(&picked)) {
                        act = Some(Act::Open(owned()));
                    }
                    ui.separator();
                    if action(ui, "Add DHCPv6 Client…", can.check("ipv6.dhcp-client.add")) {
                        act = Some(Act::New);
                    }
                }
                Menu::Empty => {
                    if action(ui, "Add DHCPv6 Client…", can.check("ipv6.dhcp-client.add")) {
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
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(key) = out.comment {
            act = Some(Act::Comment(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.tables.dhcp6.selection(&rows);
            let picked: Vec<&Value> = clients
                .iter()
                .filter(|r| sel.contains(&text(r, "id")))
                .collect();
            let allowed = match s {
                Shortcut::Remove | Shortcut::Comment | Shortcut::Open => some(&picked).is_ok(),
                Shortcut::Enable => can_enable(&picked, true).is_ok(),
                Shortcut::Disable => can_enable(&picked, false).is_ok(),
            };
            if allowed {
                act = Some(match s {
                    Shortcut::Remove => Act::Remove(sel),
                    Shortcut::Enable => Act::Enable(sel),
                    Shortcut::Disable => Act::Disable(sel),
                    Shortcut::Comment => Act::Comment(sel),
                    Shortcut::Open => Act::Open(sel),
                });
            }
        }
        if let Some(a) = act {
            self.dhcp6_act(a, &rows);
        }
    }

    fn dhcp6_act(&mut self, act: Act, rows: &[Row]) {
        let each = |me: &mut Self, keys: &[String], cmd: &str, extra: Value| {
            for id in keys {
                let mut p = json!({ "id": id });
                if let (Value::Object(o), Value::Object(e)) = (&mut p, &extra) {
                    o.extend(e.clone());
                }
                me.run(cmd, p);
            }
        };
        match act {
            Act::Enable(k) => each(self, &k, "ipv6.dhcp-client.set", json!({"disabled": false})),
            Act::Disable(k) => each(self, &k, "ipv6.dhcp-client.set", json!({"disabled": true})),
            Act::Remove(k) => each(self, &k, "ipv6.dhcp-client.remove", json!({})),
            Act::Renew(k) => each(self, &k, "ipv6.dhcp-client.renew", json!({})),
            Act::Release(k) => each(self, &k, "ipv6.dhcp-client.release", json!({})),
            Act::Comment(keys) => {
                let text = match keys.as_slice() {
                    [one] => self
                        .dhcp6_row(one)
                        .map(|r| text(r, "comment"))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                if !keys.is_empty() {
                    self.open_dhcp6_dialog(Dhcp6Dialog::Comment {
                        targets: keys,
                        base: text.clone(),
                        text,
                    });
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_dhcp6(k);
                }
            }
            Act::New => {
                let mut form = Dhcp6Form::new();
                let taken: Vec<String> = self
                    .v6
                    .clients
                    .iter()
                    .map(|r| text(r, "interface"))
                    .collect();
                if let Some(free) = self
                    .interface_names(None)
                    .into_iter()
                    .find(|n| !taken.contains(n) && n != "lo")
                {
                    form.interface = free;
                }
                // A pool name to start with (the LAN addresses use it).
                let mut n = 1;
                let pools: Vec<String> = self
                    .v6
                    .clients
                    .iter()
                    .map(|r| text(r, "pool_name"))
                    .collect();
                while pools.contains(&format!("pd{n}")) {
                    n += 1;
                }
                form.pool_name = format!("pd{n}");
                self.open_dhcp6_dialog(Dhcp6Dialog::New {
                    base: form.clone(),
                    form,
                    tab: Tab::Dhcp,
                });
            }
            Act::SelectAll => self.tables.dhcp6.select_all(rows),
            Act::Refresh => self.cache.refreshed_at = None,
        }
    }

    fn open_dhcp6_dialog(&mut self, dialog: Dhcp6Dialog) {
        self.next_dialog = self.next_dialog.wrapping_add(1);
        self.v6.dialogs.push(Dhcp6DialogWin {
            id: self.next_dialog,
            dialog,
            status: Status::default(),
        });
        self.cache.refreshed_at = None;
    }

    pub(crate) fn open_dhcp6(&mut self, id: &str) {
        let Some(row) = self.dhcp6_row(id).cloned() else {
            return;
        };
        let open = self
            .v6
            .dialogs
            .iter()
            .any(|d| matches!(&d.dialog, Dhcp6Dialog::Props { id: i, .. } if i == id));
        if open {
            return;
        }
        let form = Dhcp6Form::of(&row);
        self.open_dhcp6_dialog(Dhcp6Dialog::Props {
            id: id.to_owned(),
            base: form.clone(),
            form,
            tab: Tab::Dhcp,
        });
    }

    pub(crate) fn dhcp6_dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let clients = self.v6.clients.clone();
        let names = self.interface_names(None);
        let mut dialogs = std::mem::take(&mut self.v6.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            let row = match &d.dialog {
                Dhcp6Dialog::Props { id, .. } => {
                    let row = clients.iter().find(|r| text(r, "id") == *id);
                    if row.is_none() && !self.v6.clients.is_empty() {
                        self.floats.forget(wid);
                        return false;
                    }
                    row.cloned()
                }
                _ => None,
            };
            let title = match &d.dialog {
                Dhcp6Dialog::New { .. } => "New DHCPv6 Client".to_owned(),
                Dhcp6Dialog::Props { form, .. } => format!(
                    "DHCPv6 Client <{}>",
                    row.as_ref()
                        .map_or(form.interface.clone(), |r| text(r, "interface"))
                ),
                Dhcp6Dialog::Comment { targets, .. } => match targets.as_slice() {
                    [one] => format!(
                        "Comment for DHCPv6 Client <{}>",
                        clients
                            .iter()
                            .find(|r| text(r, "id") == *one)
                            .map(|r| text(r, "interface"))
                            .unwrap_or_default()
                    ),
                    many => format!("Comment for {} DHCPv6 Clients", many.len()),
                },
            };
            let can = self.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(crate::windows::Win::Dhcp6Client)),
            };
            let options = row
                .as_ref()
                .and_then(|r| self.v6.options.get(&text(r, "id")))
                .cloned();
            let pressed =
                dialog::show(&mut self.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(
                        ui,
                        f,
                        &mut d.dialog,
                        row.as_ref(),
                        options.as_ref(),
                        &names,
                        &can,
                    )
                });
            let keep = pressed.is_none_or(|b| self.dhcp6_button(d, b, row.as_ref()));
            if !keep {
                self.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.v6.dialogs);
        self.v6.dialogs = dialogs;
    }

    fn dhcp6_button(
        &mut self,
        d: &mut Dhcp6DialogWin,
        b: Press<Button>,
        row: Option<&Value>,
    ) -> bool {
        if b == Press::Cancel {
            return false;
        }
        let set = "ipv6.dhcp-client.set";
        let (sends, close): (Vec<(&str, Value, Effect)>, bool) = match &d.dialog {
            Dhcp6Dialog::New { form, .. } => {
                let effect = if b == Press::Apply {
                    Effect::OpenCreated
                } else {
                    Effect::None
                };
                (
                    vec![("ipv6.dhcp-client.add", form.add_params(), effect)],
                    true,
                )
            }
            Dhcp6Dialog::Props { id, form, base, .. } => match b {
                Press::Ok | Press::Apply => match form.set_params(id, base) {
                    Some(p) => (
                        vec![(set, p, Effect::Applied(Box::new(form.clone())))],
                        b == Press::Ok,
                    ),
                    None => return b != Press::Ok,
                },
                Press::Other(Button::Toggle) => {
                    let now = row.is_some_and(|r| flag(r, "disabled"));
                    (
                        vec![(
                            set,
                            json!({"id": id, "disabled": !now}),
                            Effect::Toggled(!now),
                        )],
                        false,
                    )
                }
                Press::Other(Button::Remove) => (
                    vec![("ipv6.dhcp-client.remove", json!({ "id": id }), Effect::None)],
                    true,
                ),
                Press::Other(Button::Renew) => (
                    vec![("ipv6.dhcp-client.renew", json!({ "id": id }), Effect::None)],
                    false,
                ),
                Press::Other(Button::Release) => (
                    vec![(
                        "ipv6.dhcp-client.release",
                        json!({ "id": id }),
                        Effect::None,
                    )],
                    false,
                ),
                Press::Cancel => return false,
            },
            Dhcp6Dialog::Comment { targets, text, .. } => (
                targets
                    .iter()
                    .map(|t| (set, json!({"id": t, "comment": text}), Effect::None))
                    .collect(),
                true,
            ),
        };
        d.status.close_on_success = close;
        for (cmd, params, effect) in sends {
            d.status.sent();
            self.run_then(cmd, params, Then::Dhcp6 { id: d.id, effect });
        }
        true
    }

    pub(crate) fn dhcp6_dialog_reply(
        &mut self,
        id: u64,
        effect: Effect,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.v6.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut created = None;
        let close = match self.v6.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, effect, &mut d.dialog) {
                    (Err(_), _, _) => {}
                    (Ok(r), Effect::OpenCreated, _) => {
                        created = r.get("id").and_then(Value::as_str).map(str::to_owned);
                    }
                    (Ok(_), Effect::Applied(sent), Dhcp6Dialog::Props { base, form, .. }) => {
                        let mut sent = *sent;
                        for s in [
                            &mut sent.interface,
                            &mut sent.pool_name,
                            &mut sent.prefix_hint,
                            &mut sent.distance,
                            &mut sent.custom_duid,
                            &mut sent.allowed_servers,
                        ] {
                            *s = s.trim().to_owned();
                        }
                        *base = sent;
                        form.disabled = base.disabled;
                    }
                    (Ok(_), Effect::Toggled(now), Dhcp6Dialog::Props { base, form, .. }) => {
                        base.disabled = now;
                        form.disabled = now;
                    }
                    (Ok(_), _, _) => {}
                }
                close
            }
        };
        if close {
            self.v6.dialogs.remove(pos);
            self.floats.forget(dialog_id(id));
        }
        self.cache.refreshed_at = None;
        if let Some(c) = created {
            let list = self.reload();
            self.v6.open_after.push((list, c));
        }
    }

    fn dhcp6_history_arrived(&mut self, value: &Value) {
        let last = value.get("last_seq").and_then(Value::as_u64).unwrap_or(0);
        let events = value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let skip = if self.v6.seq.is_none() {
            events.len().saturating_sub(FIRST_LOOK)
        } else {
            0
        };
        for e in events.iter().skip(skip) {
            let bad = matches!(
                text(e, "event").as_str(),
                "lost" | "status" | "refused" | "error"
            );
            self.push_log(LogLine {
                ok: !bad,
                command: "dhcpv6-client".into(),
                message: format!("{}: {}", text(e, "interface"), text(e, "message")),
            });
        }
        self.v6.seq = Some(last);
    }

    pub(crate) fn ipv6_pools(&mut self, ui: &mut Ui) {
        const POOL_COLUMNS: [table::Column; 6] = [
            col(""),
            col("Name"),
            col("Prefix"),
            col("Interface"),
            col("Expires After"),
            col("Used By"),
        ];
        let rows: Vec<Row> = self
            .v6
            .pools
            .iter()
            .map(|p| {
                let used: Vec<String> = p
                    .get("used")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|u| match u.get("address").and_then(Value::as_str) {
                        Some(a) => format!("{a}@{}", text(u, "interface")),
                        None => format!("(waiting)@{}", text(u, "interface")),
                    })
                    .collect();
                Row {
                    key: text(p, "name"),
                    cells: vec![
                        text(p, "flags"),
                        text(p, "name"),
                        text(p, "prefix"),
                        text(p, "interface"),
                        text(p, "expires_after"),
                        used.join(", "),
                    ],
                    dimmed: p.get("prefix").is_none_or(Value::is_null),
                    section: false,
                    tint: None,
                }
            })
            .collect();
        ui.horizontal(|ui| {
            ui.weak("Pools come from DHCPv6 clients (pool name). Number a LAN with");
            ui.monospace("ip.address.add address=::1/64 from_pool=<pool>");
        });
        ui.separator();
        table::show(
            ui,
            POOL_TABLE,
            0.0,
            &mut self.tables.pool6,
            &POOL_COLUMNS,
            &rows,
            |_, _| {},
        );
    }

    pub(crate) fn ipv6_settings(&mut self, ui: &mut Ui) {
        let s = self.v6.settings.clone();
        let can = self.can();
        let mut mode = text(&s, "accept_router_advertisements");
        let mut on = text(&s, "accept_router_advertisements_on");
        let (mode0, on0) = (mode.clone(), on.clone());
        let mut lists = vec!["all".to_owned(), "none".to_owned()];
        lists.extend(
            self.fw
                .rows(crate::firewall::Feed::Lists)
                .iter()
                .map(|l| text(l, "name")),
        );
        let enabled = can.check("ipv6.settings.set");
        ui.add_enabled_ui(enabled.is_ok(), |ui| {
            Grid::new("ipv6-settings")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Accept Router Advertisements");
                    egui::ComboBox::from_id_salt("ipv6-accept-ra")
                        .selected_text(mode.as_str())
                        .show_ui(ui, |ui| {
                            for m in ACCEPT {
                                ui.selectable_value(&mut mode, m.to_owned(), m);
                            }
                        });
                    ui.end_row();
                    ui.label("Accept RA On (interface list)");
                    egui::ComboBox::from_id_salt("ipv6-accept-ra-on")
                        .selected_text(on.as_str())
                        .show_ui(ui, |ui| {
                            for l in &lists {
                                ui.selectable_value(&mut on, l.clone(), l);
                            }
                        });
                    ui.end_row();
                });
        })
        .response
        .on_disabled_hover_text(enabled.err().unwrap_or_default());
        ui.weak("auto: only where a DHCPv6 client runs (the WAN); never on the LAN.");
        if mode != mode0 && !mode0.is_empty() {
            self.run(
                "ipv6.settings.set",
                json!({"accept_router_advertisements": mode}),
            );
        }
        if on != on0 && !on0.is_empty() {
            self.run(
                "ipv6.settings.set",
                json!({"accept_router_advertisements_on": on}),
            );
        }
        ui.separator();
        const RA_COLUMNS: [table::Column; 3] = [col("Interface"), col("Accept RA"), col("Why")];
        let rows: Vec<Row> = s
            .get("interfaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|i| Row {
                key: text(i, "interface"),
                cells: vec![text(i, "interface"), text(i, "accept"), text(i, "why")],
                dimmed: !flag(i, "accepts"),
                section: false,
                tint: None,
            })
            .collect();
        table::show(
            ui,
            RA_TABLE,
            0.0,
            &mut self.tables.ra6,
            &RA_COLUMNS,
            &rows,
            |_, _| {},
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn dialog_body(
    ui: &mut Ui,
    f: &Form,
    d: &mut Dhcp6Dialog,
    row: Option<&Value>,
    options: Option<&Value>,
    names: &[String],
    can: &Avail,
) -> Footer<Button> {
    let props = matches!(d, Dhcp6Dialog::Props { .. });
    match d {
        Dhcp6Dialog::Comment { text, .. } => {
            Grid::new("dhcp6-comment").num_columns(2).show(ui, |ui| {
                f.text(ui, "Comment", "comment", text, "");
            });
            return Footer::edit(false, can.check("ipv6.dhcp-client.set"));
        }
        Dhcp6Dialog::New { form, tab, .. } | Dhcp6Dialog::Props { form, tab, .. } => {
            ui.horizontal(|ui| {
                ui.selectable_value(tab, Tab::Dhcp, "DHCP");
                if props {
                    ui.selectable_value(tab, Tab::Status, "Status");
                }
                ui.selectable_value(tab, Tab::Advanced, "Advanced");
                if props {
                    ui.selectable_value(tab, Tab::Options, "Options");
                }
            });
            ui.separator();
            match tab {
                Tab::Dhcp => dhcp_tab(ui, f, form, names, props),
                Tab::Advanced => advanced_tab(ui, f, form),
                Tab::Status => status_tab(ui, row),
                Tab::Options => options_tab(ui, row, options),
            }
        }
    }
    let ok = can.check(if props {
        "ipv6.dhcp-client.set"
    } else {
        "ipv6.dhcp-client.add"
    });
    let mut footer = Footer::edit(true, ok);
    if let Some(r) = row {
        let disabled = flag(r, "disabled");
        let run = if disabled {
            Err("A disabled client does not run: enable it first".to_owned())
        } else {
            Ok(())
        };
        footer.extra = vec![
            (
                if disabled { "Enable" } else { "Disable" },
                Button::Toggle,
                can.check("ipv6.dhcp-client.set"),
            ),
            (
                "Remove",
                Button::Remove,
                can.check("ipv6.dhcp-client.remove"),
            ),
            (
                "Release",
                Button::Release,
                can.and("ipv6.dhcp-client.release", run.clone()),
            ),
            (
                "Renew",
                Button::Renew,
                can.and("ipv6.dhcp-client.renew", run),
            ),
        ];
    }
    footer
}

fn dhcp_tab(ui: &mut Ui, f: &Form, form: &mut Dhcp6Form, names: &[String], props: bool) {
    Grid::new("dhcp6-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Interface");
            crate::windows::combo(ui, "dhcp6-iface", "interface", &mut form.interface, names);
            ui.end_row();
            ui.label("Request");
            egui::ComboBox::from_id_salt("dhcp6-request")
                .selected_text(form.request.as_str())
                .show_ui(ui, |ui| {
                    for r in REQUESTS {
                        ui.selectable_value(&mut form.request, r.to_owned(), r);
                    }
                });
            ui.end_row();
            f.text(
                ui,
                "Pool Name",
                "pool_name",
                &mut form.pool_name,
                "(needed for a prefix)",
            );
            f.text(
                ui,
                "Prefix Hint",
                "prefix_hint",
                &mut form.prefix_hint,
                "::/56",
            );
            ui.label("Use Peer DNS");
            ui.checkbox(&mut form.use_peer_dns, "");
            ui.end_row();
            ui.label("Add Default Route");
            ui.checkbox(&mut form.add_default_route, "").on_hover_text(
                "::/0 via the server's link-local; usually the RA gives the default route",
            );
            ui.end_row();
            f.text(
                ui,
                "Default Route Distance",
                "default_route_distance",
                &mut form.distance,
                "1",
            );
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            if props {
                ui.label("Disabled");
                ui.checkbox(&mut form.disabled, "");
                ui.end_row();
            }
        });
}

fn advanced_tab(ui: &mut Ui, f: &Form, form: &mut Dhcp6Form) {
    Grid::new("dhcp6-advanced")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Rapid Commit");
            ui.checkbox(&mut form.rapid_commit, "");
            ui.end_row();
            ui.label("Accept Prefix Without Address");
            ui.checkbox(&mut form.accept_prefix_without_address, "");
            ui.end_row();
            f.text(
                ui,
                "Custom DUID",
                "custom_duid",
                &mut form.custom_duid,
                "(DUID-LL of the MAC)",
            );
            f.text(
                ui,
                "Allowed Servers",
                "allowed_servers",
                &mut form.allowed_servers,
                "(any) fe80::1, 0x0003…, AA:BB:…",
            );
        });
}

fn status_tab(ui: &mut Ui, row: Option<&Value>) {
    let Some(r) = row else {
        ui.weak("Not created yet.");
        return;
    };
    Grid::new("dhcp6-status")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for (label, key) in [
                ("Status", "status"),
                ("Address", "address"),
                ("Address Expires After", "address_expires_after"),
                ("Prefix", "prefix"),
                ("Prefix Expires After", "prefix_expires_after"),
                ("DHCP Server", "dhcp_server"),
                ("Server DUID", "server_duid"),
                ("DUID", "duid"),
                ("Primary DNS", "primary_dns"),
                ("Secondary DNS", "secondary_dns"),
                ("Domains", "domains"),
                ("Renew After (T1)", "t1_after"),
                ("Rebind After (T2)", "t2_after"),
            ] {
                ui.label(label);
                ui.add_enabled(
                    false,
                    TextEdit::singleline(&mut text(r, key)).desired_width(260.0),
                );
                ui.end_row();
            }
        });
    if let Some(routes) = r
        .get("routes")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    {
        ui.label("Routes");
        for route in routes {
            ui.monospace(format!("  {}", value_text(route)));
        }
    }
    for n in r
        .get("missing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        ui.colored_label(ui.visuals().warn_fg_color, value_text(n));
    }
    let error = text(r, "error");
    if !error.is_empty() {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
}

fn options_tab(ui: &mut Ui, row: Option<&Value>, options: Option<&Value>) {
    let bound = row.is_some_and(|r| {
        matches!(
            text(r, "status").as_str(),
            "bound" | "renewing" | "rebinding"
        )
    });
    let list = options
        .and_then(|o| o.get("options"))
        .and_then(Value::as_array)
        .filter(|_| bound);
    let Some(list) = list else {
        ui.weak("No lease: the options the server sends show here.");
        return;
    };
    ui.weak(format!(
        "Sent by {}",
        options.map(|o| text(o, "dhcp_server")).unwrap_or_default()
    ));
    ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
        Grid::new("dhcp6-options")
            .num_columns(3)
            .striped(true)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for h in ["Code", "Name", "Value"] {
                    ui.strong(h);
                }
                ui.end_row();
                for o in list {
                    ui.label(text(o, "code"));
                    ui.label(text(o, "name"));
                    ui.label(RichText::new(text(o, "value")).monospace())
                        .on_hover_text(text(o, "hex"));
                    ui.end_row();
                }
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_send_only_what_changed() {
        let mut f = Dhcp6Form::new();
        f.interface = "ether1".into();
        f.pool_name = "pd1".into();
        assert_eq!(
            f.add_params(),
            json!({"interface": "ether1", "request": "address,prefix", "pool_name": "pd1"})
        );
        let base = f.clone();
        assert_eq!(f.set_params("*1", &base), None);
        f.add_default_route = true;
        f.prefix_hint = " ::/56 ".into();
        assert_eq!(
            f.set_params("*1", &base),
            Some(json!({"id": "*1", "add_default_route": true, "prefix_hint": "::/56"}))
        );
        let row = json!({"id": "*1", "interface": "ether1", "request": "prefix", "pool_name": "pd",
            "default_route_distance": 1, "allowed_servers": ["fe80::1", "0x0003"],
            "use_peer_dns": true, "rapid_commit": true, "accept_prefix_without_address": true});
        let of = Dhcp6Form::of(&row);
        assert_eq!(of.allowed_servers, "fe80::1, 0x0003");
        assert_eq!(of.request, "prefix");
    }
}

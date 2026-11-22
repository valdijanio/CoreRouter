//! PPP › PPPoE Client (G3.9ga), RouterOS `/interface pppoe-client`: the
//! router dialing a provider's PPPoE server. The list window pattern
//! (G0.24, `docs/ui-style.md`): the bar + − ✓ ✗ 💬 and Reconnect, status
//! filter chips, one row per client with its state chip (and why the last
//! session ended), interface by key colour, address, uptime and default
//! route; under the table, the selected client's `monitor`; the add/edit
//! modal fed by `interface.pppoe-client.preview` (default-route clash,
//! MTU, the access risk, the commands).
//!
//! The engine decides everything (status, warnings, defaults); this file
//! only draws and sends `interface.pppoe-client.*`.

use std::collections::BTreeMap;

use egui::{Grid, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::i18n::{Lang, tr_in};
use crate::list::{self, Act, Cmds, Filters, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "pppoe-client";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "pppoe-client";
pub(crate) const TABLE: &str = "pppoe-client";
/// Scope of the window's translations (`i18n/auto/pppoe_client_*.rs`).
const SCOPE: &str = "pppoe_client";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "PPP",
        title: "PPPoE Client",
        size: [1000.0, 620.0],
        escape: true,
    }],
    new: || Box::new(PppoeClientPanel::default()),
};

const CMDS: Cmds = Cmds {
    add: "interface.pppoe-client.add",
    remove: "interface.pppoe-client.remove",
    set: Some("interface.pppoe-client.set"),
    what: "PPPoE clients",
};

const FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "interface.pppoe-client.name", input: Input::Text("automatic: pppoe-outN"), edit: false },
    Field { param: "interface", label: "Interface", help: "interface.pppoe-client.interface", input: Input::Choice, edit: true },
    Field { param: "user", label: "User", help: "interface.pppoe-client.user", input: Input::Text("cliente@provedor"), edit: true },
    Field { param: "password", label: "Password", help: "interface.pppoe-client.password", input: Input::Secret("the provider's password"), edit: true },
    Field { param: "service_name", label: "Service Name", help: "interface.pppoe-client.service_name", input: Input::Text("any"), edit: true },
    Field { param: "ac_name", label: "AC Name", help: "interface.pppoe-client.ac_name", input: Input::Text("any"), edit: true },
    Field { param: "add_default_route", label: "Add Default Route", help: "interface.pppoe-client.add_default_route", input: Input::Check, edit: true },
    Field { param: "default_route_distance", label: "Default Route Distance", help: "interface.pppoe-client.default_route_distance", input: Input::Text("1"), edit: true },
    Field { param: "use_peer_dns", label: "Use Peer DNS", help: "interface.pppoe-client.use_peer_dns", input: Input::Check, edit: true },
    Field { param: "profile", label: "Profile", help: "interface.pppoe-client.profile", input: Input::Text("default"), edit: true },
    Field { param: "max_mtu", label: "Max MTU", help: "interface.pppoe-client.max_mtu", input: Input::Text("1460"), edit: true },
    Field { param: "max_mru", label: "Max MRU", help: "interface.pppoe-client.max_mru", input: Input::Text("1460"), edit: true },
    Field { param: "keepalive_timeout", label: "Keepalive Timeout", help: "interface.pppoe-client.keepalive_timeout", input: Input::Text("60"), edit: true },
    Field { param: "allow", label: "Allow", help: "interface.pppoe-client.allow", input: Input::Text("mschap2,mschap1,chap,pap"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
    Field { param: "disabled", label: "Disabled", help: "interface.pppoe-client.disabled", input: Input::Check, edit: true },
];

pub(crate) const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New PPPoE Client",
    edit_title: "PPPoE Client",
    help: "interface.pppoe-client",
    fields: FIELDS,
    preview: "interface.pppoe-client.preview",
};

const COLUMNS: [table::Column; 9] = [
    col("State").help("interface.pppoe-client.status"),
    col("Name").help("interface.pppoe-client.name"),
    col("Interface").help("interface.pppoe-client.interface"),
    col("User").help("interface.pppoe-client.user"),
    col("Address").help("interface.pppoe-client.address"),
    col("Uptime").help("interface.pppoe-client.uptime"),
    col("MTU").help("interface.pppoe-client.max_mtu"),
    col("Default Route").help("interface.pppoe-client.add_default_route"),
    comment(),
];

/// The status filter chips: (value, label).
const STATES: [(&str, &str); 4] = [
    ("connected", "connected"),
    ("dialing", "dialing"),
    ("disconnected", "disconnected"),
    ("disabled", "disabled"),
];

#[derive(Default)]
pub(crate) struct PppoeClientPanel {
    /// `interface.pppoe-client.list`, while the window is open.
    pub(crate) rows: Vec<Value>,
    /// `interface.pppoe-client.monitor` of the one selected client.
    pub(crate) monitor: Option<Value>,
    pub(crate) filters: Filters,
    pub(crate) modal: Option<Modal>,
    pub(crate) table: TableState,
    help: Option<crate::help::HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(crate::value_text).unwrap_or_default()
}

fn state_kind(status: &str) -> Kind {
    match status {
        "connected" => Kind::Green,
        "dialing" | "connecting" | "authenticating" | "disconnecting" => Kind::Blue,
        "disconnected" | "error" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

/// The status code as a label of the catalog (`tr_in` needs one).
pub(crate) fn status_label(code: &str) -> &'static str {
    match code {
        "connected" => "connected",
        "dialing" => "dialing",
        "connecting" => "connecting",
        "authenticating" => "authenticating",
        "disconnecting" => "disconnecting",
        "disconnected" => "disconnected",
        "disabled" => "disabled",
        "error" => "error",
        _ => "stopped",
    }
}

/// Why the last session ended, as the operator reads it (English label;
/// `tr_in` translates it).
pub(crate) fn reason_label(code: &str) -> &'static str {
    match code {
        "no-offer" => "no server answered",
        "service-error" => "service not offered",
        "ac-error" => "server refused the session",
        "padt" => "server ended the session",
        "lcp" => "link negotiation failed",
        "auth-failed" => "login refused",
        "ncp" => "no address from the server",
        "keepalive" => "server stopped answering",
        "local" => "closed here",
        _ => "down",
    }
}

/// `3d 04:12:05`, RouterOS style.
pub(crate) fn uptime_text(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// The table row of client `r`.
pub(crate) fn row(r: &Value, l: Lang) -> Row {
    let status = s(r, "status");
    let mut chips = vec![(tr_in(SCOPE, l, status_label(&status)).to_owned(), state_kind(&status))];
    let mut note = String::new();
    if status != "connected" && status != "disabled" {
        if let Some(reason) = r.pointer("/last_down/reason").and_then(Value::as_str) {
            chips.push((tr_in(SCOPE, l, reason_label(reason)).to_owned(), Kind::Amber));
        }
        if let Some(n) = r.get("retry_in_secs").and_then(Value::as_u64) {
            note = format!("{} {n} s", tr_in(SCOPE, l, "redial in"));
        }
    }
    let as_cell = |text: &str, chips: &[(String, Kind)]| {
        let c: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
        cell(text, &c)
    };
    let interface = s(r, "interface");
    let route = if r.get("add_default_route").and_then(Value::as_bool).unwrap_or(false) {
        format!("{} {}", tr_in(SCOPE, l, "distance"), s(r, "default_route_distance"))
    } else {
        String::new()
    };
    let mut address = s(r, "local_address");
    if let Some(peer) = r.get("remote_address").and_then(Value::as_str) {
        address = format!("{address}  {} {peer}", tr_in(SCOPE, l, "peer"));
    }
    Row {
        key: s(r, "name"),
        cells: vec![
            as_cell(&note, &chips),
            as_cell("", &[(s(r, "name"), Kind::Neutral)]),
            as_cell("", &[(interface.clone(), Kind::Hashed(chip::name_hue(&interface)))]),
            s(r, "user"),
            address,
            r.get("uptime_secs").and_then(Value::as_u64).map(uptime_text).unwrap_or_default(),
            r.get("mtu").filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_default(),
            route,
            s(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

/// The modal's fields for an existing row.
fn values_of(r: &Value) -> BTreeMap<&'static str, String> {
    let yes = |k: &str| if r.get(k).and_then(Value::as_bool).unwrap_or(false) { "yes" } else { "no" }.to_owned();
    BTreeMap::from([
        ("name", s(r, "name")),
        ("interface", s(r, "interface")),
        ("user", s(r, "user")),
        ("service_name", s(r, "service_name")),
        ("ac_name", s(r, "ac_name")),
        ("add_default_route", yes("add_default_route")),
        ("default_route_distance", s(r, "default_route_distance")),
        ("use_peer_dns", yes("use_peer_dns")),
        ("profile", s(r, "profile")),
        ("max_mtu", s(r, "max_mtu")),
        ("max_mru", s(r, "max_mru")),
        ("keepalive_timeout", s(r, "keepalive_timeout")),
        ("allow", s(r, "allow")),
        ("comment", s(r, "comment")),
        ("disabled", yes("disabled")),
    ])
}

/// What a new client starts with: RouterOS' defaults.
fn defaults() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("default_route_distance", "1".to_owned()),
        ("profile", "default".to_owned()),
        ("max_mtu", "1460".to_owned()),
        ("max_mru", "1460".to_owned()),
        ("keepalive_timeout", "60".to_owned()),
        ("allow", "mschap2,mschap1,chap,pap".to_owned()),
    ])
}

impl PppoeClientPanel {
    /// Tests: act as the bar or the menu would.
    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, ui: &Ui) {
        let rows: Vec<Row> = self.rows.iter().map(|r| row(r, app.lang.labels)).collect();
        self.act(app, a, ui, &rows);
    }

    fn selected(&self) -> Vec<String> {
        let rows: Vec<Row> = self.rows.iter().map(|r| row(r, Lang::default())).collect();
        self.table.selection(&rows).to_vec()
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        let row_of = |k: &str| self.rows.iter().find(|r| s(r, "name") == k).cloned();
        let each = |app: &mut CoreRouterUi, keys: &[String], command: &str| {
            for k in keys {
                app.run(command, json!({ "name": k }));
            }
        };
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    self.modal = Some(Modal::open(app, None, defaults()));
                }
            }
            Act::Edit(k) => {
                if let Some(m) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = row_of(&k) {
                    self.modal = Some(Modal::open(app, Some((k.clone(), k)), values_of(&r)));
                }
            }
            Act::Remove(keys) => each(app, &keys, "interface.pppoe-client.remove"),
            Act::Enable(keys) => each(app, &keys, "interface.pppoe-client.enable"),
            Act::Disable(keys) => each(app, &keys, "interface.pppoe-client.disable"),
            Act::Comment(keys) => {
                // One row at a time through the modal (its comment field).
                if let Some(k) = keys.first() {
                    self.act(app, Act::Edit(k.clone()), ui, rows);
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                // Never the password (the list shows `***`).
                let picked: Vec<Value> = keys
                    .iter()
                    .filter_map(|k| row_of(k))
                    .map(|mut r| {
                        if let Some(o) = r.as_object_mut() {
                            o.remove("password");
                        }
                        r
                    })
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &refs, syntax));
            }
        }
    }

    /// The selected client's `monitor`, under the table.
    fn monitor_pane(&self, ui: &mut Ui, l: Lang) {
        let Some(m) = &self.monitor else {
            ui.weak(tr_in(SCOPE, l, "Select one client to see its session."));
            return;
        };
        let line = |ui: &mut Ui, label: &'static str, value: String| {
            ui.label(tr_in(SCOPE, l, label));
            ui.monospace(if value.is_empty() { "—".to_owned() } else { value });
            ui.end_row();
        };
        Grid::new("pppoe-client-monitor").num_columns(2).striped(true).show(ui, |ui| {
            let status = s(m, "status");
            ui.label(tr_in(SCOPE, l, "Status"));
            chip::chip(ui, tr_in(SCOPE, l, status_label(&status)), state_kind(&status).tone(ui.visuals()));
            ui.end_row();
            line(ui, "Uptime", m.get("uptime_secs").and_then(Value::as_u64).map(uptime_text).unwrap_or_default());
            line(ui, "AC Name", s(m, "ac_name"));
            line(ui, "AC MAC", s(m, "ac_mac"));
            line(ui, "Session ID", s(m, "session_id"));
            line(ui, "Encoding", s(m, "encoding"));
            line(ui, "MTU / MRU", match (s(m, "mtu"), s(m, "mru")) {
                (a, b) if a.is_empty() => b,
                (a, b) => format!("{a} / {b}"),
            });
            line(ui, "Local Address", s(m, "local_address"));
            line(ui, "Remote Address", s(m, "remote_address"));
            let dns: Vec<String> = m.get("dns").and_then(Value::as_array).into_iter().flatten().map(crate::value_text).collect();
            line(ui, "DNS", dns.join(", "));
            line(ui, "Packets in / out", format!("{} / {}", s(m, "rx_packets"), s(m, "tx_packets")));
            line(ui, "Dropped", s(m, "dropped"));
            if let Some(d) = m.get("last_down").filter(|d| !d.is_null()) {
                let reason = tr_in(SCOPE, l, reason_label(&s(d, "reason"))).to_owned();
                let said = d.get("message").and_then(Value::as_str).map(|t| format!(" — \"{t}\"")).unwrap_or_default();
                line(ui, "Last Down", format!("{reason}{said}"));
            }
            if let Some(e) = m.get("last_error").and_then(Value::as_str) {
                line(ui, "Error", e.to_owned());
            }
        });
    }
}

impl PanelState for PppoeClientPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command("interface.pppoe-client.list") {
            return Vec::new();
        }
        let mut out = vec![Query {
            key: "list",
            command: "interface.pppoe-client.list",
            params: Value::Null,
        }];
        if let [one] = self.selected().as_slice() {
            out.push(Query {
                key: "monitor",
                command: "interface.pppoe-client.monitor",
                params: json!({ "name": one }),
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "list" => {
                self.rows = match value {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
            }
            "monitor" => self.monitor = Some(value),
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.rows.clone();
        let shown: Vec<&Value> = all.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| row(r, l)).collect();
        let selection = self.table.selection(&rows);
        if selection.len() != 1 {
            self.monitor = None;
        }
        let picked: Vec<Item> = shown
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let reconnect = app.can().and(
            "interface.pppoe-client.reconnect",
            if picked.iter().any(|i| !i.disabled) {
                Ok(())
            } else {
                Err(tr_in(SCOPE, l, "Select an enabled client first").to_owned())
            },
        );
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            if table::action(ui, tr_in(SCOPE, l, "Reconnect"), reconnect.clone()) {
                for k in &selection {
                    app.run("interface.pppoe-client.reconnect", json!({ "name": k }));
                }
            }
            ui.separator();
            for (value, label) in STATES {
                let on = self.filters.is_on("status", value);
                if list::filter_chip(ui, tr_in(SCOPE, l, label), on) {
                    self.filters.toggle("status", value);
                }
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        // Room under the table: the footer, and the monitor (16 lines) of a
        // single selected client.
        let lines = if selection.len() == 1 { 17.0 } else { 3.0 };
        let footer_h = ui.spacing().interact_size.y * lines;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let picked: Vec<Item> = all
                    .iter()
                    .filter(|r| sel.contains(&s(r, "name")))
                    .map(|r| Item::of(r, "name", ""))
                    .collect();
                let tools = Tools::new(&app.can, &CMDS, &picked);
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New PPPoE Client…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(crate::help::HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "clients", chip::neutral_tone(&v)),
                (list::count(&all, "status", "connected"), "connected", chip::GREEN.tone(&v)),
                (list::count(&all, "status", "disconnected"), "down", chip::AMBER.tone(&v)),
                (list::count(&all, "status", "disabled"), "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        ui.separator();
        self.monitor_pane(ui, l);
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.modal {
            // PPPoE runs on a port, a VLAN, a bond or a bridge.
            let names: Vec<String> = ["ether", "vlan", "bonding", "bridge"]
                .into_iter()
                .flat_map(|k| app.interface_names(Some(k)))
                .collect();
            let open = m.show(app, ctx, area, &SPEC, &|p| if p == "interface" { names.clone() } else { Vec::new() });
            if !open {
                self.modal = None;
            }
        }
        crate::help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
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

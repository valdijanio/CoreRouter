//! RADIUS (G4.3j), RouterOS' `/radius` as its own menu group. One window,
//! three tabs (parts of a window are tabs, `docs/ui-style.md`):
//!
//! - **Servers:** `/radius` in the list pattern (G0.24): the bar + − ✓ ✗ 💬,
//!   the add/edit modal fed by `radius.preview`, a state chip per server
//!   from the monitor, the services as chips, and **Test…**: an
//!   Access-Request for a test user through the router's AAA service, with
//!   the reply's attributes decoded (operator diagnosis; RouterOS has none);
//! - **Incoming:** `/radius incoming` (CoA and Disconnect, RFC 5176): the
//!   settings, where it listens, the allowed sources and the counters;
//! - **Monitor:** `/radius monitor`, live, one row per server.
//!
//! The engine validates and the daemon's `radius` service does the work;
//! the window only shows and sends. Every label carries an ⓘ.

use std::collections::BTreeMap;

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Buttons, Footer, Head, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "radius";
pub(crate) const WIN: &str = "radius";
const SERVERS: &str = "radius-servers";
const MONITOR: &str = "radius-monitor";
const SCOPE: &str = "radius";
const INCOMING_SET: &str = "radius.incoming.set";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "RADIUS",
        title: "RADIUS",
        size: [940.0, 440.0],
        escape: true,
    }],
    new: || Box::<RadiusPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Servers,
    Incoming,
    Monitor,
}

const CMDS: Cmds = Cmds {
    add: "radius.add",
    remove: "radius.remove",
    set: Some("radius.set"),
    what: "servers",
};

const SERVER_COLUMNS: [table::Column; 9] = [
    col("State").help("radius.state"),
    col("Address").help("radius.address"),
    col("Service").help("radius.service"),
    col("Ports").help("radius.ports"),
    num("Timeout").help("radius.timeout"),
    col("Src. Address").help("radius.src_address"),
    col("VRF").help("radius.vrf"),
    col("Message-Auth").help("radius.require_message_auth"),
    comment(),
];

const MONITOR_COLUMNS: [table::Column; 12] = [
    col("State").help("radius.state"),
    col("Server").help("radius.address"),
    num("Pending").help("radius.monitor.pending"),
    num("Requests").help("radius.monitor.requests"),
    num("Accepts").help("radius.monitor.accepts"),
    num("Rejects").help("radius.monitor.rejects"),
    num("Acct").help("radius.monitor.acct_responses"),
    num("Resends").help("radius.monitor.resends"),
    num("Timeouts").help("radius.monitor.timeouts"),
    num("Bad Replies").help("radius.monitor.bad_replies"),
    num("RTT").help("radius.monitor.last_request_rtt"),
    num("Sockets").help("radius.monitor.sockets"),
];

const FIELDS: &[Field] = &[
    Field { param: "address", label: "Address", help: "radius.address", input: Input::Text("10.0.0.10"), edit: true },
    Field { param: "service", label: "Service", help: "radius.service", input: Input::Text("ppp,login"), edit: true },
    Field { param: "secret", label: "Secret", help: "radius.secret", input: Input::Secret("shared secret (unchanged if empty)"), edit: true },
    Field { param: "authentication_port", label: "Authentication Port", help: "radius.authentication_port", input: Input::Text("1812"), edit: true },
    Field { param: "accounting_port", label: "Accounting Port", help: "radius.accounting_port", input: Input::Text("1813"), edit: true },
    Field { param: "timeout", label: "Timeout (ms)", help: "radius.timeout", input: Input::Text("1100"), edit: true },
    Field { param: "src_address", label: "Src. Address", help: "radius.src_address", input: Input::Text("route's address"), edit: true },
    Field { param: "vrf", label: "VRF", help: "radius.vrf", input: Input::Text("main"), edit: true },
    Field { param: "require_message_auth", label: "Require Message-Auth", help: "radius.require_message_auth", input: Input::Choice, edit: true },
    Field { param: "realm", label: "Realm", help: "radius.realm", input: Input::Text("(optional)"), edit: true },
    Field { param: "called_id", label: "Called ID", help: "radius.called_id", input: Input::Text("(optional)"), edit: true },
    Field { param: "accounting_backup", label: "Accounting Backup", help: "radius.accounting_backup", input: Input::Check, edit: true },
    Field { param: "status_server", label: "Status-Server", help: "radius.status_server", input: Input::Check, edit: true },
    Field { param: "disabled", label: "Disabled", help: "radius.disabled", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New RADIUS Server",
    edit_title: "RADIUS Server",
    help: "radius.server",
    fields: FIELDS,
    preview: "radius.preview",
};

/// `/radius incoming`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IncomingForm {
    pub accept: bool,
    pub port: String,
    pub vrf: String,
    pub replay_window: String,
    pub require_event_timestamp: bool,
    pub require_message_auth: bool,
}

impl IncomingForm {
    fn of(v: &Value) -> Self {
        Self {
            accept: flag(v, "accept"),
            port: text(v, "port"),
            vrf: text(v, "vrf"),
            replay_window: text(v, "replay_window"),
            require_event_timestamp: flag(v, "require_event_timestamp"),
            require_message_auth: flag(v, "require_message_auth"),
        }
    }

    pub(crate) fn set_params(&self, base: &Self) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [
            ("accept", self.accept, base.accept),
            ("require_event_timestamp", self.require_event_timestamp, base.require_event_timestamp),
            ("require_message_auth", self.require_message_auth, base.require_message_auth),
        ] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        for (k, now, was) in [("port", &self.port, &base.port), ("replay_window", &self.replay_window, &base.replay_window)] {
            if now.trim() != was.trim() {
                // A number goes as one; anything else as typed (the engine
                // says what is wrong with it).
                let v = now.trim().parse::<u64>().map_or_else(|_| json!(now.trim()), |x| json!(x));
                p.insert(k.into(), v);
            }
        }
        if self.vrf.trim() != base.vrf.trim() {
            p.insert("vrf".into(), json!(self.vrf.trim()));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// Test… : one Access-Request through the router's AAA service.
pub(crate) struct TestDialog {
    pub id: u64,
    pub user: String,
    pub password: String,
    pub service: String,
    /// The task `radius.test` started.
    pub task: Option<u64>,
    /// Its answer (the event), once done.
    pub answer: Option<Value>,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestButton {
    Send,
}

/// Replies: an Apply of Incoming, a toolbar action, a test started.
struct Saved(IncomingForm);
struct Done;
struct TestStarted(u64);

#[derive(Default)]
pub(crate) struct RadiusPanel {
    pub(crate) tab: Tab,
    /// `radius.list`, `radius.monitor`, `radius.incoming.get`.
    pub(crate) servers: Vec<Value>,
    pub(crate) monitor: Vec<Value>,
    pub(crate) incoming: Value,
    pub(crate) form: IncomingForm,
    base: IncomingForm,
    waiting: usize,
    pub(crate) error: Option<String>,
    servers_table: TableState,
    monitor_table: TableState,
    pub(crate) modal: Option<Modal>,
    pub(crate) test: Option<TestDialog>,
    pub(crate) help: Option<HelpView>,
}

fn showing(app: &CoreRouterUi) -> bool {
    app.open.contains(&Win::Panel(WIN))
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

pub(crate) fn state_kind(state: &str) -> Kind {
    match state {
        "up" => Kind::Green,
        "down" => Kind::Red,
        "probing" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

/// A label with its ⓘ; the explanation key is `radius.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("radius-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("radius.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

impl RadiusPanel {
    fn state_of(&self, id: &str) -> String {
        self.monitor
            .iter()
            .find(|m| text(m, "id") == id)
            .map(|m| text(m, "state"))
            .unwrap_or_default()
    }

    pub(crate) fn server_row(&self, r: &Value) -> Row {
        let id = text(r, "id");
        let disabled = flag(r, "disabled");
        let state = match (disabled, self.state_of(&id)) {
            (true, _) => "disabled".to_owned(),
            (false, s) if s.is_empty() => "idle".to_owned(),
            (false, s) => s,
        };
        let services: Vec<String> = r
            .get("service")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        let service_chips: Vec<(&str, Kind)> =
            services.iter().map(|s| (s.as_str(), Kind::Hashed(chip::name_hue(s)))).collect();
        let vrf = text(r, "vrf");
        let ma = text(r, "require_message_auth");
        let mut addr_chips: Vec<(&str, Kind)> = Vec::new();
        if flag(r, "accounting_backup") {
            addr_chips.push(("acct backup", Kind::Blue));
        }
        if flag(r, "status_server") {
            addr_chips.push(("status-server", Kind::Blue));
        }
        Row {
            key: id,
            cells: vec![
                chip::cell("", &[(state.as_str(), state_kind(&state))]),
                chip::cell(&text(r, "address"), &addr_chips),
                chip::cell("", &service_chips),
                format!("{}/{}", text(r, "authentication_port"), text(r, "accounting_port")),
                format!("{} ms", text(r, "timeout")),
                text(r, "src_address"),
                if vrf.is_empty() || vrf == "main" {
                    String::new()
                } else {
                    chip::cell("", &[(vrf.as_str(), Kind::Hashed(chip::name_hue(&vrf)))])
                },
                if ma == "no" {
                    chip::cell("", &[("off", Kind::Amber)])
                } else {
                    chip::cell("", &[("required", Kind::Green)])
                },
                text(r, "comment"),
            ],
            dimmed: disabled,
            section: false,
            tint: None,
        }
    }

    fn monitor_row(&self, m: &Value) -> Row {
        let state = text(m, "state");
        let address = self
            .servers
            .iter()
            .find(|r| text(r, "id") == text(m, "id"))
            .map(|r| text(r, "address"))
            .unwrap_or_else(|| text(m, "address"));
        let warn = |v: u64, k: Kind| if v > 0 { chip::cell("", &[(v.to_string().as_str(), k)]) } else { "0".into() };
        let rtt = n(m, "last_request_rtt");
        Row {
            key: text(m, "id"),
            cells: vec![
                chip::cell("", &[(state.as_str(), state_kind(&state))]),
                address,
                n(m, "pending").to_string(),
                n(m, "requests").to_string(),
                n(m, "accepts").to_string(),
                n(m, "rejects").to_string(),
                n(m, "acct_responses").to_string(),
                warn(n(m, "resends"), Kind::Amber),
                warn(n(m, "timeouts"), Kind::Red),
                warn(n(m, "bad_replies"), Kind::Red),
                match (rtt, n(m, "accepts") + n(m, "rejects") + n(m, "acct_responses")) {
                    (0, 0) => "–".into(),
                    // Answered within the same millisecond (a LAN server).
                    (0, _) => "<1 ms".into(),
                    (ms, _) => format!("{ms} ms"),
                },
                n(m, "sockets").to_string(),
            ],
            dimmed: state == "disabled",
            section: false,
            tint: None,
        }
    }

    fn values(r: &Value) -> BTreeMap<&'static str, String> {
        let yes = |b: bool| if b { "yes" } else { "no" }.to_owned();
        let services = r
            .get("service")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        let mut v: BTreeMap<&'static str, String> = BTreeMap::new();
        for f in FIELDS {
            let val = match f.param {
                "service" => services.clone(),
                // Write-only: the window never has it; empty keeps it.
                "secret" => String::new(),
                p if f.input == Input::Check => yes(flag(r, p)),
                p => text(r, p),
            };
            v.insert(f.param, val);
        }
        v
    }

    fn servers_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.servers.iter().map(|r| self.server_row(r)).collect();
        let sel = self.servers_table.selection(&rows);
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| self.servers.iter().find(|t| text(t, "id") == *k))
            .map(|t| Item::of(t, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        let mut test = false;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, SERVERS, &tools, &sel, l);
            ui.separator();
            let can_test = if self.servers.iter().any(|r| !flag(r, "disabled")) {
                app.can().check("radius.test")
            } else {
                Err(tr_in(SCOPE, l, "Add a server first").to_owned())
            };
            test = table::action(ui, tr_in(SCOPE, l, "Test…"), can_test);
            if help::info_button(ui, Id::unique("radius-help-test"), tr_in(SCOPE, l, "Test…")).clicked() {
                self.help = Some(HelpView::new("radius.test", tr_in(SCOPE, l, "Test…")));
            }
            if help::info_button(ui, Id::unique("radius-help-servers"), tr_in(SCOPE, l, "Servers")).clicked() {
                self.help = Some(HelpView::new("radius.server", tr_in(SCOPE, l, "Servers")));
            }
            table::find_field(ui, SERVERS, &mut self.servers_table);
        });
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, SERVERS, footer_h, &mut self.servers_table, &SERVER_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, true, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New RADIUS Server…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = SERVER_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Act::Edit(k));
        }
        let states: Vec<String> = rows
            .iter()
            .map(|r| chip::split(r.cells.first().map_or("", String::as_str)).1.first().map_or(String::new(), |(_, t)| (*t).to_owned()))
            .collect();
        let count = |s: &str| states.iter().filter(|x| *x == s).count();
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.servers.len(), "servers", chip::neutral_tone(&v)),
                (count("up"), "up", chip::GREEN.tone(&v)),
                (count("probing"), "probing", chip::AMBER.tone(&v)),
                (count("down"), "down", chip::RED.tone(&v)),
                (count("disabled"), "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        if test {
            self.open_test(app);
        }
        if let Some(a) = act {
            self.act(app, a, &rows, ui);
        }
    }

    /// Tests: act as the bar or the menu would.
    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, ui: &Ui) {
        let rows: Vec<Row> = self.servers.iter().map(|r| self.server_row(r)).collect();
        self.act(app, a, &rows, ui);
    }

    pub(crate) fn open_test(&mut self, app: &mut CoreRouterUi) {
        if let Some(t) = &mut self.test {
            t.status.bring_to_front();
            return;
        }
        app.next_dialog = app.next_dialog.wrapping_add(1);
        let service = self
            .servers
            .iter()
            .filter(|r| !flag(r, "disabled"))
            .find_map(|r| r.get("service").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str))
            .unwrap_or("ppp")
            .to_owned();
        self.test = Some(TestDialog {
            id: app.next_dialog,
            user: String::new(),
            password: String::new(),
            service,
            task: None,
            answer: None,
            status: Status::default(),
        });
    }

    fn act(&mut self, app: &mut CoreRouterUi, a: Act, rows: &[Row], ui: &Ui) {
        let step = |command: &str, params: Value| json!({"command": command, "params": params});
        let steps: Vec<Value> = match a {
            Act::Add => {
                let mut v = BTreeMap::new();
                v.insert("service", "ppp".to_owned());
                v.insert("require_message_auth", "yes-for-request-resp".to_owned());
                self.modal = Some(Modal::open(app, None, v));
                return;
            }
            Act::Edit(k) => {
                if let Some(m) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = self.servers.iter().find(|t| text(t, "id") == k) {
                    let name = text(r, "address");
                    self.modal = Some(Modal::open(app, Some((k, name)), Self::values(r)));
                }
                return;
            }
            // The comment is a field of the modal.
            Act::Comment(ids) => {
                if let Some(k) = ids.into_iter().next() {
                    self.act(app, Act::Edit(k), rows, ui);
                }
                return;
            }
            Act::Remove(ids) => ids.iter().map(|id| step(CMDS.remove, json!({"id": id}))).collect(),
            Act::Enable(ids) => ids.iter().map(|id| step("radius.enable", json!({"id": id}))).collect(),
            Act::Disable(ids) => ids.iter().map(|id| step("radius.disable", json!({"id": id}))).collect(),
            Act::Copy(ids) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| ids.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
                return;
            }
            Act::CopyAs(ids, syntax) => {
                let picked: Vec<&Value> = self.servers.iter().filter(|t| ids.contains(&text(t, "id"))).collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &picked, syntax));
                return;
            }
        };
        if !steps.is_empty() {
            app.run_steps(steps, crate::panel::then(NAME, Done));
        }
    }

    fn incoming_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let inc = self.incoming.clone();
        let mut help = self.help.take();
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut help, l, "incoming.listening", "Listening");
            let listening = text(&inc, "listening");
            if listening.is_empty() {
                let why = if flag(&inc, "accept") { "not open" } else { "off" };
                chip::chip(ui, tr_in(SCOPE, l, why), if flag(&inc, "accept") { chip::RED.tone(ui.visuals()) } else { chip::neutral_tone(ui.visuals()) });
            } else {
                chip::chip(ui, &listening, chip::GREEN.tone(ui.visuals()));
            }
            ui.separator();
            for (k, name, kind) in [
                ("requests", "requests", Kind::Neutral),
                ("acks", "ACK", Kind::Green),
                ("naks", "NAK", Kind::Amber),
                ("dropped", "dropped", Kind::Red),
                ("duplicates", "duplicates", Kind::Neutral),
                ("owners", "session owners", Kind::Blue),
            ] {
                let v = n(&inc, k);
                let tone = if v == 0 { chip::neutral_tone(ui.visuals()) } else { kind.tone(ui.visuals()) };
                chip::chip(ui, &format!("{} {v}", tr_in(SCOPE, l, name)), tone);
            }
            let err = text(&inc, "last_error");
            if !err.is_empty() {
                ui.colored_label(ui.visuals().error_fg_color, err);
            }
        });
        ui.separator();
        Grid::new("radius-incoming").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            label(ui, &mut help, l, "incoming.accept", "Accept");
            ui.checkbox(&mut self.form.accept, tr_in(SCOPE, l, "CoA and Disconnect-Request"));
            ui.end_row();
            label(ui, &mut help, l, "incoming.port", "Port");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.form.port).desired_width(70.0));
                ui.weak(tr_in(SCOPE, l, "RFC 5176: 3799 · MikroTik: 1700"));
            });
            ui.end_row();
            label(ui, &mut help, l, "incoming.vrf", "VRF");
            ui.add(TextEdit::singleline(&mut self.form.vrf).desired_width(120.0));
            ui.end_row();
            label(ui, &mut help, l, "incoming.replay_window", "Replay Window (s)");
            ui.add(TextEdit::singleline(&mut self.form.replay_window).desired_width(70.0));
            ui.end_row();
            label(ui, &mut help, l, "incoming.require_event_timestamp", "Require Event-Timestamp");
            ui.checkbox(&mut self.form.require_event_timestamp, "");
            ui.end_row();
            label(ui, &mut help, l, "incoming.require_message_auth", "Require Message-Auth");
            ui.checkbox(&mut self.form.require_message_auth, "");
            ui.end_row();
            label(ui, &mut help, l, "incoming.allowed", "Allowed Sources");
            ui.horizontal_wrapped(|ui| {
                let allowed: Vec<String> = inc
                    .get("allowed")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default();
                if allowed.is_empty() {
                    ui.weak(tr_in(SCOPE, l, "none: add a server in Servers"));
                }
                for a in allowed {
                    chip::chip(ui, &a, chip::neutral_tone(ui.visuals()));
                }
            });
            ui.end_row();
        });
        self.help = help;
        let dirty = self.form.set_params(&self.base).is_some();
        let mut apply = false;
        let mut revert = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err(tr_in(SCOPE, l, "Saving…").to_owned())
            } else if !dirty {
                Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
            } else {
                app.can().check(INCOMING_SET)
            };
            apply = table::action(ui, tr_in(SCOPE, l, "Apply"), ok);
            revert = table::action(ui, tr_in(SCOPE, l, "Revert"), if dirty { Ok(()) } else { Err(tr_in(SCOPE, l, "Nothing changed").to_owned()) });
            if dirty {
                ui.weak(format!("{} {}", dialog::UNSAVED, tr_in(SCOPE, l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(INCOMING_SET, p, crate::panel::then(NAME, Saved(self.form.clone())));
        }
        if revert {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    fn monitor_tab(&mut self, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.monitor.iter().map(|m| self.monitor_row(m)).collect();
        ui.horizontal(|ui| {
            ui.weak(tr_in(SCOPE, l, "Live counters of the router's RADIUS client, per server (authentication and accounting summed)"));
            if help::info_button(ui, Id::unique("radius-help-monitor"), tr_in(SCOPE, l, "Monitor")).clicked() {
                self.help = Some(HelpView::new("radius.monitor", tr_in(SCOPE, l, "Monitor")));
            }
        });
        let out = table::show(ui, MONITOR, 0.0, &mut self.monitor_table, &MONITOR_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = MONITOR_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No RADIUS server yet (Servers: +)"));
        }
    }

    fn test_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut t) = self.test.take() else {
            return;
        };
        let l = app.lang.labels;
        let wid = dialog_id(t.id);
        let head = Head {
            id: wid,
            title: tr_in(SCOPE, l, "RADIUS Test"),
            dirty: false,
            pos: cascade(area, t.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let can = app.can().check("radius.test");
        let running = t.task.is_some() && t.answer.is_none();
        let mut help = self.help.take();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut t.status, |ui, f| {
            let mut pressed = None;
            Grid::new("radius-test").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                label(ui, &mut help, l, "test.user", "User");
                ui.add(TextEdit::singleline(&mut t.user).id(dialog::field_id(f.window(), "user")).desired_width(200.0));
                ui.end_row();
                label(ui, &mut help, l, "test.password", "Password");
                ui.add(TextEdit::singleline(&mut t.password).password(true).id(dialog::field_id(f.window(), "password")).desired_width(200.0));
                ui.end_row();
                label(ui, &mut help, l, "service", "Service");
                ComboBox::from_id_salt("radius-test-service").width(200.0).selected_text(t.service.clone()).show_ui(ui, |ui| {
                    for s in ["ppp", "login", "hotspot", "dhcp", "wireless", "ipsec", "dot1x"] {
                        ui.selectable_value(&mut t.service, s.to_owned(), s);
                    }
                });
                ui.end_row();
            });
            ui.horizontal(|ui| {
                let ok = if running { Err(tr_in(SCOPE, l, "Waiting for the answer…").to_owned()) } else { can.clone() };
                if table::action(ui, tr_in(SCOPE, l, "Send Access-Request"), ok) {
                    pressed = Some(TestButton::Send);
                }
                if running {
                    ui.spinner();
                }
            });
            if let Some(a) = &t.answer {
                ui.separator();
                answer(ui, l, a);
            }
            Footer { buttons: Buttons::View, ok: Ok(()), extra: Vec::new(), pressed }
        });
        self.help = help;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Other(TestButton::Send)) => {
                let mut p = json!({"user": t.user.trim(), "service": t.service});
                if !t.password.is_empty()
                    && let Some(o) = p.as_object_mut()
                {
                    o.insert("password".into(), json!(t.password));
                }
                t.answer = None;
                t.task = None;
                t.status.sent();
                app.run_then("radius.test", p, crate::panel::then(NAME, TestStarted(t.id)));
            }
            _ => {}
        }
        self.test = Some(t);
    }
}

/// The reply of a test: outcome chip, server, round trip, the attributes.
fn answer(ui: &mut Ui, l: Lang, a: &Value) {
    let outcome = text(a, "outcome");
    let kind = match outcome.as_str() {
        "accept" => Kind::Green,
        "reject" => Kind::Red,
        _ => Kind::Amber,
    };
    ui.horizontal_wrapped(|ui| {
        chip::chip(ui, &outcome, kind.tone(ui.visuals()));
        let server = text(a, "server_address");
        if !server.is_empty() {
            ui.label(format!("{} {server} ({})", tr_in(SCOPE, l, "from"), text(a, "server")));
        }
        if let Some(ms) = a.get("rtt_ms").and_then(Value::as_u64) {
            ui.weak(format!("{ms} ms"));
        }
    });
    let message = text(a, "message");
    if !message.is_empty() {
        ui.label(message);
    }
    let attrs = a.get("attributes").and_then(Value::as_array).cloned().unwrap_or_default();
    if attrs.is_empty() {
        return;
    }
    egui::ScrollArea::vertical().max_height(220.0).id_salt("radius-test-attrs").show(ui, |ui| {
        Grid::new("radius-test-reply").num_columns(2).striped(true).spacing([16.0, 2.0]).show(ui, |ui| {
            ui.strong(tr_in(SCOPE, l, "Attribute"));
            ui.strong(tr_in(SCOPE, l, "Value"));
            ui.end_row();
            for at in &attrs {
                ui.label(text(at, "name"));
                let mut v = text(at, "value");
                if let Some(tag) = at.get("tag").and_then(Value::as_u64) {
                    v = format!("{v} (tag {tag})");
                }
                ui.monospace(v);
                ui.end_row();
            }
        });
    });
}

impl PanelState for RadiusPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut q = Vec::new();
        if let Some(id) = self.test.as_ref().filter(|t| t.answer.is_none()).and_then(|t| t.task) {
            q.push(Query { key: "test-poll", command: "tool.task.poll", params: json!({"id": id, "max": 16}) });
        }
        if !showing(app) || !app.has_command("radius.list") {
            return q;
        }
        q.push(Query { key: "list", command: "radius.list", params: json!({}) });
        q.push(Query { key: "monitor", command: "radius.monitor", params: json!({}) });
        if self.tab == Tab::Incoming {
            q.push(Query { key: "incoming", command: "radius.incoming.get", params: json!({}) });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "list" => {
                if let Value::Array(a) = value {
                    self.servers = a;
                }
            }
            "monitor" => {
                if let Value::Array(a) = value {
                    self.monitor = a;
                }
            }
            "incoming" if value.is_object() => {
                let now = IncomingForm::of(&value);
                if self.waiting == 0 && self.form == self.base {
                    self.form = now.clone();
                }
                self.base = now;
                self.incoming = value;
            }
            "test-poll" => {
                if let Some(t) = self.test.as_mut()
                    && value.get("done").and_then(Value::as_bool) == Some(true)
                {
                    let ev = value
                        .get("events")
                        .and_then(Value::as_array)
                        .and_then(|e| e.last())
                        .cloned()
                        .unwrap_or_else(|| json!({"outcome": "error", "message": text(&value, "reason")}));
                    t.answer = Some(ev);
                }
            }
            list_modal::PREVIEW => {
                if let Some(m) = self.modal.as_mut() {
                    m.arrived(value);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let mut help = self.help.take();
        ui.horizontal(|ui| {
            for (t, name, key) in [
                (Tab::Servers, "Servers", "server"),
                (Tab::Incoming, "Incoming", "incoming"),
                (Tab::Monitor, "Monitor", "monitor"),
            ] {
                if ui.selectable_value(&mut self.tab, t, tr_in(SCOPE, l, name)).changed() {
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, Id::unique(("radius-tab", key)), tr_in(SCOPE, l, name)).clicked() {
                    help = Some(HelpView::new(format!("radius.{key}"), tr_in(SCOPE, l, name)));
                }
            }
        });
        self.help = help;
        ui.separator();
        match self.tab {
            Tab::Servers => self.servers_tab(app, ui, l),
            Tab::Incoming => self.incoming_tab(app, ui, l),
            Tab::Monitor => self.monitor_tab(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let options = |p: &str| -> Vec<String> {
            match p {
                "require_message_auth" => vec!["yes-for-request-resp".into(), "no".into()],
                _ => Vec::new(),
            }
        };
        if let Some(m) = self.modal.as_mut()
            && !m.show(app, ctx, area, &SPEC, &options)
        {
            self.modal = None;
        }
        self.test_dialog(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let then = match then.downcast::<Saved>() {
            Ok(s) => {
                self.waiting = self.waiting.saturating_sub(1);
                match result {
                    Ok(_) => {
                        self.error = None;
                        self.base = s.0;
                    }
                    Err(e) => self.error = Some(e.clone()),
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        let then = match then.downcast::<TestStarted>() {
            Ok(s) => {
                if let Some(t) = self.test.as_mut().filter(|t| t.id == s.0) {
                    t.status.replied(result);
                    t.task = result.as_ref().ok().and_then(|v| v.get("id")).and_then(Value::as_u64);
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        if let Ok(a) = then.downcast::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Servers => self.servers_table.escape(),
            Tab::Monitor => self.monitor_table.escape(),
            Tab::Incoming => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(SERVERS, &self.servers_table), (MONITOR, &self.monitor_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(SERVERS, &mut self.servers_table), (MONITOR, &mut self.monitor_table)]
    }
}

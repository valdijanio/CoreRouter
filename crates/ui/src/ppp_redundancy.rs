//! PPP › Redundancy (G4.3h): the active/standby pair of BNGs, a tab of the
//! PPP window. Left, `/ppp redundancy` (`ppp.redundancy.get/set`): the
//! peer (TLS), the mode (stateless / hot standby), the virtual MAC, the
//! fencing and its witness, the timers. Right, the pair now
//! (`ppp.redundancy.monitor`): this node's role, the peer and the two
//! paths it is heard on, the witness, the sync (sessions N/N, lag, delay),
//! config drift and the last role changes; **Switchover** and **Simular
//! falha** each ask first. The engine and the daemon's `ppp-ha` service
//! decide; the tab only shows and sends.

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::chip::{self, AMBER, BLUE, GREEN, RED};
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Buttons, Footer, Head, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{PanelThen, Query};
use crate::table;
use crate::{CoreRouterUi, Win};

const SCOPE: &str = "ppp_ha";
const SET: &str = "ppp.redundancy.set";

/// The form, as text the operator edits (the engine checks it).
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Form {
    pub enabled: bool,
    pub mode: String,
    pub group: String,
    pub peer: String,
    pub listen_port: String,
    /// Empty: unchanged (the secret is write-only).
    pub secret: String,
    pub priority: String,
    pub preempt: bool,
    pub preempt_delay: String,
    pub virtual_mac: String,
    pub interfaces: String,
    pub fencing: String,
    pub witness: String,
    pub track: String,
    pub hello_interval: String,
    pub dead_interval: String,
    pub init_hold: String,
    pub recover_hold: String,
}

fn list(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

fn num(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_u64).map(|n| n.to_string()).unwrap_or_default()
}

fn n(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

impl Form {
    pub(crate) fn of(v: &Value) -> Form {
        Form {
            enabled: flag(v, "enabled"),
            mode: text(v, "mode"),
            group: num(v, "group"),
            peer: text(v, "peer"),
            listen_port: num(v, "listen_port"),
            secret: String::new(),
            priority: num(v, "priority"),
            preempt: flag(v, "preempt"),
            preempt_delay: num(v, "preempt_delay"),
            virtual_mac: text(v, "virtual_mac"),
            interfaces: list(v, "interfaces"),
            fencing: text(v, "fencing"),
            witness: list(v, "witness"),
            track: list(v, "track"),
            hello_interval: num(v, "hello_interval"),
            dead_interval: num(v, "dead_interval"),
            init_hold: num(v, "init_hold"),
            recover_hold: num(v, "recover_hold"),
        }
    }

    /// The `ppp.redundancy.set` params of what changed against `base`.
    pub(crate) fn set_params(&self, base: &Form) -> Option<Value> {
        let mut p = Map::new();
        if self.enabled != base.enabled {
            p.insert("enabled".into(), json!(self.enabled));
        }
        if self.preempt != base.preempt {
            p.insert("preempt".into(), json!(self.preempt));
        }
        let texts = [
            ("mode", &self.mode, &base.mode),
            ("peer", &self.peer, &base.peer),
            ("virtual_mac", &self.virtual_mac, &base.virtual_mac),
            ("fencing", &self.fencing, &base.fencing),
            ("interfaces", &self.interfaces, &base.interfaces),
            ("witness", &self.witness, &base.witness),
            ("track", &self.track, &base.track),
        ];
        for (k, a, b) in texts {
            if a != b {
                p.insert(k.into(), json!(a.trim()));
            }
        }
        let nums = [
            ("group", &self.group, &base.group),
            ("listen_port", &self.listen_port, &base.listen_port),
            ("priority", &self.priority, &base.priority),
            ("preempt_delay", &self.preempt_delay, &base.preempt_delay),
            ("hello_interval", &self.hello_interval, &base.hello_interval),
            ("dead_interval", &self.dead_interval, &base.dead_interval),
            ("init_hold", &self.init_hold, &base.init_hold),
            ("recover_hold", &self.recover_hold, &base.recover_hold),
        ];
        for (k, a, b) in nums {
            if a != b {
                // Not a number: sent as text, and the engine says why.
                let v = a.trim().parse::<u64>().map_or_else(|_| json!(a.trim()), |x| json!(x));
                p.insert(k.into(), v);
            }
        }
        if !self.secret.is_empty() {
            p.insert("secret".into(), json!(self.secret));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// What a confirmation dialog will send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ask {
    Switchover,
    SimulateFailure,
}

struct Confirm {
    id: u64,
    ask: Ask,
    force: bool,
    seconds: String,
    status: Status,
}

/// A reply this tab asked for.
pub(crate) struct Sent(Option<Form>);

#[derive(Default)]
pub(crate) struct RedundancyTab {
    pub(crate) cfg: Value,
    pub(crate) monitor: Value,
    pub(crate) form: Form,
    base: Form,
    waiting: usize,
    pub(crate) error: Option<String>,
    pub(crate) note: Option<String>,
    help: Option<HelpView>,
    confirm: Option<Confirm>,
}

/// A label with its ⓘ; the explanation key is `ppp_ha.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, t: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, t));
        if help::info_button(ui, Id::unique(("ppp-ha-help", key)), tr_in(SCOPE, l, t)).clicked() {
            *help = Some(HelpView::new(format!("ppp_ha.{key}"), tr_in(SCOPE, l, t)));
        }
    });
}

fn role_tone(role: &str, v: &egui::Visuals) -> chip::Tone {
    match role {
        "active" => GREEN.tone(v),
        "standby" => BLUE.tone(v),
        "fenced" => RED.tone(v),
        "yielding" | "init" => AMBER.tone(v),
        _ => chip::neutral_tone(v),
    }
}

fn yes_no(ui: &mut Ui, l: Lang, ok: bool, yes: &'static str, no: &'static str) {
    let v = ui.visuals().clone();
    if ok {
        chip::chip(ui, tr_in(SCOPE, l, yes), GREEN.tone(&v));
    } else {
        chip::chip(ui, tr_in(SCOPE, l, no), RED.tone(&v));
    }
}

impl RedundancyTab {
    pub(crate) fn queries(&self, q: &mut Vec<Query>) {
        q.push(Query { key: "redundancy", command: "ppp.redundancy.get", params: json!({}) });
        q.push(Query { key: "redundancy-monitor", command: "ppp.redundancy.monitor", params: json!({}) });
    }

    /// A query reply; whether it was this tab's.
    pub(crate) fn arrived(&mut self, key: &str, v: Value) -> bool {
        match key {
            "redundancy" if v.is_object() => {
                let now = Form::of(&v);
                if self.waiting == 0 && self.form == self.base {
                    self.form = now.clone();
                }
                self.base = now;
                self.cfg = v;
                true
            }
            "redundancy-monitor" if v.is_object() => {
                self.monitor = v;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn ui(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.columns(2, |cols| {
            if let [left, right] = cols {
                self.settings(app, left, l);
                self.state(app, right, l);
            }
        });
    }

    fn settings(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let mut help = self.help.take();
        ui.strong(tr_in(SCOPE, l, "Settings"));
        Grid::new("ppp-ha-form").num_columns(2).spacing([12.0, 5.0]).show(ui, |ui| {
            label(ui, &mut help, l, "enabled", "Enabled");
            ui.checkbox(&mut self.form.enabled, "");
            ui.end_row();
            label(ui, &mut help, l, "mode", "Mode");
            egui::ComboBox::from_id_salt("ppp-ha-mode")
                .selected_text(self.form.mode.clone())
                .show_ui(ui, |ui| {
                    for m in ["hot-standby", "stateless"] {
                        ui.selectable_value(&mut self.form.mode, m.to_owned(), m);
                    }
                });
            ui.end_row();
            label(ui, &mut help, l, "peer", "Peer (TLS)");
            ui.add(TextEdit::singleline(&mut self.form.peer).hint_text("10.0.0.2:8730").desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "secret", "Secret");
            let hint = if text(&self.cfg, "secret").is_empty() { tr_in(SCOPE, l, "not set") } else { tr_in(SCOPE, l, "set (type to change)") };
            ui.add(TextEdit::singleline(&mut self.form.secret).password(true).hint_text(hint).desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "priority", "Priority");
            ui.add(TextEdit::singleline(&mut self.form.priority).desired_width(60.0));
            ui.end_row();
            label(ui, &mut help, l, "preempt", "Preempt");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.preempt, "");
                ui.label(tr_in(SCOPE, l, "after (s)"));
                ui.add(TextEdit::singleline(&mut self.form.preempt_delay).desired_width(50.0));
            });
            ui.end_row();
            label(ui, &mut help, l, "virtual_mac", "Virtual MAC");
            ui.add(TextEdit::singleline(&mut self.form.virtual_mac).hint_text(text(&self.cfg, "virtual_mac_in_use")).desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "group", "Group");
            ui.add(TextEdit::singleline(&mut self.form.group).desired_width(60.0));
            ui.end_row();
            label(ui, &mut help, l, "interfaces", "Access Ports");
            ui.add(TextEdit::singleline(&mut self.form.interfaces).hint_text(tr_in(SCOPE, l, "every PPPoE server port")).desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "fencing", "Fencing");
            egui::ComboBox::from_id_salt("ppp-ha-fencing")
                .selected_text(self.form.fencing.clone())
                .show_ui(ui, |ui| {
                    for m in ["witness-and-access", "witness", "access"] {
                        ui.selectable_value(&mut self.form.fencing, m.to_owned(), m);
                    }
                });
            ui.end_row();
            label(ui, &mut help, l, "witness", "Witness");
            ui.add(TextEdit::singleline(&mut self.form.witness).hint_text(tr_in(SCOPE, l, "the gateway's address")).desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "track", "Track");
            ui.add(TextEdit::singleline(&mut self.form.track).desired_width(180.0));
            ui.end_row();
            label(ui, &mut help, l, "timers", "Hello / Dead (ms)");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.form.hello_interval).desired_width(50.0));
                ui.label("/");
                ui.add(TextEdit::singleline(&mut self.form.dead_interval).desired_width(50.0));
            });
            ui.end_row();
            label(ui, &mut help, l, "holds", "Init / Recover Hold (s)");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.form.init_hold).desired_width(50.0));
                ui.label("/");
                ui.add(TextEdit::singleline(&mut self.form.recover_hold).desired_width(50.0));
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
                app.can().check(SET)
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
        for w in self.cfg.get("warnings").and_then(Value::as_array).into_iter().flatten() {
            if let Some(w) = w.as_str() {
                ui.colored_label(ui.visuals().warn_fg_color, w);
            }
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(SET, p, crate::panel::then(crate::ppp::NAME, Sent(Some(self.form.clone()))));
        }
        if revert {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    fn state(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let mut help = self.help.take();
        let m = self.monitor.clone();
        let v = ui.visuals().clone();
        ui.strong(tr_in(SCOPE, l, "Pair"));
        if !flag(&m, "running") {
            ui.weak(tr_in(SCOPE, l, "Not running: enable it here, on the daemon with the pppoe service"));
        }
        let role = text(&m, "role");
        Grid::new("ppp-ha-state").num_columns(2).spacing([12.0, 5.0]).show(ui, |ui| {
            label(ui, &mut help, l, "role", "This Node");
            ui.horizontal(|ui| {
                chip::chip(ui, if role.is_empty() { "disabled" } else { role.as_str() }, role_tone(&role, &v));
                if n(&m, "epoch") > 0 {
                    ui.weak(format!("{} {}", tr_in(SCOPE, l, "epoch"), n(&m, "epoch")));
                }
                if let Some(s) = m.get("simulating_secs").and_then(Value::as_u64) {
                    chip::chip(ui, &format!("{} {s}s", tr_in(SCOPE, l, "simulated failure")), AMBER.tone(&v));
                }
            });
            ui.end_row();
            let peer = m.get("peer").cloned().unwrap_or(Value::Null);
            label(ui, &mut help, l, "peer_state", "Peer");
            ui.horizontal(|ui| {
                let pr = text(&peer, "role");
                if pr.is_empty() {
                    chip::chip(ui, tr_in(SCOPE, l, "not heard"), RED.tone(&v));
                } else {
                    chip::chip(ui, &pr, role_tone(&pr, &v));
                }
                yes_no(ui, l, flag(&peer, "connected"), "TLS up", "TLS down");
            });
            ui.end_row();
            label(ui, &mut help, l, "paths", "Heard On");
            ui.horizontal(|ui| {
                yes_no(ui, l, flag(&peer, "sync_path"), "sync link", "sync link");
                yes_no(ui, l, flag(&peer, "access_path"), "access", "access");
            });
            ui.end_row();
            label(ui, &mut help, l, "witness_state", "Witness");
            yes_no(ui, l, flag(&m, "witness"), "reachable", "unreachable");
            ui.end_row();
            let sync = m.get("sync").cloned().unwrap_or(Value::Null);
            label(ui, &mut help, l, "sync", "Sync");
            ui.horizontal(|ui| {
                let (have, total) = (n(&sync, "synced"), n(&sync, "sessions"));
                let tone = if flag(&m, "in_sync") { GREEN.tone(&v) } else { AMBER.tone(&v) };
                chip::chip(ui, &format!("{have}/{total}"), tone);
                ui.weak(format!(
                    "{} {} · {} {} ms",
                    tr_in(SCOPE, l, "lag"),
                    n(&sync, "lag"),
                    tr_in(SCOPE, l, "delay"),
                    n(&sync, "delay_ms")
                ));
                if let Some(s) = sync.get("snapshot").and_then(Value::as_array) {
                    let got = s.first().and_then(Value::as_u64).unwrap_or(0);
                    let of = s.get(1).and_then(Value::as_u64).unwrap_or(0);
                    chip::chip(ui, &format!("{} {got}/{of}", tr_in(SCOPE, l, "snapshot")), BLUE.tone(&v));
                }
            });
            ui.end_row();
            label(ui, &mut help, l, "drift", "Config Drift");
            ui.horizontal_wrapped(|ui| {
                let drift: Vec<&str> = m.get("drift").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
                if drift.is_empty() {
                    chip::chip(ui, tr_in(SCOPE, l, "none"), GREEN.tone(&v));
                }
                for d in drift {
                    chip::chip(ui, d, AMBER.tone(&v));
                }
            });
            ui.end_row();
        });
        if let Some(e) = m.get("last_error").and_then(Value::as_str) {
            ui.colored_label(ui.visuals().warn_fg_color, e);
        }
        ui.horizontal(|ui| {
            let can_switch = if role == "active" { app.can().check("ppp.redundancy.switchover") } else { Err(tr_in(SCOPE, l, "only the active node hands over").to_owned()) };
            if table::action(ui, tr_in(SCOPE, l, "Switchover"), can_switch) {
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.confirm = Some(Confirm { id: app.next_dialog, ask: Ask::Switchover, force: false, seconds: String::new(), status: Status::default() });
            }
            let can_sim = if flag(&m, "running") { app.can().check("ppp.redundancy.simulate-failure") } else { Err(tr_in(SCOPE, l, "redundancy is not running").to_owned()) };
            if table::action(ui, tr_in(SCOPE, l, "Simulate Failure"), can_sim) {
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.confirm = Some(Confirm { id: app.next_dialog, ask: Ask::SimulateFailure, force: false, seconds: "30".into(), status: Status::default() });
            }
            if help::info_button(ui, Id::unique("ppp-ha-actions"), tr_in(SCOPE, l, "Switchover")).clicked() {
                help = Some(HelpView::new("ppp_ha.actions", tr_in(SCOPE, l, "Switchover")));
            }
        });
        if let Some(n) = &self.note {
            ui.weak(n.as_str());
        }
        ui.add_space(6.0);
        label(ui, &mut help, l, "history", "Role Changes");
        let rows: Vec<Value> = m.get("history").and_then(Value::as_array).cloned().unwrap_or_default();
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "none yet"));
        }
        Grid::new("ppp-ha-history").striped(true).spacing([10.0, 3.0]).show(ui, |ui| {
            for r in rows.iter().take(8) {
                ui.weak(crate::system_log::short_time(n(r, "at"), 0));
                ui.horizontal(|ui| {
                    chip::chip(ui, &text(r, "from"), role_tone(&text(r, "from"), &v));
                    ui.label("→");
                    chip::chip(ui, &text(r, "to"), role_tone(&text(r, "to"), &v));
                });
                ui.label(text(r, "reason"));
                if flag(r, "stateful") {
                    chip::chip(ui, tr_in(SCOPE, l, "sessions kept"), GREEN.tone(&v));
                } else {
                    ui.label("");
                }
                ui.end_row();
            }
        });
        self.help = help;
    }

    pub(crate) fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(mut c) = self.confirm.take() {
            let l = app.lang.labels;
            let wid = dialog_id(c.id);
            let title = match c.ask {
                Ask::Switchover => tr_in(SCOPE, l, "Switchover"),
                Ask::SimulateFailure => tr_in(SCOPE, l, "Simulate Failure"),
            };
            let head = Head { id: wid, title, dirty: false, pos: cascade(area, c.id), parent: Some(crate::win_id(Win::Panel(crate::ppp::WIN))) };
            let ask = c.ask;
            let (mut force, mut seconds) = (c.force, c.seconds.clone());
            let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut c.status, |ui, _| {
                match ask {
                    Ask::Switchover => {
                        ui.label(tr_in(SCOPE, l, "This node stops answering and hands every session to the peer, which keeps them (hot standby). If the peer does not take over in 2 s, this node resumes."));
                        ui.checkbox(&mut force, tr_in(SCOPE, l, "even if the peer's copy is incomplete (those subscribers redial)"));
                    }
                    Ask::SimulateFailure => {
                        ui.label(tr_in(SCOPE, l, "This node behaves as dead: no answers, no hellos. The peer takes over for real; this node comes back as standby."));
                        ui.horizontal(|ui| {
                            ui.label(tr_in(SCOPE, l, "Seconds"));
                            ui.add(TextEdit::singleline(&mut seconds).desired_width(50.0));
                        });
                    }
                }
                Footer { buttons: Buttons::Edit { apply: false }, ok: Ok(()), extra: Vec::new(), pressed: None::<()> }
            });
            c.force = force;
            c.seconds = seconds;
            match pressed {
                Some(Press::Ok) => {
                    let (cmd, p) = match c.ask {
                        Ask::Switchover => ("ppp.redundancy.switchover", json!({"force": c.force})),
                        Ask::SimulateFailure => ("ppp.redundancy.simulate-failure", json!({"seconds": c.seconds.trim().parse::<u64>().map_or_else(|_| json!(c.seconds.trim()), |s| json!(s))})),
                    };
                    app.run_then(cmd, p, crate::panel::then(crate::ppp::NAME, Sent(None)));
                    app.floats.forget(wid);
                }
                Some(_) => app.floats.forget(wid),
                None => self.confirm = Some(c),
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    /// A command reply; `Err(then)` when it was not this tab's.
    pub(crate) fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) -> Result<(), PanelThen> {
        let s = then.downcast::<Sent>()?;
        match s.0 {
            Some(form) => {
                self.waiting = self.waiting.saturating_sub(1);
                match result {
                    Ok(_) => {
                        self.error = None;
                        self.base = form;
                        self.form.secret.clear();
                    }
                    Err(e) => self.error = Some(e.clone()),
                }
            }
            None => match result {
                Ok(v) => {
                    self.error = None;
                    self.note = v.get("note").and_then(Value::as_str).map(str::to_owned);
                }
                Err(e) => self.error = Some(e.clone()),
            },
        }
        app.cache.refreshed_at = None;
        Ok(())
    }
}

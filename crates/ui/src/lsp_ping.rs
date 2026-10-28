//! Tools › LSP Ping (G3.5b): MPLS echo along the LSP of a FEC (RFC 8029),
//! Cisco's `ping mpls ipv4` / `traceroute mpls ipv4` and Junos'
//! `ping mpls ldp` in one window — RouterOS has none.
//!
//! Two modes, like Tools › MTR: **Ping** (`tool.mpls.ping.start`: each
//! reply with its round trip and return code, the statistics) and
//! **Traceroute** (`tool.mpls.traceroute.start`: one line per hop with the
//! labels it hands downstream, until the egress or the first error). The
//! one-letter codes operators know from Cisco (`!` egress, `L` switched,
//! `N` no label entry…) are chips coloured by meaning; the full return
//! code is the last column. MPLS › Forwarding Table opens this window on
//! a FEC ("LSP Ping…").

use egui::{Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Row, TableState, col, num};
use crate::windows::combo;
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "lsp-ping";
pub(crate) const WIN: &str = "lsp-ping";
const SCOPE: &str = "lsp_ping";
const PING: &str = "tool.mpls.ping.start";
const TRACE: &str = "tool.mpls.traceroute.start";
const STOP: &str = "tool.task.stop";
const TABLE: &str = "lsp-ping";
/// Events kept (a long ping): the newest.
const MAX_EVENTS: usize = 5000;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "LSP Ping",
        size: [940.0, 440.0],
        escape: true,
    }],
    new: || Box::<LspPingPanel>::default(),
};

const PING_COLUMNS: [table::Column; 5] = [
    num("Seq").help("lsp_ping.col.seq"),
    col("Code").help("lsp_ping.col.code"),
    col("From").help("lsp_ping.col.from"),
    num("Time (ms)").help("lsp_ping.col.time"),
    col("Return Code").help("lsp_ping.col.return_code"),
];

const TRACE_COLUMNS: [table::Column; 7] = [
    num("Hop").help("lsp_ping.col.hop"),
    col("Code").help("lsp_ping.col.code"),
    col("Address").help("lsp_ping.col.from"),
    num("Time (ms)").help("lsp_ping.col.time"),
    num("MTU").help("lsp_ping.col.mtu"),
    col("Labels").help("lsp_ping.col.labels"),
    col("Return Code").help("lsp_ping.col.return_code"),
];

pub(crate) struct LspPingPanel {
    pub(crate) trace: bool,
    pub(crate) fec: String,
    pub(crate) fec_type: String,
    pub(crate) count: String,
    pub(crate) interval: String,
    pub(crate) timeout: String,
    pub(crate) size: String,
    pub(crate) ttl: String,
    pub(crate) max_hops: String,
    pub(crate) exp: String,
    pub(crate) validate: bool,
    pub(crate) task: Option<u64>,
    after: u64,
    starting: bool,
    pub(crate) done: bool,
    pub(crate) state: String,
    pub(crate) summary: Value,
    pub(crate) events: Vec<Value>,
    pub(crate) error: Option<String>,
    help: Option<HelpView>,
    table: TableState,
}

impl Default for LspPingPanel {
    fn default() -> Self {
        Self {
            trace: false,
            fec: String::new(),
            fec_type: "ldp".into(),
            count: "5".into(),
            interval: "1000".into(),
            timeout: "2000".into(),
            size: String::new(),
            ttl: "255".into(),
            max_hops: "30".into(),
            exp: "0".into(),
            validate: true,
            task: None,
            after: 0,
            starting: false,
            done: false,
            state: String::new(),
            summary: Value::Null,
            events: Vec::new(),
            error: None,
            help: None,
            table: TableState::default(),
        }
    }
}

struct Started;
struct Stopped;

fn s(v: &Value, k: &str) -> String {
    v.get(k).filter(|x| !x.is_null()).map(value_text).unwrap_or_default()
}

/// Chip colour of a one-letter return code.
fn letter_kind(letter: &str) -> Kind {
    match letter {
        "!" => Kind::Green,
        "L" | "I" | "l" => Kind::Blue,
        "." | "Q" => Kind::Amber,
        "" | " " => Kind::Neutral,
        _ => Kind::Red,
    }
}

/// The labels a hop hands downstream, as chips (`MPLS 1402`).
fn labels_cell(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    if text == "implicit-null" {
        return cell("", &[("implicit-null", Kind::Neutral)]);
    }
    let chips: Vec<String> = text.split(' ').map(|l| format!("MPLS {l}")).collect();
    let refs: Vec<(&str, Kind)> = chips.iter().map(|c| (c.as_str(), Kind::Blue)).collect();
    cell("", &refs)
}

fn time(v: &Value) -> String {
    v.get("rtt_ms").and_then(Value::as_f64).map(|ms| format!("{ms:.3}")).unwrap_or_default()
}

pub(crate) fn ping_row(e: &Value) -> Row {
    let letter = s(e, "letter");
    Row {
        key: s(e, "seq"),
        cells: vec![
            s(e, "seq"),
            cell("", &[(letter.as_str(), letter_kind(&letter))]),
            s(e, "address"),
            time(e),
            s(e, "detail"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

pub(crate) fn trace_row(e: &Value) -> Row {
    let letter = s(e, "letter");
    let mut detail = s(e, "detail");
    let received = s(e, "received");
    if !received.is_empty() {
        detail = format!("{detail} ({received})");
    }
    let local = s(e, "status") == "local";
    Row {
        key: s(e, "hop"),
        cells: vec![
            s(e, "hop"),
            if local { String::new() } else { cell("", &[(letter.as_str(), letter_kind(&letter))]) },
            s(e, "address"),
            time(e),
            s(e, "mtu"),
            labels_cell(&s(e, "out_label")),
            if local {
                format!("→ {} ({})", s(e, "downstream"), s(e, "interface"))
            } else {
                detail
            },
        ],
        dimmed: local,
        section: false,
        tint: None,
    }
}

/// Open the window on `fec` (MPLS › Forwarding Table's "LSP Ping…").
pub(crate) fn open_with(app: &mut CoreRouterUi, fec: &str, trace: bool) {
    if let Some(p) = app.panel_mut::<LspPingPanel>()
        && !fec.is_empty()
    {
        p.fec = fec.to_owned();
        p.trace = trace;
    }
    if !app.open.insert(Win::Panel(WIN)) {
        app.floats.raise(crate::win_id(Win::Panel(WIN)));
    }
}

impl LspPingPanel {
    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    /// The start command and its parameters from the form (the engine
    /// validates; a field that is not a number goes as typed).
    pub(crate) fn params(&self) -> (&'static str, Value) {
        let mut m = Map::new();
        m.insert("fec".into(), json!(self.fec.trim()));
        m.insert("fec_type".into(), json!(self.fec_type));
        m.insert("validate".into(), json!(self.validate));
        let fields: &[(&str, &String)] = if self.trace {
            &[("max_hops", &self.max_hops), ("timeout_ms", &self.timeout), ("exp", &self.exp)]
        } else {
            &[
                ("count", &self.count),
                ("interval_ms", &self.interval),
                ("timeout_ms", &self.timeout),
                ("size", &self.size),
                ("ttl", &self.ttl),
                ("exp", &self.exp),
            ]
        };
        for (key, v) in fields {
            let v = v.trim();
            match v.parse::<u64>() {
                Ok(n) => {
                    m.insert((*key).into(), json!(n));
                }
                Err(_) if !v.is_empty() => {
                    m.insert((*key).into(), json!(v));
                }
                Err(_) => {}
            }
        }
        (if self.trace { TRACE } else { PING }, Value::Object(m))
    }

    pub(crate) fn start(&mut self, app: &mut CoreRouterUi) {
        let (command, p) = self.params();
        self.starting = true;
        self.error = None;
        self.summary = Value::Null;
        self.events.clear();
        self.after = 0;
        self.done = false;
        self.task = None;
        app.run_then(command, p, crate::panel::then(NAME, Started));
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("lsp-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn field(&mut self, ui: &mut Ui, l: Lang, which: &'static str, title: &'static str, key: &'static str, width: f32) {
        ui.label(tr_in(SCOPE, l, title));
        let v = match which {
            "count" => &mut self.count,
            "interval" => &mut self.interval,
            "timeout" => &mut self.timeout,
            "size" => &mut self.size,
            "ttl" => &mut self.ttl,
            "max_hops" => &mut self.max_hops,
            _ => &mut self.exp,
        };
        ui.add(TextEdit::singleline(v).desired_width(width));
        self.info(ui, l, key, title);
    }

    fn form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let running = self.running();
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                if crate::list::filter_chip(ui, tr_in(SCOPE, l, "Ping"), !self.trace) {
                    self.trace = false;
                }
                if crate::list::filter_chip(ui, tr_in(SCOPE, l, "Traceroute"), self.trace) {
                    self.trace = true;
                }
            });
            self.info(ui, l, "lsp_ping.mode", "Mode");
        });
        let mut enter = false;
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                ui.label(tr_in(SCOPE, l, "FEC"));
                let r = ui.add(TextEdit::singleline(&mut self.fec).hint_text("10.255.0.3/32").desired_width(170.0));
                enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                self.info(ui, l, "lsp_ping.fec", "FEC");
                ui.label(tr_in(SCOPE, l, "FEC Type"));
                combo(ui, "lsp-fec-type", "ldp", &mut self.fec_type, &["ldp".to_owned(), "generic".to_owned()]);
                self.info(ui, l, "lsp_ping.fec_type", "FEC Type");
                ui.checkbox(&mut self.validate, tr_in(SCOPE, l, "Validate FEC"));
                self.info(ui, l, "lsp_ping.validate", "Validate FEC");
            });
        });
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                if self.trace {
                    self.field(ui, l, "max_hops", "Max Hops", "lsp_ping.max_hops", 40.0);
                } else {
                    self.field(ui, l, "count", "Count", "lsp_ping.count", 50.0);
                    self.field(ui, l, "interval", "Interval (ms)", "lsp_ping.interval", 50.0);
                    self.field(ui, l, "size", "Size", "lsp_ping.size", 45.0);
                    self.field(ui, l, "ttl", "TTL", "lsp_ping.ttl", 35.0);
                }
                self.field(ui, l, "exp", "EXP", "lsp_ping.exp", 25.0);
                self.field(ui, l, "timeout", "Timeout (ms)", "lsp_ping.timeout", 50.0);
            });
            ui.separator();
            let can = app.can();
            let command = if self.trace { TRACE } else { PING };
            if running {
                if ui.button(tr_in(SCOPE, l, "Stop")).clicked()
                    && let Some(id) = self.task
                {
                    app.run_then(STOP, json!({"id": id}), crate::panel::then(NAME, Stopped));
                }
            } else {
                let ready = if self.fec.trim().is_empty() {
                    Err(tr_in(SCOPE, l, "Type the FEC (the egress's loopback)").to_owned())
                } else {
                    Ok(())
                };
                let check = can.and(command, ready);
                if (ui
                    .add_enabled(check.is_ok() && !self.starting, egui::Button::new(tr_in(SCOPE, l, "Start")))
                    .on_disabled_hover_text(check.clone().err().unwrap_or_default())
                    .clicked()
                    || (enter && check.is_ok()))
                    && !self.starting
                {
                    self.start(app);
                }
            }
        });
    }

    fn path_line(&mut self, ui: &mut Ui, l: Lang) {
        let Some(path) = self.summary.get("path").filter(|p| !p.is_null()).cloned() else {
            return;
        };
        let v = ui.visuals().clone();
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Path"));
            let out = s(&path, "out_label");
            if out == "implicit-null" {
                chip::chip(ui, "implicit-null", chip::neutral_tone(&v))
                    .on_hover_text(tr_in(SCOPE, l, "The next hop is the egress: the request leaves unlabeled"));
            } else {
                for label in out.split(' ') {
                    chip::chip(ui, &format!("MPLS {label}"), chip::BLUE.tone(&v));
                }
            }
            ui.label(format!("→ {} {} {}", s(&path, "nexthop"), tr_in(SCOPE, l, "on"), s(&path, "interface")));
            let src = s(&path, "src");
            if !src.is_empty() {
                ui.weak(format!("{} {src}", tr_in(SCOPE, l, "from")));
            }
            let paths = self.summary.get("paths").and_then(Value::as_u64).unwrap_or(1);
            if paths > 1 {
                chip::chip(ui, &format!("ECMP {paths}"), chip::AMBER.tone(&v))
                    .on_hover_text(tr_in(SCOPE, l, "The FEC has several paths: the requests follow the first"));
            }
            self.info(ui, l, "lsp_ping.path", "Path");
        });
    }

    fn results(&mut self, ui: &mut Ui, l: Lang) {
        let v = ui.visuals().clone();
        let trace = self.summary.get("mode").and_then(Value::as_str) == Some("traceroute");
        if let Some(e) = &self.error {
            ui.colored_label(crate::err_color(ui), e);
        }
        if self.summary.is_null() {
            if self.task.is_none() && self.error.is_none() {
                ui.weak(tr_in(SCOPE, l, "Sends MPLS echo requests along the LSP of the FEC (RFC 8029). The router at the far end answers if it runs an LSP ping responder (CoreRouter, Cisco, Junos, Nokia)."));
            }
            return;
        }
        self.path_line(ui, l);
        if trace {
            if let Some(r) = self.summary.get("result").and_then(Value::as_str) {
                let tone = if r.starts_with("reached") { chip::GREEN.tone(&v) } else { chip::RED.tone(&v) };
                ui.horizontal(|ui| {
                    chip::chip(ui, tr_in(SCOPE, l, if r.starts_with("reached") { "egress" } else { "stopped" }), tone);
                    ui.label(r);
                });
            }
        } else {
            let st = self.summary.get("stats").cloned().unwrap_or_default();
            ui.horizontal(|ui| {
                let n = |k: &str| s(&st, k);
                ui.label(format!(
                    "{} {}  {} {}  {} {}%",
                    tr_in(SCOPE, l, "sent"),
                    n("sent"),
                    tr_in(SCOPE, l, "received"),
                    n("received"),
                    tr_in(SCOPE, l, "loss"),
                    n("loss_pct")
                ));
                if st.get("avg_ms").is_some_and(Value::is_number) {
                    ui.label(format!("min/avg/max {}/{}/{} ms", n("min_ms"), n("avg_ms"), n("max_ms")));
                }
                for c in self.summary.get("codes").and_then(Value::as_array).into_iter().flatten() {
                    let letter = s(c, "letter");
                    chip::chip(ui, &format!("{letter} ×{}", s(c, "count")), letter_kind(&letter).tone(&v))
                        .on_hover_text(s(c, "meaning"));
                }
            });
        }
        ui.separator();
        let rows: Vec<Row> = if trace {
            self.events.iter().filter(|e| e.get("hop").is_some()).map(trace_row).collect()
        } else {
            self.events.iter().rev().map(ping_row).collect()
        };
        let columns: &[table::Column] = if trace { &TRACE_COLUMNS } else { &PING_COLUMNS };
        let out = table::show(ui, TABLE, 4.0, &mut self.table, columns, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }
}

impl PanelState for LspPingPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        match self.task {
            Some(id) if !self.done && app.open.contains(&Win::Panel(WIN)) => vec![Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": self.after, "max": 256}),
            }],
            _ => Vec::new(),
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key != "poll" || value.get("id").and_then(Value::as_u64) != self.task {
            return;
        }
        if let Some(n) = value.get("next_seq").and_then(Value::as_u64) {
            self.after = n;
        }
        if let Some(s) = value.get("summary").filter(|s| !s.is_null()) {
            self.summary = s.clone();
        }
        for e in value.get("events").and_then(Value::as_array).into_iter().flatten() {
            // A traceroute hop that timed out once and then answered: the
            // answer replaces the "no reply".
            if let Some(hop) = e.get("hop")
                && let Some(prev) = self.events.iter_mut().rev().find(|p| p.get("hop") == Some(hop))
            {
                *prev = e.clone();
                continue;
            }
            self.events.push(e.clone());
        }
        if self.events.len() > MAX_EVENTS {
            let extra = self.events.len() - MAX_EVENTS;
            self.events.drain(..extra);
        }
        self.state = s(&value, "state");
        if value.get("done").and_then(Value::as_bool) == Some(true) {
            self.done = true;
            if self.state == "failed" {
                self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.form(app, ui, l);
        ui.separator();
        self.results(ui, l);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Started>().is_some() {
            self.starting = false;
            match result {
                Ok(v) => {
                    self.task = v.get("task_id").and_then(Value::as_u64);
                    self.state = "running".into();
                }
                Err(e) => {
                    self.error = Some(e.clone());
                    self.done = true;
                }
            }
        } else if then.downcast_ref::<Stopped>().is_some()
            && let Err(e) = result
        {
            self.error = Some(e.clone());
        }
        app.cache.refreshed_at = None;
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

#[cfg(test)]
impl LspPingPanel {
    /// Every explanation key the window uses (the test checks both languages).
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut k: Vec<&'static str> = vec![
            "menu.lsp-ping",
            "lsp_ping.mode",
            "lsp_ping.fec",
            "lsp_ping.fec_type",
            "lsp_ping.validate",
            "lsp_ping.count",
            "lsp_ping.interval",
            "lsp_ping.size",
            "lsp_ping.ttl",
            "lsp_ping.max_hops",
            "lsp_ping.exp",
            "lsp_ping.timeout",
            "lsp_ping.path",
        ];
        k.extend(PING_COLUMNS.iter().chain(&TRACE_COLUMNS).map(|c| c.help));
        k
    }
}

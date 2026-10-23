//! Tools › Torch (G6.4a): an interface's traffic per flow, live — RouterOS'
//! `/tool torch`.
//!
//! The form picks the interface, what the rows are grouped by (chips: src,
//! dst, protocol, port, VLAN, DSCP, MAC) and a filter; Start runs
//! `tool.torch.start` (a task) and the window polls its summary: the top
//! rows of the last interval, the totals, and the interface's own counters.
//!
//! Each row is a conversation seen from the interface: Src. is this side
//! (a subscriber, on an access port), Dst. the far side with its AS pill
//! (the MTR's colours). Next to Src. goes the subscriber's identity chip
//! (G0.25's `ip.identity.lookup`, asked only when the router has it).
//! Sampling, how much the capture saw and the warnings are chips above the
//! table. No logic here: the engine groups, samples and warns.

use std::collections::BTreeMap;

use egui::{Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::list::filter_chip;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Column, Row, TableState, col, num, weak};
use crate::windows::combo;
use crate::{CoreRouterUi, Win, value_text};

const NAME: &str = "torch";
pub(crate) const WIN: &str = "torch";
const TABLE: &str = "torch-rows";
const START: &str = "tool.torch.start";
const STOP: &str = "tool.task.stop";
/// G0.25: who an address belongs to. Asked only when the router has it.
pub(crate) const IDENTITY: &str = "ip.identity.lookup";
/// Rows whose subscriber is asked for at once.
const IDENTITY_BATCH: usize = 64;

/// Grouping fields: engine name, chip label, explanation key.
pub(crate) const GROUPS: [(&str, &str); 7] = [
    ("src", "Src."),
    ("dst", "Dst."),
    ("proto", "Protocol"),
    ("port", "Port"),
    ("vlan", "VLAN"),
    ("dscp", "DSCP"),
    ("mac", "MAC"),
];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "Torch",
        size: [980.0, 520.0],
        escape: true,
    }],
    new: || Box::new(TorchPanel::default()),
};

pub(crate) struct TorchPanel {
    pub(crate) interface: String,
    /// On/off per [`GROUPS`] entry.
    pub(crate) group: [bool; 7],
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) port: String,
    pub(crate) protocol: String,
    /// `auto`, `off` or a rate.
    pub(crate) sampling: String,
    pub(crate) task: Option<u64>,
    pub(crate) starting: bool,
    pub(crate) done: bool,
    pub(crate) state: String,
    pub(crate) summary: Value,
    pub(crate) error: Option<String>,
    /// Subscriber of an address (G0.25), as the router answered.
    pub(crate) identities: BTreeMap<String, String>,
    pub(crate) table: TableState,
    pub(crate) help: Option<HelpView>,
}

impl Default for TorchPanel {
    fn default() -> Self {
        Self {
            interface: String::new(),
            group: [true, true, false, false, false, false, false],
            src: String::new(),
            dst: String::new(),
            port: String::new(),
            protocol: String::new(),
            sampling: "auto".into(),
            task: None,
            starting: false,
            done: false,
            state: String::new(),
            summary: Value::Null,
            error: None,
            identities: BTreeMap::new(),
            table: TableState::default(),
            help: None,
        }
    }
}

struct Started;
struct Stopped;

fn f64_of(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

/// `12.4 Mbps`.
pub(crate) fn rate(bps: f64) -> String {
    let (v, unit) = if bps >= 1e9 {
        (bps / 1e9, "Gbps")
    } else if bps >= 1e6 {
        (bps / 1e6, "Mbps")
    } else if bps >= 1e3 {
        (bps / 1e3, "kbps")
    } else {
        return format!("{bps:.0} bps");
    };
    format!("{v:.1} {unit}")
}

fn pps(n: f64) -> String {
    if n >= 1e6 {
        format!("{:.2} M", n / 1e6)
    } else if n >= 1e4 {
        format!("{:.1} k", n / 1e3)
    } else {
        format!("{n:.0}")
    }
}

/// The scope chip of an address (`privada`, `CGNAT`), as the MTR shows it.
fn scope_chip(scope: &str) -> Option<(&'static str, Kind)> {
    match scope {
        "private" => Some(("privada", Kind::Neutral)),
        "cgnat" => Some(("CGNAT", Kind::Amber)),
        "loopback" => Some(("loopback", Kind::Neutral)),
        "link-local" => Some(("link-local", Kind::Neutral)),
        _ => None,
    }
}

impl TorchPanel {
    fn grouped(&self, field: &str) -> bool {
        GROUPS
            .iter()
            .zip(self.group)
            .any(|((f, _), on)| on && *f == field)
    }

    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    /// `tool.torch.start`'s parameters from the form.
    pub(crate) fn params(&self) -> Value {
        let mut m = Map::new();
        m.insert("interface".into(), json!(self.interface.trim()));
        let group: Vec<&str> = GROUPS
            .iter()
            .zip(self.group)
            .filter_map(|((f, _), on)| on.then_some(*f))
            .collect();
        m.insert("group".into(), json!(group));
        for (key, v) in [
            ("src_address", &self.src),
            ("dst_address", &self.dst),
            ("protocol", &self.protocol),
        ] {
            if !v.trim().is_empty() {
                m.insert(key.into(), json!(v.trim()));
            }
        }
        if let Ok(p) = self.port.trim().parse::<u32>() {
            m.insert("port".into(), json!(p));
        } else if !self.port.trim().is_empty() {
            // Not a number: the engine says why.
            m.insert("port".into(), json!(self.port.trim()));
        }
        if self.sampling != "auto" {
            m.insert("sampling".into(), json!(self.sampling));
        }
        Value::Object(m)
    }

    fn columns(&self) -> Vec<Column> {
        let mut c = Vec::new();
        if self.grouped("vlan") {
            c.push(col("VLAN"));
        }
        if self.grouped("src") {
            c.push(col("Src."));
        }
        if self.grouped("port") {
            c.push(num("Src. Port"));
        }
        if self.grouped("dst") {
            c.push(col("Dst."));
        }
        if self.grouped("port") {
            c.push(num("Dst. Port"));
        }
        if self.grouped("proto") {
            c.push(col("Protocol"));
        }
        if self.grouped("dscp") {
            c.push(num("DSCP"));
        }
        if self.grouped("mac") {
            c.push(weak("MAC"));
        }
        c.extend([num("Tx"), num("Rx"), num("Tx Packets"), num("Rx Packets")]);
        c
    }

    /// One table row from an engine row.
    pub(crate) fn row(&self, r: &Value) -> Row {
        let t = |k: &str| r.get(k).map(value_text).unwrap_or_default();
        let mut cells = Vec::new();
        if self.grouped("vlan") {
            let v = t("vlan");
            cells.push(match r.get("vlan").and_then(Value::as_u64) {
                Some(id) => chip::cell("", &[(v.as_str(), Kind::Hashed(chip::hashed(id)))]),
                None => String::new(),
            });
        }
        if self.grouped("src") {
            let src = t("src");
            let mut chips: Vec<(String, Kind)> = Vec::new();
            if let Some(c) = scope_chip(&t("src_scope")) {
                chips.push((c.0.to_owned(), c.1));
            }
            if let Some(who) = self.identities.get(&src).filter(|w| !w.is_empty()) {
                chips.push((who.clone(), Kind::Hashed(chip::name_hue(who))));
            }
            let refs: Vec<(&str, Kind)> = chips.iter().map(|(s, k)| (s.as_str(), *k)).collect();
            cells.push(chip::cell(&src, &refs));
        }
        if self.grouped("port") {
            cells.push(t("src_port"));
        }
        if self.grouped("dst") {
            let dst = t("dst");
            let mut chips: Vec<(String, Kind)> = Vec::new();
            if let Some(c) = scope_chip(&t("dst_scope")) {
                chips.push((c.0.to_owned(), c.1));
            }
            if let Some(asn) = r.get("asn").and_then(Value::as_u64) {
                let name = t("as_name");
                let pill = if name.is_empty() {
                    format!("AS{asn}")
                } else {
                    format!("AS{asn} {name}")
                };
                chips.push((pill, Kind::Hashed(chip::hashed(asn))));
            }
            let refs: Vec<(&str, Kind)> = chips.iter().map(|(s, k)| (s.as_str(), *k)).collect();
            cells.push(chip::cell(&dst, &refs));
        }
        if self.grouped("port") {
            cells.push(t("dst_port"));
        }
        if self.grouped("proto") {
            cells.push(t("proto"));
        }
        if self.grouped("dscp") {
            cells.push(t("dscp"));
        }
        if self.grouped("mac") {
            cells.push(t("mac"));
        }
        cells.push(rate(f64_of(r, "tx_bps")));
        cells.push(rate(f64_of(r, "rx_bps")));
        cells.push(pps(f64_of(r, "tx_pps")));
        cells.push(pps(f64_of(r, "rx_pps")));
        let key = ["vlan", "src", "src_port", "dst", "dst_port", "proto", "dscp", "mac"]
            .iter()
            .map(|k| t(k))
            .collect::<Vec<_>>()
            .join("|");
        Row {
            key,
            cells,
            dimmed: false,
            section: false,
            tint: None,
        }
    }

    fn rows(&self) -> Vec<Value> {
        self.summary
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str) {
        if help::info_button(ui, Id::unique(("torch-help", key)), tr_in("torch", l, title)).clicked() {
            self.help = Some(HelpView::new(format!("torch.{key}"), tr_in("torch", l, title)));
        }
    }

    fn form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let running = self.running();
        ui.horizontal_wrapped(|ui| {
            ui.label(tr_in("torch", l, "Interface"));
            let names = app.interface_names(None);
            ui.add_enabled_ui(!running, |ui| {
                combo(ui, "torch-iface", tr_in("torch", l, "pick one"), &mut self.interface, &names);
            });
            self.info(ui, l, "interface", "Interface");
            ui.separator();
            ui.label(tr_in("torch", l, "Group by"));
            for (i, (_, label)) in GROUPS.iter().enumerate() {
                let on = self.group.get(i).copied().unwrap_or(false);
                if filter_chip(ui, tr_in("torch", l, label), on)
                    && !running
                    && let Some(g) = self.group.get_mut(i)
                {
                    *g = !*g;
                }
            }
            self.info(ui, l, "group", "Group by");
        });
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            text_field(ui, !running, tr_in("torch", l, "Src."), &mut self.src, "100.64.0.0/10", 120.0);
            self.info(ui, l, "src", "Src.");
            text_field(ui, !running, tr_in("torch", l, "Dst."), &mut self.dst, "0.0.0.0/0", 120.0);
            self.info(ui, l, "dst", "Dst.");
            text_field(ui, !running, tr_in("torch", l, "Port"), &mut self.port, "443", 50.0);
            self.info(ui, l, "port", "Port");
            text_field(ui, !running, tr_in("torch", l, "Protocol"), &mut self.protocol, "tcp", 60.0);
            self.info(ui, l, "protocol", "Protocol");
            ui.separator();
            ui.label(tr_in("torch", l, "Sampling"));
            ui.add_enabled_ui(!running, |ui| {
                let opts: Vec<String> = ["auto", "off", "10", "100", "1000"]
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect();
                combo(ui, "torch-sampling", "auto", &mut self.sampling, &opts);
            });
            self.info(ui, l, "sampling", "Sampling");
            ui.separator();
            let can = app.can();
            if running {
                if ui.button(tr_in("torch", l, "Stop")).clicked()
                    && let Some(id) = self.task
                {
                    app.run_then(STOP, json!({"id": id}), crate::panel::then(NAME, Stopped));
                }
            } else {
                let ready = if self.interface.trim().is_empty() {
                    Err(tr_in("torch", l, "Pick an interface first").to_owned())
                } else {
                    Ok(())
                };
                let check = can.and(START, ready);
                if ui
                    .add_enabled(check.is_ok() && !self.starting, egui::Button::new(tr_in("torch", l, "Start")))
                    .on_disabled_hover_text(check.err().unwrap_or_default())
                    .clicked()
                {
                    self.start(app);
                }
            }
        });
    }

    pub(crate) fn start(&mut self, app: &mut CoreRouterUi) {
        self.starting = true;
        self.error = None;
        self.summary = Value::Null;
        self.done = false;
        self.state.clear();
        self.table = TableState::default();
        app.run_then(START, self.params(), crate::panel::then(NAME, Started));
    }

    /// The chips above the table: sampling, coverage, backend, warnings.
    fn status(&self, ui: &mut Ui, l: Lang) {
        let s = &self.summary;
        ui.horizontal_wrapped(|ui| {
            if !self.state.is_empty() {
                let kind = match self.state.as_str() {
                    "running" => Kind::Green,
                    "failed" | "lost" => Kind::Red,
                    _ => Kind::Neutral,
                };
                chip::chip(ui, &self.state, kind.tone(ui.visuals()));
            }
            let sample = s.get("sampling").and_then(Value::as_u64).unwrap_or(1);
            if sample > 1 {
                chip::chip(ui, &format!("1:{sample}"), chip::AMBER.tone(ui.visuals()))
                    .on_hover_text(tr_in("torch", l, "Sampled: one packet in N is read and counted N times; the rows are estimates"));
            }
            if let Some(seen) = s.get("seen_pct").and_then(Value::as_f64) {
                let kind = if seen >= 90.0 { Kind::Green } else { Kind::Amber };
                chip::chip(ui, &format!("{} {seen:.0} %", tr_in("torch", l, "seen")), kind.tone(ui.visuals()))
                    .on_hover_text(tr_in("torch", l, "Share of the interface's packets (its own counters) the capture read"));
            }
            if let Some(b) = s.get("backend").and_then(Value::as_str) {
                chip::chip(ui, b, chip::neutral_tone(ui.visuals()));
            }
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
        });
        for w in s
            .get("warnings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            ui.colored_label(ui.visuals().warn_fg_color, w);
        }
    }

    /// Totals under the table: what the rows add up to, and the
    /// interface's own counters.
    fn totals(&mut self, ui: &mut Ui, l: Lang) {
        let s = self.summary.clone();
        let line = |v: &Value| {
            format!(
                "Tx {}  Rx {}  ·  {} / {} pps",
                rate(f64_of(v, "tx_bps")),
                rate(f64_of(v, "rx_bps")),
                pps(f64_of(v, "tx_pps")),
                pps(f64_of(v, "rx_pps")),
            )
        };
        ui.horizontal_wrapped(|ui| {
            if let Some(t) = s.get("total") {
                ui.strong(tr_in("torch", l, "Total"));
                ui.label(line(t));
            }
            if let Some(o) = s.get("others").filter(|o| f64_of(o, "rows") > 0.0) {
                ui.separator();
                ui.label(format!("{} {}", f64_of(o, "rows"), tr_in("torch", l, "more rows")));
                ui.weak(line(o));
            }
            if let Some(k) = s.get("kernel") {
                ui.separator();
                ui.label(tr_in("torch", l, "Interface counters"));
                ui.weak(line(k));
                self.info(ui, l, "counters", "Interface counters");
            }
        });
    }

    /// Addresses of the rows whose subscriber is not known yet.
    fn unknown_sources(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .rows()
            .iter()
            .filter_map(|r| r.get("src").and_then(Value::as_str))
            .filter(|a| !self.identities.contains_key(*a))
            .map(str::to_owned)
            .collect();
        out.sort();
        out.dedup();
        out.truncate(IDENTITY_BATCH);
        out
    }
}

impl PanelState for TorchPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(id) = self.task.filter(|_| !self.done) {
            // Only the summary: the rows of the last interval.
            out.push(Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 1u64 << 52, "max": 1}),
            });
        }
        let unknown = self.unknown_sources();
        if self.grouped("src") && !unknown.is_empty() && app.has_command(IDENTITY) {
            out.push(Query {
                key: "identity",
                command: IDENTITY,
                params: json!({"addresses": unknown}),
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "poll" => {
                if let Some(s) = value.get("summary").filter(|s| !s.is_null()) {
                    self.summary = s.clone();
                }
                self.state = value.get("state").and_then(Value::as_str).unwrap_or("").to_owned();
                if value.get("done").and_then(Value::as_bool) == Some(true) {
                    self.done = true;
                    if self.state == "failed" {
                        self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
                    }
                }
            }
            "identity" => absorb_identities(&mut self.identities, &value),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.form(app, ui, l);
        ui.separator();
        self.status(ui, l);
        let columns = self.columns();
        let rows: Vec<Row> = self.rows().iter().map(|r| self.row(r)).collect();
        let reserve = ui.spacing().interact_size.y + 8.0;
        table::show(ui, TABLE, reserve, &mut self.table, &columns, &rows, |_, _| {});
        ui.separator();
        self.totals(ui, l);
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

/// A labelled text box, greyed while `enabled` is false.
fn text_field(ui: &mut Ui, enabled: bool, label: &str, value: &mut String, hint: &str, width: f32) {
    ui.label(label);
    ui.add_enabled(enabled, TextEdit::singleline(value).hint_text(hint).desired_width(width));
}

/// Take `ip.identity.lookup`'s answer: a list of `{address, subscriber}`
/// (or `name` / `login`), or an object by address. Addresses it does not
/// know are remembered as "" so they are not asked again.
pub(crate) fn absorb_identities(into: &mut BTreeMap<String, String>, value: &Value) {
    let who = |v: &Value| -> String {
        match v {
            Value::String(s) => s.clone(),
            Value::Object(o) => ["subscriber", "name", "login", "username"]
                .iter()
                .find_map(|k| o.get(*k).and_then(Value::as_str))
                .unwrap_or("")
                .to_owned(),
            _ => String::new(),
        }
    };
    let rows = value.get("rows").unwrap_or(value);
    match rows {
        Value::Array(a) => {
            for r in a {
                if let Some(addr) = r.get("address").and_then(Value::as_str) {
                    into.insert(addr.to_owned(), who(r));
                }
            }
        }
        Value::Object(o) => {
            for (addr, v) in o {
                into.insert(addr.clone(), who(v));
            }
        }
        _ => {}
    }
    // Keep the map bounded across a long Torch.
    while into.len() > 4096 {
        let Some(first) = into.keys().next().cloned() else { break };
        into.remove(&first);
    }
}

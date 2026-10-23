//! IP › Traffic Flow (G4.4b): IPFIX / NetFlow v9 export, RouterOS'
//! `/ip traffic-flow`. One window, four tabs (parts of a window are tabs,
//! `docs/ui-style.md`):
//!
//! - **General:** the state of the exporter (running, its source, the
//!   kernel's accounting, records a minute, loss) and the settings, an ⓘ
//!   on every label;
//! - **Targets:** the collectors in the list pattern (G0.24): the toolbar,
//!   the add/edit modal with the engine's preview, and per collector its
//!   state, records a minute, templates sent, queue and loss;
//! - **Top Talkers:** subscribers by traffic over the last minutes, from
//!   the router's own records (no collector needed), with the subscriber's
//!   name when the router knows it (`ip.identity.lookup`, G0.25), and the
//!   records as CSV;
//! - **Statistics:** every counter of the exporter.

use std::collections::BTreeMap;

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, num, weak};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "traffic-flow";
pub(crate) const WIN: &str = "traffic-flow";
const TARGETS: &str = "traffic-flow-targets";
const TOP: &str = "traffic-flow-top";
const SET: &str = "ip.traffic-flow.set";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "Traffic Flow",
        size: [900.0, 560.0],
        escape: true,
    }],
    new: || Box::<TrafficFlowPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    General,
    Targets,
    Top,
    Statistics,
}

const TARGET_COLUMNS: [table::Column; 9] = [
    col("State"),
    col("Collector"),
    col("Version"),
    num("Records/min"),
    num("Records"),
    col("Templates"),
    // Chips go after the text: left-aligned, or they would spill over.
    col("Queue"),
    col("Lost"),
    weak("Last Error"),
];

const TOP_COLUMNS: [table::Column; 6] = [
    col("Subscriber"),
    num("Total"),
    num("Up"),
    num("Down"),
    num("Packets"),
    num("Conns"),
];

const CMDS: Cmds = Cmds {
    add: "ip.traffic-flow.target.add",
    remove: "ip.traffic-flow.target.remove",
    set: Some("ip.traffic-flow.target.set"),
    what: "targets",
};

const FIELDS: &[Field] = &[
    Field { param: "dst_address", label: "Dst. Address", help: "traffic-flow.target.dst_address", input: Input::Text("192.0.2.10"), edit: true },
    Field { param: "port", label: "Port", help: "traffic-flow.target.port", input: Input::Text("2055"), edit: true },
    Field { param: "version", label: "Version", help: "traffic-flow.target.version", input: Input::Choice, edit: true },
    Field { param: "transport", label: "Transport", help: "traffic-flow.target.transport", input: Input::Choice, edit: true },
    Field { param: "src_address", label: "Src. Address", help: "traffic-flow.target.src_address", input: Input::Text("route's address"), edit: true },
    Field { param: "template_refresh", label: "Template Refresh", help: "traffic-flow.target.template_refresh", input: Input::Text("20"), edit: true },
    Field { param: "template_timeout", label: "Template Timeout", help: "traffic-flow.target.template_timeout", input: Input::Text("600"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Traffic Flow Target",
    edit_title: "Traffic Flow Target",
    help: "traffic-flow.target",
    fields: FIELDS,
    preview: "ip.traffic-flow.target.preview",
};

/// The settings form, as typed (text, so a half-typed number stays).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Form {
    pub enabled: bool,
    pub interfaces: String,
    pub cache_entries: String,
    pub active_flow_timeout: String,
    pub inactive_flow_timeout: String,
    pub sampling_interval: String,
    pub nat_events: bool,
    pub nat_events_destination: bool,
    pub retention_hours: String,
    pub retention_records: String,
}

/// Number fields: (param, label, unit).
const NUMBERS: &[(&str, &str, &str)] = &[
    ("cache_entries", "Cache Entries", ""),
    ("active_flow_timeout", "Active Flow Timeout", "s"),
    ("inactive_flow_timeout", "Inactive Flow Timeout", "s"),
    ("sampling_interval", "Sampling Interval", "1 in N"),
    ("retention_hours", "Retention", "h"),
    ("retention_records", "Retention Records", ""),
];

fn text(v: &Value, k: &str) -> String {
    v.get(k).filter(|x| !x.is_null()).map(value_text).unwrap_or_default()
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

impl Form {
    fn of(v: &Value) -> Self {
        let interfaces = v
            .get("interfaces")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        Self {
            enabled: flag(v, "enabled"),
            interfaces,
            cache_entries: text(v, "cache_entries"),
            active_flow_timeout: text(v, "active_flow_timeout"),
            inactive_flow_timeout: text(v, "inactive_flow_timeout"),
            sampling_interval: text(v, "sampling_interval"),
            nat_events: flag(v, "nat_events"),
            nat_events_destination: flag(v, "nat_events_destination"),
            retention_hours: text(v, "retention_hours"),
            retention_records: text(v, "retention_records"),
        }
    }

    fn number(&self, k: &str) -> &str {
        match k {
            "cache_entries" => &self.cache_entries,
            "active_flow_timeout" => &self.active_flow_timeout,
            "inactive_flow_timeout" => &self.inactive_flow_timeout,
            "sampling_interval" => &self.sampling_interval,
            "retention_hours" => &self.retention_hours,
            _ => &self.retention_records,
        }
    }

    fn number_mut(&mut self, k: &str) -> &mut String {
        match k {
            "cache_entries" => &mut self.cache_entries,
            "active_flow_timeout" => &mut self.active_flow_timeout,
            "inactive_flow_timeout" => &mut self.inactive_flow_timeout,
            "sampling_interval" => &mut self.sampling_interval,
            "retention_hours" => &mut self.retention_hours,
            _ => &mut self.retention_records,
        }
    }

    /// `ip.traffic-flow.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &Form) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [
            ("enabled", self.enabled, base.enabled),
            ("nat_events", self.nat_events, base.nat_events),
            ("nat_events_destination", self.nat_events_destination, base.nat_events_destination),
        ] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        if self.interfaces.trim() != base.interfaces.trim() {
            p.insert("interfaces".into(), json!(self.interfaces.trim()));
        }
        for (k, _, _) in NUMBERS {
            let (now, was) = (self.number(k).trim(), base.number(k).trim());
            if now != was {
                // A number goes as one; anything else as typed (the engine
                // says what is wrong with it).
                let v = now.parse::<u64>().map_or_else(|_| json!(now), |x| json!(x));
                p.insert((*k).into(), v);
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// An Apply's reply: the form it sent.
struct Saved(Form);
/// A toolbar action's reply (remove, enable, disable, comment).
struct Done;

#[derive(Default)]
pub(crate) struct TrafficFlowPanel {
    pub(crate) tab: Tab,
    pub(crate) get: Value,
    pub(crate) targets: Vec<Value>,
    pub(crate) stats: Value,
    pub(crate) top: Vec<Value>,
    /// Subscriber names by address (`ip.identity.lookup`).
    pub(crate) names: BTreeMap<String, String>,
    pub(crate) form: Form,
    base: Form,
    waiting: usize,
    pub(crate) error: Option<String>,
    pub(crate) minutes: u32,
    pub(crate) by: String,
    targets_table: TableState,
    top_table: TableState,
    pub(crate) modal: Option<Modal>,
    pub(crate) help: Option<HelpView>,
    /// The CSV of the last export, until it is copied to the clipboard.
    csv: Option<String>,
    pub(crate) csv_rows: Option<u64>,
}

fn showing(app: &CoreRouterUi) -> bool {
    app.open.contains(&Win::Panel(WIN))
}

/// `1.2 MiB`.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS.get(u).copied().unwrap_or("B")) }
}

fn state_kind(state: &str) -> Kind {
    match state {
        "running" | "sending" => Kind::Green,
        "error" => Kind::Red,
        "connecting" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

pub(crate) fn target_row(t: &Value) -> Row {
    let disabled = flag(t, "disabled");
    let state = if disabled { "disabled".to_owned() } else { text(t, "state") };
    let collector = format!("{}:{}", text(t, "dst_address"), text(t, "port"));
    let transport = text(t, "transport");
    let version = chip::cell(
        &if text(t, "version") == "9" { "NetFlow v9".to_owned() } else { "IPFIX".to_owned() },
        &[(transport.as_str(), Kind::Neutral)],
    );
    let templates = match t.get("last_template").and_then(Value::as_u64) {
        Some(at) => format!("{} · {}", n(t, "template_sends"), crate::ntp_client::utc(at)),
        None => "–".into(),
    };
    let lost = n(t, "dropped") + n(t, "send_errors");
    // A number that needs a look is a chip with the number itself.
    let lost_cell = if lost > 0 { chip::cell("", &[(lost.to_string().as_str(), Kind::Red)]) } else { "0".into() };
    let queue = n(t, "queue");
    let queue_cell = if queue > 0 { chip::cell("", &[(queue.to_string().as_str(), Kind::Amber)]) } else { "0".into() };
    Row {
        key: text(t, "id"),
        cells: vec![
            chip::cell("", &[(state.as_str(), state_kind(&state))]),
            collector,
            version,
            n(t, "records_per_min").to_string(),
            n(t, "records").to_string(),
            templates,
            queue_cell,
            lost_cell,
            text(t, "last_error"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

fn top_row(r: &Value, name: Option<&String>) -> Row {
    let address = text(r, "address");
    let cell = match name {
        Some(n) => chip::cell(&address, &[(n.as_str(), Kind::Blue)]),
        None => address.clone(),
    };
    Row {
        key: address,
        cells: vec![
            cell,
            bytes(n(r, "bytes")),
            bytes(n(r, "up_bytes")),
            bytes(n(r, "down_bytes")),
            n(r, "packets").to_string(),
            n(r, "flows").to_string(),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// A label with its ⓘ; the explanation key is `traffic-flow.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr(l, text));
        if help::info_button(ui, Id::unique(("tf-help", key)), tr(l, text)).clicked() {
            *help = Some(HelpView::new(format!("traffic-flow.{key}"), tr(l, text)));
        }
    });
}

impl TrafficFlowPanel {
    fn status_strip(&mut self, ui: &mut Ui, l: Lang) {
        let s = &self.stats;
        let state = if text(&self.get, "state").is_empty() { "stopped".to_owned() } else { text(&self.get, "state") };
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut self.help, l, "state", "Status");
            chip::chip(ui, &state, state_kind(&state).tone(ui.visuals()));
            let source = text(s, "source");
            if !source.is_empty() {
                chip::chip(ui, &source, chip::neutral_tone(ui.visuals()))
                    .on_hover_text(tr(l, "Where the flows come from: the kernel's connection tracking, or the lab"));
            }
            for (key, name) in [("accounting", "counters"), ("timestamps", "timestamps")] {
                match s.get(key).and_then(Value::as_bool) {
                    Some(true) => {
                        chip::chip(ui, name, chip::GREEN.tone(ui.visuals()));
                    }
                    Some(false) => {
                        chip::chip(ui, &format!("{name} off"), chip::AMBER.tone(ui.visuals()))
                            .on_hover_text(tr(l, "The kernel does not count or stamp connections: flows without bytes or times"));
                    }
                    None => {}
                }
            }
            ui.separator();
            ui.label(format!("{} {}", n(&self.get, "records_per_min"), tr(l, "records/min")));
            for (key, name, tip) in [
                ("kernel_overruns", "kernel overruns", "Times the kernel dropped events because the exporter fell behind"),
                ("queue_dropped", "queue drops", "Events dropped because the queue between the reader and the exporter was full"),
            ] {
                let v = n(s, key);
                if v > 0 {
                    chip::chip(ui, &format!("{name} {v}"), chip::RED.tone(ui.visuals())).on_hover_text(tr(l, tip));
                }
            }
            let err = text(&self.get, "last_error");
            if !err.is_empty() {
                ui.colored_label(ui.visuals().error_fg_color, err);
            }
        });
    }

    fn general(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let can = app.can();
        let dirty = self.form.set_params(&self.base).is_some();
        let mut help = self.help.take();
        Grid::new("tf-settings").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            label(ui, &mut help, l, "enabled", "Enabled");
            ui.checkbox(&mut self.form.enabled, "");
            ui.end_row();
            label(ui, &mut help, l, "interfaces", "Interfaces");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.form.interfaces).hint_text("all").desired_width(220.0));
                ui.weak(tr(l, "empty = all; ether1,vlan100"));
            });
            ui.end_row();
            for (k, name, unit) in NUMBERS {
                label(ui, &mut help, l, k, name);
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(self.form.number_mut(k)).desired_width(90.0));
                    if !unit.is_empty() {
                        ui.weak(*unit);
                    }
                });
                ui.end_row();
            }
            label(ui, &mut help, l, "nat_events", "NAT Events");
            ui.checkbox(&mut self.form.nat_events, tr(l, "RFC 8158 session create/delete"));
            ui.end_row();
            label(ui, &mut help, l, "nat_events_destination", "NAT Events Destination");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.nat_events_destination, "");
                if self.form.nat_events_destination {
                    chip::chip(ui, "Marco Civil art. 14", chip::AMBER.tone(ui.visuals()))
                        .on_hover_text(tr(l, "A connection provider may not keep application access records (the destination)"));
                } else {
                    ui.weak(tr(l, "source only: the connection log"));
                }
            });
            ui.end_row();
        });
        self.help = help;
        let mut apply = false;
        let mut revert = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err(tr(l, "Saving…").to_owned())
            } else if !dirty {
                Err(tr(l, "Nothing changed").to_owned())
            } else {
                can.check(SET)
            };
            apply = table::action(ui, tr(l, "Apply"), ok);
            revert = table::action(ui, tr(l, "Revert"), if dirty { Ok(()) } else { Err(tr(l, "Nothing changed").to_owned()) });
            if dirty {
                ui.weak(format!("{} {}", crate::dialog::UNSAVED, tr(l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        let warning = text(&self.get, "warning");
        if !warning.is_empty() {
            ui.colored_label(ui.visuals().warn_fg_color, warning);
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(SET, p, crate::panel::then(NAME, Saved(self.form.clone())));
        }
        if revert {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    fn targets_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.targets.iter().map(target_row).collect();
        let sel = self.targets_table.selection(&rows);
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| self.targets.iter().find(|t| text(t, "id") == *k))
            .map(|t| Item::of(t, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TARGETS, &tools, &sel, l);
            if help::info_button(ui, Id::unique("tf-help-targets"), tr(l, "Targets")).clicked() {
                self.help = Some(HelpView::new("traffic-flow.target", tr(l, "Targets")));
            }
            table::find_field(ui, TARGETS, &mut self.targets_table);
        });
        let out = table::show(ui, TARGETS, 24.0, &mut self.targets_table, &TARGET_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu
                && let Some(a) = list::row_menu(ui, &tools, sel, true, l)
            {
                act = Some(a);
            }
        });
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Act::Edit(k));
        }
        let sending = self.targets.iter().filter(|t| text(t, "state") == "sending" && !flag(t, "disabled")).count();
        let failing = self.targets.iter().filter(|t| text(t, "state") == "error").count();
        let off = self.targets.iter().filter(|t| flag(t, "disabled")).count();
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.targets.len(), "targets", chip::neutral_tone(&v)),
                (sending, "sending", chip::GREEN.tone(&v)),
                (failing, "error", chip::RED.tone(&v)),
                (off, "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, a, &rows, ui);
        }
    }

    fn values(t: &Value) -> BTreeMap<&'static str, String> {
        FIELDS.iter().map(|f| (f.param, text(t, f.param))).collect()
    }

    fn act(&mut self, app: &mut CoreRouterUi, a: Act, rows: &[Row], ui: &Ui) {
        let step = |command: &str, params: Value| json!({"command": command, "params": params});
        let steps: Vec<Value> = match a {
            Act::Add => {
                let mut v = BTreeMap::new();
                v.insert("version", "ipfix".to_owned());
                v.insert("transport", "udp".to_owned());
                self.modal = Some(Modal::open(app, None, v));
                return;
            }
            // The comment is a field of the modal.
            Act::Edit(k) => {
                if let Some(t) = self.targets.iter().find(|t| text(t, "id") == k) {
                    let name = format!("{}:{}", text(t, "dst_address"), text(t, "port"));
                    self.modal = Some(Modal::open(app, Some((k, name)), Self::values(t)));
                }
                return;
            }
            Act::Comment(ids) => {
                if let Some(k) = ids.into_iter().next() {
                    self.act(app, Act::Edit(k), rows, ui);
                }
                return;
            }
            Act::Remove(ids) => ids.iter().map(|id| step(CMDS.remove, json!({"id": id}))).collect(),
            Act::Enable(ids) => ids.iter().map(|id| step("ip.traffic-flow.target.set", json!({"id": id, "disabled": false}))).collect(),
            Act::Disable(ids) => ids.iter().map(|id| step("ip.traffic-flow.target.set", json!({"id": id, "disabled": true}))).collect(),
            Act::Copy(ids) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| ids.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
                return;
            }
            Act::CopyAs(ids, syntax) => {
                let picked: Vec<&Value> = self.targets.iter().filter(|t| ids.contains(&text(t, "id"))).collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &picked, syntax));
                return;
            }
        };
        if !steps.is_empty() {
            app.run_steps(steps, crate::panel::then(NAME, Done));
        }
    }

    fn top_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let (mut minutes, mut by) = (self.minutes(), self.by());
        let mut help = false;
        let mut export = false;
        ui.horizontal(|ui| {
            ui.label(tr(l, "Period"));
            ComboBox::from_id_salt("tf-top-minutes")
                .width(80.0)
                .selected_text(format!("{minutes} min"))
                .show_ui(ui, |ui| {
                    for m in [1u32, 5, 15, 60] {
                        ui.selectable_value(&mut minutes, m, format!("{m} min"));
                    }
                });
            ui.label(tr(l, "By"));
            ComboBox::from_id_salt("tf-top-by")
                .width(90.0)
                .selected_text(tr(l, by))
                .show_ui(ui, |ui| {
                    for b in ["bytes", "packets", "flows"] {
                        ui.selectable_value(&mut by, b, tr(l, b));
                    }
                });
            help = help::info_button(ui, Id::unique("tf-help-top"), tr(l, "Top Talkers")).clicked();
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                export = table::action(ui, tr(l, "Copy CSV"), app.can().check("ip.traffic-flow.export"));
                if let Some(r) = self.csv_rows {
                    ui.weak(format!("{r} {}", tr(l, "rows copied")));
                }
            });
        });
        if (minutes, by) != (self.minutes(), self.by()) {
            self.minutes = minutes;
            self.by = by.to_owned();
            app.cache.refreshed_at = None;
        }
        if help {
            self.help = Some(HelpView::new("traffic-flow.top", tr(l, "Top Talkers")));
        }
        if export {
            app.run_then(
                "ip.traffic-flow.export",
                json!({"minutes": minutes * 12}),
                crate::panel::then(NAME, Csv),
            );
        }
        let rows: Vec<Row> = self.top.iter().map(|r| top_row(r, self.names.get(&text(r, "address")))).collect();
        table::show(ui, TOP, 0.0, &mut self.top_table, &TOP_COLUMNS, &rows, |_, _| {});
        if rows.is_empty() {
            ui.weak(tr(l, "No traffic in this window yet (turn Traffic Flow on in General)"));
        }
    }

    fn minutes(&self) -> u32 {
        if self.minutes == 0 { 5 } else { self.minutes }
    }

    fn by(&self) -> &'static str {
        match self.by.as_str() {
            "packets" => "packets",
            "flows" => "flows",
            _ => "bytes",
        }
    }

    fn statistics(&mut self, ui: &mut Ui, l: Lang) {
        let s = self.stats.clone();
        let mut help = self.help.take();
        Grid::new("tf-stats").num_columns(2).spacing([16.0, 4.0]).striped(true).show(ui, |ui| {
            for (key, name) in STATS {
                label(ui, &mut help, l, &format!("stats.{key}"), name);
                let v = match *key {
                    "queue" => format!("{} / {}", n(&s, "queue"), n(&s, "queue_size")),
                    k => s.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_else(|| "–".into()),
                };
                ui.label(v);
                ui.end_row();
            }
        });
        self.help = help;
    }
}

/// The counters of the Statistics tab: (key, label).
const STATS: &[(&str, &str)] = &[
    ("events", "Events"),
    ("kernel_overruns", "Kernel Overruns"),
    ("queue", "Queue"),
    ("queue_dropped", "Queue Drops"),
    ("cache_used", "Cache Used"),
    ("cache_full", "Cache Full"),
    ("sampled_out", "Sampled Out"),
    ("vanished", "Vanished"),
    ("flows", "Flow Records"),
    ("nat_events", "NAT Events"),
    ("records_per_min", "Records/min"),
    ("kept", "Kept Locally"),
    ("evicted", "Evicted"),
];

/// The CSV export's reply.
struct Csv;

impl PanelState for TrafficFlowPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !showing(app) || !app.has_command("ip.traffic-flow.get") {
            return Vec::new();
        }
        let mut q = vec![
            Query { key: "get", command: "ip.traffic-flow.get", params: json!({}) },
            Query { key: "stats", command: "ip.traffic-flow.stats", params: json!({}) },
        ];
        match self.tab {
            Tab::Targets => q.push(Query { key: "targets", command: "ip.traffic-flow.target.list", params: json!({}) }),
            Tab::Top => {
                q.push(Query {
                    key: "top",
                    command: "ip.traffic-flow.top",
                    params: json!({"minutes": self.minutes(), "by": self.by(), "limit": 50}),
                });
                // The subscribers' names, in one batch (G0.25).
                let addresses: Vec<String> = self.top.iter().map(|r| text(r, "address")).collect();
                if !addresses.is_empty() && app.has_command("ip.identity.lookup") {
                    q.push(Query { key: "names", command: "ip.identity.lookup", params: json!({"addresses": addresses}) });
                }
            }
            Tab::General | Tab::Statistics => {}
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "get" if value.is_object() => {
                let now = Form::of(&value);
                if self.waiting == 0 && self.form == self.base {
                    self.form = now.clone();
                }
                self.base = now;
                self.get = value;
            }
            "stats" => self.stats = value,
            "targets" => {
                if let Value::Array(a) = value {
                    self.targets = a;
                }
            }
            "top" => {
                if let Value::Array(a) = value {
                    self.top = a;
                }
            }
            "names" => {
                if let Value::Array(a) = value {
                    self.names = a
                        .iter()
                        .filter_map(|r| {
                            let name = r.get("primary")?.get("name")?.as_str()?.to_owned();
                            Some((text(r, "address"), name))
                        })
                        .collect();
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
        if let Some(csv) = self.csv.take() {
            ui.ctx().copy_text(csv);
        }
        self.status_strip(ui, l);
        ui.horizontal(|ui| {
            for (t, name) in [(Tab::General, "General"), (Tab::Targets, "Targets"), (Tab::Top, "Top Talkers"), (Tab::Statistics, "Statistics")] {
                if ui.selectable_value(&mut self.tab, t, tr(l, name)).changed() {
                    app.cache.refreshed_at = None;
                }
            }
        });
        ui.separator();
        match self.tab {
            Tab::General => self.general(app, ui, l),
            Tab::Targets => self.targets_tab(app, ui, l),
            Tab::Top => self.top_tab(app, ui, l),
            Tab::Statistics => self.statistics(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        let options = |p: &str| -> Vec<String> {
            match p {
                "version" => vec!["ipfix".into(), "9".into()],
                "transport" => vec!["udp".into(), "tcp".into()],
                _ => Vec::new(),
            }
        };
        if let Some(m) = self.modal.as_mut()
            && !m.show(app, ctx, area, &SPEC, &options)
        {
            self.modal = None;
        }
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
        let then = match then.downcast::<Csv>() {
            Ok(_) => {
                if let Ok(v) = result {
                    self.csv = Some(text(v, "csv"));
                    self.csv_rows = Some(n(v, "rows"));
                }
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
            Tab::Targets => self.targets_table.escape(),
            Tab::Top => self.top_table.escape(),
            _ => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TARGETS, &self.targets_table), (TOP, &self.top_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TARGETS, &mut self.targets_table), (TOP, &mut self.top_table)]
    }
}

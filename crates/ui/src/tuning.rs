//! System › Tuning (G1.26): the kernel and hardware settings of a box that
//! forwards packets. Tabs Summary (the machine, the diagnosis, the profile
//! and its actions), Kernel (the parameters as a property list: current,
//! configured, recommended, range, ⓘ), Interfaces, CPU and IRQ, Boot (the
//! next parts, G1.26b–d) and Profiles (the four profiles side by side).
//!
//! The engine calculates everything (`system.tuning.*`); the window shows
//! it, in the languages of Settings (G0.15): labels through `tr`, the ⓘ
//! modal and the engine's reasons in the language of the explanations.

use std::collections::BTreeSet;

use egui::{
    Align, ComboBox, Grid, Id, Layout, RichText, ScrollArea, Sense, TextEdit, Ui, UiBuilder, pos2,
    vec2,
};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, RED, chip, neutral_tone};
use crate::help::{self, HelpView};
use crate::i18n::{self, Lang, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, human_bytes};

const NAME: &str = "tuning";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "tuning";
const PRINT: &str = "system.tuning.parameter.print";
const HARDWARE: &str = "system.tuning.hardware";
const DIAGNOSE: &str = "system.tuning.diagnose";
const SET: &str = "system.tuning.set";
const UNSET: &str = "system.tuning.unset";
const APPLY: &str = "system.tuning.profile.apply";
const DIFF: &str = "system.tuning.profile.diff";
const SAFE_MODE: &str = "config.safe-mode.enter";
const PORT_PRINT: &str = "system.tuning.interface.parameter.print";
const PORT_SET: &str = "system.tuning.interface.set";
const PORT_UNSET: &str = "system.tuning.interface.unset";
const PORT_APPLY: &str = "system.tuning.interface.apply";
const CPU_PRINT: &str = "system.tuning.cpu.parameter.print";
const CPU_SET: &str = "system.tuning.cpu.set";
const CPU_UNSET: &str = "system.tuning.cpu.unset";
const BOOT_PRINT: &str = "system.tuning.boot.parameter.print";
const BOOT_SET: &str = "system.tuning.boot.set";
const BOOT_UNSET: &str = "system.tuning.boot.unset";

/// The Boot sections (G1.26d).
const BOOT_SECTIONS: [&str; 5] = [
    "CPU isolation",
    "Idle states",
    "Power saving",
    "IOMMU",
    "Security",
];

/// The CPU sections (G1.26c), and the port section shown with them.
const CPU_SECTIONS: [&str; 3] = ["Frequency", "Idle states", "Watchdog"];
const CPU_PORT_SECTIONS: [&str; 1] = ["CPU and IRQ"];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Tuning",
        size: [1080.0, 760.0],
        escape: true,
    }],
    new: || Box::new(TuningPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Summary,
    Kernel,
    Interfaces,
    Cpu,
    Boot,
    Profiles,
}

const TABS: [(Tab, &str); 6] = [
    (Tab::Summary, "Summary"),
    (Tab::Kernel, "Kernel"),
    (Tab::Interfaces, "Interfaces"),
    (Tab::Cpu, "CPU and IRQ"),
    (Tab::Boot, "Boot"),
    (Tab::Profiles, "Profiles"),
];

/// Profiles: (engine id, label, query key of the Profiles tab).
const PROFILES: [(&str, &str, &str); 4] = [
    ("conservative", "Conservative", "p-conservative"),
    ("balanced", "Balanced", "p-balanced"),
    ("throughput", "High throughput", "p-throughput"),
    ("latency", "Low latency", "p-latency"),
];

/// The engine's sections, in order (their labels, translated with `tr`).
const SECTIONS: [&str; 6] = [
    "Packet receive",
    "Routing",
    "Connection tracking",
    "Neighbor tables",
    "Stability",
    "Control plane (TCP)",
];

/// The port sections, in order (G1.26b).
const PORT_SECTIONS: [&str; 6] = [
    "Rings and queues",
    "Interrupt coalescing",
    "Offloads",
    "Flow control",
    "Transmit queue",
    "Filtering",
];

/// Whose settings a property list shows: the kernel's or a port's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    Kernel,
    Port(String),
    Cpu,
}

impl Scope {
    /// `i18n` key of `key`'s explanation.
    fn help_key(&self, key: &str) -> String {
        match self {
            Scope::Kernel => format!("tuning.{key}"),
            Scope::Port(_) => format!("tuning.port.{key}"),
            Scope::Cpu => format!("tuning.cpu.{key}"),
        }
    }

    fn set(&self, key: &str, value: i64) -> (&'static str, Value) {
        match self {
            Scope::Kernel => (SET, json!({"name": key, "value": value})),
            Scope::Port(p) => (PORT_SET, json!({"name": p, "key": key, "value": value})),
            Scope::Cpu => (CPU_SET, json!({"key": key, "value": value})),
        }
    }

    fn unset(&self, key: &str) -> (&'static str, Value) {
        match self {
            Scope::Kernel => (UNSET, json!({"name": key})),
            Scope::Port(p) => (PORT_UNSET, json!({"name": p, "key": key})),
            Scope::Cpu => (CPU_UNSET, json!({"key": key})),
        }
    }

    /// The terminal commands that set and unset `key`.
    fn commands(&self, key: &str, value: i64) -> String {
        match self {
            Scope::Kernel => format!(
                "`/system tuning set name={key} value={value}`\n\n`/system tuning unset name={key}`"
            ),
            Scope::Port(p) => format!(
                "`/system tuning interface set name={p} key={key} value={value}`\n\n\
                 `/system tuning interface unset name={p} key={key}`"
            ),
            Scope::Cpu => format!(
                "`/system tuning cpu set key={key} value={value}`\n\n`/system tuning cpu unset key={key}`"
            ),
        }
    }

    fn salt(&self) -> String {
        match self {
            Scope::Kernel => "kernel".into(),
            Scope::Port(p) => format!("port-{p}"),
            Scope::Cpu => "cpu".into(),
        }
    }
}

/// Width of the property list's columns.
const COLS: [f32; 6] = [320.0, 165.0, 150.0, 165.0, 200.0, 28.0];

/// One parameter as `system.tuning.print` describes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Param {
    pub name: String,
    pub section: String,
    pub current: Option<i64>,
    pub configured: Option<i64>,
    pub recommended: Option<i64>,
    pub why: String,
    pub why_id: String,
    pub why_args: Vec<(String, String)>,
    pub min: i64,
    pub max: i64,
    pub unit: String,
    pub choices: Vec<(i64, String)>,
    pub obsolete: bool,
    pub control_plane: bool,
    /// Valid from the next boot (G1.26d).
    pub reboot: bool,
    /// Changing it takes the port down for a moment (G1.26b).
    pub link_flap: bool,
    /// The driver keeps it as it is (an offload marked fixed).
    pub fixed: bool,
}

impl Param {
    fn of(v: &Value) -> Option<Self> {
        let int = |k: &str| v.get(k).and_then(Value::as_i64);
        let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        Some(Self {
            name: v.get("name")?.as_str()?.to_owned(),
            section: text("section"),
            current: int("current"),
            configured: int("configured"),
            recommended: int("recommended"),
            why: text("why"),
            why_id: text("why_id"),
            why_args: v
                .get("why_args")
                .and_then(Value::as_object)
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                        .collect()
                })
                .unwrap_or_default(),
            min: int("min").unwrap_or(0),
            max: int("max").unwrap_or(0),
            unit: text("unit"),
            choices: v
                .get("choices")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|c| {
                            Some((c.get("value")?.as_i64()?, c.get("name")?.as_str()?.to_owned()))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            obsolete: flag("obsolete"),
            control_plane: flag("control_plane"),
            reboot: flag("reboot"),
            link_flap: flag("link_flap"),
            fixed: flag("fixed"),
        })
    }

    /// What the kernel will have: the configured value, else the current.
    fn effective(&self) -> Option<i64> {
        self.configured.or(self.current)
    }

    /// The recommendation differs from what the router has.
    pub(crate) fn differs(&self) -> bool {
        self.current.is_some()
            && self
                .recommended
                .is_some_and(|r| Some(r) != self.effective())
    }

    /// `v` as the operator reads it: a choice's name, bytes in KiB/MiB.
    pub(crate) fn value_text(&self, v: i64) -> String {
        if let Some((_, n)) = self.choices.iter().find(|(c, _)| *c == v) {
            return format!("{v} ({n})");
        }
        let bytes = |b: i64| human_bytes(u64::try_from(b).unwrap_or(0));
        match self.unit.as_str() {
            "B" => bytes(v),
            "KiB" => bytes(v.saturating_mul(1024)),
            "s" | "µs" => format!("{} {}", grouped(v), self.unit),
            _ => grouped(v),
        }
    }

    fn range_text(&self) -> String {
        if self.choices.is_empty() {
            format!("{} – {}", grouped(self.min), grouped(self.max))
        } else {
            self.choices
                .iter()
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    /// The reason in the language of the explanations.
    fn why_text(&self, lang: Lang) -> String {
        // The profile's engine id reads as its label.
        let args: Vec<(&str, &str)> = self
            .why_args
            .iter()
            .map(|(k, v)| {
                let label = PROFILES
                    .iter()
                    .find(|(id, ..)| k == "profile" && id == v)
                    .map(|(_, label, _)| tr(lang, label));
                (k.as_str(), label.unwrap_or(v.as_str()))
            })
            .collect();
        i18n::template(lang, &format!("why.{}", self.why_id), &args, &self.why)
    }
}

/// `6684672` → `6 684 672` (from five digits on: `7440` stays).
pub(crate) fn grouped(v: i64) -> String {
    let digits = v.unsigned_abs().to_string();
    if digits.len() < 5 {
        return v.to_string();
    }
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    if v < 0 { format!("-{out}") } else { out }
}

pub(crate) fn params(print: &Value) -> Vec<Param> {
    print
        .get("params")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Param::of).collect())
        .unwrap_or_default()
}

/// A command reply.
enum Reply {
    Changed,
    Diff,
}

#[derive(Default)]
pub(crate) struct TuningPanel {
    pub(crate) tab: Tab,
    /// Engine id of the profile the Recommended column follows.
    pub(crate) profile: &'static str,
    pub(crate) print: Option<Value>,
    hardware: Option<Value>,
    pub(crate) diagnosis: Option<Value>,
    /// The Profiles tab: `print` of each profile, by query key.
    compare: Vec<(&'static str, Value)>,
    pub(crate) find: String,
    collapsed: BTreeSet<String>,
    pub(crate) selected: Option<String>,
    /// The value typed for the selected parameter.
    pub(crate) edit: String,
    pub(crate) error: Option<String>,
    waiting: usize,
    pub(crate) help: Option<HelpView>,
    /// `system.tuning.profile.diff` shown in a modal.
    pub(crate) diff: Option<Value>,
    /// The Interfaces tab: the port shown and its settings.
    pub(crate) port: Option<String>,
    pub(crate) port_print: Option<Value>,
    /// The CPU and IRQ tab: `system.tuning.cpu.parameter.print`.
    pub(crate) cpu_print: Option<Value>,
    /// The Boot tab: `system.tuning.boot.parameter.print`, and the
    /// confirmation `mitigations=off` asks for.
    pub(crate) boot_print: Option<Value>,
    pub(crate) boot_confirm: bool,
}

impl TuningPanel {
    fn profile(&self) -> &'static str {
        if self.profile.is_empty() {
            "balanced"
        } else {
            self.profile
        }
    }

    fn rows(&self) -> Vec<Param> {
        self.print.as_ref().map(params).unwrap_or_default()
    }
}

impl PanelState for TuningPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(PRINT) {
            return Vec::new();
        }
        let mut q = vec![Query {
            key: "print",
            command: PRINT,
            params: json!({"profile": self.profile()}),
        }];
        if self.tab == Tab::Boot && app.has_command(BOOT_PRINT) {
            q.push(Query {
                key: "boot",
                command: BOOT_PRINT,
                params: json!({"profile": self.profile()}),
            });
        }
        if self.tab == Tab::Cpu && app.has_command(CPU_PRINT) {
            q.push(Query {
                key: "cpu",
                command: CPU_PRINT,
                params: json!({"profile": self.profile()}),
            });
        }
        if matches!(self.tab, Tab::Interfaces | Tab::Cpu)
            && let Some(port) = &self.port
            && app.has_command(PORT_PRINT)
        {
            q.push(Query {
                key: "port",
                command: PORT_PRINT,
                params: json!({"name": port, "profile": self.profile()}),
            });
        }
        if matches!(self.tab, Tab::Summary | Tab::Interfaces | Tab::Cpu) {
            q.push(Query {
                key: "hardware",
                command: HARDWARE,
                params: json!({}),
            });
            q.push(Query {
                key: "diagnose",
                command: DIAGNOSE,
                params: json!({}),
            });
        }
        if self.tab == Tab::Profiles {
            q.extend(PROFILES.iter().map(|(id, _, key)| Query {
                key,
                command: PRINT,
                params: json!({"profile": id, "tab": "kernel"}),
            }));
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "print" => self.print = Some(value),
            "hardware" => {
                // The Interfaces tab starts on the first port.
                if self.port.is_none() {
                    self.port = value
                        .get("nics")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(|n| n.get("name"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
                self.hardware = Some(value);
            }
            "port" => self.port_print = Some(value),
            "cpu" => self.cpu_print = Some(value),
            "boot" => self.boot_print = Some(value),
            "diagnose" => self.diagnosis = Some(value),
            k => {
                if let Some(slot) = self.compare.iter_mut().find(|(c, _)| *c == k) {
                    slot.1 = value;
                } else {
                    self.compare.push((k, value));
                }
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        self.diff_modal(app, ctx);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        self.waiting = self.waiting.saturating_sub(1);
        match (*r, result) {
            (_, Err(e)) => self.error = Some(e.clone()),
            (Reply::Changed, Ok(_)) => self.error = None,
            (Reply::Diff, Ok(v)) => self.diff = Some(v.clone()),
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        if !self.find.is_empty() {
            self.find.clear();
            true
        } else {
            self.selected.take().is_some()
        }
    }
}

impl TuningPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        if !app.has_command(PRINT) {
            ui.weak(tr(
                l,
                "This router has no System › Tuning yet: update corerouter-daemon.",
            ));
            return;
        }
        ui.horizontal(|ui| {
            for (tab, label) in TABS {
                if ui.selectable_label(self.tab == tab, tr(l, label)).clicked() {
                    if self.tab != tab {
                        self.selected = None;
                    }
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let current = PROFILES
                    .iter()
                    .find(|(id, ..)| *id == self.profile())
                    .map_or("", |(_, label, _)| *label);
                let before = self.profile();
                let mut picked = before;
                ComboBox::from_id_salt("tuning-profile")
                    .selected_text(tr(l, current))
                    .show_ui(ui, |ui| {
                        for (id, label, _) in PROFILES {
                            ui.selectable_value(&mut picked, id, tr(l, label));
                        }
                    });
                ui.label(tr(l, "Profile"));
                if picked != before {
                    self.profile = picked;
                    app.cache.refreshed_at = None;
                }
            });
        });
        ui.separator();
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        match self.tab {
            Tab::Summary => self.summary(app, ui),
            Tab::Kernel => self.kernel(app, ui),
            Tab::Profiles => self.profiles(app, ui),
            Tab::Interfaces => self.interfaces(app, ui),
            Tab::Cpu => self.cpu(app, ui),
            Tab::Boot => self.boot(app, ui),
        }
    }

    // ---- Summary ----------------------------------------------------------

    fn summary(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.strong(tr(l, "Hardware"));
            match &self.hardware {
                Some(hw) => hardware(ui, l, hw),
                None => {
                    ui.weak(tr(l, "waiting for the router…"));
                }
            }
            ui.add_space(8.0);
            ui.strong(tr(l, "Diagnosis"));
            self.findings(app, ui);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.strong(tr(l, "Profile"));
                if help::info_button(ui, Id::unique("tuning-profiles-help"), tr(l, "Profiles"))
                    .clicked()
                {
                    self.help = Some(HelpView::new("tuning.profiles", tr(l, "Profiles")));
                }
            });
            self.profile_actions(app, ui);
        });
    }

    fn findings(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let list: Vec<Value> = self
            .diagnosis
            .as_ref()
            .and_then(|d| d.get("findings"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if self.diagnosis.is_none() {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        }
        if list.is_empty() {
            ui.weak(tr(l, "Nothing to report: the counters look healthy."));
            return;
        }
        let can = app.can();
        for f in list {
            let text = |k: &str| f.get(k).and_then(Value::as_str).unwrap_or("");
            let args: Vec<(String, String)> = f
                .get("args")
                .and_then(Value::as_object)
                .map(|o| {
                    o.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let says = i18n::template(
                app.lang.help,
                &format!("finding.{}", text("id")),
                &args,
                text("text"),
            );
            ui.horizontal_wrapped(|ui| {
                let v = ui.visuals().clone();
                let (label, tone) = match text("severity") {
                    "critical" => ("critical", RED.tone(&v)),
                    "warning" => ("warning", AMBER.tone(&v)),
                    _ => ("info", BLUE.tone(&v)),
                };
                chip(ui, tr(l, label), tone);
                ui.label(says);
                let param = f.get("param").and_then(Value::as_str);
                let value = f.get("suggest").and_then(Value::as_i64);
                if let (Some(p), Some(v)) = (param, value)
                    && action(ui, &format!("{} {p} = {v}", tr(l, "Set")), can.check(SET))
                {
                    self.waiting += 1;
                    app.run_then(
                        SET,
                        json!({"name": p, "value": v}),
                        crate::panel::then(NAME, Reply::Changed),
                    );
                }
            });
        }
    }

    fn profile_actions(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows = self.rows();
        let n = rows.iter().filter(|p| p.differs()).count();
        let label = PROFILES
            .iter()
            .find(|(id, ..)| *id == self.profile())
            .map_or("", |(_, label, _)| *label);
        ui.label(format!(
            "{}: {n} {}",
            tr(l, label),
            tr(l, "parameters differ from this profile.")
        ));
        ui.horizontal(|ui| {
            let can = app.can();
            if action(ui, tr(l, "Show differences"), can.check(DIFF)) {
                self.waiting += 1;
                app.run_then(
                    DIFF,
                    json!({"profile": self.profile()}),
                    crate::panel::then(NAME, Reply::Diff),
                );
            }
            let ok = if n == 0 {
                Err(tr(l, "Nothing to change").to_owned())
            } else {
                safe_mode_ok(app).and_then(|()| can.check(APPLY))
            };
            if action(ui, tr(l, "Apply with Safe Mode"), ok) {
                self.apply_profile(app);
            }
        });
        ui.weak(tr(
            l,
            "Safe Mode: confirm with the Safe Mode button on the top bar; if the connection drops, every change goes back.",
        ));
    }

    fn apply_profile(&mut self, app: &mut CoreRouterUi) {
        if !safe_mode_mine(app) {
            app.run(SAFE_MODE, json!({}));
        }
        self.waiting += 1;
        app.run_then(
            APPLY,
            json!({"profile": self.profile()}),
            crate::panel::then(NAME, Reply::Changed),
        );
    }

    fn diff_modal(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context) {
        let Some(diff) = &self.diff else {
            return;
        };
        let l = app.lang.labels;
        let rows: Vec<Value> = diff.as_array().cloned().unwrap_or_default();
        let by_name = self.rows();
        let mut apply = false;
        let shown = egui::Modal::new(Id::unique("tuning-diff")).show(ctx, |ui| {
            ui.set_max_width(1100.0);
            ui.label(RichText::new(tr(l, "Show differences")).strong().heading());
            ui.separator();
            if rows.is_empty() {
                ui.weak(tr(l, "Nothing to change"));
            }
            ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                Grid::new("tuning-diff-grid")
                    .striped(true)
                    .num_columns(4)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong(tr(l, "Parameter"));
                        ui.strong(tr(l, "Current"));
                        ui.strong(tr(l, "Recommended"));
                        ui.strong(tr(l, "Why"));
                        ui.end_row();
                        for r in &rows {
                            let name = r.get("name").and_then(Value::as_str).unwrap_or("");
                            let p = by_name.iter().find(|p| p.name == name);
                            let show = |v: Option<i64>| match (v, p) {
                                (Some(v), Some(p)) => p.value_text(v),
                                (Some(v), None) => v.to_string(),
                                (None, _) => "–".into(),
                            };
                            let now = r
                                .get("configured")
                                .and_then(Value::as_i64)
                                .or_else(|| r.get("current").and_then(Value::as_i64));
                            let why = p.map_or_else(
                                || r.get("why").and_then(Value::as_str).unwrap_or("").to_owned(),
                                |p| p.why_text(app.lang.help),
                            );
                            ui.label(name);
                            ui.label(show(now));
                            ui.strong(show(r.get("recommended").and_then(Value::as_i64)));
                            ui.weak(why);
                            ui.end_row();
                        }
                    });
            });
            ui.separator();
            let mut close = false;
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    close = ui.button(tr(l, "Close")).clicked();
                    let ok = if rows.is_empty() {
                        Err(tr(l, "Nothing to change").to_owned())
                    } else {
                        safe_mode_ok(app).and_then(|()| app.can().check(APPLY))
                    };
                    apply = action(ui, tr(l, "Apply with Safe Mode"), ok);
                });
            });
            close || apply
        });
        if apply {
            self.apply_profile(app);
        }
        if shown.inner || shown.should_close() {
            self.diff = None;
        }
    }

    // ---- Kernel -------------------------------------------------------------

    fn kernel(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows = self.rows();
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.find)
                    .hint_text(tr(l, "Find"))
                    .desired_width(220.0),
            );
            if self.print.as_ref().and_then(|p| p.get("machine")) == Some(&Value::Bool(false)) {
                ui.weak(tr(
                    l,
                    "This backend does not describe the machine: ranges come from the kernel only.",
                ));
            }
        });
        self.list(app, ui, &rows, &SECTIONS, &Scope::Kernel, None);
    }

    /// The property list of `rows`, grouped by `sections`, and the editor
    /// of the selected row under it.
    fn list(
        &mut self,
        app: &mut CoreRouterUi,
        ui: &mut Ui,
        rows: &[Param],
        sections: &[&'static str],
        scope: &Scope,
        height: Option<f32>,
    ) {
        let l = app.lang.labels;
        let editor_h = ui.spacing().interact_size.y * 3.0;
        let list_h = height.unwrap_or_else(|| (ui.available_height() - editor_h).max(80.0));
        ScrollArea::both()
            .id_salt(("tuning-list", scope.salt()))
            .max_height(list_h)
            .auto_shrink(false)
            .show(ui, |ui| {
                header(
                    ui,
                    l,
                    &[
                        "Parameter",
                        "Current",
                        "Configured",
                        "Recommended",
                        "Range",
                    ],
                );
                let needle = self.find.to_lowercase();
                for section in sections {
                    let in_section: Vec<&Param> = rows
                        .iter()
                        .filter(|p| p.section == *section)
                        .filter(|p| {
                            needle.is_empty()
                                || p.name.contains(&needle)
                                || tr(l, section).to_lowercase().contains(&needle)
                        })
                        .collect();
                    if in_section.is_empty() {
                        continue;
                    }
                    let open = !self.collapsed.contains(*section) || !needle.is_empty();
                    if section_row(ui, tr(l, section), in_section.len(), open)
                        && !self.collapsed.remove(*section)
                    {
                        self.collapsed.insert((*section).to_owned());
                    }
                    if !open {
                        continue;
                    }
                    for p in in_section {
                        self.param_row(app, ui, p, scope);
                    }
                }
            });
        self.editor(app, ui, rows, scope);
    }

    // ---- Interfaces -----------------------------------------------------------

    fn interfaces(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        if !app.has_command(PORT_PRINT) {
            later(
                ui,
                l,
                "This router has no port tuning yet: update corerouter-daemon.",
            );
            return;
        }
        let names: Vec<String> = self
            .hardware
            .as_ref()
            .and_then(|h| h.get("nics"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|n| n.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(tr(l, "Port"));
            let current = self.port.clone().unwrap_or_default();
            let mut picked = current.clone();
            ComboBox::from_id_salt("tuning-port")
                .selected_text(&current)
                .show_ui(ui, |ui| {
                    for n in &names {
                        ui.selectable_value(&mut picked, n.clone(), n);
                    }
                });
            if picked != current {
                self.port = Some(picked);
                self.port_print = None;
                self.selected = None;
                app.cache.refreshed_at = None;
            }
            ui.add(
                TextEdit::singleline(&mut self.find)
                    .hint_text(tr(l, "Find"))
                    .desired_width(160.0),
            );
            let ok = safe_mode_ok(app).and_then(|()| app.can().check(PORT_APPLY));
            if action(ui, tr(l, "Apply to all ports with Safe Mode"), ok) {
                if !safe_mode_mine(app) {
                    app.run(SAFE_MODE, json!({}));
                }
                self.waiting += 1;
                app.run_then(
                    PORT_APPLY,
                    json!({"profile": self.profile()}),
                    crate::panel::then(NAME, Reply::Changed),
                );
            }
        });
        let Some(port) = self.port.clone() else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let data = self.port_print.as_ref().and_then(|v| {
            v.get("ports")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().find(|p| p.get("name").and_then(Value::as_str) == Some(&port)))
        });
        let Some(data) = data.cloned() else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let rows = params(&data);
        ui.horizontal_wrapped(|ui| {
            let text = |k: &str| data.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            ui.strong(&port);
            ui.label(format!("{} {}", text("driver"), text("model")));
            if let Some(sp) = data.get("speed_mbps").and_then(Value::as_u64) {
                ui.label(speed(sp));
            }
            if rows.iter().any(|p| p.link_flap && p.differs()) {
                let v = ui.visuals().clone();
                chip(ui, tr(l, "flaps link"), AMBER.tone(&v)).on_hover_text(tr(
                    l,
                    "Changing rings or queues resets the port: its link drops for a moment. Use Safe Mode on a port you manage the router through.",
                ));
            }
        });
        if let Some(notes) = data.get("notes").and_then(Value::as_array)
            && !notes.is_empty()
        {
            let text: Vec<&str> = notes.iter().filter_map(Value::as_str).collect();
            ui.weak(text.join("; "));
        }
        self.list(app, ui, &rows, &PORT_SECTIONS, &Scope::Port(port), None);
    }

    // ---- CPU and IRQ ----------------------------------------------------------

    fn cpu(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        if !app.has_command(CPU_PRINT) {
            later(ui, l, "This router has no CPU tuning yet: update corerouter-daemon.");
            return;
        }
        let Some(cpu) = self.cpu_print.clone() else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        if cpu.get("irqbalance").and_then(Value::as_bool) == Some(true) {
            ui.horizontal(|ui| {
                let v = ui.visuals().clone();
                chip(ui, tr(l, "warning"), AMBER.tone(&v));
                ui.label(tr(l, "irqbalance is running: it undoes the IRQ affinity."));
            });
        }
        let rows = params(&cpu);
        let row_h = ui.spacing().interact_size.y + 4.0;
        let h = row_h * (rows.len() + CPU_SECTIONS.len() + 2) as f32;
        self.list(app, ui, &rows, &CPU_SECTIONS, &Scope::Cpu, Some(h));
        ui.separator();
        // Each port's IRQ affinity, RPS and XPS.
        let names: Vec<String> = self
            .hardware
            .as_ref()
            .and_then(|h| h.get("nics"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|n| n.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(tr(l, "Port"));
            let current = self.port.clone().unwrap_or_default();
            let mut picked = current.clone();
            ComboBox::from_id_salt("tuning-cpu-port")
                .selected_text(&current)
                .show_ui(ui, |ui| {
                    for n in &names {
                        ui.selectable_value(&mut picked, n.clone(), n);
                    }
                });
            if picked != current {
                self.port = Some(picked);
                self.port_print = None;
                self.selected = None;
                app.cache.refreshed_at = None;
            }
        });
        let Some(port) = self.port.clone() else {
            return;
        };
        let data = self.port_print.as_ref().and_then(|v| {
            v.get("ports")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().find(|p| p.get("name").and_then(Value::as_str) == Some(&port)))
                .cloned()
        });
        let Some(data) = data else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let irqs: Vec<String> = data
            .get("irqs")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|i| {
                        // "→" is not in the GUI's font.
                        Some(format!(
                            "{}: {}",
                            i.get("irq")?.as_u64()?,
                            i.get("cpus")?.as_str()?
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !irqs.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.strong(tr(l, "Queue IRQs"));
                ui.label(irqs.join(", "));
            });
        }
        let rows = params(&data);
        self.list(app, ui, &rows, &CPU_PORT_SECTIONS, &Scope::Port(port), None);
    }

    fn param_row(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, p: &Param, scope: &Scope) {
        let l = app.lang.labels;
        let h = ui.spacing().interact_size.y + 2.0;
        let width: f32 = COLS.iter().sum();
        let (rect, resp) = ui.allocate_exact_size(vec2(width, h), Sense::click());
        let selected = self.selected.as_deref() == Some(p.name.as_str());
        let v = ui.visuals().clone();
        if selected {
            ui.painter().rect_filled(rect, 2.0, v.selection.bg_fill);
        } else if resp.hovered() {
            ui.painter().rect_filled(rect, 2.0, v.widgets.hovered.weak_bg_fill);
        }
        if resp.clicked() {
            if selected {
                self.selected = None;
            } else {
                self.selected = Some(p.name.clone());
                self.edit = p.effective().map(|v| v.to_string()).unwrap_or_default();
            }
        }
        let mut x = rect.left() + 6.0;
        let mut cell = |ui: &mut Ui, i: usize, add: &mut dyn FnMut(&mut Ui)| {
            let w = COLS.get(i).copied().unwrap_or(100.0);
            let r = egui::Rect::from_min_size(pos2(x, rect.top()), vec2(w - 6.0, h));
            x += w;
            let mut child = ui.new_child(
                UiBuilder::new()
                    .max_rect(r)
                    .layout(Layout::left_to_right(Align::Center)),
            );
            child.set_clip_rect(r.intersect(ui.clip_rect()));
            // A click on the text selects the row, not the text.
            child.style_mut().interaction.selectable_labels = false;
            add(&mut child);
        };
        let text_color = if selected {
            v.selection.stroke.color
        } else {
            v.text_color()
        };
        cell(ui, 0, &mut |ui| {
            ui.label(RichText::new(&p.name).color(text_color));
            if p.control_plane {
                chip(ui, tr(l, "control plane"), BLUE.tone(&v));
            }
            if p.obsolete {
                chip(ui, tr(l, "obsolete"), neutral_tone(&v));
            }
            if p.reboot {
                chip(ui, tr(l, "needs reboot"), AMBER.tone(&v));
            }
            if p.link_flap {
                chip(ui, tr(l, "flaps link"), AMBER.tone(&v));
            }
            if p.fixed {
                chip(ui, tr(l, "fixed"), neutral_tone(&v))
                    .on_hover_text(tr(l, "The driver does not let it change."));
            }
        });
        cell(ui, 1, &mut |ui| match p.current {
            Some(c) => {
                ui.label(RichText::new(p.value_text(c)).color(text_color));
                if p.differs() && p.configured.is_none() {
                    chip(ui, tr(l, "differs"), AMBER.tone(&v));
                }
            }
            None => {
                ui.weak("–").on_hover_text(tr(
                    l,
                    "Not in this kernel or network namespace (conntrack: not loaded yet).",
                ));
            }
        });
        cell(ui, 2, &mut |ui| match p.configured {
            Some(c) => {
                ui.label(RichText::new(p.value_text(c)).color(text_color));
                if p.current.is_some_and(|now| now != c) {
                    chip(ui, tr(l, "not applied"), RED.tone(&v));
                } else if p.differs() {
                    chip(ui, tr(l, "differs"), AMBER.tone(&v));
                }
            }
            None => {
                ui.weak("–");
            }
        });
        let why = p.why_text(app.lang.help);
        cell(ui, 3, &mut |ui| match p.recommended {
            Some(r) => {
                ui.label(RichText::new(p.value_text(r)).color(text_color).strong())
                    .on_hover_text(&why);
            }
            None => {
                ui.weak("–");
            }
        });
        cell(ui, 4, &mut |ui| {
            ui.label(RichText::new(p.range_text()).color(text_color));
        });
        let mut info = false;
        cell(ui, 5, &mut |ui| {
            let id = Id::unique(("tuning-help", scope.salt(), &p.name));
            info = help::info_button(ui, id, &p.name).clicked();
        });
        if info {
            self.help = Some(explanation(p, &why, scope));
        }
    }

    /// Under the list: change the selected parameter.
    fn editor(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, rows: &[Param], scope: &Scope) {
        let l = app.lang.labels;
        let Some(p) = self
            .selected
            .as_ref()
            .and_then(|s| rows.iter().find(|p| &p.name == s))
        else {
            if *scope != Scope::Cpu {
                ui.weak(tr(l, "Click a parameter to change it."));
            }
            return;
        };
        let can = app.can();
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(&p.name);
            ui.label(tr(l, "Value"));
            if p.choices.is_empty() {
                ui.add(TextEdit::singleline(&mut self.edit).desired_width(120.0));
                if !p.unit.is_empty() {
                    ui.weak(&p.unit);
                }
            } else {
                let mut pick: Option<i64> = self.edit.trim().parse().ok();
                let shown = pick.map(|v| p.value_text(v)).unwrap_or_default();
                ComboBox::from_id_salt(("tuning-choice", &p.name))
                    .selected_text(shown)
                    .show_ui(ui, |ui| {
                        for (v, _) in &p.choices {
                            ui.selectable_value(&mut pick, Some(*v), p.value_text(*v));
                        }
                    });
                if let Some(v) = pick {
                    self.edit = v.to_string();
                }
            }
            let value: Result<i64, String> = self
                .edit
                .trim()
                .parse()
                .map_err(|_| tr(l, "Type a whole number").to_owned());
            let busy = if self.waiting > 0 {
                Err(tr(l, "Saving…").to_owned())
            } else {
                Ok(())
            };
            let busy = if p.fixed {
                Err(tr(l, "The driver does not let it change.").to_owned())
            } else {
                busy
            };
            let set_ok = busy
                .clone()
                .and_then(|()| value.clone().map(|_| ()))
                .and_then(|()| can.check(scope.set(&p.name, 0).0));
            if action(ui, tr(l, "Set"), set_ok)
                && let Ok(v) = value
            {
                self.waiting += 1;
                let (id, params) = scope.set(&p.name, v);
                app.run_then(id, params, crate::panel::then(NAME, Reply::Changed));
            }
            let unset_ok = busy.clone().and_then(|()| {
                if p.configured.is_some() {
                    can.check(scope.unset(&p.name).0)
                } else if *scope == Scope::Kernel {
                    Err(tr(l, "Not set: the kernel's own value is in use").to_owned())
                } else if *scope == Scope::Cpu {
                    Err(tr(l, "Not set: the machine's own value is in use").to_owned())
                } else {
                    Err(tr(l, "Not set: the port's own value is in use").to_owned())
                }
            });
            if action(ui, tr(l, "Unset"), unset_ok) {
                self.waiting += 1;
                let (id, params) = scope.unset(&p.name);
                app.run_then(id, params, crate::panel::then(NAME, Reply::Changed));
            }
            if let Some(r) = p.recommended
                && action(
                    ui,
                    &format!("{} ({})", tr(l, "Use recommended"), p.value_text(r)),
                    busy.and_then(|()| can.check(scope.set(&p.name, r).0)),
                )
            {
                self.edit = r.to_string();
                self.waiting += 1;
                let (id, params) = scope.set(&p.name, r);
                app.run_then(id, params, crate::panel::then(NAME, Reply::Changed));
            }
        });
    }

    // ---- Boot -----------------------------------------------------------------

    fn boot(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        if !app.has_command(BOOT_PRINT) {
            later(
                ui,
                l,
                "This router has no boot parameters yet: update corerouter-daemon.",
            );
            return;
        }
        let Some(data) = self.boot_print.clone() else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let v = ui.visuals().clone();
        let text = |k: &str| data.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        ui.horizontal_wrapped(|ui| {
            chip(ui, tr(l, "next boot"), AMBER.tone(&v));
            ui.label(if data.get("image_ab").and_then(Value::as_bool) == Some(true) {
                tr(l, "Valid from the next boot; a boot that fails goes back to the previous image.")
            } else {
                tr(
                    l,
                    "Valid from the next boot. The A/B image does not exist yet (G1.6): the parameters are saved in the config and wait for it (G1.26h).",
                )
            });
            if help::info_button(ui, Id::unique("tuning-boot-help"), tr(l, "Boot")).clicked() {
                self.help = Some(HelpView::new("tuning.boot", tr(l, "Boot")));
            }
        });
        Grid::new("tuning-boot-cmdlines")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.label(tr(l, "Running"));
                ui.label(RichText::new(text("running_cmdline")).monospace());
                ui.end_row();
                ui.label(tr(l, "Next boot"));
                ui.label(RichText::new(text("next_cmdline")).monospace().strong());
                ui.end_row();
            });
        ui.add_space(6.0);
        let rows: Vec<Value> = data
            .get("params")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let field = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).map(str::to_owned);
        let mut clicked: Option<String> = None;
        let mut info: Option<Value> = None;
        Grid::new("tuning-boot")
            .striped(true)
            .num_columns(6)
            .spacing([16.0, 5.0])
            .show(ui, |ui| {
                for t in ["Parameter", "Running", "Next boot", "Recommended", "Range"] {
                    ui.strong(tr(l, t));
                }
                ui.label("");
                ui.end_row();
                for section in BOOT_SECTIONS {
                    let in_section: Vec<&Value> = rows
                        .iter()
                        .filter(|r| r.get("section").and_then(Value::as_str) == Some(section))
                        .collect();
                    if in_section.is_empty() {
                        continue;
                    }
                    ui.label(RichText::new(tr(l, section)).strong().italics());
                    ui.end_row();
                    for r in in_section {
                        let name = field(r, "name").unwrap_or_default();
                        let selected = self.selected.as_deref() == Some(name.as_str());
                        ui.horizontal(|ui| {
                            if ui.selectable_label(selected, &name).clicked() {
                                clicked = Some(name.clone());
                            }
                            if r.get("danger").and_then(Value::as_bool) == Some(true) {
                                chip(ui, tr(l, "security risk"), RED.tone(&v));
                            }
                        });
                        let running = field(r, "running");
                        let next = field(r, "configured");
                        ui.label(running.clone().unwrap_or_else(|| "–".into()));
                        ui.horizontal(|ui| match &next {
                            Some(n) => {
                                ui.strong(n);
                                if running.as_ref() != Some(n) {
                                    chip(ui, tr(l, "next boot"), AMBER.tone(&v));
                                }
                            }
                            None => {
                                ui.weak("–");
                            }
                        });
                        let why = field(r, "why_id").map_or_else(String::new, |id| {
                            i18n::template(
                                app.lang.help,
                                &format!("why.{id}"),
                                &[],
                                &field(r, "why").unwrap_or_default(),
                            )
                        });
                        match field(r, "recommended") {
                            Some(rec) => {
                                ui.label(rec).on_hover_text(&why);
                            }
                            None => {
                                ui.weak("–");
                            }
                        }
                        ui.label(boot_range(r));
                        if help::info_button(ui, Id::unique(("tuning-boot-help", &name)), &name)
                            .clicked()
                        {
                            info = Some(r.clone());
                        }
                        ui.end_row();
                    }
                }
            });
        if let Some(c) = clicked {
            if self.selected.as_deref() == Some(c.as_str()) {
                self.selected = None;
            } else {
                self.edit = rows
                    .iter()
                    .find(|r| field(r, "name").as_deref() == Some(c.as_str()))
                    .and_then(|r| field(r, "configured").or_else(|| field(r, "running")))
                    .unwrap_or_default();
                self.boot_confirm = false;
                self.selected = Some(c);
            }
        }
        if let Some(r) = info {
            let name = field(&r, "name").unwrap_or_default();
            let mut view = HelpView::new(format!("tuning.boot.{name}"), name.clone());
            if let Some(rec) = field(&r, "recommended") {
                let why = field(&r, "why_id").map_or_else(String::new, |id| {
                    i18n::template(
                        app.lang.help,
                        &format!("why.{id}"),
                        &[],
                        &field(&r, "why").unwrap_or_default(),
                    )
                });
                view = view.with("Recommended here", format!("**{rec}**: {why}"));
            }
            let value = field(&r, "recommended")
                .or_else(|| field(&r, "configured"))
                .unwrap_or_else(|| "…".into());
            view = view.with(
                "Equivalent command",
                format!(
                    "`/system tuning boot set key={name} value={value}`\n\n`/system tuning boot unset key={name}`"
                ),
            );
            self.help = Some(view);
        }
        self.boot_editor(app, ui, &rows);
    }

    fn boot_editor(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, rows: &[Value]) {
        let l = app.lang.labels;
        let Some(r) = self.selected.as_ref().and_then(|s| {
            rows.iter()
                .find(|r| r.get("name").and_then(Value::as_str) == Some(s.as_str()))
        }) else {
            ui.weak(tr(l, "Click a parameter to change it."));
            return;
        };
        let name = r.get("name").and_then(Value::as_str).unwrap_or("").to_owned();
        let choices: Vec<String> = r
            .get("choices")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        let danger = r.get("danger").and_then(Value::as_bool) == Some(true);
        let can = app.can();
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(&name);
            ui.label(tr(l, "Value"));
            if choices.is_empty() {
                ui.add(TextEdit::singleline(&mut self.edit).desired_width(160.0));
            } else {
                ComboBox::from_id_salt(("tuning-boot-choice", &name))
                    .selected_text(self.edit.clone())
                    .show_ui(ui, |ui| {
                        for c in &choices {
                            ui.selectable_value(&mut self.edit, c.clone(), c);
                        }
                    });
            }
            let needs_confirm = danger && self.edit.trim() == "off";
            if needs_confirm {
                ui.checkbox(&mut self.boot_confirm, tr(l, "I understand the security risk"));
            }
            let busy = if self.waiting > 0 {
                Err(tr(l, "Saving…").to_owned())
            } else {
                Ok(())
            };
            let ok = busy.clone().and_then(|()| {
                if needs_confirm && !self.boot_confirm {
                    Err(tr(l, "I understand the security risk").to_owned())
                } else {
                    can.check(BOOT_SET)
                }
            });
            if action(ui, tr(l, "Set"), ok) {
                self.waiting += 1;
                app.run_then(
                    BOOT_SET,
                    json!({"key": name, "value": self.edit.trim(), "confirm": self.boot_confirm}),
                    crate::panel::then(NAME, Reply::Changed),
                );
            }
            let unset_ok = busy.clone().and_then(|()| {
                if r.get("configured").is_some_and(|c| !c.is_null()) {
                    can.check(BOOT_UNSET)
                } else {
                    Err(tr(l, "Not set for the next boot").to_owned())
                }
            });
            if action(ui, tr(l, "Unset"), unset_ok) {
                self.waiting += 1;
                app.run_then(
                    BOOT_UNSET,
                    json!({"key": name}),
                    crate::panel::then(NAME, Reply::Changed),
                );
            }
            if let Some(rec) = r.get("recommended").and_then(Value::as_str)
                && action(
                    ui,
                    &format!("{} ({rec})", tr(l, "Use recommended")),
                    busy.and_then(|()| can.check(BOOT_SET)),
                )
            {
                self.edit = rec.to_owned();
                self.waiting += 1;
                app.run_then(
                    BOOT_SET,
                    json!({"key": name, "value": rec}),
                    crate::panel::then(NAME, Reply::Changed),
                );
            }
        });
    }

    // ---- Profiles -------------------------------------------------------------

    fn profiles(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.label(tr(
                l,
                "The four profiles for this machine, side by side. The profile picked at the top is the one Summary applies.",
            ));
            if help::info_button(ui, Id::unique("tuning-profiles-help-2"), tr(l, "Profiles"))
                .clicked()
            {
                self.help = Some(HelpView::new("tuning.profiles", tr(l, "Profiles")));
            }
        });
        let by: Vec<(&str, Vec<Param>)> = PROFILES
            .iter()
            .map(|(_, label, key)| {
                let rows = self
                    .compare
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| params(v))
                    .unwrap_or_default();
                (*label, rows)
            })
            .collect();
        let Some((_, first)) = by.iter().find(|(_, r)| !r.is_empty()) else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let first = first.clone();
        ScrollArea::both()
            .id_salt("tuning-profiles")
            .auto_shrink(false)
            .show(ui, |ui| {
                Grid::new("tuning-profiles-grid")
                    .striped(true)
                    .num_columns(6)
                    .spacing([14.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong(tr(l, "Parameter"));
                        ui.strong(tr(l, "Current"));
                        for (label, _) in &by {
                            ui.strong(tr(l, label));
                        }
                        ui.end_row();
                        for section in SECTIONS {
                            let mut first_in = true;
                            for p in first.iter().filter(|p| p.section == section) {
                                if first_in {
                                    ui.label(RichText::new(tr(l, section)).strong().italics());
                                    ui.end_row();
                                    first_in = false;
                                }
                                ui.label(&p.name);
                                ui.label(p.current.map_or_else(|| "–".into(), |v| p.value_text(v)));
                                for (_, rows) in &by {
                                    let r = rows.iter().find(|r| r.name == p.name);
                                    match r.and_then(|r| r.recommended.map(|v| (r, v))) {
                                        Some((r, v)) => {
                                            let t = RichText::new(r.value_text(v));
                                            let t = if Some(v) == p.current { t } else { t.strong() };
                                            ui.label(t).on_hover_text(r.why_text(app.lang.help));
                                        }
                                        None => {
                                            ui.weak("–");
                                        }
                                    }
                                }
                                ui.end_row();
                            }
                        }
                    });
            });
    }
}

/// The ⓘ modal of `p`: its explanation, the value recommended here and
/// the command that sets it.
pub(crate) fn explanation(p: &Param, why: &str, scope: &Scope) -> HelpView {
    let mut v = HelpView::new(scope.help_key(&p.name), p.name.clone());
    if let Some(r) = p.recommended {
        v = v.with("Recommended here", format!("**{}**: {why}", p.value_text(r)));
    }
    let value = p.recommended.or(p.effective()).unwrap_or(p.min);
    v.with("Equivalent command", scope.commands(&p.name, value))
}

/// The values a boot parameter takes, as the Range column shows them.
fn boot_range(r: &Value) -> String {
    match r.get("kind").and_then(Value::as_str) {
        Some("cpus") => "CPU list (1-…)".into(),
        Some("int") => format!(
            "{} – {}",
            r.get("min").and_then(Value::as_i64).unwrap_or(0),
            r.get("max").and_then(Value::as_i64).unwrap_or(0)
        ),
        _ => r
            .get("choices")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default(),
    }
}

fn later(ui: &mut Ui, l: Lang, what: &'static str) {
    ui.add_space(12.0);
    ui.weak(tr(l, what));
}

fn header(ui: &mut Ui, l: Lang, titles: &[&'static str]) {
    let h = ui.spacing().interact_size.y;
    let width: f32 = COLS.iter().sum();
    let (rect, _) = ui.allocate_exact_size(vec2(width, h), Sense::hover());
    let mut x = rect.left() + 6.0;
    let font = egui::TextStyle::Body.resolve(ui.style());
    let color = ui.visuals().strong_text_color();
    for (i, t) in titles.iter().enumerate() {
        ui.painter().text(
            pos2(x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            tr(l, t),
            font.clone(),
            color,
        );
        x += COLS.get(i).copied().unwrap_or(100.0);
    }
    ui.painter().hline(
        rect.x_range(),
        rect.bottom(),
        ui.visuals().widgets.noninteractive.bg_stroke,
    );
}

/// A section band; whether it was clicked (open or close it).
fn section_row(ui: &mut Ui, title: &str, n: usize, open: bool) -> bool {
    let h = ui.spacing().interact_size.y + 4.0;
    let width: f32 = COLS.iter().sum();
    let (rect, resp) = ui.allocate_exact_size(vec2(width, h), Sense::click());
    let v = ui.visuals();
    ui.painter()
        .rect_filled(rect.shrink2(vec2(0.0, 1.0)), 2.0, v.faint_bg_color);
    // Painted: the default fonts have no ▸/▾.
    let c = pos2(rect.left() + 11.0, rect.center().y);
    let r = 4.0;
    let tri = if open {
        vec![c + vec2(-r, -r * 0.6), c + vec2(r, -r * 0.6), c + vec2(0.0, r * 0.7)]
    } else {
        vec![c + vec2(-r * 0.6, -r), c + vec2(r * 0.7, 0.0), c + vec2(-r * 0.6, r)]
    };
    ui.painter().add(egui::Shape::convex_polygon(
        tri,
        v.strong_text_color(),
        egui::Stroke::NONE,
    ));
    ui.painter().text(
        pos2(rect.left() + 22.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        format!("{title} ({n})"),
        egui::TextStyle::Body.resolve(ui.style()),
        v.strong_text_color(),
    );
    resp.clicked()
}

fn hardware(ui: &mut Ui, l: Lang, hw: &Value) {
    let int = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64);
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let gib = |kib: u64| format!("{:.1} GiB", kib as f64 / 1_048_576.0);
    Grid::new("tuning-hw").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(tr(l, "CPUs"));
        ui.label(format!(
            "{} × {}",
            int(hw, "cpus").unwrap_or(0),
            text(hw, "cpu_model")
        ));
        ui.end_row();
        let nodes: Vec<String> = hw
            .get("numa")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|n| {
                        let cpus = cpu_ranges(
                            &n.get("cpus")
                                .and_then(Value::as_array)
                                .map(|c| c.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
                                .unwrap_or_default(),
                        );
                        let mem = int(n, "mem_kib").map(gib).unwrap_or_default();
                        format!("{}: {cpus} {mem}", int(n, "id").unwrap_or(0))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ui.label(tr(l, "NUMA nodes"));
        ui.label(if nodes.is_empty() {
            "1".to_owned()
        } else {
            format!("{} ({})", nodes.len(), nodes.join("; "))
        });
        ui.end_row();
        ui.label(tr(l, "Memory"));
        ui.label(gib(int(hw, "mem_kib").unwrap_or(0)));
        ui.end_row();
        ui.label(tr(l, "Kernel"));
        ui.label(text(hw, "kernel"));
        ui.end_row();
    });
    let nics: Vec<Value> = hw
        .get("nics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if nics.is_empty() {
        return;
    }
    ui.add_space(4.0);
    Grid::new("tuning-nics")
        .striped(true)
        .num_columns(8)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for t in [
                "Port", "Driver", "Speed", "NUMA", "Queues", "RX ring", "TX ring", "RX missed",
            ] {
                ui.strong(tr(l, t));
            }
            ui.end_row();
            let of = |n: &Value, a: &str, b: &str| match (int(n, a), int(n, b)) {
                (Some(x), Some(y)) => format!("{x} / {y}"),
                (Some(x), None) => x.to_string(),
                _ => "–".into(),
            };
            for n in &nics {
                ui.label(text(n, "name"));
                ui.label(text(n, "driver"));
                ui.label(int(n, "speed_mbps").map_or_else(|| "–".into(), speed));
                ui.label(int(n, "numa_node").map_or_else(|| "–".into(), |v| v.to_string()));
                ui.label(of(n, "queues", "queues_max"));
                ui.label(of(n, "ring_rx", "ring_rx_max"));
                ui.label(of(n, "ring_tx", "ring_tx_max"));
                ui.label(int(n, "rx_missed").map_or_else(|| "–".into(), |v| v.to_string()));
                ui.end_row();
            }
        });
}

fn speed(mbps: u64) -> String {
    if mbps >= 1000 && mbps.is_multiple_of(1000) {
        format!("{} Gb/s", mbps / 1000)
    } else {
        format!("{mbps} Mb/s")
    }
}

/// `0-7,16-23` from a list of CPU numbers.
pub(crate) fn cpu_ranges(cpus: &[u64]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut it = cpus.iter().copied().peekable();
    while let Some(a) = it.next() {
        let mut b = a;
        while it.peek() == Some(&(b + 1)) {
            b += 1;
            it.next();
        }
        out.push(if a == b { a.to_string() } else { format!("{a}–{b}") });
    }
    out.join(",")
}

/// Safe Mode held by this connection.
fn safe_mode_mine(app: &CoreRouterUi) -> bool {
    let sm = app.cache.summary.get("safe_mode");
    sm.and_then(|s| s.get("active")).and_then(Value::as_bool) == Some(true)
        && sm.and_then(|s| s.get("yours")).and_then(Value::as_bool) == Some(true)
}

/// Whether this connection can enter (or already holds) Safe Mode.
fn safe_mode_ok(app: &CoreRouterUi) -> Result<(), String> {
    let sm = app.cache.summary.get("safe_mode");
    let active = sm.and_then(|s| s.get("active")).and_then(Value::as_bool) == Some(true);
    if active && !safe_mode_mine(app) {
        let owner = sm
            .and_then(|s| s.get("owner"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return Err(format!(
            "{} {owner}",
            tr(app.lang.labels, "Safe Mode is held by")
        ));
    }
    if safe_mode_mine(app) {
        Ok(())
    } else {
        app.can().check(SAFE_MODE)
    }
}

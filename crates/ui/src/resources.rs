//! System › Resources (G4.8a): the router's health at a glance, RouterOS
//! `/system resource` + `/system health` + `/tool profile` in one window,
//! with tabs (parts of a window are tabs, `docs/ui-style.md`):
//!
//! - **Overview**: four cards (CPU, Memory, Disk, Temperature) with a
//!   sparkline of the last 5 min, the links (state, rates, errors) and the
//!   health checks with their reason;
//! - **CPU** (per core, softirq and the receive softirq of each CPU: RSS
//!   balance), **Memory** (use, PSI, swap), **Disk**, **Network**,
//!   **Sensors**, **Processes** (sortable) and **OS Log** (G4.8b).
//!
//! The top bar gets the health chip (always; a click opens this window)
//! and, when Settings turns it on, the router's live CPU and memory next
//! to the theme switch ([`top_bar`]).
//!
//! The engine computes everything (`system.resource.*`, `system.health.*`);
//! the window asks once a second while open, the readout only while on,
//! the chip every 5 s.

use std::cell::Cell;

use egui::{Grid, Id, ProgressBar, RichText, Sense, Stroke, Ui, pos2, vec2};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, GREEN, RED, Tone, chip, neutral_tone};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::neighbors::uptime_text;
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::table::{self, Row, TableState, col, num};
use crate::{CoreRouterUi, Win, human_bytes, icons};

const NAME: &str = "resources";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "resources";
/// The translations' scope (`i18n/auto/resources_*.rs`).
const SCOPE: &str = "resources";
const PRINT: &str = "system.resource.print";
const CPU: &str = "system.resource.cpu.print";
const PROCS: &str = "system.resource.process.print";
const NET: &str = "system.resource.network.print";
const SENSORS: &str = "system.health.print";
pub(crate) const CHECK: &str = "system.health.check";
/// Refreshes (1 s) between two health checks for the top bar's chip.
const CHIP_EVERY: u32 = 5;
const PROC_LIMIT: u32 = 200;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Resources",
        size: [900.0, 780.0],
        escape: true,
    }],
    new: || Box::new(ResourcesPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Overview,
    Cpu,
    Memory,
    Disk,
    Network,
    Sensors,
    Processes,
    OsLog,
}

const TABS: [(Tab, &str, &str); 8] = [
    (Tab::Overview, "Overview", "overview"),
    (Tab::Cpu, "CPU", "cpu"),
    (Tab::Memory, "Memory", "memory"),
    (Tab::Disk, "Disk", "disk"),
    (Tab::Network, "Network", "network"),
    (Tab::Sensors, "Sensors", "sensors"),
    (Tab::Processes, "Processes", "processes"),
    (Tab::OsLog, "OS Log", "os_log"),
];

/// Sort keys of the Processes tab (the engine sorts).
const SORTS: [(&str, &str); 5] = [
    ("cpu", "CPU"),
    ("memory", "Memory"),
    ("name", "Name"),
    ("pid", "PID"),
    ("threads", "Threads"),
];

const T_IFACES: &str = "resources-ifaces";
const T_DISK: &str = "resources-disk";
const T_NET: &str = "resources-net";
const T_SENSORS: &str = "resources-sensors";
const T_PROCS: &str = "resources-procs";

#[derive(Default)]
pub(crate) struct ResourcesPanel {
    pub(crate) tab: Tab,
    pub(crate) print: Option<Value>,
    pub(crate) cpu: Option<Value>,
    pub(crate) procs: Option<Value>,
    pub(crate) net: Option<Value>,
    pub(crate) sensors: Option<Value>,
    pub(crate) check: Option<Value>,
    /// The last refusal (an old daemon, a backend without readings).
    pub(crate) error: Option<String>,
    pub(crate) sort: &'static str,
    /// Settings › Top bar: the router's CPU and memory next to the theme
    /// switch (off by default).
    pub(crate) readout: bool,
    /// Refreshes since the chip's last check.
    ticks: Cell<u32>,
    help: Option<HelpView>,
    ifaces: TableState,
    disks: TableState,
    links: TableState,
    sensor_table: TableState,
    proc_table: TableState,
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn arr(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "–".into(), |v| format!("{v:.0} %"))
}

/// `level` of a check or sensor → its chip tone.
fn tone(v: &egui::Visuals, level: &str) -> Tone {
    match level {
        "ok" => GREEN.tone(v),
        "warning" => AMBER.tone(v),
        "error" => RED.tone(v),
        _ => neutral_tone(v),
    }
}

/// A share in use → ok / warning / error, for bars (the engine's checks
/// use the same 85/95 marks for memory and disk).
fn used_level(p: f64) -> &'static str {
    if p >= 95.0 {
        "error"
    } else if p >= 85.0 {
        "warning"
    } else {
        "ok"
    }
}

/// The overall health of a `system.health.check` reply.
fn status(check: Option<&Value>) -> (&str, u64, u64) {
    let Some(c) = check else { return ("unknown", 0, 0) };
    (
        s(c, "status"),
        c.get("warnings").and_then(Value::as_u64).unwrap_or(0),
        c.get("errors").and_then(Value::as_u64).unwrap_or(0),
    )
}

impl ResourcesPanel {
    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, label: &'static str) {
        if help::info_button(ui, Id::unique(("resources-help", key)), tr_in(SCOPE, l, label)).clicked() {
            self.help = Some(HelpView::new(format!("resources.{key}"), tr_in(SCOPE, l, label)));
        }
    }

    /// A label with its ⓘ.
    fn label(&mut self, ui: &mut Ui, l: Lang, key: &str, label: &'static str) {
        ui.label(tr_in(SCOPE, l, label));
        self.info(ui, l, key, label);
    }
}

impl PanelState for ResourcesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let q = |key, command, params| Query { key, command, params };
        let open = app.open.contains(&Win::Panel(WIN));
        let mut out = Vec::new();
        if !app.has_command(PRINT) {
            return out;
        }
        if open || self.readout {
            out.push(q("print", PRINT, Value::Null));
        }
        let n = self.ticks.get();
        self.ticks.set(n.wrapping_add(1));
        if app.has_command(CHECK) && (open || n.is_multiple_of(CHIP_EVERY)) {
            out.push(q("check", CHECK, Value::Null));
        }
        if !open {
            return out;
        }
        match self.tab {
            Tab::Overview | Tab::Network => out.push(q("net", NET, Value::Null)),
            Tab::Cpu => out.push(q("cpu", CPU, Value::Null)),
            Tab::Sensors => out.push(q("sensors", SENSORS, Value::Null)),
            Tab::Processes => out.push(q(
                "procs",
                PROCS,
                json!({"sort": if self.sort.is_empty() { "cpu" } else { self.sort }, "limit": PROC_LIMIT}),
            )),
            Tab::Memory => out.push(q("procs", PROCS, json!({"sort": "memory", "limit": 8}))),
            Tab::Disk | Tab::OsLog => {}
        }
        if self.tab == Tab::Overview {
            out.push(q("sensors", SENSORS, Value::Null));
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if let Some(e) = value.get("error").and_then(Value::as_str) {
            self.error = Some(e.to_owned());
            return;
        }
        let slot = match key {
            "print" => &mut self.print,
            "cpu" => &mut self.cpu,
            "procs" => &mut self.procs,
            "net" => &mut self.net,
            "sensors" => &mut self.sensors,
            "check" => &mut self.check,
            _ => return,
        };
        *slot = Some(value);
        if key == "print" {
            self.error = None;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.header(app, ui, l);
        ui.horizontal_wrapped(|ui| {
            for (t, name, key) in TABS {
                if ui.selectable_value(&mut self.tab, t, tr_in(SCOPE, l, name)).changed() {
                    app.cache.refreshed_at = None;
                }
                self.info(ui, l, &format!("tab.{key}"), name);
            }
        });
        ui.separator();
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        // Tables scroll by themselves; the other tabs scroll as a page.
        let page = |ui: &mut Ui, f: &mut dyn FnMut(&mut Ui)| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| f(ui));
        };
        match self.tab {
            Tab::Overview => page(ui, &mut |ui| self.overview(app, ui, l)),
            Tab::Cpu => page(ui, &mut |ui| self.cpu_tab(ui, l)),
            Tab::Memory => page(ui, &mut |ui| self.memory_tab(ui, l)),
            Tab::Disk => self.disk_tab(ui, l),
            Tab::Network => self.network_tab(ui, l),
            Tab::Sensors => self.sensors_tab(ui, l),
            Tab::Processes => self.processes_tab(app, ui, l),
            Tab::OsLog => os_log(app, ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.proc_table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(T_PROCS, &self.proc_table), (T_NET, &self.links)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(T_PROCS, &mut self.proc_table), (T_NET, &mut self.links)]
    }
}

/// The OS Log tab: G4.8b's panel draws it once it lands.
fn os_log(app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
    let _ = app;
    ui.weak(tr_in(SCOPE, l, "OS Log (G4.8b): the operating system's log comes in its own change."));
}

impl ResourcesPanel {
    fn header(&mut self, app: &CoreRouterUi, ui: &mut Ui, l: Lang) {
        let identity = app
            .cache
            .summary
            .get("identity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let commit = app.cache.info.get("commit").and_then(Value::as_str).unwrap_or("").to_owned();
        let uptime = self.print.as_ref().and_then(|p| p.get("uptime_secs")).and_then(Value::as_u64);
        let (st, warnings, errors) = status(self.check.as_ref());
        let st = st.to_owned();
        ui.horizontal(|ui| {
            health_chip(ui, &st, warnings, errors, l);
            self.info(ui, l, "health", "Health");
            ui.separator();
            ui.strong(identity);
            if !commit.is_empty() {
                ui.separator();
                ui.weak(format!("CoreRouter {commit}"));
            }
            if let Some(u) = uptime {
                ui.separator();
                ui.label(format!("{} {}", tr_in(SCOPE, l, "Uptime"), uptime_text(u)));
                self.info(ui, l, "uptime", "Uptime");
            }
        });
        ui.add_space(2.0);
    }

    fn overview(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(p) = self.print.clone() else {
            ui.weak(tr_in(SCOPE, l, "Waiting for the router…"));
            return;
        };
        let history = arr(p.get("history")).to_vec();
        let series = |k: &str| -> Vec<Option<f64>> { history.iter().map(|h| f(h, k)).collect() };
        let width = ((ui.available_width() - 3.0 * 8.0) / 4.0).max(160.0);
        ui.horizontal_wrapped(|ui| {
            // CPU.
            self.card(ui, l, width, "cpu", "CPU", |me, ui| {
                let load = f(&p, "cpu_load");
                ui.label(RichText::new(pct(load)).size(22.0).strong());
                sparkline(ui, &series("cpu"), Some(100.0));
                let cores = p.get("cpu_count").and_then(Value::as_u64).unwrap_or(0);
                let la = p.get("load_avg");
                ui.weak(format!(
                    "{cores} {} · {} {}",
                    tr_in(SCOPE, l, "cores"),
                    tr_in(SCOPE, l, "load"),
                    la.map(|a| format!("{:.2} {:.2} {:.2}", f(a, "one").unwrap_or(0.0), f(a, "five").unwrap_or(0.0), f(a, "fifteen").unwrap_or(0.0))).unwrap_or_else(|| "–".into())
                ));
                if let Some(mhz) = f(&p, "cpu_frequency_mhz") {
                    ui.weak(format!("{:.2} GHz", mhz / 1000.0));
                }
                let _ = me;
            });
            // Memory.
            self.card(ui, l, width, "memory", "Memory", |me, ui| {
                let total = p.get("total_memory").and_then(Value::as_u64).unwrap_or(0);
                let free = p.get("free_memory").and_then(Value::as_u64).unwrap_or(0);
                let used = f(&p, "memory_used_percent");
                ui.label(RichText::new(pct(used)).size(22.0).strong());
                bar(ui, used.unwrap_or(0.0) / 100.0, &format!("{} / {}", human_bytes(total.saturating_sub(free)), human_bytes(total)));
                let psi = p.pointer("/pressure/memory/some60").and_then(Value::as_f64);
                ui.weak(format!("PSI {}", psi.map_or_else(|| "–".into(), |v| format!("{v:.1} %"))));
                let m = p.get("memory");
                let (st, sf) = (
                    m.and_then(|m| m.get("swap_total")).and_then(Value::as_u64).unwrap_or(0),
                    m.and_then(|m| m.get("swap_free")).and_then(Value::as_u64).unwrap_or(0),
                );
                ui.weak(if st == 0 {
                    tr_in(SCOPE, l, "no swap").to_owned()
                } else {
                    format!("swap {} / {}", human_bytes(st.saturating_sub(sf)), human_bytes(st))
                });
                let _ = me;
            });
            // Disk.
            self.card(ui, l, width, "disk", "Disk", |me, ui| {
                let total = p.get("total_hdd_space").and_then(Value::as_u64).unwrap_or(0);
                let free = p.get("free_hdd_space").and_then(Value::as_u64).unwrap_or(0);
                let free_pct = if total > 0 { free as f64 * 100.0 / total as f64 } else { 0.0 };
                ui.label(RichText::new(format!("{free_pct:.0} % {}", tr_in(SCOPE, l, "free"))).size(22.0).strong());
                bar(ui, 1.0 - free_pct / 100.0, &format!("{} {} / {}", human_bytes(free), tr_in(SCOPE, l, "free"), human_bytes(total)));
                let nvme = arr(me.sensors.as_ref())
                    .iter()
                    .find(|x| s(x, "chip") == "nvme" || s(x, "chip").starts_with("drivetemp"))
                    .and_then(|x| f(x, "value"));
                if let Some(t) = nvme {
                    ui.weak(format!("{} {t:.0} °C", tr_in(SCOPE, l, "device")));
                }
                let w: f64 = arr(p.get("disk_io")).iter().filter_map(|d| f(d, "write_rate")).sum();
                ui.weak(format!("{} {}/s", tr_in(SCOPE, l, "writes"), human_bytes(w as u64)));
            });
            // Temperature.
            self.card(ui, l, width, "temperature", "Temperature", |me, ui| {
                let t = p.get("temperature");
                let v = t.and_then(|t| f(t, "value"));
                ui.label(RichText::new(v.map_or_else(|| "–".into(), |v| format!("{v:.0} °C"))).size(22.0).strong());
                sparkline(ui, &series("temperature"), t.and_then(|t| f(t, "crit")));
                if let Some(c) = t.and_then(|t| f(t, "crit")) {
                    ui.weak(format!("crit {c:.0} °C · {}", t.map(|t| s(t, "sensor")).unwrap_or("")));
                } else if let Some(t) = t {
                    ui.weak(s(t, "sensor"));
                }
                match f(&p, "fan_rpm") {
                    Some(r) => ui.weak(format!("{} {r:.0} rpm", tr_in(SCOPE, l, "fan"))),
                    None => ui.weak(tr_in(SCOPE, l, "no fan sensor")),
                };
                let _ = me;
            });
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Interfaces"));
            self.info(ui, l, "interfaces", "Interfaces");
        });
        let rows = link_rows(arr(self.net.as_ref()), true);
        let h = (rows.len().min(8) as f32 + 2.6) * ui.spacing().interact_size.y;
        ui.allocate_ui(vec2(ui.available_width(), h), |ui| {
            let cols = [
                col("Name").help("resources.col.name"),
                col("Link").help("resources.col.link"),
                num("Rx").help("resources.col.rx"),
                num("Tx").help("resources.col.tx"),
                col("Errors").help("resources.col.errors"),
            ];
            let out = table::show(ui, T_IFACES, 0.0, &mut self.ifaces, &cols, &rows, |_, _| {});
            if let Some(k) = out.help {
                self.help = Some(HelpView::new(k, col_title(&cols, k, l)));
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Health checks"));
            self.info(ui, l, "checks", "Health checks");
        });
        self.checks(app, ui, l);
    }

    /// One Overview card: a framed group of a fixed width.
    fn card(&mut self, ui: &mut Ui, l: Lang, width: f32, key: &str, title: &'static str, body: impl FnOnce(&mut Self, &mut Ui)) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(width - 14.0);
            ui.set_min_height(130.0);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(tr_in(SCOPE, l, title));
                    self.info(ui, l, &format!("card.{key}"), title);
                });
                body(self, ui);
            });
        });
    }

    fn checks(&mut self, _app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let checks = arr(self.check.as_ref().and_then(|c| c.get("checks"))).to_vec();
        if checks.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Waiting for the router…"));
            return;
        }
        Grid::new("resources-checks").num_columns(4).spacing([10.0, 4.0]).striped(true).show(ui, |ui| {
            for c in &checks {
                let sev = s(c, "severity");
                let word = match sev {
                    "ok" => "ok",
                    "warning" => "aviso",
                    "error" => "erro",
                    _ => "?",
                };
                chip(ui, word, tone(ui.visuals(), sev));
                ui.horizontal(|ui| {
                    ui.label(tr_in(SCOPE, l, static_name(s(c, "name"))));
                    self.info(ui, l, &format!("check.{}", s(c, "key")), static_name(s(c, "name")));
                });
                ui.weak(s(c, "value"));
                let r = ui.label(s(c, "reason"));
                if let Some(a) = c.get("action").and_then(Value::as_str) {
                    r.on_hover_text(a);
                }
                ui.end_row();
            }
        });
    }

    fn cpu_tab(&mut self, ui: &mut Ui, l: Lang) {
        let cores = arr(self.cpu.as_ref()).to_vec();
        if cores.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Waiting for the router…"));
            return;
        }
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Load per core"));
            self.info(ui, l, "cpu.cores", "Load per core");
            ui.weak(tr_in(SCOPE, l, "user · system · irq · softirq"));
        });
        let total_rx: f64 = cores.iter().filter_map(|c| f(c, "net_rx_rate")).sum();
        Grid::new("resources-cores").num_columns(4).spacing([10.0, 2.0]).show(ui, |ui| {
            for c in &cores {
                ui.monospace(format!("CPU{}", c.get("cpu").and_then(Value::as_u64).unwrap_or(0)));
                stacked_bar(ui, 260.0, [f(c, "user"), f(c, "system"), f(c, "irq"), f(c, "softirq")]);
                ui.label(pct(f(c, "load")));
                let share = f(c, "net_rx_rate").filter(|_| total_rx > 0.0).map(|r| r * 100.0 / total_rx);
                ui.weak(format!(
                    "{} {} · {} MHz",
                    tr_in(SCOPE, l, "rx softirq"),
                    pct(share),
                    c.get("frequency_mhz").and_then(Value::as_u64).map_or_else(|| "–".into(), |m| m.to_string())
                ));
                ui.end_row();
            }
        });
    }

    fn memory_tab(&mut self, ui: &mut Ui, l: Lang) {
        let Some(p) = self.print.clone() else { return };
        let m = p.get("memory").cloned().unwrap_or(Value::Null);
        let b = |k: &str| m.get(k).and_then(Value::as_u64).unwrap_or(0);
        Grid::new("resources-memory").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            for (key, label, v) in [
                ("mem.total", "Total", b("total")),
                ("mem.available", "Available", b("available")),
                ("mem.free", "Unused", b("free")),
                ("mem.cached", "Cache", b("cached").saturating_add(b("buffers"))),
                ("mem.swap_total", "Swap total", b("swap_total")),
                ("mem.swap_used", "Swap used", b("swap_total").saturating_sub(b("swap_free"))),
            ] {
                ui.horizontal(|ui| self.label(ui, l, key, label));
                ui.label(human_bytes(v));
                ui.end_row();
            }
            for (res, label) in [("memory", "Memory pressure"), ("cpu", "CPU pressure"), ("io", "I/O pressure")] {
                ui.horizontal(|ui| self.label(ui, l, &format!("psi.{res}"), label));
                let ps = p.pointer(&format!("/pressure/{res}"));
                ui.label(match ps.filter(|v| !v.is_null()) {
                    Some(v) => format!(
                        "some {:.1} / {:.1} / {:.1} %{}",
                        f(v, "some10").unwrap_or(0.0),
                        f(v, "some60").unwrap_or(0.0),
                        f(v, "some300").unwrap_or(0.0),
                        f(v, "full60").filter(|_| res != "cpu").map(|x| format!(" · full {x:.1} %")).unwrap_or_default()
                    ),
                    None => "–".into(),
                });
                ui.end_row();
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Largest processes"));
            self.info(ui, l, "mem.top", "Largest processes");
        });
        for x in arr(self.procs.as_ref()) {
            ui.horizontal(|ui| {
                ui.monospace(format!("{:>8}", human_bytes(x.get("memory").and_then(Value::as_u64).unwrap_or(0))));
                ui.label(s(x, "name"));
            });
        }
    }

    fn disk_tab(&mut self, ui: &mut Ui, l: Lang) {
        let Some(p) = self.print.clone() else { return };
        let rows: Vec<Row> = arr(p.get("disks"))
            .iter()
            .map(|d| {
                let used = f(d, "used_percent").unwrap_or(0.0);
                Row {
                    key: s(d, "mount").to_owned(),
                    cells: vec![
                        s(d, "mount").to_owned(),
                        s(d, "device").to_owned(),
                        s(d, "fs").to_owned(),
                        human_bytes(d.get("total").and_then(Value::as_u64).unwrap_or(0)),
                        human_bytes(d.get("available").and_then(Value::as_u64).unwrap_or(0)),
                        crate::chip::cell(&format!("{used:.0} %"), &[(used_level(used), level_kind(used_level(used)))]),
                    ],
                    dimmed: false,
                    section: false,
                    tint: None,
                }
            })
            .collect();
        let cols = [
            col("Mount").help("resources.col.mount"),
            col("Device"),
            col("FS"),
            num("Size"),
            num("Free").help("resources.col.free"),
            col("Used").help("resources.col.used"),
        ];
        // Room under the table for the I/O lines and the total written.
        let below = (arr(p.get("disk_io")).len() as f32 + 2.5) * ui.spacing().interact_size.y;
        let out = table::show(ui, T_DISK, below, &mut self.disks, &cols, &rows, |_, _| {});
        if let Some(k) = out.help {
            self.help = Some(HelpView::new(k, col_title(&cols, k, l)));
        }
        ui.add_space(6.0);
        for d in arr(p.get("disk_io")) {
            ui.horizontal(|ui| {
                ui.monospace(s(d, "name"));
                ui.label(format!(
                    "{} {}/s · {} {}/s",
                    tr_in(SCOPE, l, "read"),
                    human_bytes(f(d, "read_rate").unwrap_or(0.0) as u64),
                    tr_in(SCOPE, l, "write"),
                    human_bytes(f(d, "write_rate").unwrap_or(0.0) as u64)
                ));
            });
        }
        if let Some(w) = p.get("write_sect_since_reboot").and_then(Value::as_u64) {
            ui.horizontal(|ui| {
                self.label(ui, l, "disk.writes", "Written since boot");
                ui.label(human_bytes(w.saturating_mul(512)));
            });
        }
    }

    fn network_tab(&mut self, ui: &mut Ui, l: Lang) {
        let rows = link_rows(arr(self.net.as_ref()), false);
        let cols = [
            col("Name").help("resources.col.name"),
            col("Link").help("resources.col.link"),
            num("Rx").help("resources.col.rx"),
            num("Tx").help("resources.col.tx"),
            num("Rx pps"),
            num("Tx pps"),
            col("Errors").help("resources.col.errors"),
            col("Drops").help("resources.col.drops"),
        ];
        ui.horizontal(|ui| {
            self.label(ui, l, "tab.network", "Network");
            table::find_field(ui, T_NET, &mut self.links);
        });
        let out = table::show(ui, T_NET, 0.0, &mut self.links, &cols, &rows, |_, _| {});
        if let Some(k) = out.help {
            self.help = Some(HelpView::new(k, col_title(&cols, k, l)));
        }
    }

    fn sensors_tab(&mut self, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = arr(self.sensors.as_ref())
            .iter()
            .map(|x| {
                let lim = |k| f(x, k).map_or_else(|| "–".into(), |v| format!("{v:.0} {}", s(x, "unit")));
                let st = s(x, "state");
                Row {
                    key: s(x, "name").to_owned(),
                    cells: vec![
                        s(x, "chip").to_owned(),
                        s(x, "label").to_owned(),
                        s(x, "type").to_owned(),
                        format!("{} {}", f(x, "value").map_or_else(|| "–".into(), |v| if v.fract() == 0.0 { format!("{v:.0}") } else { format!("{v:.1}") }), s(x, "unit")),
                        lim("max"),
                        lim("crit"),
                        crate::chip::cell("", &[(st, level_kind(st))]),
                    ],
                    dimmed: false,
                    section: false,
                    tint: None,
                }
            })
            .collect();
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "This router reports no sensors."));
            return;
        }
        let cols = [
            col("Chip").help("resources.col.chip"),
            col("Sensor"),
            col("Type"),
            num("Value"),
            num("Max").help("resources.col.max"),
            num("Crit").help("resources.col.crit"),
            col("State").help("resources.col.state"),
        ];
        let out = table::show(ui, T_SENSORS, 0.0, &mut self.sensor_table, &cols, &rows, |_, _| {});
        if let Some(k) = out.help {
            self.help = Some(HelpView::new(k, col_title(&cols, k, l)));
        }
    }

    fn processes_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            self.label(ui, l, "procs.sort", "Sort by");
            for (key, label) in SORTS {
                let on = self.sort == key || (self.sort.is_empty() && key == "cpu");
                if ui.selectable_label(on, tr_in(SCOPE, l, label)).clicked() {
                    self.sort = key;
                    app.cache.refreshed_at = None;
                }
            }
            table::find_field(ui, T_PROCS, &mut self.proc_table);
        });
        let rows: Vec<Row> = arr(self.procs.as_ref())
            .iter()
            .map(|x| {
                let pid = x.get("pid").and_then(Value::as_u64).unwrap_or(0);
                Row {
                    key: pid.to_string(),
                    cells: vec![
                        pid.to_string(),
                        s(x, "name").to_owned(),
                        s(x, "state").to_owned(),
                        x.get("threads").and_then(Value::as_u64).unwrap_or(0).to_string(),
                        f(x, "cpu").map_or_else(|| "–".into(), |c| format!("{c:.1} %")),
                        human_bytes(x.get("memory").and_then(Value::as_u64).unwrap_or(0)),
                    ],
                    dimmed: false,
                    section: false,
                    tint: None,
                }
            })
            .collect();
        let cols = [
            num("PID"),
            col("Name"),
            col("State").help("resources.col.proc_state"),
            num("Threads"),
            num("CPU").help("resources.col.proc_cpu"),
            num("Memory").help("resources.col.proc_mem"),
        ];
        let out = table::show(ui, T_PROCS, 0.0, &mut self.proc_table, &cols, &rows, |_, _| {});
        if let Some(k) = out.help {
            self.help = Some(HelpView::new(k, col_title(&cols, k, l)));
        }
    }
}

/// The title of the column whose ⓘ is `key`, translated.
fn col_title(cols: &[table::Column], key: &str, l: Lang) -> String {
    cols.iter()
        .find(|c| c.help == key)
        .map_or_else(|| key.to_owned(), |c| tr_in(SCOPE, l, c.title).to_owned())
}

/// English names the engine sends for its checks, as `'static` keys of
/// the label catalog (unknown ones fall back to a generic label).
fn static_name(name: &str) -> &'static str {
    [
        "CPU",
        "Memory pressure",
        "Swap",
        "Disk",
        "Temperature",
        "NIC errors",
        "Conntrack",
        "CGNAT ports",
        "OOM kills",
        "NTP",
        "Services",
        "RSS balance",
    ]
    .into_iter()
    .find(|n| *n == name)
    .unwrap_or("Check")
}

fn level_kind(level: &str) -> crate::chip::Kind {
    use crate::chip::Kind;
    match level {
        "ok" => Kind::Green,
        "warning" => Kind::Amber,
        "error" => Kind::Red,
        _ => Kind::Neutral,
    }
}

/// Rows of the links table (`brief`: Overview's five columns).
fn link_rows(rows: &[Value], brief: bool) -> Vec<Row> {
    let rate = |v: Option<f64>| v.map_or_else(|| "–".into(), crate::torch::rate);
    rows.iter()
        .filter(|r| !brief || s(r, "name") != "lo")
        .map(|r| {
            let up = r.get("running").and_then(Value::as_bool).unwrap_or(false);
            let speed = r.get("speed_mbps").and_then(Value::as_u64);
            let link = match (up, speed) {
                (true, Some(m)) if m >= 1000 => format!("{} G", m / 1000),
                (true, Some(m)) => format!("{m} M"),
                (true, None) => "up".into(),
                (false, _) => "down".into(),
            };
            let link_cell = crate::chip::cell("", &[(&link, if up { crate::chip::Kind::Green } else { crate::chip::Kind::Neutral })]);
            let eps = f(r, "errors_per_second").unwrap_or(0.0);
            let dps = f(r, "drops_per_second").unwrap_or(0.0);
            let errs = r.get("rx_errors").and_then(Value::as_u64).unwrap_or(0) + r.get("tx_errors").and_then(Value::as_u64).unwrap_or(0);
            let drops = r.get("rx_drops").and_then(Value::as_u64).unwrap_or(0) + r.get("tx_drops").and_then(Value::as_u64).unwrap_or(0);
            let counter = |total: u64, per_s: f64, warn: f64| {
                let kind = if per_s >= warn { crate::chip::Kind::Amber } else { crate::chip::Kind::Neutral };
                let text = if per_s > 0.0 { format!("{per_s:.1}/s") } else { "0/s".into() };
                crate::chip::cell(&total.to_string(), &[(&text, kind)])
            };
            let mut cells = vec![
                s(r, "name").to_owned(),
                link_cell,
                rate(f(r, "rx_bits_per_second")),
                rate(f(r, "tx_bits_per_second")),
            ];
            if !brief {
                cells.push(f(r, "rx_packets_per_second").map_or_else(|| "–".into(), |v| format!("{v:.0}")));
                cells.push(f(r, "tx_packets_per_second").map_or_else(|| "–".into(), |v| format!("{v:.0}")));
                cells.push(counter(errs, eps, f64::MIN_POSITIVE));
                cells.push(counter(drops, dps, 100.0));
            } else {
                cells.push(counter(errs + drops, eps + dps, f64::MIN_POSITIVE));
            }
            Row {
                key: s(r, "name").to_owned(),
                cells,
                dimmed: !up,
                section: false,
                tint: None,
            }
        })
        .collect()
}

/// A thin bar with text, coloured by how full it is.
fn bar(ui: &mut Ui, frac: f64, text: &str) {
    let frac = frac.clamp(0.0, 1.0) as f32;
    let t = tone(ui.visuals(), used_level(f64::from(frac) * 100.0));
    ui.add(ProgressBar::new(frac).desired_height(8.0).fill(t.ink));
    ui.label(RichText::new(text).small());
}

/// A sparkline of `points` (oldest first), 0 at the bottom; `top` fixes
/// the scale (100 %), else the highest point.
fn sparkline(ui: &mut Ui, points: &[Option<f64>], top: Option<f64>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width().min(220.0), 28.0), Sense::hover());
    let v = ui.visuals();
    ui.painter().rect_filled(rect, 2.0, v.extreme_bg_color);
    let max = top
        .or_else(|| points.iter().flatten().copied().reduce(f64::max))
        .filter(|m| *m > 0.0)
        .unwrap_or(1.0);
    let n = points.len().max(2) - 1;
    let ink = crate::chip::BLUE.tone(v).ink;
    let mut run = Vec::new();
    for (i, p) in points.iter().enumerate() {
        match p {
            Some(p) => {
                let x = rect.left() + rect.width() * i as f32 / n as f32;
                let y = rect.bottom() - rect.height() * ((p / max).clamp(0.0, 1.0) as f32);
                run.push(pos2(x, y));
            }
            None => {
                if run.len() > 1 {
                    ui.painter().line(std::mem::take(&mut run), Stroke::new(1.3, ink));
                }
                run.clear();
            }
        }
    }
    if run.len() > 1 {
        ui.painter().line(run, Stroke::new(1.3, ink));
    }
}

/// One core's bar: user, system, irq and softirq stacked, %.
fn stacked_bar(ui: &mut Ui, width: f32, parts: [Option<f64>; 4]) {
    let h = ui.spacing().interact_size.y * 0.55;
    let (rect, resp) = ui.allocate_exact_size(vec2(width, h), Sense::hover());
    let v = ui.visuals();
    ui.painter().rect_filled(rect, 2.0, v.extreme_bg_color);
    let hues = [crate::chip::BLUE.tone(v).ink, crate::chip::GREEN.tone(v).ink, AMBER.tone(v).ink, RED.tone(v).ink];
    let mut x = rect.left();
    for (p, ink) in parts.iter().zip(hues) {
        let w = rect.width() * (p.unwrap_or(0.0) / 100.0).clamp(0.0, 1.0) as f32;
        if w > 0.0 {
            let r = egui::Rect::from_min_size(pos2(x, rect.top()), vec2(w, rect.height()));
            ui.painter().rect_filled(r, 0.0, ink);
            x += w;
        }
    }
    let p = |i: usize| parts.get(i).copied().flatten().unwrap_or(0.0);
    resp.on_hover_text(format!("user {:.1} % · system {:.1} % · irq {:.1} % · softirq {:.1} %", p(0), p(1), p(2), p(3)));
}

/// The health chip: `ok`, `1 aviso`, `2 erros`, with the totals.
fn health_chip(ui: &mut Ui, st: &str, warnings: u64, errors: u64, l: Lang) -> egui::Response {
    let text = match st {
        "error" => format!("{} {errors} {}", icons::PULSE, tr_in(SCOPE, l, if errors == 1 { "error" } else { "errors" })),
        "warning" => format!("{} {warnings} {}", icons::PULSE, tr_in(SCOPE, l, if warnings == 1 { "warning" } else { "warnings" })),
        "ok" => format!("{} {}", icons::PULSE, tr_in(SCOPE, l, "healthy")),
        _ => format!("{} …", icons::PULSE),
    };
    chip(ui, &text, tone(ui.visuals(), st))
}

pub(crate) fn chip_id() -> Id {
    Id::unique("resources-top-chip")
}

/// The top bar's part, right of the theme switch: the router's live CPU
/// and memory (when Settings turns it on) and the health chip, which opens
/// System › Resources.
pub(crate) fn top_bar(app: &mut CoreRouterUi, ui: &mut Ui) {
    let Some((readout, print, check)) = app
        .panel_mut::<ResourcesPanel>()
        .map(|p| (p.readout, p.print.clone(), p.check.clone()))
    else {
        return;
    };
    // Nothing to show until the router answers with a status (an older
    // router has no health checks).
    let check = check.filter(|c| c.get("status").is_some_and(Value::is_string));
    if check.is_none() && !readout {
        return;
    }
    let l = app.lang.labels;
    // Right to left: the chip first, then the readout at its left.
    let (st, warnings, errors) = status(check.as_ref());
    let drawn = health_chip(ui, st, warnings, errors, l);
    let resp = ui
        .interact(drawn.rect, chip_id(), Sense::click())
        .on_hover_text(tr_in(SCOPE, l, "Router health: click for System › Resources"));
    if resp.clicked() {
        app.open_from_menu(Win::Panel(WIN));
    }
    if readout && let Some(p) = &print {
        let mem = f(p, "memory_used_percent");
        let cpu = f(p, "cpu_load");
        // Right to left: the two thin bars (CPU over memory), then the
        // numbers at their left — about 120 px, next to the theme switch.
        let (rect, bars) = ui.allocate_exact_size(vec2(32.0, 12.0), Sense::hover());
        let vis = ui.visuals();
        for (i, v) in [cpu, mem].into_iter().enumerate() {
            let frac = v.unwrap_or(0.0) / 100.0;
            let row = egui::Rect::from_min_size(rect.min + vec2(0.0, 2.0 + 5.0 * i as f32), vec2(rect.width(), 3.0));
            ui.painter().rect_filled(row, 1.0, vis.extreme_bg_color);
            let ink = tone(vis, used_level(frac * 100.0)).ink;
            let w = row.width() * frac.clamp(0.0, 1.0) as f32;
            ui.painter().rect_filled(egui::Rect::from_min_size(row.min, vec2(w, row.height())), 1.0, ink);
        }
        let text = ui.label(RichText::new(format!("CPU {}  MEM {}", pct(cpu), pct(mem))).small());
        let tip = tr_in(SCOPE, l, "The router's CPU and memory (the daemon this window manages, not this computer). Settings › Top bar turns it off.");
        bars.on_hover_text(tip);
        text.on_hover_text(tip);
    }
}

/// Settings › Top bar: the readout switch.
pub(crate) fn settings_ui(app: &mut CoreRouterUi, ui: &mut Ui) {
    let l = app.lang.labels;
    let mut help = None;
    if let Some(p) = app.panel_mut::<ResourcesPanel>() {
        ui.strong(tr_in(SCOPE, l, "Top bar"));
        ui.horizontal(|ui| {
            ui.checkbox(&mut p.readout, tr_in(SCOPE, l, "Show the router's CPU and memory"));
            if help::info_button(ui, Id::unique("resources-help-readout"), tr_in(SCOPE, l, "Show the router's CPU and memory")).clicked() {
                help = Some(HelpView::new("resources.readout", tr_in(SCOPE, l, "Show the router's CPU and memory")));
            }
        });
    }
    if let Some(h) = help
        && let Some(s) = app.panel_mut::<crate::settings::SettingsPanel>()
    {
        s.help = Some(h);
    }
}

pub(crate) fn prefs(app: &CoreRouterUi) -> Value {
    let readout = crate::panel::all()
        .iter()
        .zip(&app.panels)
        .find_map(|(p, s)| (p.name == NAME).then_some(s.as_ref()))
        .flatten()
        .and_then(|s| (s.as_ref() as &dyn std::any::Any).downcast_ref::<ResourcesPanel>())
        .is_some_and(|p| p.readout);
    json!({"readout": readout})
}

pub(crate) fn apply_prefs(app: &mut CoreRouterUi, v: &Value) {
    if let Some(p) = app.panel_mut::<ResourcesPanel>() {
        p.readout = v.get("readout").and_then(Value::as_bool).unwrap_or(false);
    }
}

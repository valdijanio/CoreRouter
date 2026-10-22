//! The tabs of an "Interface <name>" window (G1.19), WinBox style:
//! General (the editable fields, in `interfaces.rs`, plus MAC addresses and
//! L2 MTU), Status (`interface.ethernet.monitor`), Hardware
//! (`interface.hardware`), Traffic (live bps/pps from `interface.stats`)
//! and Statistics (every counter, with a "Zero view" that only moves this
//! window's baseline; the kernel counters are never reset).
//!
//! While a window is open its queries go out with the UI refresh (the
//! monitor and counters every second, the hardware every 10 s), one of
//! each at a time. Values the router cannot report read "not supported".

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use egui::{CollapsingHeader, Grid, RichText, ScrollArea, Ui};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use serde_json::{Value, json};

use crate::avail::Avail;
use crate::ethernet_tab::{self, CABLE_TEST, Cable, EthEdit, SET, TASK_POLL};
use crate::{CoreRouterUi, Pending, REFRESH_SECS, value_text};

pub(crate) const MONITOR: &str = "interface.ethernet.monitor";
pub(crate) const HARDWARE: &str = "interface.hardware";
pub(crate) const STATS: &str = "interface.stats";
/// The hardware rarely changes: asked again this often.
const HARDWARE_SECS: f64 = 10.0;
/// A query unanswered this long is asked again (the reply was lost).
const STALE_SECS: f64 = 15.0;
/// Traffic samples kept (about two minutes at one per second).
const HISTORY: usize = 120;
/// Height of the tab area, so switching tabs does not resize the window.
const BODY_HEIGHT: f32 = 380.0;
const BODY_WIDTH: f32 = 470.0;
const NOT_SUPPORTED: &str = "not supported";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    General,
    Ethernet,
    Status,
    Sfp,
    Hardware,
    Traffic,
    Stats,
}

impl Tab {
    pub(crate) const ALL: [Tab; 7] = [
        Tab::General,
        Tab::Ethernet,
        Tab::Status,
        Tab::Sfp,
        Tab::Hardware,
        Tab::Traffic,
        Tab::Stats,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Tab::General => "General",
            Tab::Ethernet => "Ethernet",
            Tab::Status => "Status",
            Tab::Sfp => "SFP",
            Tab::Hardware => "Hardware",
            Tab::Traffic => "Traffic",
            Tab::Stats => "Statistics",
        }
    }
}

/// Which query a reply answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum What {
    Monitor,
    Hardware,
    Stats,
    /// The operator's actions from the Ethernet tab (G1.20).
    CableStart,
    CablePoll,
    Reset,
}

impl What {
    /// The periodic queries.
    const ALL: [What; 3] = [What::Monitor, What::Hardware, What::Stats];

    fn command(self) -> &'static str {
        match self {
            What::Monitor => MONITOR,
            What::Hardware => HARDWARE,
            What::Stats => STATS,
            What::CableStart => CABLE_TEST,
            What::CablePoll => TASK_POLL,
            What::Reset => SET,
        }
    }

    fn every(self) -> f64 {
        match self {
            What::Hardware => HARDWARE_SECS,
            What::CablePoll => 0.5,
            _ => REFRESH_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NicReq {
    pub name: String,
    pub what: What,
}

/// Rates at one moment: seconds since the window opened, then rx/tx bits
/// and packets per second.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rate {
    t: f64,
    rx_bps: f64,
    tx_bps: f64,
    rx_pps: f64,
    tx_pps: f64,
}

/// Live data of one open "Interface <name>" window (UI state only).
#[derive(Default)]
pub(crate) struct NicView {
    monitor: Option<Result<Value, String>>,
    hardware: Option<Result<Value, String>>,
    stats: Option<Result<Value, String>>,
    asked: BTreeMap<What, f64>,
    pending: BTreeSet<What>,
    opened: Option<f64>,
    /// Last counters seen (time, rx/tx bytes, rx/tx packets), for rates.
    last: Option<(f64, [u64; 4])>,
    rates: VecDeque<Rate>,
    /// "Zero view": the value of each (group, counter) when pressed.
    zero: BTreeMap<(String, String), u64>,
    /// The Ethernet tab's edit buffer (G1.20).
    pub(crate) eth: EthEdit,
    pub(crate) cable: Cable,
    /// "Reset to Port Defaults" was pressed.
    pub(crate) reset: bool,
    /// Why the last Ethernet-tab action failed.
    pub(crate) action_error: Option<String>,
}

impl NicView {
    pub(crate) fn monitor_value(&self) -> Option<&Value> {
        match &self.monitor {
            Some(Ok(v)) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn hardware_value(&self) -> Option<&Value> {
        match &self.hardware {
            Some(Ok(v)) => Some(v),
            _ => None,
        }
    }

    /// MAC, factory MAC and L2 MTU for the General tab.
    pub(crate) fn general(&self) -> (Option<String>, Option<String>, Option<String>) {
        let hw = match &self.hardware {
            Some(Ok(v)) => v,
            _ => return (None, None, None),
        };
        let s = |k: &str| hw.get(k).filter(|v| !v.is_null()).map(value_text);
        (s("mac"), s("perm_mac"), s("max_mtu"))
    }

    fn stats_value(&self) -> Option<&Value> {
        match &self.stats {
            Some(Ok(v)) => Some(v),
            _ => None,
        }
    }

    /// A new `interface.stats` at UI time `now`: one traffic sample.
    fn sample(&mut self, now: f64, stats: &Value) {
        let get = |n: &str| counter(stats, "interface", n);
        let (Some(rb), Some(tb), Some(rp), Some(tp)) = (
            get("rx_bytes"),
            get("tx_bytes"),
            get("rx_packets"),
            get("tx_packets"),
        ) else {
            return;
        };
        let cur = [rb, tb, rp, tp];
        let start = *self.opened.get_or_insert(now);
        if let Some((t0, prev)) = self.last {
            let dt = now - t0;
            // A counter that went back (driver reload, wrap) gives no rate.
            let back = cur.iter().zip(prev).any(|(c, p)| *c < p);
            if dt > 0.05 && !back {
                let per = |i: usize| {
                    let d = cur.get(i).zip(prev.get(i)).map_or(0, |(c, p)| c - p);
                    d as f64 / dt
                };
                self.rates.push_back(Rate {
                    t: now - start,
                    rx_bps: per(0) * 8.0,
                    tx_bps: per(1) * 8.0,
                    rx_pps: per(2),
                    tx_pps: per(3),
                });
                while self.rates.len() > HISTORY {
                    self.rates.pop_front();
                }
            }
        }
        self.last = Some((now, cur));
    }

    fn zero_view(&mut self) {
        let Some(stats) = self.stats_value() else {
            return;
        };
        self.zero = groups(stats)
            .flat_map(|(g, cs)| cs.into_iter().map(move |(n, v)| ((g.clone(), n), v)))
            .collect();
    }
}

/// `value` of counter `name` in group `group` of an `interface.stats`.
fn counter(stats: &Value, group: &str, name: &str) -> Option<u64> {
    groups(stats)
        .find(|(g, _)| g == group)?
        .1
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
}

/// The groups of an `interface.stats`, as (name, [(counter, value)]).
fn groups(stats: &Value) -> impl Iterator<Item = (String, Vec<(String, u64)>)> + '_ {
    stats
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|g| {
            let name = g.get("name").map(value_text).unwrap_or_default();
            let counters = g
                .get("counters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|c| {
                    Some((
                        c.get("name").map(value_text)?,
                        c.get("value").and_then(Value::as_u64)?,
                    ))
                })
                .collect();
            (name, counters)
        })
}

impl CoreRouterUi {
    /// Names of the open "Interface <name>" windows.
    fn props_open(&self) -> Vec<String> {
        self.dialogs
            .iter()
            .filter_map(|d| match &d.dialog {
                crate::interfaces::Dialog::Props(p) => Some(p.name.clone()),
                _ => None,
            })
            .collect()
    }

    /// Ask what the open interface windows show, when due.
    pub(crate) fn nic_tick(&mut self, now: f64) {
        let open = self.props_open();
        self.nic.retain(|name, _| open.contains(name));
        for name in open {
            let view = self.nic.entry(name.clone()).or_default();
            view.opened.get_or_insert(now);
            // A reply lost with the link: ask again after a while.
            let asked = view.asked.clone();
            view.pending
                .retain(|w| asked.get(w).is_some_and(|t| now - t < STALE_SECS));
            let due: Vec<What> = What::ALL
                .into_iter()
                .filter(|w| !view.pending.contains(w))
                .filter(|w| view.asked.get(w).is_none_or(|t| now - t >= w.every()))
                .collect();
            let mut due = due;
            if let Some(v) = self.nic.get(&name) {
                due.extend(actions(v, now));
            }
            for what in due {
                let params = match self.nic.get_mut(&name) {
                    Some(v) => action_params(v, what, &name),
                    None => json!({ "name": name }),
                };
                if let Err(why) = self.can.check(what.command()) {
                    if let Some(v) = self.nic.get_mut(&name) {
                        let slot = v.slot(what);
                        *slot = Some(Err(why));
                        v.asked.insert(what, now);
                    }
                    continue;
                }
                let req = self.backend.submit(
                    "engine.execute",
                    json!({"command": what.command(), "params": params}),
                );
                self.pending.insert(
                    req,
                    Pending::Nic(NicReq {
                        name: name.clone(),
                        what,
                    }),
                );
                if let Some(v) = self.nic.get_mut(&name) {
                    v.pending.insert(what);
                    v.asked.insert(what, now);
                }
            }
        }
        self.nic_clock = now;
    }

    /// A reply to one of [`Self::nic_tick`]'s queries (not logged: the UI
    /// asked it, not the operator).
    pub(crate) fn nic_reply(&mut self, req: NicReq, result: Result<Value, String>) {
        let now = self.nic_clock;
        let Some(view) = self.nic.get_mut(&req.name) else {
            return;
        };
        view.pending.remove(&req.what);
        match (req.what, &result) {
            (What::Stats, Ok(v)) => view.sample(now, v),
            (What::Monitor, Ok(v)) => view.eth.seed_link(v),
            (What::Hardware, Ok(v)) => view.eth.seed_offloads(v),
            _ => {}
        }
        match req.what {
            What::Monitor | What::Hardware | What::Stats => *view.slot(req.what) = Some(result),
            What::CableStart => {
                view.cable = match result {
                    Ok(v) => match v.get("id").and_then(Value::as_u64) {
                        Some(id) => Cable::Running { id },
                        None => Cable::Failed(format!("no task id in {v}")),
                    },
                    Err(e) => Cable::Failed(e),
                };
            }
            What::CablePoll => match result {
                Ok(v) if v.get("done") == Some(&Value::Bool(true)) => {
                    view.cable = if v.get("state").and_then(Value::as_str) == Some("done") {
                        Cable::Done(v.get("summary").cloned().unwrap_or(Value::Null))
                    } else {
                        let why = v.get("reason").map(value_text).unwrap_or_default();
                        Cable::Failed(format!(
                            "cable test {}: {why}",
                            v.get("state").map(value_text).unwrap_or_default()
                        ))
                    };
                }
                Ok(_) => {}
                Err(e) => view.cable = Cable::Failed(e),
            },
            What::Reset => match result {
                Ok(_) => {
                    // The form starts over from the router's next answers.
                    view.eth = EthEdit::default();
                    view.action_error = None;
                    view.asked.remove(&What::Monitor);
                    view.asked.remove(&What::Hardware);
                }
                Err(e) => view.action_error = Some(e),
            },
        }
    }
}

/// The Ethernet tab's actions due now: a pressed button, a running test.
fn actions(v: &NicView, now: f64) -> Vec<What> {
    let mut out = Vec::new();
    let free = |w: What| !v.pending.contains(&w);
    if v.cable == Cable::Requested && free(What::CableStart) {
        out.push(What::CableStart);
    }
    if matches!(v.cable, Cable::Running { .. })
        && free(What::CablePoll)
        && v.asked
            .get(&What::CablePoll)
            .is_none_or(|t| now - t >= What::CablePoll.every())
    {
        out.push(What::CablePoll);
    }
    if v.reset && free(What::Reset) {
        out.push(What::Reset);
    }
    out
}

/// The params of `what` for window `name` (and the state change it means).
fn action_params(v: &mut NicView, what: What, name: &str) -> Value {
    match what {
        What::CableStart => {
            v.cable = Cable::Starting;
            json!({ "name": name })
        }
        What::CablePoll => match v.cable {
            Cable::Running { id } => json!({ "id": id }),
            _ => json!({ "name": name }),
        },
        What::Reset => {
            v.reset = false;
            json!({ "name": name, "reset": true })
        }
        What::Monitor | What::Hardware | What::Stats => json!({ "name": name }),
    }
}

impl NicView {
    fn slot(&mut self, what: What) -> &mut Option<Result<Value, String>> {
        match what {
            What::Monitor => &mut self.monitor,
            What::Hardware => &mut self.hardware,
            What::Stats | What::CableStart | What::CablePoll | What::Reset => &mut self.stats,
        }
    }
}

/// The tab buttons on top of the window; SFP is coloured while a module
/// reading is past its thresholds.
pub(crate) fn tab_bar(ui: &mut Ui, tab: &mut Tab, view: Option<&NicView>) {
    let alert = view.and_then(ethernet_tab::sfp_alert);
    ui.horizontal(|ui| {
        for t in Tab::ALL {
            let label = match (t, alert) {
                (Tab::Sfp, Some(true)) => RichText::new("SFP ⚠").color(ui.visuals().error_fg_color),
                (Tab::Sfp, Some(false)) => RichText::new("SFP ⚠").color(ui.visuals().warn_fg_color),
                _ => RichText::new(t.label()),
            };
            ui.selectable_value(tab, t, label);
        }
    });
    ui.separator();
}

/// Draw tab `tab` in a fixed-size scrolling area (switching tabs does not
/// resize the window); `general` draws the General tab's fields.
pub(crate) fn body(
    ui: &mut Ui,
    tab: Tab,
    view: Option<&mut NicView>,
    can: &Avail,
    general: impl FnOnce(&mut Ui, Option<&NicView>),
) {
    ui.set_min_width(BODY_WIDTH);
    if tab == Tab::General {
        // Editable fields: no scrolling, so they lay out on the first frame.
        let size = egui::vec2(BODY_WIDTH, BODY_HEIGHT);
        ui.allocate_ui_with_layout(size, egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.set_min_size(size);
            general(ui, view.as_deref());
        });
        return;
    }
    ScrollArea::vertical()
        .id_salt(("iface-tab", tab.label()))
        .max_height(BODY_HEIGHT)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_height(BODY_HEIGHT);
            let Some(view) = view else {
                ui.weak("Loading…");
                return;
            };
            match tab {
                Tab::General => {}
                Tab::Ethernet => ethernet_tab::ethernet(ui, view, can),
                Tab::Status => status(ui, view),
                Tab::Sfp => ethernet_tab::sfp(ui, view),
                Tab::Hardware => hardware(ui, view),
                Tab::Traffic => traffic(ui, view),
                Tab::Stats => statistics(ui, view),
            }
        });
}

/// The reply of a query, or why there is none yet: "Loading…", the error.
fn loaded<'a>(ui: &mut Ui, r: &'a Option<Result<Value, String>>) -> Option<&'a Value> {
    match r {
        None => {
            ui.weak("Loading…");
            None
        }
        Some(Err(e)) => {
            ui.colored_label(ui.visuals().error_fg_color, e);
            None
        }
        Some(Ok(v)) => {
            if v.get("available") == Some(&Value::Bool(false)) {
                let why = v.get("reason").map(value_text).unwrap_or_default();
                ui.label(
                    RichText::new(format!("Not supported here: {why}"))
                        .weak()
                        .italics(),
                );
                ui.add_space(4.0);
            }
            Some(v)
        }
    }
}

/// One `label: value` row; a missing value reads "not supported".
fn row(ui: &mut Ui, label: &str, value: Option<String>) {
    ui.label(label);
    match value {
        Some(v) => ui.label(v),
        None => ui.weak(NOT_SUPPORTED),
    };
    ui.end_row();
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).filter(|x| !x.is_null()).map(value_text)
}

fn yes_no(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_bool)
        .map(|b| if b { "yes" } else { "no" }.to_owned())
}

fn list(v: &Value, key: &str) -> Option<String> {
    let items: Vec<String> = v.get(key)?.as_array()?.iter().map(value_text).collect();
    (!items.is_empty()).then(|| items.join(", "))
}

/// `when` (unix seconds) relative to `now`: "5m12s ago".
fn ago(v: &Value, key: &str) -> Option<String> {
    let when = v.get(key)?.as_u64()?;
    let now = v.get("now")?.as_u64()?;
    Some(format!(
        "{} ago",
        crate::firewall::duration(now.saturating_sub(when))
    ))
}

fn status(ui: &mut Ui, view: &NicView) {
    let Some(m) = loaded(ui, &view.monitor) else {
        return;
    };
    let ok = m.get("status").and_then(Value::as_str) == Some("link-ok");
    Grid::new("iface-status")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label("Status");
            let green = if ui.visuals().dark_mode {
                egui::Color32::from_rgb(90, 200, 110)
            } else {
                egui::Color32::from_rgb(30, 130, 50)
            };
            let (color, label) = if ok {
                (green, "link-ok")
            } else {
                (ui.visuals().error_fg_color, "no-link")
            };
            ui.label(RichText::new(label).color(color).strong());
            ui.end_row();
            row(
                ui,
                "Rate",
                text(m, "rate").or_else(|| ok.then(|| "unknown".into())),
            );
            row(ui, "Full Duplex", yes_no(m, "full_duplex"));
            row(ui, "Auto Negotiation", text(m, "auto_negotiation"));
            row(ui, "Port", text(m, "port"));
            let mdix = match (text(m, "mdix"), text(m, "mdix_ctrl")) {
                (Some(now), Some(ctrl)) => Some(format!("{now} ({ctrl})")),
                (a, b) => a.or(b),
            };
            row(ui, "MDI/MDI-X", mdix);
            row(ui, "Rx Flow Control", yes_no(m, "rx_flow_control"));
            row(ui, "Tx Flow Control", yes_no(m, "tx_flow_control"));
            row(
                ui,
                "Flow Control Autoneg",
                yes_no(m, "flow_control_autoneg"),
            );
            row(ui, "Link Downs", text(m, "link_downs"));
            row(ui, "Carrier Changes", text(m, "carrier_changes"));
            // Times are known only since the router began watching (it
            // has a clock); before that, "unknown".
            let watching = m.get("watching_since").and_then(Value::as_u64);
            let now = m.get("now").and_then(Value::as_u64);
            let never = |what: &str| match (watching, now) {
                (Some(s), Some(n)) => format!(
                    "{what} watching began ({} ago)",
                    crate::firewall::duration(n.saturating_sub(s))
                ),
                _ => "unknown (the router has no clock)".to_owned(),
            };
            let up = ago(m, "last_link_up_time")
                .unwrap_or_else(|| never(if ok { "up since before" } else { "not since" }));
            row(ui, "Last Link Up", Some(up));
            let down = ago(m, "last_link_down_time").unwrap_or_else(|| never("not since"));
            row(ui, "Last Link Down", Some(down));
            if let Some(why) = text(m, "down_reason") {
                row(ui, "Down Reason", Some(why));
            }
            for (label, key) in [
                ("Supported", "supported_modes"),
                ("Advertising", "advertising"),
                ("Link Partner", "link_partner_advertising"),
            ] {
                ui.label(label);
                match list(m, key) {
                    Some(l) => ui.add(egui::Label::new(l).wrap()),
                    None => ui.weak(NOT_SUPPORTED),
                };
                ui.end_row();
            }
        });
    notes(ui, m);
}

fn hardware(ui: &mut Ui, view: &NicView) {
    let Some(h) = loaded(ui, &view.hardware) else {
        return;
    };
    let named = |name: &str, id: &str| match (text(h, name), text(h, id)) {
        (Some(n), Some(i)) => Some(format!("{n} [{i}]")),
        (n, i) => n.or(i),
    };
    let pair = |a: &str, b: &str, sep: &str| match (text(h, a), text(h, b)) {
        (Some(x), Some(y)) => Some(format!("{x}{sep}{y}")),
        (x, y) => x.or(y),
    };
    Grid::new("iface-hw")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            row(ui, "Vendor", named("vendor", "vendor_id"));
            row(ui, "Model", named("model", "device_id"));
            let sub = match (
                text(h, "subsystem"),
                pair("subsystem_vendor_id", "subsystem_device_id", ":"),
            ) {
                (Some(n), Some(i)) => Some(format!("{n} [{i}]")),
                (n, i) => n.or(i),
            };
            row(ui, "Subsystem", sub);
            row(ui, "Driver", text(h, "driver"));
            row(ui, "Driver Version", text(h, "driver_version"));
            row(ui, "Firmware", text(h, "firmware"));
            row(ui, "Serial", text(h, "serial"));
            row(ui, "Bus", pair("bus", "bus_address", " "));
            row(ui, "NUMA Node", text(h, "numa_node"));
            row(ui, "Queues (rx/tx)", pair("rx_queues", "tx_queues", " / "));
            row(
                ui,
                "Channels",
                pair("combined_channels", "combined_channels_max", " of max "),
            );
            row(ui, "Rx Ring", pair("ring_rx", "ring_rx_max", " of max "));
            row(ui, "Tx Ring", pair("ring_tx", "ring_tx_max", " of max "));
            row(ui, "IRQs", list(h, "irqs"));
            row(ui, "MTU range", pair("min_mtu", "max_mtu", " – "));
        });
    let offloads: Vec<&Value> = h
        .get("offloads")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    ui.add_space(6.0);
    ui.label(RichText::new("Offloads").strong());
    if offloads.is_empty() {
        ui.weak(NOT_SUPPORTED);
    } else {
        Grid::new("iface-offloads")
            .num_columns(3)
            .spacing([12.0, 2.0])
            .striped(true)
            .show(ui, |ui| {
                for o in offloads {
                    let on = o.get("active").and_then(Value::as_bool).unwrap_or(false);
                    let fixed = o.get("fixed").and_then(Value::as_bool).unwrap_or(false);
                    ui.label(o.get("name").map(value_text).unwrap_or_default())
                        .on_hover_text(o.get("feature").map(value_text).unwrap_or_default());
                    ui.label(if on { "on" } else { "off" });
                    if fixed {
                        ui.weak("fixed");
                    } else {
                        ui.label("");
                    }
                    ui.end_row();
                }
            });
    }
    notes(ui, h);
}

/// Driver notes (what was not supported and why), folded.
fn notes(ui: &mut Ui, v: &Value) {
    let Some(notes) = v
        .get("notes")
        .and_then(Value::as_array)
        .filter(|n| !n.is_empty())
    else {
        return;
    };
    ui.add_space(6.0);
    CollapsingHeader::new(format!("Notes ({})", notes.len()))
        .id_salt("iface-notes")
        .show(ui, |ui| {
            for n in notes {
                ui.weak(value_text(n));
            }
        });
}

/// 1_500_000 → "1.5 Mbps".
pub(crate) fn bits(v: f64) -> String {
    scaled(v, "bps")
}

pub(crate) fn packets(v: f64) -> String {
    scaled(v, "pps")
}

fn scaled(v: f64, unit: &str) -> String {
    let (n, p) = if v >= 1e9 {
        (v / 1e9, "G")
    } else if v >= 1e6 {
        (v / 1e6, "M")
    } else if v >= 1e3 {
        (v / 1e3, "k")
    } else {
        return format!("{v:.0} {unit}");
    };
    format!("{n:.1} {p}{unit}")
}

/// Transmit and receive colours, as in WinBox's traffic graphs.
const TX: egui::Color32 = egui::Color32::from_rgb(220, 60, 60);
const RX: egui::Color32 = egui::Color32::from_rgb(40, 120, 220);

fn traffic(ui: &mut Ui, view: &NicView) {
    let last = view.rates.back();
    Grid::new("iface-rates")
        .num_columns(4)
        .spacing([12.0, 2.0])
        .show(ui, |ui| {
            ui.label("Tx");
            ui.label(RichText::new(last.map_or("-".into(), |r| bits(r.tx_bps))).color(TX));
            ui.label(RichText::new(last.map_or("-".into(), |r| packets(r.tx_pps))).color(TX));
            ui.end_row();
            ui.label("Rx");
            ui.label(RichText::new(last.map_or("-".into(), |r| bits(r.rx_bps))).color(RX));
            ui.label(RichText::new(last.map_or("-".into(), |r| packets(r.rx_pps))).color(RX));
            ui.end_row();
        });
    if view.rates.is_empty() {
        ui.weak("Collecting samples…");
    }
    let series =
        |f: fn(&Rate) -> f64| -> Vec<[f64; 2]> { view.rates.iter().map(|r| [r.t, f(r)]).collect() };
    let chart = |ui: &mut Ui, id: &str, unit: &str, tx: Vec<[f64; 2]>, rx: Vec<[f64; 2]>| {
        let fmt: fn(f64) -> String = if unit == "bps" { bits } else { packets };
        Plot::new(id)
            .height(130.0)
            .legend(Legend::default())
            .include_y(0.0)
            .x_axis_label("s")
            .y_axis_formatter(move |m, _| fmt(m.value))
            .allow_scroll(false)
            .allow_drag(false)
            .allow_zoom(false)
            .show(ui, |p| {
                p.line(
                    Line::new(format!("Tx {unit}"), PlotPoints::from(tx))
                        .color(TX)
                        .width(1.5),
                );
                p.line(
                    Line::new(format!("Rx {unit}"), PlotPoints::from(rx))
                        .color(RX)
                        .width(1.5),
                );
            });
    };
    chart(
        ui,
        "iface-bps",
        "bps",
        series(|r| r.tx_bps),
        series(|r| r.rx_bps),
    );
    chart(
        ui,
        "iface-pps",
        "pps",
        series(|r| r.tx_pps),
        series(|r| r.rx_pps),
    );
}

/// `rx_crc_errors` → `rx-crc-errors` (RouterOS spelling).
fn kebab(s: &str) -> String {
    s.replace('_', "-")
}

fn statistics(ui: &mut Ui, view: &mut NicView) {
    let mut zero = false;
    let mut unzero = false;
    ui.horizontal(|ui| {
        zero = ui
            .button("Zero view")
            .on_hover_text(
                "Count from now in this window only; the router's counters are not reset",
            )
            .clicked();
        if !view.zero.is_empty() {
            unzero = ui.button("Show totals").clicked();
            ui.weak("counting from \"Zero view\"");
        }
    });
    if zero {
        view.zero_view();
    }
    if unzero {
        view.zero.clear();
    }
    let Some(st) = loaded(ui, &view.stats) else {
        return;
    };
    for (i, (group, counters)) in groups(st).enumerate() {
        CollapsingHeader::new(RichText::new(group.clone()).strong())
            .id_salt(("iface-stats", i))
            .default_open(true)
            .show(ui, |ui| {
                Grid::new(("iface-stats-grid", i))
                    .num_columns(2)
                    .spacing([24.0, 2.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for (name, value) in counters {
                            let base = view
                                .zero
                                .get(&(group.clone(), name.clone()))
                                .copied()
                                .unwrap_or(0);
                            ui.label(kebab(&name));
                            // Right-aligned in a fixed column, so digits line up.
                            let h = ui.text_style_height(&egui::TextStyle::Monospace);
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(150.0, h), egui::Sense::hover());
                            ui.painter().text(
                                rect.right_center(),
                                egui::Align2::RIGHT_CENTER,
                                value.saturating_sub(base).to_string(),
                                egui::TextStyle::Monospace.resolve(ui.style()),
                                ui.visuals().text_color(),
                            );
                            ui.end_row();
                        }
                    });
            });
    }
    notes(ui, st);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(rx: u64, tx: u64) -> Value {
        json!({"groups": [{"name": "interface", "counters": [
            {"name": "rx_bytes", "value": rx},
            {"name": "tx_bytes", "value": tx},
            {"name": "rx_packets", "value": rx / 100},
            {"name": "tx_packets", "value": tx / 100},
        ]}]})
    }

    #[test]
    fn rates_come_from_counter_deltas() {
        let mut v = NicView::default();
        v.sample(10.0, &stats(0, 0));
        assert!(v.rates.is_empty(), "one sample has no rate");
        v.sample(12.0, &stats(2_000, 1_000));
        let r = v.rates.back().copied().unwrap();
        assert_eq!(r.t, 2.0);
        assert_eq!(r.rx_bps, 8_000.0);
        assert_eq!(r.tx_bps, 4_000.0);
        assert_eq!(r.rx_pps, 10.0);
        // Counters that went back (reset) give no sample, then resume.
        v.sample(13.0, &stats(10, 10));
        assert_eq!(v.rates.len(), 1);
        v.sample(14.0, &stats(110, 10));
        assert_eq!(v.rates.back().unwrap().rx_bps, 800.0);
        for i in 0..300u32 {
            v.sample(15.0 + f64::from(i), &stats(200 + u64::from(i), 10));
        }
        assert_eq!(v.rates.len(), HISTORY);
    }

    #[test]
    fn zero_view_moves_only_the_baseline() {
        let mut v = NicView {
            stats: Some(Ok(stats(5_000, 7_000))),
            ..NicView::default()
        };
        v.zero_view();
        assert_eq!(
            v.zero.get(&("interface".into(), "rx_bytes".into())),
            Some(&5_000)
        );
        assert_eq!(
            counter(v.stats_value().unwrap(), "interface", "rx_bytes"),
            Some(5_000)
        );
    }

    #[test]
    fn units_scale() {
        assert_eq!(bits(999.0), "999 bps");
        assert_eq!(bits(1_500_000.0), "1.5 Mbps");
        assert_eq!(bits(10e9), "10.0 Gbps");
        assert_eq!(packets(2_500.0), "2.5 kpps");
        assert_eq!(kebab("rx_crc_errors"), "rx-crc-errors");
    }
}

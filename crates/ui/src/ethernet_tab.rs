//! The Ethernet and SFP tabs of "Interface <name>" (G1.20).
//!
//! Ethernet edits what `interface.ethernet.set` takes (auto-negotiation,
//! advertised modes or a forced rate, flow control, offloads) and sends it
//! with the window's OK/Apply; the engine checks it against the port. What
//! the driver does not let change is grey, with the reason on hover. The
//! cable test is a button: it starts `interface.ethernet.cable-test` and
//! follows the task. SFP shows the module and its DOM readings against the
//! module's own thresholds; a reading past one is coloured, and so is the
//! tab.
//!
//! The form starts from the router's answers (monitor and hardware) the
//! first time they arrive and is not overwritten by the refreshes after.

use std::collections::{BTreeMap, BTreeSet};

use egui::{Color32, Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::avail::Avail;
use crate::iface_tabs::NicView;
use crate::value_text;

pub(crate) const SET: &str = "interface.ethernet.set";
pub(crate) const CABLE_TEST: &str = "interface.ethernet.cable-test";
pub(crate) const TASK_POLL: &str = "tool.task.poll";
const FLOW: [&str; 3] = ["off", "on", "auto"];

/// The link part of the form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EthForm {
    pub autoneg: bool,
    pub advertise: BTreeSet<String>,
    /// The rate mode forced when not auto-negotiating.
    pub forced: String,
    pub rx: String,
    pub tx: String,
}

/// Edit buffer of the Ethernet tab: what the operator set, and what the
/// router had (only differences are sent).
#[derive(Debug, Clone, Default)]
pub(crate) struct EthEdit {
    pub form: Option<EthForm>,
    base: Option<EthForm>,
    /// Feature → on, for the offloads the driver lets change.
    pub offloads: BTreeMap<String, bool>,
    base_offloads: BTreeMap<String, bool>,
}

/// Rate modes (`1000baseT/Full`), the ones `interface.ethernet.set` takes.
fn rate_mode(m: &str) -> bool {
    m.split_once("base")
        .is_some_and(|(r, rest)| r.parse::<u32>().is_ok() && rest.contains('/'))
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `on`/`off`/`auto` of a flow-control direction: as configured, else as
/// the port runs it.
fn flow_of(m: &Value, key: &str) -> String {
    if let Some(c) = m
        .get("configured")
        .and_then(|c| c.get(key))
        .and_then(Value::as_str)
    {
        return c.to_owned();
    }
    let on = m.get(key).and_then(Value::as_bool).unwrap_or(false);
    let auto = m.get("flow_control_autoneg").and_then(Value::as_bool) == Some(true);
    match (on, auto) {
        (_, true) => "auto",
        (true, false) => "on",
        (false, false) => "off",
    }
    .to_owned()
}

impl EthEdit {
    /// Fill the link part from the first monitor answer.
    pub(crate) fn seed_link(&mut self, m: &Value) {
        if self.form.is_some() {
            return;
        }
        if m.get("available") == Some(&Value::Bool(false)) {
            return;
        }
        let supported: Vec<String> = strings(m, "supported_modes")
            .into_iter()
            .filter(|x| rate_mode(x))
            .collect();
        let speed = m.get("speed_mbps").and_then(Value::as_u64);
        let full = m
            .get("full_duplex")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let current = supported
            .iter()
            .find(|x| {
                let rate = x.split("base").next().and_then(|r| r.parse::<u64>().ok());
                rate == speed && x.ends_with(if full { "/Full" } else { "/Half" })
            })
            .or_else(|| supported.last())
            .cloned()
            .unwrap_or_default();
        let form = EthForm {
            autoneg: m.get("autoneg").and_then(Value::as_bool).unwrap_or(true),
            advertise: strings(m, "advertising")
                .into_iter()
                .filter(|x| rate_mode(x))
                .collect(),
            forced: current,
            rx: flow_of(m, "rx_flow_control"),
            tx: flow_of(m, "tx_flow_control"),
        };
        self.base = Some(form.clone());
        self.form = Some(form);
    }

    /// Fill the offloads from the first hardware answer.
    pub(crate) fn seed_offloads(&mut self, hw: &Value) {
        if !self.base_offloads.is_empty() {
            return;
        }
        let map: BTreeMap<String, bool> = hw
            .get("offloads")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|o| {
                Some((
                    o.get("feature")?.as_str()?.to_owned(),
                    o.get("active")?.as_bool()?,
                ))
            })
            .collect();
        self.base_offloads = map.clone();
        self.offloads = map;
    }

    /// `interface.ethernet.set` params for what changed, if anything did.
    pub(crate) fn params(&self, name: &str) -> Option<Value> {
        let mut p = serde_json::Map::new();
        if let (Some(f), Some(b)) = (&self.form, &self.base) {
            if f.autoneg != b.autoneg {
                p.insert("auto_negotiation".into(), json!(f.autoneg));
            }
            if f.autoneg && (f.advertise != b.advertise || !b.autoneg) && !f.advertise.is_empty() {
                p.insert("advertise".into(), json!(f.advertise));
            }
            if !f.autoneg && (f.forced != b.forced || b.autoneg) && !f.forced.is_empty() {
                p.insert("speed".into(), json!(f.forced));
            }
            if f.rx != b.rx {
                p.insert("rx_flow_control".into(), json!(f.rx));
            }
            if f.tx != b.tx {
                p.insert("tx_flow_control".into(), json!(f.tx));
            }
        }
        let offloads: serde_json::Map<String, Value> = self
            .offloads
            .iter()
            .filter(|(k, v)| self.base_offloads.get(*k) != Some(*v))
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        if !offloads.is_empty() {
            p.insert("offloads".into(), Value::Object(offloads));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("name".into(), json!(name));
        Some(Value::Object(p))
    }

    /// What was sent is the router's now.
    pub(crate) fn applied(&mut self) {
        self.base = self.form.clone();
        self.base_offloads = self.offloads.clone();
    }

    #[cfg(test)]
    pub(crate) fn dirty(&self) -> bool {
        self.params("").is_some()
    }
}

/// The cable test of one window.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) enum Cable {
    #[default]
    Idle,
    /// The button was pressed; the start goes out with the next tick.
    Requested,
    Starting,
    Running {
        id: u64,
    },
    Done(Value),
    Failed(String),
}

fn amber(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(240, 190, 80)
    } else {
        Color32::from_rgb(170, 110, 0)
    }
}

/// Colour of a DOM level: amber for warnings, red for alarms.
fn level_color(ui: &Ui, level: &str) -> Option<Color32> {
    match level {
        "low-alarm" | "high-alarm" => Some(ui.visuals().error_fg_color),
        "low-warning" | "high-warning" => Some(amber(ui)),
        _ => None,
    }
}

/// The SFP module has readings past their thresholds (the tab is coloured).
pub(crate) fn sfp_alert(view: &NicView) -> Option<bool> {
    let m = view.monitor_value()?;
    let alerts = m.get("sfp")?.get("alerts")?.as_array()?;
    let alarm = alerts
        .iter()
        .filter_map(Value::as_str)
        .any(|a| a.contains("alarm"));
    (!alerts.is_empty()).then_some(alarm)
}

/// A greyed widget row: label, then the reason.
fn grey_row(ui: &mut Ui, label: &str, why: &str) {
    ui.add_enabled(false, egui::Label::new(label));
    ui.weak(why);
    ui.end_row();
}

pub(crate) fn ethernet(ui: &mut Ui, view: &mut NicView, can: &Avail) {
    let Some(m) = view.monitor_value().cloned() else {
        ui.weak("Loading…");
        return;
    };
    if m.get("available") == Some(&Value::Bool(false)) {
        let why = m.get("reason").map(value_text).unwrap_or_default();
        ui.label(
            RichText::new(format!(
                "The driver does not let CoreRouter set this port: {why}"
            ))
            .weak()
            .italics(),
        );
        return;
    }
    let can_reset = can.check(SET);
    ui.horizontal(|ui| {
        let test = can.check(CABLE_TEST);
        let busy = matches!(
            view.cable,
            Cable::Requested | Cable::Starting | Cable::Running { .. }
        );
        let mut b = ui.add_enabled(test.is_ok() && !busy, egui::Button::new("Cable Test"));
        if let Err(why) = &test {
            b = b.on_disabled_hover_text(why);
        }
        if b.on_hover_text("the link drops for a few seconds while the PHY measures")
            .clicked()
        {
            view.cable = Cable::Requested;
        }
        let r = ui.add_enabled(
            can_reset.is_ok(),
            egui::Button::new("Reset to Port Defaults"),
        );
        if r.on_hover_text("forget every setting here: the port goes back to what it had")
            .clicked()
        {
            view.reset = true;
        }
    });
    if let Some(e) = &view.action_error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }
    cable_result(ui, &view.cable);
    ui.separator();
    let editable = can.check(SET);
    let supported: Vec<String> = strings(&m, "supported_modes")
        .into_iter()
        .filter(|x| rate_mode(x))
        .collect();
    let has_pause = m.get("rx_flow_control").is_some_and(|v| !v.is_null());
    let hw = view.hardware_value().cloned();
    let edit = &mut view.eth;
    let Some(form) = edit.form.as_mut() else {
        ui.weak("Loading…");
        return;
    };
    let enabled = editable.is_ok();
    if let Err(why) = &editable {
        ui.weak(format!("Read only: {why}"));
    }
    Grid::new("iface-ethernet")
        .num_columns(2)
        .min_col_width(110.0)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            if supported.is_empty() {
                grey_row(ui, "Auto Negotiation", "the driver lists no link modes");
            } else {
                ui.label("Auto Negotiation");
                ui.add_enabled(enabled, egui::Checkbox::new(&mut form.autoneg, ""));
                ui.end_row();
                ui.label("Speed");
                ui.add_enabled_ui(enabled && !form.autoneg, |ui| {
                    crate::windows::combo(ui, "eth-speed", "rate", &mut form.forced, &supported);
                })
                .response
                .on_disabled_hover_text("forced with auto-negotiation off");
                ui.end_row();
            }
            for (label, value, id) in [
                ("Rx Flow Control", &mut form.rx, "eth-rx"),
                ("Tx Flow Control", &mut form.tx, "eth-tx"),
            ] {
                if has_pause {
                    ui.label(label);
                    let options: Vec<String> = FLOW.iter().map(|s| (*s).to_owned()).collect();
                    ui.add_enabled_ui(enabled, |ui| {
                        crate::windows::combo(ui, id, "off", value, &options);
                    });
                    ui.end_row();
                } else {
                    grey_row(ui, label, "the driver has no pause frames");
                }
            }
        });
    if !supported.is_empty() {
        ui.add_space(4.0);
        ui.label(RichText::new("Advertise").strong())
            .on_hover_text("the link modes offered while auto-negotiating");
        Grid::new("iface-eth-adv")
            .num_columns(3)
            .spacing([18.0, 2.0])
            .show(ui, |ui| {
                for (i, mode) in supported.iter().enumerate() {
                    let mut on = form.advertise.contains(mode);
                    let r = ui
                        .add_enabled(enabled && form.autoneg, egui::Checkbox::new(&mut on, mode))
                        .on_disabled_hover_text("advertised while auto-negotiating");
                    if r.changed() {
                        if on {
                            form.advertise.insert(mode.clone());
                        } else {
                            form.advertise.remove(mode);
                        }
                    }
                    if i % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
    }
    if !form.autoneg && !supported.is_empty() {
        ui.colored_label(
            amber(ui),
            "Auto-negotiation off: the other end must be forced to the same rate and duplex.",
        );
    }

    ui.add_space(6.0);
    ui.label(RichText::new("Offloads").strong());
    let offloads: Vec<Value> = hw
        .as_ref()
        .and_then(|h| h.get("offloads"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if offloads.is_empty() {
        ui.weak("not supported");
    } else {
        Grid::new("iface-eth-offloads")
            .num_columns(3)
            .spacing([18.0, 2.0])
            .show(ui, |ui| {
                for (i, o) in offloads.iter().enumerate() {
                    let name = o.get("name").map(value_text).unwrap_or_default();
                    let feature = o.get("feature").map(value_text).unwrap_or_default();
                    let fixed = o.get("fixed").and_then(Value::as_bool).unwrap_or(false);
                    let mut on = edit.offloads.get(&feature).copied().unwrap_or_else(|| {
                        o.get("active").and_then(Value::as_bool).unwrap_or(false)
                    });
                    let r = ui
                        .add_enabled(enabled && !fixed, egui::Checkbox::new(&mut on, &name))
                        .on_hover_text(&feature)
                        .on_disabled_hover_text(if fixed {
                            format!("{feature}: fixed by the driver")
                        } else {
                            feature.clone()
                        });
                    if r.changed() {
                        edit.offloads.insert(feature, on);
                    }
                    if i % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
        if edit.offloads.get("rx-lro") == Some(&true) {
            ui.colored_label(
                amber(ui),
                "LRO breaks forwarding: the router will refuse it unless forced.",
            );
        }
    }
}

fn cable_result(ui: &mut Ui, cable: &Cable) {
    match cable {
        Cable::Idle => {}
        Cable::Requested | Cable::Starting | Cable::Running { .. } => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Testing the cable…");
            });
        }
        Cable::Failed(why) => {
            ui.colored_label(ui.visuals().error_fg_color, why);
        }
        Cable::Done(summary) => {
            let pairs: Vec<&Value> = summary
                .get("pairs")
                .and_then(Value::as_array)
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            ui.label(format!(
                "cable-pairs: {}",
                summary
                    .get("cable_pairs")
                    .map(value_text)
                    .unwrap_or_default()
            ));
            Grid::new("iface-cable")
                .num_columns(3)
                .striped(true)
                .spacing([16.0, 2.0])
                .show(ui, |ui| {
                    ui.strong("Pair");
                    ui.strong("Status");
                    ui.strong("Distance");
                    ui.end_row();
                    for p in pairs {
                        let status = p.get("status").map(value_text).unwrap_or_default();
                        ui.label(p.get("pair").map(value_text).unwrap_or_default());
                        if status == "ok" {
                            ui.label(&status);
                        } else {
                            ui.colored_label(ui.visuals().error_fg_color, &status);
                        }
                        ui.label(
                            p.get("distance_m")
                                .and_then(Value::as_f64)
                                .map(|d| format!("{d:.1} m"))
                                .unwrap_or_else(|| "-".into()),
                        );
                        ui.end_row();
                    }
                });
        }
    }
}

/// `-3.10 dBm`.
fn reading(v: Option<f64>, unit: &str) -> String {
    match v {
        Some(x) if unit == "V" => format!("{x:.3} V"),
        Some(x) if unit == "C" => format!("{x:.1} °C"),
        Some(x) => format!("{x:.2} {unit}"),
        None => "-".into(),
    }
}

pub(crate) fn sfp(ui: &mut Ui, view: &NicView) {
    let Some(m) = view.monitor_value() else {
        ui.weak("Loading…");
        return;
    };
    let module = match m.get("sfp") {
        Some(v) if !v.is_null() => v,
        _ => {
            let why = m
                .get("sfp_reason")
                .filter(|v| !v.is_null())
                .map(value_text)
                .unwrap_or_else(|| "no module cage".into());
            ui.label(RichText::new(format!("No SFP: {why}")).weak().italics());
            return;
        }
    };
    if module.get("module_present") != Some(&Value::Bool(true)) {
        ui.label(RichText::new("The cage is empty.").weak().italics());
        return;
    }
    let alerts: Vec<String> = strings(module, "alerts");
    for a in &alerts {
        let alarm = a.contains("alarm");
        let color = if alarm {
            ui.visuals().error_fg_color
        } else {
            amber(ui)
        };
        ui.colored_label(color, format!("⚠ {a}"));
    }
    let dom: Vec<&Value> = module
        .get("dom")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    ui.label(RichText::new("Diagnostics (DOM)").strong());
    if dom.is_empty() {
        ui.weak("the module has no diagnostics");
    } else {
        Grid::new("iface-dom")
            .num_columns(6)
            .striped(true)
            .spacing([10.0, 2.0])
            .show(ui, |ui| {
                for h in [
                    "Reading",
                    "Value",
                    "Low Alarm",
                    "Low Warn",
                    "High Warn",
                    "High Alarm",
                ] {
                    ui.strong(h);
                }
                ui.end_row();
                for r in dom {
                    let unit = r.get("unit").and_then(Value::as_str).unwrap_or("");
                    let mut name = r.get("name").map(value_text).unwrap_or_default();
                    if let Some(l) = r.get("lane").and_then(Value::as_u64) {
                        name.push_str(&format!(" {l}"));
                    }
                    let level = r.get("level").and_then(Value::as_str).unwrap_or("");
                    let value = reading(r.get("value").and_then(Value::as_f64), unit);
                    match level_color(ui, level) {
                        Some(c) => {
                            ui.colored_label(c, &name).on_hover_text(level);
                            ui.colored_label(c, RichText::new(value).strong());
                        }
                        None => {
                            ui.label(&name);
                            ui.label(value);
                        }
                    }
                    let lim = |k: &str| {
                        reading(
                            r.get("limits")
                                .and_then(|l| l.get(k))
                                .and_then(Value::as_f64),
                            unit,
                        )
                    };
                    for k in ["low_alarm", "low_warning", "high_warning", "high_alarm"] {
                        ui.weak(lim(k));
                    }
                    ui.end_row();
                }
            });
    }
    ui.add_space(6.0);
    ui.label(RichText::new("Module").strong());
    let t = |k: &str| module.get(k).filter(|v| !v.is_null()).map(value_text);
    let yes_no = |k: &str| {
        module
            .get(k)
            .and_then(Value::as_bool)
            .map(|b| if b { "yes" } else { "no" }.to_owned())
    };
    Grid::new("iface-sfp")
        .num_columns(2)
        .min_col_width(110.0)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            let mut row = |label: &str, v: Option<String>| {
                ui.label(label);
                match v {
                    Some(v) => ui.label(v),
                    None => ui.weak("-"),
                };
                ui.end_row();
            };
            row("Type", t("kind"));
            row("Connector", t("connector"));
            let compliance = strings(module, "compliance");
            row(
                "Compliance",
                (!compliance.is_empty()).then(|| compliance.join(", ")),
            );
            row("Vendor", t("vendor_name"));
            row("Part Number", t("vendor_part_number"));
            row("Revision", t("vendor_revision"));
            row("Serial", t("vendor_serial"));
            row("Manufactured", t("manufacturing_date"));
            row(
                "Wavelength",
                module
                    .get("wavelength_nm")
                    .and_then(Value::as_f64)
                    .map(|w| format!("{w:.0} nm")),
            );
            row(
                "Nominal Rate",
                module
                    .get("nominal_rate_mbd")
                    .and_then(Value::as_u64)
                    .map(|r| format!("{r} MBd")),
            );
            let lengths: Vec<String> = module
                .get("link_length")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|l| {
                    Some(format!(
                        "{} {} m",
                        l.get("medium")?.as_str()?,
                        l.get("meters")?.as_u64()?
                    ))
                })
                .collect();
            row("Reach", (!lengths.is_empty()).then(|| lengths.join(", ")));
            row("Rx Loss", yes_no("rx_loss"));
            row("Tx Fault", yes_no("tx_fault"));
            row(
                "EEPROM Checksum",
                module
                    .get("checksum_ok")
                    .and_then(Value::as_bool)
                    .map(|b| if b { "good" } else { "bad" }.to_owned()),
            );
        });
    let notes = strings(module, "notes");
    if !notes.is_empty() {
        egui::CollapsingHeader::new(format!("Notes ({})", notes.len()))
            .id_salt("iface-sfp-notes")
            .show(ui, |ui| {
                for n in notes {
                    ui.weak(n);
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor() -> Value {
        json!({
            "available": true,
            "autoneg": true,
            "speed_mbps": 1000,
            "full_duplex": true,
            "supported_modes": ["10baseT/Half", "100baseT/Full", "1000baseT/Full", "Autoneg"],
            "advertising": ["100baseT/Full", "1000baseT/Full"],
            "rx_flow_control": false,
            "tx_flow_control": false,
            "flow_control_autoneg": false,
            "configured": {},
        })
    }

    #[test]
    fn only_changes_are_sent() {
        let mut e = EthEdit::default();
        e.seed_link(&monitor());
        assert_eq!(e.params("ether1"), None);
        let f = e.form.as_mut().unwrap();
        assert_eq!(f.forced, "1000baseT/Full");
        f.advertise.remove("1000baseT/Full");
        f.rx = "auto".into();
        assert_eq!(
            e.params("ether1"),
            Some(
                json!({"name": "ether1", "advertise": ["100baseT/Full"], "rx_flow_control": "auto"})
            )
        );
        e.applied();
        assert!(!e.dirty());
        let f = e.form.as_mut().unwrap();
        f.autoneg = false;
        f.forced = "100baseT/Full".into();
        assert_eq!(
            e.params("ether1"),
            Some(json!({"name": "ether1", "auto_negotiation": false, "speed": "100baseT/Full"}))
        );
        // A refresh does not overwrite what the operator typed.
        e.seed_link(&monitor());
        assert!(e.dirty());
    }

    #[test]
    fn offload_changes() {
        let mut e = EthEdit::default();
        e.seed_offloads(&json!({"offloads": [
            {"name": "GRO", "feature": "rx-gro", "active": true, "fixed": false},
            {"name": "LRO", "feature": "rx-lro", "active": false, "fixed": true},
        ]}));
        assert_eq!(e.params("e"), None);
        e.offloads.insert("rx-gro".into(), false);
        assert_eq!(
            e.params("e"),
            Some(json!({"name": "e", "offloads": {"rx-gro": false}}))
        );
    }
}

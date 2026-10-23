//! IP › Fast Path (G2.4): the flowtable (RouterOS FastTrack) and hardware
//! flow offload.
//!
//! - Settings (enabled, ports, hardware offload, counters), each with ⓘ,
//!   sent with `ip.firewall.fastpath.set`.
//! - What is installed: active or not, software or hardware, and why not
//!   hardware when it was asked for.
//! - One row per port: in the flowtable or not, how (`hardware` /
//!   `software` / `off`), the card (driver, eSwitch mode, hw-tc-offload)
//!   and, when hardware is possible but not on, what to run for it.
//! - How many connections ride the flowtable now.

use egui::{ComboBox, Id, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Row, TableState, col, weak};
use crate::{CoreRouterUi, Win, value_text};

const NAME: &str = "fastpath";
pub(crate) const WIN: &str = "fastpath";
const PORTS: &str = "fastpath-ports";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "Fast Path",
        size: [900.0, 600.0],
        escape: false,
    }],
    new: || Box::<FastPath>::default(),
};

const COLUMNS: [table::Column; 5] = [
    col("Port"),
    col("Offload"),
    col("Card"),
    col("eSwitch"),
    weak("Why"),
];

/// The settings form, filled from `ip.firewall.fastpath.get` until edited.
#[derive(Default, Clone, PartialEq)]
pub(crate) struct Form {
    pub(crate) enabled: bool,
    pub(crate) interfaces: String,
    pub(crate) hw_offload: String,
    pub(crate) counters: bool,
}

#[derive(Default)]
pub(crate) struct FastPath {
    pub(crate) status: Value,
    /// What the router has (the form starts from it).
    saved: Option<Form>,
    pub(crate) form: Option<Form>,
    pub(crate) note: Option<String>,
    ports_t: TableState,
    help: Option<HelpView>,
}

struct Applied;

fn text(v: &Value, k: &str) -> String {
    v.get(k).map(value_text).unwrap_or_default()
}

fn form_of(v: &Value) -> Form {
    Form {
        enabled: v.get("enabled").and_then(Value::as_bool) == Some(true),
        interfaces: v
            .get("interfaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(value_text)
            .collect::<Vec<_>>()
            .join(", "),
        hw_offload: text(v, "hw_offload"),
        counters: v.get("counters").and_then(Value::as_bool) != Some(false),
    }
}

fn offload_kind(o: &str) -> Kind {
    match o {
        "hardware" => Kind::Green,
        "software" => Kind::Blue,
        _ => Kind::Neutral,
    }
}

fn port_row(p: &Value) -> Row {
    let offload = text(p, "offload");
    let card = [text(p, "driver"), text(p, "firmware")]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut chips: Vec<(String, Kind)> = Vec::new();
    if p.get("representor").and_then(Value::as_bool) == Some(true) {
        chips.push(("representor".into(), Kind::Neutral));
    }
    match p.get("hw_tc_offload").and_then(Value::as_bool) {
        Some(true) => chips.push(("hw-tc-offload".into(), Kind::Green)),
        Some(false) => chips.push(("hw-tc-offload off".into(), Kind::Amber)),
        None => {}
    }
    let eswitch = text(p, "eswitch");
    let eswitch_kind = if eswitch == "switchdev" { Kind::Green } else { Kind::Amber };
    let chip_refs: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    Row {
        key: text(p, "name"),
        cells: vec![
            text(p, "name"),
            chip::cell("", &[(offload.as_str(), offload_kind(&offload))]),
            chip::cell(&card, &chip_refs),
            if eswitch.is_empty() {
                String::new()
            } else {
                chip::cell("", &[(eswitch.as_str(), eswitch_kind)])
            },
            text(p, "why"),
        ],
        dimmed: p.get("in_flowtable").and_then(Value::as_bool) != Some(true),
        section: false,
        tint: None,
    }
}

impl FastPath {
    fn info(&mut self, ui: &mut Ui, key: &str, title: &str) {
        if help::info_button(ui, Id::unique(("fastpath-help", key)), title).clicked() {
            self.help = Some(HelpView::new(key, title));
        }
    }

    fn settings(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(mut f) = self.form.clone().or_else(|| self.saved.clone()) else {
            ui.weak(tr(l, "Reading…"));
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut f.enabled, tr(l, "Enabled"));
            self.info(ui, "fastpath.enabled", tr(l, "Enabled"));
            ui.add_space(12.0);
            ui.label(tr(l, "HW Offload"));
            ComboBox::from_id_salt("fastpath-hw")
                .selected_text(f.hw_offload.clone())
                .show_ui(ui, |ui| {
                    for v in ["auto", "yes", "no"] {
                        ui.selectable_value(&mut f.hw_offload, v.to_owned(), v);
                    }
                });
            self.info(ui, "fastpath.hw_offload", tr(l, "HW Offload"));
            ui.add_space(12.0);
            ui.checkbox(&mut f.counters, tr(l, "Counters"));
            self.info(ui, "fastpath.counters", tr(l, "Counters"));
        });
        ui.horizontal(|ui| {
            ui.label(tr(l, "Interfaces"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized(
                [320.0, h],
                TextEdit::singleline(&mut f.interfaces).hint_text(tr(l, "every Ethernet and bond port")),
            );
            self.info(ui, "fastpath.interfaces", tr(l, "Interfaces"));
            let changed = Some(&f) != self.saved.as_ref();
            let can = app.can().check("ip.firewall.fastpath.set");
            if ui
                .add_enabled(changed && can.is_ok(), egui::Button::new(tr(l, "Apply")))
                .on_disabled_hover_text(can.err().unwrap_or_default())
                .clicked()
            {
                app.run_then(
                    "ip.firewall.fastpath.set",
                    json!({
                        "enabled": f.enabled,
                        "interfaces": f.interfaces.trim(),
                        "hw_offload": f.hw_offload,
                        "counters": f.counters,
                    }),
                    crate::panel::then(NAME, Applied),
                );
            }
        });
        self.form = (Some(&f) != self.saved.as_ref()).then_some(f);
        if let Some(n) = &self.note {
            ui.colored_label(ui.visuals().error_fg_color, n.clone());
        }
    }

    fn state(&mut self, ui: &mut Ui, l: Lang) {
        let st = &self.status;
        if st.is_null() {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            let active = st.get("active").and_then(Value::as_bool) == Some(true);
            let hardware = st.get("hardware").and_then(Value::as_bool) == Some(true);
            let v = ui.visuals().clone();
            if active {
                chip::chip(ui, tr(l, "installed"), chip::GREEN.tone(&v));
                if hardware {
                    chip::chip(ui, tr(l, "hardware asked"), chip::GREEN.tone(&v));
                } else {
                    chip::chip(ui, tr(l, "software"), chip::BLUE.tone(&v));
                }
            } else {
                chip::chip(ui, tr(l, "off"), chip::neutral_tone(&v));
            }
            let flows = st.get("flows").cloned().unwrap_or(Value::Null);
            ui.label(format!(
                "{} {} · {} {} · {} {}",
                text(&flows, "total"),
                tr(l, "connections"),
                text(&flows, "software"),
                tr(l, "in software"),
                text(&flows, "hardware"),
                tr(l, "in hardware"),
            ));
        });
        if let Some(n) = st.get("note").map(value_text) {
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, "note", chip::AMBER.tone(ui.visuals()));
                ui.label(n);
            });
        }
    }
}

impl PanelState for FastPath {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command("ip.firewall.fastpath.status") {
            return Vec::new();
        }
        vec![
            Query { key: "status", command: "ip.firewall.fastpath.status", params: json!({}) },
            Query { key: "get", command: "ip.firewall.fastpath.get", params: json!({}) },
        ]
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "status" => self.status = value,
            "get" => self.saved = Some(form_of(&value)),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Fast Path"));
            self.info(ui, "fastpath.window", tr(l, "Fast Path"));
        });
        self.settings(app, ui, l);
        ui.separator();
        self.state(ui, l);
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Ports"));
            self.info(ui, "fastpath.ports", tr(l, "Ports"));
        });
        let rows: Vec<Row> = self
            .status
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(port_row)
            .collect();
        // What to run for hardware offload, port by port, under the table
        // (a command is too long for a column).
        let fixes: Vec<(String, String)> = self
            .status
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.get("fix").is_some())
            .map(|p| (text(p, "name"), text(p, "fix")))
            .collect();
        let reserve = if fixes.is_empty() {
            0.0
        } else {
            (fixes.len() as f32 + 1.0) * (ui.spacing().interact_size.y + 4.0)
        };
        table::show(ui, PORTS, reserve, &mut self.ports_t, &COLUMNS, &rows, |_, _| {});
        if !fixes.is_empty() {
            ui.horizontal(|ui| {
                ui.strong(tr(l, "Fix"));
                self.info(ui, "fastpath.fix", tr(l, "Fix"));
            });
            for (port, fix) in fixes {
                ui.horizontal(|ui| {
                    ui.label(port);
                    if ui.small_button(tr(l, "Copy")).clicked() {
                        ui.ctx().copy_text(fix.clone());
                    }
                    ui.label(egui::RichText::new(fix).monospace().small());
                });
            }
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast::<Applied>().is_err() {
            return;
        }
        match result {
            Ok(v) => {
                self.saved = Some(form_of(v));
                self.form = None;
                self.note = None;
            }
            Err(e) => self.note = Some(e.clone()),
        }
        app.cache.refreshed_at = None;
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(PORTS, &self.ports_t)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(PORTS, &mut self.ports_t)]
    }
}

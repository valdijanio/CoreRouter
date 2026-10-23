//! Tools › IP Calculator (G6.9): Subnet (network, broadcast, hosts, mask,
//! wildcard; split, summarize, range to prefixes; overlaps with what is
//! configured), IPv6 PD (how many delegations a prefix holds, the
//! DHCPv6-PD pools) and the CGNAT planner (the CGNAT's own formula: what
//! fits, what to change, the mapping preview, create the pool, export).
//! Every number comes from `tool.ip-calc.*`; this only asks and shows.

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Row, TableState, col, num};
use crate::{CoreRouterUi, value_text};

const NAME: &str = "ip-calc";
pub(crate) const WIN: &str = "ip-calc";
const PREVIEW_TABLE: &str = "ip-calc-preview";
/// How long the planner inputs rest before the plan is asked.
const SETTLE_SECS: f64 = 0.4;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "IP Calculator",
        size: [860.0, 620.0],
        escape: false,
    }],
    new: || Box::<IpCalc>::default(),
};

const PREVIEW_COLUMNS: [table::Column; 4] = [num("#"), col("Subscriber"), col("Public"), col("Ports")];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Subnet,
    Pd,
    Cgnat,
}

#[derive(Default)]
pub(crate) struct IpCalc {
    pub(crate) tab: Tab,
    // Subnet
    pub(crate) address: String,
    pub(crate) subnet: Option<Result<Value, String>>,
    pub(crate) split_to: String,
    pub(crate) split: Option<Result<Value, String>>,
    pub(crate) summarize: String,
    pub(crate) summary: Option<Result<Value, String>>,
    pub(crate) range: (String, String),
    pub(crate) range_out: Option<Result<Value, String>>,
    // IPv6 PD
    pub(crate) pd_prefix: String,
    pub(crate) pd_length: u8,
    pub(crate) pd: Option<Result<Value, String>>,
    // CGNAT planner
    pub(crate) inside: String,
    pub(crate) outside: String,
    pub(crate) ports: String,
    pub(crate) port_range: String,
    pub(crate) mode: String,
    pub(crate) pool_name: String,
    pub(crate) plan: Option<Result<Value, String>>,
    /// The planner inputs the last plan was asked for.
    asked: Option<Value>,
    /// Inputs being typed, and since when: asked once they rest.
    typing: Option<(Value, f64)>,
    pub(crate) rules: Option<String>,
    /// Text to put on the clipboard at the next frame, and the note.
    copy: Option<String>,
    pub(crate) note: Option<String>,
    preview_t: TableState,
    pub(crate) help: Option<HelpView>,
}

enum Reply {
    Subnet,
    Split,
    Summary,
    Range,
    Pd,
    Plan,
    Export(&'static str),
    Created,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).map(value_text).unwrap_or_default()
}

fn info(ui: &mut Ui, help: &mut Option<HelpView>, key: &str, title: &str) {
    if help::info_button(ui, Id::unique(("ip-calc-help", key)), title).clicked() {
        *help = Some(HelpView::new(key, title));
    }
}

/// A result grid: (label, value) rows.
fn facts(ui: &mut Ui, id: &str, rows: &[(&'static str, String)], l: Lang) {
    Grid::new(id).num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
        for (label, value) in rows {
            ui.weak(tr(l, label));
            ui.label(egui::RichText::new(value).monospace());
            ui.end_row();
        }
    });
}

fn error(ui: &mut Ui, e: &str) {
    ui.colored_label(ui.visuals().error_fg_color, e);
}

impl IpCalc {
    fn planner_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("inside".into(), json!(self.inside.trim()));
        p.insert("outside".into(), json!(self.outside.trim()));
        if let Ok(n) = self.ports.trim().parse::<u64>() {
            p.insert("ports_per_subscriber".into(), json!(n));
        }
        if !self.port_range.trim().is_empty() {
            p.insert("port_range".into(), json!(self.port_range.trim()));
        }
        if !self.mode.is_empty() {
            p.insert("mode".into(), json!(self.mode));
        }
        p.insert("preview".into(), json!(50));
        Value::Object(p)
    }

    fn subnet_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let run = |app: &mut CoreRouterUi, id: &str, p: Value, r: Reply| {
            app.run_then(id, p, crate::panel::then(NAME, r));
        };
        ui.horizontal(|ui| {
            ui.label(tr(l, "Address"));
            let h = ui.spacing().interact_size.y;
            let r = ui.add_sized([260.0, h], TextEdit::singleline(&mut self.address).hint_text("192.168.10.77/24, 10.1.2.3 255.255.255.0, 2001:db8::1/64"));
            info(ui, &mut self.help, "ipcalc.address", tr(l, "Address"));
            if ui.button(tr(l, "Calculate")).clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                run(app, "tool.ip-calc.subnet", json!({"address": self.address.trim()}), Reply::Subnet);
            }
        });
        match &self.subnet {
            Some(Ok(v)) => {
                let mut rows = vec![("Network", text(v, "network"))];
                for (label, key) in [
                    ("Broadcast", "broadcast"),
                    ("First host", "first"),
                    ("Last host", "last"),
                    ("Hosts", "hosts"),
                    ("Mask", "mask"),
                    ("Wildcard", "wildcard"),
                    ("Scope", "scope"),
                ] {
                    if v.get(key).is_some() {
                        rows.push((label, text(v, key)));
                    }
                }
                facts(ui, "ip-calc-subnet", &rows, l);
                let overlaps = v.get("overlaps").and_then(Value::as_array).cloned().unwrap_or_default();
                if overlaps.is_empty() {
                    chip::chip(ui, tr(l, "no overlap with the configuration"), chip::GREEN.tone(ui.visuals()));
                } else {
                    for o in overlaps {
                        ui.horizontal(|ui| {
                            chip::chip(ui, &text(&o, "what"), chip::AMBER.tone(ui.visuals()));
                            ui.label(text(&o, "item"));
                        });
                    }
                }
            }
            Some(Err(e)) => error(ui, e),
            None => {}
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Split"));
            info(ui, &mut self.help, "ipcalc.split", tr(l, "Split"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized([90.0, h], TextEdit::singleline(&mut self.split_to).hint_text("/26 or 6"));
            if ui.button(tr(l, "Split")).clicked() {
                let t = self.split_to.trim();
                let p = match t.strip_prefix('/') {
                    Some(n) => json!({"network": self.address.trim(), "prefix": n.parse::<u64>().unwrap_or(0)}),
                    None => json!({"network": self.address.trim(), "count": t.parse::<u64>().unwrap_or(0)}),
                };
                run(app, "tool.ip-calc.split", p, Reply::Split);
            }
        });
        match &self.split {
            Some(Ok(v)) => {
                let list: Vec<String> = v.get("subnets").and_then(Value::as_array).into_iter().flatten().map(value_text).collect();
                ui.label(format!("{} × /{}", text(v, "total"), text(v, "prefix")));
                egui::ScrollArea::vertical().id_salt("ip-calc-split").max_height(110.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(list.join("  ")).monospace());
                });
            }
            Some(Err(e)) => error(ui, e),
            None => {}
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Summarize"));
            info(ui, &mut self.help, "ipcalc.summarize", tr(l, "Summarize"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized([360.0, h], TextEdit::singleline(&mut self.summarize).hint_text("10.0.0.0/24, 10.0.1.0/24, 10.0.3.0/24"));
            if ui.button(tr(l, "Summarize")).clicked() {
                run(app, "tool.ip-calc.summarize", json!({"prefixes": self.summarize.trim()}), Reply::Summary);
            }
        });
        match &self.summary {
            Some(Ok(v)) => facts(
                ui,
                "ip-calc-summary",
                &[
                    ("Aggregated", v.get("aggregated").and_then(Value::as_array).into_iter().flatten().map(value_text).collect::<Vec<_>>().join(", ")),
                    ("Supernet", text(v, "supernet")),
                    ("Addresses it adds", text(v, "extra")),
                ],
                l,
            ),
            Some(Err(e)) => error(ui, e),
            None => {}
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Range to prefixes"));
            info(ui, &mut self.help, "ipcalc.range", tr(l, "Range to prefixes"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized([140.0, h], TextEdit::singleline(&mut self.range.0).hint_text("10.0.0.1"));
            ui.label("–");
            ui.add_sized([140.0, h], TextEdit::singleline(&mut self.range.1).hint_text("10.0.0.200"));
            if ui.button(tr(l, "Convert")).clicked() {
                run(app, "tool.ip-calc.range", json!({"first": self.range.0.trim(), "last": self.range.1.trim()}), Reply::Range);
            }
        });
        match &self.range_out {
            Some(Ok(v)) => {
                let list: Vec<String> = v.get("prefixes").and_then(Value::as_array).into_iter().flatten().map(value_text).collect();
                ui.label(egui::RichText::new(format!("{}  ({} {})", list.join(", "), text(v, "addresses"), tr(l, "addresses"))).monospace());
            }
            Some(Err(e)) => error(ui, e),
            None => {}
        }
    }

    fn pd_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        if self.pd_length == 0 {
            self.pd_length = 56;
        }
        ui.horizontal(|ui| {
            ui.label(tr(l, "Prefix"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized([220.0, h], TextEdit::singleline(&mut self.pd_prefix).hint_text("2001:db8::/40"));
            info(ui, &mut self.help, "ipcalc.pd_prefix", tr(l, "Prefix"));
            ui.label(tr(l, "Delegate"));
            ComboBox::from_id_salt("ip-calc-pd-len")
                .selected_text(format!("/{}", self.pd_length))
                .show_ui(ui, |ui| {
                    for n in [48u8, 52, 56, 60, 62, 64] {
                        ui.selectable_value(&mut self.pd_length, n, format!("/{n}"));
                    }
                });
            info(ui, &mut self.help, "ipcalc.pd_length", tr(l, "Delegate"));
            if ui.button(tr(l, "Calculate")).clicked() {
                app.run_then(
                    "tool.ip-calc.pd",
                    json!({"prefix": self.pd_prefix.trim(), "length": self.pd_length, "show": 32}),
                    crate::panel::then(NAME, Reply::Pd),
                );
            }
        });
        match &self.pd {
            Some(Ok(v)) => {
                facts(
                    ui,
                    "ip-calc-pd",
                    &[
                        ("Delegations", text(v, "count")),
                        ("/64 networks in each", text(v, "customers_per")),
                        ("Last", text(v, "last")),
                    ],
                    l,
                );
                let list: Vec<String> = v.get("first").and_then(Value::as_array).into_iter().flatten().map(value_text).collect();
                egui::ScrollArea::vertical().id_salt("ip-calc-pd-list").max_height(160.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(list.join("\n")).monospace());
                });
                let pools = v.get("pools").and_then(Value::as_array).cloned().unwrap_or_default();
                ui.separator();
                ui.strong(tr(l, "DHCPv6-PD pools"));
                if pools.is_empty() {
                    ui.weak(tr(l, "No IPv6 pool yet (IPv6 › DHCP › Pool)."));
                }
                for p in pools {
                    ui.horizontal(|ui| {
                        let inside = p.get("inside").and_then(Value::as_bool) == Some(true);
                        let tone = if inside { chip::GREEN.tone(ui.visuals()) } else { chip::neutral_tone(ui.visuals()) };
                        chip::chip(ui, &text(&p, "name"), tone);
                        ui.label(format!("{} /{}", text(&p, "prefix"), text(&p, "prefix_length")));
                        if inside {
                            ui.weak(tr(l, "inside this prefix"));
                        }
                    });
                }
            }
            Some(Err(e)) => error(ui, e),
            None => {}
        }
    }

    fn cgnat_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        if self.port_range.is_empty() && self.ports.is_empty() && self.mode.is_empty() {
            self.ports = "1000".into();
            self.port_range = "1024-65535".into();
            self.mode = "deterministic".into();
            self.pool_name = "cgnat1".into();
        }
        Grid::new("ip-calc-cgnat").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
            for (label, field, hint, key) in [
                ("Subscribers", &mut self.inside, "100.64.0.0/22 or 4096", "ipcalc.inside"),
                ("Public addresses", &mut self.outside, "203.0.113.0/28 or 32", "ipcalc.outside"),
                ("Ports per Subscriber", &mut self.ports, "1000", "cgnat.ports_per_subscriber"),
                ("Port Range", &mut self.port_range, "1024-65535", "cgnat.port_range"),
            ] {
                ui.label(tr(l, label));
                let h = ui.spacing().interact_size.y;
                ui.add_sized([260.0, h], TextEdit::singleline(field).hint_text(hint));
                info(ui, &mut self.help, key, tr(l, label));
                ui.end_row();
            }
            ui.label(tr(l, "Mode"));
            ComboBox::from_id_salt("ip-calc-mode").selected_text(self.mode.clone()).show_ui(ui, |ui| {
                for m in ["deterministic", "blocks"] {
                    ui.selectable_value(&mut self.mode, m.to_owned(), m);
                }
            });
            info(ui, &mut self.help, "cgnat.mode", tr(l, "Mode"));
            ui.end_row();
        });
        ui.separator();
        // The plan follows the inputs, asked once they rest for a moment
        // (not one command per key typed).
        let params = self.planner_params();
        let now = ui.input(|i| i.time);
        if !self.inside.trim().is_empty() && !self.outside.trim().is_empty() && self.asked.as_ref() != Some(&params) {
            match &self.typing {
                Some((p, since)) if *p == params => {
                    if now - since >= SETTLE_SECS {
                        self.typing = None;
                        self.asked = Some(params.clone());
                        app.run_then("tool.ip-calc.cgnat.plan", params, crate::panel::then(NAME, Reply::Plan));
                    } else {
                        ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(SETTLE_SECS));
                    }
                }
                _ => {
                    self.typing = Some((params, now));
                    ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(SETTLE_SECS));
                }
            }
        }
        let plan = match &self.plan {
            Some(Ok(v)) => v.clone(),
            Some(Err(e)) => {
                error(ui, e);
                return;
            }
            None => {
                ui.weak(tr(l, "Type the subscribers and the public addresses."));
                return;
            }
        };
        let fits = plan.get("fits").and_then(Value::as_bool) == Some(true);
        ui.horizontal(|ui| {
            let (t, tone) = if fits { (tr(l, "fits"), chip::GREEN) } else { (tr(l, "does not fit"), chip::RED) };
            chip::chip(ui, t, tone.tone(ui.visuals()));
            ui.label(format!(
                "{} {} · {} {} · {} {}",
                text(&plan, "subscribers"),
                tr(l, "subscribers"),
                text(&plan, "per_address"),
                tr(l, "per public address"),
                text(&plan, "capacity"),
                tr(l, "capacity"),
            ));
        });
        facts(
            ui,
            "ip-calc-plan",
            &[
                ("Public addresses needed", text(&plan, "public_needed")),
                ("Public addresses spare", text(&plan, "public_spare")),
                ("Ports left on each address", text(&plan, "ports_left_per_address")),
                ("Ports if spread evenly", text(&plan, "ports_if_spread")),
            ],
            l,
        );
        for w in plan.get("warnings").and_then(Value::as_array).into_iter().flatten() {
            ui.horizontal_wrapped(|ui| {
                let (t, tone) = match text(w, "level").as_str() {
                    "error" => ("error", chip::RED),
                    "warn" | "warning" => ("warning", chip::AMBER),
                    _ => ("tip", chip::BLUE),
                };
                chip::chip(ui, t, tone.tone(ui.visuals()));
                ui.label(text(w, "text"));
                if let Some(s) = w.get("suggestion") {
                    ui.weak(format!("— {}", value_text(s)));
                }
            });
        }
        ui.separator();
        ui.horizontal(|ui| {
            let can = app.can();
            ui.label(tr(l, "Pool name"));
            let h = ui.spacing().interact_size.y;
            ui.add_sized([110.0, h], TextEdit::singleline(&mut self.pool_name));
            let create = can.check("ip.firewall.cgnat.pool.add").and_then(|()| if fits { Ok(()) } else { Err("the plan does not fit".to_owned()) });
            if ui
                .add_enabled(create.is_ok(), egui::Button::new(tr(l, "Create CGNAT pool")))
                .on_disabled_hover_text(create.err().unwrap_or_default())
                .clicked()
                && let Some(mut p) = plan.get("pool").cloned()
            {
                if let Some(o) = p.as_object_mut() {
                    o.insert("name".into(), json!(self.pool_name.trim()));
                }
                app.run_then("ip.firewall.cgnat.pool.add", p, crate::panel::then(NAME, Reply::Created));
            }
            for (label, format) in [("Copy CSV", "csv"), ("Copy printable", "text"), ("Copy as RouterOS script", "routeros")] {
                if ui.add_enabled(fits, egui::Button::new(tr(l, label))).clicked() {
                    let mut p = self.planner_params();
                    if let Some(o) = p.as_object_mut() {
                        o.remove("preview");
                    o.remove("mode");
                        o.insert("format".into(), json!(format));
                        o.insert("name".into(), json!(self.pool_name.trim()));
                    }
                    app.run_then("tool.ip-calc.cgnat.export", p, crate::panel::then(NAME, Reply::Export(format)));
                }
            }
            if ui.add_enabled(fits, egui::Button::new(tr(l, "View rules"))).clicked() {
                let mut p = self.planner_params();
                if let Some(o) = p.as_object_mut() {
                    o.remove("preview");
                    o.remove("mode");
                    o.insert("format".into(), json!("nft"));
                }
                app.run_then("tool.ip-calc.cgnat.export", p, crate::panel::then(NAME, Reply::Export("nft")));
            }
        });
        if let Some(n) = &self.note {
            ui.weak(n.clone());
        }
        if let Some(r) = &self.rules {
            egui::CollapsingHeader::new(tr(l, "Generated rules (nftables)")).default_open(true).show(ui, |ui| {
                egui::ScrollArea::vertical().id_salt("ip-calc-rules").max_height(140.0).show(ui, |ui| {
                    ui.label(egui::RichText::new(r).monospace().small());
                });
            });
        }
        let rows: Vec<Row> = plan
            .get("preview")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(i, r)| Row {
                key: i.to_string(),
                cells: vec![i.to_string(), text(r, "subscriber"), text(r, "public"), format!("{}–{}", text(r, "first_port"), text(r, "last_port"))],
                dimmed: false,
                section: false,
                tint: None,
            })
            .collect();
        if !rows.is_empty() {
            ui.strong(tr(l, "Mapping preview"));
            table::show(ui, PREVIEW_TABLE, 0.0, &mut self.preview_t, &PREVIEW_COLUMNS, &rows, |_, _| {});
        }
    }
}

impl PanelState for IpCalc {
    fn queries(&self, _app: &CoreRouterUi) -> Vec<Query> {
        Vec::new()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, _key: &'static str, _: RequestId, _value: Value) {}

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        if let Some(t) = self.copy.take() {
            ui.ctx().copy_text(t);
        }
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label) in [(Tab::Subnet, "Subnet"), (Tab::Pd, "IPv6 PD"), (Tab::Cgnat, "CGNAT planner")] {
                if ui.selectable_label(self.tab == tab, tr(l, label)).clicked() {
                    self.tab = tab;
                }
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().id_salt("ip-calc-body").show(ui, |ui| match self.tab {
            Tab::Subnet => self.subnet_tab(app, ui, l),
            Tab::Pd => self.pd_tab(app, ui, l),
            Tab::Cgnat => self.cgnat_tab(app, ui, l),
        });
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else { return };
        let r2 = result.clone();
        match *r {
            Reply::Subnet => self.subnet = Some(r2),
            Reply::Split => self.split = Some(r2),
            Reply::Summary => self.summary = Some(r2),
            Reply::Range => self.range_out = Some(r2),
            Reply::Pd => self.pd = Some(r2),
            Reply::Plan => self.plan = Some(r2),
            Reply::Export(format) => match result {
                Ok(v) if format == "nft" => self.rules = Some(text(v, "text")),
                Ok(v) => {
                    self.copy = Some(text(v, "text"));
                    self.note = Some(format!("{} {} ({format})", text(v, "rows"), "rows copied to the clipboard"));
                }
                Err(e) => self.note = Some(e.clone()),
            },
            Reply::Created => {
                self.note = Some(match result {
                    Ok(v) => format!("pool {} created", text(v, "name")),
                    Err(e) => e.clone(),
                });
            }
        }
        app.cache.refreshed_at = None;
    }
}

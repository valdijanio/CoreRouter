//! CGNAT (G2.3d): the pools, the 1:1 exceptions, "who was", the mapping
//! table, the port blocks and the port alerts, as tabs of one window (parts
//! of a window are tabs, `docs/ui-style.md`). Everything comes from
//! `ip.firewall.cgnat.*`: the engine computes the formula, the capacity
//! and the checks; this only shows and sends. Every field has an ⓘ.

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "cgnat";
pub(crate) const WIN: &str = "cgnat";
const POOLS: &str = "cgnat-pools";
const EXCEPTIONS: &str = "cgnat-exceptions";
const MAPPING: &str = "cgnat-mapping";
const BLOCKS: &str = "cgnat-blocks";
const ALERTS: &str = "cgnat-alerts";
const HISTORY: &str = "cgnat-history";
/// Rows of one mapping page.
pub(crate) const PAGE: u64 = 500;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "CGNAT",
        title: "CGNAT",
        size: [1080.0, 560.0],
        escape: true,
    }],
    new: || Box::<Cgnat>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Pools,
    Exceptions,
    WhoWas,
    Mapping,
    Blocks,
    Alerts,
    History,
}

const POOL_COLUMNS: [table::Column; 9] = [
    col("Name"),
    col("Mode"),
    col("Inside"),
    col("Outside"),
    num("Ports"),
    num("Subscribers"),
    num("Per IP"),
    col("Capacity"),
    comment(),
];
const EXCEPTION_COLUMNS: [table::Column; 4] = [col("Subscriber"), col("Public"), col("Pool"), comment()];
const MAPPING_COLUMNS: [table::Column; 4] = [num("#"), col("Subscriber"), col("Public"), col("Ports")];
const BLOCK_COLUMNS: [table::Column; 5] = [col("Subscriber"), col("Pool"), col("Public"), col("Ports"), col("Since")];
const LOG_COLUMNS: [table::Column; 5] = [col("Subscriber"), col("Pool"), col("Public"), col("Ports"), col("Period")];
const ALERT_COLUMNS: [table::Column; 6] = [
    col("Subscriber"),
    col("Pool"),
    col("Used"),
    num("Peak"),
    num("Times"),
    col("Last"),
];
const HISTORY_COLUMNS: [table::Column; 4] = [col("Since"), col("Until"), col("Pools"), num("Exceptions")];

/// The fields of a pool, in dialog order: (key, label, hint).
pub(crate) const POOL_FIELDS: &[(&str, &str, &str)] = &[
    ("name", "Name", "cgnat1"),
    ("inside", "Inside", "100.64.0.0/22"),
    ("outside", "Outside", "203.0.113.0/28"),
    ("ports_per_subscriber", "Ports per Subscriber", "1000"),
    ("port_range", "Port Range", "1024-65535"),
    ("max_blocks", "Max Blocks", "4"),
    ("block_timeout", "Block Timeout", "2m"),
    ("out_interface", "Out. Interface", "ether1"),
    ("alert_percent", "Alert %", "90"),
    ("comment", "Comment", ""),
];
/// The pool's switches: (key, label).
pub(crate) const POOL_FLAGS: &[(&str, &str)] = &[
    ("endpoint_independent_mapping", "Endpoint-Independent Mapping"),
    ("endpoint_independent_filtering", "Endpoint-Independent Filtering"),
    ("hairpin", "Hairpin"),
    ("disabled", "Disabled"),
];

#[derive(Default)]
pub(crate) struct Cgnat {
    pub(crate) tab: Tab,
    pub(crate) pools: Vec<Value>,
    pub(crate) exceptions: Vec<Value>,
    pub(crate) settings: Value,
    pub(crate) mapping: Value,
    pub(crate) mapping_pool: String,
    pub(crate) mapping_find: String,
    pub(crate) mapping_offset: u64,
    pub(crate) blocks: Value,
    pub(crate) block_history: Vec<Value>,
    pub(crate) alerts: Value,
    pub(crate) history: Vec<Value>,
    pub(crate) who: WhoWas,
    pools_t: TableState,
    exceptions_t: TableState,
    mapping_t: TableState,
    blocks_t: TableState,
    alerts_t: TableState,
    history_t: TableState,
    pub(crate) pool_dialog: Option<PoolDialog>,
    pub(crate) exception_dialog: Option<ExceptionDialog>,
    pub(crate) help: Option<HelpView>,
}

/// The "who was" form and its answer.
#[derive(Default)]
pub(crate) struct WhoWas {
    pub public: String,
    pub port: String,
    pub time: String,
    pub subscriber: String,
    pub answer: Option<Result<Value, String>>,
    pub lookup: Option<Result<Value, String>>,
}

pub(crate) struct PoolDialog {
    id: u64,
    item: Option<String>,
    mode: String,
    values: Vec<String>,
    flags: Vec<bool>,
    orig: (String, Vec<String>, Vec<bool>),
    status: Status,
}

impl PoolDialog {
    /// Fill field `key` (tests drive the dialog).
    #[cfg(test)]
    pub(crate) fn set(&mut self, key: &str, value: &str) {
        if let Some(i) = POOL_FIELDS.iter().position(|(k, _, _)| *k == key)
            && let Some(v) = self.values.get_mut(i)
        {
            *v = value.to_owned();
        }
    }
}

pub(crate) struct ExceptionDialog {
    id: u64,
    item: Option<String>,
    subscriber: String,
    public: String,
    comment: String,
    orig: (String, String, String),
    status: Status,
}

enum Reply {
    Pool(u64),
    Exception(u64),
    WhoWas,
    Lookup,
    Other,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).map(value_text).unwrap_or_default()
}

fn list_text(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::Array(a)) => a.iter().map(value_text).collect::<Vec<_>>().join(", "),
        Some(other) => value_text(other),
        None => String::new(),
    }
}

/// The capacity chip and the warnings of a pool row.
fn checks_cell(r: &Value) -> String {
    let mut chips: Vec<(String, Kind)> = Vec::new();
    for c in r.get("checks").and_then(Value::as_array).into_iter().flatten() {
        let kind = match text(c, "level").as_str() {
            "error" => Kind::Red,
            "warn" => Kind::Amber,
            _ => continue,
        };
        chips.push((text(c, "label"), kind));
    }
    let used = r.get("public_used").and_then(Value::as_u64).unwrap_or(0);
    let all = r.get("public_addresses").and_then(Value::as_u64).unwrap_or(0);
    let refs: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    chip::cell(&format!("{used}/{all} IPs"), &refs)
}

pub(crate) fn pool_row(r: &Value) -> Row {
    let mode = text(r, "mode");
    let kind = if mode == "blocks" { Kind::Blue } else { Kind::Green };
    Row {
        key: text(r, "name"),
        cells: vec![
            text(r, "name"),
            chip::cell("", &[(mode.as_str(), kind)]),
            list_text(r, "inside"),
            list_text(r, "outside"),
            text(r, "ports_per_subscriber"),
            text(r, "subscribers"),
            text(r, "per_address"),
            checks_cell(r),
            text(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

fn exception_row(r: &Value) -> Row {
    Row {
        key: text(r, "id"),
        cells: vec![text(r, "subscriber"), text(r, "public"), text(r, "pool"), text(r, "comment")],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

fn ports(r: &Value) -> String {
    format!("{}–{}", text(r, "first_port"), text(r, "last_port"))
}

impl Cgnat {
    fn ask_who(&mut self, app: &mut CoreRouterUi) {
        let mut p = Map::new();
        p.insert("public".into(), json!(self.who.public.trim()));
        p.insert(
            "port".into(),
            self.who.port.trim().parse::<u64>().map_or_else(|_| json!(self.who.port.trim()), |n| json!(n)),
        );
        if !self.who.time.trim().is_empty() {
            p.insert("time".into(), json!(self.who.time.trim()));
        }
        self.who.answer = None;
        app.run_then("ip.firewall.cgnat.who-was", Value::Object(p), crate::panel::then(NAME, Reply::WhoWas));
    }

    fn pools_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.pools.iter().map(pool_row).collect();
        let selection = self.pools_t.selection(&rows);
        let can = app.can();
        let (mut new, mut remove) = (false, false);
        ui.horizontal(|ui| {
            new = table::tool(ui, POOLS, Icon::Add, tr(l, "Add"), can.check("ip.firewall.cgnat.pool.add")).clicked();
            let picked = if selection.is_empty() { Err(tr(l, "Select a pool first").to_owned()) } else { Ok(()) };
            remove = table::tool(ui, POOLS, Icon::Remove, tr(l, "Remove"), can.and("ip.firewall.cgnat.pool.remove", picked)).clicked();
            ui.separator();
            let days = text(&self.settings, "history_days");
            let since = self.settings.get("history").map(|h| text(h, "since")).unwrap_or_default();
            ui.weak(format!("{}: {days} {}", tr(l, "History kept"), tr(l, "days")));
            if !since.is_empty() {
                ui.weak(format!("({} {since})", tr(l, "since")));
            }
            if help::info_button(ui, Id::unique("cgnat-help-history"), tr(l, "History kept")).clicked() {
                self.help = Some(HelpView::new("cgnat.history_days", tr(l, "History kept")));
            }
            table::find_field(ui, POOLS, &mut self.pools_t);
        });
        ui.separator();
        let out = table::show(ui, POOLS, 0.0, &mut self.pools_t, &POOL_COLUMNS, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, tr(l, "Add Pool…"), can.check("ip.firewall.cgnat.pool.add"))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for name in &selection {
                app.run_then("ip.firewall.cgnat.pool.remove", json!({"id": name}), crate::panel::then(NAME, Reply::Other));
            }
        }
        let key = out.opened.or(out.comment).or_else(|| {
            matches!(out.shortcut, Some(Shortcut::Open)).then(|| selection.first().cloned()).flatten()
        });
        let opened = key.and_then(|k| self.pools.iter().find(|p| text(p, "name") == k).cloned());
        if (new || opened.is_some()) && self.pool_dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let get = |k: &str| match &opened {
                Some(p) => match k {
                    "inside" | "outside" => list_text(p, k),
                    "block_timeout" => text(p, k),
                    _ => text(p, k),
                },
                None => String::new(),
            };
            let values: Vec<String> = POOL_FIELDS.iter().map(|(k, _, _)| get(k)).collect();
            let flags: Vec<bool> = POOL_FLAGS
                .iter()
                .map(|(k, _)| match &opened {
                    Some(p) => p.get(*k).and_then(Value::as_bool).unwrap_or(false),
                    None => matches!(*k, "endpoint_independent_mapping" | "hairpin"),
                })
                .collect();
            let mode = opened.as_ref().map_or_else(|| "deterministic".to_owned(), |p| text(p, "mode"));
            self.pool_dialog = Some(PoolDialog {
                id: app.next_dialog,
                item: opened.as_ref().map(|p| text(p, "name")),
                orig: (mode.clone(), values.clone(), flags.clone()),
                mode,
                values,
                flags,
                status: Status::default(),
            });
        }
    }

    fn exceptions_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.exceptions.iter().map(exception_row).collect();
        let selection = self.exceptions_t.selection(&rows);
        let can = app.can();
        let (mut new, mut remove) = (false, false);
        ui.horizontal(|ui| {
            new = table::tool(ui, EXCEPTIONS, Icon::Add, tr(l, "Add"), can.check("ip.firewall.cgnat.exception.add")).clicked();
            let picked = if selection.is_empty() { Err(tr(l, "Select an exception first").to_owned()) } else { Ok(()) };
            remove = table::tool(ui, EXCEPTIONS, Icon::Remove, tr(l, "Remove"), can.and("ip.firewall.cgnat.exception.remove", picked)).clicked();
            ui.weak(tr(l, "A subscriber with a public address of its own (1:1), outside every pool."));
            if help::info_button(ui, Id::unique("cgnat-help-exception"), tr(l, "Exceptions")).clicked() {
                self.help = Some(HelpView::new("cgnat.exception", tr(l, "Exceptions")));
            }
        });
        ui.separator();
        let out = table::show(ui, EXCEPTIONS, 0.0, &mut self.exceptions_t, &EXCEPTION_COLUMNS, &rows, |_, _| {});
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for id in &selection {
                app.run_then("ip.firewall.cgnat.exception.remove", json!({"id": id}), crate::panel::then(NAME, Reply::Other));
            }
        }
        let opened = out.opened.and_then(|k| self.exceptions.iter().find(|e| text(e, "id") == k).cloned());
        if (new || opened.is_some()) && self.exception_dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let get = |k: &str| opened.as_ref().map(|e| text(e, k)).unwrap_or_default();
            let vals = (get("subscriber"), get("public"), get("comment"));
            self.exception_dialog = Some(ExceptionDialog {
                id: app.next_dialog,
                item: opened.as_ref().map(|e| text(e, "id")),
                subscriber: vals.0.clone(),
                public: vals.1.clone(),
                comment: vals.2.clone(),
                orig: vals,
                status: Status::default(),
            });
        }
    }

    fn who_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.label(tr(l, "Who used a public address and port at a given time (Marco Civil, Lei 12.965/2014 art. 13)."));
        ui.add_space(4.0);
        let mut ask = false;
        Grid::new("cgnat-who").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
            for (label, field, hint, key) in [
                ("Public Address", &mut self.who.public, "203.0.113.7", "cgnat.who.public"),
                ("Port", &mut self.who.port, "40312", "cgnat.who.port"),
                ("Date and Time", &mut self.who.time, "2026-05-03T14:02:00-03:00", "cgnat.who.time"),
            ] {
                ui.label(tr(l, label));
                let h = ui.spacing().interact_size.y;
                let r = ui.add_sized([260.0, h], TextEdit::singleline(field).hint_text(hint));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    ask = true;
                }
                if help::info_button(ui, Id::unique(("cgnat-help", key)), tr(l, label)).clicked() {
                    self.help = Some(HelpView::new(key, tr(l, label)));
                }
                ui.end_row();
            }
        });
        let can = app.can();
        let enabled = can.check("ip.firewall.cgnat.who-was");
        if ui
            .add_enabled(enabled.is_ok() && !self.who.public.trim().is_empty(), egui::Button::new(tr(l, "Find")))
            .clicked()
        {
            ask = true;
        }
        if ask {
            self.ask_who(app);
        }
        ui.separator();
        match &self.who.answer {
            None => {}
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            Some(Ok(v)) => {
                ui.horizontal(|ui| {
                    ui.heading(text(v, "subscriber"));
                    let via = text(v, "via");
                    chip::chip(ui, &via, chip::palette_tone(ui.visuals(), chip::name_hue(&via)));
                    chip::chip(ui, &text(v, "mode"), chip::neutral_tone(ui.visuals()));
                });
                Grid::new("cgnat-who-answer").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
                    ui.weak(tr(l, "Public"));
                    ui.label(format!("{}  {}–{}", text(v, "public"), text(v, "first_port"), text(v, "last_port")));
                    ui.end_row();
                    ui.weak(tr(l, "Asked for (UTC)"));
                    ui.label(text(v, "time"));
                    ui.end_row();
                    ui.weak(tr(l, "Mapping valid"));
                    let until = v.get("until").map(value_text).unwrap_or_else(|| tr(l, "now").to_owned());
                    ui.label(format!("{} – {until}", text(v, "since")));
                    ui.end_row();
                    for d in v.get("dhcp").and_then(Value::as_array).into_iter().flatten() {
                        ui.weak("DHCP");
                        let mut parts = vec![text(d, "mac")];
                        for k in ["host_name", "circuit_id", "remote_id"] {
                            let t = text(d, k);
                            if !t.is_empty() {
                                parts.push(format!("{k}={t}"));
                            }
                        }
                        parts.push(format!("{} – {}", text(d, "from"), text(d, "until")));
                        ui.label(parts.join("  "));
                        ui.end_row();
                    }
                });
            }
        }
        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(tr(l, "Subscriber"));
            ui.add(TextEdit::singleline(&mut self.who.subscriber).hint_text("100.64.0.9").desired_width(140.0));
            if ui
                .add_enabled(can.check("ip.firewall.cgnat.lookup").is_ok(), egui::Button::new(tr(l, "Lookup")))
                .clicked()
            {
                self.who.lookup = None;
                app.run_then(
                    "ip.firewall.cgnat.lookup",
                    json!({"subscriber": self.who.subscriber.trim()}),
                    crate::panel::then(NAME, Reply::Lookup),
                );
            }
            match &self.who.lookup {
                Some(Ok(v)) => {
                    ui.label(format!("= {}  {}–{}", text(v, "public"), text(v, "first_port"), text(v, "last_port")));
                    chip::chip(ui, &text(v, "via"), chip::neutral_tone(ui.visuals()));
                }
                Some(Err(e)) => {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                }
                None => {}
            }
        });
    }

    fn mapping_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let names: Vec<String> = self.pools.iter().map(|p| text(p, "name")).collect();
        if self.mapping_pool.is_empty() || !names.contains(&self.mapping_pool) {
            self.mapping_pool = names.first().cloned().unwrap_or_default();
        }
        let before = (self.mapping_pool.clone(), self.mapping_find.clone());
        let total = self.mapping.get("total").and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            ui.label(tr(l, "Pool"));
            ComboBox::from_id_salt("cgnat-mapping-pool")
                .selected_text(self.mapping_pool.clone())
                .show_ui(ui, |ui| {
                    for n in &names {
                        ui.selectable_value(&mut self.mapping_pool, n.clone(), n);
                    }
                });
            ui.label(tr(l, "Subscriber or public"));
            ui.add(TextEdit::singleline(&mut self.mapping_find).hint_text("100.64.0.9 / 203.0.113.1").desired_width(160.0));
            ui.separator();
            let first = if total == 0 { 0 } else { self.mapping_offset + 1 };
            let last = (self.mapping_offset + PAGE).min(total);
            if ui.add_enabled(self.mapping_offset > 0, egui::Button::new("‹")).clicked() {
                self.mapping_offset = self.mapping_offset.saturating_sub(PAGE);
                app.cache.refreshed_at = None;
            }
            ui.label(format!("{first}–{last} {} {total}", tr(l, "of")));
            if ui.add_enabled(last < total, egui::Button::new("›")).clicked() {
                self.mapping_offset += PAGE;
                app.cache.refreshed_at = None;
            }
            if help::info_button(ui, Id::unique("cgnat-help-mapping"), tr(l, "Mapping")).clicked() {
                self.help = Some(HelpView::new("cgnat.mapping", tr(l, "Mapping")));
            }
        });
        if (self.mapping_pool.clone(), self.mapping_find.clone()) != before {
            self.mapping_offset = 0;
            app.cache.refreshed_at = None;
        }
        ui.separator();
        let rows: Vec<Row> = self
            .mapping
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| {
                        let sub = text(r, "subscriber");
                        let sub = match r.get("exception") {
                            Some(e) => chip::cell(&sub, &[(format!("1:1 {}", value_text(e)).as_str(), Kind::Amber)]),
                            None => sub,
                        };
                        Row {
                            key: text(r, "index"),
                            cells: vec![text(r, "index"), sub, text(r, "public"), ports(r)],
                            dimmed: r.get("exception").is_some(),
                            section: false,
                            tint: None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        table::show(ui, MAPPING, 0.0, &mut self.mapping_t, &MAPPING_COLUMNS, &rows, |_, _| {});
    }

    fn blocks_tab(&mut self, ui: &mut Ui, l: Lang) {
        let total = self.blocks.get("total").and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            ui.label(format!("{total} {}", tr(l, "blocks in use")));
            if help::info_button(ui, Id::unique("cgnat-help-blocks"), tr(l, "Blocks")).clicked() {
                self.help = Some(HelpView::new("cgnat.blocks", tr(l, "Blocks")));
            }
        });
        let rows: Vec<Row> = self
            .blocks
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| {
                        let mut chips: Vec<(&str, Kind)> = Vec::new();
                        if r.get("current").and_then(Value::as_bool) == Some(true) {
                            chips.push(("current", Kind::Green));
                        }
                        let idle = r.get("idle").map(|v| format!("idle {}s", value_text(v)));
                        if let Some(t) = &idle {
                            chips.push((t.as_str(), Kind::Neutral));
                        }
                        Row {
                            key: format!("{} {}", text(r, "subscriber"), text(r, "first_port")),
                            cells: vec![
                                text(r, "subscriber"),
                                text(r, "pool"),
                                text(r, "public"),
                                chip::cell(&ports(r), &chips),
                                text(r, "since"),
                            ],
                            dimmed: false,
                            section: false,
                            tint: None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let h = (ui.available_height() * 0.55).max(120.0);
        ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), h), egui::Layout::top_down(egui::Align::Min), |ui| {
            table::show(ui, BLOCKS, 0.0, &mut self.blocks_t, &BLOCK_COLUMNS, &rows, |_, _| {});
        });
        ui.separator();
        ui.strong(tr(l, "Block log"));
        let rows: Vec<Row> = self
            .block_history
            .iter()
            .enumerate()
            .map(|(i, r)| Row {
                key: i.to_string(),
                cells: vec![
                    text(r, "subscriber"),
                    text(r, "pool"),
                    text(r, "public"),
                    ports(r),
                    format!("{} – {}", text(r, "from"), r.get("until").map(value_text).unwrap_or_else(|| "…".into())),
                ],
                dimmed: r.get("until").is_some(),
                section: false,
                tint: None,
            })
            .collect();
        table::show(ui, HISTORY, 0.0, &mut self.history_t, &LOG_COLUMNS, &rows, |_, _| {});
    }

    fn alerts_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let failed = self.alerts.get("insert_failed").and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            if failed > 0 {
                chip::chip(ui, &format!("insert failed {failed}"), chip::RED.tone(ui.visuals()))
                    .on_hover_text(tr(l, "New connections the kernel could not translate: no free port"));
            }
            if ui
                .add_enabled(app.can().check("ip.firewall.cgnat.alert.clear").is_ok(), egui::Button::new(tr(l, "Clear")))
                .clicked()
            {
                app.run_then("ip.firewall.cgnat.alert.clear", json!({}), crate::panel::then(NAME, Reply::Other));
            }
            if help::info_button(ui, Id::unique("cgnat-help-alerts"), tr(l, "Alerts")).clicked() {
                self.help = Some(HelpView::new("cgnat.alerts", tr(l, "Alerts")));
            }
        });
        let rows: Vec<Row> = self
            .alerts
            .get("rows")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| {
                        let pct = r.get("percent").and_then(Value::as_u64).unwrap_or(0);
                        let above = r.get("above").and_then(Value::as_bool) == Some(true);
                        let kind = if above { Kind::Red } else { Kind::Neutral };
                        Row {
                            key: text(r, "subscriber"),
                            cells: vec![
                                text(r, "subscriber"),
                                text(r, "pool"),
                                chip::cell(&format!("{}/{}", text(r, "used"), text(r, "ports")), &[(format!("{pct} %").as_str(), kind)]),
                                text(r, "peak"),
                                text(r, "crossings"),
                                text(r, "last"),
                            ],
                            dimmed: !above,
                            section: false,
                            tint: None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        table::show(ui, ALERTS, 0.0, &mut self.alerts_t, &ALERT_COLUMNS, &rows, |_, _| {});
    }

    fn history_tab(&mut self, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            ui.weak(tr(l, "Every change of the pools, with its time (RFC 7422 §3): who was reads the one in force."));
        });
        let rows: Vec<Row> = self
            .history
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let pools: Vec<String> = r
                    .get("pools")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|p| format!("{} {} – {} ({} ports)", text(p, "name"), list_text(p, "inside"), list_text(p, "outside"), text(p, "ports_per_subscriber")))
                    .collect();
                Row {
                    key: i.to_string(),
                    cells: vec![
                        text(r, "since"),
                        r.get("until").map(value_text).unwrap_or_else(|| tr(l, "in force").to_owned()),
                        pools.join("; "),
                        text(r, "exceptions"),
                    ],
                    dimmed: r.get("until").is_some(),
                    section: false,
                    tint: None,
                }
            })
            .collect();
        table::show(ui, HISTORY, 0.0, &mut self.history_t, &HISTORY_COLUMNS, &rows, |_, _| {});
    }
}

impl PanelState for Cgnat {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command("ip.firewall.cgnat.pool.list") {
            return Vec::new();
        }
        let q = |key, command, params| Query { key, command, params };
        let mut out = vec![
            q("pools", "ip.firewall.cgnat.pool.list", json!({})),
            q("settings", "ip.firewall.cgnat.get", json!({})),
        ];
        match self.tab {
            Tab::Exceptions => out.push(q("exceptions", "ip.firewall.cgnat.exception.list", json!({}))),
            Tab::Mapping if !self.mapping_pool.is_empty() => {
                let mut p = json!({"pool": self.mapping_pool, "offset": self.mapping_offset, "count": PAGE});
                let find = self.mapping_find.trim();
                if !find.is_empty()
                    && let Some(o) = p.as_object_mut()
                {
                    // An address of the pool's inside is a subscriber; else a
                    // public address.
                    let inside = self
                        .pools
                        .iter()
                        .find(|x| text(x, "name") == self.mapping_pool)
                        .is_some_and(|x| list_text(x, "inside").split(", ").any(|r| in_range(r, find)));
                    o.insert(if inside { "subscriber" } else { "public" }.into(), json!(find));
                }
                out.push(q("mapping", "ip.firewall.cgnat.mapping.list", p));
            }
            Tab::Blocks => {
                out.push(q("blocks", "ip.firewall.cgnat.block.list", json!({"count": 2000})));
                out.push(q("block_history", "ip.firewall.cgnat.block.history", json!({"count": 500})));
            }
            Tab::Alerts => out.push(q("alerts", "ip.firewall.cgnat.alert.list", json!({}))),
            Tab::History => out.push(q("history", "ip.firewall.cgnat.history.list", json!({}))),
            _ => {}
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match (key, value) {
            ("pools", Value::Array(a)) => self.pools = a,
            ("exceptions", Value::Array(a)) => self.exceptions = a,
            ("settings", v) => self.settings = v,
            ("mapping", v) => self.mapping = v,
            ("blocks", v) => self.blocks = v,
            ("block_history", Value::Array(a)) => self.block_history = a,
            ("alerts", v) => self.alerts = v,
            ("history", Value::Array(a)) => self.history = a,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let has_blocks = self.pools.iter().any(|p| text(p, "mode") == "blocks");
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Pools, "Pools"),
                (Tab::Exceptions, "Exceptions"),
                (Tab::WhoWas, "Who Was"),
                (Tab::Mapping, "Mapping"),
                (Tab::Blocks, "Blocks"),
                (Tab::Alerts, "Alerts"),
                (Tab::History, "History"),
            ] {
                if tab == Tab::Blocks && !has_blocks {
                    continue;
                }
                if ui.selectable_label(self.tab == tab, tr(l, label)).clicked() && self.tab != tab {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
            }
        });
        ui.separator();
        match self.tab {
            Tab::Pools => self.pools_tab(app, ui, l),
            Tab::Exceptions => self.exceptions_tab(app, ui, l),
            Tab::WhoWas => self.who_tab(app, ui, l),
            Tab::Mapping => self.mapping_tab(app, ui, l),
            Tab::Blocks => self.blocks_tab(ui, l),
            Tab::Alerts => self.alerts_tab(app, ui, l),
            Tab::History => self.history_tab(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        self.pool_dialog_ui(app, ctx, area);
        self.exception_dialog_ui(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>() {
            match *r {
                Reply::Pool(id) => {
                    if let Some(d) = self.pool_dialog.as_mut().filter(|d| d.id == id)
                        && d.status.replied(result)
                    {
                        app.floats.forget(dialog_id(d.id));
                        self.pool_dialog = None;
                    }
                }
                Reply::Exception(id) => {
                    if let Some(d) = self.exception_dialog.as_mut().filter(|d| d.id == id)
                        && d.status.replied(result)
                    {
                        app.floats.forget(dialog_id(d.id));
                        self.exception_dialog = None;
                    }
                }
                Reply::WhoWas => self.who.answer = Some(result.clone()),
                Reply::Lookup => self.who.lookup = Some(result.clone()),
                Reply::Other => {}
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Pools => self.pools_t.escape(),
            Tab::Exceptions => self.exceptions_t.escape(),
            _ => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (POOLS, &self.pools_t),
            (EXCEPTIONS, &self.exceptions_t),
            (MAPPING, &self.mapping_t),
            (BLOCKS, &self.blocks_t),
            (ALERTS, &self.alerts_t),
            (HISTORY, &self.history_t),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (POOLS, &mut self.pools_t),
            (EXCEPTIONS, &mut self.exceptions_t),
            (MAPPING, &mut self.mapping_t),
            (BLOCKS, &mut self.blocks_t),
            (ALERTS, &mut self.alerts_t),
            (HISTORY, &mut self.history_t),
        ]
    }
}

/// Whether address `ip` is in `range` (`a.b.c.d/n`, `a-b` or one address);
/// only to pick the right mapping filter, so a guess is enough.
fn in_range(range: &str, ip: &str) -> bool {
    let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else { return false };
    let ip = u32::from(ip);
    if let Some((a, b)) = range.split_once('-') {
        return match (a.trim().parse::<std::net::Ipv4Addr>(), b.trim().parse::<std::net::Ipv4Addr>()) {
            (Ok(a), Ok(b)) => (u32::from(a)..=u32::from(b)).contains(&ip),
            _ => false,
        };
    }
    if let Some((a, n)) = range.split_once('/') {
        let (Ok(a), Ok(n)) = (a.parse::<std::net::Ipv4Addr>(), n.parse::<u32>()) else { return false };
        let mask = if n == 0 { 0 } else { u32::MAX.checked_shl(32 - n.min(32)).unwrap_or(0) };
        return u32::from(a) & mask == ip & mask;
    }
    range.parse::<std::net::Ipv4Addr>().is_ok_and(|a| u32::from(a) == ip)
}

impl Cgnat {
    fn pool_dialog_ui(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.pool_dialog.take() else { return };
        let l = app.lang.labels;
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(n) => format!("{} <{n}>", tr(l, "CGNAT Pool")),
            None => tr(l, "New CGNAT Pool").to_owned(),
        };
        let cmd = if d.item.is_some() { "ip.firewall.cgnat.pool.set" } else { "ip.firewall.cgnat.pool.add" };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: (d.mode.clone(), d.values.clone(), d.flags.clone()) != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let mut info: Option<(String, String)> = None;
        let blocks = d.mode == "blocks";
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("cgnat-pool-fields").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label(tr(l, "Mode"));
                ComboBox::from_id_salt("cgnat-pool-mode")
                    .selected_text(d.mode.clone())
                    .show_ui(ui, |ui| {
                        for m in ["deterministic", "blocks"] {
                            ui.selectable_value(&mut d.mode, m.to_owned(), m);
                        }
                    });
                if help::info_button(ui, Id::unique(("cgnat-pool-help", "mode")), tr(l, "Mode")).clicked() {
                    info = Some(("cgnat.mode".into(), tr(l, "Mode").into()));
                }
                ui.end_row();
                for ((key, label, hint), value) in POOL_FIELDS.iter().zip(d.values.iter_mut()) {
                    if !blocks && matches!(*key, "max_blocks" | "block_timeout") {
                        continue;
                    }
                    ui.label(tr(l, label));
                    let h = ui.spacing().interact_size.y;
                    let id = crate::dialog::field_id(f.window(), key);
                    ui.add_sized([220.0, h], TextEdit::singleline(value).id(id).hint_text(*hint));
                    if help::info_button(ui, Id::unique(("cgnat-pool-help", *key)), tr(l, label)).clicked() {
                        info = Some((format!("cgnat.{key}"), tr(l, label).into()));
                    }
                    ui.end_row();
                }
                for ((key, label), on) in POOL_FLAGS.iter().zip(d.flags.iter_mut()) {
                    ui.label(tr(l, label));
                    ui.checkbox(on, "");
                    if help::info_button(ui, Id::unique(("cgnat-pool-help", *key)), tr(l, label)).clicked() {
                        info = Some((format!("cgnat.{key}"), tr(l, label).into()));
                    }
                    ui.end_row();
                }
            });
            Footer::<()>::edit(false, can.check(cmd))
        });
        if let Some((key, title)) = info {
            self.help = Some(HelpView::new(key, title));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = Map::new();
                if let Some(item) = &d.item {
                    p.insert("id".into(), json!(item));
                }
                if d.item.is_none() || d.mode != d.orig.0 {
                    p.insert("mode".into(), json!(d.mode));
                }
                for (((key, _, _), v), o) in POOL_FIELDS.iter().zip(&d.values).zip(&d.orig.1) {
                    if d.item.is_some() && v == o {
                        continue;
                    }
                    let t = v.trim();
                    if t.is_empty() && !matches!(*key, "comment" | "out_interface") {
                        continue;
                    }
                    let val = match *key {
                        "ports_per_subscriber" | "max_blocks" | "alert_percent" => {
                            t.parse::<u64>().map_or_else(|_| json!(t), |n| json!(n))
                        }
                        _ => json!(t),
                    };
                    p.insert((*key).into(), val);
                }
                for (((key, _), on), o) in POOL_FLAGS.iter().zip(&d.flags).zip(&d.orig.2) {
                    if d.item.is_none() || on != o {
                        p.insert((*key).into(), json!(on));
                    }
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, Value::Object(p), crate::panel::then(NAME, Reply::Pool(d.id)));
            }
            _ => {}
        }
        self.pool_dialog = Some(d);
    }

    fn exception_dialog_ui(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.exception_dialog.take() else { return };
        let l = app.lang.labels;
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(n) => format!("{} <{n}>", tr(l, "CGNAT Exception")),
            None => tr(l, "New CGNAT Exception").to_owned(),
        };
        let cmd = if d.item.is_some() { "ip.firewall.cgnat.exception.set" } else { "ip.firewall.cgnat.exception.add" };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: (d.subscriber.clone(), d.public.clone(), d.comment.clone()) != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let mut info: Option<(&str, &str)> = None;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("cgnat-exception-fields").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                for (key, label, value, hint) in [
                    ("subscriber", "Subscriber", &mut d.subscriber, "100.64.0.9"),
                    ("public", "Public", &mut d.public, "198.51.100.9"),
                    ("comment", "Comment", &mut d.comment, ""),
                ] {
                    ui.label(tr(l, label));
                    let h = ui.spacing().interact_size.y;
                    let id = crate::dialog::field_id(f.window(), key);
                    ui.add_sized([200.0, h], TextEdit::singleline(value).id(id).hint_text(hint));
                    if help::info_button(ui, Id::unique(("cgnat-exception-help", key)), tr(l, label)).clicked() {
                        info = Some((key, label));
                    }
                    ui.end_row();
                }
            });
            Footer::<()>::edit(false, can.check(cmd))
        });
        if let Some((key, label)) = info {
            self.help = Some(HelpView::new(format!("cgnat.exception.{key}"), tr(l, label)));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = json!({"subscriber": d.subscriber.trim(), "public": d.public.trim(), "comment": d.comment});
                if let (Some(item), Some(o)) = (&d.item, p.as_object_mut()) {
                    o.insert("id".into(), json!(item));
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, p, crate::panel::then(NAME, Reply::Exception(d.id)));
            }
            _ => {}
        }
        self.exception_dialog = Some(d);
    }
}

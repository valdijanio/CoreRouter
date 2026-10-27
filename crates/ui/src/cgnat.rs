//! CGNAT (G2.3d): the pools, the 1:1 exceptions, "who was", the mapping
//! table, the port blocks, the port alerts and the capacity (G2.7b: how
//! many ports the subscribers really use and the `ports_per_subscriber`
//! that fits, applied under Safe Mode), as tabs of one window (parts
//! of a window are tabs, `docs/ui-style.md`). Everything comes from
//! `ip.firewall.cgnat.*`: the engine computes the formula, the capacity
//! and the checks; this only shows and sends. Every field has an ⓘ.

use egui::{ComboBox, Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use std::collections::BTreeMap;

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
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
    Capacity,
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
const ALERT_COLUMNS: [table::Column; 7] = [
    col("Subscriber"),
    col("Pool"),
    col("Used"),
    num("Peak"),
    num("Times"),
    col("Refused"),
    col("Last"),
];
const HISTORY_COLUMNS: [table::Column; 4] = [col("Since"), col("Until"), col("Pools"), num("Exceptions")];

/// The pool modal's fields (G0.24 list window pattern).
const POOL_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "cgnat.name", input: Input::Text("cgnat1"), edit: true },
    Field { param: "mode", label: "Mode", help: "cgnat.mode", input: Input::Choice, edit: true },
    Field { param: "inside", label: "Inside", help: "cgnat.inside", input: Input::Text("100.64.0.0/22"), edit: true },
    Field { param: "outside", label: "Outside", help: "cgnat.outside", input: Input::Text("203.0.113.0/28"), edit: true },
    Field { param: "ports_per_subscriber", label: "Ports per Subscriber", help: "cgnat.ports_per_subscriber", input: Input::Text("1000"), edit: true },
    Field { param: "port_range", label: "Port Range", help: "cgnat.port_range", input: Input::Text("1024-65535"), edit: true },
    Field { param: "max_blocks", label: "Max Blocks", help: "cgnat.max_blocks", input: Input::Text("4"), edit: true },
    Field { param: "block_timeout", label: "Block Timeout", help: "cgnat.block_timeout", input: Input::Text("2m"), edit: true },
    Field { param: "out_interface", label: "Out. Interface", help: "cgnat.out_interface", input: Input::Text("ether1"), edit: true },
    Field { param: "alert_percent", label: "Alert %", help: "cgnat.alert_percent", input: Input::Text("90"), edit: true },
    Field { param: "endpoint_independent_mapping", label: "Endpoint-Independent Mapping", help: "cgnat.endpoint_independent_mapping", input: Input::Check, edit: true },
    Field { param: "endpoint_independent_filtering", label: "Endpoint-Independent Filtering", help: "cgnat.endpoint_independent_filtering", input: Input::Check, edit: true },
    Field { param: "hairpin", label: "Hairpin", help: "cgnat.hairpin", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "cgnat.comment", input: Input::Text(""), edit: true },
];
const POOL_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New CGNAT Pool",
    edit_title: "CGNAT Pool",
    help: "cgnat.pool",
    fields: POOL_FIELDS,
    preview: "ip.firewall.cgnat.pool.preview",
};
const POOL_CMDS: Cmds = Cmds {
    add: "ip.firewall.cgnat.pool.add",
    remove: "ip.firewall.cgnat.pool.remove",
    set: Some("ip.firewall.cgnat.pool.set"),
    what: "pools",
};
const EXCEPTION_FIELDS: &[Field] = &[
    Field { param: "subscriber", label: "Subscriber", help: "cgnat.exception.subscriber", input: Input::Text("100.64.0.9"), edit: true },
    Field { param: "public", label: "Public", help: "cgnat.exception.public", input: Input::Text("198.51.100.9"), edit: true },
    Field { param: "comment", label: "Comment", help: "cgnat.exception.comment", input: Input::Text(""), edit: true },
];
const EXCEPTION_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New CGNAT Exception",
    edit_title: "CGNAT Exception",
    help: "cgnat.exception",
    fields: EXCEPTION_FIELDS,
    preview: "ip.firewall.cgnat.exception.preview",
};
const EXCEPTION_CMDS: Cmds = Cmds {
    add: "ip.firewall.cgnat.exception.add",
    remove: "ip.firewall.cgnat.exception.remove",
    set: Some("ip.firewall.cgnat.exception.set"),
    what: "exceptions",
};

/// Which list the open modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Which {
    Pool,
    Exception,
}

impl Which {
    fn spec(self) -> &'static Spec {
        match self {
            Which::Pool => &POOL_SPEC,
            Which::Exception => &EXCEPTION_SPEC,
        }
    }
}

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
    pub(crate) capacity: CapacityView,
    pools_t: TableState,
    exceptions_t: TableState,
    mapping_t: TableState,
    blocks_t: TableState,
    alerts_t: TableState,
    history_t: TableState,
    pub(crate) modal: Option<(Which, Modal)>,
    pub(crate) filters: list::Filters,
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

/// The Capacity tab (G2.7b): the pool shown, its numbers, the ports to
/// try and their preview.
#[derive(Default)]
pub(crate) struct CapacityView {
    pub pool: String,
    pub data: Value,
    /// The value in the field (the suggestion until the operator types).
    pub ports: String,
    pub preview: Option<Result<Value, String>>,
    /// The ports the preview was asked for: apply only what was previewed.
    pub previewed: String,
    pub applied: Option<Result<Value, String>>,
}

enum Reply {
    WhoWas,
    Lookup,
    CapacityPreview,
    CapacityApplied,
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

    /// What a row of the pool list says of itself, for the bar.
    fn pool_values(row: Option<&Value>) -> BTreeMap<&'static str, String> {
        let mut v: BTreeMap<&'static str, String> = BTreeMap::new();
        for f in POOL_FIELDS {
            let text = match (row, f.input) {
                (Some(r), Input::Check) => {
                    if r.get(f.param).and_then(Value::as_bool).unwrap_or(false) { "yes" } else { "no" }.to_owned()
                }
                (Some(r), _) => match f.param {
                    "inside" | "outside" => list_text(r, f.param),
                    _ => text(r, f.param),
                },
                (None, Input::Check) => {
                    if matches!(f.param, "endpoint_independent_mapping" | "hairpin") { "yes" } else { "no" }.to_owned()
                }
                (None, _) if f.param == "mode" => "deterministic".to_owned(),
                (None, _) => String::new(),
            };
            v.insert(f.param, text);
        }
        v
    }

    /// Open item `k` of `which` in the modal.
    fn edit(&mut self, app: &mut CoreRouterUi, which: Which, k: &str) {
        let (rows, key) = match which {
            Which::Pool => (&self.pools, "name"),
            Which::Exception => (&self.exceptions, "id"),
        };
        let Some(r) = rows.iter().find(|r| text(r, key) == k).cloned() else { return };
        let values = match which {
            Which::Pool => Self::pool_values(Some(&r)),
            Which::Exception => EXCEPTION_FIELDS.iter().map(|f| (f.param, text(&r, f.param))).collect(),
        };
        let name = match which {
            Which::Pool => text(&r, "name"),
            Which::Exception => format!("{} – {}", text(&r, "subscriber"), text(&r, "public")),
        };
        self.modal = Some((which, Modal::open(app, Some((k.to_owned(), name)), values)));
    }

    /// Act on a list's bar, menu or keys: one dispatcher for both lists.
    fn act(&mut self, app: &mut CoreRouterUi, ui: &Ui, which: Which, act: Act) {
        let (cmds, rows, key) = match which {
            Which::Pool => (POOL_CMDS, &self.pools, "name"),
            Which::Exception => (EXCEPTION_CMDS, &self.exceptions, "id"),
        };
        let set = cmds.set.unwrap_or(cmds.remove);
        let steps = |keys: &[String], extra: Value| -> Vec<Value> {
            keys.iter()
                .map(|k| {
                    let mut p = extra.clone();
                    if let Some(o) = p.as_object_mut() {
                        o.insert("id".into(), json!(k));
                    }
                    json!({"command": set, "params": p})
                })
                .collect()
        };
        match act {
            Act::Add => {
                let values = match which {
                    Which::Pool => Self::pool_values(None),
                    Which::Exception => EXCEPTION_FIELDS.iter().map(|f| (f.param, String::new())).collect(),
                };
                self.modal = Some((which, Modal::open(app, None, values)));
            }
            // Comment: the modal has the comment field (one item at a time).
            Act::Edit(k) => self.edit(app, which, &k),
            Act::Comment(keys) => {
                if let Some(k) = keys.first() {
                    self.edit(app, which, k);
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, crate::panel::then(NAME, Reply::Other));
            }
            Act::Enable(keys) => {
                app.run_steps(steps(&keys, json!({"disabled": false})), crate::panel::then(NAME, Reply::Other));
            }
            Act::Disable(keys) => {
                app.run_steps(steps(&keys, json!({"disabled": true})), crate::panel::then(NAME, Reply::Other));
            }
            Act::Copy(keys) => {
                let rows: Vec<Row> = rows
                    .iter()
                    .filter(|r| keys.contains(&text(r, key)))
                    .map(|r| match which {
                        Which::Pool => pool_row(r),
                        Which::Exception => exception_row(r),
                    })
                    .collect();
                let refs: Vec<&Row> = rows.iter().collect();
                ui.ctx().copy_text(list::copy_rows(&refs));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = rows.iter().filter(|r| keys.contains(&text(r, key))).cloned().collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    fn pools_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let shown: Vec<&Value> = self.pools.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| pool_row(r)).collect();
        let selection = self.pools_t.selection(&rows);
        let picked: Vec<Item> = self
            .pools
            .iter()
            .filter(|r| selection.contains(&text(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &POOL_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, POOLS, &tools, &selection, l);
            self.filters.chips(ui, "mode", &[("deterministic", "deterministic"), ("blocks", "blocks")], l);
            let days = text(&self.settings, "history_days");
            ui.weak(format!("{}: {days} {}", tr(l, "History kept"), tr(l, "days")));
            if help::info_button(ui, Id::unique("cgnat-help-history"), tr(l, "History kept")).clicked() {
                self.help = Some(HelpView::new("cgnat.history_days", tr(l, "History kept")));
            }
            table::find_field(ui, POOLS, &mut self.pools_t);
        });
        let can_copy = !app.cache.commands.is_empty();
        let foot = ui.spacing().interact_size.y + 4.0;
        let out = table::show(ui, POOLS, foot, &mut self.pools_t, &POOL_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu {
                act = list::row_menu(ui, &tools, sel, can_copy, l).or(act.take());
            }
        });
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.map(Act::Edit));
        let total = self.pools.len();
        let disabled = list::count(&self.pools, "disabled", "true");
        let blocks = list::count(&self.pools, "mode", "blocks");
        list::footer(
            ui,
            &[
                (total, "pools", chip::neutral_tone(ui.visuals())),
                (blocks, "blocks mode", chip::BLUE.tone(ui.visuals())),
                (disabled, "disabled", chip::neutral_tone(ui.visuals())),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, ui, Which::Pool, a);
        }
    }

    fn exceptions_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.exceptions.iter().map(exception_row).collect();
        let selection = self.exceptions_t.selection(&rows);
        let picked: Vec<Item> = self
            .exceptions
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .map(|r| Item::of(r, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &EXCEPTION_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, EXCEPTIONS, &tools, &selection, l);
            ui.weak(tr(l, "A subscriber with a public address of its own (1:1), outside every pool."));
            if help::info_button(ui, Id::unique("cgnat-help-exception"), tr(l, "Exceptions")).clicked() {
                self.help = Some(HelpView::new("cgnat.exception", tr(l, "Exceptions")));
            }
            table::find_field(ui, EXCEPTIONS, &mut self.exceptions_t);
        });
        let can_copy = !app.cache.commands.is_empty();
        let foot = ui.spacing().interact_size.y + 4.0;
        let out = table::show(ui, EXCEPTIONS, foot, &mut self.exceptions_t, &EXCEPTION_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu {
                act = list::row_menu(ui, &tools, sel, can_copy, l).or(act.take());
            }
        });
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.map(Act::Edit));
        list::footer(ui, &[(self.exceptions.len(), "exceptions", chip::neutral_tone(ui.visuals()))], l);
        if let Some(a) = act {
            self.act(app, ui, Which::Exception, a);
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
                    // G0.25: who that subscriber was then.
                    crate::identity::badge_at(app, ui, "cgnat", &text(v, "subscriber"), Some(&text(v, "time")));
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
        let num = |k: &str| self.alerts.get(k).and_then(Value::as_u64).unwrap_or(0);
        let (refused, icmp, full) = (num("refused"), num("icmp_sent"), num("full"));
        let icmp_on = self.settings.get("icmp_unreachable").and_then(Value::as_bool) != Some(false);
        let rate = text(&self.settings, "icmp_rate");
        ui.horizontal(|ui| {
            if failed > 0 {
                chip::chip(ui, &format!("insert failed {failed}"), chip::RED.tone(ui.visuals()))
                    .on_hover_text(tr(l, "New connections the kernel could not translate: no free port"));
            }
            if refused > 0 {
                chip::chip(ui, &format!("refused {refused}"), chip::RED.tone(ui.visuals()))
                    .on_hover_text(tr(l, "New connections dropped for lack of a port (RFC 6888 REQ-11)"));
            }
            let (label, tone) = if icmp_on {
                (format!("ICMP unreachable · {rate}/s · sent {icmp}"), chip::GREEN.tone(ui.visuals()))
            } else {
                ("ICMP unreachable off".to_owned(), chip::neutral_tone(ui.visuals()))
            };
            chip::chip(ui, &label, tone);
            if help::info_button(ui, Id::unique("cgnat-help-icmp"), tr(l, "ICMP Unreachable")).clicked() {
                self.help = Some(HelpView::new("cgnat.icmp_unreachable", tr(l, "ICMP Unreachable")));
            }
            if full > 0 {
                chip::chip(ui, &format!("checked {full}"), chip::AMBER.tone(ui.visuals()))
                    .on_hover_text(tr(l, "Subscribers near the end of their ports: their new connections are checked for a free port"));
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
                                match r.get("refused").and_then(Value::as_u64).unwrap_or(0) {
                                    0 => String::new(),
                                    n => chip::cell(&n.to_string(), &[(format!("ICMP {}", text(r, "icmp")).as_str(), Kind::Red)]),
                                },
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

    /// The pool the Capacity tab shows: the chosen one, else the first.
    fn capacity_pool(&self) -> String {
        if !self.capacity.pool.is_empty() && self.pools.iter().any(|p| text(p, "name") == self.capacity.pool) {
            return self.capacity.pool.clone();
        }
        self.pools.first().map(|p| text(p, "name")).unwrap_or_default()
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(key), tr(l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr(l, title)));
        }
    }

    fn capacity_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let pool = self.capacity_pool();
        if pool.is_empty() {
            ui.weak(tr(l, "No pool yet."));
            return;
        }
        ui.horizontal(|ui| {
            ui.label(tr(l, "Pool"));
            ComboBox::from_id_salt("cgnat-capacity-pool").selected_text(&pool).show_ui(ui, |ui| {
                for p in &self.pools {
                    let name = text(p, "name");
                    if ui.selectable_label(name == pool, &name).clicked() && name != pool {
                        self.capacity = CapacityView { pool: name, ..CapacityView::default() };
                        app.cache.refreshed_at = None;
                    }
                }
            });
            self.info(ui, l, "cgnat.capacity", "Capacity");
            let d = &self.capacity.data;
            if d.get("seen").is_some() {
                ui.weak(format!(
                    "{} {} {} {} · {}",
                    text(d, "seen"),
                    tr(l, "of"),
                    text(d, "subscribers"),
                    tr(l, "subscribers seen"),
                    tr(l, "peaks of the last 7 days")
                ));
            }
        });
        let d = self.capacity.data.clone();
        if d.get("ports").is_none() {
            ui.weak(tr(l, "Waiting for the router…"));
            return;
        }
        ui.add_space(4.0);
        // Three cards: the limit, the p99 peak, who hit the limit.
        let width = ((ui.available_width() - 16.0) / 3.0).max(180.0);
        ui.horizontal(|ui| {
            let card = |me: &mut Self, ui: &mut Ui, key: &'static str, title: &'static str, big: String, small: String, tone: Option<chip::Tone>| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(width - 14.0);
                    ui.set_min_height(74.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.strong(tr(l, title));
                            me.info(ui, l, key, title);
                        });
                        ui.horizontal(|ui| {
                            ui.heading(&big);
                            if let Some(t) = tone {
                                chip::chip(ui, &small, t);
                            }
                        });
                        if tone.is_none() {
                            ui.weak(&small);
                        }
                    });
                });
            };
            let per = text(&d, "per_address");
            card(self, ui, "cgnat.capacity.ports", "Ports per Subscriber", text(&d, "ports"), format!("{per} {}", tr(l, "per public address")), None);
            let pct = d.get("p99_percent").and_then(Value::as_u64).unwrap_or(0);
            let tone = match pct {
                0..=74 => chip::GREEN.tone(ui.visuals()),
                75..=89 => chip::AMBER.tone(ui.visuals()),
                _ => chip::RED.tone(ui.visuals()),
            };
            card(self, ui, "cgnat.capacity.p99", "Peak p99, 7 days", text(&d, "p99"), format!("{pct} %"), Some(tone));
            let hit = d.get("hit_24h").and_then(Value::as_u64).unwrap_or(0);
            let small = format!(
                "{} {} · ICMP {}",
                text(&d, "refused_24h"),
                tr(l, "refused"),
                text(&d, "icmp_24h")
            );
            let tone = if hit > 0 { chip::RED.tone(ui.visuals()) } else { chip::GREEN.tone(ui.visuals()) };
            card(self, ui, "cgnat.capacity.hit", "Hit the limit, 24 h", hit.to_string(), small, Some(tone));
        });
        ui.add_space(6.0);
        // The distribution of the 7-day peaks.
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Peak distribution"));
            self.info(ui, l, "cgnat.capacity.bands", "Peak distribution");
        });
        let bands: Vec<(String, u64)> = d
            .get("bands")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|b| (text(b, "band"), b.get("count").and_then(Value::as_u64).unwrap_or(0))).collect())
            .unwrap_or_default();
        let most = bands.iter().map(|b| b.1).max().unwrap_or(0).max(1);
        Grid::new("cgnat-capacity-bands").num_columns(3).spacing([10.0, 3.0]).show(ui, |ui| {
            for (band, count) in &bands {
                ui.label(if band == "100" { "100 %".to_owned() } else { format!("{band} %") });
                let hue = match band.as_str() {
                    "100" => &chip::RED,
                    "90-100" => &chip::AMBER,
                    _ => &chip::BLUE,
                };
                let tone = hue.tone(ui.visuals());
                let full = 360.0;
                let (rect, _) = ui.allocate_exact_size(egui::vec2(full, 14.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 3.0, tone.fill);
                let w = full * (*count as f32) / (most as f32);
                let bar = egui::Rect::from_min_size(rect.min, egui::vec2(w.max(if *count > 0 { 2.0 } else { 0.0 }), rect.height()));
                ui.painter().rect_filled(bar, 3.0, tone.ink);
                ui.label(count.to_string());
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        // The suggestion, its preview and the apply under Safe Mode.
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Suggestion"));
            self.info(ui, l, "cgnat.capacity.suggestion", "Suggestion");
        });
        let Some(sug) = d.get("suggestion").cloned() else {
            ui.weak(tr(l, "No suggestion: no readings yet, or a blocks-mode pool (grow max_blocks instead)."));
            return;
        };
        let now = text(&d, "ports_per_subscriber");
        Grid::new("cgnat-capacity-suggestion").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label(tr(l, "Ports per Subscriber"));
            ui.horizontal(|ui| {
                ui.label(format!("{now} ->"));
                ui.add(TextEdit::singleline(&mut self.capacity.ports).desired_width(70.0));
                chip::chip(ui, &format!("{} {}", tr(l, "suggested"), text(&sug, "ports_per_subscriber")), chip::BLUE.tone(ui.visuals()));
            });
            ui.end_row();
            ui.label(tr(l, "Per public address"));
            let gain = sug.get("gain_per_address").and_then(Value::as_i64).unwrap_or(0);
            ui.horizontal(|ui| {
                ui.label(format!("{} -> {}", text(&d, "per_address"), text(&sug, "per_address")));
                let (label, hue) = if gain >= 0 { (format!("+{gain}"), &chip::GREEN) } else { (gain.to_string(), &chip::AMBER) };
                chip::chip(ui, &label, hue.tone(ui.visuals()));
            });
            ui.end_row();
            ui.label(tr(l, "Public addresses"));
            let fits = sug.get("fits").and_then(Value::as_bool) == Some(true);
            ui.horizontal(|ui| {
                ui.label(format!("{} {} {}", text(&sug, "public_needed"), tr(l, "needed of"), text(&d, "public_addresses")));
                if !fits {
                    chip::chip(ui, tr(l, "does not fit"), chip::RED.tone(ui.visuals()));
                }
            });
            ui.end_row();
            ui.label(tr(l, "Why"));
            ui.label(tr(l, static_reason(&text(&sug, "reason"))));
            ui.end_row();
        });
        let ports = self.capacity.ports.trim().to_owned();
        ui.horizontal(|ui| {
            let can_preview = app.can().check("ip.firewall.cgnat.capacity.preview").is_ok() && !ports.is_empty();
            if ui.add_enabled(can_preview, egui::Button::new(tr(l, "Preview"))).clicked() {
                let n: u64 = ports.parse().unwrap_or(0);
                self.capacity.previewed = ports.clone();
                self.capacity.applied = None;
                app.run_then(
                    "ip.firewall.cgnat.capacity.preview",
                    json!({"pool": pool, "ports_per_subscriber": n}),
                    crate::panel::then(NAME, Reply::CapacityPreview),
                );
            }
            let previewed_ok = self.capacity.previewed == ports
                && matches!(&self.capacity.preview, Some(Ok(v)) if v.get("fits").and_then(Value::as_bool) == Some(true));
            let can_apply = previewed_ok
                && app.can().check("config.safe-mode.enter").is_ok()
                && app.can().check("ip.firewall.cgnat.pool.set").is_ok();
            let apply = ui
                .add_enabled(can_apply, egui::Button::new(tr(l, "Apply with Safe Mode")))
                .on_disabled_hover_text(tr(l, "Preview this value first"));
            if apply.clicked() {
                let n: u64 = ports.parse().unwrap_or(0);
                app.run("config.safe-mode.enter", json!({}));
                app.run_then(
                    "ip.firewall.cgnat.pool.set",
                    json!({"id": pool, "ports_per_subscriber": n}),
                    crate::panel::then(NAME, Reply::CapacityApplied),
                );
            }
            self.info(ui, l, "cgnat.capacity.apply", "Apply with Safe Mode");
        });
        match &self.capacity.preview {
            Some(Ok(v)) => {
                ui.horizontal(|ui| {
                    chip::chip(ui, &format!("{} {}", text(v, "remapped"), tr(l, "subscribers remapped")), chip::AMBER.tone(ui.visuals()));
                    chip::chip(ui, &format!("{} {}", text(v, "connections"), tr(l, "connections dropped")), chip::AMBER.tone(ui.visuals()));
                    if v.get("fits").and_then(Value::as_bool) == Some(true) {
                        chip::chip(ui, &format!("{} {}", text(v, "per_address"), tr(l, "per public address")), chip::GREEN.tone(ui.visuals()));
                    } else {
                        chip::chip(ui, tr(l, "does not fit"), chip::RED.tone(ui.visuals()));
                        ui.weak(text(v, "error"));
                    }
                });
            }
            Some(Err(e)) => {
                ui.colored_label(chip::RED.tone(ui.visuals()).ink, e);
            }
            None => {}
        }
        match &self.capacity.applied {
            Some(Ok(_)) => {
                ui.colored_label(
                    chip::GREEN.tone(ui.visuals()).ink,
                    tr(l, "Applied under Safe Mode: confirm with the Safe Mode button, or it rolls back."),
                );
            }
            Some(Err(e)) => {
                ui.colored_label(chip::RED.tone(ui.visuals()).ink, e);
            }
            None => {}
        }
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
            Tab::Capacity => {
                let pool = self.capacity_pool();
                if !pool.is_empty() {
                    out.push(q("capacity", "ip.firewall.cgnat.capacity", json!({"pool": pool})));
                }
            }
            Tab::History => out.push(q("history", "ip.firewall.cgnat.history.list", json!({}))),
            _ => {}
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some((_, m)) = self.modal.as_mut() {
                m.arrived(value);
            }
            return;
        }
        match (key, value) {
            ("pools", Value::Array(a)) => self.pools = a,
            ("exceptions", Value::Array(a)) => self.exceptions = a,
            ("settings", v) => self.settings = v,
            ("mapping", v) => self.mapping = v,
            ("blocks", v) => self.blocks = v,
            ("block_history", Value::Array(a)) => self.block_history = a,
            ("alerts", v) => self.alerts = v,
            ("capacity", v) => {
                // A new suggestion fills the field unless the operator typed.
                let old = self.capacity.data.get("suggestion").map(|s| text(s, "ports_per_subscriber"));
                let new = v.get("suggestion").map(|s| text(s, "ports_per_subscriber"));
                if new.is_some() && (self.capacity.ports.is_empty() || self.capacity.ports == old.clone().unwrap_or_default()) {
                    self.capacity.ports = new.unwrap_or_default();
                }
                self.capacity.data = v;
            }
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
                (Tab::Capacity, "Capacity"),
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
            Tab::Capacity => self.capacity_tab(app, ui, l),
            Tab::History => self.history_tab(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        if let Some((which, modal)) = self.modal.as_mut() {
            let options = |param: &str| -> Vec<String> {
                match param {
                    "mode" => vec!["deterministic".into(), "blocks".into()],
                    _ => Vec::new(),
                }
            };
            if !modal.show(app, ctx, area, which.spec(), &options) {
                self.modal = None;
            }
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let then = match then.downcast::<list_modal::Applied>() {
            Ok(applied) => {
                if let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == applied.0)
                    && m.replied(app, result)
                {
                    self.modal = None;
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(other) => other,
        };
        if let Ok(r) = then.downcast::<Reply>() {
            match *r {
                Reply::WhoWas => self.who.answer = Some(result.clone()),
                Reply::Lookup => self.who.lookup = Some(result.clone()),
                Reply::CapacityPreview => self.capacity.preview = Some(result.clone()),
                Reply::CapacityApplied => {
                    self.capacity.applied = Some(result.clone());
                    self.capacity.preview = None;
                    self.capacity.previewed.clear();
                }
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

/// The engine's suggestion reasons, as `'static` keys for the translation.
fn static_reason(r: &str) -> &'static str {
    match r {
        "already right" => "already right",
        "more than 1 % of the subscribers ran out of ports in 24 h" => "more than 1 % of the subscribers ran out of ports in 24 h",
        _ => "p99 of the 7-day peaks plus 25 %",
    }
}

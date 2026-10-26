//! Queues (G4.9): bandwidth per target, as WinBox's Queues window with
//! three tabs — Simple Queues (fixed and dynamic, with the origin of each
//! dynamic one and the precedence warnings), Per-IP (PCQ) and Queue Types.
//! The G0.24 list pattern (+ − ✓ ✗ 💬, filter chips, footer, the modal fed
//! by `queue.*.preview`). `queue.*` decides; this only shows and sends.

use std::collections::BTreeMap;

use egui::{Grid, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::HelpView;
use crate::i18n::tr_in;
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Filters, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "queues";
pub(crate) const WIN: &str = "queues";
const SCOPE: &str = "queues";
const SIMPLE_TABLE: &str = "queues-simple";
const PCQ_TABLE: &str = "queues-pcq";
const TYPES_TABLE: &str = "queues-types";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Queues",
        title: "Queues",
        size: [980.0, 420.0],
        escape: true,
    }],
    new: || Box::new(QueuesPanel::default()),
};

const SIMPLE: Cmds = Cmds {
    add: "queue.simple.add",
    remove: "queue.simple.remove",
    set: Some("queue.simple.set"),
    what: "queues",
};

const PER_IP: Cmds = Cmds {
    add: "queue.per-ip.add",
    remove: "queue.simple.remove",
    set: Some("queue.simple.set"),
    what: "per-IP limits",
};

const TYPES: Cmds = Cmds {
    add: "queue.type.add",
    remove: "queue.type.remove",
    set: Some("queue.type.set"),
    what: "queue types",
};

const DYNAMIC: &str = "A dynamic queue comes from a PPPoE/IPoE session (its profile or RADIUS), \
     a DHCP lease or a DHCP network: change its rate there";
const BUILTIN: &str = "A built-in type cannot be removed (edit it: a copy is kept)";

/// Which tab is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Simple,
    PerIp,
    Types,
}

const TABS: [(Tab, &str, &str); 3] = [
    (Tab::Simple, "Simple Queues", "queues.tab.simple"),
    (Tab::PerIp, "Per-IP (PCQ)", "queues.tab.pcq"),
    (Tab::Types, "Queue Types", "queues.tab.types"),
];

const SIMPLE_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "queues.simple.name", input: Input::Text("queue1"), edit: true },
    Field { param: "target", label: "Target", help: "queues.simple.target", input: Input::Text("10.0.0.5, 10.0.1.0/24 or ether2"), edit: true },
    Field { param: "max_limit", label: "Max Limit", help: "queues.simple.max_limit", input: Input::Text("10M/50M (upload/download)"), edit: true },
    Field { param: "limit_at", label: "Limit At", help: "queues.simple.limit_at", input: Input::Text("0/0"), edit: true },
    Field { param: "burst_limit", label: "Burst Limit", help: "queues.simple.burst_limit", input: Input::Text("0/0"), edit: true },
    Field { param: "burst_threshold", label: "Burst Threshold", help: "queues.simple.burst_threshold", input: Input::Text("0/0"), edit: true },
    Field { param: "burst_time", label: "Burst Time", help: "queues.simple.burst_time", input: Input::Text("8s/8s"), edit: true },
    Field { param: "bucket_size", label: "Bucket Size", help: "queues.simple.bucket_size", input: Input::Text("0.1/0.1"), edit: true },
    Field { param: "priority", label: "Priority", help: "queues.simple.priority", input: Input::Text("8/8"), edit: true },
    Field { param: "queue", label: "Queue Type", help: "queues.simple.queue", input: Input::Text("default-small/default-small"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
    Field { param: "disabled", label: "Disabled", help: "queues.simple.disabled", input: Input::Check, edit: true },
];

const SIMPLE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Simple Queue",
    edit_title: "Simple Queue",
    help: "queues.simple",
    fields: SIMPLE_FIELDS,
    preview: "queue.simple.preview",
};

const PCQ_FIELDS: &[Field] = &[
    Field { param: "target", label: "Target", help: "queues.pcq.target", input: Input::Text("10.0.0.0/16"), edit: false },
    Field { param: "rate", label: "Rate Each", help: "queues.pcq.rate", input: Input::Text("10M/20M (upload/download)"), edit: false },
    Field { param: "max_limit", label: "Max Limit", help: "queues.pcq.max_limit", input: Input::Text("0/0 (all together)"), edit: false },
    Field { param: "ipv6_mask", label: "IPv6 Mask", help: "queues.pcq.ipv6_mask", input: Input::Text("64"), edit: false },
    Field { param: "name", label: "Name", help: "queues.simple.name", input: Input::Text("(automatic)"), edit: false },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: false },
];

const PCQ_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Per-IP Limit",
    edit_title: "Per-IP Limit",
    help: "queues.pcq",
    fields: PCQ_FIELDS,
    preview: "queue.per-ip.preview",
};

const TYPE_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "queues.type.name", input: Input::Text("pcq-down-20M"), edit: true },
    Field { param: "kind", label: "Kind", help: "queues.type.kind", input: Input::Choice, edit: true },
    Field { param: "pfifo_limit", label: "PFIFO Limit", help: "queues.type.pfifo_limit", input: Input::Text("50 (packets)"), edit: true },
    Field { param: "bfifo_limit", label: "BFIFO Limit", help: "queues.type.bfifo_limit", input: Input::Text("15000 (bytes)"), edit: true },
    Field { param: "pcq_rate", label: "PCQ Rate", help: "queues.type.pcq_rate", input: Input::Text("0 (share)"), edit: true },
    Field { param: "pcq_classifier", label: "PCQ Classifier", help: "queues.type.pcq_classifier", input: Input::Choice, edit: true },
    Field { param: "pcq_dst_address6_mask", label: "PCQ IPv6 Mask", help: "queues.type.pcq_mask6", input: Input::Text("128"), edit: true },
    Field { param: "fq_codel_target", label: "FQ-CoDel Target", help: "queues.type.fq_codel_target", input: Input::Text("5ms"), edit: true },
    Field { param: "fq_codel_interval", label: "FQ-CoDel Interval", help: "queues.type.fq_codel_interval", input: Input::Text("100ms"), edit: true },
    Field { param: "fq_codel_ecn", label: "FQ-CoDel ECN", help: "queues.type.fq_codel_ecn", input: Input::Check, edit: true },
    Field { param: "cake_rtt", label: "CAKE RTT", help: "queues.type.cake_rtt", input: Input::Text("100ms"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const TYPE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Queue Type",
    edit_title: "Queue Type",
    help: "queues.type",
    fields: TYPE_FIELDS,
    preview: "queue.type.preview",
};

const SIMPLE_COLUMNS: [table::Column; 9] = [
    col("Origin").help("queues.simple.origin"),
    col("Name").help("queues.simple.name"),
    col("Target").help("queues.simple.target"),
    col("Max Limit").help("queues.simple.max_limit"),
    col("Rate").help("queues.simple.rate"),
    num("Queue (ms)").help("queues.simple.queued"),
    num("Drops").help("queues.simple.dropped"),
    col("Queue Type").help("queues.simple.queue"),
    comment(),
];

const PCQ_COLUMNS: [table::Column; 7] = [
    col("Name").help("queues.simple.name"),
    col("Target").help("queues.pcq.target"),
    col("Rate Each").help("queues.pcq.rate"),
    col("Max Limit").help("queues.pcq.max_limit"),
    num("Addresses").help("queues.pcq.addresses"),
    col("Queue Type").help("queues.simple.queue"),
    comment(),
];

const TYPE_COLUMNS: [table::Column; 5] = [
    col("Name").help("queues.type.name"),
    col("Kind").help("queues.type.kind"),
    col("Settings").help("queues.type.settings"),
    col("Used By").help("queues.type.used_by"),
    comment(),
];

#[derive(Default)]
pub(crate) struct QueuesPanel {
    pub(crate) tab: Tab,
    pub(crate) simple: Value,
    pub(crate) pcq: Vec<Value>,
    pub(crate) types: Vec<Value>,
    pub(crate) filters: Filters,
    simple_table: TableState,
    pcq_table: TableState,
    types_table: TableState,
    pub(crate) modal: Option<(Tab, Modal)>,
    note: Option<NoteDialog>,
    pub(crate) help: Option<HelpView>,
}

/// 💬 on the selection.
struct NoteDialog {
    id: u64,
    tab: Tab,
    keys: Vec<String>,
    text: String,
    status: Status,
}

struct NoteReply(u64);

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(crate::value_text).unwrap_or_default()
}

fn pair(r: &Value, k: &str) -> (u64, u64) {
    let a = r.get(k).and_then(Value::as_array);
    let at = |i: usize| a.and_then(|a| a.get(i)).and_then(Value::as_u64).unwrap_or(0);
    (at(0), at(1))
}

/// `12.3M` from bits per second.
fn bps(v: u64) -> String {
    match v {
        0 => "0".into(),
        v if v >= 1_000_000_000 => format!("{:.1}G", v as f64 / 1e9),
        v if v >= 1_000_000 => format!("{:.1}M", v as f64 / 1e6),
        v if v >= 1_000 => format!("{:.0}k", v as f64 / 1e3),
        v => v.to_string(),
    }
}

fn origin_chip(o: &str) -> (&'static str, Kind) {
    match o {
        "pppoe" => ("PPPoE", Kind::Blue),
        "ipoe" => ("IPoE", Kind::Blue),
        "dhcp-lease" => ("DHCP lease", Kind::Blue),
        "dhcp-network" => ("DHCP network", Kind::Blue),
        _ => ("fixed", Kind::Neutral),
    }
}

pub(crate) fn simple_row(r: &Value) -> Row {
    let (o, k) = origin_chip(&s(r, "origin"));
    let mut chips = vec![(o.to_owned(), k)];
    if r.get("dynamic").and_then(Value::as_bool).unwrap_or(false) {
        chips.insert(0, ("D".to_owned(), Kind::Neutral));
    }
    if r.get("disabled").and_then(Value::as_bool).unwrap_or(false) {
        chips.push(("disabled".to_owned(), Kind::Neutral));
    }
    let warnings = r.get("warnings").and_then(Value::as_array).map_or(0, Vec::len);
    let mut name_chips: Vec<(String, Kind)> = Vec::new();
    if warnings > 0 {
        name_chips.push((format!("{warnings} warning{}", if warnings == 1 { "" } else { "s" }), Kind::Amber));
    }
    let as_cell = |text: &str, chips: &[(String, Kind)]| {
        let c: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
        cell(text, &c)
    };
    let (up, down) = pair(r, "rate_bps");
    let (_, q_us) = pair(r, "queued_us");
    let (d_up, d_down) = pair(r, "dropped");
    Row {
        key: s(r, "id"),
        cells: vec![
            as_cell("", &chips),
            as_cell(&s(r, "name"), &name_chips),
            s(r, "target"),
            s(r, "max_limit"),
            format!("{}/{}", bps(up), bps(down)),
            wait_text(q_us),
            (d_up + d_down).to_string(),
            s(r, "queue"),
            s(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

/// A queue's wait (microseconds) as the Queue (ms) column shows it; empty
/// when nothing waits (not shaped, or an empty queue).
pub(crate) fn wait_text(us: u64) -> String {
    if us == 0 { String::new() } else { format!("{:.1} ms", us as f64 / 1000.0) }
}

pub(crate) fn pcq_row(r: &Value) -> Row {
    Row {
        key: s(r, "id"),
        cells: vec![
            s(r, "name"),
            s(r, "target"),
            s(r, "rate"),
            s(r, "max_limit"),
            s(r, "pcq_queues"),
            s(r, "queue"),
            s(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

/// The type's own settings in one line (`10M dst-address /64`).
fn settings_text(r: &Value) -> String {
    match s(r, "kind").as_str() {
        "pfifo" => format!("{} packets", s(r, "pfifo_limit")),
        "bfifo" => format!("{} bytes", s(r, "bfifo_limit")),
        "pcq" => format!(
            "{} each · {} · v6 /{}",
            s(r, "pcq_rate"),
            s(r, "pcq_classifier"),
            if s(r, "pcq_classifier") == "src-address" { s(r, "pcq_src_address6_mask") } else { s(r, "pcq_dst_address6_mask") }
        ),
        "fq-codel" => format!(
            "target {} · interval {}{}",
            s(r, "fq_codel_target"),
            s(r, "fq_codel_interval"),
            if r.get("fq_codel_ecn").and_then(Value::as_bool).unwrap_or(false) { " · ECN" } else { "" }
        ),
        "cake" => format!("rtt {}", s(r, "cake_rtt")),
        _ => String::new(),
    }
}

pub(crate) fn type_row(r: &Value) -> Row {
    let kind = s(r, "kind");
    let mut chips = vec![(kind.clone(), Kind::Hashed(chip::name_hue(&kind)))];
    if r.get("builtin").and_then(Value::as_bool).unwrap_or(false) {
        chips.push(("built-in".to_owned(), Kind::Neutral));
    }
    let c: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    let used: Vec<String> = r
        .get("used_by")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    Row {
        key: s(r, "name"),
        cells: vec![s(r, "name"), cell("", &c), settings_text(r), used.join(", "), s(r, "comment")],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn simple_values(r: &Value) -> BTreeMap<&'static str, String> {
    let yes = |b: bool| if b { "yes" } else { "no" }.to_owned();
    BTreeMap::from([
        ("name", s(r, "name")),
        ("target", s(r, "target")),
        ("max_limit", s(r, "max_limit")),
        ("limit_at", s(r, "limit_at")),
        ("burst_limit", s(r, "burst_limit")),
        ("burst_threshold", s(r, "burst_threshold")),
        ("burst_time", s(r, "burst_time")),
        ("bucket_size", s(r, "bucket_size")),
        ("priority", s(r, "priority")),
        ("queue", s(r, "queue")),
        ("comment", s(r, "comment")),
        ("disabled", yes(r.get("disabled").and_then(Value::as_bool).unwrap_or(false))),
    ])
}

fn type_values(r: &Value) -> BTreeMap<&'static str, String> {
    let mut v = BTreeMap::from([("name", s(r, "name")), ("kind", s(r, "kind")), ("comment", s(r, "comment"))]);
    for k in [
        "pfifo_limit",
        "bfifo_limit",
        "pcq_rate",
        "pcq_classifier",
        "pcq_dst_address6_mask",
        "fq_codel_target",
        "fq_codel_interval",
        "cake_rtt",
    ] {
        if r.get(k).is_some() {
            v.insert(k, s(r, k));
        }
    }
    if let Some(b) = r.get("fq_codel_ecn").and_then(Value::as_bool) {
        v.insert("fq_codel_ecn", if b { "yes" } else { "no" }.to_owned());
    }
    v
}

impl QueuesPanel {
    fn simple_rows(&self) -> Vec<Value> {
        self.simple
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    fn row_of(&self, tab: Tab, key: &str) -> Option<Value> {
        let find = |v: &[Value], k: &str| v.iter().find(|r| s(r, k) == key).cloned();
        match tab {
            Tab::Simple => find(&self.simple_rows(), "id"),
            Tab::PerIp => find(&self.pcq, "id"),
            Tab::Types => find(&self.types, "name"),
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, tab: Tab, act: Act, ui: &Ui, rows: &[Row]) {
        let (cmds, id_param) = match tab {
            Tab::Simple => (&SIMPLE, "id"),
            Tab::PerIp => (&PER_IP, "id"),
            Tab::Types => (&TYPES, "id"),
        };
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let values = match tab {
                        Tab::Types => BTreeMap::from([("kind", "fq-codel".to_owned())]),
                        _ => BTreeMap::new(),
                    };
                    self.modal = Some((tab, Modal::open(app, None, values)));
                }
            }
            Act::Edit(k) => {
                if let Some((_, m)) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = self.row_of(tab, &k) {
                    match tab {
                        Tab::Simple if !r.get("dynamic").and_then(Value::as_bool).unwrap_or(false) => {
                            self.modal = Some((Tab::Simple, Modal::open(app, Some((k, s(&r, "name"))), simple_values(&r))));
                        }
                        // A per-IP rule is a simple queue: edit it there.
                        Tab::PerIp => {
                            if let Some(sr) = self.row_of(Tab::Simple, &k) {
                                self.modal = Some((Tab::Simple, Modal::open(app, Some((k, s(&sr, "name"))), simple_values(&sr))));
                            }
                        }
                        Tab::Types => {
                            self.modal = Some((Tab::Types, Modal::open(app, Some((k, s(&r, "name"))), type_values(&r))));
                        }
                        _ => {}
                    }
                }
            }
            Act::Remove(keys) => {
                for k in keys {
                    app.run(cmds.remove, json!({ id_param: k }));
                }
            }
            Act::Enable(keys) => {
                app.run("queue.simple.enable", json!({ "id": keys }));
            }
            Act::Disable(keys) => {
                app.run("queue.simple.disable", json!({ "id": keys }));
            }
            Act::Comment(keys) => {
                let text = keys.first().and_then(|k| self.row_of(tab, k)).map(|r| s(&r, "comment")).unwrap_or_default();
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.note = Some(NoteDialog {
                    id: app.next_dialog,
                    tab,
                    keys,
                    text,
                    status: Status::default(),
                });
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| self.row_of(tab, k)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                let add = if tab == Tab::Types { TYPES.add } else { SIMPLE.add };
                ui.ctx().copy_text(list::copy_commands(app, add, &refs, syntax));
            }
        }
    }

    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, help) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                if crate::help::info_button(ui, egui::Id::unique(("queues-tab-help", help)), tr_in(SCOPE, l, label)).clicked() {
                    self.help = Some(HelpView::new(help, tr_in(SCOPE, l, label)));
                }
            }
        });
    }

    fn simple_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.simple_rows();
        let running = self.simple.get("running").and_then(Value::as_bool).unwrap_or(false);
        let note = self.simple.get("note").and_then(Value::as_str).map(str::to_owned);
        let shown: Vec<&Value> = all.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| simple_row(r)).collect();
        let selection = self.simple_table.selection(&rows);
        let picked: Vec<Item> = shown.iter().filter(|r| selection.contains(&s(r, "id"))).map(|r| Item::of(r, "id", DYNAMIC)).collect();
        let tools = Tools::new(&app.can(), &SIMPLE, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, SIMPLE_TABLE, &tools, &selection, l);
            ui.separator();
            self.filters.chips(
                ui,
                "origin",
                &[("fixed", "fixed"), ("pppoe", "PPPoE"), ("ipoe", "IPoE"), ("dhcp-lease", "DHCP lease"), ("dhcp-network", "DHCP network")],
                l,
            );
            table::find_field(ui, SIMPLE_TABLE, &mut self.simple_table);
        });
        if !running && !all.is_empty() {
            ui.horizontal(|ui| {
                let text = note.unwrap_or_else(|| "no data plane shapes these queues here".to_owned());
                ui.label(egui::RichText::new(text.as_str()).color(ui.visuals().warn_fg_color));
            });
        }
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = 2.0 * ui.spacing().interact_size.y + 8.0;
        let out = table::show(ui, SIMPLE_TABLE, footer_h, &mut self.simple_table, &SIMPLE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let picked: Vec<Item> = all.iter().filter(|r| sel.contains(&s(r, "id"))).map(|r| Item::of(r, "id", DYNAMIC)).collect();
                let tools = Tools::new(&app.can, &SIMPLE, &picked);
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, "New Simple Queue…", tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = SIMPLE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        act = act.or_else(|| list::from_shortcut(out.shortcut, &tools, &selection)).or_else(|| out.opened.or(out.comment).map(Act::Edit));
        // The selected queue's warnings, in full.
        if let Some(r) = shown.iter().find(|r| selection.first().is_some_and(|k| *k == s(r, "id"))) {
            for w in r.get("warnings").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                ui.label(egui::RichText::new(w).color(ui.visuals().warn_fg_color));
            }
        }
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "queues", chip::neutral_tone(&v)),
                (list::count(&all, "origin", "fixed"), "fixed", chip::neutral_tone(&v)),
                (all.len() - list::count(&all, "origin", "fixed"), "dynamic", chip::BLUE.tone(&v)),
                (list::count(&all, "disabled", "true"), "disabled", chip::neutral_tone(&v)),
                (all.iter().filter(|r| r.get("warnings").and_then(Value::as_array).is_some_and(|w| !w.is_empty())).count(), "with warnings", chip::AMBER.tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, Tab::Simple, a, ui, &rows);
        }
    }

    fn pcq_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.pcq.clone();
        let rows: Vec<Row> = all.iter().map(pcq_row).collect();
        let selection = self.pcq_table.selection(&rows);
        let picked: Vec<Item> = all.iter().filter(|r| selection.contains(&s(r, "id"))).map(|r| Item::of(r, "id", DYNAMIC)).collect();
        let tools = Tools::new(&app.can(), &PER_IP, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, PCQ_TABLE, &tools, &selection, l);
            table::find_field(ui, PCQ_TABLE, &mut self.pcq_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, PCQ_TABLE, footer_h, &mut self.pcq_table, &PCQ_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, "New Per-IP Limit…", tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = PCQ_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        act = act.or_else(|| list::from_shortcut(out.shortcut, &tools, &selection)).or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(ui, &[(all.len(), "per-IP limits", chip::neutral_tone(&v))], l);
        if let Some(a) = act {
            self.act(app, Tab::PerIp, a, ui, &rows);
        }
    }

    fn types_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.types.clone();
        let rows: Vec<Row> = all.iter().map(type_row).collect();
        let selection = self.types_table.selection(&rows);
        let picked: Vec<Item> = all
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| {
                let mut it = Item::of(r, "name", BUILTIN);
                if r.get("builtin").and_then(Value::as_bool).unwrap_or(false) {
                    it.fixed = Some(BUILTIN.to_owned());
                }
                it
            })
            .collect();
        let mut tools = Tools::new(&app.can(), &TYPES, &picked);
        // Types have no "disabled".
        tools.enable = Err("Queue types are always on".into());
        tools.disable = Err("Queue types are always on".into());
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TYPES_TABLE, &tools, &selection, l);
            table::find_field(ui, TYPES_TABLE, &mut self.types_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, TYPES_TABLE, footer_h, &mut self.types_table, &TYPE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, "New Queue Type…", tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = TYPE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        act = act.or_else(|| list::from_shortcut(out.shortcut, &tools, &selection)).or_else(|| out.opened.map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "types", chip::neutral_tone(&v)),
                (list::count(&all, "builtin", "true"), "built-in", chip::neutral_tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, Tab::Types, a, ui, &rows);
        }
    }

    fn note_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.note.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let title = if d.keys.len() == 1 { "Comment".to_owned() } else { format!("Comment ({} items)", d.keys.len()) };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: false,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let set = if d.tab == Tab::Types { "queue.type.set" } else { "queue.simple.set" };
        let can = app.can();
        let mut text = d.text.clone();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("queues-note").num_columns(2).show(ui, |ui| {
                ui.label("Comment");
                ui.add(TextEdit::multiline(&mut text).id(dialog::field_id(f.window(), "comment")).desired_rows(3));
                ui.end_row();
            });
            Footer::<()>::edit(false, can.check(set))
        });
        d.text = text;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let steps: Vec<Value> = d
                    .keys
                    .iter()
                    .map(|k| json!({"command": set, "params": {"id": k, "comment": d.text.trim()}}))
                    .collect();
                d.status.close_on_success = true;
                d.status.sent();
                app.run_steps(steps, crate::panel::then(NAME, NoteReply(d.id)));
            }
            _ => {}
        }
        self.note = Some(d);
    }
}

impl PanelState for QueuesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let q = |key, command| Query { key, command, params: json!({}) };
        if app.has_command("queue.simple.list") {
            out.push(q("simple", "queue.simple.list"));
        }
        if self.tab == Tab::PerIp && app.has_command("queue.per-ip.list") {
            out.push(q("pcq", "queue.per-ip.list"));
        }
        // The modal's Queue Type field and the types tab both want them.
        if app.has_command("queue.type.list") {
            out.push(q("types", "queue.type.list"));
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            list_modal::PREVIEW => {
                if let Some((_, m)) = &mut self.modal {
                    m.arrived(value);
                }
            }
            "simple" => self.simple = value,
            "pcq" => self.pcq = value.as_array().cloned().unwrap_or_default(),
            "types" => self.types = value.as_array().cloned().unwrap_or_default(),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Simple => self.simple_tab(app, ui),
            Tab::PerIp => self.pcq_tab(app, ui),
            Tab::Types => self.types_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some((tab, m)) = &mut self.modal {
            let spec = match tab {
                Tab::Simple => &SIMPLE_SPEC,
                Tab::PerIp => &PCQ_SPEC,
                Tab::Types => &TYPE_SPEC,
            };
            let open = m.show(app, ctx, area, spec, &|p| match p {
                "kind" => ["pfifo", "bfifo", "pcq", "fq-codel", "cake"].iter().map(|s| (*s).to_owned()).collect(),
                "pcq_classifier" => vec!["dst-address".to_owned(), "src-address".to_owned()],
                _ => Vec::new(),
            });
            if !open {
                self.modal = None;
            }
        }
        self.note_dialog(app, ctx, area);
        crate::help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        if let Some(r) = then.downcast_ref::<NoteReply>()
            && let Some(d) = self.note.as_mut().filter(|d| d.id == r.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.note = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        false
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(SIMPLE_TABLE, &self.simple_table), (PCQ_TABLE, &self.pcq_table), (TYPES_TABLE, &self.types_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(SIMPLE_TABLE, &mut self.simple_table), (PCQ_TABLE, &mut self.pcq_table), (TYPES_TABLE, &mut self.types_table)]
    }
}

//! IP › Firewall XDP (G2.5a): the filter that runs in the NIC driver.
//! Tabs Interfaces (where it runs, how it is attached, packets per second
//! passed and dropped by reason), Filter (block and allow lists, rate
//! limit, malformed and TCP flags) and Top Sources (the most dropped
//! sources). Every label has its ⓘ (G0.15). `ip.firewall.xdp.*` decides;
//! this only shows and sends. A panel.

use egui::{Grid, Id, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win, human_bytes};

const NAME: &str = "xdp";
pub(crate) const WIN: &str = "xdp";
const TABLE: &str = "xdp-interfaces";
const TOP_TABLE: &str = "xdp-top";
const LIST: &str = "ip.firewall.xdp.interface.list";
const PRINT: &str = "ip.firewall.xdp.print";
const TOP: &str = "ip.firewall.xdp.top";
const ADD: &str = "ip.firewall.xdp.interface.add";
const SET_IF: &str = "ip.firewall.xdp.interface.set";
const REMOVE: &str = "ip.firewall.xdp.interface.remove";
const SET: &str = "ip.firewall.xdp.set";
const RESET: &str = "ip.firewall.xdp.reset-counters";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "Firewall XDP",
        size: [1000.0, 440.0],
        escape: true,
    }],
    new: || Box::new(XdpPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Interfaces,
    Filter,
    Top,
}

const TABS: [(Tab, &str); 3] = [
    (Tab::Interfaces, "Interfaces"),
    (Tab::Filter, "Filter"),
    (Tab::Top, "Top Sources"),
];

const COLUMNS: [table::Column; 12] = [
    col("Interface"),
    col("Mode"),
    col("Active"),
    num("Pass pps"),
    num("Fast NAT pps"),
    num("Drop pps"),
    num("Blocked"),
    num("Rate Limit"),
    num("Malformed"),
    num("TCP Flags"),
    col("Note"),
    comment(),
];

const TOP_COLUMNS: [table::Column; 6] = [
    col("Address"),
    num("Packets"),
    num("Bytes"),
    col("Reason"),
    col("List"),
    num("Last Seen"),
];

/// The labels above the Interfaces table with their ⓘ: (label, help key).
const LEGEND: [(&str, &str); 9] = [
    ("Mode", "xdp.mode"),
    ("Active", "xdp.active"),
    ("Pass pps", "xdp.pass"),
    ("Drop pps", "xdp.drop"),
    ("Blocked", "xdp.blocked"),
    ("Rate Limit", "xdp.rate-limit"),
    ("Malformed", "xdp.malformed"),
    ("TCP Flags", "xdp.tcp-flags"),
    ("Fast NAT pps", "xdp.fast_nat"),
];

/// Every explanation the window opens (the tests check both languages).
#[cfg(test)]
pub(crate) const HELP_KEYS: [&str; 16] = [
    "xdp",
    "xdp.mode",
    "xdp.active",
    "xdp.pass",
    "xdp.drop",
    "xdp.blocked",
    "xdp.rate-limit",
    "xdp.malformed",
    "xdp.tcp-flags",
    "xdp.block_lists",
    "xdp.allow_lists",
    "xdp.rate_limit",
    "xdp.rate_burst",
    "xdp.top",
    "xdp.unavailable",
    "xdp.fast_nat",
];

/// The Filter form's text fields: (param, label, hint, help key).
const FILTER_TEXT: [(&str, &str, &str, &str); 4] = [
    ("block_lists", "Block Lists", "bogons, attackers", "xdp.block_lists"),
    ("allow_lists", "Allow Lists", "noc, bgp-peers", "xdp.allow_lists"),
    ("rate_limit", "Rate Limit (pps per source)", "0 = off", "xdp.rate_limit"),
    ("rate_burst", "Burst (packets)", "0 = one second's worth", "xdp.rate_burst"),
];

/// The Filter form's yes/no fields: (param, label, help key).
const FILTER_FLAGS: [(&str, &str, &str); 3] = [
    ("drop_malformed", "Drop Malformed", "xdp.malformed"),
    ("drop_invalid_tcp_flags", "Drop Invalid TCP Flags", "xdp.tcp-flags"),
    ("fast_nat", "CGNAT Fast Path", "xdp.fast_nat"),
];

#[derive(Default)]
pub(crate) struct XdpPanel {
    pub(crate) tab: Tab,
    pub(crate) rows: Vec<Value>,
    pub(crate) filter: Value,
    pub(crate) top: Vec<Value>,
    table: TableState,
    top_table: TableState,
    /// The Filter form: text values by param (4), flags (2), and what
    /// they were when loaded (to send only the changes).
    pub(crate) form: Option<FilterForm>,
    pub(crate) dialog: Option<IfaceDialog>,
    pub(crate) help: Option<HelpView>,
    /// The last Filter apply: warnings or the error.
    pub(crate) notice: Option<(bool, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FilterForm {
    pub(crate) text: [String; 4],
    pub(crate) flags: [bool; 3],
}

pub(crate) struct IfaceDialog {
    id: u64,
    /// Editing this interface; `None`: adding.
    item: Option<String>,
    pub(crate) interface: String,
    pub(crate) mode: String,
    disabled: bool,
    comment: String,
    orig: (String, bool, String),
    status: Status,
}

enum Reply {
    Dialog(u64),
    Filter,
    Other,
}

fn num_of(v: &Value, path: &[&str]) -> u64 {
    path.iter()
        .try_fold(v, |v, k| v.get(*k))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// 1234567 → "1.2 M" (packet counts and rates).
pub(crate) fn count(n: u64) -> String {
    match n {
        0..1_000 => n.to_string(),
        1_000..1_000_000 => format!("{:.1} k", n as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} M", n as f64 / 1e6),
        _ => format!("{:.1} G", n as f64 / 1e9),
    }
}

/// The text of a list field: `["a","b"]` → "a, b".
fn lists_text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

pub(crate) fn row(r: &Value) -> Row {
    let active = text(r, "active");
    let disabled = r.get("disabled").and_then(Value::as_bool) == Some(true);
    let (label, kind) = match active.as_str() {
        "native" => ("native", Kind::Green),
        "generic" => ("generic", Kind::Amber),
        _ if disabled => ("disabled", Kind::Neutral),
        _ => ("off", Kind::Red),
    };
    let c = |reason: &str| count(num_of(r, &["counters", reason, "packets"]));
    Row {
        key: text(r, "interface"),
        cells: vec![
            text(r, "interface"),
            text(r, "mode"),
            chip::cell("", &[(label, kind)]),
            count(num_of(r, &["pass_pps"])),
            count(num_of(r, &["fast_nat_pps"])),
            count(num_of(r, &["drop_pps"])),
            c("blocked"),
            c("rate-limit"),
            c("malformed"),
            c("tcp-flags"),
            text(r, "note"),
            text(r, "comment"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

fn top_row(r: &Value) -> Row {
    let reason = text(r, "reason");
    let list = text(r, "list");
    let mut chips = vec![(reason.as_str(), Kind::Red)];
    if reason == "rate-limit" {
        chips = vec![(reason.as_str(), Kind::Amber)];
    }
    let last = num_of(r, &["last_secs"]);
    Row {
        key: text(r, "address"),
        cells: vec![
            text(r, "address"),
            count(num_of(r, &["packets"])),
            human_bytes(num_of(r, &["bytes"])),
            chip::cell("", &chips),
            if list.is_empty() {
                String::new()
            } else {
                chip::cell("", &[(&list, Kind::Hashed(chip::name_hue(&list)))])
            },
            format!("{last} s"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl XdpPanel {
    fn info(&mut self, ui: &mut Ui, l: Lang, label: &'static str, key: &'static str) {
        if help::info_button(ui, Id::unique(("xdp-help", key, label)), tr(l, label)).clicked() {
            self.help = Some(HelpView::new(key, tr(l, label)));
        }
    }

    fn label(&mut self, ui: &mut Ui, l: Lang, label: &'static str, key: &'static str) {
        ui.horizontal(|ui| {
            ui.label(tr(l, label));
            self.info(ui, l, label, key);
        });
    }

    pub(crate) fn form_of(filter: &Value) -> FilterForm {
        FilterForm {
            text: [
                lists_text(filter, "block_lists"),
                lists_text(filter, "allow_lists"),
                num_of(filter, &["rate_limit"]).to_string(),
                num_of(filter, &["rate_burst"]).to_string(),
            ],
            flags: FILTER_FLAGS.map(|(k, ..)| filter.get(k).and_then(Value::as_bool) == Some(true)),
        }
    }

    fn interfaces_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows: Vec<Row> = self.rows.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let can = app.can();
        let mut new = false;
        let mut remove = false;
        ui.horizontal(|ui| {
            new = table::tool(ui, TABLE, Icon::Add, tr(l, "Add"), can.check(ADD)).clicked();
            let picked = if selection.is_empty() {
                Err(tr(l, "Select an interface first").to_owned())
            } else {
                Ok(())
            };
            remove = table::tool(ui, TABLE, Icon::Remove, tr(l, "Remove"), can.and(REMOVE, picked))
                .clicked();
            if ui
                .add_enabled(can.check(RESET).is_ok(), egui::Button::new(tr(l, "Reset Counters")))
                .clicked()
            {
                app.run_then(RESET, json!({}), crate::panel::then(NAME, Reply::Other));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.horizontal_wrapped(|ui| {
            for (label, key) in LEGEND {
                ui.weak(tr(l, label));
                self.info(ui, l, label, key);
                ui.add_space(6.0);
            }
        });
        ui.separator();
        let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, tr(l, "Add XDP Interface…"), can.check(ADD))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for k in &selection {
                app.run(REMOVE, json!({ "interface": k }));
            }
        }
        let key = out.opened.or(out.comment).or_else(|| {
            matches!(out.shortcut, Some(Shortcut::Open))
                .then(|| selection.first().cloned())
                .flatten()
        });
        let opened = key.and_then(|k| self.rows.iter().find(|r| text(r, "interface") == k).cloned());
        if (new || opened.is_some()) && self.dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let (interface, mode, disabled, comment) = match &opened {
                Some(r) => (
                    text(r, "interface"),
                    text(r, "mode"),
                    r.get("disabled").and_then(Value::as_bool) == Some(true),
                    text(r, "comment"),
                ),
                None => {
                    let used: Vec<String> = self.rows.iter().map(|r| text(r, "interface")).collect();
                    let free = app
                        .interface_names(Some("ether"))
                        .into_iter()
                        .find(|n| !used.contains(n))
                        .unwrap_or_default();
                    (free, "auto".to_owned(), false, String::new())
                }
            };
            self.dialog = Some(IfaceDialog {
                id: app.next_dialog,
                item: opened.as_ref().map(|r| text(r, "interface")),
                orig: (mode.clone(), disabled, comment.clone()),
                interface,
                mode,
                disabled,
                comment,
                status: Status::default(),
            });
        }
    }

    fn filter_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let loaded = Self::form_of(&self.filter);
        let mut form = self.form.take().unwrap_or_else(|| loaded.clone());
        Grid::new("xdp-filter")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                for ((_, label, hint, key), v) in FILTER_TEXT.iter().zip(form.text.iter_mut()) {
                    self.label(ui, l, label, key);
                    ui.add(TextEdit::singleline(v).hint_text(tr(l, hint)).desired_width(320.0));
                    ui.end_row();
                }
                for ((_, label, key), on) in FILTER_FLAGS.iter().zip(form.flags.iter_mut()) {
                    self.label(ui, l, label, key);
                    ui.checkbox(on, "");
                    ui.end_row();
                }
            });
        // The lists named, with their entry counts, and the tries' size.
        ui.horizontal_wrapped(|ui| {
            let lists = self.filter.get("lists").and_then(Value::as_array).cloned().unwrap_or_default();
            for li in &lists {
                let name = text(li, "name");
                let n = num_of(li, &["entries"]);
                let tone = Kind::Hashed(chip::name_hue(&name)).tone(ui.visuals());
                chip::chip(ui, &format!("{name} {}", count(n)), tone);
            }
            ui.weak(format!(
                "{}: {} / {}: {}",
                tr(l, "Blocked prefixes"),
                num_of(&self.filter, &["block_prefixes"]),
                tr(l, "Allowed prefixes"),
                num_of(&self.filter, &["allow_prefixes"]),
            ));
        });
        // The CGNAT fast path: what the service reports, and why packets
        // of carried connections still went to the kernel.
        if self.filter.get("fast_nat").and_then(Value::as_bool) == Some(true) {
            let st = self.filter.get("fast_nat_status").cloned().unwrap_or(Value::Null);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(tr(l, "CGNAT Fast Path")).strong());
                self.info(ui, l, "CGNAT Fast Path", "xdp.fast_nat");
                ui.weak(format!(
                    "{}: {} · {}: {} · {}: {}",
                    tr(l, "connections"),
                    num_of(&st, &["carried"]),
                    tr(l, "flow directions"),
                    num_of(&self.filter, &["fast_nat_flows"]),
                    tr(l, "timeouts renewed"),
                    num_of(&st, &["renewed"]),
                ));
                for k in ["idle", "last_error"] {
                    let t = text(&st, k);
                    if !t.is_empty() {
                        let tone = Kind::Amber.tone(ui.visuals());
                        chip::chip(ui, &t, tone);
                    }
                }
            });
            if let Some(m) = self.filter.get("fast_nat_misses").and_then(Value::as_array) {
                ui.horizontal_wrapped(|ui| {
                    ui.weak(tr(l, "Sent to the kernel:"));
                    for row in m {
                        if let (Some(why), Some(n)) = (
                            row.get(0).and_then(Value::as_str),
                            row.get(1).and_then(Value::as_u64),
                        ) {
                            let tone = Kind::Neutral.tone(ui.visuals());
                            chip::chip(ui, &format!("{why} {}", count(n)), tone);
                        }
                    }
                });
            }
        }
        ui.separator();
        let dirty = form != loaded;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(dirty && app.can().check(SET).is_ok(), egui::Button::new(tr(l, "Apply")))
                .clicked()
            {
                let mut p = Map::new();
                for (((key, ..), v), old) in FILTER_TEXT.iter().zip(&form.text).zip(&loaded.text) {
                    if v == old {
                        continue;
                    }
                    let value = if key.ends_with("_lists") {
                        json!(v.trim())
                    } else {
                        match v.trim().parse::<u64>() {
                            Ok(n) => json!(n),
                            Err(_) => json!(v.trim()),
                        }
                    };
                    p.insert((*key).into(), value);
                }
                for (((key, ..), on), old) in FILTER_FLAGS.iter().zip(&form.flags).zip(&loaded.flags) {
                    if on != old {
                        p.insert((*key).into(), json!(on));
                    }
                }
                app.run_then(SET, Value::Object(p), crate::panel::then(NAME, Reply::Filter));
            }
            if ui.add_enabled(dirty, egui::Button::new(tr(l, "Cancel"))).clicked() {
                form = loaded.clone();
            }
        });
        if let Some((ok, msg)) = &self.notice {
            let color = if *ok {
                ui.visuals().warn_fg_color
            } else {
                ui.visuals().error_fg_color
            };
            ui.label(RichText::new(msg).color(color));
        }
        // Keep the edits only while they differ from the router's.
        self.form = (form != loaded).then_some(form);
    }

    fn top_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.weak(tr(l, "Most dropped sources"));
            self.info(ui, l, "Top Sources", "xdp.top");
        });
        ui.separator();
        let rows: Vec<Row> = self.top.iter().map(top_row).collect();
        let _ = table::show(ui, TOP_TABLE, 0.0, &mut self.top_table, &TOP_COLUMNS, &rows, |_, _| {});
    }
}

impl PanelState for XdpPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !(app.open.contains(&Win::Panel(WIN)) && app.has_command(LIST)) {
            return Vec::new();
        }
        let mut q = vec![
            Query {
                key: "list",
                command: LIST,
                params: Value::Null,
            },
            Query {
                key: "print",
                command: PRINT,
                params: Value::Null,
            },
        ];
        if self.tab == Tab::Top {
            q.push(Query {
                key: "top",
                command: TOP,
                params: json!({"count": 50}),
            });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match (key, value) {
            ("list", Value::Array(a)) => self.rows = a,
            ("top", Value::Array(a)) => self.top = a,
            ("print", v) => self.filter = v,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        if !app.has_command(LIST) {
            ui.weak(tr(l, "This router has no XDP filter yet: update corerouter-daemon."));
            return;
        }
        ui.horizontal(|ui| {
            for (tab, label) in TABS {
                if ui.selectable_label(self.tab == tab, tr(l, label)).clicked() && self.tab != tab {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
            }
            self.info(ui, l, "Firewall XDP", "xdp");
            if self.filter.get("available").and_then(Value::as_bool) == Some(false) {
                let tone = Kind::Red.tone(ui.visuals());
                chip::chip(ui, tr(l, "unavailable"), tone);
                ui.weak(text(&self.filter, "unavailable"));
                self.info(ui, l, "unavailable", "xdp.unavailable");
            }
        });
        ui.separator();
        match self.tab {
            Tab::Interfaces => self.interfaces_tab(app, ui),
            Tab::Filter => self.filter_tab(app, ui),
            Tab::Top => self.top_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let l = app.lang.labels;
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(n) => format!("XDP <{n}>"),
            None => tr(l, "New XDP Interface").to_owned(),
        };
        let cmd = if d.item.is_some() { SET_IF } else { ADD };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: (d.mode.clone(), d.disabled, d.comment.clone()) != d.orig || d.item.is_none(),
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let names = app.interface_names(None);
        let mut help_key = None;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, _f| {
            Grid::new("xdp-iface-fields")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(tr(l, "Interface"));
                    if d.item.is_some() {
                        ui.label(&d.interface);
                    } else {
                        egui::ComboBox::from_id_salt(("xdp-iface", d.id))
                            .selected_text(d.interface.clone())
                            .show_ui(ui, |ui| {
                                for n in &names {
                                    ui.selectable_value(&mut d.interface, n.clone(), n);
                                }
                            });
                    }
                    ui.end_row();
                    ui.horizontal(|ui| {
                        ui.label(tr(l, "Mode"));
                        if help::info_button(ui, Id::unique(("xdp-dlg-help", d.id)), tr(l, "Mode")).clicked() {
                            help_key = Some("xdp.mode");
                        }
                    });
                    egui::ComboBox::from_id_salt(("xdp-mode", d.id))
                        .selected_text(d.mode.clone())
                        .show_ui(ui, |ui| {
                            for m in ["auto", "native", "generic"] {
                                ui.selectable_value(&mut d.mode, m.to_owned(), m);
                            }
                        });
                    ui.end_row();
                    ui.label(tr(l, "Disabled"));
                    ui.checkbox(&mut d.disabled, "");
                    ui.end_row();
                    ui.label(tr(l, "Comment"));
                    ui.text_edit_singleline(&mut d.comment);
                    ui.end_row();
                });
            Footer::<()>::edit(false, can.check(cmd))
        });
        if let Some(k) = help_key {
            self.help = Some(HelpView::new(k, tr(l, "Mode")));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = Map::new();
                p.insert("interface".into(), json!(d.interface));
                p.insert("mode".into(), json!(d.mode));
                p.insert("disabled".into(), json!(d.disabled));
                if !d.comment.is_empty() || d.item.is_some() {
                    p.insert("comment".into(), json!(d.comment));
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, Value::Object(p), crate::panel::then(NAME, Reply::Dialog(d.id)));
            }
            _ => {}
        }
        self.dialog = Some(d);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        match *r {
            Reply::Dialog(id) => {
                if let Some(d) = self.dialog.as_mut().filter(|d| d.id == id)
                    && d.status.replied(result)
                {
                    app.floats.forget(dialog_id(d.id));
                    self.dialog = None;
                }
            }
            Reply::Filter => {
                self.notice = match result {
                    Ok(v) => {
                        self.form = None;
                        let w: Vec<String> = v
                            .get("warnings")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                            .unwrap_or_default();
                        (!w.is_empty()).then(|| (true, w.join("\n")))
                    }
                    Err(e) => Some((false, e.clone())),
                };
            }
            Reply::Other => {}
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Top => self.top_table.escape(),
            _ => self.table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (TOP_TABLE, &self.top_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table), (TOP_TABLE, &mut self.top_table)]
    }
}

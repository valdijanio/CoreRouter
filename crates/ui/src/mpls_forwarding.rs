//! MPLS › Forwarding Table (G3.5), RouterOS v7 `/mpls forwarding-table` in
//! the approved mockup: one line per FEC (and per label entry no FEC
//! explains) with the incoming and outgoing labels (`implicit-null (pop)`),
//! the next hop, IGP sync as a chip and, for a FEC without an outgoing
//! label, **why**. The static LSPs (`/mpls static`) are added and removed
//! here too. `mpls.forwarding-table.page` pages and explains in the engine.

use std::collections::BTreeMap;

use egui::{Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "mpls-forwarding";
pub(crate) const WIN: &str = "mpls-forwarding";
const SCOPE: &str = "mpls";
const TABLE: &str = "mpls-forwarding";
/// Rows asked per refresh: the search narrows the rest.
const LIMIT: u32 = 500;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "MPLS",
        title: "Forwarding Table",
        size: [1000.0, 480.0],
        escape: true,
    }],
    new: || Box::<ForwardingPanel>::default(),
};

const FIELDS: &[Field] = &[
    Field { param: "label", label: "In Label", help: "mpls.static.label", input: Input::Text("above the dynamic range"), edit: false },
    Field { param: "nexthop", label: "Next Hop", help: "mpls.static.nexthop", input: Input::Text("10.0.12.2"), edit: true },
    Field { param: "interface", label: "Interface", help: "mpls.static.interface", input: Input::Choice, edit: true },
    Field { param: "out_labels", label: "Out Labels", help: "mpls.static.out_labels", input: Input::Text("empty: pop (implicit-null)"), edit: true },
    Field { param: "disabled", label: "Disabled", help: "mpls.disabled", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Static LSP",
    edit_title: "Static LSP",
    help: "mpls.static",
    fields: FIELDS,
    preview: "mpls.static.preview",
};

const COLUMNS: [table::Column; 8] = [
    col("FEC").help("mpls.fwd.fec"),
    col("In Label").help("mpls.fwd.in_label"),
    col("Out Label").help("mpls.fwd.out_label"),
    col("Next Hop").help("mpls.fwd.nexthop"),
    col("Interface").help("mpls.fwd.interface"),
    col("Sync IGP").help("mpls.sync"),
    col("Origin").help("mpls.fwd.origin"),
    col("Reason").help("mpls.fwd.reason"),
];

#[derive(Default)]
pub(crate) struct ForwardingPanel {
    pub(crate) page: Value,
    pub(crate) statics: Vec<Value>,
    pub(crate) ifaces: Vec<String>,
    pub(crate) find: String,
    pub(crate) unlabeled: bool,
    table: TableState,
    modal: Option<Modal>,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn origin_kind(o: &str) -> Kind {
    match o {
        "ldp" => Kind::Green,
        "static" => Kind::Blue,
        _ => Kind::Neutral,
    }
}

/// The row's key: the FEC, or `label:<n>` for an entry without one.
fn key_of(r: &Value) -> String {
    match r.get("fec").and_then(Value::as_str) {
        Some(f) => f.to_owned(),
        None => format!("label:{}", s(r, "in_label")),
    }
}

/// A label with the RFC 3032 §2.1 name of a reserved value.
fn label_text(l: u64) -> String {
    match l {
        0 => "explicit-null".into(),
        2 => "ipv6-explicit-null".into(),
        3 => "implicit-null".into(),
        l => l.to_string(),
    }
}

pub(crate) fn row(r: &Value) -> Row {
    let out = s(r, "out_label");
    let out_cell = match r.get("mtu").and_then(Value::as_str) {
        // "MTU 1500 < 1504": the rest is the tooltip of the Reason cell.
        Some(m) => cell(&out, &[(m.split(':').next().unwrap_or(m), Kind::Red)]),
        None => out,
    };
    let sync = match s(r, "igp_sync").as_str() {
        "achieved" => cell("", &[("achieved", Kind::Green)]),
        "waiting" => cell("", &[("waiting for LDP", Kind::Amber)]),
        _ => String::new(),
    };
    let origin = s(r, "origin");
    let reason = match (r.get("reason").and_then(Value::as_str), r.get("mtu").and_then(Value::as_str)) {
        (Some(why), _) => why.to_owned(),
        (None, Some(m)) => m.to_owned(),
        _ => String::new(),
    };
    let in_label = r
        .get("in_label")
        .and_then(Value::as_u64)
        .map(label_text)
        .unwrap_or_else(|| "–".into());
    Row {
        key: key_of(r),
        cells: vec![
            r.get("fec").and_then(Value::as_str).unwrap_or("").to_owned(),
            in_label,
            out_cell,
            s(r, "nexthop"),
            s(r, "interface"),
            sync,
            cell("", &[(origin.as_str(), origin_kind(&origin))]),
            reason,
        ],
        dimmed: r.get("installed").and_then(Value::as_bool) == Some(false),
        section: false,
        tint: None,
    }
}

impl ForwardingPanel {
    fn info(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("mpls-fwd-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn banner(&mut self, app: &CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let p = self.page.clone();
        ui.horizontal_wrapped(|ui| {
            if p.get("available").and_then(Value::as_bool) == Some(false) {
                chip::chip(ui, tr_in(SCOPE, l, "no MPLS in the kernel"), chip::RED.tone(&v));
                ui.weak(s(&p, "why"));
                return;
            }
            let ldp = p.get("ldp").cloned().unwrap_or_default();
            if ldp.get("running").and_then(Value::as_bool) == Some(true) {
                if ldp.get("daemon").and_then(Value::as_bool) == Some(true) {
                    chip::chip(ui, "LDP", chip::GREEN.tone(&v));
                } else {
                    chip::chip(ui, tr_in(SCOPE, l, "LDP: no daemon"), chip::neutral_tone(&v));
                    ui.weak(tr_in(SCOPE, l, "The FECs come from FRR's ldpd (--frr); the kernel's labels are below."));
                }
            } else {
                chip::chip(ui, tr_in(SCOPE, l, "LDP off"), chip::neutral_tone(&v));
            }
            if let Some(e) = ldp.get("error").and_then(Value::as_str) {
                ui.colored_label(v.error_fg_color, e);
            }
            if let Some(n) = p.get("note").and_then(Value::as_str) {
                ui.weak(n);
            }
        });
    }

    fn toolbar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, selected: &[String]) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            if table::action(ui, tr_in(SCOPE, l, "+ Static LSP"), app.can().check("mpls.static.add")) && self.modal.is_none() {
                let mut values = BTreeMap::new();
                values.insert("disabled", "no".to_owned());
                self.modal = Some(Modal::open(app, None, values));
            }
            let statics: Vec<String> = selected
                .iter()
                .filter_map(|k| k.strip_prefix("label:"))
                .filter(|l| self.statics.iter().any(|r| s(r, "label") == *l))
                .map(str::to_owned)
                .collect();
            let can = if statics.is_empty() { Err("select a static LSP".to_owned()) } else { app.can().check("mpls.static.remove") };
            if table::action(ui, tr_in(SCOPE, l, "Remove"), can) {
                let steps: Vec<Value> = statics.iter().map(|k| json!({"command": "mpls.static.remove", "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            ui.separator();
            if ui.checkbox(&mut self.unlabeled, tr_in(SCOPE, l, "Without label")).changed() {
                app.cache.refreshed_at = None;
            }
            self.info(ui, l, "mpls.fwd.unlabeled", "Without label");
            ui.separator();
            let r = ui.add(egui::TextEdit::singleline(&mut self.find).hint_text(tr_in(SCOPE, l, "FEC, label, next hop…")).desired_width(180.0));
            if r.changed() {
                app.cache.refreshed_at = None;
            }
        });
    }

    fn edit(&mut self, app: &mut CoreRouterUi, key: &str) {
        let Some(label) = key.strip_prefix("label:") else { return };
        let Some(r) = self.statics.iter().find(|r| s(r, "label") == label).cloned() else { return };
        if self.modal.is_some() {
            return;
        }
        let mut v = BTreeMap::new();
        v.insert("label", label.to_owned());
        v.insert("nexthop", s(&r, "nexthop"));
        v.insert("interface", s(&r, "interface"));
        let out = r.get("out_labels").and_then(Value::as_array).map(|a| a.iter().map(value_text).collect::<Vec<_>>().join(" ")).unwrap_or_default();
        v.insert("out_labels", out);
        v.insert("disabled", if r.get("disabled").and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.to_owned());
        v.insert("comment", s(&r, "comment"));
        self.modal = Some(Modal::open(app, Some((label.to_owned(), label.to_owned())), v));
    }
}

impl PanelState for ForwardingPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut params = json!({"limit": LIMIT, "unlabeled": self.unlabeled});
        if !self.find.trim().is_empty()
            && let Some(o) = params.as_object_mut()
        {
            o.insert("find".into(), json!(self.find.trim()));
        }
        [
            ("page", "mpls.forwarding-table.page", params),
            ("statics", "mpls.static.list", json!({})),
            ("ifaces", "interface.list", json!({})),
        ]
        .into_iter()
        .filter(|(_, c, _)| app.has_command(c))
        .map(|(key, command, params)| Query { key, command, params })
        .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            "page" => self.page = value,
            "statics" => self.statics = value.as_array().cloned().unwrap_or_default(),
            "ifaces" => {
                self.ifaces = value.as_array().into_iter().flatten().map(|r| s(r, "name")).filter(|n| !n.is_empty()).collect();
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.banner(app, ui);
        ui.separator();
        let data: Vec<Value> = self.page.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
        let rows: Vec<Row> = data.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let picked: Vec<String> = selection.as_slice().to_vec();
        self.toolbar(app, ui, &picked);
        ui.separator();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 12.0;
        let mut open = None;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu
                && let Some(k) = sel.as_slice().first()
                && k.starts_with("label:")
                && table::action(ui, tr_in(SCOPE, l, "Edit Static LSP…"), Ok(()))
            {
                open = Some(k.clone());
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if let Some(k) = open.or(out.opened) {
            self.edit(app, &k);
        }
        let v = ui.visuals().clone();
        let sum = self.page.get("summary").cloned().unwrap_or_default();
        let n = |k: &str| sum.get(k).and_then(Value::as_u64).and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
        crate::list::footer(
            ui,
            &[
                (n("fecs"), "FECs", chip::neutral_tone(&v)),
                (n("labeled"), "with label", chip::GREEN.tone(&v)),
                (n("unlabeled"), "without label", chip::AMBER.tone(&v)),
                (n("static"), "static", chip::BLUE.tone(&v)),
                (n("mtu_warnings"), "MTU too small", chip::RED.tone(&v)),
                (n("labels"), "kernel labels", chip::neutral_tone(&v)),
            ],
            l,
        );
        let total = self.page.get("total").and_then(Value::as_u64).unwrap_or(0);
        if total > u64::from(LIMIT) {
            ui.weak(format!("{} {LIMIT} / {total}: {}", tr_in(SCOPE, l, "showing"), tr_in(SCOPE, l, "type in the search to narrow")));
        } else if data.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No label yet: LDP labels the IGP's routes once a neighbor is up; + Static LSP adds one by hand."));
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let ifaces = self.ifaces.clone();
        let options = move |p: &str| -> Vec<String> {
            if p == "interface" {
                std::iter::once(String::new()).chain(ifaces.iter().cloned()).collect()
            } else {
                Vec::new()
            }
        };
        if let Some(m) = &mut self.modal
            && !m.show(app, ctx, area, &SPEC, &options)
        {
            self.modal = None;
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table)]
    }
}

#[cfg(test)]
impl ForwardingPanel {
    /// Every explanation key the window uses (the test checks both languages).
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut k: Vec<&'static str> = vec!["menu.mpls-forwarding", SPEC.help, "mpls.fwd.unlabeled"];
        k.extend(FIELDS.iter().map(|f| f.help).filter(|h| !h.is_empty()));
        k.extend(COLUMNS.iter().map(|c| c.help).filter(|h| !h.is_empty()));
        k
    }
}

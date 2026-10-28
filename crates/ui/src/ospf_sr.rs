//! Routing › OSPF › Segment Routing (G3.4f): the SR switch with its
//! blocks (the modal previews what moves to labels, the MTU and the MPLS
//! input, with Safe Mode), this router's prefix SIDs (a list window,
//! G0.24), the SIDs the network announces with their labels, the SR
//! routers and the SID clashes. `routing.ospf.segment-routing.*` and
//! `routing.ospf.prefix-sid.*` decide; this only shows and sends.

use std::collections::BTreeMap;

use egui::Ui;
use serde_json::Value;

use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Cmds};
use crate::list_modal::{Field, Input, Modal, Spec};
use crate::ospf::{NAME, OspfPanel, SCOPE, WIN, What};
use crate::table::{self, Row, col, comment, num};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const SIDS: &str = "ospf-sr-sids";
pub(crate) const NET_SIDS: &str = "ospf-sr-network";
pub(crate) const NODES: &str = "ospf-sr-nodes";

pub(crate) const SID_CMDS: Cmds = Cmds {
    add: "routing.ospf.prefix-sid.add",
    remove: "routing.ospf.prefix-sid.remove",
    set: Some("routing.ospf.prefix-sid.set"),
    what: "prefix SIDs",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input, edit: bool) -> Field {
    Field { param, label, help, input, edit }
}

pub(crate) const SR_FIELDS: &[Field] = &[
    field("instance", "Instance", "ospf.sr.instance", Input::Choice, true),
    field("srgb", "SRGB", "ospf.sr.srgb", Input::Text("16000-23999"), true),
    field("srlb", "SRLB", "ospf.sr.srlb", Input::Text("15000-15999"), true),
    field("node_msd", "Node MSD", "ospf.sr.node_msd", Input::Text("8"), true),
    field("ti_lfa", "TI-LFA", "ospf.sr.ti_lfa", Input::Choice, true),
    field("auto_sid", "Loopback SIDs", "ospf.sr.auto_sid", Input::Check, true),
    field("disabled", "Disabled", "ospf.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

pub(crate) const SID_FIELDS: &[Field] = &[
    field("prefix", "Prefix", "ospf.sid.prefix", Input::Text("10.255.0.1/32"), false),
    field("interface", "Interface", "ospf.sid.interface", Input::Text("lo0"), false),
    field("index", "Index", "ospf.sid.index", Input::Text("auto"), true),
    field("behavior", "Behavior", "ospf.sid.behavior", Input::Choice, true),
    field("force", "Force", "ospf.sid.force", Input::Check, true),
    field("disabled", "Disabled", "ospf.disabled", Input::Check, true),
    field("comment", "Comment", "", Input::Text(""), true),
];

pub(crate) const SR_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "Segment Routing",
    edit_title: "Segment Routing",
    help: "ospf.sr",
    fields: SR_FIELDS,
    preview: "routing.ospf.segment-routing.check",
};

pub(crate) const SID_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Prefix SID",
    edit_title: "Prefix SID",
    help: "ospf.sid",
    fields: SID_FIELDS,
    preview: "routing.ospf.prefix-sid.check",
};

const SID_COLUMNS: [table::Column; 7] = [
    col("Prefix").help("ospf.sid.prefix"),
    col("Interface").help("ospf.sid.interface"),
    num("Index").help("ospf.sid.index"),
    num("Label").help("ospf.sid.label"),
    col("Behavior").help("ospf.sid.behavior"),
    col("Announced").help("ospf.sid.announced"),
    comment(),
];

const NET_COLUMNS: [table::Column; 8] = [
    col("Prefix").help("ospf.sid.prefix"),
    col("Router").help("ospf.sr.router"),
    num("Index").help("ospf.sid.index"),
    num("Label").help("ospf.sid.label"),
    num("In").help("ospf.sr.in_label"),
    col("Out").help("ospf.sr.out_label"),
    col("Interface").help("ospf.sid.interface"),
    col("Next Hop").help("ospf.sr.nexthop"),
];

const NODE_COLUMNS: [table::Column; 6] = [
    col("Router").help("ospf.sr.router"),
    col("SRGB").help("ospf.sr.srgb"),
    col("SRLB").help("ospf.sr.srlb"),
    num("MSD").help("ospf.sr.node_msd"),
    num("Prefix SIDs").help("ospf.sid.prefix"),
    num("Adjacency SIDs").help("ospf.sr.adjacencies"),
];

/// Which list the tab shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SrView {
    #[default]
    ThisRouter,
    Network,
    Routers,
}

const VIEWS: [(SrView, &str); 3] = [
    (SrView::ThisRouter, "This Router"),
    (SrView::Network, "Network SIDs"),
    (SrView::Routers, "SR Routers"),
];

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn dash(t: String) -> String {
    if t.is_empty() { "–".into() } else { t }
}

/// A row of this router's prefix SIDs.
pub(crate) fn sid_row(r: &Value) -> Row {
    let b = s(r, "behavior");
    let announced = flag(r, "announced");
    Row {
        key: s(r, "id"),
        cells: vec![
            s(r, "prefix"),
            dash(s(r, "interface")),
            s(r, "index"),
            dash(s(r, "label")),
            cell("", &[(b.as_str(), if b == "php" { Kind::Neutral } else { Kind::Blue })]),
            if announced { cell("", &[("yes", Kind::Green)]) } else { cell("", &[("no", Kind::Red)]) },
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// An out label as RouterOS writes it: 3 is the implicit null (pop).
fn out_label(r: &Value) -> String {
    match r.get("out_label").and_then(Value::as_u64) {
        None => "–".into(),
        Some(3) => "implicit-null (pop)".into(),
        Some(0) => "explicit-null".into(),
        Some(n) => n.to_string(),
    }
}

fn net_row(r: &Value) -> Row {
    let router = s(r, "router");
    let who = if flag(r, "own") {
        cell("", &[("this router", Kind::Green)])
    } else {
        router.clone()
    };
    Row {
        key: format!("{}|{}", s(r, "prefix"), router),
        cells: vec![
            s(r, "prefix"),
            who,
            s(r, "index"),
            dash(s(r, "label")),
            match r.get("in_label").and_then(Value::as_u64) {
                Some(0) | None => "–".into(),
                Some(n) => n.to_string(),
            },
            out_label(r),
            dash(s(r, "interface")),
            dash(s(r, "nexthop")),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn node_row(r: &Value) -> Row {
    let srgb = s(r, "srgb");
    let srgb_cell = if flag(r, "same_srgb") {
        srgb
    } else {
        cell("", &[(srgb.as_str(), Kind::Amber)])
    };
    let router = s(r, "router_id");
    Row {
        key: router.clone(),
        cells: vec![
            if flag(r, "me") { cell("", &[(router.as_str(), Kind::Green)]) } else { router.clone() },
            srgb_cell,
            s(r, "srlb"),
            dash(s(r, "msd")),
            s(r, "prefixes"),
            s(r, "adjacencies"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The modal of the SR settings: new, or the current ones.
pub(crate) fn open_settings(p: &mut OspfPanel, app: &mut CoreRouterUi, off: bool) {
    if let Some((_, m)) = &mut p.modal {
        m.status.bring_to_front();
        return;
    }
    let sr = &p.sr;
    let mut values = BTreeMap::new();
    let configured = flag(sr, "configured");
    for f in SR_FIELDS {
        let v = match f.param {
            "auto_sid" => if configured { "no" } else { "yes" }.to_owned(),
            "ti_lfa" => Some(s(sr, "ti_lfa")).filter(|t| !t.is_empty()).unwrap_or_else(|| "off".to_owned()),
            "disabled" => if off || flag(sr, "disabled") { "yes" } else { "no" }.to_owned(),
            k => s(sr, k),
        };
        values.insert(f.param, v);
    }
    if !configured
        && let Some(first) = p.instances.iter().find(|i| s(i, "version") == "2")
    {
        values.insert("instance", s(first, "name"));
    }
    let item = configured.then(|| (s(sr, "instance"), s(sr, "instance")));
    p.modal = Some((What::Sr, Modal::open(app, item, values)));
}

pub(crate) fn tab(p: &mut OspfPanel, app: &mut CoreRouterUi, ui: &mut Ui) {
    let l = app.lang.labels;
    let sr = p.sr.clone();
    let v = ui.visuals().clone();
    ui.horizontal_wrapped(|ui| {
        let available = sr.get("available").and_then(Value::as_bool).unwrap_or(true);
        let (state, tone) = if !available {
            ("unavailable", chip::RED.tone(&v))
        } else if flag(&sr, "active") {
            ("SR on", chip::GREEN.tone(&v))
        } else if flag(&sr, "configured") {
            ("SR disabled", chip::AMBER.tone(&v))
        } else {
            ("SR off", chip::neutral_tone(&v))
        };
        chip::chip(ui, tr_in(SCOPE, l, state), tone);
        if !available {
            ui.label(s(&sr, "why"));
        }
        if flag(&sr, "configured") {
            for (k, label) in [("instance", "Instance"), ("srgb", "SRGB"), ("srlb", "SRLB"), ("ldp_block", "LDP")] {
                let t = s(&sr, k);
                if !t.is_empty() {
                    ui.weak(tr_in(SCOPE, l, label));
                    ui.label(t);
                }
            }
            if help::info_button(ui, egui::Id::unique("ospf-sr-ldp-help"), tr_in(SCOPE, l, "LDP")).clicked() {
                p.help = Some(HelpView::new("ospf.sr.ldp_block", tr_in(SCOPE, l, "LDP")));
            }
        }
        ui.separator();
        let label = if flag(&sr, "configured") { "Settings…" } else { "Turn On…" };
        if ui.add_enabled(available, egui::Button::new(tr_in(SCOPE, l, label))).clicked() {
            open_settings(p, app, false);
        }
        if flag(&sr, "active") && ui.button(tr_in(SCOPE, l, "Turn Off…")).clicked() {
            open_settings(p, app, true);
        }
        if s(&sr, "source") == "virtual lab sample" {
            chip::chip(ui, tr_in(SCOPE, l, "virtual lab sample"), chip::AMBER.tone(&v));
        }
        if let Some(e) = sr.get("error").filter(|e| !e.is_null()) {
            ui.colored_label(v.error_fg_color, value_text(e));
        }
    });
    // Clashes and config problems first: they break forwarding.
    let conflicts = sr.get("conflicts").and_then(Value::as_array).cloned().unwrap_or_default();
    let issues = sr.get("issues").and_then(Value::as_array).cloned().unwrap_or_default();
    if !conflicts.is_empty() || !issues.is_empty() {
        egui::ScrollArea::vertical().id_salt("ospf-sr-conflicts").max_height(90.0).show(ui, |ui| {
            for c in &conflicts {
                ui.horizontal_wrapped(|ui| {
                    chip::chip(ui, tr_in(SCOPE, l, "conflict"), chip::RED.tone(&v));
                    ui.label(s(c, "detail"));
                });
            }
            for i in &issues {
                ui.horizontal_wrapped(|ui| {
                    chip::chip(ui, tr_in(SCOPE, l, "error"), chip::RED.tone(&v));
                    ui.label(value_text(i));
                });
            }
        });
        if help::info_button(ui, egui::Id::unique("ospf-sr-conflict-help"), tr_in(SCOPE, l, "conflict")).clicked() {
            p.help = Some(HelpView::new("ospf.sr.conflicts", tr_in(SCOPE, l, "conflict")));
        }
    }
    ui.horizontal(|ui| {
        for (view, label) in VIEWS {
            if ui.selectable_label(p.sr_view == view, tr_in(SCOPE, l, label)).clicked() {
                p.sr_view = view;
            }
        }
        if help::info_button(ui, egui::Id::unique("ospf-sr-views"), tr_in(SCOPE, l, "Segment Routing")).clicked() {
            p.help = Some(HelpView::new("ospf.sr.views", tr_in(SCOPE, l, "Segment Routing")));
        }
    });
    ui.separator();
    match p.sr_view {
        SrView::ThisRouter => {
            if flag(&sr, "configured") {
                p.list_tab(app, ui, What::PrefixSid, SIDS, &SID_COLUMNS, "id", "prefix SIDs");
            } else {
                ui.weak(tr_in(
                    SCOPE,
                    l,
                    "Segment Routing is off. Turn it on for the OSPFv2 instance: the preview shows what moves to labels before anything changes.",
                ));
            }
        }
        SrView::Network => {
            let data = sr.get("sids").and_then(Value::as_array).cloned().unwrap_or_default();
            let rows: Vec<Row> = data.iter().map(net_row).collect();
            ui.horizontal(|ui| table::find_field(ui, NET_SIDS, &mut p.sr_sid_table));
            let footer_h = ui.spacing().interact_size.y + 6.0;
            let out = table::show(ui, NET_SIDS, footer_h, &mut p.sr_sid_table, &NET_COLUMNS, &rows, |_, _| {});
            column_help(p, app, out.help, &NET_COLUMNS);
            let own = data.iter().filter(|r| flag(r, "own")).count();
            list::footer(ui, &[(data.len(), "SIDs", chip::neutral_tone(&v)), (own, "this router", chip::GREEN.tone(&v)), (conflicts.len(), "conflicts", chip::RED.tone(&v))], l);
        }
        SrView::Routers => {
            let data = sr.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
            let rows: Vec<Row> = data.iter().map(node_row).collect();
            ui.horizontal(|ui| table::find_field(ui, NODES, &mut p.sr_node_table));
            let footer_h = ui.spacing().interact_size.y + 6.0;
            let out = table::show(ui, NODES, footer_h, &mut p.sr_node_table, &NODE_COLUMNS, &rows, |_, _| {});
            column_help(p, app, out.help, &NODE_COLUMNS);
            let other = data.iter().filter(|r| !flag(r, "same_srgb")).count();
            list::footer(ui, &[(data.len(), "SR routers", chip::neutral_tone(&v)), (other, "other SRGB", chip::AMBER.tone(&v))], l);
        }
    }
}

fn column_help(p: &mut OspfPanel, app: &CoreRouterUi, key: Option<&'static str>, columns: &[table::Column]) {
    if let Some(key) = key {
        let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
        p.help = Some(HelpView::new(key, tr_in(SCOPE, app.lang.labels, title)));
    }
}

/// Every explanation key the tab uses (the catalog test).
#[cfg(test)]
pub(crate) fn help_keys() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = SID_COLUMNS.iter().chain(&NET_COLUMNS).chain(&NODE_COLUMNS).map(|c| c.help).collect();
    out.extend(SR_FIELDS.iter().chain(SID_FIELDS).map(|f| f.help));
    out.extend([SR_SPEC.help, SID_SPEC.help, "ospf.sr.ldp_block", "ospf.sr.conflicts", "ospf.sr.views"]);
    out
}

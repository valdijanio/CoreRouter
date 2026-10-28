//! Routing › OSPF › Fast Reroute (G3.4d): TI-LFA coverage (protected
//! routes and the protection type, IOS-XR's `fast-reroute prefix-summary`),
//! each route with its primary and backup next hop and label stack
//! (Junos' backup next hop), the routes left unprotected with the reason,
//! and "simulate a link cut" (the backups taken and the path after
//! convergence, without touching the network). `routing.ospf.fast-reroute*`
//! decides; this only shows and sends.

use egui::Ui;
use serde_json::Value;

use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list;
use crate::ospf::{OspfPanel, SCOPE};
use crate::table::{self, Row, col, num};
use crate::{CoreRouterUi, value_text};

pub(crate) const ROUTES: &str = "ospf-frr-routes";
pub(crate) const UNPROTECTED: &str = "ospf-frr-unprotected";
pub(crate) const SIM: &str = "ospf-frr-sim";

const ROUTE_COLUMNS: [table::Column; 6] = [
    col("Prefix").help("ospf.route.prefix"),
    num("Cost").help("ospf.route.cost"),
    col("Primary").help("ospf.frr.primary"),
    col("Backup").help("ospf.frr.backup"),
    col("Label Stack").help("ospf.frr.labels"),
    col("Protected").help("ospf.frr.protected"),
];

const UNPROT_COLUMNS: [table::Column; 2] = [col("Prefix").help("ospf.route.prefix"), col("Reason").help("ospf.frr.reason")];

const SIM_COLUMNS: [table::Column; 6] = [
    col("Prefix").help("ospf.route.prefix"),
    col("Before").help("ospf.frr.primary"),
    col("Backup").help("ospf.frr.backup"),
    col("Segments").help("ospf.frr.segments"),
    col("Label Stack").help("ospf.frr.labels"),
    col("After Convergence").help("ospf.frr.after"),
];

/// Which list the tab shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FrrView {
    #[default]
    Routes,
    Unprotected,
    Simulate,
}

const VIEWS: [(FrrView, &str); 3] = [(FrrView::Routes, "Routes"), (FrrView::Unprotected, "Unprotected"), (FrrView::Simulate, "Simulate Link Cut")];

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn labels(v: Option<&Value>) -> String {
    let l: Vec<String> = v.and_then(Value::as_array).map(|a| a.iter().map(value_text).collect()).unwrap_or_default();
    if l.is_empty() {
        "–".into()
    } else {
        let c: Vec<(&str, Kind)> = l.iter().map(|x| (x.as_str(), Kind::Blue)).collect();
        cell("", &c)
    }
}

/// "10.0.12.2 · crsr-a".
fn hop_text(h: &Value) -> String {
    let via = s(h, "via");
    let i = s(h, "interface");
    match (via.is_empty(), i.is_empty()) {
        (true, true) => "–".into(),
        (true, false) => i,
        (false, true) => via,
        (false, false) => format!("{via} · {i}"),
    }
}

fn route_row(r: &Value) -> Row {
    let backup = r.get("backup").filter(|b| !b.is_null());
    let protected = flag(r, "protected");
    let mark = if !protected {
        cell("", &[("no", Kind::Red)])
    } else if flag(r, "computed") {
        cell("", &[("yes", Kind::Green), ("lab", Kind::Amber)])
    } else {
        cell("", &[("yes", Kind::Green)])
    };
    Row {
        key: s(r, "prefix"),
        cells: vec![
            s(r, "prefix"),
            s(r, "cost"),
            hop_text(r.get("primary").unwrap_or(&Value::Null)),
            backup.map_or_else(|| "–".into(), hop_text),
            labels(backup.and_then(|b| b.get("labels"))),
            mark,
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn unprot_row(r: &Value) -> Row {
    Row { key: s(r, "prefix"), cells: vec![s(r, "prefix"), s(r, "reason")], dimmed: false, section: false, tint: None }
}

fn sim_row(r: &Value) -> Row {
    let b = r.get("backup").filter(|b| !b.is_null());
    let before = r.get("before").cloned().unwrap_or(Value::Null);
    let after = r.get("after").cloned().unwrap_or(Value::Null);
    let path: Vec<String> = after.get("path").and_then(Value::as_array).map(|a| a.iter().map(value_text).collect()).unwrap_or_default();
    let segs: Vec<String> = b.and_then(|b| b.get("segments")).and_then(Value::as_array).map(|a| a.iter().map(value_text).collect()).unwrap_or_default();
    Row {
        key: s(r, "prefix"),
        cells: vec![
            s(r, "prefix"),
            format!("{} · {}", s(&before, "via"), s(&before, "cost")),
            b.map_or_else(|| "–".into(), |b| {
                let nh = s(b, "nexthop");
                if flag(b, "installed") { cell(&nh, &[("installed", Kind::Green)]) } else { cell(&nh, &[("computed", Kind::Amber)]) }
            }),
            if segs.is_empty() { "–".into() } else { segs.join(", ") },
            labels(b.and_then(|b| b.get("labels"))),
            if path.is_empty() { "–".into() } else { format!("{} · {}", path.join(" → "), s(&after, "cost")) },
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

pub(crate) fn tab(p: &mut OspfPanel, app: &mut CoreRouterUi, ui: &mut Ui) {
    let l = app.lang.labels;
    let f = p.frr.clone();
    let v = ui.visuals().clone();
    let ti = s(&f, "ti_lfa");
    ui.horizontal_wrapped(|ui| {
        let (t, tone) = match ti.as_str() {
            "link" => ("TI-LFA · link", chip::GREEN.tone(&v)),
            "node" => ("TI-LFA · node", chip::GREEN.tone(&v)),
            _ => ("TI-LFA off", chip::neutral_tone(&v)),
        };
        chip::chip(ui, tr_in(SCOPE, l, t), tone);
        let cov = f.get("coverage").cloned().unwrap_or(Value::Null);
        let pct = cov.get("percent").and_then(Value::as_f64).unwrap_or(0.0);
        if ti != "off" && !ti.is_empty() {
            let tone = if pct >= 95.0 {
                chip::GREEN.tone(&v)
            } else if pct >= 70.0 {
                chip::AMBER.tone(&v)
            } else {
                chip::RED.tone(&v)
            };
            chip::chip(ui, &format!("{pct:.1}% {}", tr_in(SCOPE, l, "protected")), tone);
            if help::info_button(ui, egui::Id::unique("ospf-frr-coverage"), tr_in(SCOPE, l, "Coverage")).clicked() {
                p.help = Some(HelpView::new("ospf.frr.coverage", tr_in(SCOPE, l, "Coverage")));
            }
        }
        ui.separator();
        if ui.button(tr_in(SCOPE, l, "TI-LFA…")).clicked() {
            crate::ospf_sr::open_settings(p, app, false);
        }
        if s(&f, "source") == "virtual lab sample" {
            chip::chip(ui, tr_in(SCOPE, l, "virtual lab sample"), chip::AMBER.tone(&v));
        }
        if flag(&f, "pending") {
            ui.weak(tr_in(SCOPE, l, "Reading the database from the routing daemon…"));
        }
        if let Some(e) = f.get("error").filter(|e| !e.is_null()) {
            ui.colored_label(v.error_fg_color, value_text(e));
        }
    });
    ui.horizontal(|ui| {
        for (view, label) in VIEWS {
            if ui.selectable_label(p.frr_view == view, tr_in(SCOPE, l, label)).clicked() {
                p.frr_view = view;
            }
        }
        if help::info_button(ui, egui::Id::unique("ospf-frr-views"), tr_in(SCOPE, l, "Fast Reroute")).clicked() {
            p.help = Some(HelpView::new("ospf.frr.views", tr_in(SCOPE, l, "Fast Reroute")));
        }
    });
    ui.separator();
    let footer_h = ui.spacing().interact_size.y + 6.0;
    match p.frr_view {
        FrrView::Routes => {
            let data = f.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
            let rows: Vec<Row> = data.iter().map(route_row).collect();
            ui.horizontal(|ui| table::find_field(ui, ROUTES, &mut p.frr_table));
            let out = table::show(ui, ROUTES, footer_h, &mut p.frr_table, &ROUTE_COLUMNS, &rows, |_, _| {});
            column_help(p, app, out.help, &ROUTE_COLUMNS);
            let cov = f.get("coverage").cloned().unwrap_or(Value::Null);
            let n = |k: &str| cov.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
            list::footer(ui, &[(n("total"), "routes", chip::neutral_tone(&v)), (n("protected"), "protected", chip::GREEN.tone(&v)), (n("total") - n("protected").min(n("total")), "unprotected", chip::RED.tone(&v))], l);
        }
        FrrView::Unprotected => {
            let data = f.get("unprotected").and_then(Value::as_array).cloned().unwrap_or_default();
            let rows: Vec<Row> = data.iter().map(unprot_row).collect();
            ui.horizontal(|ui| table::find_field(ui, UNPROTECTED, &mut p.frr_unprot_table));
            let out = table::show(ui, UNPROTECTED, footer_h, &mut p.frr_unprot_table, &UNPROT_COLUMNS, &rows, |_, _| {});
            column_help(p, app, out.help, &UNPROT_COLUMNS);
            list::footer(ui, &[(data.len(), "unprotected", chip::RED.tone(&v))], l);
        }
        FrrView::Simulate => simulate(p, app, ui, &f),
    }
}

fn simulate(p: &mut OspfPanel, app: &mut CoreRouterUi, ui: &mut Ui, f: &Value) {
    let l = app.lang.labels;
    let v = ui.visuals().clone();
    let nbrs = f.get("neighbors").and_then(Value::as_array).cloned().unwrap_or_default();
    ui.horizontal_wrapped(|ui| {
        ui.label(tr_in(SCOPE, l, "Cut the link to"));
        let shown = nbrs
            .iter()
            .find(|n| s(n, "router_id") == p.frr_pick)
            .map_or_else(|| p.frr_pick.clone(), |n| format!("{} · {}", s(n, "router_id"), s(n, "interface")));
        egui::ComboBox::from_id_salt("ospf-frr-neighbor").selected_text(shown).show_ui(ui, |ui| {
            for n in &nbrs {
                let id = s(n, "router_id");
                ui.selectable_value(&mut p.frr_pick, id.clone(), format!("{id} · {}", s(n, "interface")));
            }
        });
        ui.checkbox(&mut p.frr_node, tr_in(SCOPE, l, "The router fails"));
        if ui.add_enabled(!p.frr_pick.is_empty(), egui::Button::new(tr_in(SCOPE, l, "Simulate"))).clicked() {
            p.frr_cut = Some((p.frr_pick.clone(), p.frr_node));
            app.cache.refreshed_at = None;
        }
        chip::chip(ui, tr_in(SCOPE, l, "simulation: nothing changes"), chip::AMBER.tone(&v));
    });
    let sim = p.frr_sim.clone();
    if p.frr_cut.is_none() || sim.is_null() {
        ui.weak(tr_in(SCOPE, l, "Pick a neighbor: the routes that leave by it are shown with the backup they take and the path after OSPF converges."));
        return;
    }
    if let Some(n) = sim.get("note") {
        ui.weak(value_text(n));
    }
    let lost = sim.get("lost").and_then(Value::as_array).cloned().unwrap_or_default();
    if !lost.is_empty() {
        egui::ScrollArea::vertical().id_salt("ospf-frr-lost").max_height(80.0).show(ui, |ui| {
            for x in &lost {
                ui.horizontal_wrapped(|ui| {
                    chip::chip(ui, &s(x, "prefix"), chip::RED.tone(&v));
                    ui.label(s(x, "reason"));
                });
            }
        });
    }
    let data = sim.get("affected").and_then(Value::as_array).cloned().unwrap_or_default();
    let rows: Vec<Row> = data.iter().map(sim_row).collect();
    let footer_h = ui.spacing().interact_size.y + 6.0;
    let out = table::show(ui, SIM, footer_h, &mut p.frr_sim_table, &SIM_COLUMNS, &rows, |_, _| {});
    column_help(p, app, out.help, &SIM_COLUMNS);
    let kept = sim.get("kept").and_then(Value::as_u64).unwrap_or(0) as usize;
    list::footer(ui, &[(data.len(), "rerouted", chip::GREEN.tone(&v)), (lost.len(), "lost", chip::RED.tone(&v)), (kept, "not affected", chip::neutral_tone(&v))], l);
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
    let mut out: Vec<&'static str> = ROUTE_COLUMNS.iter().chain(&UNPROT_COLUMNS).chain(&SIM_COLUMNS).map(|c| c.help).collect();
    out.extend(["ospf.frr.coverage", "ospf.frr.views", "ospf.tab.frr"]);
    out
}

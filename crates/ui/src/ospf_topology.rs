//! Routing › OSPF › Topology (G3.4c): the network the LSDB describes,
//! drawn — routers as circles, transit networks as squares, links with
//! the cost each end announces. The positions come from the engine
//! (`routing.ospf.topology`, a force-directed layout made once per LSDB);
//! this only scales, pans and paints. A click on a router asks "why this
//! path?" and the path is drawn over the map with the cost hop by hop.
//!
//! The answer is turned into flat vectors once, when it arrives
//! ([`View::arrived`]); a frame only walks them (no JSON, no allocation
//! per node), so 500 routers draw well inside a 60 fps frame
//! (`docs/ospf.md`, **medido**).

use std::collections::HashMap;

use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, Ui, Vec2};
use serde_json::Value;

use crate::chip;
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::ospf::{OspfPanel, SCOPE};
use crate::{CoreRouterUi, value_text};

/// One node, ready to draw.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct NodeView {
    pub key: String,
    pub label: String,
    pub network: bool,
    pub me: bool,
    pub abr: bool,
    pub asbr: bool,
    /// Our neighbor's state, when it is one ("Full · DR").
    pub neighbor: Option<String>,
    pub at: Pos2,
}

/// What the Topology tab keeps between frames.
#[derive(Debug, Clone, Default)]
pub(crate) struct View {
    /// The area shown ("" until the first answer picks one).
    pub area: String,
    pub areas: Vec<String>,
    pub nodes: Vec<NodeView>,
    /// Index pairs, the cost from `a` and the cost back.
    pub edges: Vec<(usize, usize, String)>,
    pub zoom: f32,
    pub pan: Vec2,
    pub source: String,
    pub layout_ms: f64,
}

impl View {
    /// Turn `routing.ospf.topology`'s answer into the flat vectors.
    pub(crate) fn arrived(&mut self, v: &Value) {
        let get = |o: &Value, k: &str| o.get(k).map(value_text).unwrap_or_default();
        self.source = get(v, "source");
        self.layout_ms = v.get("layout_ms").and_then(Value::as_f64).unwrap_or(0.0);
        self.areas = v
            .get("areas")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_text).collect())
            .unwrap_or_default();
        let area = get(v, "area");
        if !area.is_empty() {
            self.area = area;
        }
        let nodes = v.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
        self.nodes = nodes
            .iter()
            .map(|n| NodeView {
                key: get(n, "key"),
                label: get(n, "label"),
                network: get(n, "kind") == "network",
                me: n.get("self").and_then(Value::as_bool).unwrap_or(false),
                abr: n.get("abr").and_then(Value::as_bool).unwrap_or(false),
                asbr: n.get("asbr").and_then(Value::as_bool).unwrap_or(false),
                neighbor: n.get("neighbor").filter(|x| !x.is_null()).map(value_text),
                at: Pos2::new(
                    n.get("x").and_then(Value::as_f64).unwrap_or(0.5) as f32,
                    n.get("y").and_then(Value::as_f64).unwrap_or(0.5) as f32,
                ),
            })
            .collect();
        let index: HashMap<&str, usize> = self.nodes.iter().enumerate().map(|(i, n)| (n.key.as_str(), i)).collect();
        self.edges = v
            .get("edges")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        let (x, y) = (index.get(get(e, "a").as_str())?, index.get(get(e, "b").as_str())?);
                        let c = get(e, "cost");
                        let back = get(e, "back_cost");
                        let label = if back.is_empty() || back == "null" || back == c { c } else { format!("{c}/{back}") };
                        Some((*x, *y, label))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if self.zoom <= 0.0 {
            self.zoom = 1.0;
        }
    }
}

/// The node keys of the path being shown, in order.
fn path_keys(path: &Value) -> Vec<String> {
    path.get("hops")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|h| h.get("key").and_then(Value::as_str).map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// The tab: its bar, the map, the path under it.
pub(crate) fn tab(p: &mut OspfPanel, app: &mut CoreRouterUi, ui: &mut Ui) {
    let l = app.lang.labels;
    ui.horizontal(|ui| {
        let names: Vec<String> = p.instances.iter().map(|r| r.get("name").map(value_text).unwrap_or_default()).collect();
        if (p.instance.is_empty() || !names.contains(&p.instance))
            && let Some(first) = names.first()
        {
            p.instance = first.clone();
        }
        ui.label(tr_in(SCOPE, l, "Instance"));
        egui::ComboBox::from_id_salt("ospf-topo-instance").selected_text(p.instance.clone()).show_ui(ui, |ui| {
            for n in &names {
                if ui.selectable_value(&mut p.instance, n.clone(), n).clicked() {
                    app.cache.refreshed_at = None;
                }
            }
        });
        ui.label(tr_in(SCOPE, l, "Area"));
        let areas = p.topo.areas.clone();
        egui::ComboBox::from_id_salt("ospf-topo-area").selected_text(p.topo.area.clone()).show_ui(ui, |ui| {
            for a in &areas {
                if ui.selectable_value(&mut p.topo.area, a.clone(), a).clicked() {
                    app.cache.refreshed_at = None;
                }
            }
        });
        if ui.button(tr_in(SCOPE, l, "Fit")).on_hover_text(tr_in(SCOPE, l, "Back to the whole map")).clicked() {
            p.topo.zoom = 1.0;
            p.topo.pan = Vec2::ZERO;
        }
        if help::info_button(ui, egui::Id::unique("ospf-topo-help"), tr_in(SCOPE, l, "Topology")).clicked() {
            p.help = Some(HelpView::new("ospf.topology.legend", tr_in(SCOPE, l, "Topology")));
        }
        if p.topo.source == "virtual lab sample" {
            chip::chip(ui, tr_in(SCOPE, l, "virtual lab sample"), chip::AMBER.tone(ui.visuals()));
        }
        ui.weak(format!("{} · {} {:.1} ms", p.topo.nodes.len(), tr_in(SCOPE, l, "layout"), p.topo.layout_ms));
    });
    p.path_bar(app, ui);
    let path_h = if p.path.get("hops").is_some() { 70.0 } else { 0.0 };
    let avail = ui.available_size() - Vec2::new(0.0, path_h);
    let (rect, resp) = ui.allocate_exact_size(avail.max(Vec2::splat(80.0)), Sense::click_and_drag());
    if resp.dragged() {
        p.topo.pan += resp.drag_delta();
    }
    if resp.hovered() {
        let scroll = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll != 0.0 {
            p.topo.zoom = (p.topo.zoom * (1.0 + scroll / 400.0)).clamp(0.2, 8.0);
        }
    }
    let clicked = paint(ui, rect, &p.topo, &path_keys(&p.path), resp.clicked().then(|| resp.interact_pointer_pos()).flatten(), resp.hover_pos());
    if let Some(k) = clicked
        && let Some(id) = k.strip_prefix("r:")
    {
        p.path_to = id.to_owned();
        p.path_asked = Some(id.to_owned());
        app.cache.refreshed_at = None;
    }
    if p.topo.nodes.is_empty() {
        ui.painter().text(rect.center(), Align2::CENTER_CENTER, tr_in(SCOPE, l, "No LSDB to draw yet"), FontId::proportional(14.0), ui.visuals().weak_text_color());
    }
    if p.path.get("hops").is_some() {
        p.path_view(app, ui);
    }
}

/// Paint the map in `rect`; the key of the node clicked, if any.
pub(crate) fn paint(ui: &Ui, rect: Rect, v: &View, path: &[String], click: Option<Pos2>, hover: Option<Pos2>) -> Option<String> {
    let painter = ui.painter_at(rect);
    let vis = ui.visuals();
    let side = rect.width().min(rect.height()) * v.zoom;
    let origin = rect.center() + v.pan - Vec2::splat(side / 2.0);
    let to_screen = |p: Pos2| origin + Vec2::new(p.x * side, p.y * side);
    let many = v.nodes.len() > 120;
    let r = if many { 4.0 } else { 9.0 };
    let line = vis.widgets.noninteractive.fg_stroke.color.gamma_multiply(0.45);
    let accent = vis.selection.stroke.color;
    let on_path = |a: &str, b: &str| {
        path.windows(2).any(|w| matches!(w, [x, y] if (x == a && y == b) || (x == b && y == a)))
    };
    for (a, b, cost) in &v.edges {
        let (Some(na), Some(nb)) = (v.nodes.get(*a), v.nodes.get(*b)) else { continue };
        let (pa, pb) = (to_screen(na.at), to_screen(nb.at));
        let hot = on_path(&na.key, &nb.key);
        painter.line_segment([pa, pb], Stroke::new(if hot { 3.0 } else { 1.0 }, if hot { accent } else { line }));
        if !many || hot {
            painter.text(pa.lerp(pb, 0.5), Align2::CENTER_CENTER, cost, FontId::monospace(10.0), vis.weak_text_color());
        }
    }
    let mut hit = None;
    let mut hovered: Option<&NodeView> = None;
    for n in &v.nodes {
        let c = to_screen(n.at);
        let fill = if n.me {
            accent
        } else if n.neighbor.is_some() {
            chip::GREEN.tone(vis).fill
        } else if n.network {
            vis.widgets.inactive.bg_fill
        } else {
            vis.widgets.active.bg_fill
        };
        let ring = if path.iter().any(|k| k == &n.key) { Stroke::new(2.5, accent) } else { Stroke::new(1.0, vis.widgets.noninteractive.fg_stroke.color) };
        if n.network {
            painter.rect(Rect::from_center_size(c, Vec2::splat(r * 1.6)), 1.0, fill, ring, egui::StrokeKind::Middle);
        } else {
            painter.circle(c, r, fill, ring);
            if n.abr || n.asbr {
                painter.circle_stroke(c, r + 2.5, Stroke::new(1.0, chip::BLUE.tone(vis).ink));
            }
        }
        if !many || n.me {
            painter.text(c + Vec2::new(0.0, r + 7.0), Align2::CENTER_CENTER, &n.label, FontId::proportional(10.0), vis.text_color());
        }
        if let Some(h) = hover
            && h.distance(c) <= r + 3.0
        {
            hovered = Some(n);
        }
        if let Some(cl) = click
            && cl.distance(c) <= r + 3.0
        {
            hit = Some(n.key.clone());
        }
    }
    if let Some(n) = hovered {
        let mut t = n.label.clone();
        if n.abr {
            t.push_str(" · ABR");
        }
        if n.asbr {
            t.push_str(" · ASBR");
        }
        if let Some(s) = &n.neighbor {
            t.push_str(&format!(" · {s}"));
        }
        let at = to_screen(n.at) + Vec2::new(r + 6.0, -r - 6.0);
        let g = painter.layout_no_wrap(t, FontId::proportional(12.0), vis.strong_text_color());
        let bg = Rect::from_min_size(at - Vec2::new(4.0, 2.0 + g.size().y), g.size() + Vec2::new(8.0, 4.0));
        painter.rect_filled(bg, 3.0, vis.extreme_bg_color);
        painter.galley(Pos2::new(at.x, at.y - g.size().y), g, Color32::PLACEHOLDER);
    }
    hit
}

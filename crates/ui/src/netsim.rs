//! Tools › Network Simulator (G3.7b): the lab's virtual routers
//! (`tool.netsim.*`, `docs/netsim.md`) drawn as a topology — routers as
//! chips coloured by AS, links coloured by state, a cut link dashed — with
//! the clock (⏮ ⏯ ⏭ ×N), the timeline of what the protocols did, the
//! selected router's routes and neighbors, and a small editor. The badge
//! "simulation — not the real network" is always on screen.
//!
//! The engine simulates; the window only shows and sends commands. While
//! the clock plays, it sends `tool.netsim.tick` with the wall time since
//! the last one (the engine multiplies by the speed).

use egui::{Align2, ComboBox, FontId, Id, Pos2, Rect, RichText, Sense, Stroke, TextEdit, Ui, Vec2, pos2};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Tone};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, value_text};

const NAME: &str = "netsim";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "netsim";
const SCOPE: &str = "netsim";
const PRESETS: &[&str] = &["square", "ring", "mesh", "star", "grid"];
const SPEEDS: &[u32] = &[1, 10, 60, 600, 3600];
/// Seconds between two ticks while playing.
const TICK_SECS: f64 = 0.5;
/// Timeline lines kept.
const KEEP: usize = 400;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "Network Simulator",
        size: [1040.0, 700.0],
        escape: false,
    }],
    new: || Box::new(NetsimPanel::new()),
};

/// What is selected on the drawing.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Sel {
    Node(String),
    Link(u64),
}

pub(crate) struct NetsimPanel {
    /// `tool.netsim.get`.
    pub(crate) view: Option<Value>,
    /// `tool.netsim.node.get` of the selected router.
    pub(crate) node: Option<Value>,
    pub(crate) timeline: Vec<Value>,
    next: u64,
    pub(crate) selected: Option<Sel>,
    last_tick: Option<f64>,
    /// Wall milliseconds to tick at the next refresh (a query: ticks are
    /// not logged like actions, which would print one line every 0.5 s).
    tick: std::cell::Cell<Option<u64>>,
    preset: String,
    nodes: String,
    asn: String,
    link_a: String,
    link_b: String,
    cost: String,
    help: Option<HelpView>,
}

impl NetsimPanel {
    fn new() -> Self {
        NetsimPanel {
            view: None,
            node: None,
            timeline: Vec::new(),
            next: 0,
            selected: None,
            last_tick: None,
            tick: std::cell::Cell::new(None),
            preset: "square".into(),
            nodes: "6".into(),
            asn: "65200".into(),
            link_a: String::new(),
            link_b: String::new(),
            cost: "10".into(),
            help: None,
        }
    }

    fn loaded(&self) -> bool {
        self.view.as_ref().and_then(|v| v.get("loaded")).and_then(Value::as_bool) == Some(true)
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("netsim-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).filter(|x| !x.is_null()).map(value_text).unwrap_or_default()
}

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// "1 min 05.250 s" / "5.250 s" of a virtual time in ms.
pub(crate) fn clock_text(ms: f64) -> String {
    let secs = ms / 1000.0;
    if secs >= 60.0 {
        let m = (secs / 60.0).floor();
        format!("{m:.0} min {:06.3} s", secs - m * 60.0)
    } else {
        format!("{secs:.3} s")
    }
}

fn layer_tone(v: &egui::Visuals, layer: &str) -> Tone {
    match layer {
        "fault" => chip::RED.tone(v),
        "bfd" => chip::AMBER.tone(v),
        "ospf" => chip::BLUE.tone(v),
        "bgp" => chip::GREEN.tone(v),
        _ => chip::neutral_tone(v),
    }
}

/// One timeline line, in words.
pub(crate) fn describe(r: &Value) -> String {
    let link = || format!("link {}", u(r, "link"));
    match s(r, "type").as_str() {
        "fault" => {
            let f = r.get("fault").cloned().unwrap_or(Value::Null);
            let what = s(&f, "kind");
            match (f.get("link"), f.get("node")) {
                (Some(l), _) => format!("{what} link {}", value_text(l)),
                (_, Some(n)) => format!("{what} router {}", value_text(n)),
                _ => what,
            }
        }
        "adj-up" => format!("OSPF Full with {} ({})", s(r, "neighbor"), link()),
        "adj-down" => format!("OSPF down with {} ({}, {})", s(r, "neighbor"), link(), s(r, "reason")),
        "bfd-down" => format!("BFD down ({})", link()),
        "bfd-up" => format!("BFD up ({})", link()),
        "igp-changed" => format!("SPF: {} routes (+{} −{})", u(r, "routes"), u(r, "added"), u(r, "removed")),
        "bgp-up" => format!("BGP {} established", s(r, "peer")),
        "bgp-down" => format!("BGP {} down: {}", s(r, "peer"), s(r, "reason")),
        "bgp-error" => format!("BGP {}: {}", s(r, "peer"), s(r, "reason")),
        "bgp-best" => format!(
            "BGP best paths: {} (+{} −{} ~{})",
            u(r, "prefixes"),
            u(r, "added"),
            u(r, "removed"),
            u(r, "changed")
        ),
        other => other.to_owned(),
    }
}

/// "link-cut: detected +0.79 s, OSPF +0.80 s, BGP +0.85 s, 0 prefixes lost".
pub(crate) fn convergence_text(c: &Value) -> Option<String> {
    let kind = c.get("fault").map(|f| s(f, "kind"))?;
    let mut parts: Vec<String> = [("detected_after_ms", "detected"), ("igp_after_ms", "OSPF"), ("bgp_after_ms", "BGP")]
        .iter()
        .filter_map(|(k, what)| {
            let ms = c.get(*k).and_then(Value::as_f64)?;
            Some(format!("{what} +{:.2} s", ms / 1000.0))
        })
        .collect();
    let lost = u(c, "bgp_prefixes_before").saturating_sub(u(c, "bgp_prefixes_now"));
    parts.push(format!("{lost} prefixes lost"));
    Some(format!("{kind}: {}", parts.join(", ")))
}

/// Distance from `p` to the segment `a`–`b`.
fn to_segment(p: Pos2, a: Pos2, b: Pos2) -> f32 {
    let ab = b - a;
    let len2 = ab.length_sq();
    if len2 <= f32::EPSILON {
        return p.distance(a);
    }
    let t = ((p - a).dot(ab) / len2).clamp(0.0, 1.0);
    p.distance(a + ab * t)
}

fn dashed(painter: &egui::Painter, a: Pos2, b: Pos2, stroke: Stroke) {
    let len = a.distance(b);
    let n = (len / 8.0).ceil().max(1.0) as usize;
    for i in (0..n).step_by(2) {
        let t0 = i as f32 / n as f32;
        let t1 = ((i + 1) as f32 / n as f32).min(1.0);
        painter.line_segment([a.lerp(b, t0), a.lerp(b, t1)], stroke);
    }
}

impl NetsimPanel {
    fn top_bar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let view = self.view.clone().unwrap_or(Value::Null);
        ui.horizontal_wrapped(|ui| {
            chip::chip(ui, tr_in(SCOPE, l, "simulation — not the real network"), chip::AMBER.tone(&v))
                .on_hover_text(tr_in(SCOPE, l, "Virtual routers in memory; nothing here touches this router."));
            self.info(ui, l, "netsim.badge", "Simulation");
            ui.separator();
            ComboBox::from_id_salt("netsim-preset")
                .selected_text(self.preset.clone())
                .width(80.0)
                .show_ui(ui, |ui| {
                    for p in PRESETS {
                        ui.selectable_value(&mut self.preset, (*p).to_owned(), *p);
                    }
                });
            if self.preset != "square" {
                ui.label(tr_in(SCOPE, l, "Routers"));
                ui.add(TextEdit::singleline(&mut self.nodes).desired_width(36.0));
            }
            let can_new = app.can.check("tool.netsim.new");
            if action(ui, tr_in(SCOPE, l, "New"), can_new) {
                let p = match self.nodes.trim().parse::<u32>() {
                    Ok(n) if self.preset != "square" => json!({"preset": self.preset, "nodes": n}),
                    _ => json!({"preset": self.preset}),
                };
                app.run("tool.netsim.new", p);
                self.reset_view(app);
            }
            self.info(ui, l, "netsim.presets", "Presets");
            if !self.loaded() {
                return;
            }
            ui.separator();
            let playing = view.get("playing").and_then(Value::as_bool) == Some(true);
            let speed = u(&view, "speed").max(1);
            if ui
                .button(RichText::new(crate::icons::SKIP_BACK).font(crate::icons::font(15.0)))
                .on_hover_text(tr_in(SCOPE, l, "Restart the preset at t = 0"))
                .clicked()
            {
                let mut p = json!({"preset": self.preset});
                if let Some(name) = view.get("name").and_then(Value::as_str)
                    && PRESETS.contains(&name)
                {
                    p = json!({"preset": name, "nodes": view.get("nodes").and_then(Value::as_array).map_or(4, Vec::len)});
                }
                app.run("tool.netsim.new", p);
                self.reset_view(app);
            }
            let (icon, act, tip) = if playing {
                (crate::icons::PAUSE, "pause", "Pause")
            } else {
                (crate::icons::PLAY, "play", "Play")
            };
            if ui.button(RichText::new(icon).font(crate::icons::font(15.0))).on_hover_text(tr_in(SCOPE, l, tip)).clicked() {
                app.run("tool.netsim.clock", json!({"action": act}));
                self.last_tick = None;
                app.cache.refreshed_at = None;
            }
            if ui
                .button(RichText::new(crate::icons::SKIP_FORWARD).font(crate::icons::font(15.0)))
                .on_hover_text(tr_in(SCOPE, l, "Step: the next instant something happens"))
                .clicked()
            {
                app.run("tool.netsim.clock", json!({"action": "step"}));
                app.cache.refreshed_at = None;
            }
            let mut chosen = speed;
            ComboBox::from_id_salt("netsim-speed")
                .selected_text(format!("×{speed}"))
                .width(60.0)
                .show_ui(ui, |ui| {
                    for s in SPEEDS {
                        ui.selectable_value(&mut chosen, u64::from(*s), format!("×{s}"));
                    }
                });
            if chosen != speed {
                let act = if playing { "play" } else { "pause" };
                app.run("tool.netsim.clock", json!({"action": act, "speed": chosen}));
                app.cache.refreshed_at = None;
            }
            self.info(ui, l, "netsim.clock", "Clock");
            ui.separator();
            let now = view.get("now_ms").and_then(Value::as_f64).unwrap_or(0.0);
            ui.label(RichText::new(format!("t = {}", clock_text(now))).monospace().strong());
        });
    }

    fn reset_view(&mut self, app: &mut CoreRouterUi) {
        self.timeline.clear();
        self.next = 0;
        self.selected = None;
        self.node = None;
        self.last_tick = None;
        app.cache.refreshed_at = None;
    }

    /// The topology: routers at their positions, links between them.
    fn drawing(&mut self, ui: &mut Ui, size: Vec2) {
        let (resp, painter) = ui.allocate_painter(size, Sense::click());
        let rect = resp.rect.shrink(28.0);
        let v = ui.visuals().clone();
        painter.rect_filled(resp.rect, 4.0, v.extreme_bg_color);
        let Some(view) = &self.view else { return };
        let nodes = arr(view, "nodes");
        let at = |n: &Value| -> Pos2 {
            let p = arr(n, "pos");
            let x = p.first().and_then(Value::as_f64).unwrap_or(0.5) as f32;
            let y = p.get(1).and_then(Value::as_f64).unwrap_or(0.5) as f32;
            pos2(rect.left() + x * rect.width(), rect.top() + y * rect.height())
        };
        let pos_of = |id: u64| nodes.iter().find(|n| u(n, "id") == id).map(at);
        let small = FontId::proportional(chip::small(ui));
        let mut link_hits = Vec::new();
        for link in arr(view, "links") {
            let (Some(a), Some(b)) = (pos_of(u(link, "a")), pos_of(u(link, "b"))) else { continue };
            let id = u(link, "id");
            let selected = self.selected == Some(Sel::Link(id));
            let width = if selected { 4.0 } else { 2.0 };
            let state = s(link, "state");
            let full = link.get("ospf_full").and_then(Value::as_bool) == Some(true);
            let ospf = link.get("ospf").and_then(Value::as_bool) == Some(true);
            let color = match state.as_str() {
                "cut" => chip::RED.tone(&v).ink,
                "down" => v.weak_text_color(),
                _ if !ospf => chip::BLUE.tone(&v).ink,
                _ if full => chip::GREEN.tone(&v).ink,
                _ => chip::AMBER.tone(&v).ink,
            };
            let stroke = Stroke::new(width, color);
            if state == "up" {
                painter.line_segment([a, b], stroke);
            } else {
                dashed(&painter, a, b, stroke);
            }
            if ospf {
                // Beside the line, not on it.
                let n = (b - a).normalized().rot90();
                let n = if n.y > 0.0 { -n } else { n };
                let mid = a.lerp(b, 0.5) + n * 10.0;
                let cost = if u(link, "cost_a") == u(link, "cost_b") {
                    s(link, "cost_a")
                } else {
                    format!("{}/{}", s(link, "cost_a"), s(link, "cost_b"))
                };
                painter.text(mid, Align2::CENTER_CENTER, cost, small.clone(), v.weak_text_color());
            }
            link_hits.push((id, a, b));
        }
        let mut node_hits = Vec::new();
        for n in nodes {
            let p = at(n);
            let name = s(n, "name");
            let asn = u(n, "asn");
            let up = n.get("up").and_then(Value::as_bool) != Some(false);
            let tone = if up {
                chip::palette_tone(&v, chip::hashed(asn))
            } else {
                chip::RED.tone(&v)
            };
            let label = format!("{name}\nAS{asn}");
            let galley = painter.layout(label, FontId::proportional(13.0), tone.ink, f32::INFINITY);
            let r = Rect::from_center_size(p, galley.size() + Vec2::new(16.0, 8.0));
            let selected = self.selected == Some(Sel::Node(name.clone()));
            // Opaque under the tint: the links end at the centre.
            painter.rect_filled(r, 8.0, v.extreme_bg_color);
            painter.rect_filled(r, 8.0, tone.fill);
            painter.rect_stroke(r, 8.0, Stroke::new(if selected { 2.5 } else { 1.0 }, tone.ink), egui::StrokeKind::Inside);
            painter.galley(r.center() - galley.size() / 2.0, galley, tone.ink);
            node_hits.push((name, r));
        }
        if resp.clicked()
            && let Some(p) = resp.interact_pointer_pos()
        {
            self.selected = node_hits
                .iter()
                .find(|(_, r)| r.contains(p))
                .map(|(n, _)| Sel::Node(n.clone()))
                .or_else(|| {
                    link_hits
                        .iter()
                        .map(|(id, a, b)| (*id, to_segment(p, *a, *b)))
                        .filter(|(_, d)| *d < 8.0)
                        .min_by(|x, y| x.1.total_cmp(&y.1))
                        .map(|(id, _)| Sel::Link(id))
                });
            self.node = None;
        }
    }

    fn side(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        match self.selected.clone() {
            None => {
                ui.weak(tr_in(SCOPE, l, "Click a router or a link."));
                self.editor(app, ui);
            }
            Some(Sel::Node(name)) => self.node_side(app, ui, &name),
            Some(Sel::Link(id)) => {
                let Some(link) = self
                    .view
                    .as_ref()
                    .and_then(|vw| arr(vw, "links").iter().find(|x| u(x, "id") == id).cloned())
                else {
                    return;
                };
                let view = self.view.clone().unwrap_or(Value::Null);
                let name_of = |nid: u64| {
                    arr(&view, "nodes")
                        .iter()
                        .find(|n| u(n, "id") == nid)
                        .map(|n| s(n, "name"))
                        .unwrap_or_default()
                };
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} {} – {} {}",
                            name_of(u(&link, "a")),
                            s(&link, "a_iface"),
                            name_of(u(&link, "b")),
                            s(&link, "b_iface")
                        ))
                        .strong(),
                    );
                    let state = s(&link, "state");
                    let tone = match state.as_str() {
                        "up" => chip::GREEN.tone(&v),
                        "cut" => chip::RED.tone(&v),
                        _ => chip::neutral_tone(&v),
                    };
                    chip::chip(ui, &state, tone);
                    self.info(ui, l, "netsim.link", "Link");
                });
                ui.label(format!(
                    "{}: {} / {}   {}: {} ms   {}: {} %",
                    tr_in(SCOPE, l, "Cost"),
                    s(&link, "cost_a"),
                    s(&link, "cost_b"),
                    tr_in(SCOPE, l, "Latency"),
                    s(&link, "latency_ms"),
                    tr_in(SCOPE, l, "Loss"),
                    s(&link, "loss_pct")
                ));
                ui.horizontal_wrapped(|ui| {
                    for (label, kind) in [("Cut", "link-cut"), ("Carrier down", "link-down"), ("Restore", "link-restore")] {
                        if ui.button(tr_in(SCOPE, l, label)).clicked() {
                            app.run("tool.netsim.fault", json!({"kind": kind, "link": id}));
                            app.cache.refreshed_at = None;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(tr_in(SCOPE, l, "Cost"));
                    ui.add(TextEdit::singleline(&mut self.cost).desired_width(48.0));
                    if ui.button(tr_in(SCOPE, l, "Apply")).clicked()
                        && let Ok(c) = self.cost.trim().parse::<u32>()
                    {
                        app.run("tool.netsim.link.set", json!({"link": id, "cost": c}));
                        app.cache.refreshed_at = None;
                    }
                    let bfd = link.get("bfd").and_then(Value::as_bool) == Some(true);
                    let mut on = bfd;
                    if ui.checkbox(&mut on, "BFD").changed() {
                        app.run("tool.netsim.link.set", json!({"link": id, "bfd": on}));
                        app.cache.refreshed_at = None;
                    }
                });
            }
        }
    }

    fn node_side(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, name: &str) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let Some(n) = self.node.clone() else {
            ui.weak("…");
            return;
        };
        let view = n.get("node").cloned().unwrap_or(Value::Null);
        let up = view.get("up").and_then(Value::as_bool) != Some(false);
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).strong());
            chip::chip(ui, &format!("AS{}", s(&view, "asn")), chip::palette_tone(&v, chip::hashed(u(&view, "asn"))));
            ui.weak(s(&view, "router_id"));
            self.info(ui, l, "netsim.node", "Router");
            let (label, kind) = if up { ("Router down", "node-down") } else { ("Router up", "node-up") };
            if ui.button(tr_in(SCOPE, l, label)).clicked() {
                app.run("tool.netsim.fault", json!({"kind": kind, "node": name}));
                app.cache.refreshed_at = None;
            }
        });
        ui.label(RichText::new(tr_in(SCOPE, l, "OSPF neighbors")).strong());
        egui::Grid::new("netsim-ospf").striped(true).show(ui, |ui| {
            for r in arr(&n, "ospf_neighbors") {
                ui.label(s(r, "iface"));
                ui.label(s(r, "neighbor"));
                let st = s(r, "state");
                let tone = if st == "full" { chip::GREEN.tone(&v) } else { chip::AMBER.tone(&v) };
                chip::chip(ui, &st, tone);
                ui.label(s(r, "cost"));
                ui.end_row();
            }
        });
        ui.label(RichText::new(tr_in(SCOPE, l, "BGP sessions")).strong());
        egui::Grid::new("netsim-bgp").striped(true).show(ui, |ui| {
            for r in arr(&n, "bgp_peers") {
                ui.label(s(r, "name"));
                ui.label(s(r, "remote_address"));
                let st = s(r, "state");
                let tone = if st == "established" { chip::GREEN.tone(&v) } else { chip::AMBER.tone(&v) };
                chip::chip(ui, &st, tone).on_hover_text(s(r, "last_error"));
                ui.label(format!("{} rx / {} tx", u(r, "prefixes_received"), u(r, "prefixes_sent")));
                ui.end_row();
            }
        });
        ui.label(RichText::new(tr_in(SCOPE, l, "Routes")).strong());
        {
            egui::Grid::new("netsim-routes-grid").striped(true).show(ui, |ui| {
                for r in arr(&n, "routes") {
                    ui.monospace(s(r, "prefix"));
                    let proto = s(r, "proto");
                    let tone = match proto.as_str() {
                        "ospf" => chip::BLUE.tone(&v),
                        "ebgp" | "ibgp" => chip::GREEN.tone(&v),
                        _ => chip::neutral_tone(&v),
                    };
                    chip::chip(ui, &proto, tone);
                    ui.label(s(r, "metric"));
                    ui.weak(s(r, "via"));
                    ui.end_row();
                }
            });
        }
    }

    fn editor(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr_in(SCOPE, l, "Editor")).strong());
            self.info(ui, l, "netsim.editor", "Editor");
        });
        ui.horizontal(|ui| {
            ui.label("AS");
            ui.add(TextEdit::singleline(&mut self.asn).desired_width(60.0));
            if ui.button(tr_in(SCOPE, l, "Add router")).clicked() {
                let asn = self.asn.trim().parse::<u32>().unwrap_or(65000);
                app.run("tool.netsim.node.add", json!({"asn": asn, "x": 0.5, "y": 0.9}));
                app.cache.refreshed_at = None;
            }
        });
        let names: Vec<String> = self
            .view
            .as_ref()
            .map(|v| arr(v, "nodes").iter().map(|n| s(n, "name")).collect())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            for (salt, value) in [("netsim-a", &mut self.link_a), ("netsim-b", &mut self.link_b)] {
                ComboBox::from_id_salt(salt)
                    .selected_text(value.clone())
                    .width(70.0)
                    .show_ui(ui, |ui| {
                        for n in &names {
                            ui.selectable_value(value, n.clone(), n);
                        }
                    });
            }
            ui.label(tr_in(SCOPE, l, "Cost"));
            ui.add(TextEdit::singleline(&mut self.cost).desired_width(40.0));
            if ui.button(tr_in(SCOPE, l, "Add link")).clicked() && !self.link_a.is_empty() && !self.link_b.is_empty() {
                let cost = self.cost.trim().parse::<u32>().unwrap_or(10);
                app.run("tool.netsim.link.add", json!({"a": self.link_a, "b": self.link_b, "cost": cost}));
                app.cache.refreshed_at = None;
            }
        });
        ui.horizontal(|ui| {
            if ui.button(tr_in(SCOPE, l, "What if: add this router")).clicked() {
                app.run("tool.netsim.import", json!({"x": 0.5, "y": 0.5}));
                app.cache.refreshed_at = None;
            }
            self.info(ui, l, "netsim.whatif", "What if");
        });
    }

    fn timeline_view(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        ui.horizontal(|ui| {
            ui.label(RichText::new(tr_in(SCOPE, l, "Timeline")).strong());
            self.info(ui, l, "netsim.timeline", "Timeline");
            if let Some(c) = self.view.as_ref().and_then(|vw| vw.get("convergence")).and_then(convergence_text) {
                ui.separator();
                ui.label(RichText::new(c).strong());
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("netsim-timeline")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for r in &self.timeline {
                    ui.horizontal(|ui| {
                        let at = r.get("at_ms").and_then(Value::as_f64).unwrap_or(0.0);
                        ui.monospace(format!("{:>14}", clock_text(at)));
                        let layer = s(r, "layer");
                        chip::chip(ui, &layer, layer_tone(&v, &layer));
                        ui.label(RichText::new(s(r, "node")).strong());
                        ui.label(describe(r));
                    });
                }
            });
    }
}

impl PanelState for NetsimPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut q = Vec::new();
        if let Some(wall) = self.tick.take() {
            q.push(Query {
                key: "tick",
                command: "tool.netsim.tick",
                params: json!({"wall_ms": wall}),
            });
        }
        q.push(Query {
            key: "get",
            command: "tool.netsim.get",
            params: json!({}),
        });
        if self.loaded() {
            q.push(Query {
                key: "timeline",
                command: "tool.netsim.timeline",
                params: json!({"after": self.next, "limit": 500}),
            });
            if let Some(Sel::Node(n)) = &self.selected {
                q.push(Query {
                    key: "node",
                    command: "tool.netsim.node.get",
                    params: json!({"node": n, "routes_limit": 500}),
                });
            }
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _id: RequestId, value: Value) {
        match key {
            "get" => {
                // A new simulation (the clock went back): start the timeline over.
                let was = self.view.as_ref().map(|v| u(v, "now_ms"));
                if was.is_some_and(|w| u(&value, "now_ms") < w) || value.get("loaded").and_then(Value::as_bool) != Some(true) {
                    self.timeline.clear();
                    self.next = 0;
                }
                self.view = Some(value);
            }
            "timeline" => {
                let total = u(&value, "total");
                if total < self.next {
                    self.timeline.clear();
                    self.next = 0;
                    return;
                }
                self.timeline.extend(arr(&value, "records").iter().cloned());
                let extra = self.timeline.len().saturating_sub(KEEP);
                self.timeline.drain(..extra);
                self.next = u(&value, "next").max(self.next);
            }
            "node" => self.node = Some(value),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        if win != WIN {
            return;
        }
        let l = app.lang.labels;
        self.top_bar(app, ui);
        ui.separator();
        if !self.loaded() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.label(tr_in(SCOPE, l, "No simulation. Pick a preset and press New."));
            });
            return;
        }
        // Playing: tick with the wall time since the last one.
        let playing = self.view.as_ref().and_then(|v| v.get("playing")).and_then(Value::as_bool) == Some(true);
        if playing {
            let now = ui.input(|i| i.time);
            match self.last_tick {
                Some(t) if now - t >= TICK_SECS => {
                    let wall = ((now - t) * 1000.0).clamp(1.0, 10_000.0) as u64;
                    self.tick.set(Some(wall));
                    app.cache.refreshed_at = None;
                    self.last_tick = Some(now);
                }
                None => self.last_tick = Some(now),
                _ => {}
            }
            ui.ctx().request_repaint_after(std::time::Duration::from_secs_f64(TICK_SECS / 2.0));
        }
        let avail = ui.available_size();
        let bottom = (avail.y * 0.3).clamp(120.0, 260.0);
        let top = (avail.y - bottom - 16.0).max(240.0);
        let w = (avail.x * 0.6).max(300.0);
        ui.allocate_ui_with_layout(
            Vec2::new(avail.x, top),
            egui::Layout::left_to_right(egui::Align::Min),
            |ui| {
                ui.set_min_height(top);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr_in(SCOPE, l, "Topology")).strong());
                        self.info(ui, l, "netsim.topology", "Topology");
                    });
                    self.drawing(ui, Vec2::new(w, (top - 28.0).max(200.0)));
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.set_width((avail.x - w - 20.0).max(200.0));
                    egui::ScrollArea::vertical()
                        .id_salt("netsim-side")
                        .max_height(top)
                        .show(ui, |ui| self.side(app, ui));
                });
            },
        );
        ui.separator();
        self.timeline_view(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }
}


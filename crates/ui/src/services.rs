//! The System › Services window (G0.10): the daemon's services under its
//! supervisor, pfSense Status › Services style. Toolbar (Start, Stop,
//! Restart, Reset failures) and summary chips; one row per service with its
//! state chip, uptime, restarts, sockets and last event; under the table,
//! the selected one's detail and the last lines of its log topic.
//!
//! The engine (`system.service.*`) and the daemon decide everything; the
//! window shows rows and sends commands. Without a daemon (lab, browser)
//! the list is empty and says so.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use std::collections::BTreeMap;

use egui::{Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, GREEN, RED, Tone, chip, neutral_tone};
use crate::neighbors::uptime_text;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::system_log::short_time;
use crate::table::action;
use crate::{CoreRouterUi, Win};

const NAME: &str = "services";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "services";
const PRINT: &str = "system.service.print";
const LOG: &str = "log.print";
/// Log lines shown under the detail.
const LOG_LINES: u32 = 6;
/// Characters of the last event in the table (the rest in the tooltip).
const EVENT_CHARS: usize = 60;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Services",
        size: [920.0, 560.0],
        escape: true,
    }],
    new: || Box::new(ServicesPanel::default()),
};

/// The window: rows as the router sent them, the selection and the log of
/// the selected service.
#[derive(Default)]
pub(crate) struct ServicesPanel {
    pub(crate) rows: Vec<Value>,
    /// Name of the selected service.
    pub(crate) selected: Option<String>,
    /// `log.print` of the selected service's topic: (topic, lines).
    log: Option<(String, Vec<Value>)>,
    /// Each row's rectangle last frame (clicks select).
    rects: BTreeMap<String, egui::Rect>,
    pub(crate) error: Option<String>,
    /// What the last command did ("stop sent to dns-server"); the row and
    /// the log line follow with the next refresh.
    pub(crate) notice: Option<String>,
}

/// A command's reply: the action, for the message.
struct Acted(&'static str);

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn n(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

/// The text and tone of a state chip.
pub(crate) fn state_chip(v: &egui::Visuals, row: &Value) -> (String, Tone) {
    // A stop or restart on its way shows over the state it leaves.
    let state = match row.get("reason").and_then(Value::as_str) {
        Some(r @ ("stopping" | "restarting")) => r,
        _ => s(row, "state"),
    };
    let tone = match state {
        "running" => GREEN.tone(v),
        // Stopped by the admin stands out from "off in the config".
        "restarting" | "stopping" | "stopped" => AMBER.tone(v),
        "failed" => RED.tone(v),
        "starting" => BLUE.tone(v),
        _ => neutral_tone(v),
    };
    let text = match (state, n(row, "restart_in_secs")) {
        ("restarting", Some(secs)) => format!("restarting {secs} s"),
        _ => state.to_owned(),
    };
    (text, tone)
}

/// The chip of a socket's reach: `all`, `LAN`, `local`, `public`.
fn scope_chip(v: &egui::Visuals, scope: &str) -> (&'static str, Tone, &'static str) {
    match scope {
        "all" => (
            "all",
            AMBER.tone(v),
            "every address of the router: who may use it is up to the service's ACL and the firewall",
        ),
        "lan" => ("LAN", BLUE.tone(v), "a private or link-local address"),
        "public" => ("public", AMBER.tone(v), "a public address of the router"),
        _ => ("local", neutral_tone(v), "loopback: this machine only"),
    }
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

impl ServicesPanel {
    fn row(&self, name: &str) -> Option<&Value> {
        self.rows.iter().find(|r| s(r, "name") == name)
    }

    /// (running, restarting, failed).
    pub(crate) fn summary(&self) -> (usize, usize, usize) {
        let count = |want: &str| self.rows.iter().filter(|r| s(r, "state") == want).count();
        (count("running"), count("restarting"), count("failed"))
    }

    fn toolbar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let sel = self.selected.as_deref().and_then(|n| self.row(n)).cloned();
        let pick = |id: &str, stops: bool| -> Result<(), String> {
            can.check(id)?;
            let Some(r) = &sel else {
                return Err("select a service first".into());
            };
            if stops && r.get("protected").and_then(Value::as_bool) == Some(true) {
                return Err("protected: it carries this management session".into());
            }
            Ok(())
        };
        let mut act: Option<&'static str> = None;
        ui.horizontal(|ui| {
            for (label, id, stops) in [
                ("Start", "system.service.start", false),
                ("Stop", "system.service.stop", true),
                ("Restart", "system.service.restart", true),
                ("Reset failures", "system.service.reset-failures", false),
            ] {
                if action(ui, label, pick(id, stops)) {
                    act = Some(id);
                }
            }
            ui.separator();
            let (running, restarting, failed) = self.summary();
            let v = ui.visuals().clone();
            chip(ui, &format!("{running} running"), GREEN.tone(&v));
            if restarting > 0 {
                chip(ui, &format!("{restarting} restarting"), AMBER.tone(&v));
            }
            if failed > 0 {
                chip(ui, &format!("{failed} failed"), RED.tone(&v));
            }
        });
        if let (Some(id), Some(name)) = (act, self.selected.clone()) {
            app.run_then(id, json!({ "name": name }), crate::panel::then(NAME, Acted(id)));
        }
    }

    fn table(&mut self, ui: &mut Ui) {
        let last = std::mem::take(&mut self.rects);
        // Every row as wide as the widest (the selection is one band).
        let right_edge = last.values().map(|r| r.right()).fold(f32::MIN, f32::max);
        let last: BTreeMap<String, egui::Rect> = last
            .into_iter()
            .map(|(k, mut r)| {
                r.set_right(right_edge);
                (k, r)
            })
            .collect();
        let mut rects = BTreeMap::new();
        let mut selected = self.selected.clone();
        let sel_fill = ui.visuals().selection.bg_fill;
        let hover_fill = ui.visuals().widgets.hovered.weak_bg_fill;
        let v = ui.visuals().clone();
        Grid::new("services-table")
            .striped(true)
            .spacing([14.0, 4.0])
            .show(ui, |ui| {
                for h in ["Name", "State", "Uptime", "Restarts", "Listen", "Last event"] {
                    ui.strong(h);
                }
                ui.end_row();
                for r in &self.rows {
                    let name = s(r, "name").to_owned();
                    if let Some(rect) = last.get(&name) {
                        let resp = ui.interact(
                            *rect,
                            egui::Id::unique(("services-row", &name)),
                            egui::Sense::click(),
                        );
                        if resp.clicked() {
                            selected = (selected.as_deref() != Some(&name)).then(|| name.clone());
                        }
                        if selected.as_deref() == Some(name.as_str()) {
                            ui.painter().rect_filled(*rect, 2.0, sel_fill);
                        } else if resp.hovered() {
                            ui.painter().rect_filled(*rect, 2.0, hover_fill);
                        }
                    }
                    let top_left = ui.cursor().min;
                    ui.add(egui::Label::new(&name).selectable(false));
                    let (text, tone) = state_chip(&v, r);
                    let reason = s(r, "reason");
                    let resp = chip(ui, &text, tone);
                    if !reason.is_empty() {
                        resp.on_hover_text(reason);
                    }
                    match n(r, "uptime_secs") {
                        Some(u) => ui.label(uptime_text(u)),
                        None => ui.weak("–"),
                    };
                    ui.label(n(r, "restarts").unwrap_or(0).to_string());
                    listen_cell(ui, r, &v);
                    let event = s(r, "last_event");
                    let mut tip = event.to_owned();
                    if let Some(e) = r.get("last_error").and_then(Value::as_str) {
                        tip = format!("{tip}\nlast error: {e}");
                    }
                    let shown = if event.is_empty() { "–" } else { event };
                    let text = RichText::new(cut(shown, EVENT_CHARS));
                    let text = if s(r, "state") == "failed" {
                        text.color(ui.visuals().error_fg_color)
                    } else {
                        text
                    };
                    let right = ui
                        .add(egui::Label::new(text).selectable(false))
                        .on_hover_text(tip)
                        .rect
                        .right();
                    ui.end_row();
                    let bottom = ui.cursor().min.y - ui.spacing().item_spacing.y;
                    rects.insert(
                        name,
                        egui::Rect::from_min_max(
                            top_left - egui::vec2(4.0, 1.0),
                            egui::pos2(right.max(top_left.x) + 4.0, bottom.max(top_left.y) + 1.0),
                        ),
                    );
                }
            });
        self.rects = rects;
        if selected != self.selected {
            self.log = None;
        }
        self.selected = selected;
    }

    fn detail(&self, ui: &mut Ui) {
        let Some(r) = self.selected.as_deref().and_then(|n| self.row(n)) else {
            ui.weak("Select a service to see how it is turned on, its policy and its log.");
            return;
        };
        ui.strong(s(r, "name"));
        Grid::new("services-detail")
            .num_columns(2)
            .spacing([12.0, 3.0])
            .show(ui, |ui| {
                let line = |ui: &mut Ui, k: &str, v: &str| {
                    ui.weak(k);
                    ui.label(if v.is_empty() { "–" } else { v });
                    ui.end_row();
                };
                ui.weak("Turned on by");
                ui.label(RichText::new(s(r, "enable")).monospace());
                ui.end_row();
                let deps: Vec<&str> = r
                    .get("depends")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                line(ui, "Depends on", &deps.join(", "));
                line(ui, "Restart policy", s(r, "policy"));
                let beat = n(r, "heartbeat_age_ms")
                    .map(|ms| format!("{:.1} s ago", ms as f64 / 1000.0))
                    .unwrap_or_default();
                line(ui, "Heartbeat", &beat);
                let threads = n(r, "threads").filter(|t| *t > 0).map(|t| t.to_string());
                line(ui, "Threads", threads.as_deref().unwrap_or(""));
                let fails = n(r, "recent_failures").unwrap_or(0);
                line(ui, "Recent failures", &fails.to_string());
                if let Some(e) = r.get("last_error").and_then(Value::as_str) {
                    ui.weak("Last error");
                    ui.colored_label(ui.visuals().error_fg_color, e);
                    ui.end_row();
                }
                if !s(r, "reason").is_empty() {
                    line(ui, "Why", s(r, "reason"));
                }
            });
        let topic = s(r, "topic");
        ui.add_space(4.0);
        ui.weak(format!("Log · {topic}"));
        let lines = match &self.log {
            Some((t, lines)) if t == topic => lines.as_slice(),
            _ => &[],
        };
        if lines.is_empty() {
            ui.weak("No lines with this topic in the log.");
        }
        let today = lines.iter().filter_map(|l| n(l, "time")).max().unwrap_or(0) / 86_400;
        for l in lines {
            ui.horizontal(|ui| {
                ui.label(RichText::new(short_time(n(l, "time").unwrap_or(0), today)).monospace());
                let msg = RichText::new(s(l, "message"));
                match s(l, "level") {
                    "error" | "critical" => ui.colored_label(ui.visuals().error_fg_color, msg),
                    "warning" => ui.colored_label(ui.visuals().warn_fg_color, msg),
                    _ => ui.label(msg),
                };
            });
        }
    }

    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        self.toolbar(app, ui);
        if let Some(n) = &self.notice {
            ui.weak(n);
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        ui.separator();
        if self.rows.is_empty() {
            ui.weak(
                "No supervised services: this session has no daemon (lab or browser). \
                 Connect to corerouter-daemon to see them.",
            );
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("services-rows")
            .max_height(ui.available_height() * 0.55)
            .show(ui, |ui| self.table(ui));
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("services-detail")
            .show(ui, |ui| self.detail(ui));
    }
}

/// The first socket with its reach chip, `+N` for the rest (all in the tooltip).
fn listen_cell(ui: &mut Ui, r: &Value, v: &egui::Visuals) {
    let all: Vec<&Value> = r
        .get("listen")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let resp = ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let Some(first) = all.first() else {
            ui.weak("–");
            return;
        };
        ui.add(
            egui::Label::new(format!("{} {}", s(first, "proto"), s(first, "address")))
                .selectable(false),
        );
        let (text, tone, _) = scope_chip(v, s(first, "scope"));
        chip(ui, text, tone);
        if all.len() > 1 {
            ui.weak(format!("+{}", all.len() - 1));
        }
    });
    if !all.is_empty() {
        let tip: Vec<String> = all
            .iter()
            .map(|l| {
                let (_, _, why) = scope_chip(v, s(l, "scope"));
                format!("{} {} — {why}", s(l, "proto"), s(l, "address"))
            })
            .collect();
        resp.response.on_hover_text(tip.join("\n"));
    }
}

impl PanelState for ServicesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(PRINT) {
            return Vec::new();
        }
        let mut q = vec![Query {
            key: "print",
            command: PRINT,
            params: json!({}),
        }];
        let topic = self
            .selected
            .as_deref()
            .and_then(|n| self.row(n))
            .map(|r| s(r, "topic"))
            .filter(|t| !t.is_empty());
        if let Some(t) = topic
            && app.has_command(LOG)
        {
            q.push(Query {
                key: "log",
                command: LOG,
                params: json!({ "topics": [t], "limit": LOG_LINES }),
            });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let Some(rows) = value.as_array() else {
            return;
        };
        match key {
            "print" => {
                self.rows = rows.clone();
                if let Some(n) = &self.selected
                    && self.row(n).is_none()
                {
                    self.selected = None;
                }
            }
            "log" => {
                let topic = self
                    .selected
                    .as_deref()
                    .and_then(|n| self.row(n))
                    .map(|r| s(r, "topic").to_owned())
                    .unwrap_or_default();
                self.log = Some((topic, rows.clone()));
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn reply(&mut self, _app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(a) = then.downcast::<Acted>() else {
            return;
        };
        let action = a.0.rsplit('.').next().unwrap_or(a.0);
        match result {
            Ok(v) => {
                self.error = None;
                self.notice = Some(format!("{action} sent to {}", s(v, "name")));
            }
            Err(e) => {
                self.notice = None;
                self.error = Some(format!("{action}: {e}"));
            }
        }
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.selected.take().is_some()
    }
}

//! The Log window (G4.6d), WinBox `/log` style: the router's own log, what
//! `/system logging` sends to the `memory` action — configuration changes,
//! DHCP, NTP, the tools — one line per event with its time, topics, origin
//! (`daemon`, or the account and channel: `admin · GUI`) and a message for
//! people. "Técnico" adds, under each message, the command, its parameters,
//! its result and the revision it created.
//!
//! The engine keeps and numbers the lines (`log.print`); the window asks
//! only for the lines after the last one it has (`since`) and filters what
//! it holds (topic, "only warnings and errors", find) on its own, at once.
//! Times are the router's clock in UTC (no time zone yet); a line from
//! another day than the newest one shows its date.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use egui::{Grid, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::ntp_client::utc;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win};

const NAME: &str = "log";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "log";
const PRINT: &str = "log.print";
const CLEAR: &str = "log.clear";
/// Lines the window holds at most (the router keeps `memory_lines`).
pub(crate) const MAX_LINES: usize = 5000;
/// Characters of a technical line drawn (the rest is cut with "…").
const MAX_TECH: usize = 400;
/// Topics offered in the filter: what, not how bad.
const TOPICS: &[&str] = &[
    "account",
    "dhcp",
    "dns",
    "firewall",
    "interface",
    "ntp",
    "route",
    "system",
    "tool",
];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Log",
        title: "Log",
        size: [960.0, 420.0],
        escape: true,
    }],
    new: || Box::new(LogPanel::default()),
};

/// One line of the log, as `log.print` sends it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Line {
    pub seq: u64,
    pub time: u64,
    pub topics: Vec<String>,
    pub level: String,
    pub origin: String,
    pub message: String,
    pub detail: Value,
}

impl Line {
    fn of(v: &Value) -> Option<Self> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        Some(Self {
            seq: v.get("seq").and_then(Value::as_u64)?,
            time: v.get("time").and_then(Value::as_u64).unwrap_or(0),
            topics: v
                .get("topics")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                .unwrap_or_default(),
            level: s("level"),
            origin: s("origin"),
            message: s("message"),
            detail: v.get("detail").cloned().unwrap_or(Value::Null),
        })
    }

    fn problem(&self) -> bool {
        matches!(self.level.as_str(), "warning" | "error" | "critical")
    }

    /// `#12 ip.address.add {"address":…} → {"id":"*1"} (revisão 3)`.
    pub(crate) fn technical(&self) -> String {
        let d = &self.detail;
        let mut out = format!("#{}", self.seq);
        if let Some(cmd) = d.get("command").and_then(Value::as_str) {
            out.push(' ');
            out.push_str(cmd);
            match d.get("params") {
                None | Some(Value::Null) => {}
                Some(Value::Object(m)) if m.is_empty() => {}
                Some(p) => {
                    out.push(' ');
                    out.push_str(&p.to_string());
                }
            }
            if let Some(e) = d.get("error").and_then(Value::as_str) {
                out.push_str(" → erro: ");
                out.push_str(e);
            } else if let Some(r) = d.get("result").filter(|r| !r.is_null()) {
                out.push_str(" → ");
                out.push_str(&r.to_string());
            }
            if let Some(rev) = d.get("revision").and_then(Value::as_u64) {
                out.push_str(&format!(" (revisão {rev})"));
            }
        } else if !d.is_null() {
            out.push(' ');
            out.push_str(&d.to_string());
        }
        cut(&out, MAX_TECH)
    }
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    s.chars().take(max).collect::<String>() + "…"
}

/// `13:05:09`, or `2026-10-21 13:05:09` on another day than `today` (Unix
/// days); `—` without a clock.
pub(crate) fn short_time(time: u64, today: u64) -> String {
    if time == 0 {
        return "—".into();
    }
    let full = utc(time);
    let full = full.trim_end_matches(" UTC");
    if time / 86_400 == today {
        full.get(11..).unwrap_or(full).to_owned()
    } else {
        full.to_owned()
    }
}

/// The Log window: the lines it has and its filters.
#[derive(Default)]
pub(crate) struct LogPanel {
    pub(crate) lines: Vec<Line>,
    /// `seq` of the newest line held: the next `log.print` asks after it.
    last_seq: u64,
    pub(crate) technical: bool,
    /// One of [`TOPICS`], or empty: all.
    pub(crate) topic: String,
    pub(crate) only_problems: bool,
    pub(crate) find: String,
    /// The view stays where it is instead of following new lines.
    pub(crate) paused: bool,
    pub(crate) error: Option<String>,
}

/// A Clear's reply.
struct Cleared;

impl LogPanel {
    /// The lines that pass the filters, oldest first.
    pub(crate) fn shown(&self) -> Vec<&Line> {
        let find = self.find.trim().to_lowercase();
        self.lines
            .iter()
            .filter(|l| self.topic.is_empty() || l.topics.contains(&self.topic))
            .filter(|l| !self.only_problems || l.problem())
            .filter(|l| {
                find.is_empty()
                    || l.message.to_lowercase().contains(&find)
                    || l.origin.to_lowercase().contains(&find)
                    || l.topics.iter().any(|t| t.contains(&find))
            })
            .collect()
    }

    fn take(&mut self, rows: &[Value]) {
        for l in rows.iter().filter_map(Line::of) {
            // Two refreshes in flight ask for the same lines: keep one.
            if l.seq > self.last_seq {
                self.last_seq = l.seq;
                self.lines.push(l);
            }
        }
        if self.lines.len() > MAX_LINES {
            let extra = self.lines.len() - MAX_LINES;
            self.lines.drain(..extra);
        }
    }

    fn reset(&mut self) {
        self.lines.clear();
        self.last_seq = 0;
    }

    fn toolbar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.technical, false, "Legível")
                .on_hover_text("A mensagem de cada evento, para pessoas");
            ui.selectable_value(&mut self.technical, true, "Técnico").on_hover_text(
                "Também o comando, os parâmetros, o resultado e a revisão criada",
            );
            ui.separator();
            egui::ComboBox::from_id_salt("log-topic")
                .selected_text(if self.topic.is_empty() {
                    "Todos os tópicos"
                } else {
                    self.topic.as_str()
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.topic, String::new(), "Todos os tópicos");
                    for t in TOPICS {
                        ui.selectable_value(&mut self.topic, (*t).to_owned(), *t);
                    }
                });
            ui.checkbox(&mut self.only_problems, "Só avisos e erros");
            ui.add(
                TextEdit::singleline(&mut self.find)
                    .hint_text("Buscar")
                    .desired_width(160.0),
            );
            ui.separator();
            let pause = if self.paused { "Seguir" } else { "Pausar" };
            if ui
                .selectable_label(self.paused, pause)
                .on_hover_text("Parar de rolar para as linhas novas (elas continuam chegando)")
                .clicked()
            {
                self.paused = !self.paused;
            }
            if action(ui, "Limpar", app.can().check(CLEAR)) {
                app.run_then(CLEAR, json!({}), crate::panel::then(NAME, Cleared));
            }
        });
    }

    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        self.toolbar(app, ui);
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        let shown = self.shown();
        ui.weak(format!("{} de {} linhas", shown.len(), self.lines.len()));
        let today = self.lines.iter().map(|l| l.time).max().unwrap_or(0) / 86_400;
        let (err, warn) = (ui.visuals().error_fg_color, ui.visuals().warn_fg_color);
        let technical = self.technical;
        ScrollArea::both()
            .auto_shrink([false, false])
            .stick_to_bottom(!self.paused)
            .show(ui, |ui| {
                Grid::new("log-lines")
                    .num_columns(4)
                    .striped(true)
                    .spacing([12.0, 3.0])
                    .show(ui, |ui| {
                        for h in ["Hora", "Tópicos", "Origem", "Mensagem"] {
                            ui.label(RichText::new(h).strong());
                        }
                        ui.end_row();
                        for l in &shown {
                            let time = ui.label(RichText::new(short_time(l.time, today)).monospace());
                            if l.time > 0 {
                                time.on_hover_text(utc(l.time));
                            }
                            ui.label(l.topics.join(","));
                            ui.label(if l.origin.is_empty() { "—" } else { &l.origin });
                            let mut msg = RichText::new(&l.message);
                            msg = match l.level.as_str() {
                                "error" | "critical" => msg.color(err),
                                "warning" => msg.color(warn),
                                "debug" => msg.weak(),
                                _ => msg,
                            };
                            if technical {
                                ui.vertical(|ui| {
                                    ui.label(msg);
                                    ui.label(RichText::new(l.technical()).monospace().weak());
                                });
                            } else {
                                ui.label(msg);
                            }
                            ui.end_row();
                        }
                    });
                if shown.is_empty() {
                    ui.weak(if self.lines.is_empty() {
                        "Nada no log ainda."
                    } else {
                        "Nenhuma linha passa nos filtros."
                    });
                }
            });
    }
}

impl PanelState for LogPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(PRINT) {
            return Vec::new();
        }
        let mut q = vec![Query {
            key: "new",
            command: PRINT,
            params: json!({ "since": self.last_seq }),
        }];
        if self.last_seq > 0 {
            // The newest line the router has: older than ours means it
            // restarted (the numbering starts again).
            q.push(Query {
                key: "head",
                command: PRINT,
                params: json!({ "limit": 1 }),
            });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let Some(rows) = value.as_array() else {
            return;
        };
        match key {
            "new" => self.take(rows),
            "head" => {
                let newest = rows.last().and_then(|r| r.get("seq")).and_then(Value::as_u64);
                if newest.is_none_or(|n| n < self.last_seq) {
                    self.reset();
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn reply(&mut self, _app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast::<Cleared>().is_err() {
            return;
        }
        match result {
            Ok(_) => {
                self.error = None;
                self.reset();
            }
            Err(e) => self.error = Some(e.clone()),
        }
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        if self.find.is_empty() {
            false
        } else {
            self.find.clear();
            true
        }
    }
}

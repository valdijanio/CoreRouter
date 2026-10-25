//! System › OS Log (G4.8b): the operating system's log under the router —
//! kernel, services, logins — distinct from the router's own Log window
//! (`system_log.rs`, the engine's events). The approved layout (option A
//! of System › Resources): level chips with their counts (`error 3`,
//! `warning 12`, `info`), source chips (kernel, services, auth), the find
//! box (text, unit, PID), a table of Time, Level, Source and Message where
//! a line that repeats is one row with a count chip (`37×`), and, under
//! it, the selected line in detail: source, driver/unit, device, priority,
//! boot, "repetido 37× em 9 min", the whole message and, for a message the
//! router knows, "O que significa" with buttons to the window that fixes
//! it ("Abrir Tuning › ether2", "Ver no gráfico").
//!
//! The engine keeps, folds and explains the lines (`log.os.print`); this
//! panel only asks for the rows changed after the last one it has
//! (`since`), holds at most [`MAX_ROWS`] and filters them itself, at once.
//! The table draws only the rows in view (virtualized), so 20 000 rows cost
//! what 30 do. It is its own window and also the OS Log tab of System ›
//! Resources (G4.8a), which calls [`tab`].

use std::cell::Cell;
use std::collections::HashMap;

use egui::{Align2, Grid, RichText, ScrollArea, Sense, TextEdit, Ui, vec2};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, AMBER, BLUE, GREEN, Kind, RED};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::{CoreRouterUi, Win};

const NAME: &str = "os-log";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "os-log";
const PRINT: &str = "log.os.print";
const SCOPE: &str = "os_log";
/// Rows held at most (the router keeps as many).
pub(crate) const MAX_ROWS: usize = 20_000;
/// Height of the detail pane under the table.
const DETAIL_H: f32 = 190.0;
/// Left edge of each column in a row (header and cells).
const COL_TIME: f32 = 6.0;
const COL_LEVEL: f32 = 172.0;
const COL_SOURCE: f32 = 256.0;
const COL_MESSAGE: f32 = 446.0;
const LEVELS: [(&str, &str); 3] = [("error", "error"), ("warning", "warning"), ("info", "info")];
const SOURCES: [&str; 3] = ["kernel", "services", "auth"];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "OS Log",
        size: [1040.0, 640.0],
        escape: true,
    }],
    new: || Box::new(OsLogPanel::default()),
};

fn t(l: Lang, en: &'static str) -> &'static str {
    tr_in(SCOPE, l, en)
}

/// Where a known message's button goes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Action {
    pub label: String,
    pub window: String,
    pub command: String,
    pub device: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Known {
    pub id: String,
    pub title: String,
    pub meaning: String,
    pub actions: Vec<Action>,
}

/// One row as `log.os.print` sends it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Row {
    pub id: u64,
    pub seq: u64,
    pub time_us: u64,
    pub first: u64,
    pub level: String,
    pub severity: u8,
    pub source: String,
    pub unit: String,
    pub device: String,
    pub pid: Option<u64>,
    pub message: String,
    pub count: u64,
    pub boot: String,
    pub this_boot: bool,
    pub known: Option<Known>,
    /// Lower-cased message, unit, device and pid, for the find box.
    hay: String,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

impl Row {
    fn of(v: &Value) -> Option<Self> {
        let known = v.get("known").filter(|k| k.is_object()).map(|k| Known {
            id: s(k, "id"),
            title: s(k, "title"),
            meaning: s(k, "meaning"),
            actions: k
                .get("actions")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|a| Action {
                            label: s(a, "label"),
                            window: s(a, "window"),
                            command: s(a, "command"),
                            device: s(a, "device"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        });
        let pid = v.get("pid").and_then(Value::as_u64);
        let (message, unit, device) = (s(v, "message"), s(v, "unit"), s(v, "device"));
        let hay = format!(
            "{}\u{1}{}\u{1}{}\u{1}{}",
            message.to_lowercase(),
            unit.to_lowercase(),
            device.to_lowercase(),
            pid.map(|p| p.to_string()).unwrap_or_default()
        );
        Some(Self {
            id: v.get("id").and_then(Value::as_u64)?,
            seq: v.get("seq").and_then(Value::as_u64).unwrap_or(0),
            time_us: v.get("time_us").and_then(Value::as_u64).unwrap_or(0),
            first: v.get("first").and_then(Value::as_u64).unwrap_or(0),
            level: s(v, "level"),
            severity: v
                .get("severity")
                .and_then(Value::as_u64)
                .and_then(|n| u8::try_from(n.min(7)).ok())
                .unwrap_or(6),
            source: s(v, "source"),
            unit,
            device,
            pid,
            message,
            count: v.get("count").and_then(Value::as_u64).unwrap_or(1),
            boot: s(v, "boot"),
            this_boot: v.get("this_boot").and_then(Value::as_bool).unwrap_or(false),
            known,
            hay,
        })
    }

    /// The level chip: `error`, `warning`, `info` (5–7).
    fn bucket(&self) -> &'static str {
        match self.severity {
            0..=3 => "error",
            4 => "warning",
            _ => "info",
        }
    }

    fn secs(&self) -> u64 {
        self.time_us / 1_000_000
    }
}

fn level_kind(severity: u8) -> Kind {
    match severity {
        0..=3 => Kind::Red,
        4 => Kind::Amber,
        5 => Kind::Blue,
        _ => Kind::Neutral,
    }
}

/// "repetido 37× em 9 min" (Portuguese: it is an explanation).
pub(crate) fn repeated(count: u64, first: u64, last: u64) -> String {
    if count <= 1 {
        return "uma vez".into();
    }
    let span = last.saturating_sub(first);
    let when = if span < 60 {
        format!("{span} s")
    } else if span < 3600 {
        format!("{} min", span / 60)
    } else {
        format!("{} h {} min", span / 3600, span % 3600 / 60)
    };
    format!("repetido {count}× em {when}")
}

#[derive(Default)]
pub(crate) struct OsLogPanel {
    rows: HashMap<u64, Row>,
    /// Ids by time, oldest first; then those the filters let through.
    order: Vec<u64>,
    pub(crate) shown: Vec<u64>,
    dirty: bool,
    last_seq: u64,
    /// Level and source chips turned on (none on: all).
    pub(crate) levels: [bool; 3],
    pub(crate) sources: [bool; 3],
    pub(crate) find: String,
    filtered_by: (String, [bool; 3], [bool; 3]),
    pub(crate) selected: Option<u64>,
    pub(crate) counts: [u64; 3],
    pub(crate) states: Vec<Value>,
    total: u64,
    /// The view stays where it is instead of following new rows.
    pub(crate) paused: bool,
    pub(crate) help: Option<HelpView>,
    /// Drawn as Resources' tab since the last refresh: ask for rows then
    /// too.
    tab_seen: Cell<bool>,
}

impl OsLogPanel {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    #[cfg(test)]
    pub(crate) fn row(&self, id: u64) -> Option<&Row> {
        self.rows.get(&id)
    }

    /// Take a reply's rows: a row seen before is replaced (a repeat moved
    /// it), the oldest go past [`MAX_ROWS`].
    pub(crate) fn take(&mut self, v: &Value) {
        if let Some(last) = v.get("last").and_then(Value::as_u64)
            && last < self.last_seq
        {
            // The router restarted: its numbering starts again.
            self.reset();
        }
        for r in v
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Row::of)
        {
            self.last_seq = self.last_seq.max(r.seq);
            self.rows.insert(r.id, r);
            self.dirty = true;
        }
        if let Some(c) = v.get("counts") {
            let n = |k: &str| c.get(k).and_then(Value::as_u64).unwrap_or(0);
            self.counts = [n("error"), n("warning"), n("info")];
        }
        if let Some(st) = v.get("sources").and_then(Value::as_array) {
            self.states = st.clone();
        }
        self.total = v.get("total").and_then(Value::as_u64).unwrap_or(self.total);
        if self.rows.len() > MAX_ROWS {
            self.resort();
            let extra = self.rows.len() - MAX_ROWS;
            for id in self.order.drain(..extra) {
                self.rows.remove(&id);
            }
        }
    }

    fn reset(&mut self) {
        self.rows.clear();
        self.order.clear();
        self.shown.clear();
        self.last_seq = 0;
        self.selected = None;
        self.dirty = true;
    }

    fn resort(&mut self) {
        let mut order: Vec<(u64, u64)> = self.rows.values().map(|r| (r.time_us, r.id)).collect();
        order.sort_unstable();
        self.order = order.into_iter().map(|(_, id)| id).collect();
    }

    /// Recompute the shown rows when rows or filters changed.
    pub(crate) fn refilter(&mut self) {
        let key = (self.find.trim().to_lowercase(), self.levels, self.sources);
        if !self.dirty && key == self.filtered_by {
            return;
        }
        if self.dirty {
            self.resort();
        }
        let any_level = !self.levels.contains(&true);
        let any_source = !self.sources.contains(&true);
        let find = key.0.clone();
        let rows = &self.rows;
        self.shown = self
            .order
            .iter()
            .copied()
            .filter(|id| {
                let Some(r) = rows.get(id) else { return false };
                (any_level
                    || LEVELS
                        .iter()
                        .zip(self.levels)
                        .any(|((l, _), on)| on && *l == r.bucket()))
                    && (any_source
                        || SOURCES.iter().zip(self.sources).any(|(s, on)| on && *s == r.source))
                    && (find.is_empty() || r.hay.contains(&find))
            })
            .collect();
        self.filtered_by = key;
        self.dirty = false;
    }

    fn toolbar(&mut self, app: &CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal_wrapped(|ui| {
            for (i, (key, label)) in LEVELS.iter().enumerate() {
                let n = self.counts.get(i).copied().unwrap_or(0);
                let text = if *key == "info" {
                    (*label).to_owned()
                } else {
                    format!("{label} {n}")
                };
                if let Some(on) = self.levels.get_mut(i)
                    && crate::list::filter_chip(ui, &text, *on)
                {
                    *on = !*on;
                }
            }
            if help::info_button(ui, ui.scope_id().with("oslog-levels"), t(l, "Levels")).clicked() {
                self.help = Some(HelpView::new("os_log.level", t(l, "Level")));
            }
            ui.separator();
            for (i, src) in SOURCES.iter().enumerate() {
                if let Some(on) = self.sources.get_mut(i)
                    && crate::list::filter_chip(ui, src, *on)
                {
                    *on = !*on;
                }
            }
            if help::info_button(ui, ui.scope_id().with("oslog-sources"), t(l, "Sources")).clicked() {
                self.help = Some(HelpView::new("os_log.source", t(l, "Source")));
            }
            ui.separator();
            ui.add(
                TextEdit::singleline(&mut self.find)
                    .hint_text(t(l, "Find: text, unit, PID"))
                    .desired_width(200.0),
            );
            if help::info_button(ui, ui.scope_id().with("oslog-find"), t(l, "Find")).clicked() {
                self.help = Some(HelpView::new("os_log.find", t(l, "Find")));
            }
            ui.separator();
            let follow = if self.paused { t(l, "Follow") } else { t(l, "Pause") };
            if ui
                .selectable_label(self.paused, follow)
                .on_hover_text(t(l, "Stop scrolling to new rows (they keep arriving)"))
                .clicked()
            {
                self.paused = !self.paused;
            }
        });
        // How each source is: a green chip, or red with the reason.
        ui.horizontal_wrapped(|ui| {
            ui.weak(t(l, "Sources:"));
            for st in &self.states {
                let name = s(st, "name");
                let lines = st.get("lines").and_then(Value::as_u64).unwrap_or(0);
                if st.get("ok").and_then(Value::as_bool) == Some(true) {
                    chip::chip(ui, &name, GREEN.tone(ui.visuals()))
                        .on_hover_text(format!("{lines} {}", t(l, "lines read")));
                } else {
                    let why = s(st, "reason");
                    chip::chip(ui, &format!("{name} {}", t(l, "unavailable")), RED.tone(ui.visuals()))
                        .on_hover_text(why);
                }
            }
            if help::info_button(ui, ui.scope_id().with("oslog-states"), t(l, "Sources")).clicked() {
                self.help = Some(HelpView::new("os_log.sources", t(l, "Sources")));
            }
        });
    }

    /// The table: a header with ⓘ, then only the rows in view.
    fn table(&mut self, app: &CoreRouterUi, ui: &mut Ui, height: f32) {
        let l = app.lang.labels;
        let row_h = ui.spacing().interact_size.y;
        let font = egui::TextStyle::Body.resolve(ui.style());
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let size = chip::small(ui);
        let cols: [(&str, &str, f32); 4] = [
            ("Time", "os_log.time", COL_TIME),
            ("Level", "os_log.level", COL_LEVEL),
            ("Source", "os_log.source", COL_SOURCE),
            ("Message", "os_log.message", COL_MESSAGE),
        ];
        let today = self.rows.values().map(Row::secs).max().unwrap_or(0) / 86_400;
        // Header, at the same offsets as the cells below.
        let (head, _) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::hover());
        for (title, key, x) in cols {
            let at = egui::Rect::from_min_size(
                egui::pos2(head.left() + x, head.top()),
                vec2(170.0, row_h),
            );
            let clicked = ui
                .scope_builder(
                    egui::UiBuilder::new()
                        .max_rect(at)
                        .layout(egui::Layout::left_to_right(egui::Align::Center)),
                    |ui| {
                        ui.label(RichText::new(t(l, title)).strong());
                        help::info_button(ui, ui.scope_id().with(("oslog-col", key)), t(l, title))
                            .clicked()
                    },
                )
                .inner;
            if clicked {
                self.help = Some(HelpView::new(key, t(l, title)));
            }
        }
        ui.separator();
        let visuals = ui.visuals().clone();
        let n = self.shown.len();
        let mut clicked = None;
        let mut area = ScrollArea::vertical()
            .id_salt("oslog-rows")
            .auto_shrink([false, false])
            .max_height(height.max(row_h * 3.0))
            .stick_to_bottom(!self.paused);
        if n == 0 {
            area = area.max_height(row_h * 2.0);
        }
        area.show_rows(ui, row_h, n, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for id in self.shown.get(range).unwrap_or(&[]) {
                let Some(r) = self.rows.get(id) else { continue };
                let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::hover());
                let resp = ui.interact(rect, ui.scope_id().with(("oslog-row", r.id)), Sense::click());
                let selected = self.selected == Some(r.id);
                let p = ui.painter_at(rect);
                if selected {
                    p.rect_filled(rect, 0.0, visuals.selection.bg_fill);
                } else if resp.hovered() {
                    p.rect_filled(rect, 0.0, visuals.widgets.hovered.weak_bg_fill);
                }
                let ink = if selected {
                    visuals.selection.stroke.color
                } else {
                    visuals.text_color()
                };
                let y = rect.center().y;
                let mut x = rect.left() + COL_TIME;
                p.text(
                    egui::pos2(x, y),
                    Align2::LEFT_CENTER,
                    crate::system_log::short_time(r.secs(), today),
                    mono.clone(),
                    ink,
                );
                x = rect.left() + COL_LEVEL;
                chip::paint_cell_chips(&p, &visuals, x - 6.0, y, row_h, &[(level_kind(r.severity), r.level.as_str())], size);
                x = rect.left() + COL_SOURCE;
                chip::paint_cell_chips(&p, &visuals, x - 6.0, y, row_h, &[(Kind::Neutral, r.source.as_str())], size);
                let src_w = chip::cell_chip_width(&p, &r.source, size);
                let unit = if r.unit.is_empty() { r.device.as_str() } else { r.unit.as_str() };
                p.text(egui::pos2(x + src_w + 2.0, y), Align2::LEFT_CENTER, cut(unit, 18), font.clone(), if selected { ink } else { visuals.weak_text_color() });
                x = rect.left() + COL_MESSAGE;
                // Count and known-message chips, then the message's first line.
                let count = format!("{}×", r.count);
                let mut chips: Vec<(Kind, &str)> = Vec::new();
                if r.count > 1 {
                    chips.push((Kind::Amber, count.as_str()));
                }
                if let Some(k) = &r.known {
                    chips.push((Kind::Blue, k.title.as_str()));
                }
                if !chips.is_empty() {
                    chip::paint_cell_chips(&p, &visuals, x - 6.0, y, row_h, &chips, size);
                    x += chip::cell_chips_width(&p, &chips, size) + 2.0;
                }
                let first = r.message.lines().next().unwrap_or("");
                let mut job = egui::text::LayoutJob::single_section(
                    first.chars().take(400).collect(),
                    egui::TextFormat::simple(font.clone(), ink),
                );
                job.wrap = egui::text::TextWrapping {
                    max_width: (rect.right() - x - 6.0).max(10.0),
                    max_rows: 1,
                    break_anywhere: true,
                    overflow_character: Some('…'),
                };
                let galley = ui.fonts_mut(|f| f.layout_job(job));
                p.galley(egui::pos2(x, y - galley.size().y / 2.0), galley, ink);
                if resp.clicked() {
                    clicked = Some(r.id);
                }
                if resp.hovered() && r.message.chars().count() > 60 {
                    resp.on_hover_text(cut(&r.message, 2000));
                }
            }
        });
        if let Some(id) = clicked {
            self.selected = if self.selected == Some(id) { None } else { Some(id) };
        }
        if n == 0 {
            ui.weak(if self.rows.is_empty() {
                t(l, "No lines yet.")
            } else {
                t(l, "No line passes the filters.")
            });
        }
    }

    fn detail(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let Some(r) = self.selected.and_then(|id| self.rows.get(&id)).cloned() else {
            ui.weak(t(l, "Click a row to see it in detail."));
            return;
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(t(l, "Details")).strong());
            if help::info_button(ui, ui.scope_id().with("oslog-detail"), t(l, "Details")).clicked() {
                self.help = Some(HelpView::new("os_log.details", t(l, "Details")));
            }
        });
        let mut help_req = None;
        let mut action = None;
        // Left: the line itself; right: what it means and where to go.
        ui.columns(2, |cols| {
            let [left, right] = cols else { return };
            ScrollArea::vertical()
                .id_salt("oslog-detail")
                .auto_shrink([false, true])
                .max_height(DETAIL_H)
                .show(left, |ui| {
                    Grid::new("oslog-detail-grid")
                        .num_columns(4)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.weak(t(l, "Source"));
                            ui.horizontal(|ui| {
                                chip::chip(ui, &r.source, chip::neutral_tone(ui.visuals()));
                            });
                            ui.weak(t(l, "Driver / unit"));
                            ui.label(if r.unit.is_empty() { "—" } else { &r.unit });
                            ui.end_row();
                            ui.weak(t(l, "Priority"));
                            ui.horizontal(|ui| {
                                chip::chip(ui, &format!("{} ({})", r.level, r.severity), level_kind(r.severity).tone(ui.visuals()));
                            });
                            ui.weak(t(l, "Device"));
                            ui.label(if r.device.is_empty() { "—" } else { &r.device });
                            ui.end_row();
                            ui.weak(t(l, "Boot"));
                            ui.horizontal(|ui| {
                                if r.this_boot {
                                    chip::chip(ui, t(l, "this boot"), GREEN.tone(ui.visuals()));
                                } else if !r.boot.is_empty() {
                                    chip::chip(ui, t(l, "earlier boot"), chip::neutral_tone(ui.visuals()));
                                }
                                ui.weak(r.boot.get(..8).unwrap_or(&r.boot));
                            });
                            ui.weak("PID");
                            ui.label(r.pid.map_or("—".to_owned(), |p| p.to_string()));
                            ui.end_row();
                            ui.weak(t(l, "Repeated"));
                            ui.horizontal(|ui| {
                                let text = repeated(r.count, r.first, r.secs());
                                if r.count > 1 {
                                    chip::chip(ui, &text, AMBER.tone(ui.visuals()));
                                } else {
                                    ui.label(text);
                                }
                                if help::info_button(ui, ui.scope_id().with("oslog-repeat"), t(l, "Repeated")).clicked() {
                                    help_req = Some(HelpView::new("os_log.repeat", t(l, "Repeated")));
                                }
                            });
                            ui.weak(t(l, "Time"));
                            let today = r.secs() / 86_400;
                            let short = |t| crate::system_log::short_time(t, today);
                            ui.label(if r.count > 1 {
                                format!("{} … {}", short(r.first), short(r.secs()))
                            } else {
                                short(r.secs())
                            })
                            .on_hover_text(crate::ntp_client::utc(r.secs()));
                            ui.end_row();
                        });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(RichText::new(cut(&r.message, 4000)).monospace()).wrap().selectable(true));
                    });
                    ui.horizontal(|ui| {
                        if ui.small_button(t(l, "Copy message")).clicked() {
                            ui.ctx().copy_text(r.message.clone());
                        }
                    });
                });
            ScrollArea::vertical()
                .id_salt("oslog-meaning")
                .auto_shrink([false, true])
                .max_height(DETAIL_H)
                .show(right, |ui| {
                    if let Some(k) = &r.known {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(t(l, "What it means")).strong());
                            chip::chip(ui, &k.title, BLUE.tone(ui.visuals()));
                            if help::info_button(ui, ui.scope_id().with("oslog-meaning"), t(l, "What it means")).clicked() {
                                help_req = Some(HelpView::new("os_log.meaning", t(l, "What it means")));
                            }
                        });
                        ui.add(egui::Label::new(&k.meaning).wrap());
                        ui.horizontal_wrapped(|ui| {
                            for a in &k.actions {
                                let can = target(&a.window).is_some();
                                let resp = chip::chip(ui, &a.label, if can { BLUE.tone(ui.visuals()) } else { chip::neutral_tone(ui.visuals()) })
                                    .interact(Sense::click())
                                    .on_hover_text(format!("{}: {}", t(l, "Command"), a.command));
                                if !can {
                                    resp.on_hover_text(t(l, "This window is not in this GUI yet"));
                                } else if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                    action = Some(a.clone());
                                }
                            }
                        });
                    } else {
                        ui.weak(t(l, "The router does not know this message yet."));
                    }
                });
        });
        if help_req.is_some() {
            self.help = help_req;
        }
        if let Some(a) = action {
            open_action(app, &a);
        }
    }

    pub(crate) fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        self.toolbar(app, ui);
        self.refilter();
        let l = app.lang.labels;
        let detail = if self.selected.is_some() { DETAIL_H + 60.0 } else { 40.0 };
        let footer = ui.spacing().interact_size.y + 8.0;
        let height = ui.available_height() - detail - footer;
        self.table(app, ui, height);
        ui.separator();
        ui.weak(format!(
            "{} {} · {} {} · {} {}",
            self.shown.len(),
            t(l, "shown"),
            self.rows.len(),
            t(l, "rows here"),
            self.total,
            t(l, "on the router")
        ));
        self.detail(app, ui);
    }
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    s.chars().take(max).collect::<String>() + "…"
}

/// The window a known message's button opens; `None`: not in this GUI.
fn target(window: &str) -> Option<Win> {
    match window {
        "interfaces" => Some(Win::Interfaces),
        "firewall" => Some(Win::Firewall),
        w => crate::panel::find(w).map(|(_, def)| Win::Panel(def.id)),
    }
}

fn open_action(app: &mut CoreRouterUi, a: &Action) {
    let Some(win) = target(&a.window) else {
        return;
    };
    if a.window == "tuning"
        && let Some(p) = app.panel_mut::<crate::tuning::TuningPanel>()
    {
        if a.command.contains("interface") && !a.device.is_empty() {
            p.tab = crate::tuning::Tab::Interfaces;
            p.port = Some(a.device.clone());
            p.port_print = None;
        } else {
            p.tab = crate::tuning::Tab::Kernel;
        }
    }
    if !app.open.insert(win) {
        app.floats.raise(crate::win_id(win));
    }
    app.cache.refreshed_at = None;
}

/// The OS Log tab of System › Resources (G4.8a): the same view, drawn
/// inside that window. Until that window lands only the tests call it.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn tab(app: &mut CoreRouterUi, ui: &mut Ui) {
    app.with_panel(NAME, |p, app| {
        let any: &mut dyn std::any::Any = p;
        if let Some(p) = any.downcast_mut::<OsLogPanel>() {
            p.tab_seen.set(true);
            p.draw(app, ui);
        }
    });
}

impl PanelState for OsLogPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let seen = self.tab_seen.replace(false);
        if !(seen || app.open.contains(&Win::Panel(WIN))) || !app.has_command(PRINT) {
            return Vec::new();
        }
        vec![Query {
            key: "rows",
            command: PRINT,
            params: json!({ "since": self.last_seq }),
        }]
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "rows" {
            self.take(&value);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        if !self.find.is_empty() {
            self.find.clear();
            true
        } else if self.selected.is_some() {
            self.selected = None;
            true
        } else {
            false
        }
    }
}

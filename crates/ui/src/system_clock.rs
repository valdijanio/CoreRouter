//! The System › Clock window (G4.6p), WinBox `/system clock` style, read
//! only: the router's time and date (UTC), where they came from (NTP, the
//! board's clock, the lab's host, never set) and the board's battery clock
//! (RTC) beside, with what writes it (G4.6o). The NTP Client window shows
//! the same first line ([`line`]).
//!
//! The engine says it all (`system.clock.print`); the window only shows.
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use egui::{Grid, Id, Ui};
use serde_json::Value;

use crate::backend::RequestId;
use crate::dhcp_client::text;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::{CoreRouterUi, Win};

const NAME: &str = "system-clock";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "system-clock";
pub(crate) const PRINT: &str = "system.clock.print";
/// The NTP windows' translations and explanations.
const SCOPE: &str = "ntp";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Clock",
        size: [460.0, 300.0],
        escape: false,
    }],
    new: || Box::new(ClockPanel::default()),
};

#[derive(Default)]
pub(crate) struct ClockPanel {
    /// `system.clock.print`, while the window is open.
    pub(crate) state: Option<Value>,
    help: Option<HelpView>,
}

impl PanelState for ClockPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) {
            vec![Query {
                key: "print",
                command: PRINT,
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "print" && value.is_object() {
            self.state = Some(value);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let Some(s) = self.state.clone() else {
            ui.weak(tr_in(SCOPE, l, "waiting for the router…"));
            return;
        };
        show(ui, &s, &mut self.help, l);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }
}

/// A label with its ⓘ; the explanation key is `ntp.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, name: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, name));
        if help::info_button(ui, Id::unique(("clock-help", key)), tr_in(SCOPE, l, name)).clicked() {
            *help = Some(HelpView::new(format!("ntp.{key}"), tr_in(SCOPE, l, name)));
        }
    });
}

/// The source as a chip in the theme's tones (docs/ui-style.md): NTP is
/// good, the board's clock or the lab's host is as good as they are, and
/// never set is wrong.
fn source_chip(ui: &mut Ui, source: &str) {
    let tone = match source {
        "ntp" => crate::chip::GREEN.tone(ui.visuals()),
        "not-set" => crate::chip::RED.tone(ui.visuals()),
        "rtc" | "host" => crate::chip::AMBER.tone(ui.visuals()),
        _ => crate::chip::neutral_tone(ui.visuals()),
    };
    crate::chip::chip(ui, source, tone);
}

/// What writes the RTC, as a chip: following the system is the installed
/// router's normal; left alone is the live image's (G4.6o).
fn written_chip(ui: &mut Ui, written: &str) {
    let tone = match written {
        "follows-system" => crate::chip::GREEN.tone(ui.visuals()),
        _ => crate::chip::neutral_tone(ui.visuals()),
    };
    crate::chip::chip(ui, written, tone);
}

/// `2026-11-12 14:02:31 UTC [ntp]`: the first line of the NTP Client
/// window and of this one.
pub(crate) fn line(ui: &mut Ui, s: &Value) {
    ui.horizontal(|ui| {
        ui.monospace(format!(
            "{} {} {}",
            text(s, "date"),
            text(s, "time"),
            text(s, "time_zone_name")
        ));
        source_chip(ui, &text(s, "source"));
    });
}

/// `−2 h 50 min`, `+3 h`, `0 s`: the RTC's distance from the system clock.
pub(crate) fn offset_text(secs: i64) -> String {
    let sign = if secs < 0 { "−" } else { "+" };
    let a = secs.unsigned_abs();
    match (a / 3_600, a % 3_600 / 60, a % 60) {
        (0, 0, s) if a == 0 => format!("{s} s"),
        (0, 0, s) => format!("{sign}{s} s"),
        (0, m, _) => format!("{sign}{m} min"),
        (h, 0, _) => format!("{sign}{h} h"),
        (h, m, _) => format!("{sign}{h} h {m} min"),
    }
}

fn show(ui: &mut Ui, s: &Value, help: &mut Option<HelpView>, l: Lang) {
    let hw = s.get("hardware_clock").cloned().unwrap_or(Value::Null);
    Grid::new("clock-print")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            label(ui, help, l, "clock_time", "Time");
            ui.monospace(text(s, "time"));
            ui.end_row();
            label(ui, help, l, "clock_date", "Date");
            ui.monospace(text(s, "date"));
            ui.end_row();
            label(ui, help, l, "clock_time_zone", "Time Zone");
            ui.label(format!("{} ({})", text(s, "time_zone_name"), text(s, "gmt_offset")));
            ui.end_row();
            label(ui, help, l, "clock_source", "Source");
            ui.horizontal(|ui| {
                source_chip(ui, &text(s, "source"));
                ui.weak(text(s, "source_detail"));
            });
            ui.end_row();
            if let Some(at) = s.get("last_sync").and_then(Value::as_u64) {
                label(ui, help, l, "last_sync", "Last Sync");
                ui.label(crate::ntp_client::utc(at));
                ui.end_row();
            }
            label(ui, help, l, "clock_hardware", "Hardware Clock");
            if hw.get("available").and_then(Value::as_bool) == Some(true) {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.monospace(format!("{} {}", text(&hw, "date"), text(&hw, "time")));
                        if let Some(o) = hw.get("offset_secs").and_then(Value::as_i64) {
                            ui.label(format!("({})", offset_text(o)));
                        }
                        written_chip(ui, &text(&hw, "written"));
                    });
                    let zone = text(&hw, "local_time_offset");
                    if !zone.is_empty() {
                        let drift = hw
                            .get("drift_secs")
                            .and_then(Value::as_i64)
                            .filter(|d| d.abs() >= 60)
                            .map(|d| format!(", {} {}", offset_text(d), tr_in(SCOPE, l, "of drift")))
                            .unwrap_or_default();
                        ui.colored_label(
                            ui.visuals().warn_fg_color,
                            format!(
                                "{} (UTC{zone}{drift})",
                                tr_in(SCOPE, l, "looks like local time, as Windows keeps it")
                            ),
                        );
                    }
                });
            } else {
                ui.weak(tr_in(SCOPE, l, "none"));
            }
            ui.end_row();
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_read_like_a_person_says_them() {
        assert_eq!(offset_text(-10_200), "−2 h 50 min");
        assert_eq!(offset_text(10_800), "+3 h");
        assert_eq!(offset_text(-600), "−10 min");
        assert_eq!(offset_text(2), "+2 s");
        assert_eq!(offset_text(0), "0 s");
    }
}

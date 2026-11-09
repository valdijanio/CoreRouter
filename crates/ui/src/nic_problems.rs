//! Interfaces: the network cards the kernel could not bring up in full
//! (G1.6ja). A card without a driver has no row in the table, so the toolbar's
//! chips are what shows it; click one for the list, with the file that went
//! missing and what to do. All from `interface.hardware.problems`: the rules
//! are the engine's.

use serde_json::Value;

use crate::backend::RequestId;
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::panel::{Panel, PanelState, Query};
use crate::windows::Win;
use crate::{CoreRouterUi, chip};

const SCOPE: &str = "nic_problems";
pub(crate) const COMMAND: &str = "interface.hardware.problems";
const HELP_KEY: &str = "nic_problems.overview";

pub(crate) const PANEL: Panel = Panel {
    name: "nic-problems",
    windows: &[],
    new: || Box::<NicProblems>::default(),
};

#[derive(Default)]
pub(crate) struct NicProblems {
    status: Value,
    open: bool,
    help: Option<HelpView>,
}

fn rows(status: &Value, key: &str) -> Vec<Value> {
    status.get(key).and_then(Value::as_array).cloned().unwrap_or_default()
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn expected(v: &Value) -> bool {
    v.get("expected").and_then(Value::as_bool).unwrap_or(false)
}

/// The chip's word for a kind.
fn word(kind: &str) -> &'static str {
    match kind {
        "no-driver" => "no driver",
        "safe-mode" => "safe mode",
        _ => "firmware",
    }
}

/// (word, how many) of what warns, in a fixed order, and the expected ones.
fn counts(status: &Value) -> (Vec<(&'static str, usize)>, usize) {
    let all = rows(status, "problems");
    let warn: Vec<(&'static str, usize)> = ["no-driver", "safe-mode", "firmware"]
        .into_iter()
        .map(|k| (word(k), all.iter().filter(|p| text(p, "kind") == k && !expected(p)).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    (warn, all.iter().filter(|p| expected(p)).count())
}

impl PanelState for NicProblems {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Interfaces) && app.has_command(COMMAND) {
            vec![Query { key: "problems", command: COMMAND, params: Value::Null }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, value: Value) {
        self.status = value;
    }

    fn window(&mut self, _: &mut CoreRouterUi, _: &'static str, _: &mut egui::Ui) {}

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        if !self.open {
            return;
        }
        let l = app.lang.labels;
        let problems = rows(&self.status, "problems");
        let ignored = rows(&self.status, "ignored");
        let kernel_log = self.status.get("kernel_log").and_then(Value::as_bool).unwrap_or(true);
        let mut close = false;
        let mut ask_help = false;
        egui::Modal::new(egui::Id::unique("nic-problems")).show(ctx, |ui| {
            ui.set_width(620.0);
            ui.horizontal(|ui| {
                ui.heading(tr_in(SCOPE, l, "Network card problems"));
                ask_help = help::info_button(ui, egui::Id::unique("nic-problems-help"), tr_in(SCOPE, l, "What this means")).clicked();
            });
            ui.separator();
            egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                if problems.is_empty() {
                    ui.label(tr_in(SCOPE, l, "Every network card has its driver and firmware."));
                }
                for p in &problems {
                    ui.horizontal_wrapped(|ui| {
                        let tone = if expected(p) { chip::neutral_tone(ui.visuals()) } else { chip::AMBER.tone(ui.visuals()) };
                        chip::chip(ui, tr_in(SCOPE, l, word(text(p, "kind"))), tone);
                        ui.strong(text(p, "name"));
                        ui.weak(text(p, "device"));
                    });
                    for f in rows(p, "files") {
                        ui.monospace(f.as_str().unwrap_or(""));
                    }
                    ui.label(text(p, "reason"));
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(tr_in(SCOPE, l, "What to do:"));
                        ui.label(text(p, "action"));
                    });
                    ui.separator();
                }
                if !ignored.is_empty() {
                    ui.weak(tr_in(SCOPE, l, "Without a driver, not a problem:"));
                    for i in &ignored {
                        ui.weak(format!("{} ({}): {}", text(i, "name"), text(i, "device"), text(i, "why")));
                    }
                }
                if !kernel_log {
                    ui.colored_label(ui.visuals().warn_fg_color, tr_in(SCOPE, l, "The kernel's log cannot be read here: a missing firmware file would not show."));
                }
            });
            ui.separator();
            close = ui.button(tr_in(SCOPE, l, "Close")).clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape));
        });
        if ask_help {
            self.help = Some(HelpView::new(HELP_KEY, tr_in(SCOPE, l, "Network card problems")));
        }
        if close {
            self.open = false;
        }
    }
}

#[cfg(test)]
impl NicProblems {
    pub(crate) fn counts_for_test(&self) -> (Vec<(&'static str, usize)>, usize) {
        counts(&self.status)
    }
}

impl CoreRouterUi {
    /// The chips of the Interfaces toolbar; nothing while all is well.
    pub(crate) fn nic_problem_chips(&mut self, ui: &mut egui::Ui) {
        let l = self.lang.labels;
        let Some(panel) = self.panel_mut::<NicProblems>() else {
            return;
        };
        let (warn, notes) = counts(&panel.status);
        let mut clicked = false;
        for (what, n) in warn {
            let label = format!("{n} {}", tr_in(SCOPE, l, what));
            clicked |= chip::chip(ui, &label, chip::AMBER.tone(ui.visuals()))
                .interact(egui::Sense::click())
                .on_hover_text(tr_in(SCOPE, l, "Click for the card, the missing file and what to do"))
                .clicked();
        }
        if notes > 0 {
            let label = format!("{notes} {}", tr_in(SCOPE, l, "until installed"));
            clicked |= chip::chip(ui, &label, chip::neutral_tone(ui.visuals()))
                .interact(egui::Sense::click())
                .on_hover_text(tr_in(SCOPE, l, "Normal on the ISO, which has no firmware files: the installed image has them"))
                .clicked();
        }
        if clicked {
            panel.open = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn counts_by_kind_and_apart_what_is_expected() {
        let s = json!({"problems": [
            {"kind": "no-driver", "expected": false},
            {"kind": "no-driver", "expected": false},
            {"kind": "safe-mode", "expected": false},
            {"kind": "firmware", "expected": true},
        ]});
        assert_eq!(counts(&s), (vec![("no driver", 2), ("safe mode", 1)], 1));
        assert_eq!(counts(&json!({})), (vec![], 0));
    }
}

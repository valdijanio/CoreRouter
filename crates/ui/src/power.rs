//! System › Reboot and System › Shutdown (G1.6qh), the items WinBox has. The
//! window is the question: what goes down, what the router would refuse and
//! what clears it (`system.power.preview`), `force`, and after the answer how
//! the connection is doing. The rules are the engine's (`cmd/system_power.rs`);
//! nothing is sent before the operator presses the button.

use egui::Ui;
use serde_json::{Value, json};

use crate::backend::{Link, RequestId};
use crate::chip::{AMBER, BLUE, GREEN, chip, neutral_tone};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{self, Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win};

const NAME: &str = "power";
const SCOPE: &str = "power";
pub(crate) const REBOOT: &str = "reboot";
pub(crate) const SHUTDOWN: &str = "shutdown";
const PREVIEW: &str = "system.power.preview";
/// How long after a reboot the window only waits, before it says where to look.
const COMEBACK_SECS: f64 = 180.0;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[
        WinDef { id: REBOOT, group: "System", title: "Reboot", size: [500.0, 400.0], escape: true },
        WinDef { id: SHUTDOWN, group: "System", title: "Shutdown", size: [500.0, 400.0], escape: true },
    ],
    new: || Box::new(PowerPanel::default()),
};

fn t(lang: Lang, s: &'static str) -> &'static str {
    tr_in(SCOPE, lang, s)
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// One window's question.
#[derive(Default)]
struct Ask {
    preview: Value,
    force: bool,
    error: Option<String>,
    notice: Option<String>,
}

/// The router said yes: what the window watches now.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Going {
    /// `ctx` time of the answer, set by the next frame.
    since: Option<f64>,
    /// The connection dropped: the next `Connected` is the router back.
    dropped: bool,
    back: bool,
}

/// Replies of the commands sent here.
enum Sent {
    Go(&'static str),
    Fix(&'static str),
}

#[derive(Default)]
pub(crate) struct PowerPanel {
    reboot: Ask,
    shutdown: Ask,
    /// The one request in progress (window, state): a router stops once.
    going: Option<(&'static str, Going)>,
    /// Cancel was pressed: closed outside the drawing of the windows.
    closing: Option<&'static str>,
    help: Option<HelpView>,
}

impl PowerPanel {
    fn ask(&mut self, win: &str) -> &mut Ask {
        if win == SHUTDOWN { &mut self.shutdown } else { &mut self.reboot }
    }

    fn info(&mut self, ui: &mut Ui, key: &'static str, title: &str) {
        if help::info_button(ui, egui::Id::unique(("power-help", key, ui.layer_id())), title).clicked() {
            self.help = Some(HelpView::new(key, title));
        }
    }

    fn draw(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        let lang = app.lang.labels;
        let reboot = win != SHUTDOWN;
        let title = if reboot { t(lang, "Reboot") } else { t(lang, "Shutdown") };
        if let Some((w, going)) = self.going
            && w == win
        {
            self.draw_going(app, reboot, going, ui);
            return;
        }
        // Which router, in words: the title bar says only what.
        let identity = s(&app.cache.summary, "identity");
        ui.horizontal(|ui| {
            ui.heading(format!("{title} {identity}?"));
            self.info(ui, if reboot { "menu.reboot" } else { "menu.shutdown" }, title);
        });
        self.draw_impact(lang, reboot, win, ui);
        ui.separator();
        let fix = self.draw_blocks(app, win, ui);
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.label(if reboot {
                t(lang, "The connection comes back on its own after the boot: this window waits for it.")
            } else {
                t(lang, "The router stays off until someone turns it on. The connection then comes back on its own.")
            });
            self.info(ui, "power.comes_back", t(lang, "Connection"));
        });
        let a = self.ask(win);
        if let Some(n) = &a.notice {
            ui.weak(n);
        }
        if let Some(e) = &a.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        ui.add_space(6.0);
        let command = if reboot { "system.reboot" } else { "system.shutdown" };
        let can = app.can().check(command).and_then(|()| self.ready(win, lang));
        let mut cancel = false;
        let mut go = false;
        ui.horizontal(|ui| {
            cancel = ui.button(t(lang, "Cancel")).clicked();
            go = action(ui, title, can);
        });
        if cancel {
            self.closing = Some(win);
        }
        if go {
            let force = self.ask(win).force;
            let a = self.ask(win);
            a.error = None;
            a.notice = None;
            let mut params = json!({"confirm": true});
            if force
                && let Some(o) = params.as_object_mut()
            {
                o.insert("force".into(), json!(true));
            }
            app.run_then(command, params, panel::then(NAME, Sent::Go(win)));
        }
        if let Some((command, params)) = fix {
            let a = self.ask(win);
            a.error = None;
            a.notice = None;
            app.run_then(&command, params, panel::then(NAME, Sent::Fix(win)));
            app.cache.refreshed_at = None;
        }
    }

    /// Why the button is grey, from what the engine said.
    fn ready(&mut self, win: &str, lang: Lang) -> Result<(), String> {
        let a = self.ask(win);
        let blocks = a.preview.get("blocks").and_then(Value::as_array);
        if let Some(b) = blocks.into_iter().flatten().find(|b| b.get("forceable") == Some(&json!(false))) {
            return Err(s(b, "message").to_owned());
        }
        if a.preview.get("needs_force") == Some(&json!(true)) && !a.force {
            return Err(t(lang, "Clear what is above, or tick Force").to_owned());
        }
        Ok(())
    }

    fn draw_impact(&mut self, lang: Lang, reboot: bool, win: &str, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.strong(t(lang, "What goes down"));
            self.info(ui, "power.impact", t(lang, "What goes down"));
        });
        let v = ui.visuals().clone();
        ui.label(if reboot {
            t(lang, "Traffic through the router stops until the boot ends, and every connection to it drops.")
        } else {
            t(lang, "Traffic through the router stops, and every connection to it drops, until someone turns it on.")
        });
        let impact = self.ask(win).preview.get("impact").and_then(Value::as_array).cloned().unwrap_or_default();
        if !impact.is_empty() {
            ui.horizontal_wrapped(|ui| {
                for row in &impact {
                    let n = row.get("count").and_then(Value::as_u64).unwrap_or(0);
                    let label = match s(row, "what") {
                        "ppp-sessions" => t(lang, "PPP sessions"),
                        "bgp-sessions" => t(lang, "BGP sessions"),
                        "ospf-neighbors" => t(lang, "OSPF neighbors"),
                        _ => continue,
                    };
                    chip(ui, &format!("{n} {label}"), AMBER.tone(&v));
                }
            });
        }
    }

    /// The checks; a click on a check's button comes back as the command.
    fn draw_blocks(&mut self, app: &CoreRouterUi, win: &str, ui: &mut Ui) -> Option<(String, Value)> {
        let lang = app.lang.labels;
        let v = ui.visuals().clone();
        let preview = self.ask(win).preview.clone();
        let mut fix = None;
        ui.horizontal(|ui| {
            ui.strong(t(lang, "Checks"));
            self.info(ui, "power.checks", t(lang, "Checks"));
        });
        if preview.is_null() {
            ui.weak(t(lang, "Asking the router…"));
        }
        if preview.get("supported") == Some(&json!(false)) {
            ui.horizontal_wrapped(|ui| {
                chip(ui, t(lang, "not available"), neutral_tone(&v));
                ui.label(s(&preview, "reason"));
            });
        }
        let blocks = preview.get("blocks").and_then(Value::as_array).cloned().unwrap_or_default();
        if blocks.is_empty() && !preview.is_null() {
            ui.horizontal(|ui| {
                chip(ui, "ok", GREEN.tone(&v));
                ui.label(t(lang, "Safe Mode is off and nothing is waiting for a commit."));
            });
        }
        for b in &blocks {
            let check = s(b, "check");
            let (label, text, button) = match check {
                "safe-mode" => (
                    t(lang, "Safe Mode on"),
                    t(lang, "Booting undoes the changes made since it started."),
                    t(lang, "Leave Safe Mode, keep changes"),
                ),
                "uncommitted" => (
                    t(lang, "pending changes"),
                    t(lang, "The changes not committed are lost."),
                    t(lang, "Commit"),
                ),
                _ => (
                    t(lang, "disk erase waiting"),
                    t(lang, "It counts this power-off as the power button. Cancel it first."),
                    t(lang, "Cancel the erase"),
                ),
            };
            ui.horizontal_wrapped(|ui| {
                chip(ui, label, AMBER.tone(&v)).on_hover_text(s(b, "message"));
                ui.label(text);
                if let Some(f) = b.get("fix") {
                    let command = s(f, "command");
                    if action(ui, button, app.can().check(command)) {
                        fix = Some((command.to_owned(), f.get("params").cloned().unwrap_or_else(|| json!({}))));
                    }
                }
            });
        }
        // Without the question (an older daemon) the router has the last word.
        let forceable = preview.is_null() || preview.get("needs_force") == Some(&json!(true));
        if forceable {
            ui.horizontal(|ui| {
                let a = self.ask(win);
                ui.checkbox(&mut a.force, t(lang, "Force"));
                self.info(ui, "power.force", t(lang, "Force"));
                ui.weak(t(lang, "do it anyway, losing what is above"));
            });
        }
        fix
    }

    fn draw_going(&mut self, app: &CoreRouterUi, reboot: bool, going: Going, ui: &mut Ui) {
        let lang = app.lang.labels;
        let v = ui.visuals().clone();
        if going.back {
            ui.horizontal(|ui| {
                chip(ui, t(lang, "back"), GREEN.tone(&v));
                ui.label(t(lang, "The router answered again."));
                let version = s(&app.cache.info, "version");
                if !version.is_empty() {
                    ui.weak(format!("{} {version}", t(lang, "Version")));
                }
            });
            return;
        }
        let waited = going.since.map_or(0.0, |since| ui.input(|i| i.time) - since);
        ui.horizontal(|ui| {
            if reboot {
                ui.spinner();
                chip(ui, t(lang, "rebooting"), BLUE.tone(&v));
            } else {
                chip(ui, t(lang, "powering off"), AMBER.tone(&v));
            }
            ui.label(format!("{waited:.0} s"));
        });
        ui.label(if reboot {
            t(lang, "The connection comes back on its own; this window says when.")
        } else {
            t(lang, "It comes back only when someone turns it on; the connection then returns on its own.")
        });
        if reboot && waited > COMEBACK_SECS {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                t(lang, "It did not come back yet. Look at the console: it shows the address and the port."),
            );
        }
        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
    }

    /// Follows the connection while a request is in progress.
    fn watch(&mut self, app: &CoreRouterUi, now: f64) {
        let Some((_, going)) = self.going.as_mut() else { return };
        if going.since.is_none() {
            going.since = Some(now);
        }
        match app.link() {
            Link::Disconnected { .. } | Link::Connecting { .. } => going.dropped = true,
            Link::Connected { .. } if going.dropped => going.back = true,
            _ => {}
        }
    }
}

impl PanelState for PowerPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.has_command(PREVIEW) || self.going.is_some() {
            return Vec::new();
        }
        [(REBOOT, "reboot"), (SHUTDOWN, "shutdown")]
            .into_iter()
            .filter(|(win, _)| app.open.contains(&Win::Panel(win)))
            .map(|(win, action)| Query { key: win, command: PREVIEW, params: json!({"action": action}) })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let a = self.ask(key);
        // Nothing left to force: a tick from before must not carry over.
        if value.get("needs_force") != Some(&json!(true)) {
            a.force = false;
        }
        a.preview = value;
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        self.watch(app, ui.input(|i| i.time));
        egui::ScrollArea::vertical().id_salt(("power", win)).show(ui, |ui| self.draw(app, win, ui));
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        if let Some(win) = self.closing.take() {
            app.open.remove(&Win::Panel(win));
            app.floats.closed(crate::win_id(Win::Panel(win)));
        }
        // Closed: the next time it opens it asks again.
        if let Some((win, _)) = self.going
            && !app.open.contains(&Win::Panel(win))
        {
            self.going = None;
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(sent) = then.downcast::<Sent>() else { return };
        app.cache.refreshed_at = None;
        let lang = app.lang.labels;
        match *sent {
            Sent::Go(win) => match result {
                Ok(_) => self.going = Some((win, Going { since: None, dropped: false, back: false })),
                // The router went before it could answer: that is the request working.
                Err(_) if !matches!(app.link(), Link::Connected { .. } | Link::Local) => {
                    self.going = Some((win, Going { since: None, dropped: true, back: false }));
                }
                Err(e) => self.ask(win).error = Some(e.chars().take(300).collect()),
            },
            Sent::Fix(win) => match result {
                Ok(_) => self.ask(win).notice = Some(t(lang, "Done. The checks follow.").to_owned()),
                Err(e) => self.ask(win).error = Some(e.chars().take(300).collect()),
            },
        }
    }
}

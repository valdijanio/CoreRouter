//! "This change would lock you out" (G2.1b). When the router refuses a
//! change because it would cut this GUI's own connection (an engine error
//! that starts with `lockout: `), the change is held and a window asks:
//!
//! - **Safe Mode, then apply** — `config.safe-mode.enter`, then the same
//!   command again: if the connection is lost, the router undoes it;
//! - **Apply anyway** — the same command with `force: true`;
//! - **Cancel** — the dialog that sent it gets the refusal as its error.
//!
//! Only for commands that take `force` (the engine's contract says which).

use egui::RichText;
use serde_json::Value;

use crate::{CoreRouterUi, Then};

/// Prefix of the engine's lockout errors (`EngineError::Lockout`).
pub(crate) const PREFIX: &str = "lockout: ";

/// A change waiting for the operator's answer.
pub(crate) struct Held {
    pub command: String,
    pub params: Value,
    pub then: Then,
    pub message: String,
}

pub(crate) fn window_id() -> egui::Id {
    egui::Id::unique("corerouter-lockout")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    SafeMode,
    Force,
    Cancel,
}

impl CoreRouterUi {
    /// Whether `command` declares `force` in its parameters.
    fn takes_force(&self, command: &str) -> bool {
        self.cache.commands.iter().any(|c| {
            c.get("id").and_then(Value::as_str) == Some(command)
                && c.get("params")
                    .and_then(Value::as_str)
                    .is_some_and(|p| p.contains("force?"))
        })
    }

    /// An action's reply: a lockout refusal is held for the operator
    /// (returns `None`); anything else goes on to `then`.
    pub(crate) fn hold_lockout(
        &mut self,
        command: String,
        params: Value,
        then: Then,
        result: &Result<Value, String>,
    ) -> Option<Then> {
        let message = match result {
            Err(e) if e.starts_with(PREFIX) => e.clone(),
            _ => return Some(then),
        };
        if self.lockout.is_some() || !self.takes_force(&command) {
            return Some(then);
        }
        self.lockout = Some(Held {
            command,
            params,
            then,
            message,
        });
        None
    }

    /// The operator's answer to the held change.
    pub(crate) fn lockout_answer(&mut self, choice: Choice) {
        let Some(held) = self.lockout.take() else {
            return;
        };
        match choice {
            Choice::Cancel => {
                let reason = held.message.clone();
                self.answer_then(held.then, &Err(reason));
            }
            Choice::Force => {
                let mut p = held.params;
                if let Some(o) = p.as_object_mut() {
                    o.insert("force".into(), Value::Bool(true));
                } else {
                    p = serde_json::json!({ "force": true });
                }
                self.run_then(&held.command, p, held.then);
            }
            Choice::SafeMode => {
                self.run("config.safe-mode.enter", serde_json::json!({}));
                self.run_then(&held.command, held.params, held.then);
            }
        }
    }

    pub(crate) fn lockout_window(&mut self, ctx: &egui::Context) {
        let Some(held) = &self.lockout else {
            return;
        };
        let message = held
            .message
            .strip_prefix(PREFIX)
            .unwrap_or(&held.message)
            .to_owned();
        let command = held.command.clone();
        let safe_mode = self.can().check("config.safe-mode.enter");
        let mut choice = None;
        egui::Window::new("This change would lock you out")
            .id(window_id())
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(520.0);
                ui.label(
                    RichText::new(format!(
                        "{command} would cut the connection this window uses to manage the router."
                    ))
                    .strong(),
                );
                ui.add_space(4.0);
                ui.label(RichText::new(message).color(ui.visuals().warn_fg_color));
                ui.add_space(6.0);
                ui.weak(
                    "Safe Mode keeps the change only while this connection lives: if the \
                     router stops answering, it undoes the change by itself.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let label = RichText::new("Safe Mode, then apply").strong();
                    let r = ui.add_enabled(safe_mode.is_ok(), egui::Button::new(label));
                    let r = match &safe_mode {
                        Ok(()) => r,
                        Err(why) => r.on_disabled_hover_text(why.as_str()),
                    };
                    if r.clicked() {
                        choice = Some(Choice::SafeMode);
                    }
                    if ui.button("Apply anyway").clicked() {
                        choice = Some(Choice::Force);
                    }
                    if ui.button("Cancel").clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        choice = Some(Choice::Cancel);
                    }
                });
            });
        if let Some(c) = choice {
            self.lockout_answer(c);
        }
    }
}

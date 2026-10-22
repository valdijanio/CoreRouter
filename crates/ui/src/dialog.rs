//! What every dialog window has in common (properties, "New …", Comment):
//! the title with a dot ([`UNSAVED`]) while edited, the error line, the OK / Cancel / Apply
//! row and the keyboard, so each dialog only draws its fields.
//!
//! Keys, as in Windows, macOS, GNOME and WinBox: Enter = OK (apply, close
//! once the router accepts), Ctrl+Enter = Apply (stay open), Esc = Cancel
//! (close, dropping the edits). While a request is out (a remote router
//! answers later) OK says "Saving…" and nothing applies a second time. An
//! error stays in the dialog and puts the cursor in the field it names.

use egui::{Button, Context, Id, Rect, RichText, TextEdit, Ui};
use serde_json::Value;

use crate::float::{Floats, Keyed, Takes};

/// After the title of a dialog with edits not saved yet. "•", not "●":
/// egui's bundled fonts have no U+25CF and would draw a missing-glyph box.
pub(crate) const UNSAVED: char = '•';

/// What the operator asked of a dialog this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Press<B> {
    Ok,
    Apply,
    Cancel,
    /// A button of the dialog's own (Disable, Remove, Add Port …).
    Other(B),
}

/// Request bookkeeping of one open dialog.
#[derive(Default)]
pub(crate) struct Status {
    /// Last engine error, shown at the bottom like WinBox does.
    pub error: Option<String>,
    /// Commands sent and not answered yet: OK, Apply and the dialog's own
    /// buttons do nothing meanwhile (never apply twice).
    pub waiting: usize,
    /// Close once every reply is in and none failed (OK, Remove, "New …").
    pub close_on_success: bool,
    /// Put the cursor in the field the new error names, once.
    focus_error: bool,
}

impl Status {
    pub(crate) fn busy(&self) -> bool {
        self.waiting > 0
    }

    /// A command of this dialog is about to be sent.
    pub(crate) fn sent(&mut self) {
        self.error = None;
        self.waiting += 1;
    }

    /// One reply arrived. Returns whether the dialog closes now.
    pub(crate) fn replied(&mut self, result: &Result<Value, String>) -> bool {
        self.waiting = self.waiting.saturating_sub(1);
        if let Err(e) = result {
            self.error = Some(e.clone());
            self.focus_error = true;
        }
        self.waiting == 0 && self.close_on_success && self.error.is_none()
    }
}

/// The buttons under the fields.
pub(crate) enum Buttons {
    /// OK, Cancel and, with `apply`, Apply.
    Edit { apply: bool },
    /// Read only: a single OK that closes.
    View,
}

/// What a dialog body hands back to [`show`].
pub(crate) struct Footer<B> {
    pub buttons: Buttons,
    /// Whether the router can run what OK / Apply send
    /// ([`crate::CoreRouterUi::can`]): `Err` greys them out with the reason,
    /// and Enter / Ctrl+Enter do nothing.
    pub ok: Result<(), String>,
    /// Extra buttons after OK / Cancel / Apply, each with whether the
    /// router can run what it sends.
    pub extra: Vec<(&'static str, B, Result<(), String>)>,
    /// A button inside the fields was pressed.
    pub pressed: Option<B>,
}

impl<B> Footer<B> {
    pub(crate) fn edit(apply: bool, ok: Result<(), String>) -> Self {
        Self {
            buttons: Buttons::Edit { apply },
            ok,
            extra: Vec::new(),
            pressed: None,
        }
    }
}

/// Field helper handed to a dialog body: text fields get ids named after
/// the command parameter they fill, so an error can point at one.
pub(crate) struct Form {
    id: Id,
    /// The parameter whose field takes the cursor this frame.
    focus: Option<String>,
}

/// The text field of `param` in the dialog window `window`.
pub(crate) fn field_id(window: Id, param: &str) -> Id {
    window.with(("field", param))
}

impl Form {
    fn field_id(&self, param: &str) -> Id {
        field_id(self.id, param)
    }

    /// A labelled one-line text field in a two-column grid.
    pub(crate) fn text(
        &self,
        ui: &mut Ui,
        label: &str,
        param: &str,
        value: &mut String,
        hint: &str,
    ) {
        ui.label(label);
        let resp = ui.add(
            TextEdit::singleline(value)
                .id(self.field_id(param))
                .hint_text(hint)
                .desired_width(180.0),
        );
        if self.focus.as_deref() == Some(param) {
            resp.request_focus();
        }
        ui.end_row();
    }
}

/// The parameter an engine error is about: `parameter 'mtu': …`.
pub(crate) fn error_param(error: &str) -> Option<&str> {
    let (_, rest) = error.split_once("parameter '")?;
    let (name, _) = rest.split_once('\'')?;
    Some(name).filter(|n| !n.is_empty())
}

/// Where and how a dialog window is drawn.
pub(crate) struct Head<'a> {
    pub id: Id,
    pub title: &'a str,
    /// Edits not saved yet: [`UNSAVED`] after the title.
    pub dirty: bool,
    pub pos: egui::Pos2,
}

/// Draw one dialog: its fields (`body`), the error line, the buttons, and
/// read the keyboard. Returns what the operator asked for; the window's ✕
/// is Cancel. While a request is out only Cancel gets through.
pub(crate) fn show<B>(
    floats: &mut Floats,
    ctx: &Context,
    area: Rect,
    head: Head<'_>,
    status: &mut Status,
    body: impl FnOnce(&mut Ui, &Form) -> Footer<B>,
) -> Option<Press<B>> {
    let title = if head.dirty {
        format!("{} {UNSAVED}", head.title)
    } else {
        head.title.to_owned()
    };
    let form = Form {
        id: head.id,
        focus: status
            .focus_error
            .then(|| status.error.as_deref().and_then(error_param))
            .flatten()
            .map(str::to_owned),
    };
    status.focus_error = false;
    let busy = status.busy();
    let error = status.error.as_deref();
    let mut open = true;
    let mut view = false;
    let mut can_ok = true;
    let pressed = floats
        .show(
            ctx,
            area,
            head.id,
            &title,
            &mut open,
            |w| w.default_pos(head.pos).resizable(false).collapsible(false),
            |ui| {
                let footer = body(ui, &form);
                view = matches!(footer.buttons, Buttons::View);
                can_ok = footer.ok.is_ok();
                buttons(ui, footer, error, busy)
            },
        )
        .flatten();
    let keyed = floats
        .keys(ctx, head.id, Takes::Dialog)
        .map(|k| match k {
            Keyed::Enter => Press::Ok,
            Keyed::CtrlEnter => Press::Apply,
            Keyed::Escape => Press::Cancel,
        })
        .filter(|_| pressed.is_none());
    let press = if open {
        pressed.or(keyed)
    } else {
        Some(Press::Cancel)
    };
    match press {
        // A read-only window has nothing to apply: OK closes it.
        Some(Press::Ok) if view => Some(Press::Cancel),
        Some(Press::Apply) if view => None,
        Some(Press::Cancel) => Some(Press::Cancel),
        Some(_) if busy => None,
        // OK / Apply greyed out: the router cannot run what they send.
        Some(Press::Ok | Press::Apply) if !can_ok => None,
        other => other,
    }
}

/// The error line and the button row. OK is the default button (Enter),
/// drawn in the accent colour.
fn buttons<B>(ui: &mut Ui, footer: Footer<B>, error: Option<&str>, busy: bool) -> Option<Press<B>> {
    if let Some(e) = error {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }
    ui.separator();
    let mut pressed = footer.pressed.map(Press::Other);
    ui.horizontal(|ui| {
        let apply = match footer.buttons {
            Buttons::View => {
                if default_button(ui, "OK", true, "Enter").clicked() {
                    pressed = Some(Press::Ok);
                }
                return;
            }
            Buttons::Edit { apply } => apply,
        };
        let ok = if busy { "Saving…" } else { "OK" };
        let can = &footer.ok;
        if default_button(ui, ok, !busy && can.is_ok(), why(can, "Enter")).clicked() {
            pressed = Some(Press::Ok);
        }
        if hinted(ui, "Cancel", true, "Esc").clicked() {
            pressed = Some(Press::Cancel);
        }
        if apply && hinted(ui, "Apply", !busy && can.is_ok(), why(can, "Ctrl+Enter")).clicked() {
            pressed = Some(Press::Apply);
        }
        for (text, b, can) in footer.extra {
            let resp = ui.add_enabled(!busy && can.is_ok(), Button::new(text));
            if let Err(why) = &can {
                resp.on_disabled_hover_text(why.as_str());
            } else if resp.clicked() {
                pressed = Some(Press::Other(b));
            }
        }
    });
    pressed
}

/// The tooltip of a button: its key, or why the router cannot run it.
fn why<'a>(can: &'a Result<(), String>, key: &'a str) -> &'a str {
    match can {
        Ok(()) => key,
        Err(why) => why,
    }
}

fn hinted(ui: &mut Ui, text: &str, enabled: bool, key: &str) -> egui::Response {
    ui.add_enabled(enabled, Button::new(text))
        .on_hover_text(key)
        .on_disabled_hover_text(key)
}

/// The button Enter presses, filled with the selection colour.
fn default_button(ui: &mut Ui, text: &str, enabled: bool, key: &str) -> egui::Response {
    let v = ui.visuals();
    let label = RichText::new(text).color(v.selection.stroke.color);
    let button = Button::new(label).fill(v.selection.bg_fill);
    let button = if enabled { button } else { Button::new(text) };
    ui.add_enabled(enabled, button)
        .on_hover_text(key)
        .on_disabled_hover_text(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_names_its_parameter() {
        assert_eq!(
            error_param("parameter 'mtu': must be 68..=9216"),
            Some("mtu")
        );
        assert_eq!(
            error_param("batch step 1 failed: parameter 'vlan_id': is required"),
            Some("vlan_id")
        );
        assert_eq!(
            error_param("unknown parameter 'x' (did you mean y?)"),
            Some("x")
        );
        assert_eq!(error_param("validation failed: …"), None);
        assert_eq!(error_param("parameter '"), None);
        assert_eq!(error_param("parameter '': x"), None);
    }

    #[test]
    fn the_unsaved_mark_has_a_glyph() {
        let ctx = Context::default();
        ctx.run_ui(egui::RawInput::default(), |_| {})
            .drop_without_applying_deltas();
        let font = egui::TextStyle::Heading.resolve(&ctx.global_style());
        assert!(ctx.fonts_mut(|f| f.has_glyph(&font, UNSAVED)));
    }

    #[test]
    fn status_closes_only_when_every_reply_succeeded() {
        let mut s = Status {
            close_on_success: true,
            ..Status::default()
        };
        s.sent();
        s.sent();
        assert!(s.busy());
        assert!(!s.replied(&Err("parameter 'mtu': bad".into())));
        assert!(!s.replied(&Ok(Value::Null)), "one failed: stays open");
        assert!(!s.busy());
        s.sent();
        assert!(s.error.is_none(), "a new try clears the old error");
        assert!(s.replied(&Ok(Value::Null)));
        // A reply nobody waits for does not underflow.
        s.waiting = 0;
        s.replied(&Ok(Value::Null));
        assert_eq!(s.waiting, 0);
    }
}

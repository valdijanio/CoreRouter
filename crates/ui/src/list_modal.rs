//! The add/edit modal of a list window (G0.24, `docs/ui-style.md`). A
//! window describes its fields once ([`Spec`]) and the modal does the rest:
//!
//! - an ⓘ after the title and after each label, opening the explanation in
//!   the language of the explanations (labels stay in English);
//! - the engine's **preview** (a query taking the same parameters as `add`,
//!   all optional, plus `id` when editing) asked again as the fields
//!   change, and drawn: calculated fields (`computed`), checks with an
//!   `ok`/`warning`/`error` chip (`checks`), the access risk (`risk`) and
//!   the commands it would run (`commands`, in the terminal's syntax);
//! - Cancel / Apply / OK (Enter = OK, Ctrl+Enter = Apply, Esc = Cancel,
//!   from `dialog.rs`), greyed while the preview has an error; the
//!   commands go as one transaction ([`CoreRouterUi::run_steps`]), so a
//!   series of 5 addresses is 5 adds or none;
//! - an error (the preview's or the router's) under the field it names,
//!   and the modal stays open.
//!
//! The preview reply:
//!
//! ```text
//! { computed: [{label, value}],
//!   checks:   [{level: ok | warning | error | pending | info, check, message, param?}],
//!   commands: [{command, params}],
//!   risk?:    "why this change may cut this session" }
//! ```
//!
//! `pending` is a check still running (an ARP probe): the modal asks again
//! shortly. A `risk` needs the operator's yes (or Safe Mode) before OK; the
//! commands then go with `force: true`.

use std::collections::BTreeMap;

use egui::{Grid, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::chip::{self, Tone};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::interfaces::{cascade, dialog_id};
use crate::{CoreRouterUi, Pending, Win};

/// How long the modal waits after the last keystroke before asking for a
/// preview, and between asks while a check is still running.
const ASK_EVERY_SECS: f64 = 0.4;
/// Commands shown in the preview; the rest are counted.
const SHOWN_COMMANDS: usize = 12;

/// How a field is typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Input {
    /// One line; the hint shows while empty.
    Text(&'static str),
    /// A pick among the options the window hands to [`Modal::show`]
    /// (interfaces); empty means "none".
    Choice,
    /// A checkbox; sent as a bool.
    Check,
    /// A write-only secret: typed hidden; when editing, empty keeps it.
    Secret(&'static str),
}

/// One field: the parameter it fills, its label (English, through `tr`)
/// and the explanation key of its ⓘ (empty: none, for what is obvious, as
/// Comment; docs/ui-style.md, "Explicação ⓘ em todo lugar que couber").
#[derive(Debug, Clone, Copy)]
pub(crate) struct Field {
    pub param: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub input: Input,
    /// Shown when editing an item (a field `set` does not take is not).
    pub edit: bool,
}

/// What a window tells the modal once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec {
    /// The panel the preview replies go to (`PanelState::arrived` with key
    /// [`PREVIEW`]; hand them to [`Modal::arrived`]).
    pub panel: &'static str,
    /// The list window the modal belongs to.
    pub parent: Win,
    pub new_title: &'static str,
    /// The item's name follows it: "Address <10.0.0.1/24>".
    pub edit_title: &'static str,
    /// Explanation key of the ⓘ after the title.
    pub help: &'static str,
    pub fields: &'static [Field],
    /// The preview query.
    pub preview: &'static str,
}

/// The query key preview replies come back with.
pub(crate) const PREVIEW: &str = "list-modal-preview";

/// The reply of what the modal applied: `PanelState::reply` hands it to
/// [`Modal::replied`].
pub(crate) struct Applied(pub u64);

/// One open modal.
pub(crate) struct Modal {
    pub id: u64,
    /// The item's id when editing (`None`: new).
    pub item: Option<String>,
    /// Its name in the title when editing.
    pub name: String,
    pub values: BTreeMap<&'static str, String>,
    orig: BTreeMap<&'static str, String>,
    pub status: Status,
    /// The last preview, and the parameters it answered.
    pub preview: Option<Value>,
    asked: Option<Value>,
    asked_at: f64,
    edited_at: f64,
    pub help: Option<HelpView>,
    /// The operator accepted the access risk.
    pub accept_risk: bool,
}

/// How a check level is drawn.
pub(crate) fn level_chip(level: &str, v: &egui::Visuals) -> (&'static str, Tone) {
    match level {
        "ok" => ("ok", chip::GREEN.tone(v)),
        "warning" => ("warning", chip::AMBER.tone(v)),
        "error" => ("error", chip::RED.tone(v)),
        "pending" => ("checking…", chip::neutral_tone(v)),
        _ => ("info", chip::BLUE.tone(v)),
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(crate::value_text).unwrap_or_default()
}

fn list<'a>(v: Option<&'a Value>, k: &str) -> &'a [Value] {
    v.and_then(|v| v.get(k))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

impl Modal {
    /// A new modal (`item: None`) or one editing `item`, its fields filled
    /// from `values` (by parameter).
    pub(crate) fn open(app: &mut CoreRouterUi, item: Option<(String, String)>, values: BTreeMap<&'static str, String>) -> Self {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        let (item, name) = item.map_or((None, String::new()), |(i, n)| (Some(i), n));
        Self {
            id: app.next_dialog,
            item,
            name,
            orig: values.clone(),
            values,
            status: Status::default(),
            preview: None,
            asked: None,
            asked_at: f64::NEG_INFINITY,
            edited_at: f64::NEG_INFINITY,
            help: None,
            accept_risk: false,
        }
    }

    fn shown(&self, spec: &Spec) -> impl Iterator<Item = &'static Field> {
        let editing = self.item.is_some();
        spec.fields.iter().filter(move |f| !editing || f.edit)
    }

    /// The parameters of the preview: every field (text trimmed, checkbox
    /// as a bool; empty text left out), `id` when editing.
    pub(crate) fn params(&self, spec: &Spec) -> Value {
        let mut p = Map::new();
        for f in self.shown(spec) {
            let v = self.values.get(f.param).map(String::as_str).unwrap_or("");
            match f.input {
                Input::Check => {
                    p.insert(f.param.into(), json!(v == "yes"));
                }
                // A new item leaves empty fields out; an edit sends them
                // (an emptied comment is cleared).
                _ if v.trim().is_empty() && self.item.is_none() => {}
                _ => {
                    p.insert(f.param.into(), json!(v.trim()));
                }
            }
        }
        if let Some(id) = &self.item {
            p.insert("id".into(), json!(id));
        }
        Value::Object(p)
    }

    /// Edited since opened (or applied): an empty field equals a missing one.
    fn dirty(&self) -> bool {
        let filled = |m: &BTreeMap<&'static str, String>| -> Vec<(&'static str, String)> {
            m.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (*k, v.clone())).collect()
        };
        filled(&self.values) != filled(&self.orig)
    }

    /// The preview answers the fields as they are now.
    fn current(&self, spec: &Spec) -> Option<&Value> {
        self.preview
            .as_ref()
            .filter(|_| self.asked.as_ref() == Some(&self.params(spec)))
    }

    /// A check still runs (ARP): ask again shortly.
    fn pending(&self) -> bool {
        list(self.preview.as_ref(), "checks")
            .iter()
            .any(|c| s(c, "level") == "pending")
    }

    /// Send the preview query when the fields changed (after a pause in the
    /// typing) or a check is still running.
    pub(crate) fn ask(&mut self, app: &mut CoreRouterUi, spec: &Spec, now: f64) {
        if !app.has_command(spec.preview) {
            return;
        }
        let p = self.params(spec);
        let changed = self.asked.as_ref() != Some(&p);
        let due = if changed {
            now - self.edited_at >= ASK_EVERY_SECS || self.asked.is_none()
        } else {
            self.pending() && now - self.asked_at >= ASK_EVERY_SECS
        };
        if !due {
            return;
        }
        let req = app
            .backend
            .submit("engine.execute", json!({"command": spec.preview, "params": p}));
        app.pending
            .insert(req, Pending::Query(crate::Field::Panel(spec.panel, PREVIEW)));
        self.asked = Some(p);
        self.asked_at = now;
    }

    /// Tests: the preview at hand answers the fields as they are.
    #[cfg(test)]
    pub(crate) fn mark_asked(&mut self, spec: &Spec) {
        self.asked = Some(self.params(spec));
    }

    /// A preview reply (the panel's `arrived` with key [`PREVIEW`]).
    pub(crate) fn arrived(&mut self, value: Value) {
        self.preview = Some(value);
    }

    /// The preview's error checks, and whether it has an answer at all.
    pub(crate) fn blocking(&self, spec: &Spec) -> Result<(), String> {
        let Some(p) = self.current(spec) else {
            return Err("checking…".into());
        };
        if let Some(e) = list(Some(p), "checks").iter().find(|c| s(c, "level") == "error") {
            return Err(s(e, "message"));
        }
        if list(Some(p), "commands").is_empty() {
            return Err("nothing to change".into());
        }
        if p.get("risk").is_some_and(|r| !r.is_null()) && !self.accept_risk {
            return Err("confirm the access risk first (or enter Safe Mode)".into());
        }
        Ok(())
    }

    /// The commands to run: the preview's, with `force` once the operator
    /// accepted the risk.
    pub(crate) fn steps(&self, spec: &Spec) -> Vec<Value> {
        let force = self.accept_risk && self.current(spec).is_some_and(|p| p.get("risk").is_some_and(|r| !r.is_null()));
        list(self.current(spec), "commands")
            .iter()
            .map(|c| {
                let mut c = c.clone();
                if force && let Some(p) = c.get_mut("params").and_then(Value::as_object_mut) {
                    p.insert("force".into(), Value::Bool(true));
                }
                c
            })
            .collect()
    }

    /// Draw the modal. `options(param)` lists a choice field's values.
    /// Returns `false` once it closed.
    pub(crate) fn show(
        &mut self,
        app: &mut CoreRouterUi,
        ctx: &egui::Context,
        area: egui::Rect,
        spec: &Spec,
        options: &dyn Fn(&str) -> Vec<String>,
    ) -> bool {
        let now = ctx.input(|i| i.time);
        self.ask(app, spec, now);
        if self.pending() {
            ctx.request_repaint_after(std::time::Duration::from_millis(300));
        }
        let l = app.lang.labels;
        let wid = dialog_id(self.id);
        let title = match &self.item {
            Some(_) => format!("{} <{}>", tr(l, spec.edit_title), self.name),
            None => tr(l, spec.new_title).to_owned(),
        };
        let can = app.can();
        let first = self.steps(spec).first().and_then(|c| c.get("command").and_then(Value::as_str).map(str::to_owned));
        let ok = self
            .blocking(spec)
            .and_then(|()| first.map_or(Ok(()), |c| can.check(&c)));
        let steps_text = crate::list::steps_text(app, list(self.current(spec), "commands"));
        let safe_mode_can = can.check("config.safe-mode.enter");
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: self.dirty(),
            pos: cascade(area, self.id),
            parent: Some(crate::win_id(spec.parent)),
        };
        let mut values = self.values.clone();
        let mut help: Option<HelpView> = None;
        let mut accept = self.accept_risk;
        let mut safe_mode = false;
        let preview = self.current(spec).cloned().or_else(|| self.preview.clone());
        let fields: Vec<&'static Field> = self.shown(spec).collect();
        let error = self.status.error.clone();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut self.status, |ui, form| {
            ui.set_min_width(420.0);
            ui.horizontal(|ui| {
                if help::info_button(ui, form.window().with("title-help"), tr(app.lang.help, "What is this?")).clicked() {
                    help = Some(HelpView::new(spec.help, title.clone()));
                }
                ui.weak(tr(app.lang.help, "What is this?"));
            });
            ui.add_space(4.0);
            Grid::new(form.window().with("fields"))
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    for f in &fields {
                        ui.horizontal(|ui| {
                            ui.label(tr(l, f.label));
                            // No ⓘ for what explains itself (Comment).
                            if !f.help.is_empty()
                                && help::info_button(ui, form.window().with(("help", f.param)), tr(app.lang.help, "Explain")).clicked() {
                                help = Some(HelpView::new(f.help, tr(l, f.label)));
                            }
                        });
                        ui.vertical(|ui| {
                            ui.set_max_width(320.0);
                            let v = values.entry(f.param).or_default();
                            field_input(ui, form, f, v, &options(f.param));
                            for m in field_messages(preview.as_ref(), error.as_deref(), f.param) {
                                ui.colored_label(ui.visuals().error_fg_color, m);
                            }
                        });
                        ui.end_row();
                    }
                });
            preview_body(ui, preview.as_ref(), &steps_text, l, &mut accept, &mut safe_mode, &safe_mode_can);
            Footer::<()>::edit(true, ok.clone())
        });
        if values != self.values {
            self.values = values;
            self.edited_at = now;
            self.accept_risk = false;
        } else {
            self.accept_risk = accept;
        }
        if help.is_some() {
            self.help = help;
        }
        help::modal(ctx, app.lang, &mut self.help);
        if safe_mode {
            app.run("config.safe-mode.enter", json!({}));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return false;
            }
            Some(p @ (Press::Ok | Press::Apply)) => {
                let steps = self.steps(spec);
                self.status.close_on_success = p == Press::Ok;
                self.status.sent();
                app.run_steps(steps, crate::panel::then(spec.panel, Applied(self.id)));
            }
            _ => {}
        }
        true
    }

    /// The reply of what OK / Apply sent. Returns whether the modal closes.
    pub(crate) fn replied(&mut self, app: &mut CoreRouterUi, result: &Result<Value, String>) -> bool {
        let close = self.status.replied(result);
        if result.is_ok() {
            // Applied: what is on screen is the new original, and a new
            // item's series starts over (Apply keeps the modal open).
            self.orig = self.values.clone();
            self.asked = None;
            self.accept_risk = false;
        }
        if close {
            app.floats.forget(dialog_id(self.id));
        }
        close
    }
}

/// The errors to show under the field of `param`: the preview's error
/// checks naming it, and the router's error naming it.
fn field_messages(preview: Option<&Value>, error: Option<&str>, param: &str) -> Vec<String> {
    let mut out: Vec<String> = list(preview, "checks")
        .iter()
        .filter(|c| s(c, "level") == "error" && s(c, "param") == param)
        .map(|c| s(c, "message"))
        .collect();
    if let Some(e) = error.filter(|e| dialog::error_param(e) == Some(param)) {
        out.push(e.to_owned());
    }
    out
}

fn field_input(ui: &mut Ui, form: &dialog::Form, f: &Field, v: &mut String, options: &[String]) {
    let id = dialog::field_id(form.window(), f.param);
    match f.input {
        Input::Text(hint) => {
            ui.add(TextEdit::singleline(v).id(id).hint_text(hint).desired_width(220.0));
        }
        Input::Secret(hint) => {
            ui.add(TextEdit::singleline(v).password(true).id(id).hint_text(hint).desired_width(220.0));
        }
        Input::Check => {
            let mut on = v == "yes";
            if ui.checkbox(&mut on, "").changed() {
                *v = if on { "yes" } else { "no" }.to_owned();
            }
        }
        Input::Choice => {
            egui::ComboBox::from_id_salt(id)
                .width(220.0)
                .selected_text(if v.is_empty() { "—" } else { v.as_str() })
                .show_ui(ui, |ui| {
                    for o in options {
                        ui.selectable_value(v, o.clone(), o);
                    }
                });
        }
    }
}

/// Calculated fields, checks, the access risk and the commands.
fn preview_body(
    ui: &mut Ui,
    p: Option<&Value>,
    steps: &[String],
    l: Lang,
    accept: &mut bool,
    safe_mode: &mut bool,
    safe_mode_can: &Result<(), String>,
) {
    let computed = list(p, "computed");
    if !computed.is_empty() {
        ui.separator();
        Grid::new("list-modal-computed").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
            for c in computed {
                ui.weak(s(c, "label"));
                ui.monospace(s(c, "value"));
                ui.end_row();
            }
        });
    }
    let checks = list(p, "checks");
    if !checks.is_empty() {
        ui.separator();
        ui.label(RichText::new(tr(l, "Checks")).strong());
        let v = ui.visuals().clone();
        for c in checks {
            ui.horizontal_wrapped(|ui| {
                let (text, tone) = level_chip(&s(c, "level"), &v);
                chip::chip(ui, tr(l, text), tone);
                ui.label(s(c, "message"));
            });
        }
    }
    if let Some(risk) = p.and_then(|p| p.get("risk")).and_then(Value::as_str) {
        ui.separator();
        let v = ui.visuals().clone();
        egui::Frame::new()
            .fill(chip::AMBER.tone(&v).fill)
            .inner_margin(6.0)
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    chip::chip(ui, tr(l, "access"), chip::AMBER.tone(&v));
                    ui.label(risk);
                });
                ui.horizontal(|ui| {
                    ui.checkbox(accept, tr(l, "I understand: apply anyway"));
                    if crate::table::action(ui, tr(l, "Enter Safe Mode"), safe_mode_can.clone()) {
                        *safe_mode = true;
                    }
                });
            });
    }
    if !steps.is_empty() {
        ui.separator();
        egui::CollapsingHeader::new(format!("{} ({})", tr(l, "Commands"), steps.len()))
            .id_salt("list-modal-commands")
            .default_open(true)
            .show(ui, |ui| {
                for line in steps.iter().take(SHOWN_COMMANDS) {
                    ui.monospace(line);
                }
                if steps.len() > SHOWN_COMMANDS {
                    ui.weak(format!("… {} {}", steps.len() - SHOWN_COMMANDS, tr(l, "more")));
                }
            });
    }
}

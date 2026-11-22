//! PPP › Secrets › **Import from MikroTik** (G4.3n): the subscribers of a
//! RouterOS `/ppp secret export show-sensitive`, with their passwords.
//!
//! The file comes from a path (read by the app: the UI does no I/O,
//! `crate::export::open`), a file dropped on the window, or a paste. The
//! engine's `ppp.secret.import dry_run=yes` answers the preview (chips: with
//! password, without, missing profiles, conflicts, errors) and the profiles
//! to map; Import sends the same command without `dry_run`: one change, one
//! revision, undone with the rest under Safe Mode. The text never shows
//! here and is forgotten on Import and on close; the dialog reminds the
//! operator to delete the file.

use std::collections::BTreeMap;

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::chip::{self, Kind};
use crate::dhcp_client::text;
use crate::dialog::{self, Buttons, Footer, Head, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::{CoreRouterUi, Win, table};

const SCOPE: &str = "ppp_import";
const COMMAND: &str = "ppp.secret.import";
/// The engine's limit (`corerouter_engine::rsc::MAX_TEXT`).
const MAX_TEXT: usize = 32 * 1024 * 1024;
/// What the mapping combo says for "the profile the file defines".
pub(crate) const FROM_FILE: &str = "(create from the file)";

/// A dialog's own buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Button {
    Load,
    Forget,
    Preview,
    Import,
    SafeMode,
}

/// The reply a request of this dialog waits for.
pub(crate) struct Reply {
    pub dialog: u64,
    pub dry_run: bool,
}

#[derive(Default)]
pub(crate) struct ImportDialog {
    pub id: u64,
    /// Where the file is (typed), and what was read from it.
    pub path: String,
    /// The export's text: never drawn, cleared on Import and on close.
    text: String,
    /// "export.rsc · 1.2 MB · 4 321 lines".
    pub source: String,
    /// The paste box (emptied into `text` as soon as something arrives).
    pub paste: String,
    pub on_conflict: String,
    /// RouterOS profile → ours ("" = same name or from the file).
    pub map: BTreeMap<String, String>,
    /// The last dry run's report.
    pub report: Option<Value>,
    /// What the last Import did.
    pub done: Option<Value>,
    pub status: Status,
}

impl ImportDialog {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            on_conflict: "skip".into(),
            ..Self::default()
        }
    }

    /// The export to import: `bytes` as UTF-8 (Latin-1 when not).
    pub(crate) fn take(&mut self, name: &str, bytes: Vec<u8>) {
        if bytes.len() > MAX_TEXT {
            self.status.error = Some(format!("{name}: larger than {} MiB", MAX_TEXT >> 20));
            return;
        }
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => e.into_bytes().into_iter().map(char::from).collect(),
        };
        // The file's name only: a long path would widen the dialog.
        let short = name.rsplit(['/', '\\']).next().unwrap_or(name);
        self.source = format!("{short} · {} · {} lines", crate::ppp::bytes(text.len() as u64), text.lines().count());
        self.text = text;
        self.report = None;
        self.done = None;
        self.status.error = None;
    }

    pub(crate) fn has_text(&self) -> bool {
        !self.text.is_empty()
    }

    /// Forget the export (the passwords) as soon as it is not needed.
    pub(crate) fn forget(&mut self) {
        self.text = String::new();
        self.paste = String::new();
        self.source.clear();
        self.report = None;
    }

    /// The command's parameters.
    pub(crate) fn params(&self, dry_run: bool) -> Value {
        let map: Map<String, Value> = self
            .map
            .iter()
            .filter(|(_, to)| !to.is_empty() && to.as_str() != FROM_FILE)
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        json!({"text": self.text, "on_conflict": self.on_conflict, "profile_map": map, "dry_run": dry_run})
    }

    /// The last preview allows the import.
    pub(crate) fn ready(&self) -> Result<(), String> {
        let Some(r) = &self.report else {
            return Err("Preview first".into());
        };
        let errors = r.get("errors_total").and_then(Value::as_u64).unwrap_or(0);
        if errors > 0 {
            return Err(format!("{errors} error(s) in the preview"));
        }
        Ok(())
    }
}

fn n(v: &Value, path: &[&str]) -> u64 {
    path.iter().try_fold(v, |v, k| v.get(*k)).and_then(Value::as_u64).unwrap_or(0)
}

/// A label with its ⓘ; the explanation key is `ppp_import.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("ppp-import-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("ppp_import.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

/// The preview's chips: what the file holds and what stops the import.
fn chips(ui: &mut Ui, l: Lang, r: &Value) {
    let v = ui.visuals().clone();
    ui.horizontal_wrapped(|ui| {
        let items = [
            (n(r, &["with_password"]), "with password", Kind::Green),
            (n(r, &["without_password", "count"]), "without password", Kind::Amber),
            (r.get("missing_profiles").and_then(Value::as_array).map_or(0, Vec::len) as u64, "missing profiles", Kind::Red),
            (n(r, &["conflicts", "count"]), "already here", Kind::Blue),
            (n(r, &["errors_total"]), "errors", Kind::Red),
        ];
        for (count, what, kind) in items {
            let kind = if count == 0 && kind != Kind::Green { Kind::Neutral } else { kind };
            chip::chip(ui, &format!("{count} {}", tr_in(SCOPE, l, what)), kind.tone(&v));
        }
    });
}

/// Errors, warnings and the fields left out, each list cut at a few lines.
fn details(ui: &mut Ui, l: Lang, r: &Value) {
    let lines = |key: &str| r.get(key).and_then(Value::as_array).cloned().unwrap_or_default();
    let warn = ui.visuals().warn_fg_color;
    let bad = ui.visuals().error_fg_color;
    for e in lines("errors").iter().take(8) {
        let at = e.get("line").and_then(Value::as_u64).filter(|n| *n > 0).map(|n| format!("line {n} · ")).unwrap_or_default();
        let who = e.get("name").and_then(Value::as_str).map(|n| format!("{n} · ")).unwrap_or_default();
        let what = e.get("param").and_then(Value::as_str).map(|p| format!("{p}: ")).unwrap_or_default();
        ui.colored_label(bad, format!("{at}{who}{what}{}", text(e, "message")));
    }
    for w in lines("warnings").iter().take(5) {
        ui.colored_label(warn, w.as_str().unwrap_or_default());
    }
    if let Some(o) = r.get("unsupported").and_then(Value::as_object).filter(|o| !o.is_empty()) {
        let list: Vec<String> = o.iter().map(|(k, v)| format!("{k} ({})", v.as_u64().unwrap_or(0))).collect();
        ui.weak(format!("{}: {}", tr_in(SCOPE, l, "Not imported (no such field here)"), list.join(", ")));
    }
}

/// Profile mapping: one row per RouterOS profile the secrets use.
fn mapping(ui: &mut Ui, l: Lang, d: &mut ImportDialog, ours: &[String], help: &mut Option<HelpView>) -> bool {
    let profiles = d.report.as_ref().and_then(|r| r.get("profiles")).and_then(Value::as_array).cloned().unwrap_or_default();
    if profiles.is_empty() {
        return false;
    }
    let mut changed = false;
    label(ui, help, l, "map", "Profile mapping");
    Grid::new(("ppp-import-map", d.id)).num_columns(3).striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.strong(tr_in(SCOPE, l, "MikroTik profile"));
        ui.strong(tr_in(SCOPE, l, "Secrets"));
        ui.strong(tr_in(SCOPE, l, "Here"));
        ui.end_row();
        for p in &profiles {
            let name = text(p, "name");
            let here = p.get("here").and_then(Value::as_bool).unwrap_or(false);
            let in_file = p.get("in_file").and_then(Value::as_bool).unwrap_or(false);
            let target = text(p, "target");
            let kind = if target.is_empty() { Kind::Red } else { Kind::Neutral };
            chip::chip(ui, &name, kind.tone(ui.visuals()));
            ui.label(n(p, &["count"]).to_string());
            let cur = d.map.entry(name.clone()).or_default();
            let shown = match (cur.as_str(), here, in_file) {
                ("", true, _) => name.clone(),
                ("", false, true) => tr_in(SCOPE, l, FROM_FILE).to_owned(),
                ("", false, false) => "—".to_owned(),
                (c, _, _) => c.to_owned(),
            };
            egui::ComboBox::from_id_salt(("ppp-import-map", d.id, name.as_str())).width(200.0).selected_text(shown).show_ui(ui, |ui| {
                if in_file && !here {
                    changed |= ui.selectable_value(cur, String::new(), tr_in(SCOPE, l, FROM_FILE)).changed();
                }
                for o in ours {
                    let value = if *o == name { String::new() } else { o.clone() };
                    changed |= ui.selectable_value(cur, value, o.as_str()).changed();
                }
            });
            ui.end_row();
        }
    });
    changed
}

/// Draw the dialog; `false` when it closed.
pub(crate) fn show(d: &mut ImportDialog, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect, parent: &'static str, ours: &[String], help: &mut Option<HelpView>) -> bool {
    let l = app.lang.labels;
    let wid = dialog_id(d.id);
    // A file dropped on the window: read by the app, as a typed path is
    // (bounded; the browser lab has no reader: paste it there).
    let dropped = ctx.input(|i| i.raw.dropped_files.clone());
    for f in dropped {
        let shown = f.path().display().to_string();
        match crate::export::open(ctx, &shown) {
            Ok(b) => {
                d.path = shown.clone();
                d.take(&shown, b);
            }
            Err(e) => d.status.error = Some(e),
        }
    }
    let head = Head { id: wid, title: tr_in(SCOPE, l, "Import from MikroTik"), dirty: d.has_text(), pos: cascade(area, d.id), parent: Some(crate::win_id(Win::Panel(parent))) };
    let can = app.can().check(COMMAND);
    let safe_on = app.cache.summary.get("safe_mode").and_then(|s| s.get("active")).and_then(Value::as_bool) == Some(true);
    let can_safe = app.can().check("config.safe-mode.enter");
    let mut map_changed = false;
    let mut status = std::mem::take(&mut d.status);
    let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut status, |ui, f| {
        let mut pressed = None;
        ui.set_max_width(640.0);
        let warn = ui.visuals().warn_fg_color;
        ui.colored_label(warn, tr_in(SCOPE, l, "The export holds every subscriber's password in clear. Read it here, then delete the file and its copies."));
        ui.add_space(4.0);
        Grid::new(("ppp-import", d.id)).num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            label(ui, help, l, "file", "File");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut d.path).id(dialog::field_id(f.window(), "path")).hint_text("/home/noc/secrets.rsc").desired_width(360.0));
                if ui.button(tr_in(SCOPE, l, "Load")).clicked() {
                    pressed = Some(Button::Load);
                }
            });
            ui.end_row();
            label(ui, help, l, "paste", "or paste it");
            ui.add(TextEdit::multiline(&mut d.paste).id(dialog::field_id(f.window(), "paste")).hint_text(tr_in(SCOPE, l, "/ppp secret export show-sensitive, or drop the .rsc file on this window")).desired_rows(2).desired_width(420.0));
            ui.end_row();
            label(ui, help, l, "on_conflict", "Name already here");
            egui::ComboBox::from_id_salt(("ppp-import-conflict", d.id)).width(200.0).selected_text(tr_in(SCOPE, l, conflict_label(&d.on_conflict))).show_ui(ui, |ui| {
                for o in ["skip", "replace", "rename"] {
                    map_changed |= ui.selectable_value(&mut d.on_conflict, o.to_owned(), tr_in(SCOPE, l, conflict_label(o))).changed();
                }
            });
            ui.end_row();
        });
        if d.has_text() {
            ui.horizontal(|ui| {
                ui.label(format!("{}: {}", tr_in(SCOPE, l, "Loaded"), d.source));
                if ui.small_button(tr_in(SCOPE, l, "Forget")).clicked() {
                    pressed = Some(Button::Forget);
                }
            });
        }
        if let Some(r) = d.report.clone().filter(|_| d.has_text()) {
            ui.separator();
            chips(ui, l, &r);
            map_changed |= mapping(ui, l, d, ours, help);
            details(ui, l, &r);
        }
        if let Some(done) = &d.done {
            ui.separator();
            let v = ui.visuals().clone();
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, &format!("{} {}", n(done, &["added"]), tr_in(SCOPE, l, "imported")), Kind::Green.tone(&v));
                chip::chip(ui, &format!("{} {}", n(done, &["replaced"]), tr_in(SCOPE, l, "replaced")), Kind::Neutral.tone(&v));
                chip::chip(ui, &format!("{} {}", n(done, &["skipped"]), tr_in(SCOPE, l, "skipped")), Kind::Neutral.tone(&v));
            });
            ui.colored_label(warn, tr_in(SCOPE, l, "Now delete the export file (and its copies): it holds every password."));
        }
        if d.has_text() {
            ui.separator();
            ui.horizontal(|ui| {
                if table::action(ui, tr_in(SCOPE, l, "Preview"), can.clone()) {
                    pressed = Some(Button::Preview);
                }
                if table::action(ui, tr_in(SCOPE, l, "Import"), can.clone().and_then(|()| d.ready())) {
                    pressed = Some(Button::Import);
                }
                if safe_on {
                    ui.label(tr_in(SCOPE, l, "Safe Mode is on: losing the router undoes the import."));
                } else {
                    ui.weak(tr_in(SCOPE, l, "The import is one change (one revision)."));
                    if table::action(ui, tr_in(SCOPE, l, "Enter Safe Mode"), can_safe.clone()) {
                        pressed = Some(Button::SafeMode);
                    }
                }
            });
        }
        Footer { buttons: Buttons::View, ok: Ok(()), extra: Vec::new(), pressed }
    });
    d.status = status;
    // A paste goes straight into the export (never drawn, never kept twice).
    if !d.paste.is_empty() {
        let p = std::mem::take(&mut d.paste);
        d.take("pasted", p.into_bytes());
    }
    match pressed {
        Some(Press::Cancel | Press::Ok) => {
            d.forget();
            app.floats.forget(wid);
            return false;
        }
        Some(Press::Other(Button::Load)) => {
            let path = d.path.trim().to_owned();
            match crate::export::open(ctx, &path) {
                Ok(b) => d.take(&path, b),
                Err(e) => d.status.error = Some(e),
            }
        }
        Some(Press::Other(Button::Forget)) => d.forget(),
        Some(Press::Other(Button::Preview)) => send(d, app, true),
        Some(Press::Other(Button::Import)) => send(d, app, false),
        Some(Press::Other(Button::SafeMode)) => {
            app.run("config.safe-mode.enter", json!({}));
        }
        _ => {}
    }
    if map_changed && d.has_text() && !d.status.busy() {
        send(d, app, true);
    }
    true
}

fn conflict_label(v: &str) -> &'static str {
    match v {
        "replace" => "replace ours",
        "rename" => "import renamed (-2)",
        _ => "skip (keep ours)",
    }
}

fn send(d: &mut ImportDialog, app: &mut CoreRouterUi, dry_run: bool) {
    d.status.sent();
    let then = crate::panel::then(crate::ppp::NAME, Reply { dialog: d.id, dry_run });
    app.run_then(COMMAND, d.params(dry_run), then);
}

/// A reply for the dialog: the preview, or what the import did.
pub(crate) fn replied(d: &mut ImportDialog, r: &Reply, result: &Result<Value, String>) {
    if r.dialog != d.id {
        return;
    }
    d.status.replied(result);
    let Ok(v) = result else {
        return;
    };
    if r.dry_run {
        d.report = Some(v.clone());
    } else {
        d.done = Some(v.clone());
        // Imported: the passwords are not needed here any more.
        d.forget();
    }
}

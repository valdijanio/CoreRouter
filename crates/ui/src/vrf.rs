//! The IP › VRF window, WinBox style: each VRF with its routing table and
//! member interfaces, with the toolbar, context menus, "New VRF" and
//! "VRF <name>" windows of the G1.9 table.
//!
//! The engine decides who may join a VRF (`ip.vrf.add`/`ip.vrf.set`); the
//! member list only leaves out what it would refuse, so the choice is short.
//! Every change goes through `CoreRouterUi::run`.

use std::collections::BTreeSet;

use egui::{Grid, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::interfaces::{Iface, cascade, field, opt_text};
use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment, num};
use crate::{CoreRouterUi, Then, value_text};

pub(crate) const TABLE: &str = "vrf";
/// Property windows opened at once from one selection.
const MAX_OPEN: usize = 8;
/// Height of the member list before it scrolls, in points.
const MEMBERS_HEIGHT: f32 = 220.0;

const COLUMNS: [table::Column; 5] = [
    col(""),
    col("Name"),
    num("Table"),
    col("Interfaces"),
    comment(),
];

/// One row of `ip.vrf.list`.
#[derive(Clone, Default)]
pub(crate) struct Vrf {
    pub name: String,
    pub table: String,
    pub interfaces: Vec<String>,
    pub disabled: bool,
    pub comment: String,
}

impl Vrf {
    fn from_row(row: &Value) -> Self {
        let text = |k: &str| row.get(k).map(value_text).unwrap_or_default();
        Self {
            name: text("name"),
            table: text("table"),
            interfaces: row
                .get("interfaces")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(value_text).collect())
                .unwrap_or_default(),
            disabled: row
                .get("disabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            comment: text("comment"),
        }
    }
}

/// Toolbar, menus and shortcuts all end up as one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

/// The editable fields of a VRF, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VrfForm {
    pub name: String,
    pub members: BTreeSet<String>,
    pub comment: String,
    pub disabled: bool,
}

impl VrfForm {
    fn of(v: &Vrf) -> Self {
        Self {
            name: v.name.clone(),
            members: v.interfaces.iter().cloned().collect(),
            comment: v.comment.clone(),
            disabled: v.disabled,
        }
    }

    /// `ip.vrf.add` params; blank optional fields are left to the engine.
    fn add_params(&self) -> Value {
        json!({
            "name": self.name.trim(),
            "interfaces": self.members,
            "comment": opt_text(&self.comment),
        })
    }

    /// `ip.vrf.set` params for what differs from `base`; `None` if nothing.
    fn set_params(&self, base: &VrfForm) -> Option<Value> {
        let mut p = Map::new();
        if self.members != base.members {
            p.insert("interfaces".into(), json!(self.members));
        }
        if self.comment != base.comment {
            p.insert("comment".into(), json!(self.comment));
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("name".into(), json!(base.name));
        Some(Value::Object(p))
    }
}

pub(crate) enum VrfDialog {
    New(VrfForm),
    /// "VRF <name>"; `base` is what the engine has.
    Props {
        form: VrfForm,
        base: VrfForm,
    },
    Comment {
        targets: Vec<String>,
        text: String,
    },
}

pub(crate) struct VrfDialogWin {
    pub id: u64,
    pub dialog: VrfDialog,
    pub error: Option<String>,
    pub waiting: usize,
    pub close_on_success: bool,
}

/// What a dialog's command changes in the dialog when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    /// "New VRF" + Apply: open the created VRF's window.
    OpenCreated,
    /// The form sent by OK/Apply is the engine's now.
    Applied(VrfForm),
    /// Enable/Disable button.
    Toggled(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Ok,
    Apply,
    Cancel,
    Toggle,
    Remove,
}

impl CoreRouterUi {
    fn vrf_rows(&self) -> Vec<Vrf> {
        self.cache.vrfs.iter().map(Vrf::from_row).collect()
    }

    fn vrf(&self, name: &str) -> Option<Vrf> {
        self.vrf_rows().into_iter().find(|v| v.name == name)
    }

    pub(crate) fn vrfs(&mut self, ui: &mut Ui) {
        let vrfs = self.vrf_rows();
        let rows: Vec<Row> = vrfs.iter().map(vrf_row).collect();
        let selection = self.tables.vrfs.selection(&rows);
        let picked: Vec<&Vrf> = vrfs
            .iter()
            .filter(|v| selection.contains(&v.name))
            .collect();
        let mut act: Option<Act> = None;

        ui.horizontal(|ui| {
            if table::tool(ui, TABLE, Icon::Add, "Add", Ok(())).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (Icon::Remove, "Remove", some(&picked)),
                (Icon::Enable, "Enable", can_enable(&picked, true)),
                (Icon::Disable, "Disable", can_enable(&picked, false)),
                (Icon::Comment, "Comment", some(&picked)),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Remove => Act::Remove(sel),
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        Icon::Add | Icon::Comment => Act::Comment(sel),
                    });
                }
            }
            table::find_field(ui, TABLE, &mut self.tables.vrfs);
        });
        ui.separator();

        let out = table::show(
            ui,
            TABLE,
            0.0,
            &mut self.tables.vrfs,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => row_menu(ui, &mut act, &vrfs, sel),
                Menu::Empty => {
                    if ui.button("Add VRF…").clicked() {
                        act = Some(Act::New);
                    }
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                    if ui.button("Refresh").clicked() {
                        act = Some(Act::Refresh);
                    }
                }
            },
        );
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(key) = out.comment {
            act = Some(Act::Comment(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.tables.vrfs.selection(&rows);
            let picked: Vec<&Vrf> = vrfs.iter().filter(|v| sel.contains(&v.name)).collect();
            // A shortcut that does not apply does nothing, like a greyed button.
            let allowed = match s {
                Shortcut::Remove | Shortcut::Comment | Shortcut::Open => some(&picked).is_ok(),
                Shortcut::Enable => can_enable(&picked, true).is_ok(),
                Shortcut::Disable => can_enable(&picked, false).is_ok(),
            };
            if allowed {
                act = Some(match s {
                    Shortcut::Remove => Act::Remove(sel),
                    Shortcut::Enable => Act::Enable(sel),
                    Shortcut::Disable => Act::Disable(sel),
                    Shortcut::Comment => Act::Comment(sel),
                    Shortcut::Open => Act::Open(sel),
                });
            }
        }
        if let Some(a) = act {
            self.vrf_act(a, &rows);
        }
    }

    fn vrf_act(&mut self, act: Act, rows: &[Row]) {
        match act {
            Act::Enable(names) => self.set_vrfs_disabled(&names, false),
            Act::Disable(names) => self.set_vrfs_disabled(&names, true),
            Act::Remove(names) => {
                for name in names {
                    self.run("ip.vrf.remove", json!({ "name": name }));
                }
            }
            Act::Comment(targets) => {
                let text = match targets.as_slice() {
                    [one] => self.vrf(one).map(|v| v.comment).unwrap_or_default(),
                    _ => String::new(),
                };
                if !targets.is_empty() {
                    self.open_vrf_dialog(VrfDialog::Comment { targets, text });
                }
            }
            Act::Open(names) => {
                for n in names.iter().take(MAX_OPEN) {
                    self.open_vrf(n);
                }
            }
            Act::New => self.open_vrf_dialog(VrfDialog::New(VrfForm::default())),
            Act::SelectAll => self.tables.vrfs.select_all(rows),
            Act::Refresh => self.cache.refreshed_at = None,
        }
    }

    fn set_vrfs_disabled(&mut self, names: &[String], disabled: bool) {
        for name in names {
            self.run("ip.vrf.set", json!({ "name": name, "disabled": disabled }));
        }
    }

    fn open_vrf_dialog(&mut self, dialog: VrfDialog) {
        self.next_dialog = self.next_dialog.wrapping_add(1);
        self.vrf_dialogs.push(VrfDialogWin {
            id: self.next_dialog,
            dialog,
            error: None,
            waiting: 0,
            close_on_success: false,
        });
    }

    /// "VRF <name>"; an already open one is not duplicated.
    pub(crate) fn open_vrf(&mut self, name: &str) {
        let Some(v) = self.vrf(name) else { return };
        let open = self
            .vrf_dialogs
            .iter()
            .any(|d| matches!(&d.dialog, VrfDialog::Props { base, .. } if base.name == v.name));
        if !open {
            self.open_vrf_dialog(VrfDialog::Props {
                form: VrfForm::of(&v),
                base: VrfForm::of(&v),
            });
        }
    }

    /// Draw every open VRF dialog as its own floating window.
    pub(crate) fn vrf_dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let vrfs = self.vrf_rows();
        let ifaces = self.ifaces();
        let mut dialogs = std::mem::take(&mut self.vrf_dialogs);
        dialogs.retain_mut(|d| {
            // A VRF window whose VRF is gone closes itself.
            if let VrfDialog::Props { base, .. } = &d.dialog
                && !vrfs.iter().any(|v| v.name == base.name)
            {
                return false;
            }
            let mut open = true;
            let mut pressed = None;
            egui::Window::new(dialog_title(&d.dialog))
                .id(egui::Id::unique(("corerouter-vrf-dialog", d.id)))
                .open(&mut open)
                .constrain_to(area)
                .default_pos(cascade(area, d.id))
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    let busy = d.waiting > 0;
                    pressed = dialog_body(ui, d, &vrfs, &ifaces, busy);
                });
            open && pressed.is_none_or(|b| self.vrf_button(d, b, &vrfs))
        });
        dialogs.append(&mut self.vrf_dialogs);
        self.vrf_dialogs = dialogs;
    }

    /// Send what a button means. Returns whether the dialog stays open now;
    /// closing on success is decided when the replies arrive.
    fn vrf_button(&mut self, d: &mut VrfDialogWin, b: Button, vrfs: &[Vrf]) -> bool {
        if b == Button::Cancel {
            return false;
        }
        let (sends, close): (Vec<(&str, Value, Effect)>, bool) = match &d.dialog {
            VrfDialog::New(form) => {
                let effect = if b == Button::Apply {
                    Effect::OpenCreated
                } else {
                    Effect::None
                };
                (vec![("ip.vrf.add", form.add_params(), effect)], true)
            }
            VrfDialog::Props { form, base } => match b {
                Button::Ok | Button::Apply => match form.set_params(base) {
                    Some(p) => (
                        vec![("ip.vrf.set", p, Effect::Applied(form.clone()))],
                        b == Button::Ok,
                    ),
                    // OK with nothing changed just closes.
                    None => return b != Button::Ok,
                },
                Button::Toggle => {
                    let now = vrfs
                        .iter()
                        .find(|v| v.name == base.name)
                        .is_some_and(|v| v.disabled);
                    (
                        vec![(
                            "ip.vrf.set",
                            json!({"name": base.name, "disabled": !now}),
                            Effect::Toggled(!now),
                        )],
                        false,
                    )
                }
                Button::Remove => (
                    vec![("ip.vrf.remove", json!({ "name": base.name }), Effect::None)],
                    true,
                ),
                Button::Cancel => return false,
            },
            VrfDialog::Comment { targets, text } => (
                targets
                    .iter()
                    .map(|t| {
                        (
                            "ip.vrf.set",
                            json!({"name": t, "comment": text}),
                            Effect::None,
                        )
                    })
                    .collect(),
                true,
            ),
        };
        d.close_on_success = close;
        d.error = None;
        for (cmd, params, effect) in sends {
            d.waiting += 1;
            self.run_then(cmd, params, Then::Vrf { id: d.id, effect });
        }
        true
    }

    /// A reply to a VRF dialog's command: an error stays in the dialog.
    pub(crate) fn vrf_dialog_reply(
        &mut self,
        id: u64,
        effect: Effect,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.vrf_dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut created = None;
        let close = match self.vrf_dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                d.waiting = d.waiting.saturating_sub(1);
                match (result, effect, &mut d.dialog) {
                    (Err(e), _, _) => d.error = Some(e.clone()),
                    (Ok(r), Effect::OpenCreated, _) => {
                        created = r.get("name").and_then(Value::as_str).map(str::to_owned);
                    }
                    (Ok(_), Effect::Applied(sent), VrfDialog::Props { base, form }) => {
                        *base = sent;
                        form.disabled = base.disabled;
                    }
                    (Ok(_), Effect::Toggled(now), VrfDialog::Props { base, form }) => {
                        base.disabled = now;
                        form.disabled = now;
                    }
                    (Ok(_), _, _) => {}
                }
                d.waiting == 0 && d.close_on_success && d.error.is_none()
            }
        };
        if close {
            self.vrf_dialogs.remove(pos);
        }
        if let Some(name) = created {
            // Opens when an `ip.vrf.list` that has it arrives.
            let list = self.reload();
            self.open_vrf_after.push((list, name));
        }
    }
}

fn vrf_row(v: &Vrf) -> Row {
    Row {
        key: v.name.clone(),
        cells: vec![
            if v.disabled { "X" } else { "" }.into(),
            v.name.clone(),
            v.table.clone(),
            v.interfaces.join(", "),
            v.comment.clone(),
        ],
        dimmed: v.disabled,
    }
}

fn some(picked: &[&Vrf]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more VRFs first".into())
    } else {
        Ok(())
    }
}

fn can_enable(picked: &[&Vrf], enable: bool) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|v| v.disabled == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

/// Interfaces worth offering as members of `vrf` (`None`: a new one): not a
/// VRF, not a bridge port, not in another VRF. The engine checks again.
fn candidates(ifaces: &[Iface], vrf: Option<&str>) -> Vec<String> {
    ifaces
        .iter()
        .filter(|i| i.kind != "vrf" && i.bridge.is_none())
        .filter(|i| i.vrf.is_none() || i.vrf.as_deref() == vrf)
        .map(|i| i.name.clone())
        .collect()
}

fn row_menu(ui: &mut Ui, act: &mut Option<Act>, vrfs: &[Vrf], sel: &[String]) {
    let picked: Vec<&Vrf> = vrfs.iter().filter(|v| sel.contains(&v.name)).collect();
    let owned = || sel.to_vec();
    if action(ui, "Enable", can_enable(&picked, true)) {
        *act = Some(Act::Enable(owned()));
    }
    if action(ui, "Disable", can_enable(&picked, false)) {
        *act = Some(Act::Disable(owned()));
    }
    if action(ui, "Remove", some(&picked)) {
        *act = Some(Act::Remove(owned()));
    }
    if action(ui, "Comment…", some(&picked)) {
        *act = Some(Act::Comment(owned()));
    }
    if action(ui, "Properties…", some(&picked)) {
        *act = Some(Act::Open(owned()));
    }
    ui.separator();
    if ui.button("Add VRF…").clicked() {
        *act = Some(Act::New);
    }
}

fn dialog_title(d: &VrfDialog) -> String {
    match d {
        VrfDialog::New(_) => "New VRF".into(),
        VrfDialog::Props { base, .. } => format!("VRF <{}>", base.name),
        VrfDialog::Comment { targets, .. } => match targets.as_slice() {
            [one] => format!("Comment for VRF <{one}>"),
            many => format!("Comment for {} VRFs", many.len()),
        },
    }
}

/// The member picker: one checkbox per interface that may join.
fn members(ui: &mut Ui, salt: u64, chosen: &mut BTreeSet<String>, offer: &[String]) {
    ui.label("Interfaces")
        .on_hover_text("Bridge ports and members of other VRFs are not listed");
    ui.vertical(|ui| {
        // A member the list no longer offers stays visible so it can be
        // taken out.
        let extra: Vec<String> = chosen
            .iter()
            .filter(|m| !offer.contains(m))
            .cloned()
            .collect();
        if offer.is_empty() && extra.is_empty() {
            ui.weak("no interface can join");
        }
        ScrollArea::vertical()
            .id_salt(("vrf-members", salt))
            .max_height(MEMBERS_HEIGHT)
            .min_scrolled_height(MEMBERS_HEIGHT)
            .show(ui, |ui| {
                for name in offer.iter().chain(&extra) {
                    let mut on = chosen.contains(name);
                    if ui.checkbox(&mut on, name.as_str()).changed() {
                        if on {
                            chosen.insert(name.clone());
                        } else {
                            chosen.remove(name);
                        }
                    }
                }
            });
    });
    ui.end_row();
}

fn read_only(ui: &mut Ui, label: &str, value: &str) {
    ui.label(label);
    ui.add_enabled(
        false,
        TextEdit::singleline(&mut value.to_owned()).desired_width(180.0),
    );
    ui.end_row();
}

/// Fields + buttons of one dialog. Returns the button pressed, if any.
fn dialog_body(
    ui: &mut Ui,
    d: &mut VrfDialogWin,
    vrfs: &[Vrf],
    ifaces: &[Iface],
    busy: bool,
) -> Option<Button> {
    let mut toggle_label = None;
    Grid::new("fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| match &mut d.dialog {
            VrfDialog::New(form) => {
                field(ui, "Name", &mut form.name, "vrf1");
                members(ui, d.id, &mut form.members, &candidates(ifaces, None));
                field(ui, "Comment", &mut form.comment, "");
            }
            VrfDialog::Props { form, base } => {
                read_only(ui, "Name", &base.name);
                if let Some(v) = vrfs.iter().find(|v| v.name == base.name) {
                    read_only(ui, "Routing Table", &v.table);
                    toggle_label = Some(if v.disabled { "Enable" } else { "Disable" });
                }
                let offer = candidates(ifaces, Some(&base.name));
                members(ui, d.id, &mut form.members, &offer);
                field(ui, "Comment", &mut form.comment, "");
                ui.label("Disabled");
                ui.checkbox(&mut form.disabled, "");
                ui.end_row();
            }
            VrfDialog::Comment { text, .. } => field(ui, "Comment", text, ""),
        });
    if let Some(e) = d.error.as_deref() {
        ui.colored_label(ui.visuals().error_fg_color, e);
    }
    ui.separator();
    let mut pressed = None;
    ui.horizontal(|ui| {
        // While the router has not answered, only Cancel works.
        let mut btn = |ui: &mut Ui, text: &str, b: Button| {
            let enabled = !busy || b == Button::Cancel;
            if ui.add_enabled(enabled, egui::Button::new(text)).clicked() {
                pressed = Some(b);
            }
        };
        btn(ui, "OK", Button::Ok);
        btn(ui, "Cancel", Button::Cancel);
        if !matches!(d.dialog, VrfDialog::Comment { .. }) {
            btn(ui, "Apply", Button::Apply);
        }
        if let Some(t) = toggle_label {
            btn(ui, t, Button::Toggle);
            btn(ui, "Remove", Button::Remove);
        }
        if busy {
            ui.weak("…");
        }
    });
    pressed
}

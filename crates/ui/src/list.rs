//! The list window pattern (G0.24, `docs/ui-style.md`, "Janela de lista e
//! modal de adicionar"): the parts every window listing configurable items
//! shares, so a window adopts them instead of copying another's code.
//!
//! - [`Tools`] + [`toolbar`]: **+ − ✓ ✗ 💬**, each greyed with the reason
//!   (the router's, from `engine.list`'s `enabled`/`disabledReason`, then
//!   the selection's, from what each row says about itself: [`Item`]);
//! - [`Filters`]: filter chips by a row field (family, origin, state…);
//! - [`footer`] + [`count`]: counts under the table (total, per state…);
//! - [`row_menu`]: the right-click menu (edit, copy, copy as command,
//!   enable/disable, remove) and [`from_shortcut`] for the keyboard;
//! - [`copy_rows`] / [`copy_commands`]: what the copies put on the
//!   clipboard (the command that recreates a row, in CoreRouter's form and
//!   RouterOS's, from the router's own command list);
//! - [`CoreRouterUi::run_steps`]: several commands as one transaction.
//!
//! The add/edit modal is [`crate::list_modal`]. Nothing here decides what a
//! row may do: the engine says it (`disabled`, `dynamic`, a reason).

use std::collections::BTreeSet;

use egui::{Sense, Ui};
use serde_json::{Value, json};

use crate::avail::Avail;
use crate::chip::{self, Tone};
use crate::i18n::{Lang, tr};
use crate::table::{self, Icon, Selection, Shortcut};
use crate::{CoreRouterUi, Pending, Then};

/// What one row says about itself, from the router's list reply.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Item {
    pub key: String,
    pub disabled: bool,
    /// Why it cannot be removed, enabled or disabled here (a dynamic item:
    /// "comes from the DHCP client …"); `None`: it can.
    pub fixed: Option<String>,
}

impl Item {
    /// From a list row: `key` names its id field; `disabled` and
    /// `dynamic` are the usual booleans; a dynamic row is fixed with
    /// `dynamic_why`.
    pub(crate) fn of(row: &Value, key: &str, dynamic_why: &str) -> Self {
        let flag = |k: &str| row.get(k).and_then(Value::as_bool).unwrap_or(false);
        Self {
            key: row.get(key).map(crate::value_text).unwrap_or_default(),
            disabled: flag("disabled"),
            fixed: flag("dynamic").then(|| dynamic_why.to_owned()),
        }
    }
}

/// The commands a list acts with; `set` takes `{id, disabled?, comment?}`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cmds {
    pub add: &'static str,
    pub remove: &'static str,
    pub set: Option<&'static str>,
    /// What the items are, plural, for the reasons ("addresses").
    pub what: &'static str,
}

/// Whether each button of the bar can act now, and why not.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Tools {
    pub add: Result<(), String>,
    pub remove: Result<(), String>,
    pub enable: Result<(), String>,
    pub disable: Result<(), String>,
    pub comment: Result<(), String>,
}

impl Tools {
    /// The rules of the bar: the router's reason first, then the
    /// selection's (`picked`: the selected rows).
    pub(crate) fn new(can: &Avail, cmds: &Cmds, picked: &[Item]) -> Self {
        let none = || -> Result<(), String> {
            if picked.is_empty() {
                Err(format!("Select one or more {} first", cmds.what))
            } else {
                Ok(())
            }
        };
        let fixed = || match picked.iter().find_map(|i| i.fixed.clone()) {
            Some(why) => Err(why),
            None => Ok(()),
        };
        let set = |rule: Result<(), String>| match cmds.set {
            Some(id) => can.and(id, rule),
            None => Err(format!("these {} have no settings to change", cmds.what)),
        };
        let toggle = |to_disabled: bool| {
            none()?;
            fixed()?;
            if picked.iter().any(|i| i.disabled != to_disabled) {
                Ok(())
            } else if to_disabled {
                Err("Already disabled".to_owned())
            } else {
                Err("Already enabled".to_owned())
            }
        };
        Self {
            add: can.check(cmds.add),
            remove: can.and(cmds.remove, none().and_then(|()| fixed())),
            enable: set(toggle(false)),
            disable: set(toggle(true)),
            comment: set(none().and_then(|()| fixed())),
        }
    }
}

/// What the operator asked of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Act {
    Add,
    /// Open the item in the modal (double click, Enter, menu).
    Edit(String),
    Remove(Vec<String>),
    Enable(Vec<String>),
    Disable(Vec<String>),
    Comment(Vec<String>),
    /// The rows' text, tab-separated.
    Copy(Vec<String>),
    /// The commands that recreate the rows.
    CopyAs(Vec<String>, Syntax),
}

/// How a copied command is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Syntax {
    /// `ip.address.add {"address": …}`: the CLI, the control channel, MCP.
    CoreRouter,
    /// `/ip address add address=…`: RouterOS and CoreRouter's terminal.
    RouterOs,
}

/// The bar: + − ✓ ✗ 💬 with their reasons. Filters and Find go after it on
/// the same line (the caller draws them).
pub(crate) fn toolbar(ui: &mut Ui, salt: &str, tools: &Tools, sel: &Selection, l: Lang) -> Option<Act> {
    let mut act = None;
    let buttons = [
        (Icon::Add, "Add", &tools.add),
        (Icon::Remove, "Remove", &tools.remove),
        (Icon::Enable, "Enable", &tools.enable),
        (Icon::Disable, "Disable", &tools.disable),
        (Icon::Comment, "Comment", &tools.comment),
    ];
    for (icon, tip, enabled) in buttons {
        if table::tool(ui, salt, icon, tr(l, tip), enabled.clone()).clicked() {
            act = Some(icon_act(icon, sel));
        }
    }
    act
}

fn icon_act(icon: Icon, sel: &Selection) -> Act {
    let keys = sel.to_vec();
    match icon {
        Icon::Add => Act::Add,
        Icon::Remove => Act::Remove(keys),
        Icon::Enable => Act::Enable(keys),
        Icon::Disable => Act::Disable(keys),
        Icon::Comment => Act::Comment(keys),
    }
}

/// A table key (Delete, Enter, Ctrl+E/D, Ctrl+M…) as the button it stands
/// for, only when that button could act.
pub(crate) fn from_shortcut(s: Option<Shortcut>, tools: &Tools, sel: &Selection) -> Option<Act> {
    let (icon, ok) = match s? {
        Shortcut::Remove => (Icon::Remove, &tools.remove),
        Shortcut::Enable => (Icon::Enable, &tools.enable),
        Shortcut::Disable => (Icon::Disable, &tools.disable),
        Shortcut::Comment => (Icon::Comment, &tools.comment),
        Shortcut::Open => return sel.first().cloned().map(Act::Edit),
    };
    ok.is_ok().then(|| icon_act(icon, sel))
}

/// The right-click menu on selected rows (call it from `table::show`'s
/// `Menu::Rows`). `can_copy_as`: the router's `add` is known, so the
/// commands can be written.
pub(crate) fn row_menu(ui: &mut Ui, tools: &Tools, sel: &Selection, can_copy_as: bool, l: Lang) -> Option<Act> {
    let keys = || sel.to_vec();
    let mut act = None;
    if let [one] = sel.as_slice()
        && ui.button(tr(l, "Open…")).clicked()
    {
        act = Some(Act::Edit(one.clone()));
    }
    if ui.button(tr(l, "Copy")).clicked() {
        act = Some(Act::Copy(keys()));
    }
    let as_cmd: Result<(), String> = if can_copy_as {
        Ok(())
    } else {
        Err("the router's command list has not arrived yet".to_owned())
    };
    if table::action(ui, tr(l, "Copy as CoreRouter command"), as_cmd.clone()) {
        act = Some(Act::CopyAs(keys(), Syntax::CoreRouter));
    }
    if table::action(ui, tr(l, "Copy as RouterOS command"), as_cmd) {
        act = Some(Act::CopyAs(keys(), Syntax::RouterOs));
    }
    ui.separator();
    for (icon, label, enabled) in [
        (Icon::Enable, "Enable", &tools.enable),
        (Icon::Disable, "Disable", &tools.disable),
        (Icon::Comment, "Comment…", &tools.comment),
        (Icon::Remove, "Remove", &tools.remove),
    ] {
        if table::action(ui, tr(l, label), enabled.clone()) {
            act = Some(icon_act(icon, sel));
        }
    }
    if act.is_some() {
        ui.close();
    }
    act
}

/// Filter chips over row fields: per field, the values switched on; a
/// field with none on lets every row through.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Filters {
    on: BTreeSet<(String, String)>,
}

impl Filters {
    pub(crate) fn is_on(&self, field: &str, value: &str) -> bool {
        self.on.contains(&(field.to_owned(), value.to_owned()))
    }

    pub(crate) fn toggle(&mut self, field: &str, value: &str) {
        let k = (field.to_owned(), value.to_owned());
        if !self.on.remove(&k) {
            self.on.insert(k);
        }
    }

    /// Whether `row` passes: for each field with chips on, its value is
    /// one of them.
    pub(crate) fn shows(&self, row: &Value) -> bool {
        let fields: BTreeSet<&str> = self.on.iter().map(|(f, _)| f.as_str()).collect();
        fields.into_iter().all(|f| {
            let v = row.get(f).map(crate::value_text).unwrap_or_default();
            self.is_on(f, &v)
        })
    }

    /// One chip per `(value, label)` of `field`; blue while on.
    pub(crate) fn chips(&mut self, ui: &mut Ui, field: &str, values: &[(&str, &'static str)], l: Lang) {
        for (value, label) in values {
            if filter_chip(ui, tr(l, label), self.is_on(field, value)) {
                self.toggle(field, value);
            }
        }
    }
}

/// A clickable chip: blue when on. Returns whether it was clicked.
pub(crate) fn filter_chip(ui: &mut Ui, text: &str, on: bool) -> bool {
    let tone = if on {
        chip::BLUE.tone(ui.visuals())
    } else {
        chip::neutral_tone(ui.visuals())
    };
    chip::chip(ui, text, tone)
        .interact(Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// How many `rows` have `field` = `value`.
pub(crate) fn count(rows: &[Value], field: &str, value: &str) -> usize {
    rows.iter()
        .filter(|r| r.get(field).map(crate::value_text).as_deref() == Some(value))
        .count()
}

/// The counts under the table, as chips; zero counts after the first are
/// left out (an "0 invalid" says nothing).
pub(crate) fn footer(ui: &mut Ui, counts: &[(usize, &'static str, Tone)], l: Lang) {
    ui.horizontal_wrapped(|ui| {
        for (i, (n, label, tone)) in counts.iter().enumerate() {
            if i == 0 || *n > 0 {
                chip::chip(ui, &format!("{n} {}", tr(l, label)), *tone);
            }
        }
    });
}

/// The rows' cells, one line each, tab-separated (empty cells kept).
pub(crate) fn copy_rows(rows: &[&table::Row]) -> String {
    rows.iter()
        .map(|r| {
            r.cells
                .iter()
                .map(|c| chip::split(c).0.trim())
                .collect::<Vec<_>>()
                .join("\t")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The router's command list as the terminal's registry.
fn registry(app: &CoreRouterUi) -> corerouter_shell::Registry {
    corerouter_shell::Registry::from_list(&Value::Array(app.cache.commands.clone()))
}

/// One command written in `syntax`.
pub(crate) fn command_text(reg: &corerouter_shell::Registry, id: &str, params: &Value, syntax: Syntax) -> String {
    match syntax {
        Syntax::CoreRouter => format!("{id} {params}"),
        Syntax::RouterOs => {
            corerouter_shell::command_line(reg, id, params).unwrap_or_else(|| format!("{id} {params}"))
        }
    }
}

/// The commands (`add`, with what the router's `add` declares) that
/// recreate `rows`, one per line; rows `add` cannot recreate are left out.
pub(crate) fn copy_commands(app: &CoreRouterUi, add: &str, rows: &[&Value], syntax: Syntax) -> String {
    let reg = registry(app);
    rows.iter()
        .filter_map(|r| corerouter_shell::recreate(&reg, add, r))
        .map(|p| command_text(&reg, add, &p, syntax))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `steps` (`[{command, params}]`) written in the terminal's syntax, for a
/// preview.
pub(crate) fn steps_text(app: &CoreRouterUi, steps: &[Value]) -> Vec<String> {
    let reg = registry(app);
    steps
        .iter()
        .map(|s| {
            let id = s.get("command").and_then(Value::as_str).unwrap_or("");
            // A secret the modal sends never shows on screen.
            let p = crate::redact::redacted(&s.get("params").cloned().unwrap_or(Value::Null));
            command_text(&reg, id, &p, Syntax::RouterOs)
        })
        .collect()
}

impl CoreRouterUi {
    /// Several commands as one transaction (`engine.batch`, atomic: all
    /// or nothing); one command goes as itself, so a lockout refusal can be
    /// answered (G2.1b). The reply goes to `then` like [`Self::run_then`]'s.
    pub(crate) fn run_steps(&mut self, steps: Vec<Value>, then: Then) -> crate::backend::RequestId {
        if let [one] = steps.as_slice() {
            let id = one.get("command").and_then(Value::as_str).unwrap_or("");
            let p = one.get("params").cloned().unwrap_or(Value::Null);
            return self.run_then(id, p, then);
        }
        let blocked = steps.iter().find_map(|s| {
            let id = s.get("command").and_then(Value::as_str).unwrap_or("");
            self.can.check(id).err()
        });
        if let Some(why) = blocked {
            self.note(false, "engine.batch", why.clone());
            self.answer_then(then, &Err(why));
            return 0;
        }
        let params = json!({"steps": steps, "atomic": true});
        let req = self.backend.submit("engine.batch", params.clone());
        self.pending.insert(
            req,
            Pending::Action {
                command: "engine.batch".into(),
                params,
                then,
            },
        );
        req
    }
}

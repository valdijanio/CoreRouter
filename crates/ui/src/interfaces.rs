//! The Interfaces window, WinBox style: toolbar, selectable table, context
//! menus, and the floating "New …" / "Interface <name>" / "Comment" dialogs.
//!
//! The greyed-out reasons here are only hints read from `interface.list`
//! (e.g. a physical port has nothing to remove); the engine is the authority
//! and every action still goes through `CoreRouterUi::run`.

use egui::{Grid, TextEdit, Ui};
use serde_json::{Value, json};

use crate::avail::Avail;
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment, num};
use crate::{CoreRouterUi, Then, form_number, human_bytes, value_text};

pub(crate) const TABLE: &str = "interfaces";
/// Property windows opened at once from one selection (WinBox opens one
/// per item; a hundred at a time helps nobody).
const MAX_OPEN: usize = 8;

const COLUMNS: [table::Column; 10] = [
    col(""),
    col("Name"),
    col("Type"),
    num("MTU"),
    num("Rx"),
    num("Tx"),
    num("Rx pkt"),
    num("Tx pkt"),
    col("Info"),
    comment(),
];

/// One row of `interface.list`, as the UI needs it for menus and dialogs.
#[derive(Clone, Default)]
pub(crate) struct Iface {
    pub name: String,
    pub kind: String,
    pub mtu: String,
    pub disabled: bool,
    pub running: bool,
    pub comment: String,
    pub parent: Option<String>,
    pub vlan_id: Option<String>,
    pub bridge: Option<String>,
    pub vrf: Option<String>,
    pub table: Option<String>,
}

impl Iface {
    fn from_row(row: &Value) -> Self {
        let text = |k: &str| row.get(k).map(value_text).unwrap_or_default();
        let opt = |k: &str| row.get(k).filter(|v| !v.is_null()).map(value_text);
        let flag = |k: &str| row.get(k).and_then(Value::as_bool).unwrap_or(false);
        Self {
            name: text("name"),
            kind: text("type"),
            mtu: text("mtu"),
            disabled: flag("disabled"),
            running: flag("running"),
            comment: text("comment"),
            parent: opt("parent"),
            vlan_id: opt("vlan_id"),
            bridge: opt("bridge"),
            vrf: opt("vrf"),
            table: opt("table"),
        }
    }

    fn physical(&self) -> bool {
        self.kind == "ether"
    }
}

/// Everything the toolbar, menus and shortcuts can ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Comment(Vec<String>),
    Open(Vec<String>),
    NewVlan { parent: Option<String> },
    NewBridge,
    NewLoopback,
    AddToBridge { bridge: String, ports: Vec<String> },
    RemoveFromBridge(Vec<String>),
    SelectAll,
    Refresh,
}

/// A floating dialog; several can be open at once, like WinBox windows.
pub(crate) enum Dialog {
    NewVlan {
        name: String,
        parent: String,
        vlan_id: String,
        mtu: String,
        comment: String,
    },
    NewBridge {
        name: String,
        comment: String,
    },
    NewLoopback {
        name: String,
        comment: String,
    },
    Comment {
        targets: Vec<String>,
        text: String,
        /// The text when the dialog opened.
        base: String,
    },
    Props(Props),
}

impl Dialog {
    /// Edits not saved yet (the dot in the title).
    fn dirty(&self) -> bool {
        match self {
            Dialog::NewVlan {
                name,
                vlan_id,
                mtu,
                comment,
                ..
            } => [name, vlan_id, mtu, comment].iter().any(|f| !f.is_empty()),
            Dialog::NewBridge { name, comment } | Dialog::NewLoopback { name, comment } => {
                !name.is_empty() || !comment.is_empty()
            }
            Dialog::Comment { text, base, .. } => text != base,
            Dialog::Props(p) => p.changes().is_some(),
        }
    }
}

/// Edit buffer of an "Interface <name>" window. `base_*` is what the
/// engine had when the window opened (or at the last Apply): only fields
/// that differ from it are sent.
pub(crate) struct Props {
    pub name: String,
    pub mtu: String,
    pub comment: String,
    pub disabled: bool,
    base_mtu: String,
    base_comment: String,
    base_disabled: bool,
    pub port_pick: String,
}

impl Props {
    fn new(i: &Iface) -> Self {
        Self {
            name: i.name.clone(),
            mtu: i.mtu.clone(),
            comment: i.comment.clone(),
            disabled: i.disabled,
            base_mtu: i.mtu.clone(),
            base_comment: i.comment.clone(),
            base_disabled: i.disabled,
            port_pick: String::new(),
        }
    }

    /// `interface.set` params for what changed; `None` when nothing did.
    fn changes(&self) -> Option<Value> {
        let mut p = serde_json::Map::new();
        if self.mtu.trim() != self.base_mtu {
            p.insert("mtu".into(), form_number(&self.mtu));
        }
        if self.comment != self.base_comment {
            p.insert("comment".into(), json!(self.comment));
        }
        if self.disabled != self.base_disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("name".into(), json!(self.name));
        Some(Value::Object(p))
    }
}

pub(crate) struct DialogWin {
    /// Stable egui id for the window, unique per dialog.
    pub id: u64,
    pub dialog: Dialog,
    pub status: Status,
}

/// What a dialog's command changes in the dialog when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    None,
    /// "New …" + Apply: open the created interface's window.
    OpenCreated,
    /// The values sent by OK/Apply are the engine's now.
    Applied {
        mtu: String,
        comment: String,
        disabled: bool,
    },
    /// Enable/Disable button.
    Toggled(bool),
}

/// The buttons of an "Interface <name>" window besides OK/Cancel/Apply.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Button {
    Toggle,
    Remove,
    /// Bridge port edits from an "Interface <bridge>" window apply at once:
    /// they are their own commands, not fields of `interface.set`.
    Port {
        add: bool,
        bridge: String,
        port: String,
    },
}

impl CoreRouterUi {
    pub(crate) fn ifaces(&self) -> Vec<Iface> {
        self.cache.interfaces.iter().map(Iface::from_row).collect()
    }

    fn iface(&self, name: &str) -> Option<Iface> {
        self.ifaces().into_iter().find(|i| i.name == name)
    }

    pub(crate) fn interfaces(&mut self, ui: &mut Ui) {
        let ifaces = self.ifaces();
        let rows: Vec<Row> = self.cache.interfaces.iter().map(iface_row).collect();
        let selection = self.tables.interfaces.selection(&rows);
        let picked: Vec<&Iface> = ifaces
            .iter()
            .filter(|i| selection.contains(&i.name))
            .collect();
        let bridges: Vec<String> = ifaces
            .iter()
            .filter(|i| i.kind == "bridge")
            .map(|i| i.name.clone())
            .collect();
        let mut act: Option<Act> = None;
        let can = self.can();

        ui.horizontal(|ui| {
            // Greyed out only when none of its kinds can be added.
            let can_add = ADD_KINDS
                .iter()
                .map(|(_, id)| can.check(id))
                .reduce(|a, b| a.or(b))
                .unwrap_or(Ok(()));
            let add = table::tool(ui, TABLE, Icon::Add, "Add", can_add);
            egui::Popup::menu(&add).show(|ui| add_menu(ui, &mut act, None, &can));
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and("interface.remove", can_remove(&picked)),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and("interface.set", can_enable(&picked, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and("interface.set", can_enable(&picked, false)),
                ),
                (
                    Icon::Comment,
                    "Comment",
                    can.and("interface.set", some(&picked)),
                ),
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
            table::find_field(ui, TABLE, &mut self.tables.interfaces);
        });
        ui.separator();

        let out = table::show(
            ui,
            TABLE,
            0.0,
            &mut self.tables.interfaces,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => row_menu(ui, &mut act, &ifaces, &bridges, sel, &can),
                Menu::Empty => {
                    ui.menu_button("Add", |ui| add_menu(ui, &mut act, None, &can));
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                    if ui.button("Refresh").clicked() {
                        act = Some(Act::Refresh);
                    }
                }
            },
        );
        if let Some(name) = out.opened {
            act = Some(Act::Open(vec![name]));
        }
        if let Some(name) = out.comment {
            act = Some(Act::Comment(vec![name]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.tables.interfaces.selection(&rows);
            if !sel.is_empty() {
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
            self.interface_act(a, &rows);
        }
    }

    pub(crate) fn interface_act(&mut self, act: Act, rows: &[Row]) {
        match act {
            Act::Enable(names) | Act::Disable(names) if names.is_empty() => {}
            Act::Enable(names) => self.set_disabled(&names, false),
            Act::Disable(names) => self.set_disabled(&names, true),
            Act::Remove(names) => {
                for n in names {
                    self.run("interface.remove", json!({ "name": n }));
                }
            }
            Act::Comment(targets) => {
                let text = match targets.as_slice() {
                    [one] => self.iface(one).map(|i| i.comment).unwrap_or_default(),
                    _ => String::new(),
                };
                self.open_dialog(Dialog::Comment {
                    targets,
                    base: text.clone(),
                    text,
                });
            }
            Act::Open(names) => {
                for n in names.iter().take(MAX_OPEN) {
                    self.open_props(n);
                }
            }
            Act::NewVlan { parent } => self.open_dialog(Dialog::NewVlan {
                name: String::new(),
                parent: parent.unwrap_or_default(),
                vlan_id: String::new(),
                mtu: String::new(),
                comment: String::new(),
            }),
            Act::NewBridge => self.open_dialog(Dialog::NewBridge {
                name: String::new(),
                comment: String::new(),
            }),
            Act::NewLoopback => self.open_dialog(Dialog::NewLoopback {
                name: String::new(),
                comment: String::new(),
            }),
            Act::AddToBridge { bridge, ports } => {
                for p in ports {
                    self.run(
                        "interface.bridge.port.add",
                        json!({"bridge": bridge, "interface": p}),
                    );
                }
            }
            Act::RemoveFromBridge(names) => {
                let picked: Vec<Iface> = names.iter().filter_map(|n| self.iface(n)).collect();
                for i in picked {
                    if let Some(b) = i.bridge {
                        self.run(
                            "interface.bridge.port.remove",
                            json!({"bridge": b, "interface": i.name}),
                        );
                    }
                }
            }
            Act::SelectAll => self.tables.interfaces.select_all(rows),
            Act::Refresh => self.cache.refreshed_at = None,
        }
    }

    fn set_disabled(&mut self, names: &[String], disabled: bool) {
        for n in names {
            self.run("interface.set", json!({ "name": n, "disabled": disabled }));
        }
    }

    fn open_dialog(&mut self, dialog: Dialog) {
        self.next_dialog = self.next_dialog.wrapping_add(1);
        self.dialogs.push(DialogWin {
            id: self.next_dialog,
            dialog,
            status: Status::default(),
        });
    }

    /// "Interface <name>"; an already open one is not duplicated.
    pub(crate) fn open_props(&mut self, name: &str) {
        let open = self
            .dialogs
            .iter()
            .any(|d| matches!(&d.dialog, Dialog::Props(p) if p.name == name));
        if let (false, Some(i)) = (open, self.iface(name)) {
            self.open_dialog(Dialog::Props(Props::new(&i)));
        }
    }

    /// Draw every open dialog as its own floating window.
    pub(crate) fn dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let ifaces = self.ifaces();
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            // A properties window whose interface is gone closes itself.
            let id = dialog_id(d.id);
            if let Dialog::Props(p) = &d.dialog
                && !ifaces.iter().any(|i| i.name == p.name)
            {
                self.floats.forget(id);
                return false;
            }
            let title = dialog_title(&d.dialog);
            let head = Head {
                id,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
            };
            let pressed =
                dialog::show(&mut self.floats, ctx, area, head, &mut d.status, |ui, f| {
                    dialog_body(ui, f, &mut d.dialog, &ifaces)
                });
            let keep = pressed.is_none_or(|b| self.dialog_button(d, b, &ifaces));
            if !keep {
                self.floats.forget(id);
            }
            keep
        });
        // Dialogs opened while these were drawn (Apply on "New …") go last.
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    /// Send what a dialog button means. Returns whether the dialog stays
    /// open now; whether it closes on success is decided when the replies
    /// arrive ([`CoreRouterUi::dialog_reply`]).
    fn dialog_button(&mut self, d: &mut DialogWin, b: Press<Button>, ifaces: &[Iface]) -> bool {
        if b == Press::Cancel {
            return false;
        }
        let open_after = if b == Press::Apply {
            Effect::OpenCreated
        } else {
            Effect::None
        };
        // "New …" closes on any success; Apply also opens what it made.
        let sends: Vec<(&str, Value, Effect)> = match &d.dialog {
            Dialog::NewVlan {
                name,
                parent,
                vlan_id,
                mtu,
                comment,
            } => vec![(
                "interface.vlan.add",
                json!({
                    "name": name.trim(),
                    "parent": parent,
                    "vlan_id": form_number(vlan_id),
                    "mtu": form_number(mtu),
                    "comment": opt_text(comment),
                }),
                open_after,
            )],
            Dialog::NewBridge { name, comment } => vec![(
                "interface.bridge.add",
                json!({"name": name.trim(), "comment": opt_text(comment)}),
                open_after,
            )],
            Dialog::NewLoopback { name, comment } => vec![(
                "interface.loopback.add",
                json!({"name": name.trim(), "comment": opt_text(comment)}),
                open_after,
            )],
            Dialog::Comment { targets, text, .. } => targets
                .iter()
                .map(|t| {
                    (
                        "interface.set",
                        json!({"name": t, "comment": text}),
                        Effect::None,
                    )
                })
                .collect(),
            Dialog::Props(p) => {
                let (sends, close) = props_sends(p, &b, ifaces);
                if sends.is_empty() {
                    // OK with nothing changed just closes.
                    return !close;
                }
                d.status.close_on_success = close;
                return self.send_dialog(d, sends);
            }
        };
        d.status.close_on_success = true;
        self.send_dialog(d, sends)
    }

    fn send_dialog(&mut self, d: &mut DialogWin, sends: Vec<(&str, Value, Effect)>) -> bool {
        for (id, params, effect) in sends {
            d.status.sent();
            self.run_then(id, params, Then::Dialog { id: d.id, effect });
        }
        true
    }

    /// A reply to a dialog's command. A failure shows the engine's error in
    /// the dialog and keeps it open; the dialog may be gone already.
    pub(crate) fn dialog_reply(&mut self, id: u64, effect: Effect, result: &Result<Value, String>) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let mut open_created = None;
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                match (result, effect, &mut d.dialog) {
                    (Err(_), _, _) => {}
                    (Ok(r), Effect::OpenCreated, _) => {
                        open_created = r.get("name").and_then(Value::as_str).map(str::to_owned);
                    }
                    (
                        Ok(_),
                        Effect::Applied {
                            mtu,
                            comment,
                            disabled,
                        },
                        Dialog::Props(p),
                    ) => {
                        p.base_mtu = mtu;
                        p.base_comment = comment;
                        p.base_disabled = disabled;
                    }
                    (Ok(_), Effect::Toggled(now), Dialog::Props(p)) => {
                        p.disabled = now;
                        p.base_disabled = now;
                    }
                    (Ok(_), _, _) => {}
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            self.floats.forget(dialog_id(id));
        }
        if let Some(name) = open_created {
            // Opens when an `interface.list` that has it arrives.
            let list = self.reload();
            self.open_after.push((list, name));
        }
    }
}

/// The commands of a button in an "Interface <name>" window, and whether
/// the window closes when they succeed.
fn props_sends(
    p: &Props,
    b: &Press<Button>,
    ifaces: &[Iface],
) -> (Vec<(&'static str, Value, Effect)>, bool) {
    match b {
        Press::Ok | Press::Apply => {
            let close = *b == Press::Ok;
            match p.changes() {
                Some(params) => {
                    let effect = Effect::Applied {
                        mtu: p.mtu.trim().to_owned(),
                        comment: p.comment.clone(),
                        disabled: p.disabled,
                    };
                    (vec![("interface.set", params, effect)], close)
                }
                None => (Vec::new(), close),
            }
        }
        // WinBox applies Enable/Disable at once, outside OK/Apply.
        Press::Other(Button::Toggle) => {
            let now = ifaces
                .iter()
                .find(|i| i.name == p.name)
                .is_some_and(|i| i.disabled);
            (
                vec![(
                    "interface.set",
                    json!({"name": p.name, "disabled": !now}),
                    Effect::Toggled(!now),
                )],
                false,
            )
        }
        Press::Other(Button::Remove) => (
            vec![("interface.remove", json!({ "name": p.name }), Effect::None)],
            true,
        ),
        Press::Other(Button::Port { add, bridge, port }) => {
            let id = if *add {
                "interface.bridge.port.add"
            } else {
                "interface.bridge.port.remove"
            };
            (
                vec![(
                    id,
                    json!({"bridge": bridge, "interface": port}),
                    Effect::None,
                )],
                false,
            )
        }
        Press::Cancel => (Vec::new(), true),
    }
}

/// New windows open down and to the right of the previous one, like WinBox,
/// instead of all on the same spot.
pub(crate) fn dialog_id(id: u64) -> egui::Id {
    egui::Id::unique(("corerouter-dialog", id))
}

pub(crate) fn cascade(area: egui::Rect, id: u64) -> egui::Pos2 {
    let step = (id % 8) as f32 * 28.0;
    area.center() + egui::vec2(-160.0 + step, -200.0 + step)
}

pub(crate) fn opt_text(s: &str) -> Value {
    if s.is_empty() { Value::Null } else { json!(s) }
}

fn iface_row(row: &Value) -> Row {
    let i = Iface::from_row(row);
    let n = |k: &str| row.get(k).and_then(Value::as_u64).unwrap_or(0);
    // RouterOS flags: X = disabled, R = running.
    let flag = if i.disabled {
        "X"
    } else if i.running {
        "R"
    } else {
        ""
    };
    Row {
        key: i.name.clone(),
        cells: vec![
            flag.to_owned(),
            i.name.clone(),
            i.kind.clone(),
            i.mtu.clone(),
            human_bytes(n("rx_bytes")),
            human_bytes(n("tx_bytes")),
            n("rx_packets").to_string(),
            n("tx_packets").to_string(),
            info(&i),
            i.comment.clone(),
        ],
        dimmed: i.disabled,
    }
}

/// "vlan 100 on ether1", "port of bridge1".
fn info(i: &Iface) -> String {
    let mut parts = Vec::new();
    if let (Some(id), Some(parent)) = (&i.vlan_id, &i.parent) {
        parts.push(format!("vlan {id} on {parent}"));
    }
    if let Some(b) = &i.bridge {
        parts.push(format!("port of {b}"));
    }
    if let Some(v) = &i.vrf {
        parts.push(format!("in VRF {v}"));
    }
    if let Some(t) = &i.table {
        parts.push(format!("routing table {t}"));
    }
    parts.join(", ")
}

fn some(picked: &[&Iface]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more interfaces first".into())
    } else {
        Ok(())
    }
}

fn can_remove(picked: &[&Iface]) -> Result<(), String> {
    some(picked)?;
    match picked.iter().find(|i| i.physical()) {
        Some(i) => Err(format!("{} is a physical port: disable it instead", i.name)),
        None => Ok(()),
    }
}

fn can_enable(picked: &[&Iface], enable: bool) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|i| i.disabled == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

/// The "+" menu: label and the command its dialog sends.
const ADD_KINDS: [(&str, &str); 3] = [
    ("VLAN", "interface.vlan.add"),
    ("Bridge", "interface.bridge.add"),
    ("Loopback", "interface.loopback.add"),
];

fn add_menu(ui: &mut Ui, act: &mut Option<Act>, parent: Option<&str>, can: &Avail) {
    for (label, id) in ADD_KINDS {
        if action(ui, label, can.check(id)) {
            *act = Some(match label {
                "VLAN" => Act::NewVlan {
                    parent: parent.map(str::to_owned),
                },
                "Bridge" => Act::NewBridge,
                _ => Act::NewLoopback,
            });
        }
    }
}

fn row_menu(
    ui: &mut Ui,
    act: &mut Option<Act>,
    ifaces: &[Iface],
    bridges: &[String],
    sel: &[String],
    can: &Avail,
) {
    let picked: Vec<&Iface> = ifaces.iter().filter(|i| sel.contains(&i.name)).collect();
    let owned = || sel.to_vec();
    if action(
        ui,
        "Enable",
        can.and("interface.set", can_enable(&picked, true)),
    ) {
        *act = Some(Act::Enable(owned()));
    }
    if action(
        ui,
        "Disable",
        can.and("interface.set", can_enable(&picked, false)),
    ) {
        *act = Some(Act::Disable(owned()));
    }
    if action(
        ui,
        "Remove",
        can.and("interface.remove", can_remove(&picked)),
    ) {
        *act = Some(Act::Remove(owned()));
    }
    if action(ui, "Comment…", can.and("interface.set", some(&picked))) {
        *act = Some(Act::Comment(owned()));
    }
    if action(ui, "Properties…", some(&picked)) {
        *act = Some(Act::Open(owned()));
    }
    ui.separator();
    match picked.as_slice() {
        [one] => {
            let label = format!("Add VLAN on {}", one.name);
            if action(ui, &label, can.check("interface.vlan.add")) {
                *act = Some(Act::NewVlan {
                    parent: Some(one.name.clone()),
                });
            }
        }
        _ => {
            let why = can.and("interface.vlan.add", Err("Select a single parent".into()));
            action(ui, "Add VLAN on …", why);
        }
    }
    let targets: Vec<&String> = bridges.iter().filter(|b| !sel.contains(b)).collect();
    let why = if picked.iter().any(|i| i.kind == "bridge") {
        Err("A bridge cannot be a bridge port".to_owned())
    } else if targets.is_empty() {
        Err("No bridge yet: create one with Add > Bridge".to_owned())
    } else {
        Ok(())
    };
    match can.and("interface.bridge.port.add", why) {
        Err(why) => {
            action(ui, "Add to Bridge", Err(why));
        }
        Ok(()) => {
            ui.menu_button("Add to Bridge", |ui| {
                for b in targets {
                    if ui.button(b.as_str()).clicked() {
                        *act = Some(Act::AddToBridge {
                            bridge: b.clone(),
                            ports: owned(),
                        });
                    }
                }
            });
        }
    }
    let ported = if picked.iter().any(|i| i.bridge.is_some()) {
        Ok(())
    } else {
        Err("Not a bridge port".into())
    };
    if action(
        ui,
        "Remove from Bridge",
        can.and("interface.bridge.port.remove", ported),
    ) {
        *act = Some(Act::RemoveFromBridge(owned()));
    }
    ui.separator();
    ui.menu_button("Add", |ui| add_menu(ui, act, None, can));
}

fn dialog_title(d: &Dialog) -> String {
    match d {
        Dialog::NewVlan { .. } => "New VLAN Interface".into(),
        Dialog::NewBridge { .. } => "New Bridge Interface".into(),
        Dialog::NewLoopback { .. } => "New Loopback Interface".into(),
        Dialog::Comment { targets, .. } => match targets.as_slice() {
            [one] => format!("Comment for Interface <{one}>"),
            many => format!("Comment for {} Interfaces", many.len()),
        },
        Dialog::Props(p) => format!("Interface <{}>", p.name),
    }
}

/// The fields of one dialog, and the buttons it has under them.
fn dialog_body(ui: &mut Ui, f: &Form, d: &mut Dialog, ifaces: &[Iface]) -> Footer<Button> {
    let names: Vec<String> = ifaces.iter().map(|i| i.name.clone()).collect();
    let mut port_op: Option<(bool, String, String)> = None;
    let mut toggle_label = None;
    Grid::new("fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| match d {
            Dialog::NewVlan {
                name,
                parent,
                vlan_id,
                mtu,
                comment,
            } => {
                f.text(ui, "Name", "name", name, "vlan100");
                ui.label("Interface");
                crate::windows::combo(ui, "vlan-parent", "parent", parent, &names);
                ui.end_row();
                f.text(ui, "VLAN ID", "vlan_id", vlan_id, "1..4094");
                f.text(ui, "MTU", "mtu", mtu, "parent MTU");
                f.text(ui, "Comment", "comment", comment, "");
            }
            Dialog::NewBridge { name, comment } => {
                f.text(ui, "Name", "name", name, "bridge1");
                f.text(ui, "Comment", "comment", comment, "");
            }
            Dialog::NewLoopback { name, comment } => {
                f.text(ui, "Name", "name", name, "lo0");
                f.text(ui, "Comment", "comment", comment, "");
            }
            Dialog::Comment { text, .. } => {
                f.text(ui, "Comment", "comment", text, "");
            }
            Dialog::Props(p) => {
                let Some(i) = ifaces.iter().find(|i| i.name == p.name) else {
                    return;
                };
                ui.label("Name");
                ui.add_enabled(
                    false,
                    TextEdit::singleline(&mut p.name.clone()).desired_width(180.0),
                );
                ui.end_row();
                ui.label("Type");
                ui.label(&i.kind);
                ui.end_row();
                f.text(ui, "MTU", "mtu", &mut p.mtu, "");
                f.text(ui, "Comment", "comment", &mut p.comment, "");
                ui.label("Disabled");
                ui.checkbox(&mut p.disabled, "");
                ui.end_row();
                if let (Some(parent), Some(id)) = (&i.parent, &i.vlan_id) {
                    ui.label("Interface");
                    ui.label(parent);
                    ui.end_row();
                    ui.label("VLAN ID");
                    ui.label(id);
                    ui.end_row();
                }
                if let Some(b) = &i.bridge {
                    ui.label("Bridge");
                    ui.horizontal(|ui| {
                        ui.label(b);
                        if ui.small_button("Remove from Bridge").clicked() {
                            port_op = Some((false, b.clone(), i.name.clone()));
                        }
                    });
                    ui.end_row();
                }
                if i.kind == "bridge" {
                    bridge_ports(ui, p, ifaces, &mut port_op);
                }
                toggle_label = Some(if i.disabled { "Enable" } else { "Disable" });
                ui.label("Status");
                ui.weak(match (i.disabled, i.running) {
                    (true, _) => "disabled",
                    (false, true) => "enabled, running",
                    (false, false) => "enabled",
                });
                ui.end_row();
            }
        });
    let mut footer = Footer::edit(!matches!(d, Dialog::Comment { .. }));
    if let Some(t) = toggle_label {
        footer.extra = vec![(t, Button::Toggle), ("Remove", Button::Remove)];
    }
    footer.pressed = port_op.map(|(add, bridge, port)| Button::Port { add, bridge, port });
    footer
}

fn bridge_ports(
    ui: &mut Ui,
    p: &mut Props,
    ifaces: &[Iface],
    port_op: &mut Option<(bool, String, String)>,
) {
    let ports: Vec<&Iface> = ifaces
        .iter()
        .filter(|i| i.bridge.as_deref() == Some(p.name.as_str()))
        .collect();
    ui.label("Ports");
    ui.vertical(|ui| {
        if ports.is_empty() {
            ui.weak("none");
        }
        for port in ports {
            ui.horizontal(|ui| {
                ui.label(&port.name);
                if ui.small_button("−").on_hover_text("Remove port").clicked() {
                    *port_op = Some((false, p.name.clone(), port.name.clone()));
                }
            });
        }
        let candidates: Vec<String> = ifaces
            .iter()
            .filter(|i| i.kind != "bridge" && i.kind != "vrf")
            .filter(|i| i.bridge.is_none() && i.vrf.is_none())
            .map(|i| i.name.clone())
            .collect();
        ui.horizontal(|ui| {
            crate::windows::combo(ui, "port-pick", "interface", &mut p.port_pick, &candidates);
            if ui.button("Add Port").clicked() && !p.port_pick.is_empty() {
                *port_op = Some((true, p.name.clone(), std::mem::take(&mut p.port_pick)));
            }
        });
    });
    ui.end_row();
}

//! IP › Addresses (G1.28), the reference of the list window pattern
//! (G0.24, `docs/ui-style.md`): the bar + − ✓ ✗ 💬, filter chips, state and
//! origin chips, interface and VRF chips by key, the footer, the right-click
//! menu with copy as command, and the add/edit modal fed by
//! `ip.address.check` (network, series, overlap, ARP, access risk).
//!
//! The window stays `Win::Addresses` (its place in the menu and the stored
//! preferences); this panel has no window of its own and holds the state:
//! `windows.rs` hands it the drawing.

use std::collections::BTreeMap;

use egui::{Grid, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Filters, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query};
use crate::table::{self, Menu, Row, col, comment};
use crate::{CoreRouterUi, Then, Win};

pub(crate) const NAME: &str = "ip-address";
/// What `windows.rs` passes as the window id.
pub(crate) const WIN: &str = "addresses";
const TABLE: &str = "addresses";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::new(AddressPanel::default()),
};

const CMDS: Cmds = Cmds {
    add: "ip.address.add",
    remove: "ip.address.remove",
    set: Some("ip.address.set"),
    what: "addresses",
};

const DYNAMIC: &str = "Dynamic addresses come from a DHCP client or a Router Advertisement: \
     release or disable the client (IP › DHCP Client, IPv6 › DHCPv6 Client) or stop accepting \
     RA (IPv6 › IPv6 Settings)";

const FIELDS: &[Field] = &[
    Field {
        param: "address",
        label: "Address",
        help: "ip.address.address",
        input: Input::Text("10.20.0.1/24"),
        edit: true,
    },
    Field {
        param: "to",
        label: "Series to",
        help: "ip.address.to",
        input: Input::Text("10.20.0.5 (optional)"),
        edit: false,
    },
    Field {
        param: "interface",
        label: "Interface",
        help: "ip.address.interface",
        input: Input::Choice,
        edit: true,
    },
    Field {
        param: "from_pool",
        label: "From Pool",
        help: "ip.address.from_pool",
        input: Input::Text("IPv6 pool (optional)"),
        edit: false,
    },
    Field {
        param: "comment",
        label: "Comment",
        help: "",
        input: Input::Text(""),
        edit: true,
    },
    Field {
        param: "disabled",
        label: "Disabled",
        help: "ip.address.disabled",
        input: Input::Check,
        edit: true,
    },
    Field {
        param: "arp",
        label: "ARP Check",
        help: "ip.address.arp",
        input: Input::Check,
        edit: true,
    },
];

pub(crate) const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Addresses,
    new_title: "New Address",
    edit_title: "Address",
    help: "ip.address",
    fields: FIELDS,
    preview: "ip.address.check",
};

const COLUMNS: [table::Column; 7] = [
    col("State").help("ip.address.state"),
    col("Address").help("ip.address.address"),
    col("Network").help("ip.address.network"),
    col("Interface").help("ip.address.interface"),
    col("VRF").help("ip.address.vrf"),
    col("Lifetime").help("ip.address.lifetime"),
    comment(),
];

#[derive(Default)]
pub(crate) struct AddressPanel {
    pub(crate) filters: Filters,
    pub(crate) modal: Option<Modal>,
    pub(crate) note: Option<NoteDialog>,
    /// The explanation a column's ⓘ opened.
    pub(crate) help: Option<crate::help::HelpView>,
}

/// 💬 on the selection: one comment for all of them.
pub(crate) struct NoteDialog {
    id: u64,
    keys: Vec<String>,
    text: String,
    status: Status,
}

struct NoteReply(u64);

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(crate::value_text).unwrap_or_default()
}

fn state_kind(state: &str) -> Kind {
    match state {
        "active" => Kind::Green,
        "disabled" => Kind::Neutral,
        "tentative" | "deprecated" => Kind::Amber,
        _ => Kind::Red,
    }
}

/// The origin chip: nothing for a static address.
fn origin(r: &Value) -> Option<(String, Kind)> {
    match s(r, "origin").as_str() {
        "" | "static" => None,
        "pool" => Some((format!("pool {}", s(r, "from_pool")), Kind::Blue)),
        o => Some((o.to_owned(), Kind::Blue)),
    }
}

fn lifetime(r: &Value) -> String {
    match (s(r, "valid_after"), s(r, "preferred_after")) {
        (v, _) if v.is_empty() => String::new(),
        (v, p) if p.is_empty() || p == v => v,
        (v, p) => format!("{v} / {p}"),
    }
}

pub(crate) fn row(r: &Value) -> Row {
    let state = s(r, "state");
    let mut state_chips = vec![(state.clone(), state_kind(&state))];
    if !s(r, "access").is_empty() {
        state_chips.push(("access".to_owned(), Kind::Amber));
    }
    let addr_chips: Vec<(String, Kind)> = origin(r).into_iter().collect();
    let interface = s(r, "interface");
    let vrf = s(r, "vrf");
    let refs = |v: &[(String, Kind)]| -> Vec<(String, Kind)> { v.to_vec() };
    let as_cell = |text: &str, chips: Vec<(String, Kind)>| {
        let c: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
        cell(text, &c)
    };
    let mut address = s(r, "address");
    if let Some(why) = r.get("reason").and_then(Value::as_str) {
        address = format!("{address} ({why})");
    }
    Row {
        key: s(r, "id"),
        cells: vec![
            as_cell("", refs(&state_chips)),
            as_cell(&address, addr_chips),
            s(r, "network"),
            as_cell("", vec![(interface.clone(), Kind::Hashed(chip::name_hue(&interface)))]),
            if vrf.is_empty() || vrf == "main" {
                String::new()
            } else {
                as_cell("", vec![(vrf.clone(), Kind::Hashed(chip::name_hue(&vrf)))])
            },
            lifetime(r),
            s(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
        section: false,
        tint: None,
    }
}

/// The modal's fields for an existing row.
fn values_of(r: &Value) -> BTreeMap<&'static str, String> {
    let yes = |b: bool| if b { "yes" } else { "no" }.to_owned();
    BTreeMap::from([
        ("address", s(r, "address")),
        ("interface", s(r, "interface")),
        ("comment", s(r, "comment")),
        ("disabled", yes(r.get("disabled").and_then(Value::as_bool).unwrap_or(false))),
        ("arp", yes(true)),
    ])
}

impl AddressPanel {
    /// Remove or switch `keys`; an address this session depends on asks
    /// first (the lockout window, G2.1b) unless Safe Mode is on.
    fn act_on(app: &mut CoreRouterUi, keys: &[String], command: &str, extra: Value) {
        let safe = app
            .cache
            .summary
            .get("safe_mode")
            .and_then(|m| m.get("active"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        for k in keys {
            let mut params = json!({ "id": k });
            if let (Some(p), Some(e)) = (params.as_object_mut(), extra.as_object()) {
                p.extend(e.clone());
            }
            let access = app
                .cache
                .addresses
                .iter()
                .find(|r| s(r, "id") == *k)
                .map(|r| s(r, "access"))
                .filter(|a| !a.is_empty());
            match access {
                Some(why) if !safe && app.lockout.is_none() => {
                    app.lockout = Some(crate::lockout::Held {
                        command: command.to_owned(),
                        params,
                        then: Then::Nothing,
                        message: format!("{why}."),
                    });
                }
                _ => {
                    app.run(command, params);
                }
            }
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        let row_of = |app: &CoreRouterUi, k: &str| app.cache.addresses.iter().find(|r| s(r, "id") == k).cloned();
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let values = BTreeMap::from([("arp", "yes".to_owned())]);
                    self.modal = Some(Modal::open(app, None, values));
                }
            }
            Act::Edit(k) => {
                if let Some(m) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = row_of(app, &k) {
                    self.modal = Some(Modal::open(app, Some((k, s(&r, "address"))), values_of(&r)));
                }
            }
            Act::Remove(keys) => Self::act_on(app, &keys, "ip.address.remove", json!({})),
            Act::Enable(keys) => Self::act_on(app, &keys, "ip.address.set", json!({"disabled": false})),
            Act::Disable(keys) => Self::act_on(app, &keys, "ip.address.set", json!({"disabled": true})),
            Act::Comment(keys) => {
                let text = keys
                    .first()
                    .and_then(|k| row_of(app, k))
                    .map(|r| s(&r, "comment"))
                    .unwrap_or_default();
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.note = Some(NoteDialog {
                    id: app.next_dialog,
                    keys,
                    text,
                    status: Status::default(),
                });
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| row_of(app, k)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, CMDS.add, &refs, syntax));
            }
        }
    }
}

impl PanelState for AddressPanel {
    fn queries(&self, _app: &CoreRouterUi) -> Vec<Query> {
        // The rows come with the app's own refresh (`cache.addresses`);
        // the modal asks its preview itself.
        Vec::new()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW
            && let Some(m) = &mut self.modal
        {
            m.arrived(value);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = app.cache.addresses.clone();
        let shown: Vec<&Value> = all.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| row(r)).collect();
        let selection = app.tables.addresses.selection(&rows);
        let picked: Vec<Item> = shown
            .iter()
            .filter(|r| selection.contains(&s(r, "id")))
            .map(|r| Item::of(r, "id", DYNAMIC))
            .collect();
        let tools = Tools::new(&app.can(), &CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            ui.separator();
            self.filters.chips(ui, "family", &[("ipv4", "IPv4"), ("ipv6", "IPv6")], l);
            ui.separator();
            let mut states: Vec<&str> = ["active", "disabled", "invalid", "tentative"].to_vec();
            for r in &all {
                let st = r.get("state").and_then(Value::as_str).unwrap_or("");
                if !st.is_empty() && !states.contains(&st) {
                    states.push(st);
                }
            }
            for st in states {
                if list::count(&all, "state", st) > 0 || self.filters.is_on("state", st) {
                    let on = self.filters.is_on("state", st);
                    if list::filter_chip(ui, st, on) {
                        self.filters.toggle("state", st);
                    }
                }
            }
            table::find_field(ui, TABLE, &mut app.tables.addresses);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(
            ui,
            TABLE,
            footer_h,
            &mut app.tables.addresses,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<Item> = all
                        .iter()
                        .filter(|r| sel.contains(&s(r, "id")))
                        .map(|r| Item::of(r, "id", DYNAMIC))
                        .collect();
                    let tools = Tools::new(&app.can, &CMDS, &picked);
                    if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                        act = Some(a);
                    }
                }
                Menu::Empty => {
                    if table::action(ui, "New Address…", tools.add.clone()) {
                        act = Some(Act::Add);
                    }
                }
            },
        );
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(crate::help::HelpView::new(key, crate::i18n::tr_in("addresses", l, title)));
        }
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "addresses", chip::neutral_tone(&v)),
                (list::count(&all, "state", "active"), "active", chip::GREEN.tone(&v)),
                (list::count(&all, "state", "disabled"), "disabled", chip::neutral_tone(&v)),
                (list::count(&all, "state", "invalid"), "invalid", chip::RED.tone(&v)),
                (list::count(&all, "state", "tentative"), "tentative", chip::AMBER.tone(&v)),
                (list::count(&all, "family", "ipv4"), "IPv4", chip::neutral_tone(&v)),
                (list::count(&all, "family", "ipv6"), "IPv6", chip::neutral_tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.modal {
            let names = app.interface_names(None);
            let open = m.show(app, ctx, area, &SPEC, &|p| {
                if p == "interface" { names.clone() } else { Vec::new() }
            });
            if !open {
                self.modal = None;
            }
        }
        self.note_dialog(app, ctx, area);
        crate::help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        if let Some(r) = then.downcast_ref::<NoteReply>()
            && let Some(d) = self.note.as_mut().filter(|d| d.id == r.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.note = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        false
    }
}

impl AddressPanel {
    /// Tests: act as the bar or the menu would.
    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, ui: &Ui) {
        let rows: Vec<Row> = app.cache.addresses.iter().map(row).collect();
        self.act(app, a, ui, &rows);
    }

    fn note_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.note.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let title = if d.keys.len() == 1 {
            "Comment".to_owned()
        } else {
            format!("Comment ({} addresses)", d.keys.len())
        };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: false,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Addresses)),
        };
        let can = app.can();
        let mut text = d.text.clone();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("ip-address-note").num_columns(2).show(ui, |ui| {
                ui.label("Comment");
                ui.add(TextEdit::multiline(&mut text).id(dialog::field_id(f.window(), "comment")).desired_rows(3));
                ui.end_row();
            });
            Footer::<()>::edit(false, can.check("ip.address.set"))
        });
        d.text = text;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let steps: Vec<Value> = d
                    .keys
                    .iter()
                    .map(|k| json!({"command": "ip.address.set", "params": {"id": k, "comment": d.text.trim()}}))
                    .collect();
                d.status.close_on_success = true;
                d.status.sent();
                app.run_steps(steps, crate::panel::then(NAME, NoteReply(d.id)));
            }
            _ => {}
        }
        self.note = Some(d);
    }
}

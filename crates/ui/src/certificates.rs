//! System › Certificates (G1.6zs), RouterOS `/certificate`: one row per
//! certificate with its state (`valid`, `expiring`, `expired`…), names,
//! key, end date and the services that serve with it. **+** makes a
//! self-signed one, **Import** takes a PEM and its key, **Export** copies
//! the PEM; a double click renames or comments. Under the table, the
//! selected certificate: fingerprint, the SPKI pin (RFC 7858 §4.2) and
//! what the operator should know (the engine's `warnings`).
//!
//! The engine decides and checks (`certificate.*`, the previews
//! `certificate.check` and `certificate.check-import`); the window only
//! shows and sends. A panel (`panel.rs`).

use std::collections::BTreeMap;

use egui::{Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{self, Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment};
use crate::{CoreRouterUi, Win};

const NAME: &str = "certificates";
pub(crate) const WIN: &str = "certificates";
const TABLE: &str = "certificates";
const SCOPE: &str = "certificates";
const PRINT: &str = "certificate.print";
/// Height of the selected certificate's detail under the table.
const DETAIL_H: f32 = 150.0;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef { id: WIN, group: "System", title: "Certificates", size: [980.0, 540.0], escape: true }],
    new: || Box::new(CertificatesPanel::default()),
};

const CMDS: Cmds = Cmds {
    add: "certificate.add",
    remove: "certificate.remove",
    set: Some("certificate.set"),
    what: "certificates",
};

const ADD_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "certificates.name", input: Input::Text("dns-lan"), edit: true },
    Field { param: "common_name", label: "Common Name", help: "certificates.common_name", input: Input::Text("blank: the identity"), edit: false },
    Field {
        param: "subject_alt_name",
        label: "Subject Alt Name",
        help: "certificates.subject_alt_name",
        input: Input::Text("blank: identity + addresses"),
        edit: false,
    },
    Field { param: "key_type", label: "Key Type", help: "certificates.key_type", input: Input::Choice, edit: false },
    Field { param: "days_valid", label: "Days Valid", help: "certificates.days_valid", input: Input::Text("825"), edit: false },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const ADD: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Certificate",
    edit_title: "Certificate",
    help: "menu.certificates",
    fields: ADD_FIELDS,
    preview: "certificate.check",
};

const IMPORT_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "certificates.name", input: Input::Text("dns-example"), edit: false },
    Field {
        param: "certificate",
        label: "Certificate",
        help: "certificates.certificate",
        input: Input::Multiline("-----BEGIN CERTIFICATE-----  (then its chain)"),
        edit: false,
    },
    Field {
        param: "private_key",
        label: "Private Key",
        help: "certificates.private_key",
        input: Input::Multiline("-----BEGIN PRIVATE KEY-----"),
        edit: false,
    },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: false },
];

const IMPORT: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "Import Certificate",
    edit_title: "Import Certificate",
    help: "certificates.import",
    fields: IMPORT_FIELDS,
    preview: "certificate.check-import",
};

const COLUMNS: [table::Column; 8] = [
    col("Name").help("certificates.name"),
    col("State").help("certificates.state"),
    col("Common Name").help("certificates.common_name"),
    col("Subject Alt Names").help("certificates.subject_alt_name"),
    col("Key").help("certificates.key_type"),
    col("Expires").help("certificates.expires"),
    col("Used By").help("certificates.used_by"),
    comment(),
];

/// Which modal is open: they share the preview key, so one at a time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Which {
    Add,
    Import,
}

#[derive(Default)]
pub(crate) struct CertificatesPanel {
    pub(crate) rows: Vec<Value>,
    table: TableState,
    pub(crate) modal: Option<(Which, Modal)>,
    help: Option<HelpView>,
    notice: Option<String>,
    /// A PEM to put on the clipboard on the next frame (Copy PEM's reply).
    to_copy: Option<String>,
}

/// The reply of Export.
struct Exported;

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(crate::value_text).unwrap_or_default()
}

fn strings(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// The engine's state as a static word (the catalogs translate it).
fn state_word(state: &str) -> &'static str {
    match state {
        "valid" => "valid",
        "expiring" => "expiring",
        "expired" => "expired",
        "not-yet-valid" => "not-yet-valid",
        _ => "invalid",
    }
}

fn state_kind(state: &str) -> Kind {
    match state {
        "valid" => Kind::Green,
        "expiring" => Kind::Amber,
        _ => Kind::Red,
    }
}

/// `2028-02-14` of unix seconds (UTC).
fn date(t: i64) -> String {
    let full = crate::ntp_client::utc(u64::try_from(t).unwrap_or(0));
    full.get(..10).unwrap_or(&full).to_owned()
}

/// `2028-02-14 (458 d)`.
fn expires(r: &Value) -> String {
    let Some(t) = r.get("not_after").and_then(Value::as_i64) else {
        return "–".to_owned();
    };
    let days = r.get("days_left").and_then(Value::as_i64).map(|d| format!(" ({d} d)")).unwrap_or_default();
    format!("{}{days}", date(t))
}

pub(crate) fn row(r: &Value, l: crate::i18n::Lang) -> Row {
    let state = s(r, "state");
    let mut chips: Vec<(&str, Kind)> = Vec::new();
    if r.get("self_signed").and_then(Value::as_bool) == Some(true) {
        chips.push((tr_in(SCOPE, l, "self-signed"), Kind::Neutral));
    }
    if r.get("private_key").and_then(Value::as_bool) == Some(false) {
        chips.push((tr_in(SCOPE, l, "no key"), Kind::Amber));
    }
    let origin_chip = [(s(r, "origin"), Kind::Blue)];
    let origin: Vec<(&str, Kind)> = origin_chip.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    let used = strings(r, "used_by").join(", ");
    Row {
        key: s(r, "name"),
        cells: vec![
            cell(&s(r, "name"), &origin),
            cell("", &[(tr_in(SCOPE, l, state_word(&state)), state_kind(&state))]),
            cell(&s(r, "common_name"), &chips),
            strings(r, "subject_alt_names").join(", "),
            s(r, "key_type"),
            expires(r),
            if used.is_empty() { "–".to_owned() } else { used },
            s(r, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The bar's buttons: a certificate is never turned off (RouterOS has no
/// `disabled` either); a service stops using it instead.
fn bar(can: &crate::avail::Avail, picked: &[Item]) -> Tools {
    let mut t = Tools::new(can, &CMDS, picked);
    let why = "a certificate is not turned off: pick another one in the service that uses it";
    t.enable = Err(why.to_owned());
    t.disable = Err(why.to_owned());
    t
}

impl CertificatesPanel {
    fn row_of(&self, name: &str) -> Option<&Value> {
        self.rows.iter().find(|r| s(r, "name") == name)
    }

    fn open(&mut self, app: &mut CoreRouterUi, which: Which, item: Option<&Value>) {
        if let Some((_, m)) = &mut self.modal {
            m.status.bring_to_front();
            return;
        }
        let values = match (which, item) {
            (Which::Add, Some(r)) => BTreeMap::from([("name", s(r, "name")), ("comment", s(r, "comment"))]),
            (Which::Add, None) => BTreeMap::from([("key_type", "ecdsa-p256".to_owned())]),
            (Which::Import, _) => BTreeMap::new(),
        };
        let key = item.map(|r| (s(r, "name"), s(r, "name")));
        self.modal = Some((which, Modal::open(app, key, values)));
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row]) {
        match act {
            Act::Add => self.open(app, Which::Add, None),
            Act::Edit(k) => {
                if let Some(r) = self.row_of(&k).cloned() {
                    self.open(app, Which::Add, Some(&r));
                }
            }
            Act::Comment(keys) => {
                if let Some(r) = keys.first().and_then(|k| self.row_of(k)).cloned() {
                    self.open(app, Which::Add, Some(&r));
                }
            }
            Act::Remove(keys) => {
                self.notice = None;
                for k in keys {
                    app.run("certificate.remove", json!({ "id": k }));
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(..) | Act::Enable(_) | Act::Disable(_) => {}
        }
    }

    /// The selected certificate, in full.
    fn detail(&self, ui: &mut Ui, sel: Option<&String>, l: crate::i18n::Lang) {
        let Some(r) = sel.and_then(|k| self.row_of(k)) else {
            ui.weak(tr_in(SCOPE, l, "Select a certificate to see its fingerprint and pin."));
            return;
        };
        Grid::new("certificates-detail").num_columns(2).spacing([12.0, 2.0]).show(ui, |ui| {
            for (label, key) in [
                ("Issuer", "issuer"),
                ("Fingerprint", "fingerprint"),
                ("SPKI Pin (SHA-256)", "spki_pin"),
                ("Serial", "serial"),
                ("Valid From", "not_before"),
            ] {
                ui.weak(tr_in(SCOPE, l, label));
                let v = if key == "not_before" {
                    r.get(key).and_then(Value::as_i64).map(date).unwrap_or_default()
                } else {
                    s(r, key)
                };
                ui.label(RichText::new(v).monospace());
                ui.end_row();
            }
        });
        for w in strings(r, "warnings") {
            ui.horizontal_wrapped(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, "warning"), chip::AMBER.tone(ui.visuals()));
                ui.label(w);
            });
        }
    }
}

impl PanelState for CertificatesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) && app.has_command(PRINT) {
            vec![Query { key: "print", command: PRINT, params: json!({}) }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some((_, m)) = &mut self.modal {
                m.arrived(value);
            }
        } else if key == "print"
            && let Some(rows) = value.as_array()
        {
            self.rows = rows.clone();
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.rows.clone();
        let rows: Vec<Row> = all.iter().map(|r| row(r, l)).collect();
        let selection = self.table.selection(&rows);
        let pick = |sel: &[String]| -> Vec<Item> {
            all.iter().filter(|r| sel.contains(&s(r, "name"))).map(|r| Item::of(r, "name", "")).collect()
        };
        let can = app.can();
        let tools = bar(&can, &pick(selection.as_slice()));
        let mut act = None;
        let mut import = false;
        let mut export = false;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TABLE, &tools, &selection, l);
            ui.separator();
            import = table::action(ui, tr_in(SCOPE, l, "Import…"), can.check("certificate.import"));
            let one = if selection.len() == 1 { can.check("certificate.export") } else { Err("Select one certificate".to_owned()) };
            export = table::action(ui, tr_in(SCOPE, l, "Copy PEM"), one);
            let title = tr_in(SCOPE, l, "Certificates");
            if help::info_button(ui, egui::Id::unique("certificates-help"), title).clicked() {
                self.help = Some(HelpView::new("menu.certificates", title));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        if let Some(n) = &self.notice {
            ui.weak(n);
        }
        ui.separator();
        self.table.empty = tr_in(SCOPE, l, "No certificates. + makes a self-signed one; Import… takes yours (PEM).").to_owned();
        if let Some(pem) = self.to_copy.take() {
            ui.ctx().copy_text(pem);
        }
        let known = !app.cache.commands.is_empty();
        // The footer and the detail below (DETAIL_H, scrolled when the
        // warnings do not fit): the table never pushes the window taller.
        let reserve = DETAIL_H + 60.0;
        let out = table::show(ui, TABLE, reserve, &mut self.table, &COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let t = bar(&can, &pick(sel.as_slice()));
                if let Some(a) = list::row_menu(ui, &t, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "Add Certificate…"), can.check("certificate.add")) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        let act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "certificates", chip::neutral_tone(&v)),
                (list::count(&all, "state", "expiring"), "expiring", chip::AMBER.tone(&v)),
                (list::count(&all, "state", "expired"), "expired", chip::RED.tone(&v)),
            ],
            l,
        );
        ui.separator();
        egui::ScrollArea::vertical().id_salt("certificates-detail-scroll").max_height(DETAIL_H).show(ui, |ui| {
            self.detail(ui, selection.first(), l);
        });
        if import {
            self.open(app, Which::Import, None);
        }
        if export && let Some(k) = selection.first() {
            app.run_then("certificate.export", json!({ "id": k }), panel::then(NAME, Exported));
        }
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let options = |param: &str| {
            if param == "key_type" { vec!["ecdsa-p256".to_owned(), "ecdsa-p384".to_owned()] } else { Vec::new() }
        };
        if let Some((which, m)) = &mut self.modal {
            let spec = match which {
                Which::Add => &ADD,
                Which::Import => &IMPORT,
            };
            if !m.show(app, ctx, area, spec, &options) {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        if then.downcast_ref::<Exported>().is_some() {
            let l = app.lang.labels;
            match result {
                Ok(v) => {
                    self.to_copy = Some(s(v, "certificate"));
                    self.notice = Some(format!("{} {}", s(v, "name"), tr_in(SCOPE, l, "copied (PEM, without the key)")));
                }
                Err(e) => self.notice = Some(e.chars().take(300).collect()),
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table)]
    }
}

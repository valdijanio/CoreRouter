//! IP › DNS › Zones (G4.1c): authoritative zones, BIND style, in WinBox
//! windows. The Zones button of the DNS window opens "DNS Zones" (found by
//! its title).
//!
//! - **DNS Zones**: one row per zone (type, serial, records, status), New
//!   and properties dialogs (SOA timers, who may transfer, NOTIFY targets,
//!   a secondary's primaries); the selected zone's records or zone file
//!   open from the tool bar.
//! - **DNS Zone Records**: the records of one zone, New/properties dialogs
//!   with the fields of the type.
//! - **DNS Zone File**: the zone file of a zone (RFC 1035 §5), to read,
//!   copy, edit and load back (a window, not a dialog: Enter is a new line
//!   there, never "OK").
//!
//! The engine validates (`ip.dns.zone.*`) and moves the serial; the windows
//! only show and send. A panel (`panel.rs`): its state lives here.

use egui::{Grid, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, chip, neutral_tone};
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "dns-zones";
pub(crate) const WIN: &str = "dns-zones";
pub(crate) const WIN_RECORDS: &str = "dns-zone-records";
pub(crate) const WIN_FILE: &str = "dns-zone-file";
pub(crate) const ZONE_TABLE: &str = "dns-zones";
pub(crate) const RECORD_TABLE: &str = "dns-zone-records";
const MAX_OPEN: usize = 8;
const TYPES: [&str; 9] = ["A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[
        WinDef {
            id: WIN,
            group: "IP",
            title: "DNS Zones",
            size: [720.0, 300.0],
            escape: true,
        },
        WinDef {
            id: WIN_RECORDS,
            group: "IP",
            title: "DNS Zone Records",
            size: [720.0, 360.0],
            escape: true,
        },
        WinDef {
            id: WIN_FILE,
            group: "IP",
            title: "DNS Zone File",
            size: [640.0, 480.0],
            escape: false,
        },
    ],
    new: || Box::new(ZonesPanel::default()),
};

const ZONE_COLUMNS: [table::Column; 7] = [
    col(""),
    col("Name"),
    col("Type"),
    num("Serial"),
    num("Records"),
    col("Status"),
    comment(),
];

const RECORD_COLUMNS: [table::Column; 6] = [
    col(""),
    col("Name"),
    col("Type"),
    col("Data"),
    num("TTL"),
    comment(),
];

#[derive(Default)]
pub(crate) struct ZonesPanel {
    /// `ip.dns.zone.print`.
    pub(crate) zones: Vec<Value>,
    pub(crate) zone_table: TableState,
    /// `ip.dns.zone.record.print`.
    pub(crate) records: Vec<Value>,
    pub(crate) record_table: TableState,
    /// The zone the records window shows ("" until one is picked).
    pub(crate) zone: String,
    pub(crate) dialogs: Vec<DialogWin>,
    /// `ip.dns.zone.dnssec.print`, while a zone dialog is open.
    pub(crate) keys: Vec<Value>,
    /// The zone file window.
    pub(crate) file: FileView,
}

/// The zone file window's state.
#[derive(Default)]
pub(crate) struct FileView {
    pub zone: String,
    pub text: String,
    /// The text as the router sent it (edits show as unsaved).
    pub loaded: String,
    pub waiting: bool,
    pub message: Option<Result<String, String>>,
}

fn split(s: &str) -> Vec<String> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn list_text(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

/// One zone, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneForm {
    pub name: String,
    pub ztype: String,
    pub primary_ns: String,
    pub admin: String,
    pub serial_policy: String,
    pub refresh_secs: String,
    pub retry_secs: String,
    pub expire_secs: String,
    pub minimum_secs: String,
    pub ttl_secs: String,
    pub allow_transfer: String,
    pub notify: String,
    pub primaries: String,
    pub dnssec: bool,
    pub dnssec_algorithm: String,
    pub signature_validity_secs: String,
    pub disabled: bool,
    pub comment: String,
}

impl Default for ZoneForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            ztype: "primary".into(),
            primary_ns: String::new(),
            admin: String::new(),
            serial_policy: "date".into(),
            refresh_secs: "86400".into(),
            retry_secs: "7200".into(),
            expire_secs: "3600000".into(),
            minimum_secs: "3600".into(),
            ttl_secs: "3600".into(),
            allow_transfer: String::new(),
            notify: String::new(),
            primaries: String::new(),
            dnssec: false,
            dnssec_algorithm: "ecdsa-p256".into(),
            signature_validity_secs: "1209600".into(),
            disabled: false,
            comment: String::new(),
        }
    }
}

const ZONE_NUMBERS: [&str; 6] = [
    "refresh_secs",
    "retry_secs",
    "expire_secs",
    "minimum_secs",
    "ttl_secs",
    "signature_validity_secs",
];
const ZONE_LISTS: [&str; 3] = ["allow_transfer", "notify", "primaries"];

impl ZoneForm {
    fn of(r: &Value) -> Self {
        Self {
            name: text(r, "name"),
            ztype: text(r, "type"),
            primary_ns: text(r, "primary_ns"),
            admin: text(r, "admin"),
            serial_policy: text(r, "serial_policy"),
            refresh_secs: text(r, "refresh_secs"),
            retry_secs: text(r, "retry_secs"),
            expire_secs: text(r, "expire_secs"),
            minimum_secs: text(r, "minimum_secs"),
            ttl_secs: text(r, "ttl_secs"),
            allow_transfer: list_text(r, "allow_transfer"),
            notify: list_text(r, "notify"),
            primaries: list_text(r, "primaries"),
            dnssec: flag(r, "dnssec"),
            dnssec_algorithm: r
                .get("dnssec_algorithm")
                .map_or("ecdsa-p256".to_owned(), |_| text(r, "dnssec_algorithm")),
            signature_validity_secs: r
                .get("signature_validity_secs")
                .map_or("1209600".to_owned(), |_| text(r, "signature_validity_secs")),
            disabled: flag(r, "disabled"),
            comment: text(r, "comment"),
        }
    }

    fn field(&self, k: &str) -> &String {
        match k {
            "name" => &self.name,
            "primary_ns" => &self.primary_ns,
            "admin" => &self.admin,
            "serial_policy" => &self.serial_policy,
            "refresh_secs" => &self.refresh_secs,
            "retry_secs" => &self.retry_secs,
            "expire_secs" => &self.expire_secs,
            "minimum_secs" => &self.minimum_secs,
            "ttl_secs" => &self.ttl_secs,
            "allow_transfer" => &self.allow_transfer,
            "notify" => &self.notify,
            "primaries" => &self.primaries,
            "dnssec_algorithm" => &self.dnssec_algorithm,
            "signature_validity_secs" => &self.signature_validity_secs,
            _ => &self.comment,
        }
    }

    const TEXTS: [&'static str; 6] = [
        "name",
        "primary_ns",
        "admin",
        "serial_policy",
        "dnssec_algorithm",
        "comment",
    ];

    fn value(k: &str, s: &str) -> Value {
        if ZONE_NUMBERS.contains(&k) {
            form_number(s)
        } else if ZONE_LISTS.contains(&k) {
            json!(split(s))
        } else {
            json!(s.trim())
        }
    }

    /// `ip.dns.zone.add`: the fields filled in.
    fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("type".into(), json!(self.ztype));
        for k in Self::TEXTS.iter().chain(&ZONE_NUMBERS).chain(&ZONE_LISTS) {
            let v = self.field(k);
            if !v.trim().is_empty() {
                p.insert((*k).into(), Self::value(k, v));
            }
        }
        if self.dnssec {
            p.insert("dnssec".into(), json!(true));
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        Value::Object(p)
    }

    /// `ip.dns.zone.set` for what differs from `base` ("" clears).
    fn set_params(&self, id: &str, base: &ZoneForm) -> Option<Value> {
        let mut p = Map::new();
        for k in Self::TEXTS.iter().chain(&ZONE_NUMBERS) {
            let (now, was) = (self.field(k), base.field(k));
            if now.trim() != was.trim() {
                let v = if now.trim().is_empty() {
                    json!("")
                } else {
                    Self::value(k, now)
                };
                p.insert((*k).into(), v);
            }
        }
        for k in ZONE_LISTS {
            if split(self.field(k)) != split(base.field(k)) {
                p.insert(k.into(), json!(split(self.field(k))));
            }
        }
        if self.dnssec != base.dnssec {
            p.insert("dnssec".into(), json!(self.dnssec));
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("id".into(), json!(id));
        Some(Value::Object(p))
    }
}

/// One record, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordForm {
    pub zone: String,
    pub name: String,
    pub rtype: String,
    pub address: String,
    pub target: String,
    pub priority: String,
    pub weight: String,
    pub port: String,
    pub text: String,
    pub caa_flags: String,
    pub caa_tag: String,
    /// Blank: the zone's TTL.
    pub ttl_secs: String,
    pub disabled: bool,
    pub comment: String,
}

impl Default for RecordForm {
    fn default() -> Self {
        Self {
            zone: String::new(),
            name: String::new(),
            rtype: "A".into(),
            address: String::new(),
            target: String::new(),
            priority: String::new(),
            weight: String::new(),
            port: String::new(),
            text: String::new(),
            caa_flags: String::new(),
            caa_tag: String::new(),
            ttl_secs: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

const RECORD_NUMBERS: [&str; 5] = ["priority", "weight", "port", "caa_flags", "ttl_secs"];

impl RecordForm {
    fn of(r: &Value) -> Self {
        Self {
            zone: text(r, "zone"),
            name: text(r, "name"),
            rtype: text(r, "type"),
            address: text(r, "address"),
            target: text(r, "target"),
            priority: text(r, "priority"),
            weight: text(r, "weight"),
            port: text(r, "port"),
            text: text(r, "text"),
            caa_flags: text(r, "caa_flags"),
            caa_tag: text(r, "caa_tag"),
            ttl_secs: text(r, "ttl_secs"),
            disabled: flag(r, "disabled"),
            comment: text(r, "comment"),
        }
    }

    fn strings(&self) -> [(&'static str, &String); 11] {
        [
            ("name", &self.name),
            ("address", &self.address),
            ("target", &self.target),
            ("priority", &self.priority),
            ("weight", &self.weight),
            ("port", &self.port),
            ("text", &self.text),
            ("caa_flags", &self.caa_flags),
            ("caa_tag", &self.caa_tag),
            ("ttl_secs", &self.ttl_secs),
            ("comment", &self.comment),
        ]
    }

    fn value(k: &str, s: &str) -> Value {
        if RECORD_NUMBERS.contains(&k) {
            form_number(s)
        } else {
            json!(s.trim())
        }
    }

    fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("zone".into(), json!(self.zone));
        p.insert("type".into(), json!(self.rtype));
        for (k, v) in self.strings() {
            if !v.trim().is_empty() {
                p.insert(k.into(), Self::value(k, v));
            }
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        Value::Object(p)
    }

    fn set_params(&self, id: &str, base: &RecordForm) -> Option<Value> {
        let mut p = Map::new();
        if self.rtype != base.rtype {
            p.insert("type".into(), json!(self.rtype));
        }
        for ((k, now), (_, was)) in self.strings().into_iter().zip(base.strings()) {
            if now.trim() != was.trim() {
                let v = if now.trim().is_empty() {
                    json!("")
                } else {
                    Self::value(k, now)
                };
                p.insert(k.into(), v);
            }
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("id".into(), json!(id));
        Some(Value::Object(p))
    }
}

pub(crate) enum Dialog {
    NewZone(Box<ZoneForm>),
    Zone {
        id: String,
        form: Box<ZoneForm>,
        base: Box<ZoneForm>,
    },
    NewRecord(Box<RecordForm>),
    Record {
        id: String,
        form: Box<RecordForm>,
        base: Box<RecordForm>,
    },
}

impl Dialog {
    fn dirty(&self) -> bool {
        match self {
            Self::NewZone(f) => **f != ZoneForm::default(),
            Self::Zone { id, form, base } => form.set_params(id, base).is_some(),
            Self::NewRecord(f) => {
                **f != RecordForm {
                    zone: f.zone.clone(),
                    ..RecordForm::default()
                }
            }
            Self::Record { id, form, base } => form.set_params(id, base).is_some(),
        }
    }

    /// The row key of a properties dialog.
    fn key(&self) -> Option<&str> {
        match self {
            Self::Zone { id, .. } | Self::Record { id, .. } => Some(id),
            _ => None,
        }
    }

    fn is_zone(&self) -> bool {
        matches!(self, Self::NewZone(_) | Self::Zone { .. })
    }
}

pub(crate) struct DialogWin {
    pub id: u64,
    pub dialog: Dialog,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Remove,
    RollZsk,
    RollKsk,
    DsPublished,
}

enum Applied {
    Zone(Box<ZoneForm>),
    Record(Box<RecordForm>),
}

enum Reply {
    Dialog { id: u64, applied: Option<Applied> },
    File { zone: String },
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Open(Vec<String>),
    New,
    Records(String),
    File(String),
    Refresh(String),
    SelectAll,
    Reload,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more first".into())
    } else {
        Ok(())
    }
}

fn one(picked: &[&Value]) -> Result<(), String> {
    if picked.len() == 1 {
        Ok(())
    } else {
        Err("Select one zone".into())
    }
}

fn can_enable(picked: &[&Value], enable: bool) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| flag(r, "disabled") == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

/// What the status column says, in words.
pub(crate) fn status_text(r: &Value) -> String {
    let st = text(r, "status");
    let err = text(r, "error");
    let base = match st.as_str() {
        "running" if r.get("signed_serial").is_some() => {
            format!("serving, signed (serial {})", text(r, "signed_serial"))
        }
        "running" if flag(r, "dnssec") => "serving, not signed yet".to_owned(),
        "running" => "serving".to_owned(),
        "loaded" if flag(r, "signed") => {
            format!("loaded, signed, serial {}", text(r, "loaded_serial"))
        }
        "loaded" => format!("loaded, serial {}", text(r, "loaded_serial")),
        "not-loaded" => "not loaded".to_owned(),
        "config-only" => "config only (no daemon)".to_owned(),
        other => other.to_owned(),
    };
    if err.is_empty() {
        base
    } else {
        format!("{base}: {err}")
    }
}

pub(crate) fn zone_row(r: &Value) -> Row {
    let secondary = text(r, "type") == "secondary";
    let serial = if secondary {
        r.get("loaded_serial")
            .map_or("–".to_owned(), |_| text(r, "loaded_serial"))
    } else {
        text(r, "serial")
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "name"),
            text(r, "type"),
            serial,
            text(r, "records"),
            status_text(r),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

pub(crate) fn record_row(r: &Value) -> Row {
    let ttl = if r.get("ttl_secs").is_some() {
        text(r, "ttl_secs")
    } else {
        format!("({})", text(r, "ttl"))
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            text(r, "name"),
            text(r, "type"),
            text(r, "data"),
            ttl,
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// Opens (or raises) one of the panel's windows.
fn open_window(app: &mut CoreRouterUi, win: &'static str) {
    if !app.open.insert(Win::Panel(win)) {
        app.floats.raise(crate::win_id(Win::Panel(win)));
    }
    app.cache.refreshed_at = None;
}

impl PanelState for ZonesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let open = |w| app.open.contains(&Win::Panel(w));
        let any = open(WIN) || open(WIN_RECORDS) || open(WIN_FILE) || !self.dialogs.is_empty();
        let mut out = Vec::new();
        if self.dialogs.iter().any(|d| matches!(d.dialog, Dialog::Zone { .. }))
            && app.has_command("ip.dns.zone.dnssec.print")
        {
            out.push(Query {
                key: "keys",
                command: "ip.dns.zone.dnssec.print",
                params: Value::Null,
            });
        }
        if any && app.has_command("ip.dns.zone.print") {
            out.push(Query {
                key: "zones",
                command: "ip.dns.zone.print",
                params: Value::Null,
            });
        }
        if (open(WIN_RECORDS) || self.dialogs.iter().any(|d| !d.dialog.is_zone()))
            && app.has_command("ip.dns.zone.record.print")
        {
            out.push(Query {
                key: "records",
                command: "ip.dns.zone.record.print",
                params: Value::Null,
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        let Value::Array(a) = value else {
            return;
        };
        match key {
            "zones" => {
                // The records window follows the first zone until one is
                // picked; a removed zone lets go.
                if !a.iter().any(|z| text(z, "name") == self.zone) {
                    self.zone = a.first().map(|z| text(z, "name")).unwrap_or_default();
                }
                if self.file.zone.is_empty() {
                    self.file.zone.clone_from(&self.zone);
                }
                self.zones = a;
            }
            "records" => self.records = a,
            "keys" => self.keys = a,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut egui::Ui) {
        match win {
            WIN_RECORDS => self.records_window(app, ui),
            WIN_FILE => self.file_window(app, ui),
            _ => self.zones_window(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.draw_dialogs(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        match *r {
            Reply::Dialog { id, applied } => self.dialog_reply(app, id, applied, result),
            Reply::File { zone } => {
                self.file.waiting = false;
                match result {
                    Ok(v) if zone == self.file.zone => {
                        self.file.text = text(v, "text");
                        self.file.loaded.clone_from(&self.file.text);
                        self.file.message = None;
                    }
                    Ok(_) => {}
                    Err(e) => self.file.message = Some(Err(e.clone())),
                }
            }
            Reply::Loaded => {
                self.file.waiting = false;
                self.file.message = Some(match result {
                    Ok(v) => {
                        self.file.loaded.clone_from(&self.file.text);
                        Ok(format!(
                            "Loaded: {} records, serial {}",
                            text(v, "records"),
                            text(v, "serial")
                        ))
                    }
                    Err(e) => Err(e.clone()),
                });
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, win: &'static str) -> bool {
        match win {
            WIN => self.zone_table.escape(),
            WIN_RECORDS => self.record_table.escape(),
            _ => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (ZONE_TABLE, &self.zone_table),
            (RECORD_TABLE, &self.record_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (ZONE_TABLE, &mut self.zone_table),
            (RECORD_TABLE, &mut self.record_table),
        ]
    }
}

impl ZonesPanel {
    fn zones_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let zones = self.zones.clone();
        let rows: Vec<Row> = zones.iter().map(zone_row).collect();
        let selection = self.zone_table.selection(&rows);
        let picked: Vec<&Value> = zones
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let first = picked.first().map(|z| text(z, "name")).unwrap_or_default();
        let secondary = picked.len() == 1 && picked.iter().all(|z| text(z, "type") == "secondary");
        let can = app.can();
        let mut act = None;
        ui.horizontal(|ui| {
            if table::tool(ui, ZONE_TABLE, Icon::Add, "Add", can.check("ip.dns.zone.add")).clicked() {
                act = Some(Act::New);
            }
            for (icon, tip, enabled) in [
                (Icon::Remove, "Remove", can.and("ip.dns.zone.remove", some(&picked))),
                (Icon::Enable, "Enable", can.and("ip.dns.zone.set", can_enable(&picked, true))),
                (Icon::Disable, "Disable", can.and("ip.dns.zone.set", can_enable(&picked, false))),
            ] {
                if table::tool(ui, ZONE_TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        _ => Act::Remove(sel),
                    });
                }
            }
            ui.separator();
            if action(ui, "Records", one(&picked)) {
                act = Some(Act::Records(first.clone()));
            }
            if action(ui, "Zone File", can.and("ip.dns.zone.file.get", one(&picked))) {
                act = Some(Act::File(first.clone()));
            }
            let refresh = if secondary {
                can.check("ip.dns.zone.refresh")
            } else {
                Err("Select one secondary zone".into())
            };
            if action(ui, "Refresh", refresh) {
                act = Some(Act::Refresh(first.clone()));
            }
            table::find_field(ui, ZONE_TABLE, &mut self.zone_table);
        });
        ui.separator();
        self.zone_table.open = self
            .dialogs
            .iter()
            .filter(|d| d.dialog.is_zone())
            .filter_map(|d| d.dialog.key().map(str::to_owned))
            .collect();
        let out = table::show(
            ui,
            ZONE_TABLE,
            0.0,
            &mut self.zone_table,
            &ZONE_COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<&Value> = zones
                        .iter()
                        .filter(|r| sel.contains(&text(r, "id")))
                        .collect();
                    let owned = || sel.to_vec();
                    let name = picked.first().map(|z| text(z, "name")).unwrap_or_default();
                    for (label, cmd, ok, a) in [
                        ("Enable", "ip.dns.zone.set", can_enable(&picked, true), Act::Enable(owned())),
                        ("Disable", "ip.dns.zone.set", can_enable(&picked, false), Act::Disable(owned())),
                        ("Remove", "ip.dns.zone.remove", some(&picked), Act::Remove(owned())),
                        ("Records…", "ip.dns.zone.record.print", one(&picked), Act::Records(name.clone())),
                        ("Zone File…", "ip.dns.zone.file.get", one(&picked), Act::File(name.clone())),
                    ] {
                        if action(ui, label, can.and(cmd, ok)) {
                            act = Some(a);
                        }
                    }
                    if action(ui, "Properties…", some(&picked)) {
                        act = Some(Act::Open(owned()));
                    }
                }
                Menu::Empty => {
                    if action(ui, "Add Zone…", can.check("ip.dns.zone.add")) {
                        act = Some(Act::New);
                    }
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                    if ui.button("Refresh").clicked() {
                        act = Some(Act::Reload);
                    }
                }
            },
        );
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(s) = out.shortcut {
            act = match s {
                Shortcut::Remove if some(&picked).is_ok() => Some(Act::Remove(selection.clone())),
                Shortcut::Open if some(&picked).is_ok() => Some(Act::Open(selection.clone())),
                Shortcut::Enable if can_enable(&picked, true).is_ok() => {
                    Some(Act::Enable(selection.clone()))
                }
                Shortcut::Disable if can_enable(&picked, false).is_ok() => {
                    Some(Act::Disable(selection.clone()))
                }
                _ => act,
            };
        }
        if let Some(a) = act {
            self.zone_act(app, a, &rows);
        }
    }

    fn zone_act(&mut self, app: &mut CoreRouterUi, act: Act, rows: &[Row]) {
        match act {
            Act::Enable(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.set", json!({"id": id, "disabled": false}));
                }
            }
            Act::Disable(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.set", json!({"id": id, "disabled": true}));
                }
            }
            Act::Remove(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.remove", json!({ "id": id }));
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_zone(app, k);
                }
            }
            Act::New => self.open_dialog(app, Dialog::NewZone(Box::default())),
            Act::Records(zone) => {
                self.zone = zone;
                open_window(app, WIN_RECORDS);
            }
            Act::File(zone) => {
                self.fetch_file(app, &zone);
                open_window(app, WIN_FILE);
            }
            Act::Refresh(zone) => {
                app.run("ip.dns.zone.refresh", json!({ "zone": zone }));
            }
            Act::SelectAll => self.zone_table.select_all(rows),
            Act::Reload => app.cache.refreshed_at = None,
        }
    }

    fn fetch_file(&mut self, app: &mut CoreRouterUi, zone: &str) {
        zone.clone_into(&mut self.file.zone);
        self.file.waiting = true;
        self.file.message = None;
        app.run_then(
            "ip.dns.zone.file.get",
            json!({ "zone": zone }),
            crate::panel::then(NAME, Reply::File { zone: zone.to_owned() }),
        );
    }

    fn zone_picker(&self, ui: &mut Ui, salt: &str, zone: &mut String, primaries_only: bool) {
        egui::ComboBox::from_id_salt(salt)
            .selected_text(if zone.is_empty() { "(none)" } else { zone.as_str() })
            .show_ui(ui, |ui| {
                for z in &self.zones {
                    if primaries_only && text(z, "type") != "primary" {
                        continue;
                    }
                    let n = text(z, "name");
                    ui.selectable_value(zone, n.clone(), n);
                }
            });
    }

    fn records_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let zone_row = self.zones.iter().find(|z| text(z, "name") == self.zone).cloned();
        let primary = zone_row
            .as_ref()
            .is_some_and(|z| text(z, "type") == "primary");
        let records: Vec<Value> = self
            .records
            .iter()
            .filter(|r| text(r, "zone") == self.zone)
            .cloned()
            .collect();
        let rows: Vec<Row> = records.iter().map(record_row).collect();
        let selection = self.record_table.selection(&rows);
        let picked: Vec<&Value> = records
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let can = app.can();
        let mut act = None;
        let mut zone = self.zone.clone();
        ui.horizontal(|ui| {
            ui.label("Zone");
            self.zone_picker(ui, "dns-zone-records-zone", &mut zone, false);
            let add = if primary {
                can.check("ip.dns.zone.record.add")
            } else {
                Err("A secondary zone gets its records by transfer".into())
            };
            if table::tool(ui, RECORD_TABLE, Icon::Add, "Add", add).clicked() {
                act = Some(Act::New);
            }
            for (icon, tip, enabled) in [
                (Icon::Remove, "Remove", can.and("ip.dns.zone.record.remove", some(&picked))),
                (Icon::Enable, "Enable", can.and("ip.dns.zone.record.set", can_enable(&picked, true))),
                (Icon::Disable, "Disable", can.and("ip.dns.zone.record.set", can_enable(&picked, false))),
            ] {
                if table::tool(ui, RECORD_TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        _ => Act::Remove(sel),
                    });
                }
            }
            if let Some(z) = &zone_row {
                ui.separator();
                let tone = if text(z, "type") == "secondary" {
                    BLUE.tone(ui.visuals())
                } else {
                    neutral_tone(ui.visuals())
                };
                chip(ui, &text(z, "type"), tone);
            }
            table::find_field(ui, RECORD_TABLE, &mut self.record_table);
        });
        self.zone = zone;
        if zone_row.is_some() && !primary {
            ui.weak("A secondary's records come from its primaries: see its Zone File.");
        }
        ui.separator();
        self.record_table.open = self
            .dialogs
            .iter()
            .filter(|d| !d.dialog.is_zone())
            .filter_map(|d| d.dialog.key().map(str::to_owned))
            .collect();
        let out = table::show(
            ui,
            RECORD_TABLE,
            0.0,
            &mut self.record_table,
            &RECORD_COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<&Value> = records
                        .iter()
                        .filter(|r| sel.contains(&text(r, "id")))
                        .collect();
                    let owned = || sel.to_vec();
                    for (label, cmd, ok, a) in [
                        ("Enable", "ip.dns.zone.record.set", can_enable(&picked, true), Act::Enable(owned())),
                        ("Disable", "ip.dns.zone.record.set", can_enable(&picked, false), Act::Disable(owned())),
                        ("Remove", "ip.dns.zone.record.remove", some(&picked), Act::Remove(owned())),
                    ] {
                        if action(ui, label, can.and(cmd, ok)) {
                            act = Some(a);
                        }
                    }
                    if action(ui, "Properties…", some(&picked)) {
                        act = Some(Act::Open(owned()));
                    }
                }
                Menu::Empty => {
                    if action(ui, "Add Record…", can.check("ip.dns.zone.record.add")) {
                        act = Some(Act::New);
                    }
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                }
            },
        );
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(s) = out.shortcut {
            act = match s {
                Shortcut::Remove if some(&picked).is_ok() => Some(Act::Remove(selection.clone())),
                Shortcut::Open if some(&picked).is_ok() => Some(Act::Open(selection.clone())),
                Shortcut::Enable if can_enable(&picked, true).is_ok() => {
                    Some(Act::Enable(selection.clone()))
                }
                Shortcut::Disable if can_enable(&picked, false).is_ok() => {
                    Some(Act::Disable(selection.clone()))
                }
                _ => act,
            };
        }
        let Some(a) = act else {
            return;
        };
        match a {
            Act::Enable(keys) | Act::Disable(keys) if keys.is_empty() => {}
            Act::Enable(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.record.set", json!({"id": id, "disabled": false}));
                }
            }
            Act::Disable(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.record.set", json!({"id": id, "disabled": true}));
                }
            }
            Act::Remove(keys) => {
                for id in keys {
                    app.run("ip.dns.zone.record.remove", json!({ "id": id }));
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_record(app, k);
                }
            }
            Act::New => {
                let form = RecordForm {
                    zone: self.zone.clone(),
                    ..RecordForm::default()
                };
                self.open_dialog(app, Dialog::NewRecord(Box::new(form)));
            }
            Act::SelectAll => self.record_table.select_all(&rows),
            _ => {}
        }
    }

    fn file_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let mut zone = self.file.zone.clone();
        let mut fetch = false;
        let mut load = false;
        let zone_type = self
            .zones
            .iter()
            .find(|z| text(z, "name") == zone)
            .map(|z| text(z, "type"))
            .unwrap_or_default();
        let dirty = self.file.text != self.file.loaded;
        ui.horizontal(|ui| {
            ui.label("Zone");
            self.zone_picker(ui, "dns-zone-file-zone", &mut zone, false);
            fetch = action(ui, "Reload", can.check("ip.dns.zone.file.get"));
            let ok = if self.file.waiting {
                Err("Waiting for the router…".to_owned())
            } else if zone_type != "primary" {
                Err("Only a primary zone takes a zone file".to_owned())
            } else if self.file.text.trim().is_empty() {
                Err("Nothing to load".to_owned())
            } else {
                can.check("ip.dns.zone.file.load")
            };
            load = action(ui, "Load into Zone", ok);
            if ui.button("Copy").clicked() {
                ui.ctx().copy_text(self.file.text.clone());
            }
            if dirty {
                ui.weak(format!("{} not loaded", dialog::UNSAVED));
            }
        });
        if zone != self.file.zone {
            fetch = true;
        }
        match &self.file.message {
            Some(Ok(m)) => {
                ui.label(RichText::new(m.as_str()).color(ui.visuals().hyperlink_color));
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e.as_str());
            }
            None => {
                ui.weak(
                    "RFC 1035 zone file: $ORIGIN, $TTL, SOA and the records. Loading replaces \
                     the zone's records; the serial moves by itself.",
                );
            }
        }
        ui.separator();
        ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                TextEdit::multiline(&mut self.file.text)
                    .code_editor()
                    .desired_rows(20)
                    .desired_width(f32::INFINITY),
            );
        });
        if fetch && !zone.is_empty() {
            self.fetch_file(app, &zone);
        }
        if load {
            self.file.waiting = true;
            self.file.message = None;
            app.run_then(
                "ip.dns.zone.file.load",
                json!({"zone": self.file.zone, "text": self.file.text}),
                crate::panel::then(NAME, Reply::Loaded),
            );
        }
    }

    fn open_dialog(&mut self, app: &mut CoreRouterUi, dialog: Dialog) {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.dialogs.push(DialogWin {
            id: app.next_dialog,
            dialog,
            status: Status::default(),
        });
        app.cache.refreshed_at = None;
    }

    fn raise(&mut self, id: &str) -> bool {
        if let Some(d) = self.dialogs.iter_mut().find(|d| d.dialog.key() == Some(id)) {
            d.status.bring_to_front();
            return true;
        }
        false
    }

    fn open_zone(&mut self, app: &mut CoreRouterUi, id: &str) {
        let Some(row) = self.zones.iter().find(|r| text(r, "id") == id).cloned() else {
            return;
        };
        if self.raise(id) {
            return;
        }
        let form = Box::new(ZoneForm::of(&row));
        self.open_dialog(app, Dialog::Zone {
            id: id.to_owned(),
            base: form.clone(),
            form,
        });
    }

    fn open_record(&mut self, app: &mut CoreRouterUi, id: &str) {
        let Some(row) = self.records.iter().find(|r| text(r, "id") == id).cloned() else {
            return;
        };
        if self.raise(id) {
            return;
        }
        let form = Box::new(RecordForm::of(&row));
        self.open_dialog(app, Dialog::Record {
            id: id.to_owned(),
            base: form.clone(),
            form,
        });
    }

    fn draw_dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let zones = self.zones.clone();
        let records = self.records.clone();
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            let gone = |list: &[Value], id: &str| {
                !list.is_empty() && !list.iter().any(|r| text(r, "id") == id)
            };
            let (title, parent) = match &d.dialog {
                Dialog::NewZone(_) => ("New DNS Zone".to_owned(), WIN),
                Dialog::Zone { id, form, .. } => {
                    if gone(&zones, id) {
                        app.floats.forget(wid);
                        return false;
                    }
                    (format!("DNS Zone <{}>", form.name), WIN)
                }
                Dialog::NewRecord(f) => (format!("New Record in {}", f.zone), WIN_RECORDS),
                Dialog::Record { id, form, .. } => {
                    if gone(&records, id) {
                        app.floats.forget(wid);
                        return false;
                    }
                    (format!("DNS Record <{} {}>", form.name, form.rtype), WIN_RECORDS)
                }
            };
            let status_row = match &d.dialog {
                Dialog::Zone { id, .. } => zones.iter().find(|z| text(z, "id") == *id).cloned(),
                _ => None,
            };
            let can = app.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Panel(parent))),
            };
            let picker_zones = zones.clone();
            let zone_keys: Vec<Value> = match &d.dialog {
                Dialog::Zone { base, .. } => self
                    .keys
                    .iter()
                    .filter(|k| text(k, "zone") == base.name)
                    .cloned()
                    .collect(),
                _ => Vec::new(),
            };
            let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
                match &mut d.dialog {
                    Dialog::NewZone(form) => zone_body(ui, f, form, true, None, &[], &can),
                    Dialog::Zone { form, .. } => {
                        zone_body(ui, f, form, false, status_row.as_ref(), &zone_keys, &can)
                    }
                    Dialog::NewRecord(form) => record_body(ui, f, form, Some(&picker_zones), &can),
                    Dialog::Record { form, .. } => record_body(ui, f, form, None, &can),
                }
            });
            let keep = pressed.is_none_or(|b| self.button(app, d, b));
            if !keep {
                app.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    fn button(&mut self, app: &mut CoreRouterUi, d: &mut DialogWin, b: Press<Button>) -> bool {
        let (cmd, params, applied, close) = match (&d.dialog, b) {
            (_, Press::Cancel) => return false,
            (Dialog::NewZone(form), _) => ("ip.dns.zone.add", form.add_params(), None, true),
            (Dialog::NewRecord(form), _) => {
                ("ip.dns.zone.record.add", form.add_params(), None, true)
            }
            (Dialog::Zone { id, .. }, Press::Other(Button::Remove)) => {
                ("ip.dns.zone.remove", json!({ "id": id }), None, true)
            }
            (Dialog::Zone { base, .. }, Press::Other(roll @ (Button::RollZsk | Button::RollKsk))) => {
                let key = if roll == Button::RollKsk { "ksk" } else { "zsk" };
                (
                    "ip.dns.zone.dnssec.rollover",
                    json!({"zone": base.name, "key": key}),
                    None,
                    false,
                )
            }
            (Dialog::Zone { base, .. }, Press::Other(Button::DsPublished)) => (
                "ip.dns.zone.dnssec.ds-published",
                json!({"zone": base.name}),
                None,
                false,
            ),
            (Dialog::Record { id, .. }, Press::Other(Button::Remove)) => {
                ("ip.dns.zone.record.remove", json!({ "id": id }), None, true)
            }
            (Dialog::Zone { id, form, base }, b) => match form.set_params(id, base) {
                Some(p) => (
                    "ip.dns.zone.set",
                    p,
                    Some(Applied::Zone(form.clone())),
                    b == Press::Ok,
                ),
                None => return b != Press::Ok,
            },
            (Dialog::Record { id, form, base }, b) => match form.set_params(id, base) {
                Some(p) => (
                    "ip.dns.zone.record.set",
                    p,
                    Some(Applied::Record(form.clone())),
                    b == Press::Ok,
                ),
                None => return b != Press::Ok,
            },
        };
        d.status.close_on_success = close;
        d.status.sent();
        app.run_then(
            cmd,
            params,
            crate::panel::then(NAME, Reply::Dialog { id: d.id, applied }),
        );
        true
    }

    fn dialog_reply(
        &mut self,
        app: &mut CoreRouterUi,
        id: u64,
        applied: Option<Applied>,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                if result.is_ok() {
                    match (applied, &mut d.dialog) {
                        (Some(Applied::Zone(sent)), Dialog::Zone { base, .. }) => *base = sent,
                        (Some(Applied::Record(sent)), Dialog::Record { base, .. }) => *base = sent,
                        _ => {}
                    }
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            app.floats.forget(dialog_id(id));
        }
    }
}

fn zone_body(
    ui: &mut Ui,
    f: &Form,
    form: &mut ZoneForm,
    new: bool,
    row: Option<&Value>,
    keys: &[Value],
    can: &Avail,
) -> Footer<Button> {
    if let Some(r) = row {
        ui.horizontal(|ui| {
            let st = text(r, "status");
            let tone = match st.as_str() {
                "running" | "loaded" => BLUE.tone(ui.visuals()),
                "not-loaded" => AMBER.tone(ui.visuals()),
                _ => neutral_tone(ui.visuals()),
            };
            chip(ui, &st, tone).on_hover_text(status_text(r));
            ui.label(format!("serial {}", text(r, "serial")));
            if r.get("signed_serial").is_some() {
                chip(ui, "signed", BLUE.tone(ui.visuals()))
                    .on_hover_text("DNSSEC: the signed version is served");
                ui.label(format!("serial {}", text(r, "signed_serial")));
            }
            ui.weak(format!("{} records", text(r, "records")));
        });
        ui.separator();
    }
    let secondary = form.ztype == "secondary";
    Grid::new("dns-zone-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(ui, "Name", "name", &mut form.name, "example.com");
            ui.label("Type");
            if new {
                egui::ComboBox::from_id_salt(f.window().with("type"))
                    .selected_text(form.ztype.as_str())
                    .show_ui(ui, |ui| {
                        for t in ["primary", "secondary"] {
                            ui.selectable_value(&mut form.ztype, t.to_owned(), t);
                        }
                    });
            } else {
                ui.label(form.ztype.as_str());
            }
            ui.end_row();
            if secondary {
                f.text(ui, "Primaries", "primaries", &mut form.primaries, "192.0.2.53");
            } else {
                // The defaults the engine fills in, as hints.
                let zone = if form.name.trim().is_empty() {
                    "<zone>".to_owned()
                } else {
                    form.name.trim().trim_end_matches('.').to_owned()
                };
                let (ns, admin) = (format!("ns1.{zone}"), format!("hostmaster@{zone}"));
                f.text(ui, "Primary NS", "primary_ns", &mut form.primary_ns, &ns);
                f.text(ui, "Admin", "admin", &mut form.admin, &admin);
                ui.label("Serial Policy").on_hover_text(
                    "How the serial moves on every change: date (YYYYMMDDnn), increment, unixtime.",
                );
                egui::ComboBox::from_id_salt(f.window().with("serial_policy"))
                    .selected_text(form.serial_policy.as_str())
                    .show_ui(ui, |ui| {
                        for t in ["date", "increment", "unixtime"] {
                            ui.selectable_value(&mut form.serial_policy, t.to_owned(), t);
                        }
                    });
                ui.end_row();
                f.text(ui, "Refresh (s)", "refresh_secs", &mut form.refresh_secs, "86400");
                f.text(ui, "Retry (s)", "retry_secs", &mut form.retry_secs, "7200");
                f.text(ui, "Expire (s)", "expire_secs", &mut form.expire_secs, "3600000");
                f.text(ui, "Negative TTL (s)", "minimum_secs", &mut form.minimum_secs, "3600");
                f.text(ui, "Default TTL (s)", "ttl_secs", &mut form.ttl_secs, "3600");
                f.text(ui, "Notify", "notify", &mut form.notify, "secondaries to tell");
                ui.label("DNSSEC").on_hover_text(
                    "Sign the zone: a KSK and a ZSK made by the router, NSEC3 without extra \
                     iterations or salt (RFC 9276). Put the DS shown below at the parent.",
                );
                ui.checkbox(&mut form.dnssec, "");
                ui.end_row();
                if form.dnssec {
                    ui.label("Algorithm");
                    egui::ComboBox::from_id_salt(f.window().with("dnssec_algorithm"))
                        .selected_text(form.dnssec_algorithm.as_str())
                        .show_ui(ui, |ui| {
                            for t in ["ecdsa-p256", "ed25519"] {
                                ui.selectable_value(&mut form.dnssec_algorithm, t.to_owned(), t);
                            }
                        });
                    ui.end_row();
                    f.text(
                        ui,
                        "Signature Validity (s)",
                        "signature_validity_secs",
                        &mut form.signature_validity_secs,
                        "1209600",
                    );
                }
            }
            f.text(
                ui,
                "Allow Transfer",
                "allow_transfer",
                &mut form.allow_transfer,
                "nobody (prefixes)",
            );
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            ui.label("Disabled");
            ui.checkbox(&mut form.disabled, "");
            ui.end_row();
        });
    ui.label(
        RichText::new(if secondary {
            "Transferred from the primaries (IXFR, AXFR) on their NOTIFY and every refresh; \
             Allow Transfer lets other secondaries copy it from here."
        } else {
            "Allow Transfer: who may copy the zone (AXFR/IXFR), empty = nobody. Notify: told \
             on every change (RFC 1996)."
        })
        .weak()
        .small(),
    );
    let pressed = if keys.is_empty() {
        None
    } else {
        dnssec_keys(ui, keys, can)
    };
    let ok = can.check(if new { "ip.dns.zone.add" } else { "ip.dns.zone.set" });
    let mut footer = Footer::edit(!new, ok);
    if !new {
        footer.extra = vec![("Remove", Button::Remove, can.check("ip.dns.zone.remove"))];
    }
    footer.pressed = pressed;
    footer
}

/// The zone's keys: one line each (role, tag, state, what comes next), the
/// DS for the parent with Copy, and the rollover buttons.
fn dnssec_keys(ui: &mut Ui, keys: &[Value], can: &Avail) -> Option<Button> {
    let mut pressed = None;
    ui.separator();
    ui.label(RichText::new("DNSSEC keys").strong());
    let ksks = keys
        .iter()
        .filter(|k| text(k, "role") == "ksk" && text(k, "state") == "active")
        .count();
    for k in keys {
        ui.horizontal(|ui| {
            chip(ui, &text(k, "role").to_uppercase(), neutral_tone(ui.visuals()));
            ui.label(format!("{} {}", text(k, "algorithm"), text(k, "key_tag")));
            let st = text(k, "state");
            let tone = match st.as_str() {
                "active" => BLUE.tone(ui.visuals()),
                "retired" => AMBER.tone(ui.visuals()),
                _ => neutral_tone(ui.visuals()),
            };
            chip(ui, &st, tone);
            let next = text(k, "next");
            if !next.is_empty() {
                ui.weak(next);
            }
        });
        let ds = text(k, "ds");
        if !ds.is_empty() && text(k, "state") != "retired" {
            ui.horizontal(|ui| {
                let mut shown = ds.clone();
                if shown.len() > 48 {
                    shown.truncate(48);
                    shown.push('…');
                }
                ui.label(RichText::new(format!("DS {shown}")).monospace().small())
                    .on_hover_text(&ds);
                if ui.small_button("Copy DS").clicked() {
                    ui.ctx().copy_text(ds.clone());
                }
            });
        }
    }
    ui.horizontal(|ui| {
        let roll = can.check("ip.dns.zone.dnssec.rollover");
        if action(ui, "Roll ZSK", roll.clone()) {
            pressed = Some(Button::RollZsk);
        }
        if action(ui, "Roll KSK", roll) {
            pressed = Some(Button::RollKsk);
        }
        let published = if ksks > 1 {
            can.check("ip.dns.zone.dnssec.ds-published")
        } else {
            Err("No KSK rollover is waiting for its DS".to_owned())
        };
        if action(ui, "DS Published", published) {
            pressed = Some(Button::DsPublished);
        }
    });
    pressed
}

fn record_body(
    ui: &mut Ui,
    f: &Form,
    form: &mut RecordForm,
    zones: Option<&[Value]>,
    can: &Avail,
) -> Footer<Button> {
    let new = zones.is_some();
    Grid::new("dns-zone-record-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Zone");
            match zones {
                Some(zs) => {
                    egui::ComboBox::from_id_salt(f.window().with("zone"))
                        .selected_text(form.zone.as_str())
                        .show_ui(ui, |ui| {
                            for z in zs.iter().filter(|z| text(z, "type") == "primary") {
                                let n = text(z, "name");
                                ui.selectable_value(&mut form.zone, n.clone(), n);
                            }
                        });
                }
                None => {
                    ui.label(form.zone.as_str());
                }
            }
            ui.end_row();
            f.text(ui, "Name", "name", &mut form.name, "@, www, *.dev");
            ui.label("Type");
            egui::ComboBox::from_id_salt(f.window().with("type"))
                .selected_text(form.rtype.as_str())
                .show_ui(ui, |ui| {
                    for t in TYPES {
                        ui.selectable_value(&mut form.rtype, t.to_owned(), t);
                    }
                });
            ui.end_row();
            match form.rtype.as_str() {
                "A" => f.text(ui, "Address", "address", &mut form.address, "192.0.2.10"),
                "AAAA" => f.text(ui, "Address", "address", &mut form.address, "2001:db8::10"),
                "CNAME" | "NS" | "PTR" => {
                    f.text(ui, "Target", "target", &mut form.target, "host.example.com")
                }
                "MX" => {
                    f.text(ui, "Exchange", "target", &mut form.target, "mail.example.com");
                    f.text(ui, "Preference", "priority", &mut form.priority, "10");
                }
                "SRV" => {
                    f.text(ui, "Target", "target", &mut form.target, "sip.example.com");
                    f.text(ui, "Port", "port", &mut form.port, "5060");
                    f.text(ui, "Priority", "priority", &mut form.priority, "0");
                    f.text(ui, "Weight", "weight", &mut form.weight, "0");
                }
                "TXT" => f.text(ui, "Text", "text", &mut form.text, "v=spf1 -all"),
                "CAA" => {
                    f.text(ui, "Flags", "caa_flags", &mut form.caa_flags, "0 (128: critical)");
                    f.text(ui, "Tag", "caa_tag", &mut form.caa_tag, "issue");
                    f.text(ui, "Value", "text", &mut form.text, "letsencrypt.org");
                }
                _ => {}
            }
            f.text(ui, "TTL (s)", "ttl_secs", &mut form.ttl_secs, "the zone's");
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            ui.label("Disabled");
            ui.checkbox(&mut form.disabled, "");
            ui.end_row();
        });
    ui.label(
        RichText::new(
            "Name is relative to the zone (@ is the zone itself); targets are full names.",
        )
        .weak()
        .small(),
    );
    let ok = can.check(if new {
        "ip.dns.zone.record.add"
    } else {
        "ip.dns.zone.record.set"
    });
    let mut footer = Footer::edit(!new, ok);
    if !new {
        footer.extra = vec![(
            "Remove",
            Button::Remove,
            can.check("ip.dns.zone.record.remove"),
        )];
    }
    footer
}

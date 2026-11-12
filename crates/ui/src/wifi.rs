//! Interfaces › Wi-Fi (G1.30), RouterOS `/interface wifi`: the router's
//! radios and the network each one joins (station) or announces (G1.30a,
//! access point). The list window pattern (G0.24, `docs/ui-style.md`) with
//! three tabs:
//!
//! - **Radios:** one row per radio with its state chip (and why the last
//!   attempt failed), the network by key colour, signal, channel and rate;
//!   the bar ✓ ✗ 💬, Scan… and Reconnect; under the table the selected
//!   radio's `monitor`. No + nor −: a radio is there because the card is,
//!   like an Ethernet port.
//! - **Networks:** what the last scan of one radio heard, strongest first;
//!   Connect… opens the radio's modal with the network filled in. G1.30i:
//!   three views of it (list, channel graph, spectrum), `wifi_scan.rs`.
//! - **Registration** (G1.30a): the clients of the access points,
//!   `wifi_clients.rs`.
//! - **Peers** (G1.30m): the station-bridges the access points take,
//!   `wifi_peers.rs`.
//!
//! The country every radio follows is on the first line, with its dialog.
//! G1.30h: the same dialog opens from "Interface <wifi1>" and from Enable
//! on a radio without a country ([`ask_country`]), with "Also enable" so
//! one OK sets the country and turns the radio on.
//! The modal is fed by `interface.wifi.preview` (the checks and warnings of
//! `interface.wifi.set`, whether the network is in range, the access risk,
//! the commands).
//!
//! The engine decides everything; this file only draws and sends
//! `interface.wifi.*`.

use std::collections::BTreeMap;

use egui::{Grid, Id, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list;
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, TableState, col, comment};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "wifi";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "wifi";
pub(crate) const TABLE: &str = "wifi";
/// The table of the Networks tab.
pub(crate) const HEARD: &str = "wifi-networks";
/// Scope of the window's translations (`i18n/auto/wifi_*.rs`).
const SCOPE: &str = "wifi";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Interfaces",
        title: "Wi-Fi",
        // G1.30i: room for the Networks tab's columns and graphs.
        size: [1240.0, 700.0],
        escape: true,
    }],
    new: || Box::new(WifiPanel::default()),
};

const FIELDS: &[Field] = &[
    Field { param: "mode", label: "Mode", help: "interface.wifi.mode", input: Input::Choice, edit: true },
    Field { param: "ssid", label: "SSID", help: "interface.wifi.ssid", input: Input::Text("the network's name"), edit: true },
    Field { param: "security", label: "Security", help: "interface.wifi.security", input: Input::Choice, edit: true },
    Field { param: "passphrase", label: "Passphrase", help: "interface.wifi.passphrase", input: Input::Secret("8 to 63 characters"), edit: true },
    Field { param: "hidden", label: "Hidden Network", help: "interface.wifi.hidden", input: Input::Check, edit: true },
    Field { param: "band", label: "Band", help: "interface.wifi.band", input: Input::Choice, edit: true },
    Field { param: "bssid", label: "Lock to BSSID", help: "interface.wifi.bssid", input: Input::Text("any access point"), edit: true },
    Field { param: "bridge_protocol", label: "Bridge Protocol", help: "interface.wifi.bridge_protocol", input: Input::Choice, edit: true },
    Field { param: "station_bridge", label: "Station Bridge", help: "interface.wifi.station_bridge", input: Input::Choice, edit: true },
    Field { param: "frequency", label: "Frequency", help: "interface.wifi.frequency", input: Input::Text("auto, a channel (36) or MHz"), edit: true },
    Field { param: "width", label: "Width", help: "interface.wifi.width", input: Input::Choice, edit: true },
    Field { param: "mtu", label: "MTU", help: "interface.wifi.mtu", input: Input::Text("1500"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
    Field { param: "disabled", label: "Disabled", help: "interface.wifi.disabled", input: Input::Check, edit: true },
];

/// G1.30m: the modal's pages. General: what the radio is and the network;
/// Channel: where it runs and the link's details.
const GENERAL_PAGE: &[&str] = &[
    "mode", "ssid", "security", "passphrase", "hidden", "bridge_protocol", "station_bridge", "disabled", "comment",
];
const CHANNEL_PAGE: &[&str] = &["band", "frequency", "width", "bssid", "mtu"];

pub(crate) const SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    // A radio is never added: the modal only edits.
    new_title: "Wi-Fi",
    edit_title: "Wi-Fi",
    help: "interface.wifi",
    fields: FIELDS,
    preview: "interface.wifi.preview",
};

const COLUMNS: [table::Column; 9] = [
    col("Name").help("interface.wifi.name"),
    col("State").help("interface.wifi.state"),
    col("SSID").help("interface.wifi.ssid"),
    col("Security").help("interface.wifi.security"),
    col("Signal").help("interface.wifi.signal"),
    col("Channel").help("interface.wifi.channel"),
    col("Rate").help("interface.wifi.rate"),
    col("Radio").help("interface.wifi.radio"),
    comment(),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    Radios,
    Networks,
    /// G1.30a: the clients of the access points.
    Registration,
    /// G1.30m: the station-bridges the access points take.
    Peers,
}

/// The country dialog: one field, and the radios to enable after it.
pub(crate) struct CountryDialog {
    pub id: u64,
    pub value: String,
    pub status: Status,
    /// The window it was opened from (G1.30h); `None`: this panel's.
    pub parent: Option<Id>,
    /// Radios an Enable without a country asked for (G1.30h): enabled
    /// once the country is set, while [`Self::enable_on`].
    pub enable: Vec<String>,
    pub enable_on: bool,
    /// The country went in and the radios' Enable is out.
    enabling: bool,
}

/// The reply of the country dialog's command.
struct CountrySet(u64);

/// The reply of an Enable the country dialog sent after the country.
struct CountryEnabled(u64);

/// The reply of an Enable sent from a list (G1.30h): refused for want of
/// a country, it opens the country dialog over window `parent`.
struct EnableTried {
    parent: Id,
    name: String,
}

/// The words of the engine's "no country yet" refusal
/// (`corerouter_model::wifi::NO_COUNTRY`, the same in the commit and in the
/// preview) that tell it apart; a test keeps the two in step.
pub(crate) const NO_COUNTRY_MARK: &str = "cannot be enabled before the country is set";

/// Whether an engine error (or one issue of it) is the "no country yet" one.
pub(crate) fn is_no_country(error: &str) -> bool {
    error.contains(NO_COUNTRY_MARK)
}

/// G1.30h: open (or raise) the country dialog over window `parent`,
/// offering to enable radios `enable` after it (ticked when `on`: the
/// operator pressed Enable). From the windows outside this panel.
pub(crate) fn ask_country(app: &mut CoreRouterUi, parent: Id, enable: Vec<String>, on: bool) {
    app.next_dialog = app.next_dialog.wrapping_add(1);
    let id = app.next_dialog;
    if let Some(p) = app.panel_mut::<WifiPanel>() {
        p.open_country(id, Some(parent), enable, on);
    }
}

/// G1.30h: Enable on radio `name` from window `parent`: the country
/// dialog when the router refuses it for want of a country.
pub(crate) fn enable_then(parent: Id, name: &str) -> crate::Then {
    crate::panel::then(
        NAME,
        EnableTried {
            parent,
            name: name.to_owned(),
        },
    )
}

/// G1.30h: Scan… from "Interface <name>": scan, and show what radio `name`
/// hears in this panel's Networks tab.
pub(crate) fn scan_from(app: &mut CoreRouterUi, name: &str) {
    app.run("interface.wifi.scan", json!({ "name": name }));
    if let Some(p) = app.panel_mut::<WifiPanel>() {
        p.radio = name.to_owned();
        p.heard = None;
        p.tab = Tab::Networks;
    }
    open_window(app);
}

/// G1.30h: Connect… from "Interface <name>": the radio's modal (network,
/// passphrase), once the list of radios is in.
pub(crate) fn connect_from(app: &mut CoreRouterUi, name: &str) {
    if let Some(p) = app.panel_mut::<WifiPanel>() {
        p.tab = Tab::Radios;
        p.edit_when_listed = Some(name.to_owned());
    }
    open_window(app);
}

/// Open (or raise) Interfaces › Wi-Fi.
fn open_window(app: &mut CoreRouterUi) {
    if !app.open.insert(Win::Panel(WIN)) {
        app.floats.raise(crate::win_id(Win::Panel(WIN)));
    }
    app.cache.refreshed_at = None;
}

/// What the bar or a menu asked for.
enum Do {
    Edit(String),
    Enable(Vec<String>),
    Disable(Vec<String>),
    Reconnect(Vec<String>),
    Scan(String),
    Copy(Vec<String>),
}

#[derive(Default)]
pub(crate) struct WifiPanel {
    /// `interface.wifi.list`, while the window is open.
    pub(crate) rows: Vec<Value>,
    /// `interface.wifi.monitor` of the one selected radio.
    pub(crate) monitor: Option<Value>,
    /// `interface.wifi.country.get`.
    pub(crate) country: Option<Value>,
    /// `interface.wifi.networks` of [`Self::radio`].
    pub(crate) heard: Option<Value>,
    pub(crate) tab: Tab,
    /// The radio whose scan the Networks tab shows.
    pub(crate) radio: String,
    pub(crate) modal: Option<Modal>,
    pub(crate) country_dialog: Option<CountryDialog>,
    /// Connect… from "Interface <name>" (G1.30h): open this radio's modal
    /// when `interface.wifi.list` arrives.
    pub(crate) edit_when_listed: Option<String>,
    pub(crate) table: TableState,
    pub(crate) heard_table: TableState,
    /// G1.30i: the views of the Networks tab.
    pub(crate) scan: crate::wifi_scan::ScanView,
    /// G1.30a: the Registration tab.
    pub(crate) clients: crate::wifi_clients::ClientsView,
    /// G1.30m: the Peers tab.
    pub(crate) peers: crate::wifi_peers::PeersView,
    /// G1.30m: the page of the radio's modal (General, Channel).
    pub(crate) modal_page: usize,
    help: Option<HelpView>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn state_kind(state: &str) -> Kind {
    match state {
        "connected" | "running" => Kind::Green,
        "searching" | "connecting" | "starting" | "radar-check" => Kind::Blue,
        "no-country" | "blocked" | "absent" | "no-ir" => Kind::Amber,
        "error" | "failed" => Kind::Red,
        _ => Kind::Neutral,
    }
}

/// The state code as a label of the catalog (`tr_in` needs one).
pub(crate) fn state_label(code: &str) -> &'static str {
    match code {
        "connected" => "connected",
        "searching" => "searching",
        "connecting" => "connecting",
        "idle" => "no network",
        "no-country" => "no country",
        "blocked" => "blocked",
        "absent" => "absent",
        "error" => "error",
        // G1.30a: an access point's.
        "running" => "running",
        "starting" => "starting",
        "radar-check" => "radar check",
        "no-ir" => "passive channel",
        "failed" => "failed",
        _ => "disabled",
    }
}

/// Why the last attempt failed, as the operator reads it.
pub(crate) fn failure_label(code: &str) -> &'static str {
    match code {
        "wrong-key" => "wrong passphrase?",
        "not-found" => "network not found",
        "rejected" => "refused by the access point",
        "no-answer" => "no answer",
        _ => "failed",
    }
}

fn failure_kind(code: &str) -> Kind {
    if code == "wrong-key" || code == "rejected" { Kind::Red } else { Kind::Amber }
}

/// What the radio is set to accept.
fn security_label(code: &str) -> &'static str {
    match code {
        "auto" => "WPA2/WPA3",
        "wpa3" => "WPA3",
        "wpa2" => "WPA2",
        "open" => "open",
        _ => "",
    }
}

/// Green down to -65 dBm, amber down to -75, red below: where a link stops
/// being comfortable and where it starts to drop.
pub(crate) fn signal_kind(dbm: i64) -> Kind {
    if dbm >= -65 {
        Kind::Green
    } else if dbm >= -75 {
        Kind::Amber
    } else {
        Kind::Red
    }
}

fn signal_cell(r: &Value, l: Lang) -> String {
    // G1.30a: an access point has clients, not a signal.
    if s(r, "mode") == "ap" {
        let n = r.get("clients").and_then(Value::as_u64).unwrap_or(0);
        return if n == 0 && s(r, "state") != "running" {
            String::new()
        } else {
            cell("", &[(&format!("{n} {}", tr_in(SCOPE, l, "clients")), Kind::Neutral)])
        };
    }
    match r.get("signal").and_then(Value::as_i64) {
        Some(dbm) => cell("", &[(&format!("{dbm} dBm"), signal_kind(dbm))]),
        None => String::new(),
    }
}

/// "5 GHz ch 44".
fn channel_text(r: &Value) -> String {
    let band = match r.get("frequency").and_then(Value::as_u64) {
        Some(mhz) if mhz < 3000 => "2.4 GHz",
        Some(mhz) if mhz < 5925 => "5 GHz",
        Some(_) => "6 GHz",
        None => return String::new(),
    };
    match r.get("channel").and_then(Value::as_u64) {
        Some(ch) => format!("{band} ch {ch}"),
        None => band.to_owned(),
    }
}

fn ssid_cell(ssid: &str, l: Lang) -> String {
    if ssid.is_empty() {
        cell("", &[(tr_in(SCOPE, l, "hidden"), Kind::Neutral)])
    } else {
        cell("", &[(ssid, Kind::Hashed(chip::name_hue(ssid)))])
    }
}

/// `2h 14m`, `3d 04h`, `45s`.
pub(crate) fn uptime_text(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60);
    if d > 0 {
        format!("{d}d {h:02}h")
    } else if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {:02}s", secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// The table row of radio `r`.
pub(crate) fn row(r: &Value, l: Lang) -> Row {
    let state = s(r, "state");
    let mut chips = vec![(tr_in(SCOPE, l, state_label(&state)).to_owned(), state_kind(&state))];
    // G1.30a: the mode, when it is not the usual one.
    if s(r, "mode") == "ap" {
        chips.insert(0, (tr_in(SCOPE, l, "AP").to_owned(), Kind::Blue));
    }
    // G1.30m: a station-bridge.
    if s(r, "mode") == "station-bridge" {
        chips.insert(0, (tr_in(SCOPE, l, "bridge").to_owned(), Kind::Blue));
    }
    if state != "connected"
        && state != "disabled"
        && let Some(f) = r.get("failure").and_then(Value::as_str)
    {
        chips.push((tr_in(SCOPE, l, failure_label(f)).to_owned(), failure_kind(f)));
    }
    let chips: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    let ssid = s(r, "ssid");
    let security = security_label(&s(r, "security"));
    Row {
        key: s(r, "name"),
        cells: vec![
            cell("", &[(&s(r, "name"), Kind::Neutral)]),
            cell("", &chips),
            if ssid.is_empty() { String::new() } else { ssid_cell(&ssid, l) },
            if ssid.is_empty() || security.is_empty() {
                String::new()
            } else {
                cell("", &[(tr_in(SCOPE, l, security), if security == "open" { Kind::Amber } else { Kind::Neutral })])
            },
            signal_cell(r, l),
            channel_text(r),
            r.get("rate").and_then(Value::as_u64).map(|m| format!("{m} Mbps")).unwrap_or_default(),
            s(r, "driver"),
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

/// The modal's fields for radio `r`.
fn values_of(r: &Value) -> BTreeMap<&'static str, String> {
    let yes = |k: &str| if flag(r, k) { "yes" } else { "no" }.to_owned();
    let auto = |k: &str| {
        let v = s(r, k);
        if v.is_empty() { "auto".to_owned() } else { v }
    };
    BTreeMap::from([
        ("mode", if s(r, "mode").is_empty() { "station".to_owned() } else { s(r, "mode") }),
        ("frequency", auto("configured_frequency")),
        ("bridge_protocol", if s(r, "bridge_protocol").is_empty() { "multi-ap".to_owned() } else { s(r, "bridge_protocol") }),
        ("station_bridge", if s(r, "station_bridge").is_empty() { "no".to_owned() } else { s(r, "station_bridge") }),
        ("width", auto("configured_width")),
        ("ssid", s(r, "ssid")),
        ("security", s(r, "security")),
        ("hidden", yes("hidden")),
        ("band", s(r, "band")),
        ("bssid", s(r, "bssid")),
        ("mtu", s(r, "mtu")),
        ("comment", s(r, "comment")),
        ("disabled", yes("disabled")),
    ])
}

impl WifiPanel {
    fn radio_row(&self, name: &str) -> Option<&Value> {
        self.rows.iter().find(|r| s(r, "name") == name)
    }

    fn selected(&self) -> Vec<String> {
        let rows: Vec<Row> = self.rows.iter().map(|r| row(r, Lang::default())).collect();
        self.table.selection(&rows).to_vec()
    }

    /// The networks the last scan of [`Self::radio`] heard.
    fn networks(&self) -> &[Value] {
        self.heard
            .as_ref()
            .filter(|h| s(h, "name") == self.radio)
            .and_then(|h| h.get("networks"))
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }

    /// Open the modal of radio `name`, with `over` on top of what it has.
    fn edit(&mut self, app: &mut CoreRouterUi, name: &str, over: &[(&'static str, String)]) {
        if let Some(m) = &mut self.modal {
            m.status.bring_to_front();
            return;
        }
        let Some(r) = self.radio_row(name) else {
            return;
        };
        let mut m = Modal::open(app, Some((name.to_owned(), name.to_owned())), values_of(r));
        self.modal_page = 0;
        for (k, v) in over {
            m.values.insert(k, v.clone());
        }
        self.modal = Some(m);
    }

    /// Connect… on network `bssid` of the scan: the radio's modal with the
    /// network's name and security, the radio on, the passphrase to type.
    pub(crate) fn connect(&mut self, app: &mut CoreRouterUi, bssid: &str) {
        let Some(n) = self.networks().iter().find(|n| s(n, "bssid") == bssid).cloned() else {
            return;
        };
        let ssid = s(&n, "ssid");
        let security = if s(&n, "security") == "open" { "open" } else { "auto" };
        let radio = self.radio.clone();
        self.edit(
            app,
            &radio,
            &[
                ("ssid", ssid.clone()),
                ("security", security.to_owned()),
                // A network that hides its name is typed, and probed by name.
                ("hidden", if ssid.is_empty() { "yes" } else { "no" }.to_owned()),
                ("bssid", String::new()),
                ("disabled", "no".to_owned()),
            ],
        );
    }

    fn act(&mut self, app: &mut CoreRouterUi, what: Do, ui: &Ui, rows: &[Row]) {
        let each = |app: &mut CoreRouterUi, keys: &[String], command: &str| {
            for k in keys {
                app.run(command, json!({ "name": k }));
            }
        };
        match what {
            Do::Edit(k) => self.edit(app, &k, &[]),
            Do::Enable(keys) => {
                // G1.30h: no country yet: the country dialog, which enables
                // them after it, instead of a refusal.
                let none = self.country.as_ref().is_some_and(|c| s(c, "country").is_empty());
                if none {
                    app.next_dialog = app.next_dialog.wrapping_add(1);
                    self.open_country(app.next_dialog, None, keys, true);
                } else {
                    let parent = crate::win_id(Win::Panel(WIN));
                    for k in keys {
                        app.run_then("interface.wifi.enable", json!({ "name": k }), enable_then(parent, &k));
                    }
                }
            }
            Do::Disable(keys) => each(app, &keys, "interface.wifi.disable"),
            Do::Reconnect(keys) => each(app, &keys, "interface.wifi.reconnect"),
            Do::Scan(k) => {
                app.run("interface.wifi.scan", json!({ "name": k }));
                self.radio = k;
                self.heard = None;
                self.tab = Tab::Networks;
            }
            Do::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
        }
    }

    /// The first line: the tabs, and the country every radio follows.
    fn head(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Radios, "Radios"),
                (Tab::Networks, "Networks"),
                (Tab::Registration, "Registration"),
                (Tab::Peers, "Peers"),
            ] {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                }
            }
            ui.separator();
            ui.label(tr_in(SCOPE, l, "Country"));
            if help::info_button(ui, Id::unique("wifi-country-help"), tr_in(SCOPE, l, "Country")).clicked() {
                self.help = Some(HelpView::new("interface.wifi.country", tr_in(SCOPE, l, "Country")));
            }
            let c = self.country.as_ref();
            let set = c.map(|c| s(c, "country")).unwrap_or_default();
            let v = ui.visuals().clone();
            if set.is_empty() {
                chip::chip(ui, tr_in(SCOPE, l, "no country"), chip::AMBER.tone(&v));
            } else {
                chip::chip(ui, &set, chip::neutral_tone(&v));
                // What the kernel applies, when it is not what was asked.
                let in_force = c.map(|c| s(c, "in_force")).unwrap_or_default();
                if !in_force.is_empty() && in_force != set {
                    let text = format!("{} {in_force}", tr_in(SCOPE, l, "in force:"));
                    chip::chip(ui, &text, chip::AMBER.tone(&v));
                }
            }
            if table::action(ui, tr_in(SCOPE, l, "Change…"), app.can().check("interface.wifi.country.set")) {
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.open_country(app.next_dialog, None, Vec::new(), false);
            }
        });
    }

    /// Open the country dialog as `id` over `parent` (`None`: this panel's
    /// window), or raise the open one; `enable`: radios it offers to turn
    /// on after it, ticked when `on`.
    pub(crate) fn open_country(&mut self, id: u64, parent: Option<Id>, enable: Vec<String>, on: bool) {
        if let Some(d) = &mut self.country_dialog {
            d.status.bring_to_front();
            d.enable_on |= on && !enable.is_empty();
            for n in enable {
                if !d.enable.contains(&n) {
                    d.enable.push(n);
                }
            }
            return;
        }
        let value = self.country.as_ref().map(|c| s(c, "country")).unwrap_or_default();
        self.country_dialog = Some(CountryDialog {
            id,
            value,
            status: Status::default(),
            parent,
            enable_on: on && !enable.is_empty(),
            enable,
            enabling: false,
        });
    }

    fn radios_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let all = self.rows.clone();
        let rows: Vec<Row> = all.iter().map(|r| row(r, l)).collect();
        let selection = self.table.selection(&rows);
        if selection.len() != 1 {
            self.monitor = None;
        }
        let picked: Vec<&Value> = all.iter().filter(|r| selection.contains(&s(r, "name"))).collect();
        let can = app.can();
        let some = || -> Result<(), String> {
            if picked.is_empty() {
                Err(tr_in(SCOPE, l, "Select one or more radios first").to_owned())
            } else {
                Ok(())
            }
        };
        let toggle = |to_disabled: bool| -> Result<(), String> {
            some()?;
            if picked.iter().any(|r| flag(r, "disabled") != to_disabled) {
                Ok(())
            } else if to_disabled {
                Err("Already disabled".to_owned())
            } else {
                Err("Already enabled".to_owned())
            }
        };
        let one = || -> Result<(), String> {
            if picked.len() == 1 {
                Ok(())
            } else {
                Err(tr_in(SCOPE, l, "Select one radio first").to_owned())
            }
        };
        let one_on = || -> Result<(), String> {
            one()?;
            if picked.iter().any(|r| flag(r, "disabled")) {
                Err(tr_in(SCOPE, l, "Enable the radio first: an off radio does not scan").to_owned())
            } else {
                Ok(())
            }
        };
        let any_on = || -> Result<(), String> {
            some()?;
            if picked.iter().any(|r| !flag(r, "disabled")) {
                Ok(())
            } else {
                Err(tr_in(SCOPE, l, "Select an enabled radio first").to_owned())
            }
        };
        let keys = || selection.to_vec();
        let first = || selection.as_slice().first().cloned().unwrap_or_default();
        let mut act = None;
        ui.horizontal(|ui| {
            if table::tool(ui, TABLE, Icon::Enable, "Enable", can.and("interface.wifi.enable", toggle(false))).clicked() {
                act = Some(Do::Enable(keys()));
            }
            if table::tool(ui, TABLE, Icon::Disable, "Disable", can.and("interface.wifi.disable", toggle(true))).clicked() {
                act = Some(Do::Disable(keys()));
            }
            if table::tool(ui, TABLE, Icon::Comment, "Comment", can.and("interface.wifi.set", one())).clicked() {
                act = Some(Do::Edit(first()));
            }
            ui.separator();
            if table::action(ui, tr_in(SCOPE, l, "Scan…"), can.and("interface.wifi.scan", one_on())) {
                act = Some(Do::Scan(first()));
            }
            if table::action(ui, tr_in(SCOPE, l, "Reconnect"), can.and("interface.wifi.reconnect", any_on())) {
                act = Some(Do::Reconnect(keys()));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        // Room under the table: the footer, and the monitor (11 lines, and
        // the words of a failure) of a single selected radio.
        let lines = if selection.len() == 1 { 16.0 } else { 3.0 };
        let footer_h = ui.spacing().interact_size.y * lines;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu {
                if let [one] = sel.as_slice() {
                    if ui.button(tr_in(SCOPE, l, "Open…")).clicked() {
                        act = Some(Do::Edit(one.clone()));
                    }
                    if ui.button(tr_in(SCOPE, l, "Scan…")).clicked() {
                        act = Some(Do::Scan(one.clone()));
                    }
                }
                if ui.button(tr_in(SCOPE, l, "Reconnect")).clicked() {
                    act = Some(Do::Reconnect(sel.to_vec()));
                }
                if ui.button(tr_in(SCOPE, l, "Copy")).clicked() {
                    act = Some(Do::Copy(sel.to_vec()));
                }
            }
        });
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Do::Edit(k));
        }
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "radios", chip::neutral_tone(&v)),
                (list::count(&all, "state", "connected"), "connected", chip::GREEN.tone(&v)),
                (list::count(&all, "state", "running"), "running", chip::GREEN.tone(&v)),
                (list::count(&all, "state", "searching"), "searching", chip::BLUE.tone(&v)),
                (list::count(&all, "state", "disabled"), "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        ui.separator();
        self.monitor_pane(ui, l);
        if let Some(a) = act {
            self.act(app, a, ui, &rows);
        }
    }

    /// The selected radio's `monitor`, under the table.
    fn monitor_pane(&mut self, ui: &mut Ui, l: Lang) {
        let Some(m) = self.monitor.clone() else {
            ui.weak(tr_in(SCOPE, l, "Select one radio to see its link."));
            return;
        };
        let mut info: Option<(&'static str, &'static str)> = None;
        let mut label = |ui: &mut Ui, text: &'static str, key: &'static str| {
            ui.horizontal(|ui| {
                ui.label(tr_in(SCOPE, l, text));
                if help::info_button(ui, Id::unique(("wifi-monitor-help", key)), tr_in(SCOPE, l, text)).clicked() {
                    info = Some((key, text));
                }
            });
        };
        let value = |ui: &mut Ui, text: String| {
            ui.monospace(if text.is_empty() { "—".to_owned() } else { text });
            ui.end_row();
        };
        let v = ui.visuals().clone();
        Grid::new("wifi-monitor").num_columns(2).striped(true).show(ui, |ui| {
            let state = s(&m, "state");
            label(ui, "State", "interface.wifi.state");
            ui.horizontal(|ui| {
                chip::chip(ui, tr_in(SCOPE, l, state_label(&state)), state_kind(&state).tone(&v));
                if let Some(secs) = m.get("uptime_secs").and_then(Value::as_u64) {
                    ui.monospace(format!("{} {}", tr_in(SCOPE, l, "for"), uptime_text(secs)));
                }
            });
            ui.end_row();
            label(ui, "SSID", "interface.wifi.ssid");
            value(ui, s(&m, "ssid"));
            label(ui, "BSSID", "interface.wifi.bssid");
            value(ui, s(&m, "bssid"));
            let ap = s(&m, "mode") == "ap";
            label(ui, "Security", "interface.wifi.security");
            let negotiated = match s(&m, "security").as_str() {
                "wpa3" => "WPA3 (SAE)",
                "wpa2" => "WPA2",
                "open" => "open",
                // G1.30a: an access point's setting.
                "auto" if ap => "WPA2 + WPA3",
                _ => "",
            };
            value(
                ui,
                match (negotiated, m.get("pmf").and_then(Value::as_bool)) {
                    ("", _) => String::new(),
                    (n, Some(true)) => format!("{}, {}", tr_in(SCOPE, l, n), tr_in(SCOPE, l, "management frames protected")),
                    (n, _) => tr_in(SCOPE, l, n).to_owned(),
                },
            );
            label(ui, "Channel", "interface.wifi.channel");
            value(
                ui,
                match (channel_text(&m), m.get("frequency").and_then(Value::as_u64)) {
                    (c, Some(mhz)) if !c.is_empty() => format!("{c} · {mhz} MHz"),
                    (c, _) => c,
                },
            );
            if ap {
                // G1.30a: an access point's width, radar check and clients.
                label(ui, "Width", "interface.wifi.width");
                value(
                    ui,
                    match (m.get("width").and_then(Value::as_u64), flag(&m, "auto_channel")) {
                        (Some(w), true) => format!("{w} MHz · {}", tr_in(SCOPE, l, "channel chosen automatically")),
                        (Some(w), false) => format!("{w} MHz"),
                        (None, _) => String::new(),
                    },
                );
                if let Some(secs) = m.get("radar_check_secs").and_then(Value::as_u64) {
                    label(ui, "Radar Check", "interface.wifi.radar");
                    value(ui, format!("{secs} s"));
                }
                label(ui, "Clients", "interface.wifi.clients");
                value(ui, s(&m, "clients"));
            } else {
                label(ui, "Signal", "interface.wifi.signal");
                match m.get("signal").and_then(Value::as_i64) {
                    Some(dbm) => {
                        chip::chip(ui, &format!("{dbm} dBm"), signal_kind(dbm).tone(&v));
                        ui.end_row();
                    }
                    None => value(ui, String::new()),
                }
                label(ui, "Rate", "interface.wifi.rate");
                value(ui, m.get("rate").and_then(Value::as_u64).map(|r| format!("{r} Mbps")).unwrap_or_default());
                label(ui, "Last Failure", "interface.wifi.failure");
                match m.pointer("/failure/code").and_then(Value::as_str) {
                    Some(code) => {
                        chip::chip(ui, tr_in(SCOPE, l, failure_label(code)), failure_kind(code).tone(&v));
                        ui.end_row();
                    }
                    None => value(ui, tr_in(SCOPE, l, "none").to_owned()),
                }
                label(ui, "Reconnects", "interface.wifi.reconnects");
                value(ui, s(&m, "reconnects"));
            }
            label(ui, "Country", "interface.wifi.country");
            let asked = s(&m, "country");
            let in_force = s(&m, "country_in_force");
            value(
                ui,
                if flag(&m, "self_managed") {
                    format!("{asked} · {}", tr_in(SCOPE, l, "this card follows its own firmware"))
                } else if in_force.is_empty() || in_force == asked {
                    asked
                } else {
                    format!("{asked} · {} {in_force}", tr_in(SCOPE, l, "in force:"))
                },
            );
            label(ui, "Radio", "interface.wifi.radio");
            value(ui, s(&m, "driver"));
        });
        // The engine's words, whole: they wrap under the grid instead of
        // stretching the window.
        for text in [m.pointer("/failure/text"), m.get("error")]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            ui.add(egui::Label::new(egui::RichText::new(text).weak()).wrap());
        }
        if let Some((key, text)) = info {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, text)));
        }
    }

    fn networks_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let names: Vec<String> = self.rows.iter().map(|r| s(r, "name")).collect();
        if !names.contains(&self.radio) {
            self.radio = names.first().cloned().unwrap_or_default();
            self.heard = None;
            self.scan.clear();
        }
        let all = self.networks().to_vec();
        let nets = self.scan.filter(&all);
        let rows: Vec<Row> = crate::wifi_scan::rows(&nets, self.scan.group, l);
        let selection = self.heard_table.selection(&rows);
        let can = app.can();
        let on = self.radio_row(&self.radio).is_some_and(|r| !flag(r, "disabled"));
        let radio_on = || -> Result<(), String> {
            if self.radio.is_empty() {
                Err(tr_in(SCOPE, l, "This router has no Wi-Fi radio").to_owned())
            } else if on {
                Ok(())
            } else {
                Err(tr_in(SCOPE, l, "Enable the radio first: an off radio does not scan").to_owned())
            }
        };
        let joinable = || -> Result<(), String> {
            let [one] = selection.as_slice() else {
                return Err(tr_in(SCOPE, l, "Select one network first").to_owned());
            };
            match nets.iter().find(|n| &s(n, "bssid") == one) {
                Some(n) if flag(n, "joinable") => Ok(()),
                Some(n) => Err(s(n, "why_not")),
                None => Err(tr_in(SCOPE, l, "Select one network first").to_owned()),
            }
        };
        let mut rescan = false;
        let mut connect: Option<String> = None;
        let mut picked_radio = None;
        // G1.30i: Auto runs only while this tab is drawn.
        let now = ui.input(|i| i.time);
        self.scan.drawn(now);
        let connected = self.radio_row(&self.radio).is_some_and(|r| s(r, "state") == "connected");
        if on && can.check("interface.wifi.scan").is_ok() && self.scan.auto_scan_due(now, connected) {
            rescan = true;
        }
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Radio"));
            egui::ComboBox::from_id_salt("wifi-scan-radio")
                .selected_text(self.radio.clone())
                .show_ui(ui, |ui| {
                    for n in &names {
                        if ui.selectable_label(*n == self.radio, n).clicked() {
                            picked_radio = Some(n.clone());
                        }
                    }
                });
            if table::action(ui, tr_in(SCOPE, l, "Rescan"), can.and("interface.wifi.scan", radio_on())) {
                rescan = true;
            }
            self.scan.auto_controls(ui, l, connected, &mut self.help);
            if table::action(ui, tr_in(SCOPE, l, "Connect…"), can.and("interface.wifi.set", joinable())) {
                connect = selection.as_slice().first().cloned();
            }
            ui.separator();
            let h = self.heard.as_ref().filter(|h| s(h, "name") == self.radio);
            let v = ui.visuals().clone();
            match h {
                Some(h) if flag(h, "scanning") => {
                    chip::chip(ui, tr_in(SCOPE, l, "scanning…"), chip::BLUE.tone(&v));
                }
                Some(h) if h.get("error").is_some_and(|e| !e.is_null()) => {
                    chip::chip(ui, tr_in(SCOPE, l, "scan failed"), chip::RED.tone(&v));
                    ui.label(s(h, "error"));
                }
                Some(h) => match h.get("age_secs").and_then(Value::as_u64) {
                    Some(age) => {
                        ui.weak(format!("{} {}", tr_in(SCOPE, l, "last scan:"), age_text(age)));
                    }
                    None => {
                        ui.weak(tr_in(SCOPE, l, "No scan yet: Rescan listens on every channel."));
                    }
                },
                None => {}
            }
            if self.scan.mode == crate::wifi_scan::Mode::List {
                table::find_field(ui, HEARD, &mut self.heard_table);
            }
        });
        self.scan.controls(ui, l, &all, &mut self.help);
        ui.separator();
        match self.scan.mode {
            crate::wifi_scan::Mode::List => {}
            crate::wifi_scan::Mode::Channels => {
                self.scan.channels(ui, l, &nets, &mut self.help);
                self.after_networks(app, picked_radio, rescan, None, &all);
                return;
            }
            crate::wifi_scan::Mode::Spectrum => {
                let radio = self.radio.clone();
                self.scan.spectrum(app, ui, l, &radio, &mut self.help);
                self.after_networks(app, picked_radio, rescan, None, &all);
                return;
            }
        }
        let footer_h = ui.spacing().interact_size.y * 4.2;
        let columns = &crate::wifi_scan::COLUMNS;
        let out = table::show(ui, HEARD, footer_h, &mut self.heard_table, columns, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu {
                if let [one] = sel.as_slice()
                    && ui.button(tr_in(SCOPE, l, "Connect…")).clicked()
                {
                    connect = Some(one.clone());
                }
                if ui.button(tr_in(SCOPE, l, "Copy")).clicked() {
                    let picked: Vec<&Row> = rows.iter().filter(|r| sel.contains(&r.key)).collect();
                    ui.ctx().copy_text(list::copy_rows(&picked));
                }
            }
        });
        if let Some(key) = out.help {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in("wifi_scan", l, title)));
        }
        if let Some(k) = out.opened {
            connect = Some(k);
        }
        let v = ui.visuals().clone();
        let count = |f: &dyn Fn(&Value) -> bool| nets.iter().filter(|n| f(n)).count();
        list::footer(
            ui,
            &[
                (nets.len(), "access points", chip::neutral_tone(&v)),
                (count(&|n| flag(n, "joinable")), "can be joined", chip::GREEN.tone(&v)),
                (count(&|n| s(n, "security") == "open"), "open", chip::AMBER.tone(&v)),
            ],
            l,
        );
        let heard = self.heard.clone();
        self.scan.suggestion(ui, l, heard.as_ref(), &mut self.help);
        self.after_networks(app, picked_radio, rescan, connect, &all);
    }

    /// What the Networks tab's bar asked for: another radio, a scan, a
    /// network to join.
    fn after_networks(
        &mut self,
        app: &mut CoreRouterUi,
        picked_radio: Option<String>,
        rescan: bool,
        connect: Option<String>,
        nets: &[Value],
    ) {
        if let Some(n) = picked_radio {
            self.radio = n;
            self.heard = None;
            self.scan.clear();
        }
        if rescan {
            app.run("interface.wifi.scan", json!({ "name": self.radio }));
        }
        if let Some(bssid) = connect {
            // Double click on what cannot be joined says why, in the log.
            match nets.iter().find(|n| s(n, "bssid") == bssid) {
                Some(n) if !flag(n, "joinable") => app.note(false, "interface.wifi.set", s(n, "why_not")),
                _ => self.connect(app, &bssid),
            }
        }
    }

    fn country_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let l = app.lang.labels;
        let Some(mut d) = self.country_dialog.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let can = app.can();
        let head = dialog::Head {
            id: wid,
            title: tr_in(SCOPE, l, "Wi-Fi Country"),
            dirty: false,
            pos: cascade(area, d.id),
            parent: d.parent.or(Some(crate::win_id(Win::Panel(WIN)))),
        };
        let mut info = false;
        let also = tr_in(SCOPE, l, "Also enable");
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("wifi-country").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr_in(SCOPE, l, "Country"));
                    info = help::info_button(ui, Id::unique("wifi-country-dialog-help"), tr_in(SCOPE, l, "Country")).clicked();
                });
                f.field(ui, "country", &mut d.value, "BR");
            });
            ui.weak(tr_in(SCOPE, l, "Two letters (ISO 3166-1): BR, US, DE. One country for every radio."));
            if !d.enable.is_empty() {
                ui.checkbox(&mut d.enable_on, format!("{also} {}", d.enable.join(", ")));
            }
            Footer::<()>::edit(false, can.check("interface.wifi.country.set"))
        });
        if info {
            self.help = Some(HelpView::new("interface.wifi.country", tr_in(SCOPE, l, "Country")));
        }
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                d.status.close_on_success = true;
                d.status.sent();
                d.enabling = false;
                app.run_then(
                    "interface.wifi.country.set",
                    json!({ "country": d.value.trim() }),
                    crate::panel::then(NAME, CountrySet(d.id)),
                );
            }
            _ => {}
        }
        self.country_dialog = Some(d);
    }
}

/// "3 s", "2 min".
fn age_text(secs: u64) -> String {
    if secs < 90 {
        format!("{secs} s")
    } else {
        format!("{} min", secs / 60)
    }
}

impl PanelState for WifiPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command("interface.wifi.list") {
            return Vec::new();
        }
        let mut out = vec![
            Query {
                key: "list",
                command: "interface.wifi.list",
                params: Value::Null,
            },
            Query {
                key: "country",
                command: "interface.wifi.country.get",
                params: Value::Null,
            },
        ];
        match self.tab {
            Tab::Radios => {
                if let [one] = self.selected().as_slice()
                    && app.has_command("interface.wifi.monitor")
                {
                    out.push(Query {
                        key: "monitor",
                        command: "interface.wifi.monitor",
                        params: json!({ "name": one }),
                    });
                }
            }
            Tab::Networks => {
                if !self.radio.is_empty() && app.has_command("interface.wifi.networks") {
                    out.push(Query {
                        key: "networks",
                        command: "interface.wifi.networks",
                        params: json!({ "name": self.radio }),
                    });
                }
                out.extend(self.scan.queries(&self.radio, app));
            }
            Tab::Registration => out.extend(self.clients.queries(app)),
            Tab::Peers => out.extend(self.peers.queries(app)),
        }
        out
    }

    fn arrived(&mut self, app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "list" => {
                self.rows = match value {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                if let Some(name) = self.edit_when_listed.take() {
                    self.edit(app, &name, &[]);
                }
            }
            "country" => self.country = Some(value),
            "monitor" => self.monitor = Some(value),
            "networks" => self.heard = Some(value),
            crate::wifi_clients::KEY => self.clients.arrived(value),
            crate::wifi_peers::KEY => self.peers.arrived(value),
            list_modal::PREVIEW => {
                if let Some(m) = &mut self.modal {
                    m.arrived(value);
                }
            }
            other => {
                self.scan.arrived(other, value);
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.head(app, ui, l);
        ui.separator();
        match self.tab {
            Tab::Radios => self.radios_tab(app, ui, l),
            Tab::Networks => self.networks_tab(app, ui, l),
            Tab::Registration => {
                if let Some(h) = self.clients.show(ui, l, &self.rows) {
                    self.help = Some(h);
                }
            }
            Tab::Peers => {
                let rows = self.rows.clone();
                if let Some(h) = self.peers.show(app, ui, l, &rows) {
                    self.help = Some(h);
                }
            }
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some(m) = &mut self.modal {
            let l = app.lang.labels;
            let page = &mut self.modal_page;
            let open = m.show_paged(app, ctx, area, &SPEC, &|p| match p {
                "security" => ["auto", "wpa3", "wpa2", "open"].map(str::to_owned).to_vec(),
                "band" => ["2ghz", "5ghz", "6ghz"].map(str::to_owned).to_vec(),
                "mode" => ["station", "ap", "station-bridge"].map(str::to_owned).to_vec(),
                "bridge_protocol" => ["multi-ap", "wds"].map(str::to_owned).to_vec(),
                "station_bridge" => ["no", "yes", "only"].map(str::to_owned).to_vec(),
                "width" => ["auto", "20", "40", "80", "160"].map(str::to_owned).to_vec(),
                _ => Vec::new(),
            }, &mut |ui| {
                ui.horizontal(|ui| {
                    for (i, label) in ["General", "Channel"].iter().enumerate() {
                        if ui.selectable_label(*page == i, tr_in(SCOPE, l, label)).clicked() {
                            *page = i;
                        }
                    }
                });
                ui.separator();
                Some(if *page == 1 { CHANNEL_PAGE } else { GENERAL_PAGE })
            });
            if !open {
                self.modal = None;
            }
        }
        self.country_dialog(app, ctx, area);
        let rows = self.rows.clone();
        self.peers.dialog(app, ctx, area, &rows);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>() {
            if let Some(m) = self.modal.as_mut().filter(|m| m.id == a.0)
                && m.replied(app, result)
            {
                self.modal = None;
            }
        } else if let Some(c) = then.downcast_ref::<CountrySet>()
            && let Some(d) = self.country_dialog.as_mut().filter(|d| d.id == c.0)
        {
            let mut close = d.status.replied(result);
            let wants = d.enable_on && !d.enabling && !d.enable.is_empty();
            // An empty field clears the country: nothing to enable with.
            let none = result.as_ref().is_ok_and(|r| r.get("country").is_none_or(Value::is_null));
            if wants && none {
                d.status.error = Some(
                    tr_in(SCOPE, app.lang.labels, "Type the country's two letters (BR, US, DE) to enable the radio")
                        .to_owned(),
                );
                close = false;
            } else if result.is_ok() && wants {
                // G1.30h: the country is in: now the radios that waited for it.
                d.enabling = true;
                close = false;
                for name in d.enable.clone() {
                    d.status.sent();
                    app.run_then(
                        "interface.wifi.enable",
                        json!({ "name": name }),
                        crate::panel::then(NAME, CountryEnabled(d.id)),
                    );
                }
            }
            if close {
                app.floats.forget(dialog_id(d.id));
                self.country_dialog = None;
            }
        } else if let Some(c) = then.downcast_ref::<CountryEnabled>()
            && let Some(d) = self.country_dialog.as_mut().filter(|d| d.id == c.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.country_dialog = None;
        } else if let Some(p) = then.downcast_ref::<crate::wifi_peers::PeerAdded>() {
            self.peers.replied(app, p.0, result);
        } else if let Some(e) = then.downcast_ref::<EnableTried>()
            && let Err(error) = result
            && is_no_country(error)
        {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            self.open_country(app.next_dialog, Some(e.parent), vec![e.name.clone()], true);
        }
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Radios => self.table.escape(),
            Tab::Networks => self.heard_table.escape(),
            Tab::Registration => self.clients.table.escape(),
            Tab::Peers => self.peers.table.escape(),
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (TABLE, &self.table),
            (HEARD, &self.heard_table),
            (crate::wifi_clients::TABLE, &self.clients.table),
            (crate::wifi_peers::TABLE, &self.peers.table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (TABLE, &mut self.table),
            (HEARD, &mut self.heard_table),
            (crate::wifi_clients::TABLE, &mut self.clients.table),
            (crate::wifi_peers::TABLE, &mut self.peers.table),
        ]
    }
}

/// The explanation keys of the window's columns and fields (tests: each
/// exists in both languages).
#[cfg(test)]
pub(crate) fn help_keys() -> Vec<&'static str> {
    COLUMNS
        .iter()
        .chain(&crate::wifi_scan::COLUMNS)
        .chain(&crate::wifi_clients::COLUMNS)
        .chain(&crate::wifi_peers::COLUMNS)
        .map(|c| c.help)
        .chain(FIELDS.iter().map(|f| f.help))
        .filter(|k| !k.is_empty())
        .collect()
}

/// The labels of the window's columns, fields, states and failures (tests:
/// each is in the Portuguese catalog).
#[cfg(test)]
pub(crate) fn labels() -> Vec<&'static str> {
    let states = [
        "connected", "searching", "connecting", "idle", "no-country", "blocked", "absent", "error", "disabled",
        "running", "starting", "radar-check", "no-ir", "failed",
    ];
    let failures = ["wrong-key", "not-found", "rejected", "no-answer", "other"];
    COLUMNS
        .iter()
        .map(|c| c.title)
        .chain(FIELDS.iter().map(|f| f.label))
        .chain(states.into_iter().map(state_label))
        .chain(failures.into_iter().map(failure_label))
        .filter(|l| *l != "Comment")
        .collect()
}


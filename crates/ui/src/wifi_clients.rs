//! Interfaces › Wi-Fi › Registration (G1.30a): the stations associated with
//! the router's access points, RouterOS v7's
//! `/interface/wifi/registration-table`. One row per client: the access
//! point, its MAC, how it joined (WPA3, WPA2, open; Wi-Fi 4 to 7), signal,
//! rates, time connected and the share of frames sent again. The engine
//! reads it all (`interface.wifi.registration-table.print`); this file only
//! draws.

use egui::Ui;
use serde_json::{Value, json};

use crate::CoreRouterUi;
use crate::chip::{Kind, cell};
use crate::help::HelpView;
use crate::i18n::{Lang, tr_in};
use crate::list;
use crate::panel::Query;
use crate::table::{self, Row, TableState, col};

/// The query key of the table.
pub(crate) const KEY: &str = "registration";
pub(crate) const TABLE: &str = "wifi-registration";
const SCOPE: &str = "wifi";

pub(crate) const COLUMNS: [table::Column; 9] = [
    col("Interface").help("interface.wifi.registration.interface"),
    col("MAC Address").help("interface.wifi.registration.mac"),
    col("Security").help("interface.wifi.registration.security"),
    col("Standard").help("interface.wifi.registration.standard"),
    col("Signal").help("interface.wifi.signal"),
    col("Tx Rate").help("interface.wifi.registration.rate"),
    col("Rx Rate").help("interface.wifi.registration.rate"),
    col("Uptime").help("interface.wifi.registration.uptime"),
    col("Retries").help("interface.wifi.registration.retries"),
];

/// The Registration tab.
#[derive(Default)]
pub(crate) struct ClientsView {
    pub(crate) rows: Vec<Value>,
    pub(crate) table: TableState,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_default()
}

fn row(r: &Value, l: Lang) -> Row {
    let mac = s(r, "mac_address");
    let security = s(r, "security");
    let sec_kind = match security.as_str() {
        "open" => Kind::Amber,
        "wpa3" => Kind::Green,
        _ => Kind::Neutral,
    };
    let mut sec = vec![(security.to_ascii_uppercase(), sec_kind)];
    if r.get("authorized").and_then(Value::as_bool) == Some(false) {
        sec.push((tr_in(SCOPE, l, "not authorized").to_owned(), Kind::Amber));
    }
    let sec: Vec<(&str, Kind)> = sec.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    let rate = |k: &str| {
        r.pointer(&format!("/{k}/text"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let retries = r
        .get("retry_percent")
        .and_then(Value::as_f64)
        .map(|p| {
            let kind = if p >= 20.0 {
                Kind::Red
            } else if p >= 10.0 {
                Kind::Amber
            } else {
                Kind::Neutral
            };
            cell("", &[(&format!("{p:.1} %"), kind)])
        })
        .unwrap_or_default();
    Row {
        key: format!("{}/{mac}", s(r, "interface")),
        cells: vec![
            cell("", &[(&s(r, "interface"), Kind::Neutral)]),
            mac,
            if security.is_empty() { String::new() } else { cell("", &sec) },
            s(r, "standard"),
            match r.get("signal").and_then(Value::as_i64) {
                Some(dbm) => cell("", &[(&format!("{dbm} dBm"), crate::wifi::signal_kind(dbm))]),
                None => String::new(),
            },
            rate("tx_rate"),
            rate("rx_rate"),
            r.get("uptime_secs").and_then(Value::as_u64).map(crate::wifi::uptime_text).unwrap_or_default(),
            retries,
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl ClientsView {
    pub(crate) fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.has_command("interface.wifi.registration-table.print") {
            return Vec::new();
        }
        vec![Query {
            key: KEY,
            command: "interface.wifi.registration-table.print",
            params: json!({}),
        }]
    }

    pub(crate) fn arrived(&mut self, value: Value) {
        self.rows = match value {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
    }

    /// Draw the tab; the explanation asked for, if any. `radios`: the
    /// Radios tab's rows (to say when no radio is an access point).
    pub(crate) fn show(&mut self, ui: &mut Ui, l: Lang, radios: &[Value]) -> Option<HelpView> {
        let aps = radios.iter().filter(|r| s(r, "mode") == "ap").count();
        if aps == 0 {
            ui.weak(tr_in(
                SCOPE,
                l,
                "No radio is an access point: set Mode to ap on a radio (Radios, double click) to see its clients here.",
            ));
            return None;
        }
        let rows: Vec<Row> = self.rows.iter().map(|r| row(r, l)).collect();
        ui.horizontal(|ui| {
            table::find_field(ui, TABLE, &mut self.table);
        });
        let footer_h = ui.spacing().interact_size.y * 2.0;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |_, _| {});
        let v = ui.visuals().clone();
        let wpa3 = list::count(&self.rows, "security", "wpa3");
        list::footer(
            ui,
            &[
                (self.rows.len(), "clients", crate::chip::neutral_tone(&v)),
                (wpa3, "WPA3", crate::chip::GREEN.tone(&v)),
                (list::count(&self.rows, "security", "open"), "open", crate::chip::AMBER.tone(&v)),
            ],
            l,
        );
        out.help.map(|key| {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            HelpView::new(key, tr_in(SCOPE, l, title))
        })
    }
}

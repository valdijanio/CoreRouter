//! Interfaces › Wi-Fi › Peers (G1.30m): the station-bridges of other
//! routers that this router's access points take. One row per registered
//! peer: its link's name (an interface of its own), the access point, the
//! MAC, whether it is up, signal, rates, time up and where its link goes
//! (bridge or bond). "Add Peer…" registers one
//! (`interface.wifi.peer.add`), − removes it. The engine checks and keeps
//! everything (`interface.wifi.peer.print`); this file only draws.

use egui::{Grid, Id, Ui};
use serde_json::{Value, json};

use crate::chip::{Kind, cell};
use crate::dialog::{self, Footer, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list;
use crate::panel::Query;
use crate::table::{self, Icon, Row, TableState, col};
use crate::{CoreRouterUi, Win};

/// The query key of the table.
pub(crate) const KEY: &str = "peers";
pub(crate) const TABLE: &str = "wifi-peers";
const SCOPE: &str = "wifi";

pub(crate) const COLUMNS: [table::Column; 9] = [
    col("Name").help("interface.wifi.peer.name"),
    col("Radio").help("interface.wifi.peer.radio"),
    col("MAC Address").help("interface.wifi.peer.mac"),
    col("State").help("interface.wifi.peer.state"),
    col("Signal").help("interface.wifi.signal"),
    col("Rate").help("interface.wifi.registration.rate"),
    col("Uptime").help("interface.wifi.registration.uptime"),
    col("Link").help("interface.wifi.peer.link"),
    col("Comment"),
];

/// The "Add Peer" dialog.
pub(crate) struct AddPeer {
    pub id: u64,
    pub radio: String,
    pub name: String,
    pub mac: String,
    pub comment: String,
    pub status: Status,
}

/// The reply of the dialog's command.
pub(crate) struct PeerAdded(pub u64);

/// The Peers tab.
#[derive(Default)]
pub(crate) struct PeersView {
    pub(crate) rows: Vec<Value>,
    pub(crate) table: TableState,
    pub(crate) add: Option<AddPeer>,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_default()
}

fn row(r: &Value, l: Lang) -> Row {
    let state = s(r, "state");
    let kind = match state.as_str() {
        "up" => Kind::Green,
        "away" => Kind::Amber,
        _ => Kind::Neutral,
    };
    let label = match state.as_str() {
        "up" => "up",
        "away" => "away",
        _ => "disabled",
    };
    let link = match (s(r, "bridge"), s(r, "bond")) {
        (b, _) if !b.is_empty() => format!("bridge {b}"),
        (_, b) if !b.is_empty() => format!("bond {b}"),
        _ => String::new(),
    };
    Row {
        key: s(r, "name"),
        cells: vec![
            cell("", &[(&s(r, "name"), Kind::Neutral)]),
            s(r, "radio"),
            s(r, "mac_address"),
            cell("", &[(tr_in(SCOPE, l, label), kind)]),
            match r.get("signal").and_then(Value::as_i64) {
                Some(dbm) => cell("", &[(&format!("{dbm} dBm"), crate::wifi::signal_kind(dbm))]),
                None => String::new(),
            },
            r.pointer("/tx_rate/text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            r.get("uptime_secs")
                .and_then(Value::as_u64)
                .map(crate::wifi::uptime_text)
                .unwrap_or_default(),
            link,
            s(r, "comment"),
        ],
        dimmed: state == "disabled",
        section: false,
        tint: None,
    }
}

impl PeersView {
    pub(crate) fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.has_command("interface.wifi.peer.print") {
            return Vec::new();
        }
        vec![Query {
            key: KEY,
            command: "interface.wifi.peer.print",
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
    /// Radios tab's rows (the access points a peer may join).
    pub(crate) fn show(
        &mut self,
        app: &mut CoreRouterUi,
        ui: &mut Ui,
        l: Lang,
        radios: &[Value],
    ) -> Option<HelpView> {
        let aps: Vec<String> = radios
            .iter()
            .filter(|r| s(r, "mode") == "ap")
            .map(|r| s(r, "name"))
            .collect();
        let rows: Vec<Row> = self.rows.iter().map(|r| row(r, l)).collect();
        let selection = self.table.selection(&rows).to_vec();
        let can = app.can();
        let mut help = None;
        ui.horizontal(|ui| {
            let add_ok = if aps.is_empty() {
                Err(tr_in(SCOPE, l, "No radio is an access point: set Mode to ap first").to_owned())
            } else {
                Ok(())
            };
            if table::tool(ui, TABLE, Icon::Add, "Add Peer…", can.and("interface.wifi.peer.add", add_ok)).clicked() {
                app.next_dialog = app.next_dialog.wrapping_add(1);
                self.add = Some(AddPeer {
                    id: app.next_dialog,
                    radio: aps.first().cloned().unwrap_or_default(),
                    name: (1..)
                        .map(|i| format!("peer{i}"))
                        .find(|n| !app.interface_names(None).contains(n))
                        .unwrap_or_default(),
                    mac: String::new(),
                    comment: String::new(),
                    status: Status::default(),
                });
            }
            let some = if selection.is_empty() {
                Err(tr_in(SCOPE, l, "Select one or more peers first").to_owned())
            } else {
                Ok(())
            };
            if table::tool(ui, TABLE, Icon::Remove, "Remove", can.and("interface.wifi.peer.remove", some)).clicked() {
                for k in &selection {
                    app.run("interface.wifi.peer.remove", json!({ "name": k }));
                }
            }
            if help::info_button(ui, Id::unique("wifi-peers-help"), tr_in(SCOPE, l, "Peers")).clicked() {
                help = Some(HelpView::new("interface.wifi.peers", tr_in(SCOPE, l, "Peers")));
            }
            table::find_field(ui, TABLE, &mut self.table);
        });
        let footer_h = ui.spacing().interact_size.y * 2.0;
        let out = table::show(ui, TABLE, footer_h, &mut self.table, &COLUMNS, &rows, |_, _| {});
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (self.rows.len(), "peers", crate::chip::neutral_tone(&v)),
                (list::count(&self.rows, "state", "up"), "up", crate::chip::GREEN.tone(&v)),
                (list::count(&self.rows, "state", "away"), "away", crate::chip::AMBER.tone(&v)),
            ],
            l,
        );
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        help
    }

    /// The "Add Peer" dialog, while open.
    pub(crate) fn dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect, radios: &[Value]) {
        let l = app.lang.labels;
        let Some(mut d) = self.add.take() else {
            return;
        };
        let aps: Vec<String> = radios
            .iter()
            .filter(|r| s(r, "mode") == "ap")
            .map(|r| s(r, "name"))
            .collect();
        let wid = dialog_id(d.id);
        let can = app.can();
        let head = dialog::Head {
            id: wid,
            title: tr_in(SCOPE, l, "Add Peer"),
            dirty: false,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(crate::wifi::WIN))),
        };
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("wifi-peer-add").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label(tr_in(SCOPE, l, "Radio"));
                egui::ComboBox::from_id_salt("wifi-peer-radio")
                    .selected_text(d.radio.as_str())
                    .show_ui(ui, |ui| {
                        for a in &aps {
                            ui.selectable_value(&mut d.radio, a.clone(), a.as_str());
                        }
                    });
                ui.end_row();
                f.text(ui, tr_in(SCOPE, l, "Name"), "name", &mut d.name, "peer1");
                f.text(ui, tr_in(SCOPE, l, "MAC Address"), "mac_address", &mut d.mac, "02:00:00:00:00:01");
                f.text(ui, tr_in(SCOPE, l, "Comment"), "comment", &mut d.comment, "");
            });
            ui.weak(tr_in(
                SCOPE,
                l,
                "The other router's station-bridge radio: its MAC is in its Wi-Fi window. Only registered peers get four addresses.",
            ));
            Footer::<()>::edit(false, can.check("interface.wifi.peer.add"))
        });
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(
                    "interface.wifi.peer.add",
                    json!({"radio": d.radio, "name": d.name.trim(), "mac_address": d.mac.trim(),
                           "comment": d.comment}),
                    crate::panel::then(crate::wifi::NAME, PeerAdded(d.id)),
                );
            }
            _ => {}
        }
        self.add = Some(d);
    }

    /// The reply of "Add Peer": an error stays in the dialog.
    pub(crate) fn replied(&mut self, app: &mut CoreRouterUi, id: u64, result: &Result<Value, String>) {
        if let Some(d) = self.add.as_mut().filter(|d| d.id == id)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.add = None;
        }
        app.cache.refreshed_at = None;
    }
}

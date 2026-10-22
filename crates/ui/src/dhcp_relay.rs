//! IP › DHCP Relay (G4.2b): the relays, one row each with its servers,
//! whether it adds option 82, its status and what it passed up and down.
//! `ip.dhcp-relay.*` decides; this only shows and sends. A panel.

use egui::{Grid, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dhcp-relay";
pub(crate) const WIN: &str = "dhcp-relay";
const TABLE: &str = "dhcp-relay";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DHCP Relay",
        size: [820.0, 260.0],
        escape: true,
    }],
    new: || Box::new(RelayPanel::default()),
};

const COLUMNS: [table::Column; 8] = [
    col("Name"),
    col("Interface"),
    col("DHCP Servers"),
    col("Local Address"),
    col("Status"),
    num("Requests"),
    num("Replies"),
    comment(),
];

/// Form fields: (key, label, hint, is a yes/no).
const FIELDS: [(&str, &str, &str, bool); 8] = [
    ("name", "Name", "relay1", false),
    ("interface", "Interface", "vlan20 (the clients' side)", false),
    ("dhcp_server", "DHCP Servers", "10.0.0.2, 10.0.0.3", false),
    ("local_address", "Local Address", "the interface's (giaddr)", false),
    ("add_relay_info", "Add Relay Info", "", true),
    ("relay_info_remote_id", "Relay Info Remote ID", "the client's MAC", false),
    ("disabled", "Disabled", "", true),
    ("comment", "Comment", "", false),
];

#[derive(Default)]
pub(crate) struct RelayPanel {
    pub(crate) relays: Vec<Value>,
    table: TableState,
    pub(crate) dialog: Option<RelayDialog>,
}

pub(crate) struct RelayDialog {
    id: u64,
    item: Option<String>,
    pub(crate) values: Vec<String>,
    orig: Vec<String>,
    status: Status,
}

struct Reply(u64);

pub(crate) fn row(r: &Value) -> Row {
    let status = text(r, "status");
    let kind = match status.as_str() {
        "running" => Kind::Green,
        "disabled" | "starting" => Kind::Neutral,
        _ => Kind::Red,
    };
    let mut chips = vec![(status.as_str(), kind)];
    if r.get("add_relay_info").and_then(Value::as_bool) == Some(true) {
        chips.push(("option 82", Kind::Blue));
    }
    Row {
        key: text(r, "name"),
        cells: vec![
            text(r, "name"),
            text(r, "interface"),
            text(r, "dhcp_server"),
            {
                let l = text(r, "local_address");
                if l.is_empty() { text(r, "giaddr") } else { l }
            },
            chip::cell("", &chips),
            text(r, "requests"),
            text(r, "replies"),
            text(r, "comment"),
        ],
        dimmed: r.get("disabled").and_then(Value::as_bool) == Some(true),
        section: false,
        tint: None,
    }
}

fn values_of(r: Option<&Value>) -> Vec<String> {
    FIELDS
        .iter()
        .map(|(k, _, _, yn)| match (r, yn) {
            (Some(r), true) => if r.get(*k).and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.into(),
            (Some(r), false) => text(r, k),
            (None, true) => "no".into(),
            (None, false) => String::new(),
        })
        .collect()
}

impl PanelState for RelayPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if (app.open.contains(&Win::Panel(WIN)) || self.dialog.is_some()) && app.has_command("ip.dhcp-relay.print") {
            vec![Query {
                key: "relays",
                command: "ip.dhcp-relay.print",
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "relays"
            && let Value::Array(a) = value
        {
            self.relays = a;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let rows: Vec<Row> = self.relays.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let can = app.can();
        let mut new = false;
        let mut remove = false;
        ui.horizontal(|ui| {
            new = table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.dhcp-relay.add")).clicked();
            let picked = if selection.is_empty() {
                Err("Select a relay first".to_owned())
            } else {
                Ok(())
            };
            remove = table::tool(ui, TABLE, Icon::Remove, "Remove", can.and("ip.dhcp-relay.remove", picked))
                .clicked();
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, "Add DHCP Relay…", can.check("ip.dhcp-relay.add"))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for k in &selection {
                app.run("ip.dhcp-relay.remove", json!({ "id": k }));
            }
        }
        let key = out.opened.or(out.comment).or_else(|| {
            matches!(out.shortcut, Some(Shortcut::Open))
                .then(|| selection.first().cloned())
                .flatten()
        });
        let opened = key.and_then(|k| self.relays.iter().find(|r| text(r, "name") == k).cloned());
        if (new || opened.is_some()) && self.dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let values = values_of(opened.as_ref());
            self.dialog = Some(RelayDialog {
                id: app.next_dialog,
                item: opened.as_ref().map(|r| text(r, "name")),
                orig: values.clone(),
                values,
                status: Status::default(),
            });
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(n) => format!("DHCP Relay <{n}>"),
            None => "New DHCP Relay".to_owned(),
        };
        let cmd = if d.item.is_some() { "ip.dhcp-relay.set" } else { "ip.dhcp-relay.add" };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: d.values != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let mut values = std::mem::take(&mut d.values);
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("dhcp-relay-fields").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                for ((key, label, hint, yn), v) in FIELDS.iter().zip(values.iter_mut()) {
                    if *yn {
                        ui.label(*label);
                        let mut on = v == "yes";
                        if ui.checkbox(&mut on, "").changed() {
                            *v = if on { "yes" } else { "no" }.into();
                        }
                        ui.end_row();
                    } else {
                        f.text(ui, label, key, v, hint);
                    }
                }
            });
            Footer::<()>::edit(false, can.check(cmd))
        });
        d.values = values;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = Map::new();
                if let Some(item) = &d.item {
                    p.insert("id".into(), json!(item));
                }
                for (((key, _, _, yn), v), old) in FIELDS.iter().zip(&d.values).zip(&d.orig) {
                    if (d.item.is_some() && v == old) || (d.item.is_none() && v.trim().is_empty()) {
                        continue;
                    }
                    p.insert((*key).into(), if *yn { json!(v == "yes") } else { json!(v.trim()) });
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, Value::Object(p), crate::panel::then(NAME, Reply(d.id)));
            }
            _ => {}
        }
        self.dialog = Some(d);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>()
            && let Some(d) = self.dialog.as_mut().filter(|d| d.id == r.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.dialog = None;
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

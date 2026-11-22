//! IP › DNS TSIG Keys (G4.1c-3): the TSIG keys (RFC 8945) a DHCP server
//! signs its RFC 2136 updates with. One row per key (algorithm, the zones
//! that let it update); New makes one (a random secret unless one is
//! pasted); the secret shows once after New, or on Show Secret, with Copy,
//! to paste into Kea's `tsig-keys` or ISC dhcpd's `key`.
//!
//! The engine validates (`ip.dns.tsig-key.*`); the window only shows and
//! sends. A panel (`panel.rs`).

use egui::{Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-tsig";
pub(crate) const WIN: &str = "dns-tsig";
pub(crate) const TABLE: &str = "dns-tsig";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS TSIG Keys",
        size: [560.0, 260.0],
        escape: true,
    }],
    new: || Box::new(TsigPanel::default()),
};

const COLUMNS: [table::Column; 4] = [col("Name"), col("Algorithm"), col("Zones"), comment()];

#[derive(Default)]
pub(crate) struct TsigPanel {
    pub(crate) keys: Vec<Value>,
    pub(crate) table: TableState,
    pub(crate) dialog: Option<NewKey>,
    /// A secret to show: (key name, base64).
    pub(crate) secret: Option<(String, String)>,
}

/// The New dialog.
pub(crate) struct NewKey {
    pub id: u64,
    pub name: String,
    pub algorithm: String,
    /// Blank: the router makes a random one.
    pub secret: String,
    pub status: Status,
}

enum Reply {
    Added { id: u64 },
    Secret { name: String },
}

fn row(r: &Value) -> Row {
    let zones = r
        .get("zones")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    Row {
        key: text(r, "name"),
        cells: vec![text(r, "name"), text(r, "algorithm"), zones, text(r, "comment")],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl PanelState for TsigPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) && app.has_command("ip.dns.tsig-key.print") {
            vec![Query {
                key: "keys",
                command: "ip.dns.tsig-key.print",
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "keys"
            && let Value::Array(a) = value
        {
            self.keys = a;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let rows: Vec<Row> = self.keys.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let can = app.can();
        let mut remove = false;
        let mut show = false;
        let mut new = false;
        ui.horizontal(|ui| {
            new = table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.dns.tsig-key.add")).clicked();
            let picked = if selection.is_empty() {
                Err("Select a key first".to_owned())
            } else {
                Ok(())
            };
            remove = table::tool(ui, TABLE, Icon::Remove, "Remove", can.and("ip.dns.tsig-key.remove", picked.clone()))
                .clicked();
            ui.separator();
            let one = if selection.len() == 1 {
                can.check("ip.dns.tsig-key.print")
            } else {
                Err("Select one key".to_owned())
            };
            show = action(ui, "Show Secret", one);
            table::find_field(ui, TABLE, &mut self.table);
        });
        if let Some((name, secret)) = self.secret.clone() {
            ui.horizontal(|ui| {
                ui.label(format!("{name}:"));
                ui.label(RichText::new(&secret).monospace());
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(secret.clone());
                }
                if ui.small_button("Hide").clicked() {
                    self.secret = None;
                }
            });
        }
        ui.separator();
        let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, "Add TSIG Key…", can.check("ip.dns.tsig-key.add"))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if new && self.dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            self.dialog = Some(NewKey {
                id: app.next_dialog,
                name: String::new(),
                algorithm: "hmac-sha256".into(),
                secret: String::new(),
                status: Status::default(),
            });
        }
        if remove {
            for name in &selection {
                app.run("ip.dns.tsig-key.remove", json!({ "id": name }));
            }
        }
        if show && let Some(name) = selection.first() {
            app.run_then(
                "ip.dns.tsig-key.print",
                json!({"show_secret": true}),
                crate::panel::then(NAME, Reply::Secret { name: name.clone() }),
            );
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let can = app.can();
        let head = Head {
            id: wid,
            title: "New TSIG Key",
            dirty: !d.name.is_empty() || !d.secret.is_empty(),
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let mut form_name = std::mem::take(&mut d.name);
        let mut form_alg = std::mem::take(&mut d.algorithm);
        let mut form_secret = std::mem::take(&mut d.secret);
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            body(ui, f, &mut form_name, &mut form_alg, &mut form_secret, &can)
        });
        d.name = form_name;
        d.algorithm = form_alg;
        d.secret = form_secret;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = json!({"name": d.name.trim(), "algorithm": d.algorithm});
                if !d.secret.trim().is_empty()
                    && let Some(o) = p.as_object_mut()
                {
                    o.insert("secret".into(), json!(d.secret.trim()));
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(
                    "ip.dns.tsig-key.add",
                    p,
                    crate::panel::then(NAME, Reply::Added { id: d.id }),
                );
            }
            _ => {}
        }
        self.dialog = Some(d);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        match *r {
            Reply::Added { id } => {
                if let Some(d) = self.dialog.as_mut().filter(|d| d.id == id)
                    && d.status.replied(result)
                {
                    app.floats.forget(dialog_id(id));
                    self.dialog = None;
                }
                if let Ok(v) = result {
                    // RFC 8945 keys are shared: shown once now, to copy.
                    self.secret = Some((text(v, "name"), text(v, "secret")));
                }
            }
            Reply::Secret { name } => {
                if let Ok(Value::Array(rows)) = result {
                    self.secret = rows
                        .iter()
                        .find(|k| text(k, "name") == name)
                        .map(|k| (name.clone(), text(k, "secret")));
                }
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

fn body(ui: &mut Ui, f: &Form, name: &mut String, alg: &mut String, secret: &mut String, can: &Avail) -> Footer<()> {
    Grid::new("dns-tsig-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(ui, "Name", "name", name, "dhcp-ddns");
            ui.label("Algorithm");
            egui::ComboBox::from_id_salt(f.window().with("algorithm"))
                .selected_text(alg.as_str())
                .show_ui(ui, |ui| {
                    for a in ["hmac-sha256", "hmac-sha384", "hmac-sha512"] {
                        ui.selectable_value(alg, a.to_owned(), a);
                    }
                });
            ui.end_row();
            f.text(ui, "Secret", "secret", secret, "blank: a random one");
        });
    ui.label(
        RichText::new("Give the same name and secret to the DHCP server (Kea: tsig-keys).")
            .weak()
            .small(),
    );
    Footer::edit(false, can.check("ip.dns.tsig-key.add"))
}

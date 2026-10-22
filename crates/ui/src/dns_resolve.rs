//! IP › DNS Resolve (G4.1d), the GUI of RouterOS `:resolve`: a name (or an
//! address, for its PTR), a record type and an optional server; Resolve
//! starts `ip.dns.resolve` (a task: the router asks without holding its
//! lock) and the answers come in with the next refreshes, one row per
//! type, with where they came from (cache, stale, the server) and how
//! long they took. Also opened from DNS Cache.

use egui::{Grid, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::dhcp_client::text;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Row, TableState, action, col, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-resolve";
pub(crate) const WIN: &str = "dns-resolve";
pub(crate) const TABLE: &str = "dns-resolve";
const RESOLVE: &str = "ip.dns.resolve";
const TYPES: [&str; 13] = [
    "", "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA", "HTTPS", "SVCB",
];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Resolve",
        size: [620.0, 260.0],
        escape: true,
    }],
    new: || Box::new(ResolvePanel::default()),
};

const COLUMNS: [table::Column; 5] = [
    col("Type"),
    col("Answer"),
    col("Source"),
    num("TTL"),
    num("ms"),
];

#[derive(Default)]
pub(crate) struct ResolvePanel {
    pub(crate) name: String,
    /// "" = A and AAAA (PTR for an address).
    pub(crate) rtype: String,
    pub(crate) server: String,
    /// The task being read.
    pub(crate) task: Option<u64>,
    pub(crate) done: bool,
    pub(crate) events: Vec<Value>,
    pub(crate) error: Option<String>,
    pub(crate) table: TableState,
}

/// `ip.dns.resolve` params from what was typed.
pub(crate) fn params(name: &str, rtype: &str, server: &str) -> Value {
    let mut p = Map::new();
    p.insert("name".into(), json!(name.trim()));
    if !rtype.is_empty() {
        p.insert("type".into(), json!(rtype));
    }
    if !server.trim().is_empty() {
        p.insert("server".into(), json!(server.trim()));
    }
    Value::Object(p)
}

pub(crate) fn row(i: usize, e: &Value) -> Row {
    let answer = match e.get("error").and_then(Value::as_str) {
        Some(err) => format!("failed: {err}"),
        None => {
            let rcode = text(e, "rcode");
            let prefix = format!("{} ", text(e, "type"));
            let recs: Vec<String> = e
                .get("records")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|r| r.strip_prefix(prefix.as_str()).unwrap_or(r).to_owned())
                        .collect()
                })
                .unwrap_or_default();
            match (rcode.as_str(), recs.is_empty()) {
                ("NXDOMAIN", _) => "NXDOMAIN (no such name)".to_owned(),
                (_, true) => "(no records of this type)".to_owned(),
                _ => recs.join(", "),
            }
        }
    };
    Row {
        key: i.to_string(),
        cells: vec![
            text(e, "type"),
            answer,
            text(e, "source"),
            e.get("ttl").and_then(Value::as_u64).map_or("–".into(), |t| t.to_string()),
            text(e, "ms"),
        ],
        dimmed: e.get("error").is_some(),
        section: false,
        tint: None,
    }
}

impl PanelState for ResolvePanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        match self.task {
            Some(id) if !self.done && app.open.contains(&Win::Panel(WIN)) => vec![Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 0}),
            }],
            _ => Vec::new(),
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key != "poll" {
            return;
        }
        if let Some(ev) = value.get("events").and_then(Value::as_array) {
            self.events = ev.clone();
        }
        if value.get("done").and_then(Value::as_bool) == Some(true) {
            self.done = true;
            if self.events.is_empty() {
                self.error = value
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let can = app.can();
        let mut go = false;
        Grid::new("dns-resolve-fields")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name").on_hover_text("A name, or an address (its PTR name).");
                let r = ui.add(TextEdit::singleline(&mut self.name).hint_text("example.com").desired_width(260.0));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
                ui.end_row();
                ui.label("Type");
                egui::ComboBox::from_id_salt("dns-resolve-type")
                    .selected_text(if self.rtype.is_empty() { "A + AAAA" } else { self.rtype.as_str() })
                    .show_ui(ui, |ui| {
                        for t in TYPES {
                            let label = if t.is_empty() { "A + AAAA" } else { t };
                            ui.selectable_value(&mut self.rtype, t.to_owned(), label);
                        }
                    });
                ui.end_row();
                ui.label("Server")
                    .on_hover_text("Ask only this server, without the cache. Empty: the router's resolver.");
                ui.add(TextEdit::singleline(&mut self.server).hint_text("(the router's resolver)").desired_width(160.0));
                ui.end_row();
            });
        ui.horizontal(|ui| {
            let ok = if self.name.trim().is_empty() {
                Err("Type a name first".to_owned())
            } else if self.task.is_some() && !self.done {
                Err("Resolving…".to_owned())
            } else {
                can.check(RESOLVE)
            };
            if action(ui, "Resolve", ok) {
                go = true;
            }
            if self.task.is_some() && !self.done {
                ui.spinner();
            }
        });
        if go && !self.name.trim().is_empty() && can.check(RESOLVE).is_ok() {
            self.events.clear();
            self.error = None;
            self.done = false;
            self.task = None;
            app.run_then(
                RESOLVE,
                params(&self.name, &self.rtype, &self.server),
                crate::panel::then(NAME, ()),
            );
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        ui.separator();
        let rows: Vec<Row> = self.events.iter().enumerate().map(|(i, e)| row(i, e)).collect();
        table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |_, _| {});
        if rows.is_empty() && self.task.is_none() {
            ui.label(
                RichText::new("Answers come from the cache, the servers (or DoH), or the server given.")
                    .weak()
                    .small(),
            );
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, _then: PanelThen, result: &Result<Value, String>) {
        match result {
            Ok(v) => self.task = v.get("id").and_then(Value::as_u64),
            Err(e) => {
                self.error = Some(e.clone());
                self.done = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_and_rows() {
        assert_eq!(params(" example.com ", "", ""), json!({"name": "example.com"}));
        assert_eq!(
            params("1.1.1.1", "PTR", "9.9.9.9"),
            json!({"name": "1.1.1.1", "type": "PTR", "server": "9.9.9.9"})
        );
        let r = row(0, &json!({"type": "A", "rcode": "NOERROR", "records": ["CNAME edge.example", "A 192.0.2.7"],
            "source": "cache", "ttl": 30, "ms": 0}));
        assert_eq!(r.cells[1], "CNAME edge.example, 192.0.2.7");
        let r = row(1, &json!({"type": "AAAA", "error": "SERVFAIL", "ms": 12}));
        assert!(r.dimmed && r.cells[1].starts_with("failed"));
        assert_eq!(r.cells[3], "–");
        let r = row(2, &json!({"type": "A", "rcode": "NXDOMAIN", "records": []}));
        assert!(r.cells[1].starts_with("NXDOMAIN"));
    }
}

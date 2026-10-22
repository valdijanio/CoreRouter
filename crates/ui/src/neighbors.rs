//! IP › Neighbors: routers heard by CRDP, LLDP and MNDP (`ip.neighbor.list`)
//! and the discovery settings (`ip.neighbor.discovery.set`).

use std::collections::BTreeSet;

use egui::{TextEdit, Ui};
use serde_json::{Value, json};

use crate::table::{self, Menu, Row, col, num};
use crate::{CoreRouterUi, form_number, value_text};

pub(crate) const TABLE: &str = "neighbors";

const COLUMNS: [table::Column; 8] = [
    col("Interface"),
    col("Protocol"),
    col("Address"),
    col("MAC Address"),
    col("Identity"),
    col("Version"),
    col("Board"),
    num("Uptime"),
];

/// Edits of the settings form; `None` until loaded from the router.
#[derive(Default)]
pub(crate) struct DiscoveryForm {
    pub loaded: Option<Loaded>,
}

pub(crate) struct Loaded {
    pub enabled: bool,
    pub interfaces: BTreeSet<String>,
    pub interval: String,
}

/// RouterOS style: `3d04:05:06`, `04:05:06`.
pub fn uptime_text(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d{h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// One `ip.neighbor.list` row as table cells, in `COLUMNS` order.
pub(crate) fn neighbor_row(r: &Value) -> Row {
    let get = |k: &str| r.get(k).map(value_text).unwrap_or_default();
    let uptime = r
        .get("uptime_secs")
        .and_then(Value::as_u64)
        .map(uptime_text)
        .unwrap_or_default();
    Row {
        key: format!(
            "{}/{}/{}",
            get("interface"),
            get("protocol"),
            r.get("node_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| r.get("mac").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| get("address"))
        ),
        cells: vec![
            get("interface"),
            get("protocol").to_uppercase(),
            get("address"),
            get("mac"),
            get("identity"),
            get("version"),
            get("board"),
            uptime,
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl CoreRouterUi {
    pub(crate) fn neighbors(&mut self, ui: &mut Ui) {
        let rows: Vec<Row> = self.cache.neighbors.iter().map(neighbor_row).collect();
        let mut select_all = false;
        ui.horizontal(|ui| {
            ui.weak("Heard with CRDP, LLDP and MNDP on the discovery interfaces");
            table::find_field(ui, TABLE, &mut self.tables.neighbors);
        });
        ui.separator();
        let reserve = ui.spacing().interact_size.y * 3.5;
        table::show(
            ui,
            TABLE,
            reserve,
            &mut self.tables.neighbors,
            &COLUMNS,
            &rows,
            |ui, menu| {
                if matches!(menu, Menu::Empty) {
                    select_all = ui.button("Select All").clicked();
                }
            },
        );
        if select_all {
            self.tables.neighbors.select_all(&rows);
        }
        ui.separator();
        self.discovery_settings(ui);
    }

    fn discovery_settings(&mut self, ui: &mut Ui) {
        if self.forms.discovery.loaded.is_none() && self.cache.discovery.is_object() {
            let d = &self.cache.discovery;
            self.forms.discovery.loaded = Some(Loaded {
                enabled: d.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                interfaces: d
                    .get("interfaces")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                interval: d.get("interval_secs").map(value_text).unwrap_or_default(),
            });
        }
        let names = self.interface_names(None);
        let can = self.can();
        let Some(form) = self.forms.discovery.loaded.as_mut() else {
            ui.weak("Discovery settings: waiting for the router…");
            return;
        };
        let mut apply = false;
        let mut reset = false;
        ui.horizontal_wrapped(|ui| {
            ui.strong("Discovery");
            ui.checkbox(&mut form.enabled, "Enabled");
            let label = match form.interfaces.len() {
                0 => "Interfaces: none".to_owned(),
                n => format!("Interfaces: {}", join_short(&form.interfaces, n)),
            };
            ui.menu_button(label, |ui| {
                for n in &names {
                    let mut on = form.interfaces.contains(n);
                    if ui.checkbox(&mut on, n).changed() {
                        if on {
                            form.interfaces.insert(n.clone());
                        } else {
                            form.interfaces.remove(n);
                        }
                    }
                }
            })
            .response
            .on_hover_text(
                "Announce and listen only here. Leave WAN ports out: an announcement \
                 tells everyone on the link our identity, version and management ports.",
            );
            ui.label("Interval");
            ui.add(TextEdit::singleline(&mut form.interval).desired_width(48.0));
            ui.label("s");
            apply = table::action(ui, "Apply", can.check("ip.neighbor.discovery.set"));
            reset = ui.button("Reset").clicked();
        });
        if apply {
            let p = json!({
                "enabled": form.enabled,
                "interfaces": form.interfaces.iter().collect::<Vec<_>>(),
                "interval_secs": form_number(&form.interval),
            });
            self.run("ip.neighbor.discovery.set", p);
        }
        if apply || reset {
            // Reload from what the router has after the reply.
            self.forms.discovery.loaded = None;
            self.cache.discovery = Value::Null;
        }
    }
}

fn join_short(set: &BTreeSet<String>, n: usize) -> String {
    let shown: Vec<&str> = set.iter().take(3).map(String::as_str).collect();
    if n > shown.len() {
        format!("{} +{}", shown.join(", "), n - shown.len())
    } else {
        shown.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Win;
    use corerouter_engine::{Session, lock, shared};
    use corerouter_model::{NeighborEntry, NeighborProtocol};

    #[test]
    fn window_lists_what_the_session_heard() {
        let session = shared(Session::virtual_lab());
        {
            let mut s = lock(&session);
            s.execute(
                "ip.neighbor.discovery.set",
                &json!({"interfaces": ["ether2"]}),
            )
            .unwrap();
            s.record_neighbor(NeighborEntry {
                interface: "ether2".parse().unwrap(),
                protocol: NeighborProtocol::Lldp,
                mac: Some("02:00:00:00:00:09".parse().unwrap()),
                addresses: vec!["192.0.2.9".parse().unwrap()],
                identity: "switch-9".into(),
                version: String::new(),
                platform: String::new(),
                board: "CRS326".into(),
                uptime_secs: Some(90_061),
                node_id: None,
                remote_interface: None,
                mgmt: None,
                last_seen: 10,
                hold_secs: 120,
            });
        }
        let mut app = CoreRouterUi::new(session);
        app.open(Win::Neighbors);
        let ctx = egui::Context::default();
        let mut texts = Vec::new();
        fn walk(s: &egui::Shape, out: &mut Vec<String>) {
            match s {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        for _ in 0..3 {
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| app.ui(ui));
            out.textures_delta.clear();
            texts.clear();
            for c in &out.shapes {
                walk(&c.shape, &mut texts);
            }
        }
        let cells = neighbor_row(&app.cache.neighbors[0]).cells;
        assert_eq!(
            cells,
            [
                "ether2",
                "LLDP",
                "192.0.2.9",
                "02:00:00:00:00:09",
                "switch-9",
                "",
                "CRS326",
                "1d01:01:01"
            ]
        );
        assert!(texts.iter().any(|t| t == "switch-9"), "{texts:?}");
        assert!(
            app.forms
                .discovery
                .loaded
                .as_ref()
                .is_some_and(|l| l.interfaces.contains("ether2")),
            "settings form loaded from the router"
        );
    }

    #[test]
    fn uptime_like_routeros() {
        assert_eq!(uptime_text(59), "00:00:59");
        assert_eq!(
            uptime_text(3 * 86_400 + 4 * 3600 + 5 * 60 + 6),
            "3d04:05:06"
        );
    }
}

//! CGNAT › Logging (G4.4j): where the NAT log goes. Which RFC 8158 events
//! the router makes (port blocks, limits, sessions) and the collectors
//! that receive them, with their state. The events and the collectors are
//! `/ip traffic-flow`'s (one exporter, one socket per collector): this tab
//! shows the NAT side of it and edits it with the same commands;
//! "Add Collector" opens the Traffic Flow target modal filled for IPFIX
//! over TLS, NAT only. Every label has an ⓘ.

use egui::{Grid, Id, Ui};
use serde_json::{Map, Value, json};

use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::Lang;
use crate::panel::Query;
use crate::table::{self, Row, TableState, col, num, weak};
use crate::{CoreRouterUi, Win, value_text};

const SCOPE: &str = "nat_log";
const COLLECTORS: &str = "cgnat-log-collectors";
const SET: &str = "ip.traffic-flow.set";

fn tr(l: Lang, en: &'static str) -> &'static str {
    crate::i18n::tr_in(SCOPE, l, en)
}

const COLUMNS: [table::Column; 8] = [
    col("State"),
    col("Collector"),
    col("Transport"),
    col("Content"),
    col("natEvent"),
    num("Records"),
    col("Lost"),
    weak("Last Error"),
];

/// The NAT switches of `ip.traffic-flow.set`: (param, label, what it adds).
const SWITCHES: &[(&str, &str, &str)] = &[
    ("nat_port_blocks", "Port Blocks", "natEvent 16/17: one record per block, with pool, VLAN and login"),
    ("nat_limits", "Limits", "natEvent 3/13/18: pool exhausted, subscriber out of ports, alert"),
    ("nat_events", "Sessions", "natEvent 4/5: one record per connection (high volume)"),
    ("nat_events_destination", "Session Destination", "destination in the session records (Marco Civil art. 14)"),
];

#[derive(Default)]
pub(crate) struct Logging {
    pub(crate) settings: Value,
    pub(crate) targets: Vec<Value>,
    pub(crate) stats: Value,
    table: TableState,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).filter(|x| !x.is_null()).map(value_text).unwrap_or_default()
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn state_kind(state: &str) -> Kind {
    match state {
        "running" | "sending" => Kind::Green,
        "error" => Kind::Red,
        "connecting" => Kind::Amber,
        _ => Kind::Neutral,
    }
}

/// One collector that receives NAT events.
fn row(t: &Value) -> Row {
    let disabled = flag(t, "disabled");
    let state = if disabled { "disabled".to_owned() } else { text(t, "state") };
    let transport = text(t, "transport");
    // Encrypted or not, at a glance: RFC 8158 §7 asks for NAT logs over a
    // secure channel.
    let transport_kind = if transport == "tls" { Kind::Green } else { Kind::Neutral };
    let codes = if flag(t, "nat_events_legacy") { ("1/2 legacy", Kind::Amber) } else { ("RFC 8158", Kind::Neutral) };
    let lost = n(t, "dropped") + n(t, "send_errors");
    Row {
        key: text(t, "id"),
        cells: vec![
            chip::cell("", &[(state.as_str(), state_kind(&state))]),
            format!("{}:{}", text(t, "dst_address"), text(t, "port")),
            chip::cell("", &[(transport.as_str(), transport_kind)]),
            text(t, "content"),
            chip::cell("", &[codes]),
            n(t, "records").to_string(),
            if lost > 0 { chip::cell("", &[(lost.to_string().as_str(), Kind::Red)]) } else { "0".into() },
            text(t, "last_error"),
        ],
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

/// A label with its ⓘ; the explanation key is `nat-log.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr(l, text));
        if help::info_button(ui, Id::unique(("nat-log-help", key)), tr(l, text)).clicked() {
            *help = Some(HelpView::new(format!("nat-log.{key}"), tr(l, text)));
        }
    });
}

impl Logging {
    pub(crate) fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.has_command("ip.traffic-flow.get") {
            return Vec::new();
        }
        vec![
            Query { key: "log_settings", command: "ip.traffic-flow.get", params: json!({}) },
            Query { key: "log_targets", command: "ip.traffic-flow.target.list", params: json!({}) },
            Query { key: "log_stats", command: "ip.traffic-flow.stats", params: json!({}) },
        ]
    }

    /// One of this tab's answers (keys `log_*`).
    pub(crate) fn arrived(&mut self, key: &str, value: Value) {
        match (key, value) {
            ("log_settings", v) => self.settings = v,
            ("log_targets", Value::Array(a)) => self.targets = a,
            ("log_stats", v) => self.stats = v,
            _ => {}
        }
    }

    pub(crate) fn show(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang, help: &mut Option<HelpView>) {
        if !app.has_command("ip.traffic-flow.get") {
            ui.weak(tr(l, "This router has no flow exporter (ip.traffic-flow)."));
            return;
        }
        let can = app.can();
        let on = flag(&self.settings, "enabled");
        let state = if text(&self.settings, "state").is_empty() { "stopped".to_owned() } else { text(&self.settings, "state") };
        ui.horizontal_wrapped(|ui| {
            label(ui, help, l, "exporter", "Exporter");
            chip::chip(ui, &state, state_kind(&state).tone(ui.visuals()));
            if on {
                ui.label(format!("{} {}", n(&self.settings, "records_per_min"), tr(l, "records/min")));
            } else if table::action(ui, tr(l, "Enable"), can.check(SET)) {
                app.run(SET, json!({"enabled": true}));
            }
            ui.separator();
            label(ui, help, l, "queue", "Queue");
            ui.label(format!("{} {}", n(&self.stats, "nat_log"), tr(l, "events")));
            let dropped = n(&self.stats, "nat_log_dropped");
            if dropped > 0 {
                chip::chip(ui, &format!("{} {dropped}", tr(l, "dropped")), chip::RED.tone(ui.visuals()));
            }
        });
        ui.add_space(4.0);
        // The switches apply at once (one command each).
        let mut changed: Option<Map<String, Value>> = None;
        Grid::new("nat-log-switches").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            for (key, name, what) in SWITCHES {
                label(ui, help, l, key, name);
                ui.horizontal(|ui| {
                    let mut v = flag(&self.settings, key);
                    let enabled = can.check(SET).is_ok() && (*key != "nat_events_destination" || flag(&self.settings, "nat_events"));
                    if ui.add_enabled(enabled, egui::Checkbox::new(&mut v, tr(l, what))).changed() {
                        changed.get_or_insert_with(Map::new).insert((*key).into(), json!(v));
                    }
                    if *key == "nat_events_destination" && v {
                        chip::chip(ui, "Marco Civil art. 14", chip::AMBER.tone(ui.visuals()));
                    }
                });
                ui.end_row();
            }
        });
        if let Some(p) = changed {
            app.run(SET, Value::Object(p));
        }
        ui.add_space(4.0);
        let mine: Vec<&Value> = self.targets.iter().filter(|t| text(t, "content") != "flows").collect();
        ui.horizontal(|ui| {
            label(ui, help, l, "collectors", "Collectors");
            if table::action(ui, tr(l, "Add Collector"), can.check("ip.traffic-flow.target.add")) {
                open_traffic_flow(app);
                // The Traffic Flow panel opens its own modal, which needs the
                // app: taken out for the call, put back after.
                let mut panel = app.panel_mut::<crate::traffic_flow::TrafficFlowPanel>().map(std::mem::take);
                if let Some(p) = panel.as_mut() {
                    p.add_nat_target(app);
                }
                if let (Some(p), Some(slot)) = (panel, app.panel_mut::<crate::traffic_flow::TrafficFlowPanel>()) {
                    *slot = p;
                }
            }
            if table::action(ui, tr(l, "Open Traffic Flow"), Ok(())) {
                open_traffic_flow(app);
            }
        });
        let rows: Vec<Row> = mine.iter().map(|t| row(t)).collect();
        table::show(ui, COLLECTORS, 24.0, &mut self.table, &COLUMNS, &rows, |_, _| {});
        let plain = mine.iter().filter(|t| text(t, "transport") != "tls" && !flag(t, "disabled")).count();
        if mine.is_empty() {
            ui.weak(tr(l, "No collector receives NAT events: they are only kept on the router (Traffic Flow › Retention)."));
        } else if plain > 0 {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                tr(l, "NAT logs say who used which address: RFC 8158 §7 asks for them encrypted (transport tls)."),
            );
        }
    }

    pub(crate) fn table(&self) -> (&'static str, &TableState) {
        (COLLECTORS, &self.table)
    }

    pub(crate) fn table_mut(&mut self) -> (&'static str, &mut TableState) {
        (COLLECTORS, &mut self.table)
    }
}

/// Opens (or raises) IP › Traffic Flow.
fn open_traffic_flow(app: &mut CoreRouterUi) {
    let win = Win::Panel(crate::traffic_flow::WIN);
    if !app.open.insert(win) {
        app.floats.raise(crate::win_id(win));
    }
    app.cache.refreshed_at = None;
}

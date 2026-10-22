//! IP › DNS › Statistics (G4.1e): what the LAN forwarder did since the
//! last reset — who answered (cache, static, upstream, stale, refused,
//! over the limit), the response codes, the record types, the clients that
//! ask most and the upstream servers. Opened by the Statistics button of
//! the DNS window. Reads `ip.dns.statistics.print`, acts with
//! `ip.dns.statistics.reset`; nothing is computed here.

use egui::{Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, chip, neutral_tone};
use crate::dhcp_client::text;
use crate::firewall::duration;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, action, col, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-statistics";
pub(crate) const WIN: &str = "dns-statistics";
const CLIENTS_TABLE: &str = "dns-statistics-clients";
const UPSTREAMS_TABLE: &str = "dns-statistics-upstreams";
const PRINT: &str = "ip.dns.statistics.print";
const RESET: &str = "ip.dns.statistics.reset";
/// Clients asked for (the table scrolls).
const TOP: u32 = 20;
/// Record types listed; the rest are summed as "others".
const TYPES: usize = 8;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Statistics",
        size: [640.0, 520.0],
        escape: true,
    }],
    new: || Box::new(DnsStatsPanel::default()),
};

const CLIENT_COLUMNS: [table::Column; 4] =
    [col("Client"), num("Queries"), num("%"), num("Refused")];
const UPSTREAM_COLUMNS: [table::Column; 5] = [
    col("Server"),
    num("Answers"),
    num("SRTT (ms)"),
    num("Failures"),
    col("State"),
];

/// What each `answered` key means, in the order shown.
const STAGES: [(&str, &str, &str); 9] = [
    ("cache", "Cache", "Answered from the cache"),
    ("static", "Static", "Answered by a static entry"),
    ("upstream", "Upstream", "Asked of an upstream server"),
    ("stale", "Stale", "Expired answer served: no server answered (RFC 8767)"),
    ("refused", "Refused", "Client outside Allowed From: REFUSED"),
    ("limit", "Over limit", "Max Queries Per Client: dropped (UDP) or REFUSED (TCP)"),
    ("busy", "Busy", "Max Concurrent Queries reached: SERVFAIL"),
    ("special", "Special", "Names the router answers itself (RFC 6761, RFC 8880)"),
    ("none", "Unanswered", "No stage answered: SERVFAIL"),
];

#[derive(Default)]
pub(crate) struct DnsStatsPanel {
    /// `ip.dns.statistics.print`.
    pub(crate) stats: Option<Value>,
    pub(crate) error: Option<String>,
    clients_table: TableState,
    upstreams_table: TableState,
}

struct Reset;

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// `part` of `whole` as a whole percentage ("–" when nothing counted).
fn percent(part: u64, whole: u64) -> String {
    (part * 100)
        .checked_div(whole)
        .map_or_else(|| "–".into(), |p| p.to_string())
}

fn client_row(r: &Value, total: u64) -> Row {
    let error = n(r, "error");
    let queries = if error > 0 {
        // Space-Saving: the count may hold up to `error` queries of
        // clients this one replaced.
        format!("≤{}", n(r, "queries"))
    } else {
        n(r, "queries").to_string()
    };
    Row {
        key: text(r, "address"),
        cells: vec![
            text(r, "address"),
            queries,
            percent(n(r, "queries"), total),
            n(r, "refused").to_string(),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn upstream_row(r: &Value) -> Row {
    let down = r.get("down").and_then(Value::as_bool).unwrap_or(false);
    let srtt = r
        .get("srtt_ms")
        .and_then(Value::as_u64)
        .map_or_else(|| "–".to_owned(), |v| v.to_string());
    Row {
        key: text(r, "server"),
        cells: vec![
            text(r, "server"),
            n(r, "answers").to_string(),
            srtt,
            n(r, "failures").to_string(),
            if down { "down" } else { "up" }.to_owned(),
        ],
        dimmed: down,
        section: false,
        tint: None,
    }
}

/// `{key: count}` as (key, count), largest first.
fn counts(v: &Value) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = v
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, c)| (k.clone(), c.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

impl PanelState for DnsStatsPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) && app.has_command(PRINT) {
            vec![Query {
                key: "print",
                command: PRINT,
                params: json!({"top": TOP}),
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "print" && value.is_object() {
            self.stats = Some(value);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast::<Reset>().is_ok() {
            self.error = result.as_ref().err().cloned();
            app.cache.refreshed_at = None;
        }
    }

    fn escape(&mut self, _: &'static str) -> bool {
        self.clients_table.escape() || self.upstreams_table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (CLIENTS_TABLE, &self.clients_table),
            (UPSTREAMS_TABLE, &self.upstreams_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (CLIENTS_TABLE, &mut self.clients_table),
            (UPSTREAMS_TABLE, &mut self.upstreams_table),
        ]
    }
}

impl DnsStatsPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let s = self.stats.clone().unwrap_or(Value::Null);
        let can = app.can();
        let mut reset = false;
        ui.horizontal(|ui| {
            reset = action(ui, "Reset Statistics", can.check(RESET));
            ui.separator();
            state_chip(ui, &s);
            match s.get("elapsed_secs").and_then(Value::as_u64) {
                Some(secs) => ui.weak(format!("counting for {}", duration(secs))),
                None => ui.weak("counting since the daemon started or the last reset"),
            };
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        ui.separator();
        let total = n(&s, "queries");
        let answered = s.get("answered").cloned().unwrap_or(Value::Null);
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{total} queries")).strong());
            ui.weak(format!("UDP {} · TCP {}", n(&s, "udp"), n(&s, "tcp")));
            let hit = s
                .get("cache_hit_percent")
                .and_then(Value::as_u64)
                .map_or_else(|| "–".to_owned(), |p| format!("{p} %"));
            ui.label("Cache hits")
                .on_hover_text("Of the queries that needed the resolver (cache, upstream, stale)");
            ui.label(RichText::new(hit).strong());
        });
        ui.add_space(4.0);
        ui.horizontal_top(|ui| {
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Answered by");
                    Grid::new("dns-stats-answered").num_columns(3).show(ui, |ui| {
                        for (key, label, tip) in STAGES {
                            let c = n(&answered, key);
                            // The optional stages only when they answered.
                            if c == 0 && STAGES.iter().position(|s| s.0 == key) > Some(5) {
                                continue;
                            }
                            ui.label(label).on_hover_text(tip);
                            ui.label(c.to_string());
                            ui.weak(format!("{} %", percent(c, total)));
                            ui.end_row();
                        }
                        // Stages this window does not know yet (adlist, zones…).
                        for (key, c) in counts(&answered) {
                            if c > 0 && !STAGES.iter().any(|s| s.0 == key) {
                                ui.label(key);
                                ui.label(c.to_string());
                                ui.weak(format!("{} %", percent(c, total)));
                                ui.end_row();
                            }
                        }
                    });
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Response codes");
                    Grid::new("dns-stats-rcodes").num_columns(2).show(ui, |ui| {
                        for (code, c) in counts(s.get("rcodes").unwrap_or(&Value::Null)) {
                            ui.label(code.to_uppercase());
                            ui.label(c.to_string());
                            ui.end_row();
                        }
                    });
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Types");
                    let types = s.get("types").and_then(Value::as_array).cloned().unwrap_or_default();
                    Grid::new("dns-stats-types").num_columns(2).show(ui, |ui| {
                        for t in types.iter().take(TYPES) {
                            ui.label(text(t, "type"));
                            ui.label(n(t, "queries").to_string());
                            ui.end_row();
                        }
                        let rest: u64 = types.iter().skip(TYPES).map(|t| n(t, "queries")).sum();
                        if rest > 0 {
                            ui.weak("others");
                            ui.label(rest.to_string());
                            ui.end_row();
                        }
                    });
                });
            });
        });
        ui.add_space(4.0);
        let clients: Vec<Row> = s
            .get("clients")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|r| client_row(r, total)).collect())
            .unwrap_or_default();
        let upstreams: Vec<Row> = s
            .get("upstreams")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(upstream_row).collect())
            .unwrap_or_default();
        let tracked = n(&s, "clients_tracked");
        ui.columns(2, |cols| {
            if let [left, right] = cols {
                left.horizontal(|ui| {
                    ui.strong("Top clients");
                    ui.weak(format!("{} of {tracked}", clients.len()));
                });
                table::show(
                    left,
                    CLIENTS_TABLE,
                    0.0,
                    &mut self.clients_table,
                    &CLIENT_COLUMNS,
                    &clients,
                    |ui, menu| refresh_menu(app, ui, &menu),
                );
                right.horizontal(|ui| {
                    ui.strong("Upstream servers");
                    ui.weak(upstreams.len().to_string());
                });
                table::show(
                    right,
                    UPSTREAMS_TABLE,
                    0.0,
                    &mut self.upstreams_table,
                    &UPSTREAM_COLUMNS,
                    &upstreams,
                    |ui, menu| refresh_menu(app, ui, &menu),
                );
            }
        });
        if reset {
            app.run_then(RESET, json!({}), crate::panel::then(NAME, Reset));
        }
    }
}

fn refresh_menu(app: &mut CoreRouterUi, ui: &mut Ui, menu: &Menu<'_>) {
    if let Menu::Empty | Menu::Rows(_) = menu
        && ui.button("Refresh").clicked()
    {
        app.cache.refreshed_at = None;
    }
}

/// Why nothing may be counting, as a chip (docs/ui-style.md).
fn state_chip(ui: &mut Ui, s: &Value) {
    let v = ui.visuals().clone();
    if s.get("resolver").and_then(Value::as_str) == Some("simulated") {
        chip(ui, "lab", neutral_tone(&v))
            .on_hover_text("No daemon: the virtual lab does not answer DNS, nothing is counted");
    } else if s.get("allow_remote_requests").and_then(Value::as_bool) == Some(false) {
        chip(ui, "forwarder off", AMBER.tone(&v))
            .on_hover_text("Allow Remote Requests is off: the LAN is not answered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows() {
        let c = json!({"address": "192.168.88.10", "queries": 30, "refused": 2, "error": 0});
        assert_eq!(client_row(&c, 120).cells, ["192.168.88.10", "30", "25", "2"]);
        let c = json!({"address": "10.0.0.9", "queries": 7, "refused": 0, "error": 6});
        assert_eq!(client_row(&c, 0).cells[1..3], ["≤7", "–"]);
        let u = json!({"server": "1.1.1.1", "answers": 5, "srtt_ms": null, "failures": 1,
            "down": true});
        let r = upstream_row(&u);
        assert_eq!(r.cells, ["1.1.1.1", "5", "–", "1", "down"]);
        assert!(r.dimmed);
        let got = counts(&json!({"noerror": 3, "nxdomain": 9, "refused": 3}));
        assert_eq!(got[0], ("nxdomain".to_owned(), 9));
        assert_eq!(got[1].0, "noerror", "ties by name");
    }
}

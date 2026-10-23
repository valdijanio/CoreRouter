//! Tools › DNS Lookup › Watch and Upstreams (G6.8): the tabs of the DNS
//! Lookup window (`dns_lookup.rs`) that run `tool.dns.watch` and
//! `tool.dns.upstreams`.
//!
//! - Watch: latency over time (egui_plot, as Ping) with the spikes the
//!   engine marked and the timeouts, and one row per query, newest first,
//!   with a `changed` chip when the answer changed. Stop or Esc ends it.
//! - Upstreams: one row per server (p50, p99, loss, SERVFAIL, transport,
//!   the hijack checks as chips), then the advice: use, remove, note, each
//!   in the explanations' language.
//!
//! No logic here: the engine measures, compares and advises.

use egui::{Grid, RichText, Ui};
use egui_plot::{Line, MarkerShape, Plot, PlotPoints, Points};
use serde_json::{Value, json};

use crate::chip::{AMBER, BLUE, GREEN, RED, chip, name_hue, neutral_tone, palette_tone};
use crate::dhcp_client::text;
use crate::i18n::{self, Langs, tr};

/// Watch rows kept (the plot and the table); older ones drop.
pub(crate) const MAX_ROWS: usize = 3600;
/// Watch rows shown in the table (the newest).
const SHOWN_ROWS: usize = 200;

/// One running (or finished) task of a tab.
#[derive(Default)]
pub(crate) struct TaskView {
    pub(crate) task: Option<u64>,
    pub(crate) done: bool,
    pub(crate) events: Vec<Value>,
    /// Watch: the last event's `seq` (polls ask for what came after it).
    pub(crate) last_seq: Option<u64>,
    pub(crate) summary: Value,
    pub(crate) error: Option<String>,
    /// Esc asked to stop it (sent on the next frame, with the app).
    pub(crate) stop: bool,
}

impl TaskView {
    pub(crate) fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// The poll's params: watch polls only what is new.
    pub(crate) fn poll(&self, id: u64) -> Value {
        match self.last_seq {
            Some(seq) => json!({"id": id, "after_seq": seq, "max": 256}),
            None => json!({"id": id, "after_seq": 0, "max": 256}),
        }
    }

    /// A poll arrived: append (`append`, watch) or replace the events.
    pub(crate) fn arrived(&mut self, value: &Value, append: bool) {
        let events = value.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
        if append {
            if let Some(seq) = events.last().and_then(|e| e.get("seq")).and_then(Value::as_u64) {
                self.last_seq = Some(seq);
            }
            self.events.extend(events);
            let extra = self.events.len().saturating_sub(MAX_ROWS);
            self.events.drain(..extra);
        } else {
            self.events = events;
        }
        if let Some(s) = value.get("summary").filter(|s| !s.is_null()) {
            self.summary = s.clone();
        }
        if value.get("done").and_then(Value::as_bool) == Some(true) {
            self.done = true;
            if value.get("state").and_then(Value::as_str) == Some("failed") {
                self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
            }
        }
    }
}

fn ms(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_f64)
        .map_or("–".into(), |m| format!("{} ms", (m * 10.0).round() / 10.0))
}

/// `HH:MM:SS` (UTC) of the event's Unix time, else `+12.3 s`.
fn time_of(ev: &Value) -> String {
    match ev.get("at").and_then(Value::as_f64) {
        Some(at) => {
            let s = at.max(0.0) as u64 % 86_400;
            format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
        }
        None => format!(
            "+{:.1} s",
            ev.get("t_ms").and_then(Value::as_u64).unwrap_or(0) as f64 / 1000.0
        ),
    }
}

/// Watch results: the summary chips, the plot and the rows.
pub(crate) fn watch_results(ui: &mut Ui, langs: Langs, w: &TaskView) {
    if let Some(e) = &w.error {
        ui.colored_label(crate::err_color(ui), e.as_str());
    }
    let rows: Vec<&Value> = w.events.iter().filter(|e| text(e, "kind") == "watch").collect();
    if rows.is_empty() {
        if w.task.is_none() {
            ui.weak("Name, type and server above; Start asks again every interval until Stop (or Esc).");
        }
        return;
    }
    let s = &w.summary;
    ui.horizontal_wrapped(|ui| {
        let v = ui.visuals().clone();
        chip(ui, &format!("{} / {}", text(s, "answered"), text(s, "sent")), neutral_tone(&v))
            .on_hover_text("Answered / sent");
        let loss = s.get("loss_pct").and_then(Value::as_f64).unwrap_or(0.0);
        let tone = if loss > 0.0 { RED.tone(&v) } else { GREEN.tone(&v) };
        chip(ui, &format!("{loss}% loss"), tone);
        chip(ui, &format!("p50 {}", ms(s, "p50_ms")), BLUE.tone(&v));
        chip(ui, &format!("p95 {}", ms(s, "p95_ms")), neutral_tone(&v));
        chip(ui, &format!("max {}", ms(s, "max_ms")), neutral_tone(&v));
        let changes = s.get("changes").and_then(Value::as_u64).unwrap_or(0);
        if changes > 0 {
            chip(ui, &format!("{changes} × {}", tr(langs.labels, "changed")), AMBER.tone(&v));
        }
        let spikes = s.get("spikes").and_then(Value::as_u64).unwrap_or(0);
        if spikes > 0 {
            chip(ui, &format!("{spikes} × {}", tr(langs.labels, "spike")), RED.tone(&v));
        }
    });
    let at = |e: &Value| e.get("t_ms").and_then(Value::as_u64).unwrap_or(0) as f64 / 1000.0;
    let line: Vec<[f64; 2]> = rows
        .iter()
        .filter_map(|e| e.get("ms").and_then(Value::as_f64).map(|m| [at(e), m]))
        .collect();
    let spikes: Vec<[f64; 2]> = rows
        .iter()
        .filter(|e| e["spike"] == true)
        .filter_map(|e| e.get("ms").and_then(Value::as_f64).map(|m| [at(e), m]))
        .collect();
    let top = line.iter().map(|p| p[1]).fold(1.0f64, f64::max);
    let lost: Vec<[f64; 2]> = rows.iter().filter(|e| e.get("error").is_some()).map(|e| [at(e), top]).collect();
    let changed: Vec<[f64; 2]> = rows
        .iter()
        .filter(|e| e["changed"] == true)
        .filter_map(|e| e.get("ms").and_then(Value::as_f64).map(|m| [at(e), m]))
        .collect();
    let v = ui.visuals().clone();
    Plot::new("dns-watch-chart")
        .height(160.0)
        .include_y(0.0)
        .y_axis_label("ms")
        .x_axis_label("s")
        .allow_scroll(false)
        .show(ui, |p| {
            p.line(Line::new("latency", PlotPoints::from(line)).color(BLUE.tone(&v).ink).width(1.5));
            if !spikes.is_empty() {
                p.points(
                    Points::new("spike", PlotPoints::from(spikes))
                        .shape(MarkerShape::Circle)
                        .color(RED.tone(&v).ink)
                        .radius(4.0),
                );
            }
            if !changed.is_empty() {
                p.points(
                    Points::new("changed", PlotPoints::from(changed))
                        .shape(MarkerShape::Diamond)
                        .color(AMBER.tone(&v).ink)
                        .radius(4.0),
                );
            }
            if !lost.is_empty() {
                p.points(
                    Points::new("lost", PlotPoints::from(lost))
                        .shape(MarkerShape::Cross)
                        .color(RED.tone(&v).ink)
                        .radius(4.0),
                );
            }
        });
    ui.add_space(4.0);
    Grid::new("dns-watch-rows")
        .striped(true)
        .num_columns(5)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for h in ["Time", "Latency", "Stage", "TTL", "Answer"] {
                ui.strong(tr(langs.labels, h));
            }
            ui.end_row();
            for e in rows.iter().rev().take(SHOWN_ROWS) {
                ui.label(time_of(e)).on_hover_text(format!("#{} · UTC", text(e, "n")));
                ui.horizontal(|ui| {
                    ui.label(e.get("ms").and_then(Value::as_u64).map_or("–".into(), |m| format!("{m} ms")));
                    if e["spike"] == true {
                        chip(ui, tr(langs.labels, "spike"), RED.tone(ui.visuals()))
                            .on_hover_text("At least 3x the median so far (and 20 ms more).");
                    }
                });
                ui.label(text(e, "stage"));
                ui.label(text(e, "ttl"));
                ui.horizontal(|ui| {
                    if e.get("error").is_some() {
                        let what = if e["timeout"] == true { "timeout" } else { "error" };
                        chip(ui, what, RED.tone(ui.visuals())).on_hover_text(text(e, "error"));
                        return;
                    }
                    let rcode = text(e, "rcode");
                    if rcode != "NOERROR" {
                        chip(ui, &rcode, AMBER.tone(ui.visuals()));
                    }
                    let data: Vec<String> = e
                        .get("data")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect();
                    let all = data.join(", ");
                    let (shown, cut) = crate::dns_lookup::fit(ui, &all, 520.0);
                    let l = ui.label(shown);
                    if cut {
                        l.on_hover_text(data.join("\n"));
                    }
                    if e["changed"] == true {
                        chip(ui, tr(langs.labels, "changed"), AMBER.tone(ui.visuals()))
                            .on_hover_text("The answer differs from the one before.");
                    }
                });
                ui.end_row();
            }
        });
}

/// The advice's text in the explanations' language.
pub(crate) fn advice_text(lang: i18n::Lang, a: &Value) -> String {
    let args: Vec<(String, String)> = a
        .get("args")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_owned)))
        .collect();
    let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    i18n::template(lang, &format!("dnsbench.{}", text(a, "why")), &args, &text(a, "text"))
}

/// Upstreams results: progress, a row per server, the advice.
pub(crate) fn bench_results(ui: &mut Ui, langs: Langs, b: &TaskView) {
    if let Some(e) = &b.error {
        ui.colored_label(crate::err_color(ui), e.as_str());
    }
    if b.running()
        && let Some(p) = b.events.iter().rev().find(|e| text(e, "kind") == "progress")
    {
        let done = p.get("done").and_then(Value::as_f64).unwrap_or(0.0);
        let total = p.get("total").and_then(Value::as_f64).unwrap_or(1.0).max(1.0);
        ui.add(egui::ProgressBar::new((done / total) as f32).text(format!("{done} / {total}")));
    }
    let rows: Vec<Value> = match b.summary.get("servers").and_then(Value::as_array) {
        Some(r) => r.clone(),
        None => b.events.iter().filter(|e| text(e, "kind") == "bench").cloned().collect(),
    };
    if rows.is_empty() {
        if b.task.is_none() {
            ui.weak("Start asks every upstream (ip.dns servers, DoH and the forwarders groups) the same mix of popular and random names.");
        }
        return;
    }
    Grid::new("dns-upstreams")
        .striped(true)
        .num_columns(7)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for h in ["Server", "Via", "p50", "p99", "Loss", "SERVFAIL", "Checks"] {
                ui.strong(tr(langs.labels, h));
            }
            ui.end_row();
            for r in &rows {
                let v = ui.visuals().clone();
                ui.horizontal(|ui| {
                    ui.label(text(r, "server"));
                    for g in r.get("groups").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                        chip(ui, g, palette_tone(&v, name_hue(g)))
                            .on_hover_text("Forwarders group");
                    }
                });
                ui.label(text(r, "transport"));
                ui.label(ms(r, "p50_ms"));
                ui.label(ms(r, "p99_ms"));
                let pct = |k: &str| r.get(k).and_then(Value::as_f64).unwrap_or(0.0);
                for k in ["loss_pct", "servfail_pct"] {
                    let x = pct(k);
                    if x > 0.0 {
                        ui.label(RichText::new(format!("{x}%")).color(RED.tone(&v).ink));
                    } else {
                        ui.label("0%");
                    }
                }
                ui.horizontal(|ui| {
                    if r["down"] == true {
                        chip(ui, tr(langs.labels, "down"), RED.tone(&v)).on_hover_text("Never answered.");
                    }
                    if r["nxdomain_hijack"] == true {
                        let data: Vec<&str> = r["nx_data"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                        chip(ui, tr(langs.labels, "NXDOMAIN hijacked"), RED.tone(&v)).on_hover_text(format!(
                            "Names that cannot exist got an answer instead of NXDOMAIN:\n{}",
                            data.join("\n")
                        ));
                    }
                    if r["proxy"] == true {
                        chip(ui, tr(langs.labels, "proxy on the path"), RED.tone(&v)).on_hover_text(format!(
                            "The resolver that reached the authoritative servers is {} (AS{}), from this router's own network, not the server's (AS{}).",
                            text(r, "egress_shown"),
                            text(r, "egress_as"),
                            text(r, "server_as")
                        ));
                    }
                    if r["other_network"] == true {
                        let egress = text(r, "egress_shown");
                        chip(ui, tr(langs.labels, "other network"), AMBER.tone(&v)).on_hover_text(format!(
                            "The resolver that reached the authoritative servers is {egress} (AS{}), outside the server's network (AS{}) and not the client's: an anycast partner, or a proxy.",
                            text(r, "egress_as"),
                            text(r, "server_as")
                        ));
                    }
                    if r["forwarder"] == true {
                        chip(ui, tr(langs.labels, "forwarder"), neutral_tone(&v))
                            .on_hover_text("A private address: it forwards to another resolver.");
                    }
                    match r["tcp"].as_bool() {
                        Some(true) => {
                            chip(ui, "TCP", GREEN.tone(&v));
                        }
                        Some(false) => {
                            chip(ui, "TCP", RED.tone(&v)).on_hover_text("No answer over TCP.");
                        }
                        None => {}
                    }
                    match r["edns"].as_bool() {
                        Some(true) => {
                            chip(ui, &format!("EDNS {}", text(r, "edns_udp")), GREEN.tone(&v))
                                .on_hover_text("EDNS(0) and the UDP buffer the server offers.");
                        }
                        Some(false) => {
                            chip(ui, "EDNS", RED.tone(&v)).on_hover_text("No OPT in the replies (RFC 8906).");
                        }
                        None => {}
                    }
                });
                ui.end_row();
            }
        });
    let advice: Vec<&Value> = b.summary.get("recommend").and_then(Value::as_array).into_iter().flatten().collect();
    if advice.is_empty() {
        return;
    }
    ui.add_space(6.0);
    ui.strong(tr(langs.labels, "Recommendation"));
    Grid::new("dns-upstreams-advice")
        .num_columns(2)
        .spacing([10.0, 4.0])
        .show(ui, |ui| {
            for a in advice {
                let v = ui.visuals().clone();
                let (label, tone) = match text(a, "kind").as_str() {
                    "use" => ("use", GREEN.tone(&v)),
                    "remove" => ("remove", RED.tone(&v)),
                    _ => ("note", neutral_tone(&v)),
                };
                chip(ui, tr(langs.labels, label), tone);
                ui.label(advice_text(langs.help, a));
                ui.end_row();
            }
        });
}

//! Tools › Ping (G6.2): `/tool ping` of RouterOS, with more to look at.
//!
//! The window only *drives* engine tasks: Start sends `tool.ping.start`,
//! then the UI polls `tool.task.poll` (every [`POLL_SECS`], one request at a
//! time) and draws what came back — a latency chart per target (losses
//! marked), the statistics the engine computed, a histogram, the replies.
//! Alert thresholds (loss %, latency) are window state: they only colour
//! what is drawn. Closing the window stops its tasks (as WinBox does).

use std::collections::VecDeque;

use egui::{Color32, Grid, RichText, ScrollArea, TextEdit, Ui};
use egui_plot::{
    Bar, BarChart, HLine, Legend, Line, LineStyle, MarkerShape, Plot, PlotPoints, Points,
};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::table::action;
use crate::windows::combo;
use crate::{CoreRouterUi, Pending, Then, err_color, form_number, value_text};

/// Seconds between two polls of a running task.
pub(crate) const POLL_SECS: f64 = 0.25;
/// Points kept per target on the chart.
const MAX_POINTS: usize = 3600;
/// Replies kept for the table and the CSV export.
const MAX_REPLIES: usize = 20_000;
/// Rows the reply table shows (the newest).
const SHOWN_REPLIES: usize = 200;

/// One colour per target, readable on light and dark backgrounds; red is
/// left for losses.
pub(crate) const COLORS: [Color32; 8] = [
    Color32::from_rgb(0x1f, 0x77, 0xb4),
    Color32::from_rgb(0xff, 0x7f, 0x0e),
    Color32::from_rgb(0x2c, 0xa0, 0x2c),
    Color32::from_rgb(0x94, 0x67, 0xbd),
    Color32::from_rgb(0x17, 0xbe, 0xcf),
    Color32::from_rgb(0xbc, 0xbd, 0x22),
    Color32::from_rgb(0xe3, 0x77, 0xc2),
    Color32::from_rgb(0x8c, 0x56, 0x4b),
];
const LOSS: Color32 = Color32::from_rgb(0xd6, 0x27, 0x28);

pub(crate) fn color(i: usize) -> Color32 {
    COLORS
        .get(i % COLORS.len())
        .copied()
        .unwrap_or(Color32::GRAY)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    General,
    Advanced,
}

/// The form, as typed (the engine validates).
pub(crate) struct PingForm {
    pub(crate) tab: Tab,
    pub(crate) address: String,
    pub(crate) count: String,
    pub(crate) interval: String,
    pub(crate) size: String,
    pub(crate) timeout: String,
    pub(crate) ttl: String,
    pub(crate) dscp: String,
    pub(crate) dont_fragment: bool,
    pub(crate) src: String,
    pub(crate) interface: String,
    pub(crate) routing_table: String,
    pub(crate) loss_alert: String,
    pub(crate) latency_alert: String,
}

impl Default for PingForm {
    fn default() -> Self {
        Self {
            tab: Tab::General,
            address: String::new(),
            count: String::new(),
            interval: "1000".into(),
            size: "56".into(),
            timeout: "1000".into(),
            ttl: String::new(),
            dscp: String::new(),
            dont_fragment: false,
            src: String::new(),
            interface: String::new(),
            routing_table: String::new(),
            loss_alert: "10".into(),
            latency_alert: "100".into(),
        }
    }
}

/// A task the window follows.
#[derive(Debug, Clone, Default)]
pub(crate) struct TaskView {
    pub(crate) id: u64,
    pub(crate) after: u64,
    pub(crate) state: String,
    pub(crate) reason: Option<String>,
    pub(crate) done: bool,
    pub(crate) polling: bool,
    pub(crate) last_poll: f64,
    pub(crate) summary: Value,
    pub(crate) lost: u64,
}

impl TaskView {
    pub(crate) fn new(id: u64) -> Self {
        Self {
            id,
            state: "running".into(),
            ..Self::default()
        }
    }

    pub(crate) fn running(&self) -> bool {
        !self.done
    }

    /// Take a poll reply; returns its events.
    pub(crate) fn absorb(&mut self, p: &Value) -> Vec<Value> {
        self.polling = false;
        self.after = p
            .get("next_seq")
            .and_then(Value::as_u64)
            .unwrap_or(self.after);
        self.state = p.get("state").map(value_text).unwrap_or_default();
        self.reason = p.get("reason").and_then(Value::as_str).map(str::to_owned);
        self.done = p.get("done").and_then(Value::as_bool).unwrap_or(false);
        // Saturating: the count comes from the router (hostile input).
        self.lost = self
            .lost
            .saturating_add(p.get("lost").and_then(Value::as_u64).unwrap_or(0));
        if let Some(s) = p.get("summary").filter(|s| !s.is_null()) {
            self.summary = s.clone();
        }
        p.get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}

/// One target's chart data.
#[derive(Debug, Clone, Default)]
struct Series {
    host: String,
    points: VecDeque<[f64; 2]>,
    /// Ping sequence numbers that got no echo.
    lost: VecDeque<f64>,
}

/// Which request a tool reply answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolReq {
    Ping,
    Mtu,
    Mtr,
}

#[derive(Default)]
pub(crate) struct PingWin {
    pub(crate) form: PingForm,
    pub(crate) ping: Option<TaskView>,
    series: Vec<Series>,
    replies: VecDeque<Value>,
    pub(crate) mtu: Option<TaskView>,
    mtu_events: Vec<Value>,
    error: Option<String>,
    starting: bool,
    hist_target: usize,
    exports: u32,
}

fn num(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

fn ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "-".into())
}

/// A CSV field: quoted when it holds a comma, a quote or a line break.
/// Text a spreadsheet would run as a formula (`=`, `+`, `-`, `@`, tab, CR
/// first; a router's reply is not trusted) starts with `'` (OWASP "CSV
/// injection"); a number such as `-1` stays a number.
fn csv_field(s: &str) -> String {
    let formula = s.starts_with(['=', '+', '-', '@', '\t', '\r']) && s.parse::<f64>().is_err();
    let s = if formula {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// Alert of one target's summary against the thresholds, if any.
fn alert(t: &Value, loss_pct: Option<f64>, latency_ms: Option<f64>) -> Option<String> {
    let mut out = Vec::new();
    if let (Some(limit), Some(loss)) = (loss_pct, num(t, "loss_pct"))
        && t.get("finished").and_then(Value::as_u64).unwrap_or(0) > 0
        && loss > limit
    {
        out.push(format!("loss {loss:.1}% > {limit}%"));
    }
    if let Some(limit) = latency_ms
        && let Some(lat) = [num(t, "avg_ms"), num(t, "last_ms")]
            .into_iter()
            .flatten()
            .reduce(f64::max)
        && lat > limit
    {
        out.push(format!("latency {lat:.1} ms > {limit} ms"));
    }
    (!out.is_empty()).then(|| out.join(", "))
}

fn threshold(s: &str) -> Option<f64> {
    s.trim()
        .parse::<f64>()
        .ok()
        .filter(|x| x.is_finite() && *x >= 0.0)
}

impl PingWin {
    /// The replies as CSV, oldest first.
    pub(crate) fn csv(&self) -> String {
        let mut out = String::from("target,host,address,seq,status,rtt_ms,size,ttl,from,detail\n");
        for r in &self.replies {
            let f = |k: &str| csv_field(&r.get(k).map(value_text).unwrap_or_default());
            let line = [
                "target", "host", "address", "icmp_seq", "status", "rtt_ms", "size", "ttl", "from",
                "detail",
            ]
            .map(f)
            .join(",");
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    fn reset(&mut self, id: u64, hosts: Vec<String>) {
        self.ping = Some(TaskView::new(id));
        self.series = hosts
            .into_iter()
            .map(|host| Series {
                host,
                ..Series::default()
            })
            .collect();
        self.replies.clear();
        self.hist_target = 0;
    }

    fn take_events(&mut self, events: Vec<Value>) {
        for ev in events {
            // `try_from`: on wasm32 an `as` cast would wrap 2^32 to target 0.
            let target = usize::try_from(ev.get("target").and_then(Value::as_u64).unwrap_or(0)).ok();
            let seq = num(&ev, "icmp_seq");
            if let (Some(s), Some(x)) = (target.and_then(|t| self.series.get_mut(t)), seq) {
                match (ev.get("status").and_then(Value::as_str), num(&ev, "rtt_ms")) {
                    (Some("ok"), Some(rtt)) => {
                        s.points.push_back([x, rtt]);
                        if s.points.len() > MAX_POINTS {
                            s.points.pop_front();
                        }
                    }
                    _ => {
                        s.lost.push_back(x);
                        if s.lost.len() > MAX_POINTS {
                            s.lost.pop_front();
                        }
                    }
                }
            }
            self.replies.push_back(ev);
            if self.replies.len() > MAX_REPLIES {
                self.replies.pop_front();
            }
        }
    }
}

impl CoreRouterUi {
    /// Send a poll for `req` (not logged: it is not an operator action).
    fn tool_poll(&mut self, req: ToolReq, id: u64, after: u64) -> RequestId {
        let rid = self.backend.submit(
            "engine.execute",
            json!({"command": "tool.task.poll", "params": {"id": id, "after_seq": after}}),
        );
        self.pending.insert(rid, Pending::Tool(req));
        rid
    }

    /// Every frame: poll the running tasks, keep frames coming while they run.
    pub(crate) fn tools_tick(&mut self, ctx: &egui::Context, now: f64) {
        let mut due = Vec::new();
        for (req, task) in [
            (ToolReq::Ping, self.ping.ping.as_mut()),
            (ToolReq::Mtu, self.ping.mtu.as_mut()),
            (ToolReq::Mtr, self.mtr.task.as_mut()),
        ] {
            let Some(t) = task else { continue };
            if t.running() {
                ctx.request_repaint_after(std::time::Duration::from_secs_f64(POLL_SECS));
                if !t.polling && now - t.last_poll >= POLL_SECS {
                    t.polling = true;
                    t.last_poll = now;
                    due.push((req, t.id, t.after));
                }
            }
        }
        for (req, id, after) in due {
            self.tool_poll(req, id, after);
        }
    }

    /// A poll got no answer in time: poll again (the task may be fine;
    /// only an error reply ends it).
    pub(crate) fn tool_timed_out(&mut self, req: ToolReq) {
        let task = match req {
            ToolReq::Ping => self.ping.ping.as_mut(),
            ToolReq::Mtu => self.ping.mtu.as_mut(),
            ToolReq::Mtr => self.mtr.task.as_mut(),
        };
        if let Some(t) = task {
            t.polling = false;
        }
    }

    pub(crate) fn tool_reply(&mut self, req: ToolReq, result: Result<Value, String>) {
        if req == ToolReq::Mtr {
            return self.mtr_reply(result);
        }
        let w = &mut self.ping;
        let task = match req {
            ToolReq::Ping => w.ping.as_mut(),
            ToolReq::Mtu | ToolReq::Mtr => w.mtu.as_mut(),
        };
        let Some(task) = task else { return };
        match result {
            Ok(p) => {
                // A reply for an older task (restarted meanwhile) is dropped.
                if p.get("id").and_then(Value::as_u64) != Some(task.id) {
                    task.polling = false;
                    return;
                }
                let events = task.absorb(&p);
                match req {
                    ToolReq::Ping => w.take_events(events),
                    ToolReq::Mtu | ToolReq::Mtr => w.mtu_events.extend(events),
                }
            }
            Err(e) => {
                // The task is gone (router restarted, expired): stop following it.
                task.polling = false;
                task.done = true;
                task.state = "lost".into();
                task.reason = Some(e);
            }
        }
    }

    pub(crate) fn tool_started(&mut self, req: ToolReq, result: &Result<Value, String>) {
        if req == ToolReq::Mtr {
            return self.mtr_started(result);
        }
        let w = &mut self.ping;
        w.starting = false;
        match result {
            Ok(r) => {
                let Some(id) = r.get("task_id").and_then(Value::as_u64) else {
                    w.error = Some(format!("the router started no task: {r}"));
                    return;
                };
                w.error = None;
                match req {
                    ToolReq::Ping => {
                        let hosts = r
                            .get("targets")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .map(value_text)
                            .collect();
                        w.reset(id, hosts);
                    }
                    ToolReq::Mtu | ToolReq::Mtr => {
                        w.mtu = Some(TaskView::new(id));
                        w.mtu_events.clear();
                    }
                }
            }
            Err(e) => w.error = Some(e.clone()),
        }
    }

    /// The window closed: stop what it was running.
    pub(crate) fn ping_closed(&mut self) {
        let running: Vec<u64> = [&self.ping.ping, &self.ping.mtu]
            .into_iter()
            .flatten()
            .filter(|t| t.running())
            .map(|t| t.id)
            .collect();
        for id in running {
            self.run("tool.task.stop", json!({ "id": id }));
        }
    }

    fn ping_params(&self) -> Value {
        let f = &self.ping.form;
        let text = |s: &str| {
            let s = s.trim();
            (!s.is_empty()).then(|| json!(s))
        };
        json!({
            "address": f.address.trim(),
            "count": form_number(&f.count),
            "interval_ms": form_number(&f.interval),
            "size": form_number(&f.size),
            "timeout_ms": form_number(&f.timeout),
            "ttl": form_number(&f.ttl),
            "dscp": form_number(&f.dscp),
            "do_not_fragment": f.dont_fragment.then_some(true),
            "src_address": text(&f.src),
            "interface": text(&f.interface),
            "routing_table": text(&f.routing_table),
        })
    }

    /// Start (Enter), unless a ping runs or is being started.
    pub(crate) fn ping_start(&mut self) {
        if self.ping.starting || self.ping.ping.as_ref().is_some_and(TaskView::running) {
            return;
        }
        let mut p = self.ping_params();
        if let Value::Object(o) = &mut p {
            o.retain(|_, v| !v.is_null());
        }
        self.ping.starting = true;
        self.run_then("tool.ping.start", p, Then::Tool(ToolReq::Ping));
    }

    /// Stop (Esc) the running ping; `false` if none ran.
    pub(crate) fn ping_stop(&mut self) -> bool {
        match &self.ping.ping {
            Some(t) if t.running() => {
                let id = t.id;
                self.run("tool.task.stop", json!({ "id": id }));
                true
            }
            _ => false,
        }
    }

    fn mtu_start(&mut self) {
        let mut p = self.ping_params();
        let first = self
            .ping
            .form
            .address
            .split(',')
            .map(str::trim)
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_owned();
        if let Value::Object(o) = &mut p {
            o.retain(|k, v| {
                !v.is_null()
                    && matches!(
                        k.as_str(),
                        "timeout_ms" | "dscp" | "src_address" | "interface" | "routing_table"
                    )
            });
            o.insert("address".into(), json!(first));
        }
        self.run_then("tool.ping.mtu", p, Then::Tool(ToolReq::Mtu));
    }

    /// Queue the replies as a CSV for the app to save (native: a file;
    /// web: a download).
    fn ping_export(&mut self) {
        self.ping.exports += 1;
        let name = format!("ping-{}.csv", self.ping.exports);
        let csv = self.ping.csv();
        let rows = self.ping.replies.len();
        self.exports.push(crate::Export {
            file_name: name.clone(),
            mime: "text/csv",
            bytes: csv.into_bytes(),
        });
        self.push_log(crate::LogLine {
            ok: true,
            command: "export".into(),
            message: format!("{name}: {rows} replies"),
        });
    }

    pub(crate) fn ping_window(&mut self, ui: &mut Ui) {
        let can = self.can();
        let running = self.ping.ping.as_ref().is_some_and(TaskView::running);
        let mtu_running = self.ping.mtu.as_ref().is_some_and(TaskView::running);
        let interfaces = self.interface_names(None);
        let mut tables = vec!["main".to_owned()];
        tables.extend(self.interface_names(Some("vrf")));

        let f = &mut self.ping.form;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut f.tab, Tab::General, "General");
            ui.selectable_value(&mut f.tab, Tab::Advanced, "Advanced");
        });
        ui.separator();
        if f.tab == Tab::General {
            ui.horizontal(|ui| {
                ui.label("Address");
                ui.add(
                    TextEdit::singleline(&mut f.address)
                        .id(crate::dialog::field_id(
                            crate::win_id(crate::Win::Ping),
                            "address",
                        ))
                        .hint_text("8.8.8.8, 1.1.1.1, example.com (comma separated)")
                        .desired_width(420.0),
                );
            });
        }
        Grid::new("ping-form")
            .num_columns(4)
            .spacing([12.0, 4.0])
            .show(ui, |ui| match f.tab {
                Tab::General => {
                    ui.label("Count");
                    ui.add(
                        TextEdit::singleline(&mut f.count)
                            .hint_text("until stopped")
                            .desired_width(90.0),
                    );
                    ui.end_row();
                    ui.label("Interval (ms)");
                    ui.add(TextEdit::singleline(&mut f.interval).desired_width(90.0));
                    ui.label("Size");
                    ui.add(TextEdit::singleline(&mut f.size).desired_width(90.0))
                        .on_hover_text("Whole IP packet, in bytes (as RouterOS)");
                    ui.end_row();
                    ui.label("Alert: loss >");
                    ui.horizontal(|ui| {
                        ui.add(TextEdit::singleline(&mut f.loss_alert).desired_width(50.0));
                        ui.label("%");
                    });
                    ui.label("latency >");
                    ui.horizontal(|ui| {
                        ui.add(TextEdit::singleline(&mut f.latency_alert).desired_width(50.0));
                        ui.label("ms");
                    });
                    ui.end_row();
                }
                Tab::Advanced => {
                    ui.label("TTL");
                    ui.add(
                        TextEdit::singleline(&mut f.ttl)
                            .hint_text("64")
                            .desired_width(90.0),
                    );
                    ui.label("DSCP");
                    ui.add(
                        TextEdit::singleline(&mut f.dscp)
                            .hint_text("0")
                            .desired_width(90.0),
                    );
                    ui.end_row();
                    ui.label("Timeout (ms)");
                    ui.add(TextEdit::singleline(&mut f.timeout).desired_width(90.0));
                    ui.label("");
                    ui.checkbox(&mut f.dont_fragment, "Do not fragment");
                    ui.end_row();
                    ui.label("Src. address");
                    ui.add(
                        TextEdit::singleline(&mut f.src)
                            .hint_text("any")
                            .desired_width(140.0),
                    );
                    ui.label("Interface");
                    ui.horizontal(|ui| {
                        let mut names = vec![String::new()];
                        names.extend(interfaces);
                        combo(ui, "ping-iface", "any", &mut f.interface, &names);
                    });
                    ui.end_row();
                    ui.label("Routing table");
                    combo(ui, "ping-table", "main", &mut f.routing_table, &tables);
                    ui.end_row();
                }
            });
        ui.separator();
        let mut start = false;
        let mut stop = false;
        let mut mtu = false;
        let mut export = false;
        ui.horizontal(|ui| {
            let start_ok = if running {
                Err("already running: Stop first".to_owned())
            } else if self.ping.form.address.trim().is_empty() {
                Err("Type an address first".to_owned())
            } else {
                Ok(())
            };
            start = action(ui, "Start", can.and("tool.ping.start", start_ok));
            let stop_ok = if running {
                Ok(())
            } else {
                Err("not running".to_owned())
            };
            stop = action(ui, "Stop", can.and("tool.task.stop", stop_ok));
            ui.separator();
            let mtu_ok = if mtu_running {
                Err("searching…".to_owned())
            } else if self.ping.form.address.trim().is_empty() {
                Err("Type an address first".to_owned())
            } else {
                Ok(())
            };
            mtu = action(ui, "Discover MTU", can.and("tool.ping.mtu", mtu_ok));
            let export_ok = if self.ping.replies.is_empty() {
                Err("nothing to export yet".to_owned())
            } else {
                Ok(())
            };
            export = action(ui, "Export CSV", export_ok);
            ui.separator();
            if let Some(t) = &self.ping.ping {
                let text = match (&t.reason, t.state.as_str()) {
                    (Some(r), "failed" | "lost") => format!("{}: {r}", t.state),
                    (_, s) => format!("task {} {s}", t.id),
                };
                if matches!(t.state.as_str(), "failed" | "lost") {
                    ui.colored_label(err_color(ui), text);
                } else {
                    ui.weak(text);
                }
            }
        });
        if start {
            self.ping_start();
        }
        if stop {
            self.ping_stop();
        }
        if mtu {
            self.mtu_start();
        }
        if export {
            self.ping_export();
        }
        if let Some(e) = &self.ping.error {
            ui.colored_label(err_color(ui), e.as_str());
        }
        self.mtu_line(ui);
        ui.separator();
        self.ping_chart(ui);
        self.ping_stats(ui);
        ui.separator();
        ui.columns(2, |cols| {
            if let [left, right] = cols {
                self.ping_histogram(left);
                self.ping_replies(right);
            }
        });
    }

    fn mtu_line(&self, ui: &mut Ui) {
        let Some(t) = &self.ping.mtu else { return };
        let s = &t.summary;
        let text = match (t.state.as_str(), s.get("mtu").and_then(Value::as_u64)) {
            ("done", Some(m)) => format!(
                "Path MTU to {}: {m} bytes (ICMP payload {}), {} probes",
                s.get("address").map(value_text).unwrap_or_default(),
                s.get("payload").map(value_text).unwrap_or_default(),
                s.get("probes").map(value_text).unwrap_or_default()
            ),
            ("failed" | "lost", _) => {
                let why = t.reason.clone().unwrap_or_default();
                ui.colored_label(err_color(ui), format!("MTU discovery failed: {why}"));
                return;
            }
            (_, best) => format!(
                "Discovering MTU… largest so far {}, {} probes",
                best.map(|b| b.to_string()).unwrap_or_else(|| "-".into()),
                self.ping.mtu_events.len()
            ),
        };
        ui.label(RichText::new(text).strong());
    }

    fn ping_chart(&self, ui: &mut Ui) {
        let latency = threshold(&self.ping.form.latency_alert);
        let series = &self.ping.series;
        let top = series
            .iter()
            .flat_map(|s| s.points.iter().map(|p| p[1]))
            .fold(1.0f64, f64::max);
        Plot::new("ping-chart")
            .height(180.0)
            .legend(Legend::default())
            .include_y(0.0)
            .include_x(0.0)
            .include_x(10.0)
            .y_axis_label("ms")
            .x_axis_label("seq")
            .allow_scroll(false)
            .show(ui, |p| {
                for (i, s) in series.iter().enumerate() {
                    let pts: Vec<[f64; 2]> = s.points.iter().copied().collect();
                    p.line(
                        Line::new(s.host.clone(), PlotPoints::from(pts))
                            .color(color(i))
                            .width(1.5),
                    );
                    if !s.lost.is_empty() {
                        let lost: Vec<[f64; 2]> = s.lost.iter().map(|x| [*x, top]).collect();
                        p.points(
                            Points::new(format!("{} lost", s.host), PlotPoints::from(lost))
                                .shape(MarkerShape::Cross)
                                .color(LOSS)
                                .radius(4.0),
                        );
                    }
                }
                if let Some(l) = latency {
                    p.hline(
                        HLine::new("latency alert", l)
                            .color(LOSS.gamma_multiply(0.6))
                            .style(LineStyle::dashed_loose()),
                    );
                }
            });
    }

    fn ping_stats(&self, ui: &mut Ui) {
        let Some(t) = &self.ping.ping else {
            ui.weak("Type one or more addresses (comma separated) and press Start (Enter).");
            return;
        };
        let loss = threshold(&self.ping.form.loss_alert);
        let latency = threshold(&self.ping.form.latency_alert);
        let empty = Vec::new();
        let targets = t
            .summary
            .get("targets")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        Grid::new("ping-stats")
            .striped(true)
            .spacing([10.0, 2.0])
            .show(ui, |ui| {
                for h in [
                    "", "Host", "Sent", "Recv", "Loss %", "Min", "Avg", "Max", "Jitter", "StdDev",
                    "p50", "p95", "p99", "Last", "",
                ] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, s) in targets.iter().enumerate() {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 2.0, color(i));
                    let host = s.get("host").map(value_text).unwrap_or_default();
                    let addr = s.get("address").map(value_text).unwrap_or_default();
                    let label = if addr.is_empty() || addr == host {
                        host
                    } else {
                        format!("{host} ({addr})")
                    };
                    ui.label(label);
                    let g = |k: &str| s.get(k).map(value_text).unwrap_or_default();
                    ui.label(g("sent"));
                    ui.label(g("received"));
                    ui.label(format!("{:.1}", num(s, "loss_pct").unwrap_or(0.0)));
                    for k in [
                        "min_ms",
                        "avg_ms",
                        "max_ms",
                        "jitter_ms",
                        "stddev_ms",
                        "p50_ms",
                        "p95_ms",
                        "p99_ms",
                        "last_ms",
                    ] {
                        ui.label(ms(num(s, k)));
                    }
                    if let Some(e) = s.get("error").and_then(Value::as_str) {
                        ui.colored_label(err_color(ui), e);
                    } else if let Some(a) = alert(s, loss, latency) {
                        let tone = crate::chip::RED.tone(ui.visuals());
                        crate::chip::chip(ui, "alerta", tone).on_hover_text(a);
                    } else {
                        ui.label("");
                    }
                    ui.end_row();
                }
            });
        if t.lost > 0 {
            ui.weak(format!(
                "{} replies were not shown (the window fell behind)",
                t.lost
            ));
        }
    }

    fn ping_histogram(&mut self, ui: &mut Ui) {
        let Some(t) = &self.ping.ping else { return };
        let empty = Vec::new();
        let targets = t
            .summary
            .get("targets")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let names: Vec<String> = targets
            .iter()
            .map(|s| s.get("host").map(value_text).unwrap_or_default())
            .collect();
        ui.horizontal(|ui| {
            ui.strong("Histogram");
            let pick = names
                .get(self.ping.hist_target)
                .cloned()
                .unwrap_or_default();
            egui::ComboBox::from_id_salt("ping-hist")
                .selected_text(pick)
                .show_ui(ui, |ui| {
                    for (i, n) in names.iter().enumerate() {
                        ui.selectable_value(&mut self.ping.hist_target, i, n);
                    }
                });
        });
        let Some(s) = targets.get(self.ping.hist_target) else {
            return;
        };
        let h = s.get("histogram").cloned().unwrap_or(Value::Null);
        let bounds: Vec<f64> = h
            .get("bounds_ms")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .collect();
        let counts: Vec<f64> = h
            .get("counts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .collect();
        let label = |i: usize| match (i.checked_sub(1).and_then(|j| bounds.get(j)), bounds.get(i)) {
            (None, Some(hi)) => format!("<{hi}"),
            (Some(lo), Some(hi)) => format!("{lo}-{hi}"),
            (Some(lo), None) => format!(">{lo}"),
            (None, None) => String::new(),
        };
        let bars: Vec<Bar> = counts
            .iter()
            .enumerate()
            .map(|(i, c)| {
                Bar::new(i as f64, *c)
                    .name(format!("{} ms", label(i)))
                    .width(0.8)
            })
            .collect();
        let labels: Vec<String> = (0..counts.len()).map(label).collect();
        let n = counts.len();
        Plot::new("ping-histogram")
            .height(140.0)
            .allow_scroll(false)
            .allow_drag(false)
            .allow_zoom(false)
            .include_y(0.0)
            // One mark per bar, so every bucket is named.
            .x_grid_spacer(move |_| {
                (0..n)
                    .map(|i| egui_plot::GridMark {
                        value: i as f64,
                        step_size: 1.0,
                    })
                    .collect()
            })
            .x_axis_formatter(move |mark, _| {
                labels
                    .get(mark.value.round() as usize)
                    .cloned()
                    .unwrap_or_default()
            })
            .show(ui, |p| {
                p.bar_chart(BarChart::new("replies", bars).color(color(self.ping.hist_target)));
            });
    }

    fn ping_replies(&self, ui: &mut Ui) {
        ui.strong("Replies");
        ScrollArea::vertical()
            .id_salt("ping-replies")
            .max_height(140.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                Grid::new("ping-replies-grid").striped(true).show(ui, |ui| {
                    for h in ["Seq", "Host", "Size", "TTL", "Time", "Status"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    let skip = self.ping.replies.len().saturating_sub(SHOWN_REPLIES);
                    for r in self.ping.replies.iter().skip(skip) {
                        let g = |k: &str| r.get(k).map(value_text).unwrap_or_default();
                        ui.label(g("icmp_seq"));
                        ui.label(g("host"));
                        ui.label(g("size"));
                        ui.label(g("ttl"));
                        ui.label(ms(num(r, "rtt_ms")));
                        let status = g("status");
                        if status == "ok" {
                            ui.label(status);
                        } else {
                            let detail = g("detail");
                            let from = g("from");
                            let mut t = if detail.is_empty() { status } else { detail };
                            if !from.is_empty() {
                                t = format!("{t} from {from}");
                            }
                            ui.colored_label(err_color(ui), t);
                        }
                        ui.end_row();
                    }
                });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_what_needs_it() {
        assert_eq!(csv_field("8.8.8.8"), "8.8.8.8");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("=1+1"), "'=1+1");
        assert_eq!(csv_field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_field("-1"), "-1");
        assert_eq!(csv_field("+cmd,x"), "\"'+cmd,x\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        let mut w = PingWin::default();
        w.reset(1, vec!["x".into()]);
        w.take_events(vec![
            json!({"target": 0, "host": "x", "icmp_seq": 0, "status": "ok",
            "rtt_ms": 1.5, "size": 56, "ttl": 64}),
        ]);
        let csv = w.csv();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next(),
            Some("target,host,address,seq,status,rtt_ms,size,ttl,from,detail")
        );
        assert_eq!(lines.next(), Some("0,x,,0,ok,1.5,56,64,,"));
    }

    #[test]
    fn alerts_follow_the_thresholds() {
        let t = json!({"finished": 10, "loss_pct": 20.0, "avg_ms": 50.0, "last_ms": 150.0});
        assert_eq!(
            alert(&t, Some(10.0), Some(100.0)).unwrap(),
            "loss 20.0% > 10%, latency 150.0 ms > 100 ms"
        );
        assert_eq!(alert(&t, Some(30.0), Some(200.0)), None);
        assert_eq!(alert(&t, None, None), None);
        assert_eq!(threshold(" 5 "), Some(5.0));
        assert_eq!(threshold("x"), None);
        assert_eq!(threshold("-1"), None);
    }
}

//! Tools › Bandwidth Test (G6.4b): a throughput test with the iperf3
//! protocol, against any `iperf3 -s` or another CoreRouter, and (tab
//! Server) this router's own iperf3 server.
//!
//! Test: address, protocol, direction, streams, duration and rate, each
//! with its ⓘ. Start asks first ("this fills the path for N s"); the
//! engine refuses a test through the port of this connection outside Safe
//! Mode. While it runs, a chart of Tx/Rx per second, the router's CPU and,
//! for UDP, loss and jitter; at the end what the far end saw.
//!
//! Server: `tool.bandwidth-server.set` (off by default; needs the prefixes
//! that may test) and its status from `tool.bandwidth-server.get`.

use egui::{Id, TextEdit, Ui};
use egui_plot::{Legend, Line, Plot, PlotPoints};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::torch::rate;
use crate::windows::combo;
use crate::{CoreRouterUi, Win, err_color};

const NAME: &str = "bandwidth";
pub(crate) const WIN: &str = "bandwidth";
const START: &str = "tool.bandwidth-test.start";
const STOP: &str = "tool.task.stop";
const SERVER_GET: &str = "tool.bandwidth-server.get";
const SERVER_SET: &str = "tool.bandwidth-server.set";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "Bandwidth Test",
        size: [820.0, 560.0],
        escape: true,
    }],
    new: || Box::new(BandwidthPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Test,
    Server,
}

/// The Server tab's form.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct ServerForm {
    pub enabled: bool,
    pub port: String,
    pub allowed: String,
    pub max_duration: String,
    pub max_streams: String,
    pub max_rate: String,
}

impl ServerForm {
    fn of(v: &Value) -> Self {
        let t = |k: &str| v.get(k).map(crate::value_text).unwrap_or_default();
        Self {
            enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            port: t("port"),
            allowed: v
                .get("allowed_addresses")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                .unwrap_or_default(),
            max_duration: t("max_duration"),
            max_streams: t("max_streams"),
            max_rate: t("max_rate"),
        }
    }

    pub(crate) fn params(&self) -> Value {
        let num = |s: &str| s.trim().parse::<u64>().map_or_else(|_| json!(s.trim()), |n| json!(n));
        json!({
            "enabled": self.enabled,
            "port": num(&self.port),
            "allowed_addresses": self.allowed.trim(),
            "max_duration": num(&self.max_duration),
            "max_streams": num(&self.max_streams),
            "max_rate": self.max_rate.trim(),
        })
    }
}

pub(crate) struct BandwidthPanel {
    pub(crate) tab: Tab,
    pub(crate) address: String,
    pub(crate) port: String,
    pub(crate) protocol: String,
    pub(crate) direction: String,
    pub(crate) streams: String,
    pub(crate) duration: String,
    pub(crate) bandwidth: String,
    /// The Start confirmation is open.
    pub(crate) confirm: bool,
    pub(crate) task: Option<u64>,
    pub(crate) starting: bool,
    pub(crate) done: bool,
    pub(crate) state: String,
    pub(crate) summary: Value,
    /// The engine's words on what the test does to the path.
    pub(crate) warning: String,
    pub(crate) error: Option<String>,
    pub(crate) server: Value,
    pub(crate) server_form: Option<ServerForm>,
    pub(crate) server_error: Option<String>,
    pub(crate) help: Option<HelpView>,
}

impl Default for BandwidthPanel {
    fn default() -> Self {
        Self {
            tab: Tab::Test,
            address: String::new(),
            port: "5201".into(),
            protocol: "tcp".into(),
            direction: "send".into(),
            streams: "1".into(),
            duration: "10".into(),
            bandwidth: String::new(),
            confirm: false,
            task: None,
            starting: false,
            done: false,
            state: String::new(),
            summary: Value::Null,
            warning: String::new(),
            error: None,
            server: Value::Null,
            server_form: None,
            server_error: None,
            help: None,
        }
    }
}

struct Started;
struct Stopped;
struct Saved;

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

impl BandwidthPanel {
    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    /// `tool.bandwidth-test.start`'s parameters from the form.
    pub(crate) fn params(&self) -> Value {
        let mut m = Map::new();
        m.insert("address".into(), json!(self.address.trim()));
        for (k, v) in [("port", &self.port), ("streams", &self.streams), ("duration", &self.duration)] {
            let v = v.trim();
            if !v.is_empty() {
                m.insert(k.into(), v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n)));
            }
        }
        m.insert("protocol".into(), json!(self.protocol));
        m.insert("direction".into(), json!(self.direction));
        if !self.bandwidth.trim().is_empty() {
            m.insert("bandwidth".into(), json!(self.bandwidth.trim()));
        }
        Value::Object(m)
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str) {
        if help::info_button(ui, Id::unique(("bw-help", key)), tr(l, title)).clicked() {
            self.help = Some(HelpView::new(format!("bandwidth.{key}"), tr(l, title)));
        }
    }

    fn field(&mut self, ui: &mut Ui, l: Lang, key: &str, label: &'static str, hint: &str, width: f32) {
        let on = !self.running();
        ui.label(tr(l, label));
        let value = match key {
            "address" => &mut self.address,
            "port" => &mut self.port,
            "streams" => &mut self.streams,
            "duration" => &mut self.duration,
            _ => &mut self.bandwidth,
        };
        ui.add_enabled(on, TextEdit::singleline(value).hint_text(hint).desired_width(width));
        self.info(ui, l, key, label);
    }

    fn test_form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let on = !self.running();
        ui.horizontal_wrapped(|ui| {
            self.field(ui, l, "address", "Address", "iperf3 server (IP or name)", 200.0);
            self.field(ui, l, "port", "Port", "5201", 50.0);
            ui.label(tr(l, "Protocol"));
            ui.add_enabled_ui(on, |ui| {
                let opts = ["tcp".to_owned(), "udp".to_owned()];
                combo(ui, "bw-proto", "tcp", &mut self.protocol, &opts);
            });
            self.info(ui, l, "protocol", "Protocol");
            ui.label(tr(l, "Direction"));
            ui.add_enabled_ui(on, |ui| {
                let opts = ["send".to_owned(), "receive".to_owned(), "both".to_owned()];
                combo(ui, "bw-dir", "send", &mut self.direction, &opts);
            });
            self.info(ui, l, "direction", "Direction");
        });
        ui.horizontal_wrapped(|ui| {
            self.field(ui, l, "streams", "Streams", "1", 40.0);
            self.field(ui, l, "duration", "Duration (s)", "10", 40.0);
            let hint = if self.protocol == "udp" { "10M" } else { tr(l, "unlimited") };
            self.field(ui, l, "bandwidth", "Rate per stream", hint, 80.0);
            ui.separator();
            if self.running() {
                if ui.button(tr(l, "Stop")).clicked()
                    && let Some(id) = self.task
                {
                    app.run_then(STOP, json!({"id": id}), crate::panel::then(NAME, Stopped));
                }
            } else {
                let ready = if self.address.trim().is_empty() {
                    Err(tr(l, "Type the server's address first").to_owned())
                } else {
                    Ok(())
                };
                let check = app.can().and(START, ready);
                if ui
                    .add_enabled(check.is_ok() && !self.starting, egui::Button::new(tr(l, "Start")))
                    .on_disabled_hover_text(check.err().unwrap_or_default())
                    .clicked()
                {
                    self.confirm = true;
                }
            }
        });
    }

    pub(crate) fn start(&mut self, app: &mut CoreRouterUi) {
        self.starting = true;
        self.confirm = false;
        self.error = None;
        self.summary = Value::Null;
        self.warning.clear();
        self.done = false;
        self.state.clear();
        app.run_then(START, self.params(), crate::panel::then(NAME, Started));
    }

    fn chart(&self, ui: &mut Ui, l: Lang) {
        let samples = self
            .summary
            .get("samples")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let series = |k: &str| -> Vec<[f64; 2]> {
            samples
                .iter()
                .filter_map(|s| Some([f(s, "t")?, f(s, k)? / 1e6]))
                .collect()
        };
        let duration = f(&self.summary, "duration").unwrap_or(10.0);
        let (tx_ink, rx_ink) = (chip::BLUE.tone(ui.visuals()).ink, chip::GREEN.tone(ui.visuals()).ink);
        Plot::new("bw-chart")
            .height(200.0)
            .legend(Legend::default())
            .include_y(0.0)
            .include_x(0.0)
            .include_x(duration)
            .y_axis_label("Mbit/s")
            .x_axis_label("s")
            .allow_scroll(false)
            .show(ui, |p| {
                let tx = series("tx_bps");
                if tx.iter().any(|x| x[1] > 0.0) {
                    p.line(Line::new(tr(l, "Tx"), PlotPoints::from(tx)).color(tx_ink).width(2.0));
                }
                let rx = series("rx_bps");
                if rx.iter().any(|x| x[1] > 0.0) {
                    p.line(Line::new(tr(l, "Rx"), PlotPoints::from(rx)).color(rx_ink).width(2.0));
                }
            });
    }

    fn status(&mut self, ui: &mut Ui, l: Lang) {
        let s = self.summary.clone();
        ui.horizontal_wrapped(|ui| {
            if !self.state.is_empty() {
                let tone = match self.state.as_str() {
                    "running" => chip::GREEN.tone(ui.visuals()),
                    "failed" | "lost" => chip::RED.tone(ui.visuals()),
                    _ => chip::neutral_tone(ui.visuals()),
                };
                chip::chip(ui, &self.state, tone);
            }
            if let Some(b) = s.get("backend").and_then(Value::as_str) {
                chip::chip(ui, b, chip::neutral_tone(ui.visuals()));
            }
            if let (Some(avg), Some(max)) = (f(&s, "cpu_avg"), f(&s, "cpu_max")) {
                let tone = if max >= 90.0 { chip::RED } else if max >= 70.0 { chip::AMBER } else { chip::GREEN };
                chip::chip(ui, &format!("{} {avg:.0}% (max {max:.0}%)", tr(l, "router CPU")), tone.tone(ui.visuals()))
                    .on_hover_text(tr(l, "All cores of this router while the test ran"));
            }
            if let Some(r) = f(&s, "remote_cpu") {
                chip::chip(ui, &format!("{} {r:.0}%", tr(l, "remote CPU")), chip::neutral_tone(ui.visuals()))
                    .on_hover_text(tr(l, "What the far end reported (iperf3: its own process)"));
            }
        });
        if !self.warning.is_empty() && self.running() {
            ui.colored_label(ui.visuals().warn_fg_color, &self.warning);
        }
        if let Some(e) = &self.error {
            ui.colored_label(err_color(ui), e);
        }
    }

    /// One line per direction: averages, peaks, UDP loss and jitter.
    fn results(&mut self, ui: &mut Ui, l: Lang) {
        let s = self.summary.clone();
        egui::Grid::new("bw-results").num_columns(6).striped(true).show(ui, |ui| {
            for h in ["", "Average", "Peak", "Loss", "Jitter", "Retransmits"] {
                ui.strong(tr(l, h));
            }
            ui.end_row();
            for (label, way, avg, peak) in [
                ("Tx", "upload", "tx_avg_bps", "tx_peak_bps"),
                ("Rx", "download", "rx_avg_bps", "rx_peak_bps"),
            ] {
                let w = s.get(way).filter(|w| !w.is_null());
                let live = f(&s, avg).unwrap_or(0.0);
                if w.is_none() && live == 0.0 {
                    continue;
                }
                ui.label(tr(l, label));
                // At the end, what the receiver got; while running, ours.
                let shown = w.and_then(|w| f(w, "received_bps")).unwrap_or(live);
                ui.label(rate(shown));
                ui.label(rate(f(&s, peak).unwrap_or(0.0)));
                let loss = w.and_then(|w| f(w, "loss_pct"));
                match loss {
                    Some(p) => {
                        let tone = if p >= 1.0 { chip::RED } else if p > 0.0 { chip::AMBER } else { chip::GREEN };
                        chip::chip(ui, &format!("{p:.1} %"), tone.tone(ui.visuals()));
                    }
                    None => {
                        ui.weak("–");
                    }
                }
                ui.label(w.and_then(|w| f(w, "jitter_ms")).map_or("–".into(), |j| format!("{j:.3} ms")));
                ui.label(
                    w.and_then(|w| w.get("retransmits"))
                        .filter(|r| !r.is_null())
                        .map_or("–".into(), crate::value_text),
                );
                ui.end_row();
            }
        });
        self.info(ui, l, "results", "Results");
    }

    fn server_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        if self.server_form.is_none() && !self.server.is_null() {
            self.server_form = Some(ServerForm::of(&self.server));
        }
        let st = self.server.get("status").cloned().unwrap_or(Value::Null);
        ui.horizontal_wrapped(|ui| {
            let state = st.get("state").and_then(Value::as_str).unwrap_or("stopped");
            let tone = match state {
                "listening" => chip::GREEN.tone(ui.visuals()),
                "testing" => chip::BLUE.tone(ui.visuals()),
                "failed" => chip::RED.tone(ui.visuals()),
                _ => chip::neutral_tone(ui.visuals()),
            };
            chip::chip(ui, state, tone);
            if let Some(at) = st.get("listening").and_then(Value::as_str) {
                ui.label(at);
            }
            ui.label(format!(
                "{} {}  ·  {} {}",
                st.get("tests_served").and_then(Value::as_u64).unwrap_or(0),
                tr(l, "tests served"),
                st.get("refused").and_then(Value::as_u64).unwrap_or(0),
                tr(l, "refused"),
            ));
            self.info(ui, l, "server", "Bandwidth Server");
        });
        for (title, key) in [("Now", "current"), ("Last test", "last")] {
            if let Some(t) = st.get(key).filter(|t| !t.is_null()) {
                let g = |k: &str| t.get(k).map(crate::value_text).unwrap_or_default();
                ui.label(format!(
                    "{}: {} {} {} · {} streams · {} s · {} bytes",
                    tr(l, title),
                    g("client"),
                    g("protocol"),
                    g("direction"),
                    g("streams"),
                    g("secs"),
                    g("bytes")
                ));
            }
        }
        if let Some(e) = st.get("last_error").and_then(Value::as_str) {
            ui.colored_label(ui.visuals().warn_fg_color, e);
        }
        ui.separator();
        let Some(mut form) = self.server_form.clone() else {
            ui.weak(tr(l, "Loading…"));
            return;
        };
        egui::Grid::new("bw-server").num_columns(3).show(ui, |ui| {
            ui.label(tr(l, "Enabled"));
            ui.checkbox(&mut form.enabled, "");
            self.info(ui, l, "server_enabled", "Enabled");
            ui.end_row();
            for (label, key, value, hint) in [
                ("Port", "server_port", &mut form.port, "5201"),
                ("Allowed addresses", "server_allowed", &mut form.allowed, "100.64.0.0/10, 192.168.88.0/24"),
                ("Max duration (s)", "server_max_duration", &mut form.max_duration, "60"),
                ("Max streams", "server_max_streams", &mut form.max_streams, "8"),
                ("Max rate", "server_max_rate", &mut form.max_rate, "0 = no cap"),
            ] {
                ui.label(tr(l, label));
                // A Grid squeezes a TextEdit to its content: fixed size.
                let h = ui.spacing().interact_size.y;
                ui.add_sized([300.0, h], TextEdit::singleline(value).hint_text(hint));
                if help::info_button(ui, Id::unique(("bw-help", key)), tr(l, label)).clicked() {
                    self.help = Some(HelpView::new(format!("bandwidth.{key}"), tr(l, label)));
                }
                ui.end_row();
            }
        });
        self.server_form = Some(form.clone());
        ui.horizontal(|ui| {
            let check = app.can().check(SERVER_SET);
            if ui
                .add_enabled(check.is_ok(), egui::Button::new(tr(l, "Apply")))
                .on_disabled_hover_text(check.err().unwrap_or_default())
                .clicked()
            {
                self.server_error = None;
                app.run_then(SERVER_SET, form.params(), crate::panel::then(NAME, Saved));
            }
            if ui.button(tr(l, "Reset")).clicked() {
                self.server_form = Some(ServerForm::of(&self.server));
            }
            if let Some(e) = &self.server_error {
                ui.colored_label(err_color(ui), e);
            }
        });
    }
}

impl PanelState for BandwidthPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(id) = self.task.filter(|_| !self.done) {
            out.push(Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 1u64 << 52, "max": 1}),
            });
        }
        if self.tab == Tab::Server && app.has_command(SERVER_GET) {
            out.push(Query { key: "server", command: SERVER_GET, params: json!({}) });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "poll" => {
                if let Some(s) = value.get("summary").filter(|s| !s.is_null()) {
                    self.summary = s.clone();
                }
                self.state = value.get("state").and_then(Value::as_str).unwrap_or("").to_owned();
                if value.get("done").and_then(Value::as_bool) == Some(true) {
                    self.done = true;
                    if self.state == "failed" {
                        self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
                    }
                }
            }
            "server" => self.server = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Test, tr(l, "Test"));
            ui.selectable_value(&mut self.tab, Tab::Server, tr(l, "Server"));
        });
        ui.separator();
        match self.tab {
            Tab::Test => {
                self.test_form(app, ui, l);
                ui.separator();
                self.status(ui, l);
                self.chart(ui, l);
                self.results(ui, l);
            }
            Tab::Server => self.server_tab(app, ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        if !self.confirm {
            return;
        }
        let l = app.lang.labels;
        let mut answer = None;
        let load = if self.bandwidth.trim().is_empty() && self.protocol == "tcp" {
            tr(l, "as much as TCP can push").to_owned()
        } else {
            format!(
                "{} × {}",
                self.streams.trim(),
                if self.bandwidth.trim().is_empty() { "10M" } else { self.bandwidth.trim() }
            )
        };
        egui::Modal::new(Id::unique("bw-confirm")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.strong(format!("{} {}?", tr(l, "Start a bandwidth test to"), self.address.trim()));
            ui.label(format!(
                "{} {} s ({}, {}, {load}).",
                tr(l, "It fills the path for"),
                self.duration.trim(),
                self.protocol,
                self.direction,
            ));
            ui.colored_label(
                ui.visuals().warn_fg_color,
                tr(l, "Subscribers on the same links will feel it while it runs."),
            );
            ui.horizontal(|ui| {
                if ui.button(tr(l, "Start")).clicked() {
                    answer = Some(true);
                }
                if ui.button(tr(l, "Cancel")).clicked() {
                    answer = Some(false);
                }
            });
        });
        match answer {
            Some(true) => self.start(app),
            Some(false) => self.confirm = false,
            None => {}
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Started>().is_some() {
            self.starting = false;
            match result {
                Ok(v) => {
                    self.task = v.get("task_id").and_then(Value::as_u64);
                    self.warning = v.get("warning").and_then(Value::as_str).unwrap_or("").to_owned();
                    self.state = "running".into();
                }
                Err(e) => {
                    self.error = Some(e.clone());
                    self.done = true;
                }
            }
        } else if then.downcast_ref::<Saved>().is_some() {
            match result {
                Ok(v) => {
                    self.server_form = Some(ServerForm::of(v));
                    self.server_error = None;
                }
                Err(e) => self.server_error = Some(e.clone()),
            }
        } else if then.downcast_ref::<Stopped>().is_some()
            && let Err(e) = result
        {
            self.error = Some(e.clone());
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        if self.confirm {
            self.confirm = false;
            return true;
        }
        false
    }
}

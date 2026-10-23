//! Tools › Packet Sniffer (G6.4a): an interface's frames into a pcap file,
//! for Wireshark — RouterOS' `/tool sniffer`, bounded.
//!
//! Start runs `tool.sniffer.start` (a task) with the filter, how many bytes
//! of each frame to keep (headers only by default), the file's size limit
//! and the duration; the window shows the packets and how full the file
//! is. Download fetches the file in pieces (`tool.sniffer.download`) and
//! hands it to the app, which saves it (native) or offers it (web), like
//! Ping's CSV. Keeping whole frames records subscribers' data: an amber
//! chip says so, and the router only lets group write start a capture.

use base64::Engine as _;
use egui::{Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::windows::combo;
use crate::{CoreRouterUi, Win};

const NAME: &str = "sniffer";
pub(crate) const WIN: &str = "sniffer";
const START: &str = "tool.sniffer.start";
const STOP: &str = "tool.task.stop";
const DOWNLOAD: &str = "tool.sniffer.download";
/// Bytes asked for per download piece.
const PIECE: u64 = 4 << 20;
/// Bytes kept per frame: headers only, a whole standard frame, a jumbo.
pub(crate) const SNAPLENS: [&str; 3] = ["128", "1514", "9216"];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "Packet Sniffer",
        size: [860.0, 200.0],
        escape: true,
    }],
    new: || Box::new(SnifferPanel::default()),
};

pub(crate) struct SnifferPanel {
    pub(crate) interface: String,
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) port: String,
    pub(crate) protocol: String,
    pub(crate) snaplen: String,
    /// KiB.
    pub(crate) file_limit: String,
    /// Seconds.
    pub(crate) duration: String,
    pub(crate) task: Option<u64>,
    pub(crate) starting: bool,
    pub(crate) done: bool,
    pub(crate) state: String,
    pub(crate) summary: Value,
    pub(crate) error: Option<String>,
    /// A download in progress: the bytes so far.
    pub(crate) download: Option<Vec<u8>>,
    pub(crate) help: Option<HelpView>,
}

impl Default for SnifferPanel {
    fn default() -> Self {
        Self {
            interface: String::new(),
            src: String::new(),
            dst: String::new(),
            port: String::new(),
            protocol: String::new(),
            snaplen: "128".into(),
            file_limit: "4096".into(),
            duration: "60".into(),
            task: None,
            starting: false,
            done: false,
            state: String::new(),
            summary: Value::Null,
            error: None,
            download: None,
            help: None,
        }
    }
}

struct Started;
struct Stopped;
/// A download piece of task `.0`.
struct Piece(u64);

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn size(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / f64::from(1u32 << 20))
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

impl SnifferPanel {
    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    /// `tool.sniffer.start`'s parameters from the form.
    pub(crate) fn params(&self) -> Value {
        let mut m = Map::new();
        m.insert("interface".into(), json!(self.interface.trim()));
        for (key, v) in [
            ("src_address", &self.src),
            ("dst_address", &self.dst),
            ("protocol", &self.protocol),
        ] {
            if !v.trim().is_empty() {
                m.insert(key.into(), json!(v.trim()));
            }
        }
        for (key, v) in [
            ("port", &self.port),
            ("snaplen", &self.snaplen),
            ("file_limit", &self.file_limit),
            ("duration", &self.duration),
        ] {
            let v = v.trim();
            match v.parse::<u64>() {
                Ok(n) => {
                    m.insert(key.into(), json!(n));
                }
                // Not a number: the engine says why.
                Err(_) if !v.is_empty() => {
                    m.insert(key.into(), json!(v));
                }
                Err(_) => {}
            }
        }
        Value::Object(m)
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, title: &'static str) {
        if help::info_button(ui, Id::unique(("sniffer-help", key)), tr(l, title)).clicked() {
            self.help = Some(HelpView::new(format!("sniffer.{key}"), tr(l, title)));
        }
    }

    fn form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let on = !self.running();
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(l, "Interface"));
            let names = app.interface_names(None);
            ui.add_enabled_ui(on, |ui| {
                combo(ui, "sniffer-iface", tr(l, "pick one"), &mut self.interface, &names);
            });
            self.info(ui, l, "interface", "Interface");
            for (label, key, hint, w) in [
                ("Src.", "src", "100.64.0.9", 110.0),
                ("Dst.", "dst", "0.0.0.0/0", 110.0),
                ("Port", "port", "53", 45.0),
                ("Protocol", "protocol", "udp", 50.0),
            ] {
                ui.label(tr(l, label));
                let field = match key {
                    "src" => &mut self.src,
                    "dst" => &mut self.dst,
                    "port" => &mut self.port,
                    _ => &mut self.protocol,
                };
                ui.add_enabled(on, TextEdit::singleline(field).hint_text(hint).desired_width(w));
                // The filter means what Torch's does: one explanation.
                if help::info_button(ui, Id::unique(("sniffer-help", key)), tr(l, label)).clicked() {
                    self.help = Some(HelpView::new(format!("torch.{key}"), tr(l, label)));
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(tr(l, "Bytes per frame"));
            let opts: Vec<String> = SNAPLENS.iter().map(|s| (*s).to_owned()).collect();
            ui.add_enabled_ui(on, |ui| {
                combo(ui, "sniffer-snaplen", "128", &mut self.snaplen, &opts);
            });
            self.info(ui, l, "snaplen", "Bytes per frame");
            if self.snaplen.trim().parse::<u32>().is_ok_and(|n| n > 128) {
                chip::chip(ui, tr(l, "payloads"), chip::AMBER.tone(ui.visuals()))
                    .on_hover_text(tr(l, "Whole frames carry subscribers' data: keep the file safe"));
            }
            ui.label(tr(l, "File limit (KiB)"));
            ui.add_enabled(on, TextEdit::singleline(&mut self.file_limit).desired_width(60.0));
            self.info(ui, l, "file_limit", "File limit (KiB)");
            ui.label(tr(l, "Duration (s)"));
            ui.add_enabled(on, TextEdit::singleline(&mut self.duration).desired_width(45.0));
            self.info(ui, l, "duration", "Duration (s)");
            ui.separator();
            let can = app.can();
            if self.running() {
                if ui.button(tr(l, "Stop")).clicked()
                    && let Some(id) = self.task
                {
                    app.run_then(STOP, json!({"id": id}), crate::panel::then(NAME, Stopped));
                }
            } else {
                let ready = if self.interface.trim().is_empty() {
                    Err(tr(l, "Pick an interface first").to_owned())
                } else {
                    Ok(())
                };
                let check = can.and(START, ready);
                if ui
                    .add_enabled(check.is_ok() && !self.starting, egui::Button::new(tr(l, "Start")))
                    .on_disabled_hover_text(check.err().unwrap_or_default())
                    .clicked()
                {
                    self.start(app);
                }
            }
        });
    }

    pub(crate) fn start(&mut self, app: &mut CoreRouterUi) {
        self.starting = true;
        self.error = None;
        self.summary = Value::Null;
        self.done = false;
        self.download = None;
        app.run_then(START, self.params(), crate::panel::then(NAME, Started));
    }

    fn ask_piece(&self, app: &mut CoreRouterUi, id: u64, offset: u64) {
        app.run_then(
            DOWNLOAD,
            json!({"id": id, "offset": offset, "length": PIECE}),
            crate::panel::then(NAME, Piece(id)),
        );
    }

    fn progress(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
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
            if let Some(end) = s.get("end").and_then(Value::as_str) {
                chip::chip(ui, end, chip::neutral_tone(ui.visuals()));
            }
            ui.label(format!(
                "{} {}  ·  {} {}",
                u(&s, "packets"),
                tr(l, "packets"),
                size(u(&s, "bytes")),
                tr(l, "on the wire"),
            ));
            if u(&s, "dropped_by_limit") > 0 {
                chip::chip(
                    ui,
                    &format!("{} {}", u(&s, "dropped_by_limit"), tr(l, "past the limit")),
                    chip::AMBER.tone(ui.visuals()),
                );
            }
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
        });
        // Before a capture, the limit the form asks for.
        let form_limit = self.file_limit.trim().parse::<u64>().unwrap_or(0).saturating_mul(1024);
        let limit = match u(&s, "limit") {
            0 => form_limit,
            n => n,
        }
        .max(1);
        let file = u(&s, "file_size");
        ui.horizontal(|ui| {
            ui.label(tr(l, "File"));
            ui.add(
                egui::ProgressBar::new((file as f32 / limit as f32).clamp(0.0, 1.0))
                    .desired_width(260.0)
                    .text(format!("{} / {}", size(file), size(limit))),
            );
            let ready = match (&self.download, self.task) {
                (Some(_), _) => Err(tr(l, "Downloading…").to_owned()),
                (None, None) => Err(tr(l, "Nothing captured yet").to_owned()),
                (None, Some(_)) if file == 0 => Err(tr(l, "Nothing captured yet").to_owned()),
                (None, Some(_)) => Ok(()),
            };
            let check = app.can().and(DOWNLOAD, ready);
            if ui
                .add_enabled(check.is_ok(), egui::Button::new(tr(l, "Download .pcap")))
                .on_disabled_hover_text(check.err().unwrap_or_default())
                .on_hover_text(tr(l, "Save the capture so far, for Wireshark"))
                .clicked()
                && let Some(id) = self.task
            {
                self.download = Some(Vec::new());
                self.ask_piece(app, id, 0);
            }
            if let Some(d) = &self.download {
                ui.weak(size(d.len() as u64));
            }
        });
    }
}

impl PanelState for SnifferPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        match self.task {
            Some(id) if !self.done && app.open.contains(&Win::Panel(WIN)) => vec![Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 1u64 << 52, "max": 1}),
            }],
            _ => Vec::new(),
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key != "poll" {
            return;
        }
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

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.form(app, ui, l);
        ui.separator();
        self.progress(app, ui, l);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast_ref::<Started>().is_some() {
            self.starting = false;
            match result {
                Ok(v) => {
                    self.task = v.get("task_id").and_then(Value::as_u64);
                    self.state = "running".into();
                }
                Err(e) => {
                    self.error = Some(e.clone());
                    self.done = true;
                }
            }
        } else if let Some(Piece(id)) = then.downcast_ref::<Piece>() {
            let id = *id;
            match result {
                Ok(v) => {
                    let piece = v
                        .get("data")
                        .and_then(Value::as_str)
                        .and_then(|d| base64::engine::general_purpose::STANDARD.decode(d).ok());
                    let (Some(piece), Some(buf)) = (piece, self.download.as_mut()) else {
                        self.download = None;
                        self.error = Some("the capture file arrived damaged".into());
                        return;
                    };
                    buf.extend_from_slice(&piece);
                    let total = u(v, "total");
                    let have = buf.len() as u64;
                    if !piece.is_empty() && have < total {
                        self.ask_piece(app, id, have);
                    } else if let Some(bytes) = self.download.take() {
                        let file_name = v
                            .get("file_name")
                            .and_then(Value::as_str)
                            .unwrap_or("sniffer.pcap")
                            .to_owned();
                        app.note(true, DOWNLOAD, format!("{file_name}: {}", size(bytes.len() as u64)));
                        app.exports.push(crate::Export {
                            file_name,
                            mime: "application/vnd.tcpdump.pcap",
                            bytes,
                        });
                    }
                }
                Err(e) => {
                    self.download = None;
                    self.error = Some(e.clone());
                }
            }
        } else if then.downcast_ref::<Stopped>().is_some()
            && let Err(e) = result
        {
            self.error = Some(e.clone());
        }
        app.cache.refreshed_at = None;
    }
}

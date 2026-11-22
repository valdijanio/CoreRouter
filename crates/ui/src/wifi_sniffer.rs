//! Interfaces › Wi-Fi Sniffer (G1.30j): a radio in monitor mode, RouterOS
//! v7's `/interface/wifi/sniffer` and the legacy snooper. A window of its
//! own next to Interfaces › Wi-Fi (the radio's path in RouterOS, and the
//! file `wifi.rs` stays the station's), with two tabs:
//!
//! - **Snooper:** who uses the air. A strip with each channel's airtime
//!   (painted), then one row per network and, under it, one per station:
//!   airtime, frames, retries, rate, signal and the notes the engine
//!   writes (far and slow, thrown out with the reason, the handshake, a
//!   hidden name given away, a twin of a network) as chips; the selected
//!   row's notes in full below.
//! - **Capture:** the frames into a pcap file for Wireshark (radiotap),
//!   with a filter (network, name, address, frame types, only the
//!   handshake), the latest frames live, and Download .pcap.
//!
//! The form above both: the radio, and for a radio the sniffer has to
//! itself (a disabled interface) the channel, its width and hopping. An
//! enabled radio keeps its station: the monitor sits beside it on its
//! channel (the engine refuses anything else, and says why).
//!
//! The engine decides everything; this file draws and sends
//! `interface.wifi.snooper.*` / `interface.wifi.sniffer.*`.

use base64::Engine as _;
use egui::{Id, Sense, TextEdit, Ui, vec2};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Column, Row, TableState, col, num};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "wifi-sniffer";
pub(crate) const WIN: &str = "wifi-sniffer";
pub(crate) const TABLE: &str = "wifi-snooper";
pub(crate) const FRAMES: &str = "wifi-sniffer-frames";
const SCOPE: &str = "wifi_sniffer";
const STOP: &str = "tool.task.stop";
const DOWNLOAD: &str = "interface.wifi.sniffer.download";
/// Bytes asked for per download piece.
const PIECE: u64 = 4 << 20;
/// Frames kept in the live list.
const LIVE: usize = 200;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Interfaces",
        title: "Wi-Fi Sniffer",
        size: [1100.0, 680.0],
        escape: true,
    }],
    new: || Box::new(WifiSnifferPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Snooper,
    Capture,
}

impl Tab {
    fn command(self) -> &'static str {
        match self {
            Self::Snooper => "interface.wifi.snooper.start",
            Self::Capture => "interface.wifi.sniffer.start",
        }
    }
}

pub(crate) struct WifiSnifferPanel {
    pub(crate) tab: Tab,
    /// `interface.wifi.list`.
    pub(crate) radios: Vec<Value>,
    pub(crate) radio: String,
    pub(crate) channel: String,
    pub(crate) width: String,
    pub(crate) hop: bool,
    pub(crate) channels: String,
    pub(crate) channel_time: String,
    pub(crate) duration: String,
    pub(crate) bssid: String,
    pub(crate) ssid: String,
    pub(crate) mac: String,
    pub(crate) mgmt: bool,
    pub(crate) control: bool,
    pub(crate) data: bool,
    pub(crate) eapol: bool,
    pub(crate) file_limit: String,
    /// The running (or last) task, and which tab started it.
    pub(crate) task: Option<u64>,
    pub(crate) task_tab: Tab,
    pub(crate) starting: bool,
    pub(crate) done: bool,
    /// After the end, one more table and list are fetched.
    final_fetch: bool,
    pub(crate) state: String,
    pub(crate) summary: Value,
    pub(crate) error: Option<String>,
    /// `interface.wifi.snooper.print`.
    pub(crate) snoop: Value,
    /// The live list, oldest first.
    pub(crate) frames: Vec<Value>,
    last_seq: u64,
    pub(crate) table: TableState,
    pub(crate) frames_table: TableState,
    pub(crate) download: Option<Vec<u8>>,
    pub(crate) help: Option<HelpView>,
}

impl Default for WifiSnifferPanel {
    fn default() -> Self {
        Self {
            tab: Tab::Snooper,
            radios: Vec::new(),
            radio: String::new(),
            channel: String::new(),
            width: "20".into(),
            hop: false,
            channels: String::new(),
            channel_time: "200".into(),
            duration: "300".into(),
            bssid: String::new(),
            ssid: String::new(),
            mac: String::new(),
            mgmt: false,
            control: false,
            data: false,
            eapol: false,
            file_limit: "16384".into(),
            task: None,
            task_tab: Tab::Snooper,
            starting: false,
            done: false,
            final_fetch: false,
            state: String::new(),
            summary: Value::Null,
            error: None,
            snoop: Value::Null,
            frames: Vec::new(),
            last_seq: 0,
            table: TableState::default(),
            frames_table: TableState::default(),
            download: None,
            help: None,
        }
    }
}

struct Started(Tab);
struct Stopped;
struct Piece(u64);

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
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

/// The channel number of a frequency (2.4, 5 and 6 GHz), for the label.
fn channel_of(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 => Some((mhz - 2407) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        5160..=5885 => Some((mhz - 5000) / 5),
        _ => None,
    }
}

fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "–".into(), |p| format!("{p:.1} %"))
}

/// A note's chip: a short label (translated), the tone by its level.
fn note_chip(n: &Value, l: Lang) -> (String, Kind) {
    let kind = match s(n, "level").as_str() {
        "red" => Kind::Red,
        "amber" => Kind::Amber,
        "green" => Kind::Green,
        _ => Kind::Neutral,
    };
    let text = s(n, "text");
    let label = match s(n, "code").as_str() {
        "far-slow" => tr_in(SCOPE, l, "far, slow").to_owned(),
        "deauth-flood" => tr_in(SCOPE, l, "deauth flood").to_owned(),
        // "deauth ×6 (reason 7: …)" → "deauth ×6".
        "deauth" | "disassoc" => text.split(" (").next().unwrap_or(&text).to_owned(),
        "handshake" => tr_in(SCOPE, l, "handshake 4/4").to_owned(),
        "handshake-partial" => text,
        "hidden" => tr_in(SCOPE, l, "hidden").to_owned(),
        "hidden-revealed" => tr_in(SCOPE, l, "hidden, revealed").to_owned(),
        "evil-twin" => tr_in(SCOPE, l, "evil twin?").to_owned(),
        "other-security" => tr_in(SCOPE, l, "same SSID, other security").to_owned(),
        "other-vendor" => tr_in(SCOPE, l, "same SSID, other vendor").to_owned(),
        "broadcast-deauth" => tr_in(SCOPE, l, "deauth to all").to_owned(),
        "probing" => tr_in(SCOPE, l, "probing").to_owned(),
        _ => s(n, "code"),
    };
    (label, kind)
}

fn notes_cell(v: &Value, l: Lang) -> String {
    let chips: Vec<(String, Kind)> = v
        .get("notes")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|n| note_chip(n, l)).collect())
        .unwrap_or_default();
    let refs: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    cell("", &refs)
}

const COLUMNS: [Column; 9] = [
    col("Network / Station").help("wifi_sniffer.network"),
    num("Channel").help("wifi_sniffer.channel"),
    col("Security").help("wifi_sniffer.security"),
    num("Airtime").help("wifi_sniffer.airtime"),
    num("Frames").help("wifi_sniffer.frames"),
    num("Retry").help("wifi_sniffer.retry"),
    col("Rate").help("wifi_sniffer.rate"),
    num("Signal").help("wifi_sniffer.signal"),
    col("Notes").help("wifi_sniffer.notes"),
];

const FRAME_COLUMNS: [Column; 10] = [
    num("Time"),
    num("Ch."),
    col("Type").help("wifi_sniffer.frame_types"),
    col("From"),
    col("To"),
    col("BSSID").help("wifi_sniffer.bssid"),
    num("Signal").help("wifi_sniffer.signal"),
    num("Rate").help("wifi_sniffer.rate"),
    num("Length"),
    col("Info"),
];

fn network_row(n: &Value, l: Lang) -> Row {
    let name = match n.get("ssid").and_then(Value::as_str) {
        Some(x) => x.to_owned(),
        None => tr_in(SCOPE, l, "(hidden)").to_owned(),
    };
    let ch = n.get("channel").and_then(Value::as_u64).map_or_else(String::new, |c| c.to_string());
    let sec = s(n, "security");
    let sec_kind = match sec.as_str() {
        "open" | "legacy" => Kind::Amber,
        _ => Kind::Neutral,
    };
    Row {
        key: s(n, "bssid"),
        cells: vec![
            cell(&name, &[(&s(n, "bssid"), Kind::Hashed(chip::name_hue(&s(n, "bssid"))))]),
            ch,
            cell("", &[(sec.as_str(), sec_kind)]),
            pct(f(n, "airtime_pct")),
            u(n, "frames").to_string(),
            pct(f(n, "retry_pct")),
            s(n, "rate"),
            n.get("signal").and_then(Value::as_i64).map_or_else(|| "–".into(), |x| format!("{x} dBm")),
            notes_cell(n, l),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn station_row(bssid: &str, st: &Value, l: Lang) -> Row {
    let mac = s(st, "mac");
    let random = st.get("random_mac").and_then(Value::as_bool) == Some(true);
    let mut chips: Vec<(&str, Kind)> = Vec::new();
    let rnd = tr_in(SCOPE, l, "random MAC");
    if random {
        chips.push((rnd, Kind::Neutral));
    }
    Row {
        key: format!("{bssid}/{mac}"),
        cells: vec![
            cell(&format!("      · {mac}"), &chips),
            st.get("frequency")
                .and_then(Value::as_u64)
                .and_then(|f| channel_of(u32::try_from(f).unwrap_or(0)))
                .map_or_else(String::new, |c| c.to_string()),
            String::new(),
            pct(f(st, "airtime_pct")),
            u(st, "frames").to_string(),
            pct(f(st, "retry_pct")),
            s(st, "rate"),
            st.get("signal").and_then(Value::as_i64).map_or_else(|| "–".into(), |x| format!("{x} dBm")),
            notes_cell(st, l),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn frame_row(p: &Value) -> Row {
    let mut flags: Vec<(&str, Kind)> = Vec::new();
    if p.get("retry").and_then(Value::as_bool) == Some(true) {
        flags.push(("retry", Kind::Amber));
    }
    if p.get("protected").and_then(Value::as_bool) == Some(true) {
        flags.push(("protected", Kind::Neutral));
    }
    let kind = match s(p, "kind").as_str() {
        "mgmt" => Kind::Blue,
        "control" => Kind::Neutral,
        _ => Kind::Green,
    };
    let t = u(p, "t_ms");
    Row {
        key: u(p, "seq").to_string(),
        cells: vec![
            format!("{}.{:03}", t / 1000, t % 1000),
            p.get("channel").and_then(Value::as_u64).map_or_else(String::new, |c| c.to_string()),
            cell("", &[(s(p, "type").as_str(), kind)]),
            s(p, "ta"),
            s(p, "ra"),
            s(p, "bssid"),
            p.get("signal").and_then(Value::as_i64).map_or_else(|| "–".into(), |x| format!("{x} dBm")),
            f(p, "rate_mbps").map_or_else(|| "–".into(), |r| format!("{r} Mb/s")),
            u(p, "length").to_string(),
            cell(&s(p, "info"), &flags),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl WifiSnifferPanel {
    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    fn radio_row(&self) -> Option<&Value> {
        self.radios.iter().find(|r| s(r, "name") == self.radio)
    }

    /// The radio keeps its station: the monitor shares its channel.
    pub(crate) fn shared(&self) -> bool {
        self.radio_row().is_some_and(|r| r.get("disabled").and_then(Value::as_bool) == Some(false))
    }

    /// The start command's parameters from the form.
    pub(crate) fn params(&self, tab: Tab) -> Value {
        let mut m = Map::new();
        m.insert("interface".into(), json!(self.radio.trim()));
        let num = |m: &mut Map<String, Value>, key: &str, v: &str| {
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
        };
        if !self.shared() {
            if self.hop {
                m.insert("hop".into(), json!(true));
                if !self.channels.trim().is_empty() {
                    m.insert("channels".into(), json!(self.channels.trim()));
                }
                num(&mut m, "channel_time", &self.channel_time);
            } else {
                num(&mut m, "channel", &self.channel);
            }
            if self.width.trim() != "20" {
                num(&mut m, "width", &self.width);
            }
        }
        num(&mut m, "duration", &self.duration);
        if tab == Tab::Capture {
            for (key, v) in [("bssid", &self.bssid), ("ssid", &self.ssid), ("mac_address", &self.mac)] {
                if !v.trim().is_empty() {
                    m.insert(key.into(), json!(v.trim()));
                }
            }
            let types: Vec<&str> = [(self.mgmt, "mgmt"), (self.control, "control"), (self.data, "data")]
                .into_iter()
                .filter_map(|(on, t)| on.then_some(t))
                .collect();
            if !types.is_empty() {
                m.insert("frame_types".into(), json!(types));
            }
            if self.eapol {
                m.insert("eapol".into(), json!(true));
            }
            num(&mut m, "file_limit", &self.file_limit);
        }
        Value::Object(m)
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &'static str, title: &'static str) {
        if help::info_button(ui, Id::unique(("wifi-sniffer-help", key)), tr_in(SCOPE, l, title)).clicked() {
            self.help = Some(HelpView::new(format!("wifi_sniffer.{key}"), tr_in(SCOPE, l, title)));
        }
    }

    pub(crate) fn start(&mut self, app: &mut CoreRouterUi, tab: Tab) {
        self.starting = true;
        self.error = None;
        self.summary = Value::Null;
        self.snoop = Value::Null;
        self.frames.clear();
        self.last_seq = 0;
        self.done = false;
        self.final_fetch = false;
        self.download = None;
        app.run_then(tab.command(), self.params(tab), crate::panel::then(NAME, Started(tab)));
    }

    /// The radio and the channel: above both tabs.
    fn form(&mut self, ui: &mut Ui, l: Lang) {
        let on = !self.running();
        let names: Vec<String> = self.radios.iter().map(|r| s(r, "name")).collect();
        if self.radio.is_empty()
            && let Some(first) = names.first()
        {
            self.radio = first.clone();
        }
        let shared = self.shared();
        ui.horizontal_wrapped(|ui| {
            ui.label(tr_in(SCOPE, l, "Interface"));
            ui.add_enabled_ui(on, |ui| {
                crate::windows::combo(ui, "wifi-sniffer-radio", tr_in(SCOPE, l, "pick one"), &mut self.radio, &names);
            });
            self.info(ui, l, "interface", "Interface");
            let v = ui.visuals().clone();
            if !self.radio.is_empty() {
                let (text, tone, tip) = if shared {
                    (
                        tr_in(SCOPE, l, "beside the station"),
                        chip::BLUE.tone(&v),
                        tr_in(SCOPE, l, "The radio stays on its network: the monitor hears the station's channel. Disable the interface to choose a channel or hop."),
                    )
                } else {
                    (
                        tr_in(SCOPE, l, "exclusive"),
                        chip::GREEN.tone(&v),
                        tr_in(SCOPE, l, "The interface is disabled: the sniffer has the radio, on any channel."),
                    )
                };
                chip::chip(ui, text, tone).on_hover_text(tip);
                self.info(ui, l, "mode", "Mode");
            }
            ui.separator();
            let free = on && !shared;
            let why = tr_in(SCOPE, l, "The radio is in use by its station: disable the interface first");
            ui.add_enabled(free, egui::Checkbox::new(&mut self.hop, tr_in(SCOPE, l, "Hop")))
                .on_disabled_hover_text(why);
            self.info(ui, l, "hop", "Hop");
            if self.hop {
                ui.label(tr_in(SCOPE, l, "Channels"));
                ui.add_enabled(free, TextEdit::singleline(&mut self.channels).hint_text("1,6,11,36,44").desired_width(90.0))
                    .on_disabled_hover_text(why);
                self.info(ui, l, "channels", "Channels");
                ui.label(tr_in(SCOPE, l, "Channel time (ms)"));
                ui.add_enabled(free, TextEdit::singleline(&mut self.channel_time).desired_width(45.0));
                self.info(ui, l, "channel_time", "Channel time (ms)");
            } else {
                ui.label(tr_in(SCOPE, l, "Channel"));
                ui.add_enabled(free, TextEdit::singleline(&mut self.channel).hint_text("44").desired_width(50.0))
                    .on_disabled_hover_text(why);
                self.info(ui, l, "channel", "Channel");
            }
            ui.label(tr_in(SCOPE, l, "Width"));
            let widths: Vec<String> = ["20", "40", "80", "160"].map(String::from).to_vec();
            ui.add_enabled_ui(free, |ui| {
                crate::windows::combo(ui, "wifi-sniffer-width", "20", &mut self.width, &widths);
            });
            self.info(ui, l, "width", "Width");
            ui.label(tr_in(SCOPE, l, "Duration (s)"));
            ui.add_enabled(on, TextEdit::singleline(&mut self.duration).desired_width(50.0));
            self.info(ui, l, "duration", "Duration (s)");
        });
    }

    /// Tabs, Start/Stop and the state.
    fn bar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.horizontal_wrapped(|ui| {
            for (tab, label, key) in [(Tab::Snooper, "Snooper", "snooper"), (Tab::Capture, "Capture", "capture")] {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                }
                self.info(ui, l, key, label);
            }
            ui.separator();
            let can = app.can();
            if self.running() {
                if ui.button(tr_in(SCOPE, l, "Stop")).clicked()
                    && let Some(id) = self.task
                {
                    app.run_then(STOP, json!({"id": id}), crate::panel::then(NAME, Stopped));
                }
            } else {
                let ready = if self.radio.trim().is_empty() {
                    Err(tr_in(SCOPE, l, "This router has no Wi-Fi radio").to_owned())
                } else {
                    Ok(())
                };
                let label = match self.tab {
                    Tab::Snooper => tr_in(SCOPE, l, "Start snooper"),
                    Tab::Capture => tr_in(SCOPE, l, "Start capture"),
                };
                let check = can.and(self.tab.command(), ready);
                if ui
                    .add_enabled(check.is_ok() && !self.starting, egui::Button::new(label))
                    .on_disabled_hover_text(check.err().unwrap_or_default())
                    .clicked()
                {
                    let tab = self.tab;
                    self.start(app, tab);
                }
            }
            let v = ui.visuals().clone();
            if !self.state.is_empty() {
                let tone = match self.state.as_str() {
                    "running" => chip::GREEN.tone(&v),
                    "failed" | "lost" => chip::RED.tone(&v),
                    _ => chip::neutral_tone(&v),
                };
                chip::chip(ui, &self.state, tone);
            }
            let sum = self.summary.clone();
            if let Some(ch) = sum.get("channel").and_then(Value::as_u64).filter(|c| *c > 0) {
                let n = channel_of(u32::try_from(ch).unwrap_or(0));
                let text = match n {
                    Some(n) => format!("ch {n} · {ch} MHz"),
                    None => format!("{ch} MHz"),
                };
                chip::chip(ui, &text, chip::BLUE.tone(&v));
            }
            if self.running() && sum.get("hopping").and_then(Value::as_bool) == Some(true) {
                chip::chip(ui, tr_in(SCOPE, l, "hopping"), chip::neutral_tone(&v));
            }
            if let Some(end) = sum.get("end").and_then(Value::as_str).filter(|e| *e != self.state) {
                chip::chip(ui, end, chip::neutral_tone(&v));
            }
            if let Some(note) = sum.get("note").and_then(Value::as_str) {
                chip::chip(ui, tr_in(SCOPE, l, "stopped hopping"), chip::AMBER.tone(&v)).on_hover_text(note);
            }
            if self.task.is_some() {
                ui.label(format!("{} {}", u(&sum, "frames"), tr_in(SCOPE, l, "frames")));
            }
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
        });
    }

    /// Each channel's airtime as a bar, the one on the air now outlined.
    fn channel_strip(&self, ui: &mut Ui, l: Lang) {
        let channels: Vec<Value> = self
            .snoop
            .get("channels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if channels.is_empty() {
            return;
        }
        let now = u(&self.snoop, "channel");
        let h = 46.0;
        let w = ui.available_width().min(60.0 * channels.len() as f32 + 8.0);
        let (rect, _) = ui.allocate_exact_size(vec2(w, h + 16.0), Sense::hover());
        let painter = ui.painter_at(rect);
        let v = ui.visuals();
        let slot = (rect.width() / channels.len().max(1) as f32).min(60.0);
        let small = egui::FontId::proportional(chip::small(ui));
        for (i, c) in channels.iter().enumerate() {
            let x = rect.left() + slot * i as f32;
            let p = f(c, "airtime_pct").unwrap_or(0.0).clamp(0.0, 100.0) as f32;
            let bar_h = (h - 12.0) * p / 100.0;
            let base = rect.top() + h - 2.0;
            let tone = if p >= 50.0 {
                chip::RED.tone(v)
            } else if p >= 20.0 {
                chip::AMBER.tone(v)
            } else {
                chip::GREEN.tone(v)
            };
            let bar = egui::Rect::from_min_max(egui::pos2(x + 6.0, base - bar_h.max(1.0)), egui::pos2(x + slot - 6.0, base));
            painter.rect_filled(bar, 2.0, tone.fill);
            if u(c, "frequency") == now {
                let frame = egui::Rect::from_min_max(egui::pos2(x + 3.0, rect.top()), egui::pos2(x + slot - 3.0, base + 1.0));
                painter.rect_stroke(frame, 3.0, egui::Stroke::new(1.0, v.selection.stroke.color), egui::StrokeKind::Inside);
            }
            painter.text(
                egui::pos2(x + slot / 2.0, rect.top() + 1.0),
                egui::Align2::CENTER_TOP,
                format!("{:.0}%", p),
                small.clone(),
                v.weak_text_color(),
            );
            painter.text(
                egui::pos2(x + slot / 2.0, base + 2.0),
                egui::Align2::CENTER_TOP,
                format!("{}", u(c, "channel")),
                small.clone(),
                v.text_color(),
            );
        }
        ui.weak(tr_in(SCOPE, l, "Airtime per channel (estimated: the frames' own duration over the time listened)"));
    }

    fn snooper_tab(&mut self, ui: &mut Ui, l: Lang) {
        self.channel_strip(ui, l);
        let nets: Vec<Value> = self.snoop.get("networks").and_then(Value::as_array).cloned().unwrap_or_default();
        let alone: Vec<Value> = self.snoop.get("unassociated").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut rows = Vec::new();
        for n in &nets {
            rows.push(network_row(n, l));
            let b = s(n, "bssid");
            for st in n.get("stations").and_then(Value::as_array).into_iter().flatten() {
                rows.push(station_row(&b, st, l));
            }
        }
        for st in &alone {
            rows.push(station_row("-", st, l));
        }
        self.table.empty = if self.task.is_none() {
            tr_in(SCOPE, l, "Start the snooper (or a capture) to see who uses the air.").to_owned()
        } else {
            tr_in(SCOPE, l, "Nothing heard yet.").to_owned()
        };
        let detail_h = ui.spacing().interact_size.y * 4.0;
        let out = table::show(ui, TABLE, detail_h, &mut self.table, &COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        // The selected row's notes in full.
        let sel = self.table.selection(&rows);
        let picked = sel.as_slice().first().and_then(|k| {
            let (b, m) = k.split_once('/').map_or((k.as_str(), None), |(b, m)| (b, Some(m)));
            match m {
                None => nets.iter().find(|n| s(n, "bssid") == b),
                Some(m) => nets
                    .iter()
                    .filter_map(|n| n.get("stations").and_then(Value::as_array))
                    .flatten()
                    .chain(alone.iter())
                    .find(|st| s(st, "mac") == m),
            }
        });
        let v = ui.visuals().clone();
        ui.horizontal_wrapped(|ui| {
            chip::chip(ui, &format!("{} {}", u(&self.snoop, "network_count"), tr_in(SCOPE, l, "networks")), chip::neutral_tone(&v));
            chip::chip(ui, &format!("{} {}", u(&self.snoop, "station_count"), tr_in(SCOPE, l, "stations")), chip::neutral_tone(&v));
            let bad = u(&self.snoop, "bad_fcs");
            if bad > 0 {
                chip::chip(ui, &format!("{bad} {}", tr_in(SCOPE, l, "bad FCS")), chip::AMBER.tone(&v));
            }
            let over = u(&self.snoop, "overflow");
            if over > 0 {
                chip::chip(ui, &format!("{over} {}", tr_in(SCOPE, l, "not kept")), chip::AMBER.tone(&v));
            }
        });
        if let Some(p) = picked {
            for n in p.get("notes").and_then(Value::as_array).into_iter().flatten() {
                ui.horizontal(|ui| {
                    let (label, kind) = note_chip(n, l);
                    chip::chip(ui, &label, kind.tone(&v));
                    ui.label(s(n, "text"));
                });
            }
        }
    }

    fn capture_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let on = !self.running();
        ui.horizontal_wrapped(|ui| {
            for (label, key, hint, w) in [
                ("BSSID", "bssid", "aa:bb:cc:dd:ee:ff", 130.0),
                ("SSID", "ssid", "CoreRouter-Lab", 120.0),
                ("MAC", "mac", "aa:bb:cc:dd:ee:ff", 130.0),
            ] {
                ui.label(tr_in(SCOPE, l, label));
                let field = match key {
                    "bssid" => &mut self.bssid,
                    "ssid" => &mut self.ssid,
                    _ => &mut self.mac,
                };
                ui.add_enabled(on, TextEdit::singleline(field).hint_text(hint).desired_width(w));
                self.info(ui, l, key, label);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(tr_in(SCOPE, l, "Frame types"));
            ui.add_enabled(on && !self.eapol, egui::Checkbox::new(&mut self.mgmt, "mgmt"));
            ui.add_enabled(on && !self.eapol, egui::Checkbox::new(&mut self.control, "control"));
            ui.add_enabled(on && !self.eapol, egui::Checkbox::new(&mut self.data, "data"));
            self.info(ui, l, "frame_types", "Frame types");
            ui.separator();
            ui.add_enabled(on, egui::Checkbox::new(&mut self.eapol, tr_in(SCOPE, l, "Handshake only (EAPOL)")));
            self.info(ui, l, "eapol", "Handshake only (EAPOL)");
            ui.separator();
            ui.label(tr_in(SCOPE, l, "File limit (KiB)"));
            ui.add_enabled(on, TextEdit::singleline(&mut self.file_limit).desired_width(60.0));
            self.info(ui, l, "file_limit", "File limit (KiB)");
        });
        // The file.
        let sum = self.summary.clone();
        let capturing = self.task_tab == Tab::Capture && self.task.is_some();
        let form_limit = self.file_limit.trim().parse::<u64>().unwrap_or(0).saturating_mul(1024);
        let limit = match u(&sum, "limit") {
            0 => form_limit,
            n => n,
        }
        .max(1);
        let file = if capturing { u(&sum, "file_size") } else { 0 };
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "File"));
            ui.add(
                egui::ProgressBar::new((file as f32 / limit as f32).clamp(0.0, 1.0))
                    .desired_width(260.0)
                    .text(format!("{} / {}", size(file), size(limit))),
            );
            let dropped = u(&sum, "dropped_by_limit");
            if capturing && dropped > 0 {
                let v = ui.visuals().clone();
                chip::chip(ui, &format!("{dropped} {}", tr_in(SCOPE, l, "past the limit")), chip::AMBER.tone(&v));
            }
            let ready = match (&self.download, self.task) {
                (Some(_), _) => Err(tr_in(SCOPE, l, "Downloading…").to_owned()),
                _ if !capturing || file <= 24 => Err(tr_in(SCOPE, l, "Nothing captured yet").to_owned()),
                _ => Ok(()),
            };
            let check = app.can().and(DOWNLOAD, ready);
            if ui
                .add_enabled(check.is_ok(), egui::Button::new(tr_in(SCOPE, l, "Download .pcap")))
                .on_disabled_hover_text(check.err().unwrap_or_default())
                .on_hover_text(tr_in(SCOPE, l, "Save the capture so far, for Wireshark (radiotap, link type 127)"))
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
        let rows: Vec<Row> = self.frames.iter().rev().map(frame_row).collect();
        self.frames_table.empty = tr_in(SCOPE, l, "Start a capture: the latest frames that pass the filter show here.").to_owned();
        let out = table::show(ui, FRAMES, 0.0, &mut self.frames_table, &FRAME_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = FRAME_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn ask_piece(&self, app: &mut CoreRouterUi, id: u64, offset: u64) {
        app.run_then(
            DOWNLOAD,
            json!({"id": id, "offset": offset, "length": PIECE}),
            crate::panel::then(NAME, Piece(id)),
        );
    }
}

impl PanelState for WifiSnifferPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = vec![Query {
            key: "radios",
            command: "interface.wifi.list",
            params: Value::Null,
        }];
        let Some(id) = self.task else { return out };
        if self.done && !self.final_fetch {
            return out;
        }
        out.push(Query {
            key: "poll",
            command: "tool.task.poll",
            params: json!({"id": id, "after_seq": 1u64 << 52, "max": 1}),
        });
        if app.has_command("interface.wifi.snooper.print") {
            out.push(Query {
                key: "table",
                command: "interface.wifi.snooper.print",
                params: json!({"id": id}),
            });
        }
        if self.task_tab == Tab::Capture && app.has_command("interface.wifi.sniffer.packets") {
            out.push(Query {
                key: "packets",
                command: "interface.wifi.sniffer.packets",
                params: json!({"id": id, "after_seq": self.last_seq, "max": 100}),
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "radios" => {
                if let Value::Array(a) = value {
                    self.radios = a;
                }
            }
            "poll" => {
                if let Some(sum) = value.get("summary").filter(|x| !x.is_null()) {
                    self.summary = sum.clone();
                }
                self.state = value.get("state").and_then(Value::as_str).unwrap_or("").to_owned();
                if value.get("done").and_then(Value::as_bool) == Some(true) {
                    // One more round for the last table and frames.
                    self.final_fetch = !self.done;
                    self.done = true;
                    if self.state == "failed" {
                        self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
                    }
                }
            }
            "table" => {
                if value.is_object() {
                    self.snoop = value;
                }
            }
            "packets" => {
                for p in value.get("packets").and_then(Value::as_array).into_iter().flatten() {
                    self.frames.push(p.clone());
                }
                if self.frames.len() > LIVE {
                    let extra = self.frames.len() - LIVE;
                    self.frames.drain(..extra);
                }
                self.last_seq = value.get("last_seq").and_then(Value::as_u64).unwrap_or(self.last_seq);
                if self.done {
                    self.final_fetch = false;
                }
            }
            _ => {}
        }
        if key == "table" && self.done && self.task_tab == Tab::Snooper {
            self.final_fetch = false;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.form(ui, l);
        ui.separator();
        self.bar(app, ui, l);
        ui.separator();
        match self.tab {
            Tab::Snooper => self.snooper_tab(ui, l),
            Tab::Capture => self.capture_tab(app, ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(Started(tab)) = then.downcast_ref::<Started>() {
            self.starting = false;
            match result {
                Ok(v) => {
                    self.task = v.get("task_id").and_then(Value::as_u64);
                    self.task_tab = *tab;
                    self.state = "running".into();
                }
                Err(e) => {
                    self.error = Some(e.clone());
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
                            .unwrap_or("wifi.pcap")
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

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (FRAMES, &self.frames_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table), (FRAMES, &mut self.frames_table)]
    }
}

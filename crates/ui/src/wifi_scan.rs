//! The Networks tab of Interfaces › Wi-Fi (G1.30i): three views of what the
//! radio hears, chosen above the table.
//!
//! - **List:** a row per access point with its channel and width, its load
//!   (BSS Load) and its air: the channels that overlap it and the networks
//!   that share its airtime, as the engine reckons them
//!   (`interface.wifi.networks`); filtered by band, grouped by channel on
//!   request, the network the radio is on marked "yours", and the channel
//!   each band has the least on under the table.
//! - **Channels:** per band, each network as a curve over its channel's
//!   width, as tall as its signal (OpenWrt's Channel Analysis), and under
//!   it the busy share of each channel where the driver counted it
//!   (`interface.wifi.frequency-scan`).
//! - **Spectrum:** an airView-style spectral scan (`interface.wifi.
//!   spectral-scan`, `spectral-data`): the waterfall, the real-time,
//!   average and peak traces, each channel's usage and what the energy
//!   looks like. Only radios with spectral scan (Qualcomm Atheros); the
//!   others show the view off, with why.
//!
//! The engine computes every number; this file lays them out.

use std::collections::VecDeque;

use egui::{Color32, Id, Pos2, Rect, Sense, Shape, Stroke, Ui, vec2};
use serde_json::{Value, json};

use crate::chip::{self, Kind, Tone, cell};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::Query;
use crate::table::{self, Row, col};
use crate::CoreRouterUi;

/// Scope of the translations (`i18n/auto/wifi_scan_*.rs`).
const SCOPE: &str = "wifi_scan";
/// Rows of the waterfall kept (the engine keeps as many).
const MAX_ROWS: usize = 240;
/// Points of a row looked at.
const MAX_POINTS: usize = 1024;
/// No sample at that point (the engine's `-128`).
const NONE: i8 = i8::MIN;

pub(crate) const COLUMNS: [table::Column; 8] = [
    col("SSID").help("interface.wifi.ssid"),
    col("Signal").help("interface.wifi.signal"),
    col("Channel").help("interface.wifi.networks.channel"),
    col("Security").help("interface.wifi.networks.security"),
    col("Load").help("interface.wifi.networks.load"),
    col("Air").help("interface.wifi.networks.air"),
    col("BSSID").help("interface.wifi.bssid"),
    col("Note").help("interface.wifi.networks"),
];

/// The view of the Networks tab.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    #[default]
    List,
    Channels,
    Spectrum,
}

/// The band filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Band {
    #[default]
    All,
    G2,
    G5,
    G6,
}

impl Band {
    fn code(self) -> Option<&'static str> {
        match self {
            Self::All => None,
            Self::G2 => Some("2ghz"),
            Self::G5 => Some("5ghz"),
            Self::G6 => Some("6ghz"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::G2 => "2.4 GHz",
            Self::G5 => "5 GHz",
            Self::G6 => "6 GHz",
        }
    }
}

/// The state of the three views.
pub(crate) struct ScanView {
    pub(crate) mode: Mode,
    pub(crate) band: Band,
    pub(crate) group: bool,
    /// `interface.wifi.frequency-scan` of the radio.
    pub(crate) survey: Option<Value>,
    /// The last `interface.wifi.spectral-data` (its rows taken out).
    pub(crate) spectral: Option<Value>,
    /// The waterfall: newest last.
    pub(crate) rows: VecDeque<Vec<i8>>,
    pub(crate) last_seq: u64,
    /// The grid the rows are on (start, step, points): a new one clears
    /// them.
    grid: (f64, f64, u64),
    texture: Option<egui::TextureHandle>,
    texture_seq: u64,
    pub(crate) range: &'static str,
    pub(crate) duration: u32,
}

impl Default for ScanView {
    fn default() -> Self {
        Self {
            mode: Mode::List,
            band: Band::All,
            group: false,
            survey: None,
            spectral: None,
            rows: VecDeque::new(),
            last_seq: 0,
            grid: (0.0, 0.0, 0),
            texture: None,
            texture_seq: 0,
            range: "current",
            duration: 60,
        }
    }
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).filter(|v| !v.is_null()).map(crate::value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn int(r: &Value, k: &str) -> Option<i64> {
    r.get(k).and_then(Value::as_i64)
}

fn band_label(code: &str) -> &'static str {
    match code {
        "2ghz" => "2.4 GHz",
        "5ghz" => "5 GHz",
        "6ghz" => "6 GHz",
        _ => "",
    }
}

/// Green down to −65 dBm, amber to −75, red below (as the Radios tab).
fn signal_kind(dbm: i64) -> Kind {
    crate::wifi::signal_kind(dbm)
}

fn security(code: &str) -> (&'static str, Kind) {
    match code {
        "wpa3" => ("WPA3", Kind::Green),
        "wpa2-wpa3" => ("WPA2/WPA3", Kind::Green),
        "wpa2" => ("WPA2", Kind::Neutral),
        "open" => ("open", Kind::Amber),
        "owe" => ("OWE", Kind::Neutral),
        "enterprise" => ("802.1X", Kind::Neutral),
        _ => ("WEP/WPA", Kind::Red),
    }
}

/// "Wi-Fi 6" from the generation.
fn generation(n: &Value) -> Option<String> {
    int(n, "generation").filter(|g| (4..=7).contains(g)).map(|g| format!("Wi-Fi {g}"))
}

/// The row of a network: its key is the access point.
pub(crate) fn row(n: &Value, l: Lang) -> Row {
    let ssid = s(n, "ssid");
    let mut name_chips: Vec<(String, Kind)> = vec![if ssid.is_empty() {
        (tr_in(SCOPE, l, "hidden").to_owned(), Kind::Neutral)
    } else {
        (ssid.clone(), Kind::Hashed(chip::name_hue(&ssid)))
    }];
    if flag(n, "connected") {
        name_chips.push((tr_in(SCOPE, l, "yours").to_owned(), Kind::Green));
    }
    let channel = match (n.get("band").and_then(Value::as_str), int(n, "channel")) {
        (Some(b), Some(ch)) => format!("{} ch {ch}", band_label(b)),
        _ => String::new(),
    };
    let mut ch_chips: Vec<(String, Kind)> = Vec::new();
    if let Some(w) = int(n, "width") {
        ch_chips.push((format!("{w} MHz"), if w > 20 { Kind::Blue } else { Kind::Neutral }));
    }
    if let Some(g) = generation(n) {
        ch_chips.push((g, Kind::Neutral));
    }
    let load = match (int(n, "stations"), n.get("utilization").and_then(Value::as_f64)) {
        (Some(st), Some(u)) => {
            let k = if u >= 60.0 { Kind::Red } else if u >= 30.0 { Kind::Amber } else { Kind::Neutral };
            let word = if st == 1 { "client" } else { "clients" };
            cell(&format!("{st} {}", tr_in(SCOPE, l, word)), &[(&format!("{u:.0}%"), k)])
        }
        _ => String::new(),
    };
    let mut air: Vec<(String, Kind)> = Vec::new();
    let overlaps: Vec<String> = n
        .get("overlaps")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).map(|c| c.to_string()).collect())
        .unwrap_or_default();
    let same = int(n, "same_channel").unwrap_or(0);
    if same > 0 {
        air.push((format!("{} ×{same}", tr_in(SCOPE, l, "same channel")), Kind::Neutral));
    }
    if !overlaps.is_empty() {
        air.push((format!("{} {}", tr_in(SCOPE, l, "overlaps ch"), overlaps.join(", ")), Kind::Neutral));
    }
    let contenders = n.get("contenders").and_then(Value::as_array).map_or(0, Vec::len);
    if contenders > 0 {
        let k = if contenders >= 3 { Kind::Red } else { Kind::Amber };
        air.push((format!("{} ×{contenders}", tr_in(SCOPE, l, "shares airtime")), k));
    }
    let (sec, sec_kind) = security(&s(n, "security"));
    let note = if flag(n, "connected") { String::new() } else { s(n, "why_not") };
    Row {
        key: s(n, "bssid"),
        cells: vec![
            cell("", &chips(&name_chips)),
            int(n, "signal").map(|d| cell("", &[(&format!("{d} dBm"), signal_kind(d))])).unwrap_or_default(),
            cell(&channel, &chips(&ch_chips)),
            cell("", &[(tr_in(SCOPE, l, sec), sec_kind)]),
            load,
            cell("", &chips(&air)),
            s(n, "bssid"),
            note,
        ],
        dimmed: !flag(n, "joinable"),
        section: false,
        tint: None,
    }
}

fn chips(v: &[(String, Kind)]) -> Vec<(&str, Kind)> {
    v.iter().map(|(t, k)| (t.as_str(), *k)).collect()
}

/// A section header row of the channel `ch` of `band`.
fn section(band: &str, ch: i64, count: usize, l: Lang) -> Row {
    let title = format!(
        "{} ch {ch} · {count} {}",
        band_label(band),
        tr_in(SCOPE, l, if count == 1 { "network" } else { "networks" })
    );
    Row {
        key: format!("section-{band}-{ch}"),
        cells: vec![title, String::new(), String::new(), String::new(), String::new(), String::new(), String::new(), String::new()],
        dimmed: false,
        section: true,
        tint: None,
    }
}

/// The table's rows: `nets` in their order, or grouped by channel (band,
/// then channel, each group strongest first) with a header per channel.
pub(crate) fn rows(nets: &[Value], group: bool, l: Lang) -> Vec<Row> {
    if !group {
        return nets.iter().map(|n| row(n, l)).collect();
    }
    let mut keys: Vec<(u64, String, i64)> = nets
        .iter()
        .map(|n| (n.get("frequency").and_then(Value::as_u64).unwrap_or(0), s(n, "band"), int(n, "channel").unwrap_or(0)))
        .collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for (f, band, ch) in keys {
        let here: Vec<&Value> = nets.iter().filter(|n| n.get("frequency").and_then(Value::as_u64) == Some(f)).collect();
        out.push(section(&band, ch, here.len(), l));
        out.extend(here.into_iter().map(|n| row(n, l)));
    }
    out
}

/// A pill that can be clicked: the band filter.
fn pill(ui: &mut Ui, text: &str, on: bool) -> egui::Response {
    let v = ui.visuals().clone();
    let tone = if on { chip::BLUE.tone(&v) } else { chip::neutral_tone(&v) };
    let galley = chip::label_galley(ui.painter(), text, chip::small(ui), tone.ink);
    let pad = vec2(8.0, 2.0);
    let h = (galley.size().y + 2.0 * pad.y).min(ui.spacing().interact_size.y - 2.0);
    let (rect, resp) = ui.allocate_exact_size(vec2(galley.size().x + 2.0 * pad.x, h), Sense::click());
    if ui.is_rect_visible(rect) {
        let stroke = if on { Stroke::new(1.0, tone.ink) } else { tone.border.map_or(Stroke::NONE, |c| Stroke::new(1.0, c)) };
        ui.painter().rect(rect, 8.0, tone.fill, stroke, egui::StrokeKind::Inside);
        ui.painter().galley(rect.center() - galley.size() / 2.0, galley, tone.ink);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

impl ScanView {
    /// The networks of `heard` in the band filter.
    pub(crate) fn filter(&self, nets: &[Value]) -> Vec<Value> {
        match self.band.code() {
            None => nets.to_vec(),
            Some(b) => nets.iter().filter(|n| n.get("band").and_then(Value::as_str) == Some(b)).cloned().collect(),
        }
    }

    /// Forget what belongs to another radio.
    pub(crate) fn clear(&mut self) {
        self.survey = None;
        self.spectral = None;
        self.rows.clear();
        self.last_seq = 0;
        self.texture_seq = 0;
    }

    /// The queries of the view on radio `radio`.
    pub(crate) fn queries(&self, radio: &str, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if radio.is_empty() {
            return out;
        }
        if self.mode == Mode::Channels && app.has_command("interface.wifi.frequency-scan") {
            out.push(Query { key: "frequency-scan", command: "interface.wifi.frequency-scan", params: json!({ "name": radio }) });
        }
        if app.has_command("interface.wifi.spectral-data") {
            let params = if self.mode == Mode::Spectrum {
                json!({ "name": radio, "since": self.last_seq })
            } else {
                // Whether the radio has it, and whether one runs: the
                // selector says so.
                json!({ "name": radio, "limit": 0 })
            };
            out.push(Query { key: "spectral-data", command: "interface.wifi.spectral-data", params });
        }
        out
    }

    /// A reply of one of [`Self::queries`]; `true` when it was one.
    pub(crate) fn arrived(&mut self, key: &str, mut value: Value) -> bool {
        match key {
            "frequency-scan" => self.survey = Some(value),
            "spectral-data" => {
                let grid = (
                    value.get("start").and_then(Value::as_f64).unwrap_or(0.0),
                    value.get("step").and_then(Value::as_f64).unwrap_or(0.0),
                    value.get("points").and_then(Value::as_u64).unwrap_or(0),
                );
                let last = value.get("last_seq").and_then(Value::as_u64).unwrap_or(0);
                // A new scan (its sequence went back) or another grid.
                if last < self.last_seq || (grid.2 > 0 && grid != self.grid) {
                    self.rows.clear();
                    self.last_seq = 0;
                    self.texture_seq = 0;
                }
                if grid.2 > 0 {
                    self.grid = grid;
                }
                if let Some(Value::Array(rows)) = value.get_mut("rows").map(Value::take) {
                    for r in rows {
                        let seq = r.get("seq").and_then(Value::as_u64).unwrap_or(0);
                        if seq <= self.last_seq {
                            continue;
                        }
                        let values: Vec<i8> = r
                            .get("values")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().take(MAX_POINTS).map(|v| v.as_i64().and_then(|x| i8::try_from(x).ok()).unwrap_or(NONE)).collect())
                            .unwrap_or_default();
                        self.rows.push_back(values);
                        self.last_seq = seq;
                    }
                    while self.rows.len() > MAX_ROWS {
                        self.rows.pop_front();
                    }
                }
                // The summary (limit 0) keeps the traces of the last full one.
                let full = value.get("realtime").is_some();
                match (&mut self.spectral, full) {
                    (Some(old), false) => {
                        for k in ["supported", "why_not", "running", "seconds_left", "range"] {
                            if let (Some(o), Some(v)) = (old.as_object_mut(), value.get(k)) {
                                o.insert(k.to_owned(), v.clone());
                            }
                        }
                    }
                    _ => self.spectral = Some(value),
                }
            }
            _ => return false,
        }
        true
    }

    fn supported(&self) -> Result<(), String> {
        match &self.spectral {
            Some(d) if flag(d, "supported") => Ok(()),
            Some(d) => Err(s(d, "why_not")),
            None => Err(String::new()),
        }
    }

    /// The second line: the view, the band filter, the grouping.
    pub(crate) fn controls(&mut self, ui: &mut Ui, l: Lang, nets: &[Value], help: &mut Option<HelpView>) {
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "View"));
            if help::info_button(ui, Id::unique("wifi-view-help"), tr_in(SCOPE, l, "View")).clicked() {
                *help = Some(HelpView::new("interface.wifi.view", tr_in(SCOPE, l, "View")));
            }
            for (mode, label) in [(Mode::List, "List"), (Mode::Channels, "Channels"), (Mode::Spectrum, "Spectrum")] {
                let why = if mode == Mode::Spectrum { self.supported().err() } else { None };
                let enabled = why.is_none();
                let r = ui.add_enabled(enabled, egui::Button::selectable(self.mode == mode, tr_in(SCOPE, l, label)));
                let r = match why {
                    Some(w) if !w.is_empty() => r.on_disabled_hover_text(w),
                    _ => r,
                };
                if r.clicked() {
                    self.mode = mode;
                }
            }
            if self.mode != Mode::Spectrum {
                ui.separator();
                for band in [Band::All, Band::G2, Band::G5, Band::G6] {
                    let n = match band.code() {
                        None => nets.len(),
                        Some(b) => nets.iter().filter(|n| n.get("band").and_then(Value::as_str) == Some(b)).count(),
                    };
                    if n == 0 && band != Band::All {
                        continue;
                    }
                    let text = format!("{} {n}", tr_in(SCOPE, l, band.label()));
                    if pill(ui, &text, self.band == band).clicked() {
                        self.band = band;
                    }
                }
                if help::info_button(ui, Id::unique("wifi-band-help"), tr_in(SCOPE, l, "Band")).clicked() {
                    *help = Some(HelpView::new("interface.wifi.band-filter", tr_in(SCOPE, l, "Band")));
                }
            }
            if self.mode == Mode::List {
                ui.separator();
                ui.checkbox(&mut self.group, tr_in(SCOPE, l, "Group by channel"));
                if help::info_button(ui, Id::unique("wifi-group-help"), tr_in(SCOPE, l, "Group by channel")).clicked() {
                    *help = Some(HelpView::new("interface.wifi.group", tr_in(SCOPE, l, "Group by channel")));
                }
            }
        });
        // The spectral scan's support went away (another radio): back.
        if self.mode == Mode::Spectrum && self.supported().is_err() && self.spectral.is_some() {
            self.mode = Mode::List;
        }
    }

    /// Under the list: the channel each band has the least on.
    pub(crate) fn suggestion(&self, ui: &mut Ui, l: Lang, heard: Option<&Value>, help: &mut Option<HelpView>) {
        let Some(sug) = heard.and_then(|h| h.get("suggested")).and_then(Value::as_array).filter(|a| !a.is_empty()) else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Least busy channel"));
            if help::info_button(ui, Id::unique("wifi-suggest-help"), tr_in(SCOPE, l, "Least busy channel")).clicked() {
                *help = Some(HelpView::new("interface.wifi.suggested", tr_in(SCOPE, l, "Least busy channel")));
            }
            let v = ui.visuals().clone();
            for g in sug {
                let text = format!("{} ch {}", band_label(&s(g, "band")), s(g, "channel"));
                let tip = format!(
                    "{} {} · {} {}%",
                    s(g, "networks"),
                    tr_in(SCOPE, l, "networks over it"),
                    tr_in(SCOPE, l, "estimated airtime"),
                    s(g, "score")
                );
                chip::chip(ui, &text, chip::GREEN.tone(&v)).on_hover_text(tip);
                if flag(g, "dfs") {
                    chip::chip(ui, "DFS", chip::AMBER.tone(&v));
                }
            }
        });
    }

    // ---- Channels ----------------------------------------------------------

    /// The channel graph of each band in the filter.
    pub(crate) fn channels(&mut self, ui: &mut Ui, l: Lang, nets: &[Value], help: &mut Option<HelpView>) {
        let mut bands: Vec<&'static str> = ["2ghz", "5ghz", "6ghz"]
            .into_iter()
            .filter(|b| self.band.code().is_none_or(|f| f == *b))
            .filter(|b| nets.iter().any(|n| n.get("band").and_then(Value::as_str) == Some(*b)))
            .collect();
        if bands.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No network heard in this band: Rescan listens on every channel."));
            return;
        }
        bands.truncate(3);
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Busy share of each channel"));
            if help::info_button(ui, Id::unique("wifi-survey-help"), tr_in(SCOPE, l, "Busy share of each channel")).clicked() {
                *help = Some(HelpView::new("interface.wifi.survey", tr_in(SCOPE, l, "Busy share of each channel")));
            }
            let v = ui.visuals().clone();
            let (text, tone) = match self.survey.as_ref().map(|s| s.get("survey").and_then(Value::as_str).unwrap_or("none")) {
                Some("full") => ("counted on every channel", chip::GREEN.tone(&v)),
                Some("partial") => ("the driver counts only the channel in use", chip::AMBER.tone(&v)),
                _ => ("the driver does not count it", chip::neutral_tone(&v)),
            };
            chip::chip(ui, tr_in(SCOPE, l, text), tone);
        });
        let channels: Vec<Value> = self
            .survey
            .as_ref()
            .and_then(|s| s.get("channels"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // The height there is, less the spacing egui puts between the
        // graphs: taking more makes the window grow a little every frame.
        let avail = ui.available_size();
        let gap = ui.spacing().item_spacing.y;
        let n = bands.len() as f32;
        let each = ((avail.y - gap * n - 4.0) / n).max(120.0);
        for b in bands {
            let (rect, _) = ui.allocate_exact_size(vec2(avail.x, each), Sense::hover());
            if ui.is_rect_visible(rect) {
                draw_band(ui, rect, b, nets, &channels, l);
            }
        }
    }

    // ---- Spectrum ----------------------------------------------------------

    /// The spectral scan: its controls, then the waterfall, the traces, the
    /// channels' usage and what the energy looks like.
    pub(crate) fn spectrum(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang, radio: &str, help: &mut Option<HelpView>) {
        if let Err(why) = self.supported() {
            ui.weak(if why.is_empty() { tr_in(SCOPE, l, "Asking the radio…").to_owned() } else { why });
            keep_height(ui);
            return;
        }
        let d = self.spectral.clone().unwrap_or(Value::Null);
        let running = flag(&d, "running");
        let can = app.can();
        let mut start = false;
        let mut stop = false;
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Range"));
            if help::info_button(ui, Id::unique("wifi-range-help"), tr_in(SCOPE, l, "Range")).clicked() {
                *help = Some(HelpView::new("interface.wifi.spectral.range", tr_in(SCOPE, l, "Range")));
            }
            egui::ComboBox::from_id_salt("wifi-spectral-range")
                .selected_text(tr_in(SCOPE, l, range_label(self.range)))
                .show_ui(ui, |ui| {
                    for r in ["current", "2ghz", "5ghz"] {
                        if ui.selectable_label(self.range == r, tr_in(SCOPE, l, range_label(r))).clicked() {
                            self.range = r;
                        }
                    }
                });
            ui.label(tr_in(SCOPE, l, "Duration"));
            ui.add(egui::DragValue::new(&mut self.duration).range(1..=600).suffix(" s"));
            if running {
                if table::action(ui, tr_in(SCOPE, l, "Stop"), can.check("interface.wifi.spectral-scan")) {
                    stop = true;
                }
            } else if table::action(ui, tr_in(SCOPE, l, "Start"), can.check("interface.wifi.spectral-scan")) {
                start = true;
            }
            let v = ui.visuals().clone();
            if running {
                let left = s(&d, "seconds_left");
                chip::chip(ui, &format!("{} · {left} s", tr_in(SCOPE, l, "scanning")), chip::BLUE.tone(&v));
            } else if d.get("realtime").is_some() {
                chip::chip(ui, tr_in(SCOPE, l, "stopped"), chip::neutral_tone(&v));
            }
            if let Some(n) = d.get("noise").and_then(Value::as_i64) {
                ui.weak(format!("{} {n} dBm", tr_in(SCOPE, l, "noise floor")));
            }
        });
        if self.range != "current" {
            ui.weak(tr_in(SCOPE, l, "A band is swept by scanning: the radio leaves its channel for a moment every few seconds, and the link stalls while it does."));
        }
        if start {
            self.rows.clear();
            self.last_seq = 0;
            self.texture_seq = 0;
            app.run("interface.wifi.spectral-scan", json!({ "name": radio, "range": self.range, "duration": self.duration }));
        }
        if stop {
            app.run("interface.wifi.spectral-scan", json!({ "name": radio, "stop": true }));
        }
        let points = d.get("points").and_then(Value::as_u64).unwrap_or(0) as usize;
        if points == 0 || self.rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No samples yet: Start listens for the seconds set."));
            keep_height(ui);
            return;
        }
        let start_mhz = d.get("start").and_then(Value::as_f64).unwrap_or(0.0) as f32;
        let step = d.get("step").and_then(Value::as_f64).unwrap_or(1.0) as f32;
        let axis = Axis { lo: start_mhz - step / 2.0, hi: start_mhz + step * (points as f32 - 0.5) };
        let noise = d.get("noise").and_then(Value::as_i64).unwrap_or(-95) as f32;
        let avail = ui.available_size();
        let usage_h = 48.0;
        let line = ui.spacing().interact_size.y + ui.spacing().item_spacing.y;
        // Three titles, the sources (two lines when they wrap) and the
        // spacing between the six parts: taking more makes the window grow.
        let rest = (avail.y - usage_h - 5.0 * line - 6.0 * ui.spacing().item_spacing.y - 4.0).max(140.0);
        let (fall_h, trace_h) = (rest * 0.55, rest * 0.45);

        // The waterfall.
        section_title(ui, l, "Waterfall", "interface.wifi.spectral.waterfall", help);
        let (rect, _) = ui.allocate_exact_size(vec2(avail.x, fall_h), Sense::hover());
        self.waterfall(ui, rect, points, noise);
        // The traces.
        section_title(ui, l, "Real-time, average and peak", "interface.wifi.spectral.trace", help);
        let (rect, _) = ui.allocate_exact_size(vec2(avail.x, trace_h), Sense::hover());
        let plot = draw_axes(ui, rect, &axis, -110, -20, l);
        let v = ui.visuals().clone();
        let to_line = |vals: Option<&Vec<Value>>, color: Color32, width: f32| -> Option<Shape> {
            let pts: Vec<Pos2> = vals?
                .iter()
                .enumerate()
                .filter_map(|(i, x)| x.as_i64().filter(|&x| x > -128).map(|x| (i, x)))
                .map(|(i, x)| Pos2::new(axis.x(plot, start_mhz + step * i as f32), y_of(plot, x as f32, -110.0, -20.0)))
                .collect();
            (pts.len() > 1).then(|| Shape::line(pts, Stroke::new(width, color)))
        };
        let arr = |k: &str| d.get(k).and_then(Value::as_array);
        for shape in [
            to_line(arr("peak"), chip::AMBER.tone(&v).ink.gamma_multiply(0.8), 1.0),
            to_line(arr("average"), chip::BLUE.tone(&v).ink, 1.5),
            to_line(arr("realtime"), chip::GREEN.tone(&v).ink, 1.0),
        ]
        .into_iter()
        .flatten()
        {
            ui.painter_at(plot).add(shape);
        }
        legend(ui, plot, &[("peak", chip::AMBER.tone(&v).ink), ("average", chip::BLUE.tone(&v).ink), ("real-time", chip::GREEN.tone(&v).ink)], l);
        // Each channel's usage.
        section_title(ui, l, "Channel usage", "interface.wifi.spectral.usage", help);
        let (rect, _) = ui.allocate_exact_size(vec2(avail.x, usage_h), Sense::hover());
        let usage: Vec<(f32, f64, u64)> = arr("channels")
            .map(|a| {
                a.iter()
                    .filter_map(|c| Some((c.get("frequency")?.as_f64()? as f32, c.get("usage")?.as_f64()?, c.get("channel")?.as_u64()?)))
                    .collect()
            })
            .unwrap_or_default();
        draw_usage(ui, rect, &axis, &usage);
        // What the energy looks like.
        ui.horizontal_wrapped(|ui| {
            ui.label(tr_in(SCOPE, l, "Sources"));
            if help::info_button(ui, Id::unique("wifi-interference-help"), tr_in(SCOPE, l, "Sources")).clicked() {
                *help = Some(HelpView::new("interface.wifi.spectral.interference", tr_in(SCOPE, l, "Sources")));
            }
            let found = arr("interference").cloned().unwrap_or_default();
            if found.is_empty() {
                ui.weak(tr_in(SCOPE, l, "nothing stands out of the noise"));
            }
            for i in found.iter().take(24) {
                let kind = s(i, "kind");
                let k = match kind.as_str() {
                    "wifi" => Kind::Blue,
                    "cw" => Kind::Red,
                    "mwo" | "bluetooth" | "fhss" => Kind::Amber,
                    _ => Kind::Neutral,
                };
                let text = format!("{} {} MHz", tr_in(SCOPE, l, kind_label(&kind)), s(i, "frequency"));
                let tip = format!("{} {} MHz · {} {} dBm · {} {}%", tr_in(SCOPE, l, "width"), s(i, "width"), tr_in(SCOPE, l, "peak"), s(i, "peak"), tr_in(SCOPE, l, "on"), s(i, "duty"));
                chip::chip(ui, &text, k.tone(&v)).on_hover_text(tip);
            }
        });
    }

    /// The rows as an image, newest on top: from the noise floor (dark
    /// blue) up 50 dB (red), rebuilt only when a row arrived.
    fn waterfall(&mut self, ui: &mut Ui, rect: Rect, points: usize, noise: f32) {
        let width = points.clamp(1, MAX_POINTS);
        let height = self.rows.len().max(1);
        if self.texture.is_none() || self.texture_seq != self.last_seq {
            let bg = ui.visuals().extreme_bg_color;
            let mut pixels = Vec::with_capacity(width * height);
            for r in self.rows.iter().rev() {
                for i in 0..width {
                    pixels.push(match r.get(i).copied() {
                        Some(v) if v != NONE => heat((f32::from(v) - noise + 3.0) / 50.0),
                        _ => bg,
                    });
                }
            }
            pixels.resize(width * height, bg);
            let image = egui::ColorImage::new([width, height], pixels);
            match &mut self.texture {
                Some(t) => t.set(image, egui::TextureOptions::NEAREST),
                None => self.texture = Some(ui.ctx().load_texture("wifi-waterfall", image, egui::TextureOptions::NEAREST)),
            }
            self.texture_seq = self.last_seq;
        }
        if let Some(t) = &self.texture {
            let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
            // Fewer rows than the full minute fill the top only.
            let h = rect.height() * (height as f32 / MAX_ROWS as f32).clamp(0.05, 1.0);
            let img = Rect::from_min_size(rect.min, vec2(rect.width(), h));
            ui.painter().rect_filled(rect, 2.0, ui.visuals().extreme_bg_color);
            ui.painter().image(t.id(), img, uv, Color32::WHITE);
            ui.painter().rect_stroke(rect, 2.0, ui.visuals().widgets.noninteractive.bg_stroke, egui::StrokeKind::Inside);
        }
    }
}

/// Take the rest of the window, so that it keeps its size while there is
/// nothing to draw yet (less the spacing, or it would grow every frame).
fn keep_height(ui: &mut Ui) {
    let room = ui.available_size() - vec2(0.0, ui.spacing().item_spacing.y + 4.0);
    ui.allocate_space(room.max(egui::Vec2::ZERO));
}

fn range_label(code: &str) -> &'static str {
    match code {
        "2ghz" => "2.4 GHz band",
        "5ghz" => "5 GHz band",
        _ => "channel in use",
    }
}

fn kind_label(code: &str) -> &'static str {
    match code {
        "wifi" => "Wi-Fi",
        "cw" => "carrier",
        "mwo" => "microwave oven",
        "bluetooth" => "Bluetooth",
        "fhss" => "hopper",
        _ => "unknown",
    }
}

/// The colour of `t` (0 = the noise floor, 1 = 50 dB above): dark blue,
/// blue, cyan, green, yellow, red, as airView's waterfall.
fn heat(t: f32) -> Color32 {
    let stops: [(f32, [u8; 3]); 6] = [
        (0.0, [10, 20, 70]),
        (0.2, [20, 70, 200]),
        (0.4, [20, 190, 220]),
        (0.6, [60, 200, 70]),
        (0.8, [240, 220, 40]),
        (1.0, [230, 40, 30]),
    ];
    let t = t.clamp(0.0, 1.0);
    let mut prev = (0.0, [10u8, 20, 70]);
    for (at, [r, g, b]) in stops {
        if t <= at {
            let [pr, pg, pb] = prev.1;
            let k = (t - prev.0) / (at - prev.0).max(1e-3);
            let mix = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * k) as u8;
            return Color32::from_rgb(mix(pr, r), mix(pg, g), mix(pb, b));
        }
        prev = (at, [r, g, b]);
    }
    Color32::from_rgb(230, 40, 30)
}

fn section_title(ui: &mut Ui, l: Lang, title: &'static str, key: &'static str, help: &mut Option<HelpView>) {
    ui.horizontal(|ui| {
        ui.strong(tr_in(SCOPE, l, title));
        if help::info_button(ui, Id::unique(("wifi-section-help", key)), tr_in(SCOPE, l, title)).clicked() {
            *help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    });
}

/// A frequency axis, MHz.
struct Axis {
    lo: f32,
    hi: f32,
}

impl Axis {
    fn x(&self, plot: Rect, mhz: f32) -> f32 {
        plot.left() + (mhz - self.lo) / (self.hi - self.lo).max(1.0) * plot.width()
    }

    fn of_band(band: &str) -> Self {
        match band {
            "2ghz" => Self { lo: 2399.0, hi: 2487.0 },
            "6ghz" => Self { lo: 5945.0, hi: 7125.0 },
            _ => Self { lo: 5165.0, hi: 5840.0 },
        }
    }
}

fn y_of(plot: Rect, dbm: f32, lo: f32, hi: f32) -> f32 {
    plot.bottom() - ((dbm - lo) / (hi - lo)).clamp(0.0, 1.0) * plot.height()
}

/// The frame, the dBm grid on the left and the channel numbers under it;
/// returns the plot's inner rect.
fn draw_axes(ui: &Ui, rect: Rect, axis: &Axis, lo: i32, hi: i32, l: Lang) -> Rect {
    let v = ui.visuals();
    let p = ui.painter_at(rect);
    let font = egui::FontId::proportional(chip::small(ui));
    let plot = Rect::from_min_max(rect.min + vec2(44.0, 6.0), rect.max - vec2(6.0, 18.0));
    p.rect_filled(plot, 2.0, v.extreme_bg_color);
    let grid = v.widgets.noninteractive.bg_stroke.color.gamma_multiply(0.6);
    let weak = v.weak_text_color();
    let mut d = lo;
    while d <= hi {
        let y = y_of(plot, d as f32, lo as f32, hi as f32);
        p.line_segment([Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)], Stroke::new(0.5, grid));
        p.text(Pos2::new(plot.left() - 4.0, y), egui::Align2::RIGHT_CENTER, format!("{d}"), font.clone(), weak);
        d += 20;
    }
    p.text(Pos2::new(plot.left() - 4.0, plot.bottom() + 4.0), egui::Align2::RIGHT_TOP, "dBm", font.clone(), weak);
    // Channel numbers: as many as fit 40 px apart (every channel on
    // 2.4 GHz; on the wide bands every 4th, 8th or 16th).
    let px_per_ch = plot.width() / ((axis.hi - axis.lo) / 5.0).max(1.0);
    let every = [1u32, 2, 4, 8, 16].into_iter().find(|e| px_per_ch * *e as f32 >= 40.0).unwrap_or(32);
    let (first, base, every) = if axis.hi < 3000.0 {
        (1, 2407.0, every.max(1))
    } else if axis.lo >= 5925.0 {
        (1, 5950.0, every.max(4))
    } else {
        (36, 5000.0, every.max(4))
    };
    // The first label on the grid of `every` from `first`, inside the axis.
    let skip = ((axis.lo - base) / 5.0 - first as f32).max(0.0) as u32;
    let first = first + skip.div_ceil(every) * every;
    let mut ch = first;
    let last = if axis.hi < 3000.0 { 14 } else { 233 };
    while ch <= last {
        let f = if axis.hi < 3000.0 && ch == 14 { 2484.0 } else { base + 5.0 * ch as f32 };
        if f > axis.hi {
            break;
        }
        if f >= axis.lo {
            let x = axis.x(plot, f);
            p.line_segment([Pos2::new(x, plot.bottom()), Pos2::new(x, plot.bottom() + 3.0)], Stroke::new(1.0, weak));
            p.text(Pos2::new(x, plot.bottom() + 4.0), egui::Align2::CENTER_TOP, format!("{ch}"), font.clone(), weak);
        }
        ch += every;
    }
    let _ = l;
    p.rect_stroke(plot, 2.0, v.widgets.noninteractive.bg_stroke, egui::StrokeKind::Inside);
    plot
}

fn legend(ui: &Ui, plot: Rect, items: &[(&'static str, Color32)], l: Lang) {
    let p = ui.painter_at(plot);
    let font = egui::FontId::proportional(chip::small(ui));
    let mut x = plot.right() - 8.0;
    for (label, color) in items.iter().rev() {
        let g = p.layout_no_wrap(tr_in(SCOPE, l, label).to_owned(), font.clone(), *color);
        x -= g.size().x;
        p.galley(Pos2::new(x, plot.top() + 4.0), g, *color);
        x -= 18.0;
        p.line_segment([Pos2::new(x, plot.top() + 10.0), Pos2::new(x + 12.0, plot.top() + 10.0)], Stroke::new(2.0, *color));
        x -= 10.0;
    }
}

/// One band of the channel graph: each network a curve over its channel's
/// width as tall as its signal, under it the survey's busy share.
fn draw_band(ui: &Ui, rect: Rect, band: &str, nets: &[Value], channels: &[Value], l: Lang) {
    let v = ui.visuals().clone();
    let bar_h = 30.0;
    let graph = Rect::from_min_max(rect.min, rect.max - vec2(0.0, bar_h + 4.0));
    let axis = Axis::of_band(band);
    let plot = draw_axes(ui, graph, &axis, -100, -20, l);
    let p = ui.painter_at(plot);
    let font = egui::FontId::proportional(chip::small(ui));
    p.text(plot.left_top() + vec2(6.0, 4.0), egui::Align2::LEFT_TOP, band_label(band), font.clone(), v.weak_text_color());
    let mut mine: Vec<&Value> = nets.iter().filter(|n| n.get("band").and_then(Value::as_str) == Some(band)).collect();
    // Labels already placed: one that would cover another goes lower.
    let mut placed: Vec<Rect> = Vec::new();
    // The weak ones first: the strong ones on top.
    mine.sort_by_key(|n| int(n, "signal").unwrap_or(-100));
    for n in mine {
        let (Some(low), Some(high), Some(sig)) = (int(n, "low"), int(n, "high"), int(n, "signal")) else {
            continue;
        };
        let ssid = s(n, "ssid");
        let tone: Tone = chip::palette_tone(&v, chip::name_hue(if ssid.is_empty() { "?" } else { &ssid }));
        let base = plot.bottom();
        let top = y_of(plot, sig as f32, -100.0, -20.0);
        let (x0, x1) = (axis.x(plot, low as f32), axis.x(plot, high as f32));
        // A rounded block: the edges rise over 12% of the width.
        let pts: Vec<Pos2> = (0..=48)
            .map(|k| {
                let t = k as f32 / 48.0;
                let edge = (t.min(1.0 - t) / 0.12).min(1.0);
                let rise = (edge * std::f32::consts::FRAC_PI_2).sin();
                Pos2::new(x0 + (x1 - x0) * t, base - (base - top) * rise)
            })
            .collect();
        let yours = flag(n, "connected");
        let fill = Color32::from_rgba_unmultiplied(tone.ink.r(), tone.ink.g(), tone.ink.b(), if yours { 70 } else { 40 });
        p.add(Shape::convex_polygon(pts.clone(), fill, Stroke::NONE));
        p.add(Shape::line(pts, Stroke::new(if yours { 2.5 } else { 1.2 }, tone.ink)));
        let name = if ssid.is_empty() { tr_in(SCOPE, l, "hidden").to_owned() } else { ssid };
        let label = if yours { format!("{name} · {}", tr_in(SCOPE, l, "yours")) } else { name };
        let galley = p.layout_no_wrap(label, font.clone(), tone.ink);
        let size = galley.size();
        let mut at = Rect::from_center_size(Pos2::new((x0 + x1) / 2.0, top - 2.0 - size.y / 2.0), size);
        while placed.iter().any(|r| r.intersects(at)) && at.bottom() < base {
            at = at.translate(vec2(0.0, size.y));
        }
        placed.push(at);
        p.galley(at.min, galley, tone.ink);
    }
    // The busy bars.
    let bars = Rect::from_min_max(Pos2::new(plot.left(), rect.bottom() - bar_h), Pos2::new(plot.right(), rect.bottom()));
    let bp = ui.painter_at(bars);
    bp.rect_filled(bars, 2.0, v.extreme_bg_color);
    // A bar per channel, as wide as the channels are apart (5 MHz on
    // 2.4 GHz, 20 on the others).
    let half = if band == "2ghz" { 2.2 } else { 9.0 };
    for c in channels.iter().filter(|c| c.get("band").and_then(Value::as_str) == Some(band)) {
        let Some(f) = c.get("frequency").and_then(Value::as_f64) else { continue };
        let (x0, x1) = (axis.x(bars, f as f32 - half), axis.x(bars, f as f32 + half));
        match c.get("load").and_then(Value::as_f64) {
            Some(load) => {
                let k = if load >= 60.0 { chip::RED.tone(&v) } else if load >= 30.0 { chip::AMBER.tone(&v) } else { chip::GREEN.tone(&v) };
                let h = (bars.height() - 12.0) * (load as f32 / 100.0).clamp(0.02, 1.0);
                let r = Rect::from_min_max(Pos2::new(x0, bars.bottom() - h), Pos2::new(x1, bars.bottom()));
                bp.rect_filled(r, 1.0, k.ink.gamma_multiply(0.7));
                if x1 - x0 > 24.0 {
                    bp.text(Pos2::new((x0 + x1) / 2.0, bars.top()), egui::Align2::CENTER_TOP, format!("{load:.0}%"), font.clone(), k.ink);
                }
                if flag(c, "in_use") {
                    bp.rect_stroke(r, 1.0, Stroke::new(1.5, chip::GREEN.tone(&v).ink), egui::StrokeKind::Outside);
                }
            }
            None => {
                if x1 - x0 > 10.0 {
                    bp.text(Pos2::new((x0 + x1) / 2.0, bars.center().y), egui::Align2::CENTER_CENTER, "–", font.clone(), v.weak_text_color());
                }
            }
        }
    }
    bp.rect_stroke(bars, 2.0, v.widgets.noninteractive.bg_stroke, egui::StrokeKind::Inside);
}

/// The usage of each channel of the spectrum, as bars under the traces.
fn draw_usage(ui: &Ui, rect: Rect, axis: &Axis, usage: &[(f32, f64, u64)]) {
    let v = ui.visuals().clone();
    let plot = Rect::from_min_max(rect.min + vec2(44.0, 0.0), rect.max - vec2(6.0, 0.0));
    let p = ui.painter_at(plot);
    p.rect_filled(plot, 2.0, v.extreme_bg_color);
    let font = egui::FontId::proportional(chip::small(ui));
    for &(f, u, ch) in usage {
        // As wide as the channels are apart (5 MHz on 2.4 GHz, 20 above).
        let half = if f < 3000.0 { 2.2 } else { 9.0 };
        let (x0, x1) = (axis.x(plot, f - half), axis.x(plot, f + half));
        let k = if u >= 60.0 { chip::RED.tone(&v) } else if u >= 30.0 { chip::AMBER.tone(&v) } else { chip::GREEN.tone(&v) };
        let h = (plot.height() - 14.0) * (u as f32 / 100.0).clamp(0.02, 1.0);
        p.rect_filled(Rect::from_min_max(Pos2::new(x0, plot.bottom() - h), Pos2::new(x1, plot.bottom())), 1.0, k.ink.gamma_multiply(0.7));
        if x1 - x0 > 22.0 {
            p.text(Pos2::new((x0 + x1) / 2.0, plot.top()), egui::Align2::CENTER_TOP, format!("ch {ch} {u:.0}%"), font.clone(), k.ink);
        }
    }
    p.rect_stroke(plot, 2.0, v.widgets.noninteractive.bg_stroke, egui::StrokeKind::Inside);
}

/// The explanation keys of the views (tests: each in both languages).
#[cfg(test)]
pub(crate) fn help_keys() -> Vec<&'static str> {
    COLUMNS
        .iter()
        .map(|c| c.help)
        .chain([
            "interface.wifi.view",
            "interface.wifi.band-filter",
            "interface.wifi.group",
            "interface.wifi.suggested",
            "interface.wifi.survey",
            "interface.wifi.spectral.range",
            "interface.wifi.spectral.waterfall",
            "interface.wifi.spectral.trace",
            "interface.wifi.spectral.usage",
            "interface.wifi.spectral.interference",
        ])
        .collect()
}

/// The labels of the views (tests: each in the Portuguese catalog).
#[cfg(test)]
pub(crate) fn labels() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = COLUMNS.iter().map(|c| c.title).collect();
    out.extend([
        "View", "List", "Channels", "Spectrum", "All", "Band", "Group by channel", "yours", "hidden",
        "client", "clients", "same channel", "overlaps ch", "shares airtime", "network", "networks",
        "Least busy channel", "networks over it", "estimated airtime", "Busy share of each channel",
        "counted on every channel", "the driver counts only the channel in use", "the driver does not count it",
        "Range", "Duration", "Start", "Stop", "scanning", "stopped", "noise floor", "Waterfall",
        "Real-time, average and peak", "Channel usage", "Sources", "peak", "average", "real-time",
        "nothing stands out of the noise", "width", "on",
    ]);
    out.extend(["current", "2ghz", "5ghz"].map(range_label));
    out.extend(["wifi", "cw", "mwo", "bluetooth", "fhss", "unknown"].map(kind_label));
    out
}

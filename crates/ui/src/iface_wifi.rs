//! G1.30g: the Wi-Fi and Radio tabs of "Interface <name>" for a Wi-Fi port.
//!
//! Wi-Fi is the link (`interface.wifi.monitor`, every second): the network
//! and access point, the signal and how it reads, the channel, both rates,
//! retries and the address. Radio is the card (`interface.wifi.radio`,
//! every 10 s): driver, firmware, standards, bands with their channels and
//! power, antennas, transmit power and the radio switch. A value the driver
//! does not report is left out and named in one line at the end, so the
//! tab does not fill with "not supported".

use egui::{CollapsingHeader, Grid, RichText, Ui};
use serde_json::Value;

use crate::iface_tabs::{loaded, notes};
use crate::value_text;

type Help<'a> = &'a mut Option<(&'static str, &'static str)>;

/// The label column of every grid of both tabs, so the sections line up.
const LABEL_WIDTH: f32 = 120.0;

/// Rows of one grid; a row without a value goes to `missing`.
struct Rows<'h, 'm> {
    help: Help<'h>,
    missing: &'m mut Vec<&'static str>,
}

impl Rows<'_, '_> {
    /// The label with its ⓘ (explanation `key`), then the value.
    fn label(&mut self, ui: &mut Ui, label: &'static str, key: &'static str) {
        ui.horizontal(|ui| {
            ui.label(label);
            if crate::help::info_button(ui, ui.scope_id().with(key), "What is this?").clicked() {
                *self.help = Some((key, label));
            }
        });
    }

    fn text(&mut self, ui: &mut Ui, label: &'static str, key: &'static str, value: Option<String>) {
        let Some(v) = value else {
            self.missing.push(label);
            return;
        };
        self.label(ui, label, key);
        ui.add(egui::Label::new(v).wrap());
        ui.end_row();
    }

    /// A value with a coloured chip after it (a state, a quality).
    fn chip(
        &mut self,
        ui: &mut Ui,
        label: &'static str,
        key: &'static str,
        chip: Option<(&str, &crate::chip::Hue)>,
        rest: Option<String>,
    ) {
        if chip.is_none() && rest.is_none() {
            self.missing.push(label);
            return;
        }
        self.label(ui, label, key);
        ui.horizontal_wrapped(|ui| {
            if let Some((text, hue)) = chip {
                crate::chip::chip(ui, text, hue.tone(ui.visuals()));
            }
            if let Some(r) = rest {
                ui.label(r);
            }
        });
        ui.end_row();
    }
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key).filter(|x| !x.is_null()).map(value_text)
}

fn int(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

fn uint(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

/// `2ghz` → `2.4 GHz`.
fn band_name(b: &str) -> &str {
    match b {
        "2ghz" => "2.4 GHz",
        "5ghz" => "5 GHz",
        "6ghz" => "6 GHz",
        other => other,
    }
}

/// The parts that exist, joined by ` · `.
fn joined(parts: impl IntoIterator<Item = Option<String>>) -> Option<String> {
    let v: Vec<String> = parts.into_iter().flatten().collect();
    (!v.is_empty()).then(|| v.join(" · "))
}

/// The state's chip: green connected, amber on its way, red when it
/// cannot (blocked, error, no country), none when idle or disabled.
fn state_hue(state: &str) -> Option<&'static crate::chip::Hue> {
    match state {
        "connected" => Some(&crate::chip::GREEN),
        "searching" | "connecting" => Some(&crate::chip::AMBER),
        "blocked" | "error" | "no-country" | "absent" => Some(&crate::chip::RED),
        _ => None,
    }
}

fn quality_hue(q: &str) -> &'static crate::chip::Hue {
    match q {
        "excellent" | "good" => &crate::chip::GREEN,
        "fair" => &crate::chip::AMBER,
        _ => &crate::chip::RED,
    }
}

/// "Not reported by this driver: …" for what was left out.
fn missing_line(ui: &mut Ui, missing: &[&str]) {
    if missing.is_empty() {
        return;
    }
    ui.add_space(4.0);
    ui.add(
        egui::Label::new(
            RichText::new(format!("Not reported by this driver: {}", missing.join(", ")))
                .weak()
                .italics(),
        )
        .wrap(),
    );
}

fn section(ui: &mut Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).strong());
}

/// The Wi-Fi tab: the link right now.
pub(crate) fn wifi(ui: &mut Ui, r: &Option<Result<Value, String>>, help: Help<'_>) {
    let Some(m) = loaded(ui, r) else {
        return;
    };
    let state = text(m, "state").unwrap_or_default();
    let connected = state == "connected";
    let mut missing = Vec::new();
    let mut rows = Rows {
        help,
        missing: &mut missing,
    };
    Grid::new("iface-wifi-link")
        .num_columns(2)
        .min_col_width(LABEL_WIDTH)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            let since = uint(m, "uptime_secs")
                .filter(|_| connected)
                .map(|s| format!("for {}", crate::firewall::duration(s)));
            let reconnects = uint(m, "reconnects")
                .filter(|n| *n > 0)
                .map(|n| format!("{n} reconnect{}", if n == 1 { "" } else { "s" }));
            rows.chip(
                ui,
                "State",
                "iface_wifi.state",
                state_hue(&state).map(|h| (state.as_str(), h)),
                joined([(state_hue(&state).is_none()).then(|| state.clone()), since, reconnects]),
            );
            let pmf = m.get("pmf").and_then(Value::as_bool).map(|p| {
                if p { "PMF on" } else { "PMF off" }.to_owned()
            });
            rows.text(
                ui,
                "Network",
                "iface_wifi.network",
                joined([
                    text(m, "ssid"),
                    text(m, "security").map(|s| s.to_ascii_uppercase()),
                    text(m, "cipher"),
                    pmf,
                ]),
            );
            if !connected {
                return;
            }
            rows.text(ui, "Access Point", "iface_wifi.ap", text(m, "bssid"));
            let quality = text(m, "quality");
            let averages = joined([
                int(m, "signal_avg").map(|a| format!("avg {a}")),
                int(m, "beacon_signal").map(|b| format!("beacons {b}")),
            ]);
            rows.chip(
                ui,
                "Signal",
                "iface_wifi.signal",
                quality.as_deref().map(|q| (q, quality_hue(q))),
                joined([int(m, "signal").map(|s| format!("{s} dBm")), averages]),
            );
            let chains: Vec<String> = m
                .get("chain_signal")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).map(|c| c.to_string()).collect())
                .unwrap_or_default();
            rows.text(
                ui,
                "Per Antenna",
                "iface_wifi.chains",
                (!chains.is_empty()).then(|| format!("{} dBm", chains.join(", "))),
            );
            rows.text(
                ui,
                "Noise / SNR",
                "iface_wifi.noise",
                joined([
                    int(m, "noise").map(|n| format!("{n} dBm")),
                    int(m, "snr").map(|s| format!("SNR {s} dB")),
                ]),
            );
        });
    if connected {
        section(ui, "Channel");
        Grid::new("iface-wifi-channel")
            .num_columns(2)
        .min_col_width(LABEL_WIDTH)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                let standard = match (text(m, "standard"), uint(m, "generation")) {
                    (Some(s), Some(g)) => Some(format!("{s} (Wi-Fi {g})")),
                    (s, _) => s,
                };
                rows.text(
                    ui,
                    "Band",
                    "iface_wifi.band",
                    joined([text(m, "band").map(|b| band_name(&b).to_owned()), standard]),
                );
                let centre = match (uint(m, "center_frequency"), uint(m, "frequency")) {
                    (Some(c), Some(f)) if c != f => Some(format!("centre {c} MHz")),
                    _ => None,
                };
                rows.text(
                    ui,
                    "Channel",
                    "iface_wifi.channel",
                    joined([
                        text(m, "channel"),
                        text(m, "frequency").map(|f| format!("{f} MHz")),
                        text(m, "width").map(|w| format!("{w} MHz wide")),
                        centre,
                    ]),
                );
            });
        section(ui, "Rates");
        Grid::new("iface-wifi-rates")
            .num_columns(2)
        .min_col_width(LABEL_WIDTH)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                let rate = |k: &str| m.get(k).and_then(|r| text(r, "text")).filter(|t| !t.is_empty());
                let tx = rate("tx_rate").or_else(|| text(m, "rate").map(|r| format!("{r} Mbit/s")));
                rows.text(ui, "TX Rate", "iface_wifi.tx_rate", tx);
                rows.text(ui, "RX Rate", "iface_wifi.rx_rate", rate("rx_rate"));
                let retries = match (m.get("retry_percent").and_then(Value::as_f64), uint(m, "tx_retries"), uint(m, "tx_packets")) {
                    (Some(p), Some(r), Some(t)) => Some(format!("{p} % ({r} of {t} frames)")),
                    (None, Some(r), _) => Some(r.to_string()),
                    _ => None,
                };
                rows.text(
                    ui,
                    "Retries",
                    "iface_wifi.retries",
                    joined([retries, uint(m, "tx_failed").map(|f| format!("{f} failed"))]),
                );
                rows.text(ui, "Beacons Lost", "iface_wifi.beacons", text(m, "beacon_loss"));
                rows.text(
                    ui,
                    "Last Heard",
                    "iface_wifi.last_heard",
                    uint(m, "inactive_ms").map(|ms| format!("{ms} ms ago")),
                );
            });
    }
    section(ui, "Address");
    Grid::new("iface-wifi-address")
        .num_columns(2)
        .min_col_width(LABEL_WIDTH)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            let addresses: Vec<String> = m
                .get("addresses")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| {
                            let addr = text(x, "address")?;
                            let dynamic = x.get("dynamic").and_then(Value::as_bool) == Some(true);
                            Some(if dynamic { format!("{addr} (DHCP)") } else { addr })
                        })
                        .collect()
                })
                .unwrap_or_default();
            rows.text(
                ui,
                "Addresses",
                "iface_wifi.addresses",
                Some(if addresses.is_empty() { "none".to_owned() } else { addresses.join(", ") }),
            );
            let country = match (text(m, "country"), text(m, "country_in_force")) {
                (Some(c), Some(f)) if c == f => Some(format!("{c} (in force)")),
                (Some(c), Some(f)) => Some(format!("{c} (in force: {f})")),
                (c, f) => c.or(f),
            };
            rows.text(ui, "Country", "iface_wifi.country", joined([country, text(m, "country_error")]));
            let failure = m
                .get("failure")
                .filter(|f| !f.is_null())
                .and_then(|f| text(f, "text"))
                .or_else(|| text(m, "error"));
            rows.text(
                ui,
                "Last Failure",
                "iface_wifi.failure",
                Some(failure.unwrap_or_else(|| "none".to_owned())),
            );
        });
    if !connected {
        ui.add_space(4.0);
        ui.weak("Signal, channel and rates show while the radio is connected.");
    }
    missing_line(ui, &missing);
    notes(ui, m);
}

/// The Radio tab: what the card is and can do.
pub(crate) fn radio(ui: &mut Ui, r: &Option<Result<Value, String>>, help: Help<'_>) {
    let Some(v) = loaded(ui, r) else {
        return;
    };
    let mut missing = Vec::new();
    let mut rows = Rows {
        help,
        missing: &mut missing,
    };
    let bands: Vec<&Value> = v
        .get("bands")
        .and_then(Value::as_array)
        .map(|b| b.iter().collect())
        .unwrap_or_default();
    Grid::new("iface-wifi-radio")
        .num_columns(2)
        .min_col_width(LABEL_WIDTH)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            rows.text(ui, "Driver", "iface_wifi.driver", text(v, "driver"));
            rows.text(ui, "Firmware", "iface_wifi.firmware", text(v, "firmware"));
            rows.text(ui, "Phy", "iface_wifi.phy", text(v, "phy"));
            let standards: Vec<String> = v
                .get("standards")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(value_text).collect())
                .unwrap_or_default();
            rows.text(
                ui,
                "Standards",
                "iface_wifi.standards",
                (!standards.is_empty()).then(|| format!("802.11{}", standards.join("/"))),
            );
            let lines: Vec<String> = bands
                .iter()
                .map(|b| {
                    let st: Vec<String> = b
                        .get("standards")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().map(value_text).collect())
                        .unwrap_or_default();
                    let dfs = uint(b, "dfs").filter(|d| *d > 0).map(|d| format!("{d} need DFS"));
                    joined([
                        Some(band_name(&text(b, "band").unwrap_or_default()).to_owned()),
                        (!st.is_empty()).then(|| st.join("/")),
                        text(b, "max_width").map(|w| format!("up to {w} MHz")),
                        uint(b, "allowed").map(|a| format!("{a} channels")),
                        dfs,
                        int(b, "max_power").map(|p| format!("up to {p} dBm")),
                    ])
                    .unwrap_or_default()
                })
                .collect();
            rows.text(ui, "Bands", "iface_wifi.bands", (!lines.is_empty()).then(|| lines.join("\n")));
            let antennas = match (uint(v, "antennas_tx"), uint(v, "antennas_rx")) {
                (Some(t), Some(r)) => Some(format!("{t}×{r} (TX {t}, RX {r})")),
                (t, r) => t.or(r).map(|n| n.to_string()),
            };
            rows.text(ui, "Antennas", "iface_wifi.antennas", antennas);
            rows.text(
                ui,
                "TX Power",
                "iface_wifi.tx_power",
                joined([
                    int(v, "tx_power").map(|p| format!("{p} dBm")),
                    int(v, "max_tx_power").map(|p| format!("up to {p} dBm on this channel")),
                ]),
            );
            let country = match (text(v, "country"), text(v, "country_in_force")) {
                (Some(c), Some(f)) if c == f => Some(format!("{c} (in force)")),
                (Some(c), Some(f)) => Some(format!("{c} (in force: {f})")),
                (c, f) => c.or(f),
            };
            let own = (v.get("self_managed").and_then(Value::as_bool) == Some(true))
                .then(|| "the card keeps its own domain".to_owned());
            rows.text(ui, "Country", "iface_wifi.country", joined([country, own]));
            match text(v, "blocked") {
                Some(b) => rows.chip(
                    ui,
                    "Radio Switch",
                    "iface_wifi.switch",
                    Some(("blocked", &crate::chip::RED)),
                    Some(if b == "hard" { "by a hardware switch or key" } else { "in software (rfkill)" }.to_owned()),
                ),
                None => rows.chip(ui, "Radio Switch", "iface_wifi.switch", Some(("free", &crate::chip::GREEN)), None),
            }
        });
    missing_line(ui, &missing);
    for b in &bands {
        let channels: Vec<&Value> = b
            .get("channels")
            .and_then(Value::as_array)
            .map(|c| c.iter().collect())
            .unwrap_or_default();
        if channels.is_empty() {
            continue;
        }
        let name = band_name(&text(b, "band").unwrap_or_default()).to_owned();
        CollapsingHeader::new(format!("Channels, {name}"))
            .id_salt(("iface-wifi-channels", name.clone()))
            .default_open(false)
            .show(ui, |ui| {
                Grid::new(("iface-wifi-channel-list", name.clone()))
                    .num_columns(4)
                    .spacing([12.0, 2.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for h in ["Channel", "MHz", "Max Power", "Notes"] {
                            ui.label(RichText::new(h).strong());
                        }
                        ui.end_row();
                        for c in channels {
                            let off = c.get("disabled").and_then(Value::as_bool) == Some(true);
                            let radar = c.get("radar").and_then(Value::as_bool) == Some(true);
                            let cell = |ui: &mut Ui, s: String| {
                                if off {
                                    ui.weak(s);
                                } else {
                                    ui.label(s);
                                }
                            };
                            cell(ui, text(c, "channel").unwrap_or_else(|| "-".into()));
                            cell(ui, text(c, "mhz").unwrap_or_default());
                            cell(ui, int(c, "max_power").map(|p| format!("{p} dBm")).unwrap_or_default());
                            let note = match (off, radar) {
                                (true, _) => "not allowed here",
                                (false, true) => "DFS (radar check first)",
                                _ => "",
                            };
                            cell(ui, note.to_owned());
                            ui.end_row();
                        }
                    });
            });
    }
    notes(ui, v);
}

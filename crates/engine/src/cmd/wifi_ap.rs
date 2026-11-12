//! /interface wifi as an access point (G1.30a): the registration table (the
//! stations associated with each access point, RouterOS v7's
//! `/interface/wifi/registration-table`), and what `interface.wifi.set`,
//! `.list` and `.monitor` add for `mode=ap` (the channel the radio will
//! use, or why it cannot; the state and the clients). The access point
//! itself runs in `crate::wifi_ap`.
//!
//! What is refused, so that the mistake is not made:
//! - a channel or width the radio may not start a network on in the
//!   country in force (not allowed, passive/no-IR, a block that crosses
//!   one, wider than the radio): `crate::wifi_ap::plan`, with the reason;
//! - a `bssid` on an access point (it is the station's choice of access
//!   point);
//! - turning a bridge port back into a station (a station cannot be one);
//! - changing the mode of the radio this connection comes through, outside
//!   Safe Mode (`interface.wifi.set`'s guard).

use corerouter_hal::wifi_ap::ApState;
use corerouter_model::wifi::{WifiConfig, WifiMode, WifiSecurity};
use corerouter_model::{IfName, Interface, InterfaceKind};
use serde_json::{Value, json};

use super::CommandSpec;
use super::args::opt_parse;
use super::wifi::{has_radios, rate_json, retry_percent, standard_of};
use crate::wifi::channel;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.wifi.registration-table.print", "Wi-Fi Registration Table", [], None,
        "{interface?: string (one access point; default all)} → [{interface, mac_address, authorized, security (wpa3 | wpa2 | open), generation, standard, signal, tx_rate: {mbps, mode, mcs, nss, width, guard_ns, text}, rx_rate: {…}, uptime_secs, inactive_ms, tx_packets, rx_packets, tx_retries, tx_failed, retry_percent}]",
        has_radios, registration_table),
];

/// `frequency` as `interface.wifi.set` takes it: MHz, a channel number, or
/// `auto` (`None` in the result's `Some`: automatic).
pub(super) fn parse_frequency(p: &Value) -> Result<Option<Option<u32>>> {
    let v = match p.get("frequency") {
        None | Some(Value::Null) => return Ok(None),
        Some(v) => v,
    };
    let text = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.trim().to_ascii_lowercase(),
        _ => return Err(EngineError::bad("frequency", "MHz (5180), a channel (36) or auto")),
    };
    if text.is_empty() || text == "auto" || text == "0" {
        return Ok(Some(None));
    }
    let n: u32 = text.trim_end_matches("mhz").parse().map_err(|_| {
        EngineError::bad(
            "frequency",
            format!(
                "'{}' is not a frequency: MHz (5180), a channel (36) or auto",
                text.chars().take(16).collect::<String>()
            ),
        )
    })?;
    // A channel number: 1..14 is 2.4 GHz, 32..177 is 5 GHz.
    let mhz = match n {
        14 => 2484,
        1..=13 => 2407 + 5 * n,
        32..=177 => 5000 + 5 * n,
        _ => n,
    };
    if !(2400..=7200).contains(&mhz) {
        return Err(EngineError::bad(
            "frequency",
            format!("{n} is neither a Wi-Fi channel nor a frequency in MHz"),
        ));
    }
    Ok(Some(Some(mhz)))
}

/// `width` as `interface.wifi.set` takes it: 20, 40, 80, 160 (or with
/// `mhz`, or RouterOS' `20/40/80mhz`: the widest), or `auto`.
pub(super) fn parse_width(p: &Value) -> Result<Option<Option<u32>>> {
    let text = match p.get("width") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.trim().to_ascii_lowercase(),
        Some(_) => return Err(EngineError::bad("width", "20, 40, 80, 160 or auto")),
    };
    if text.is_empty() || text == "auto" {
        return Ok(Some(None));
    }
    let widest = text
        .trim_end_matches("mhz")
        .rsplit('/')
        .next()
        .and_then(|w| w.parse::<u32>().ok())
        .ok_or_else(|| {
            EngineError::bad(
                "width",
                format!(
                    "'{}' is not a width: 20, 40, 80, 160 or auto",
                    text.chars().take(16).collect::<String>()
                ),
            )
        })?;
    Ok(Some(Some(widest)))
}

/// The checks of `interface.wifi.set` for the settings `st` will have:
/// errors for what the radio cannot do, warnings for what the operator
/// should know. `old` is the mode before.
pub(super) fn check(
    s: &mut Session,
    name: &IfName,
    iface: &Interface,
    st: &WifiConfig,
    old: WifiMode,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if st.mode == WifiMode::Station {
        if let Some(b) = iface.bridge.as_ref().filter(|_| old == WifiMode::Ap) {
            return Err(EngineError::bad(
                "mode",
                format!(
                    "'{name}' is a port of bridge '{b}', and a station cannot be one: take it out \
                     first (interface.bridge.port.remove)"
                ),
            ));
        }
        return Ok(warnings);
    }
    if st.bssid.is_some() {
        return Err(EngineError::bad(
            "bssid",
            "bssid picks the access point a station joins; an access point has its own (the \
             radio's MAC): set bssid empty",
        ));
    }
    if st.ssid.is_empty() {
        warnings.push(format!(
            "'{name}' is an access point with no ssid: it announces nothing until it has one"
        ));
        return Ok(warnings);
    }
    let plan = s.wifi_ap_plan(name, st).map_err(|e| {
        let param = if st.width.is_some() && !e.contains("channel ") {
            "width"
        } else {
            "frequency"
        };
        EngineError::bad(param, e)
    })?;
    if plan.radar {
        warnings.push(format!(
            "channel {} needs radar detection (DFS): the access point listens for a minute (ten \
             on the weather radar channels) before the first beacon, and moves if it hears one",
            channel(plan.frequency_mhz).unwrap_or(0)
        ));
    }
    if st.security == WifiSecurity::Open {
        warnings.push(format!(
            "'{}' is an open network: anybody in range joins it and reads its traffic",
            st.ssid
        ));
    }
    if st.security == WifiSecurity::Wpa3 {
        warnings.push(
            "security=wpa3 leaves out clients that only speak WPA2 (older phones, printers); \
             auto offers both"
                .into(),
        );
    }
    if st.hidden {
        warnings.push(
            "a hidden network is not safer: clients announce its name when they look for it"
                .into(),
        );
    }
    Ok(warnings)
}

/// `interface.wifi.list`'s and `.monitor`'s state of an access point.
pub(super) fn ap_state(s: &Session, name: &IfName) -> &'static str {
    match s.wifi().and_then(|rt| rt.aps.get(name)) {
        Some(r) if r.status.state == ApState::Running => "running",
        Some(r) if r.error.is_some() => "error",
        Some(r) if r.status.state == ApState::Stopped && r.plan.is_some() => "starting",
        Some(r) => r.status.state.as_str(),
        None => "idle",
    }
}

/// What `interface.wifi.list` adds for an access point.
pub(super) fn list_fields(s: &Session, name: &IfName) -> Value {
    let r = s.wifi().and_then(|rt| rt.aps.get(name));
    let freq = r.and_then(|r| r.status.frequency_mhz.or(r.plan.as_ref().map(|p| p.frequency_mhz)));
    json!({
        "frequency": freq,
        "channel": freq.and_then(channel),
        "width": r.and_then(|r| r.plan.as_ref()).map(|p| p.width_mhz),
        "clients": r.map_or(0, |r| r.status.clients.len()),
    })
}

/// `interface.wifi.monitor` of an access point.
pub(super) fn monitor(s: &Session, name: &IfName, st: &WifiConfig) -> Value {
    let rt = s.wifi();
    let now = rt.map_or(0, |rt| rt.now_ms);
    let r = rt.and_then(|rt| rt.aps.get(name));
    let plan = r.and_then(|r| r.plan.as_ref());
    let freq = r.and_then(|r| r.status.frequency_mhz).or(plan.map(|p| p.frequency_mhz));
    json!({
        "mode": "ap",
        "ssid": (!st.ssid.is_empty()).then(|| st.ssid.clone()),
        "security": st.security.as_str(),
        "frequency": freq,
        "band": super::wifi::band_of(freq),
        "channel": freq.and_then(channel),
        "width": plan.map(|p| p.width_mhz),
        "center_frequency": plan.map(|p| p.center_mhz),
        "auto_channel": plan.map(|p| p.auto),
        "radar": plan.map(|p| p.radar),
        "radar_check_secs": r.and_then(|r| r.status.radar_check_secs),
        "standard": plan
            .and_then(|p| standard_of(if p.he { 6 } else if p.vht { 5 } else if p.ht { 4 } else { 0 })),
        "uptime_secs": r.and_then(|r| r.up_since_ms).map(|t| now.saturating_sub(t) / 1000),
        "clients": r.map_or(0, |r| r.status.clients.len()),
        "error": r.and_then(|r| r.error.clone()),
    })
}

/// The lines of `interface.wifi.preview` for an access point: the network,
/// its security, and the channel it would run on (or why not).
pub(super) fn computed(s: &Session, name: &IfName, iface: &Interface, st: &WifiConfig) -> Vec<Value> {
    let line = |label: &str, value: String| json!({"label": label, "value": value});
    if st.ssid.is_empty() {
        return vec![line("Network", "none: the access point announces nothing".into())];
    }
    let hw = s
        .wifi()
        .and_then(|rt| rt.radios.get(name))
        .and_then(|r| r.hardware.clone());
    let planned = crate::wifi_ap::plan(st, hw.as_ref(), &|band, allowed| {
        crate::wifi_ap::suggestion(s, name, band, allowed)
    });
    let ch = match planned {
        Ok(p) => format!(
            "{} ({} MHz), {} MHz wide{}{}",
            channel(p.frequency_mhz).unwrap_or(0),
            p.frequency_mhz,
            p.width_mhz,
            if p.auto { ", chosen automatically" } else { "" },
            if p.radar { ", radar check first" } else { "" }
        ),
        Err(e) => format!("cannot start: {e}"),
    };
    vec![
        line("Mode", "access point".into()),
        line("Network", st.ssid.clone()),
        line(
            "Security",
            match st.security {
                WifiSecurity::Auto => "WPA2 and WPA3 together (each client uses the best it has)",
                WifiSecurity::Wpa3 => "WPA3 only",
                WifiSecurity::Wpa2 => "WPA2 only",
                WifiSecurity::Open => "none (open network)",
            }
            .to_owned(),
        ),
        line("Channel", ch),
        line(
            "Bridge",
            iface
                .bridge
                .as_ref()
                .map_or_else(|| "none: route to the clients".to_owned(), ToString::to_string),
        ),
        line("Radio", if iface.disabled { "off" } else { "on" }.to_owned()),
    ]
}

fn registration_table(s: &mut Session, p: &Value) -> Result<Value> {
    let only: Option<IfName> = opt_parse(p, "interface")?;
    if let Some(n) = &only {
        let (_, st) = super::wifi::radio_of(s.store().candidate(), n)?;
        if st.mode != WifiMode::Ap {
            return Err(EngineError::bad(
                "interface",
                format!("'{n}' is a station, not an access point: it has no clients"),
            ));
        }
    }
    let Some(rt) = s.wifi() else {
        return Ok(json!([]));
    };
    let ap_names: Vec<IfName> = s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter(|i| matches!(&i.kind, InterfaceKind::Wifi(w) if w.mode == WifiMode::Ap))
        .map(|i| i.name.clone())
        .collect();
    let mut out = Vec::new();
    for (name, r) in &rt.aps {
        if only.as_ref().is_some_and(|o| o != name) || !ap_names.contains(name) {
            continue;
        }
        for c in &r.status.clients {
            let l = &c.link;
            out.push(json!({
                "interface": name,
                "mac_address": c.mac,
                "authorized": c.authorized,
                "security": c.security,
                "generation": c.generation,
                "standard": c.generation.and_then(standard_of),
                "signal": l.signal_avg_dbm,
                "tx_rate": l.tx.as_ref().map(rate_json),
                "rx_rate": l.rx.as_ref().map(rate_json),
                "uptime_secs": l.connected_secs,
                "inactive_ms": l.inactive_ms,
                "tx_packets": l.tx_packets,
                "rx_packets": l.rx_packets,
                "tx_retries": l.tx_retries,
                "tx_failed": l.tx_failed,
                "retry_percent": retry_percent(l.tx_retries, l.tx_packets),
            }));
        }
    }
    Ok(Value::Array(out))
}

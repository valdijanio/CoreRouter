//! /interface wifi frequency-scan and spectral-scan (G1.30i): what the air
//! around a radio looks like, for the three views of the Networks tab of
//! Interfaces › Wi-Fi (the list with the channels' overlap and contention,
//! the channel graph, the spectrum). Names are RouterOS v7's
//! (`/interface/wifi/frequency-scan`, `/interface/wifi/spectral-scan`);
//! the analysis is `crate::wifi_air`, the spectrum's data
//! `crate::wifi_spectrum`. The scan itself is `interface.wifi.scan`.
//!
//! Neither touches the configuration. A spectral scan of a band makes the
//! radio scan every few seconds, which takes it off its channel for a
//! moment each time: said in the reply (the Channel Analysis of OpenWrt's
//! LuCI was reported dropping clients the same way).

use corerouter_hal::wifi::{MAX_SPECTRAL_SECS, WifiState};
use corerouter_model::IfName;
use serde_json::{Value, json};

use super::CommandSpec;
use super::args::{opt_bool, opt_str, opt_u32, req_parse};
use super::wifi::{band_of, has_radios, joinable, not_running, radio_of};
use crate::wifi::channel;
use crate::wifi_air::{self, Relation};
use crate::wifi_spectrum::{MAX_ROWS, Range};
use crate::{EngineError, Result, Session};

/// The default length of a spectral scan, s.
const DEFAULT_SECS: u32 = 60;
/// Contenders named per network at most.
const MAX_NAMED: usize = 16;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.wifi.frequency-scan", "Wi-Fi Frequency Scan", [], None,
        "{name: string, scan?: bool (start a scan first; the channels fill in a few seconds later)} → {name, scanning, age_secs, error, survey (full | partial | none: whether the driver counted every channel, only the one in use, or none), channels: [{band, channel, frequency, networks (primary here), secondary (wider networks covering it), max_signal, min_signal, load (% busy; null: not counted), noise, in_use}]}",
        has_radios, frequency_scan),
    cmd!(query "interface.wifi.spectral-scan", "Wi-Fi Spectral Scan", [], None,
        "{name: string, duration?: int (s, 1..=600, default 60), range?: string (current | 2ghz | 5ghz; default current: the channel in use), stop?: bool} → {name, running, range, duration, warnings}",
        has_radios, spectral_scan),
    cmd!(query "interface.wifi.spectral-data", "Wi-Fi Spectral Data", [], None,
        "{name: string, since?: int (rows after this sequence number; 0: all kept), limit?: int (newest rows at most, default 240; 0: only supported, why_not, running, seconds_left, range, last_seq)} → {name, supported, why_not, running, seconds_left, range, start, step, points, noise, samples, last_seq, rows: [{seq, values: [int dBm; -128: no sample]}], realtime: [int], average: [int], peak: [int], channels: [{channel, frequency, usage (%)}], interference: [{kind (wifi | cw | mwo | bluetooth | fhss | unknown), frequency, width, peak, duty (%)}], error}",
        has_radios, spectral_data),
];

fn radio_name(s: &Session, p: &Value) -> Result<IfName> {
    let name: IfName = req_parse(p, "name")?;
    radio_of(s.store().candidate(), &name)?;
    Ok(name)
}

/// `interface.wifi.networks`: the last scan, each network with its
/// channel, its load and the air it shares, and the channel each band has
/// the least on.
pub(super) fn networks(s: &mut Session, p: &Value) -> Result<Value> {
    let name = radio_name(s, p)?;
    let unix = s.now();
    let Some(r) = s.wifi().and_then(|rt| rt.radios.get(&name)) else {
        return Ok(json!({
            "name": name, "scanning": false, "age_secs": null, "error": null, "networks": [],
            "suggested": [],
        }));
    };
    let on = r.status.bssid.as_deref().filter(|_| r.status.state == WifiState::Connected);
    let air = wifi_air::analyse(&r.scan);
    let rows: Vec<Value> = r
        .scan
        .iter()
        .zip(&air)
        .map(|(b, a)| {
            let why = joinable(b.security);
            let span = wifi_air::spans(b);
            let contention = a
                .contenders
                .iter()
                .filter_map(|&j| r.scan.get(j))
                .filter_map(|o| wifi_air::relation(b, o))
                .min_by_key(|rel| match rel {
                    Relation::SameChannel => 0,
                    Relation::Covered => 1,
                    Relation::Overlap => 2,
                })
                .map(|rel| match rel {
                    Relation::SameChannel => "same-channel",
                    Relation::Covered => "covered",
                    Relation::Overlap => "overlap",
                });
            let contenders: Vec<&str> = a
                .contenders
                .iter()
                .filter_map(|&j| r.scan.get(j))
                .map(|o| o.bssid.as_str())
                .take(MAX_NAMED)
                .collect();
            json!({
                "ssid": b.ssid,
                "bssid": b.bssid,
                "signal": b.signal_dbm,
                "frequency": b.frequency_mhz,
                "band": band_of(Some(b.frequency_mhz)),
                "channel": channel(b.frequency_mhz),
                "security": b.security.as_str(),
                "joinable": why.is_none(),
                "why_not": why,
                "connected": on.is_some_and(|x| x.eq_ignore_ascii_case(&b.bssid)),
                "width": b.width_mhz,
                "center_frequency": b.center_mhz,
                "center_frequency2": b.center2_mhz,
                "low": span.first().map(|s| s.0),
                "high": span.last().map(|s| s.1),
                "generation": b.generation,
                "stations": b.stations,
                "utilization": b.utilization.map(|u| (f64::from(u) * 1000.0 / 255.0).round() / 10.0),
                "same_channel": a.same_channel,
                "overlaps": a.overlaps,
                "contenders": contenders,
                "contention": contention,
            })
        })
        .collect();
    // The bands this radio has (or, unknown, those it heard).
    let allowed: Vec<(u32, bool)> = r
        .hardware
        .iter()
        .flat_map(|h| &h.bands)
        .flat_map(|b| &b.channels)
        .filter(|c| !c.disabled)
        .map(|c| (c.mhz, c.radar))
        .collect();
    let mut bands: Vec<&'static str> = allowed.iter().filter_map(|(f, _)| wifi_air::band(*f)).collect();
    if bands.is_empty() {
        bands = r.scan.iter().filter_map(|b| wifi_air::band(b.frequency_mhz)).collect();
    }
    bands.sort_unstable();
    bands.dedup();
    let suggested: Vec<Value> = bands
        .into_iter()
        .filter_map(|band| wifi_air::suggest(band, &r.scan, &r.survey, &allowed))
        .map(|g| {
            json!({
                "band": g.band, "channel": g.channel, "frequency": g.frequency_mhz,
                "networks": g.networks, "score": (g.score * 1000.0).round() / 10.0, "dfs": g.dfs,
            })
        })
        .collect();
    Ok(json!({
        "name": name,
        "scanning": r.scan_started_ms.is_some(),
        "age_secs": r.scanned_at.zip(unix).map(|(at, now)| now.saturating_sub(at)),
        "error": r.scan_error,
        "networks": rows,
        "suggested": suggested,
    }))
}

fn frequency_scan(s: &mut Session, p: &Value) -> Result<Value> {
    let name = radio_name(s, p)?;
    if opt_bool(p, "scan")?.unwrap_or(false) {
        not_running(s.store().running(), &name)?;
        let now = s.wifi().map_or(0, |rt| rt.now_ms);
        s.wifi_service(now);
        s.wifi_scan(&name).map_err(|e| EngineError::bad("name", e))?;
    }
    let unix = s.now();
    let Some(r) = s.wifi().and_then(|rt| rt.radios.get(&name)) else {
        return Ok(json!({
            "name": name, "scanning": false, "age_secs": null, "error": null, "survey": "none",
            "channels": [],
        }));
    };
    let counted = r.survey.iter().filter(|c| c.busy_ms.is_some()).count();
    let survey = match counted {
        0 => "none",
        n if n * 2 >= r.survey.len() => "full",
        _ => "partial",
    };
    let channels: Vec<Value> = wifi_air::channels(&r.scan, &r.survey)
        .into_iter()
        .map(|c| {
            json!({
                "band": c.band, "channel": c.channel, "frequency": c.frequency_mhz,
                "networks": c.primary, "secondary": c.secondary,
                "max_signal": c.max_signal, "min_signal": c.min_signal,
                "load": c.load, "noise": c.noise, "in_use": c.in_use,
            })
        })
        .collect();
    Ok(json!({
        "name": name,
        "scanning": r.scan_started_ms.is_some(),
        "age_secs": r.scanned_at.zip(unix).map(|(at, now)| now.saturating_sub(at)),
        "error": r.scan_error,
        "survey": survey,
        "channels": channels,
    }))
}

/// Can radio `name` scan the spectrum, and why not.
fn support(s: &Session, name: &IfName) -> std::result::Result<(), String> {
    let hw = s.wifi().and_then(|rt| rt.radios.get(name)).and_then(|r| r.hardware.as_ref());
    match hw {
        Some(h) if h.spectral_scan => Ok(()),
        Some(h) => Err(h
            .spectral_why_not
            .clone()
            .unwrap_or_else(|| "this radio has no spectral scan".to_owned())),
        None => Err(format!("the radio of '{name}' is not open yet: enable it, then try again")),
    }
}

fn spectral_scan(s: &mut Session, p: &Value) -> Result<Value> {
    let name = radio_name(s, p)?;
    if opt_bool(p, "stop")?.unwrap_or(false) {
        s.wifi_spectral_stop(&name);
        return Ok(json!({ "name": name, "running": false, "range": null, "duration": null, "warnings": [] }));
    }
    let secs = match opt_u32(p, "duration")? {
        None => DEFAULT_SECS,
        Some(d) if (1..=MAX_SPECTRAL_SECS).contains(&d) => d,
        Some(d) => {
            return Err(EngineError::bad(
                "duration",
                format!("{d} is out of range: 1..={MAX_SPECTRAL_SECS} seconds"),
            ));
        }
    };
    let text = opt_str(p, "range")?.unwrap_or("").trim();
    let range = Range::parse(text).ok_or_else(|| {
        EngineError::bad(
            "range",
            format!(
                "'{}' is not a range: use current, 2ghz or 5ghz",
                text.chars().take(16).collect::<String>()
            ),
        )
    })?;
    not_running(s.store().running(), &name)?;
    let now = s.wifi().map_or(0, |rt| rt.now_ms);
    s.wifi_service(now);
    support(s, &name).map_err(|why| EngineError::bad("name", why))?;
    if range == Range::Current {
        let connected = s
            .wifi()
            .and_then(|rt| rt.radios.get(&name))
            .is_some_and(|r| r.status.state == WifiState::Connected);
        if !connected {
            return Err(EngineError::bad(
                "range",
                format!("'{name}' is on no channel: connect it to a network, or scan a band (range=2ghz or 5ghz)"),
            ));
        }
    }
    s.wifi_spectral_start(&name, range, secs)
        .map_err(|e| EngineError::bad("name", e))?;
    let mut warnings = Vec::new();
    if range != Range::Current {
        warnings.push(
            "a band is swept by scanning every 4 s: each scan takes the radio off its channel for \
             a moment, and the link stalls while it does"
                .to_owned(),
        );
    }
    Ok(json!({
        "name": name, "running": true, "range": range.as_str(), "duration": secs,
        "warnings": warnings,
    }))
}

/// MHz to a tenth, as an `f64` (an `f32` prints `5232.10009765625`).
fn tenth(mhz: f32) -> f64 {
    (f64::from(mhz) * 10.0).round() / 10.0
}

fn spectral_data(s: &mut Session, p: &Value) -> Result<Value> {
    let name = radio_name(s, p)?;
    let since = opt_u32(p, "since")?.map_or(0, u64::from);
    let limit = opt_u32(p, "limit")?.map_or(MAX_ROWS, |l| (l as usize).min(MAX_ROWS));
    let supported = support(s, &name);
    let now = s.wifi().map_or(0, |rt| rt.now_ms);
    let r = s.wifi().and_then(|rt| rt.radios.get(&name));
    let Some(sp) = r.and_then(|r| r.spectrum.as_ref()) else {
        return Ok(json!({
            "name": name, "supported": supported.is_ok(), "why_not": supported.err(),
            "running": false, "rows": [], "last_seq": 0,
        }));
    };
    if limit == 0 {
        return Ok(json!({
            "name": name, "supported": supported.is_ok(), "why_not": supported.err(),
            "running": sp.running(),
            "seconds_left": sp.until_ms.map(|u| u.saturating_sub(now).div_ceil(1000)),
            "range": sp.range.as_str(), "last_seq": sp.last_seq(), "rows": [],
        }));
    }
    let scan = r.map(|r| r.scan.as_slice()).unwrap_or(&[]);
    let mut rows: Vec<Value> = sp
        .rows_since(since)
        .map(|(seq, v)| json!({ "seq": seq, "values": v }))
        .collect();
    let extra = rows.len().saturating_sub(limit);
    rows.drain(..extra);
    let round = |v: &[f32]| -> Vec<Value> {
        v.iter()
            .map(|a| if a.is_nan() { json!(null) } else { json!(a.round() as i32) })
            .collect()
    };
    let interference: Vec<Value> = sp
        .classify(scan)
        .into_iter()
        .map(|i| {
            json!({
                "kind": i.kind, "frequency": tenth(i.frequency_mhz), "width": tenth(i.width_mhz),
                "peak": i.peak_dbm, "duty": i.duty,
            })
        })
        .collect();
    let channels: Vec<Value> = sp
        .channel_usage()
        .into_iter()
        .map(|(ch, f, usage)| json!({ "channel": ch, "frequency": f, "usage": usage }))
        .collect();
    Ok(json!({
        "name": name,
        "supported": supported.is_ok(),
        "why_not": supported.err(),
        "running": sp.running(),
        "seconds_left": sp.until_ms.map(|u| u.saturating_sub(now).div_ceil(1000)),
        "range": sp.range.as_str(),
        "start": (f64::from(sp.start_mhz) * 1000.0).round() / 1000.0,
        "step": (f64::from(sp.step_mhz) * 1000.0).round() / 1000.0,
        "points": sp.points,
        "noise": sp.noise(),
        "samples": sp.samples,
        "last_seq": sp.last_seq(),
        "rows": rows,
        "realtime": sp.realtime(),
        "average": round(&sp.average),
        "peak": sp.peak,
        "channels": channels,
        "interference": interference,
        "error": sp.error,
    }))
}

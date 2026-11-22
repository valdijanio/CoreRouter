//! /interface wifi sniffer and snooper (G1.30j): a radio in monitor mode.
//! The snooper shows who uses the air, per network and per station
//! (airtime, retries, rate, signal, and notes: far and slow, thrown out,
//! hidden name given away, a twin of a network); the sniffer also records
//! the frames into a pcap file (radiotap, link type 127) for Wireshark.
//! Both are tasks, like `tool.sniffer` (`tool.task.poll`, `tool.task.stop`);
//! the job is `crate::tools::wifi_snoop`. Names follow RouterOS v7's
//! `/interface/wifi/sniffer` and the legacy `/interface/wireless/snooper`.
//!
//! The sniffer never takes a radio off its network, so it never cuts the
//! management that comes through it:
//! - on an enabled radio it is `shared`: a monitor interface beside the
//!   station, which stays connected, on the station's channel (the kernel
//!   does not move a monitor while the station is up);
//! - choosing a channel or hopping needs the radio to itself (`exclusive`):
//!   the interface disabled first (`interface.wifi.disable`, which asks for
//!   Safe Mode on the radio this connection comes through). If the radio
//!   is enabled again meanwhile (Safe Mode undoing the disable, or by
//!   hand), the sniffer stops at once ([`watch`]) and the station gets the
//!   radio back.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use corerouter_hal::ieee80211::{self, Mac, parse_mac};
use corerouter_hal::wifi_monitor::{MonitorMode, MonitorSpec};
use corerouter_model::{IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str, req_u32};
use super::CommandSpec;
use crate::tools::wifi_snoop::{self, Capture, Shared, SnoopJob, WifiFilter};
use crate::{EngineError, Result, Session};

/// Sniffers kept at once with their tables and files (each file up to its
/// limit).
pub const MAX_KEPT: usize = 2;
/// Largest capture file (KiB).
pub const MAX_FILE_KIB: u32 = 65_536;
pub const DEFAULT_FILE_KIB: u32 = 16_384;
/// Largest piece one download returns.
pub const MAX_CHUNK: u32 = 4 << 20;
/// Channels one hop list holds at most.
pub const MAX_HOP: usize = 64;
const SNOOPER: &str = "wifi-snooper";
const SNIFFER: &str = "wifi-sniffer";


pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.wifi.snooper.start", "Wi-Fi Snooper", ["Interfaces", "Wi-Fi Sniffer"], None,
        "{interface: string (a Wi-Fi radio), mode?: string (auto | shared | exclusive; auto: shared beside the station of an enabled radio, which stays connected on its channel; exclusive on a disabled radio, any channel), channel?: int (MHz, or the channel number on 2.4/5 GHz; exclusive only; default: the radio's first), hop?: bool (go round the channels; exclusive only), channels?: string|[int] (the channels to go round, MHz or numbers; default: every channel the radio allows), channel_time?: int 50..10000 (ms on each channel, default 200), width?: int (20 | 40 | 80 | 160: MHz around each channel; exclusive only; default 20: a wider network's data frames are heard only with its width), duration?: int 1..86400 (s, default 300)} → {id, task_id, radio, mode, monitor, channel, hop: [int]}",
        can_monitor, snooper_start)
    .task(),
    cmd!(query "interface.wifi.sniffer.start", "Wi-Fi Sniffer", ["Interfaces", "Wi-Fi Sniffer"], None,
        "{interface: string (a Wi-Fi radio), mode?: string (auto | shared | exclusive; auto: shared beside the station of an enabled radio, which stays connected on its channel; exclusive on a disabled radio, any channel), channel?: int (MHz, or the channel number on 2.4/5 GHz; exclusive only; default: the radio's first), hop?: bool (go round the channels; exclusive only), channels?: string|[int] (the channels to go round, MHz or numbers; default: every channel the radio allows), channel_time?: int 50..10000 (ms on each channel, default 200), width?: int (20 | 40 | 80 | 160: MHz around each channel; exclusive only; default 20: a wider network's data frames are heard only with its width), duration?: int 1..86400 (s, default 300), bssid?: string (only this network's frames), ssid?: string (only the networks of this name), mac_address?: string (frames to or from this address), frame_types?: string|[string] (mgmt, control, data; default all), eapol?: bool (only the EAPOL frames and one beacon per network: what Wireshark needs to decrypt with the passphrase), file_limit?: int 1..65536 (KiB, default 16384)} → {id, task_id, radio, mode, monitor, channel, hop: [int]}",
        can_monitor, sniffer_start)
    .task(),
    cmd!(query "interface.wifi.snooper.print", "Wi-Fi Snooper Table", [], None,
        "{id: int (the snooper's or the sniffer's task)} → {id, radio, mode, monitor, running, channel, hopping, seconds, frames, bad_fcs, overflow, network_count, station_count, channels: [{frequency, channel, band, frames, dwell_ms, airtime_pct, noise, networks, stations}], networks: [{bssid, ssid, hidden, frequency, channel, band, security, signal, airtime_pct, frames, retry_pct, rate, beacons, station_count, notes: [{code, level, text}], stations: [{mac, random_mac, frequency, airtime_pct, frames, retry_pct, rate_mbps, rate, signal, deauth, disassoc, reason, handshake, notes}]}], unassociated: [station]}",
        super::always, snooper_print),
    cmd!(query "interface.wifi.sniffer.packets", "Wi-Fi Sniffer Packets", [], None,
        "{id: int, after_seq?: int (only newer ones), max?: int 1..512 (newest, default 100)} → {id, running, last_seq, packets: [{seq, t_ms, frequency, channel, kind (mgmt | control | data), type, ta, ra, bssid, signal, rate_mbps, retry, protected, length, info}]}",
        super::always, sniffer_packets),
    cmd!(query "interface.wifi.sniffer.download", "Download Wi-Fi Capture", [], None,
        "{id: int, offset?: int, length?: int 1..4194304 (default 4194304)} → {id, file_name, offset, length, total, complete, data}",
        super::always, sniffer_download),
];


/// One sniffer or snooper of this session.
struct Entry {
    radio: IfName,
    kind: &'static str,
    mode: MonitorMode,
    shared: Shared,
    abort: Arc<AtomicBool>,
}

/// The sniffers and snoopers by task id.
#[derive(Default)]
pub(crate) struct WifiSniffers(BTreeMap<u64, Entry>);

/// Why the commands are off here, if they are.
fn can_monitor(s: &Session) -> std::result::Result<(), String> {
    crate::tasks::can_run(s)?;
    let radios = s
        .store()
        .running()
        .interfaces
        .values()
        .any(|i| matches!(i.kind, InterfaceKind::Wifi(_)));
    if !radios {
        return Err("this router has no Wi-Fi radio".into());
    }
    s.hal().wifi_monitor().map(|_| ())
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => {
            Err(EngineError::bad(key, format!("must be {lo}..={hi}")))
        }
        v => Ok(v),
    }
}

fn opt_mac(p: &Value, key: &str) -> Result<Option<Mac>> {
    match opt_str(p, key)?.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => parse_mac(s)
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "must be a MAC address like aa:bb:cc:dd:ee:ff")),
    }
}

/// A channel given as MHz or as a number on 2.4/5 GHz (§E.1).
fn mhz_of(key: &str, v: u32) -> Result<u32> {
    let f = match v {
        14 => 2484,
        1..=13 => 2407 + 5 * v,
        32..=177 => 5000 + 5 * v,
        2400..=7200 => v,
        _ => 0,
    };
    if ieee80211::channel_of(f).is_none() {
        return Err(EngineError::bad(
            key,
            format!("{v} is not a Wi-Fi channel (a number 1..14 or 32..177, or MHz 2412..7115)"),
        ));
    }
    Ok(f)
}

/// The list of `channels` (a JSON array, or "1,6,11").
fn channel_list(p: &Value) -> Result<Option<Vec<u32>>> {
    let raw: Vec<u32> = match p.get("channels") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| {
                x.trim().parse::<u32>().map_err(|_| {
                    let shown: String = x.chars().take(12).collect();
                    EngineError::bad("channels", format!("'{shown}' is not a channel"))
                })
            })
            .collect::<Result<_>>()?,
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| EngineError::bad("channels", "must be a list of channels"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("channels", "must be a list of channels")),
    };
    if raw.len() > MAX_HOP {
        return Err(EngineError::bad("channels", format!("at most {MAX_HOP} channels")));
    }
    let mut out = Vec::with_capacity(raw.len());
    for v in raw {
        let f = mhz_of("channels", v)?;
        if !out.contains(&f) {
            out.push(f);
        }
    }
    Ok(Some(out))
}

fn frame_types(p: &Value, f: &mut WifiFilter) -> Result<()> {
    let raw: Vec<String> = match p.get("frame_types") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|x| x.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("frame_types", "must be a list: mgmt, control, data"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("frame_types", "must be a list: mgmt, control, data")),
    };
    for t in raw.iter().filter(|t| !t.is_empty()) {
        match t.as_str() {
            "mgmt" | "management" => f.mgmt = true,
            "control" | "ctl" => f.control = true,
            "data" => f.data = true,
            other => {
                let shown: String = other.chars().take(16).collect();
                return Err(EngineError::bad(
                    "frame_types",
                    format!("unknown frame type '{shown}' (mgmt, control, data)"),
                ));
            }
        }
    }
    Ok(())
}

/// What a start resolved to.
struct Plan {
    radio: IfName,
    spec: MonitorSpec,
    hop: Vec<u32>,
    channel_time: Duration,
    duration: Duration,
}

/// The radio, the mode and the channels; refuses what would take a radio
/// off its network.
fn plan(s: &mut Session, p: &Value) -> Result<Plan> {
    // Monitor mode changes the radio and hears everyone's frames: only
    // accounts that may change the router.
    s.permit(crate::auth::Group::Write)
        .map_err(|reason| EngineError::Denied {
            id: "interface.wifi.sniffer.start".into(),
            reason,
        })?;
    let radio: IfName = req_str(p, "interface")?
        .trim()
        .parse()
        .map_err(|e| EngineError::bad("interface", format!("{e}")))?;
    let enabled = match s.store().running().interfaces.get(&radio) {
        Some(i) if matches!(i.kind, InterfaceKind::Wifi(_)) => !i.disabled,
        Some(i) => {
            return Err(EngineError::bad(
                "interface",
                format!("'{radio}' is a {}, not a Wi-Fi radio", i.kind.label()),
            ));
        }
        None => {
            return Err(EngineError::bad(
                "interface",
                format!("no Wi-Fi interface '{radio}' (see interface.wifi.list)"),
            ));
        }
    };
    let hw = s.hal_mut().wifi_radio(&radio);
    if hw.as_ref().and_then(|h| h.monitor) == Some(false) {
        return Err(EngineError::bad(
            "interface",
            format!("the driver of '{radio}' has no monitor mode"),
        ));
    }
    let channel = opt_u32(p, "channel")?.map(|v| mhz_of("channel", v)).transpose()?;
    let hop = opt_bool(p, "hop")?.unwrap_or(false);
    let list = channel_list(p)?;
    let width = match opt_u32(p, "width")? {
        None => 20,
        Some(w @ (20 | 40 | 80 | 160)) => w,
        Some(_) => return Err(EngineError::bad("width", "must be 20, 40, 80 or 160")),
    };
    let channel_time = ranged(p, "channel_time", 50, 10_000)?.unwrap_or(200);
    let duration = ranged(p, "duration", 1, 86_400)?.unwrap_or(300);
    let wants_channel = channel.is_some() || hop || list.is_some() || width != 20;
    let mode = match opt_str(p, "mode")?.map(str::trim) {
        None | Some("" | "auto") => {
            if enabled {
                MonitorMode::Shared
            } else {
                MonitorMode::Exclusive
            }
        }
        Some("shared") => MonitorMode::Shared,
        Some("exclusive") => MonitorMode::Exclusive,
        Some(other) => {
            let shown: String = other.chars().take(16).collect();
            return Err(EngineError::bad(
                "mode",
                format!("unknown mode '{shown}' (auto, shared, exclusive)"),
            ));
        }
    };
    // The lockout rule: never take an enabled radio off its network.
    if enabled && (mode == MonitorMode::Exclusive || wants_channel) {
        let through_it = super::ethernet::management_ports(s)
            .is_some_and(|(_, ports)| ports.contains(&radio));
        let how = if through_it {
            format!(
                "this connection comes through '{radio}': enter Safe Mode (config.safe-mode.enter), \
                 then interface.wifi.disable {radio}, so that losing the connection gives it back"
            )
        } else {
            format!("interface.wifi.disable {radio} first")
        };
        return Err(EngineError::bad(
            if mode == MonitorMode::Exclusive { "mode" } else { "channel" },
            format!(
                "'{radio}' is enabled: the sniffer stays beside its station, on the station's \
                 channel, and never takes it off its network. To choose a channel or hop, give it \
                 the radio: {how}"
            ),
        ));
    }
    if hw.as_ref().and_then(|h| h.monitor_shared) == Some(false) && mode == MonitorMode::Shared && enabled {
        return Err(EngineError::bad(
            "interface",
            format!(
                "the driver of '{radio}' cannot run a monitor beside its station: disable the \
                 interface to give the sniffer the radio"
            ),
        ));
    }
    // The channels the radio allows, for the defaults and the checks.
    let allowed: Vec<u32> = hw
        .map(|h| {
            h.bands
                .iter()
                .flat_map(|b| b.channels.iter())
                .filter(|c| !c.disabled)
                .map(|c| c.mhz)
                .collect()
        })
        .unwrap_or_default();
    let check = |key: &str, f: u32| -> Result<()> {
        if !allowed.is_empty() && !allowed.contains(&f) {
            return Err(EngineError::bad(
                key,
                format!("'{radio}' cannot use {f} MHz here (see interface.wifi.radio)"),
            ));
        }
        Ok(())
    };
    let mut hop_list = Vec::new();
    if mode == MonitorMode::Exclusive {
        if let Some(c) = channel {
            check("channel", c)?;
        }
        if hop {
            hop_list = list.unwrap_or_else(|| allowed.iter().copied().take(MAX_HOP).collect());
            for f in &hop_list {
                check("channels", *f)?;
            }
            if hop_list.len() < 2 {
                return Err(EngineError::bad("channels", "hopping needs two channels or more"));
            }
        } else if list.is_some() {
            return Err(EngineError::bad("channels", "a channel list is for hop=yes"));
        }
    }
    let start = channel
        .or_else(|| hop_list.first().copied())
        .or_else(|| (mode == MonitorMode::Exclusive).then(|| allowed.first().copied()).flatten());
    Ok(Plan {
        spec: MonitorSpec {
            radio: radio.to_string(),
            mode,
            freq_mhz: if mode == MonitorMode::Exclusive { start } else { None },
            width_mhz: width,
        },
        radio,
        hop: hop_list,
        channel_time: Duration::from_millis(u64::from(channel_time)),
        duration: Duration::from_secs(u64::from(duration)),
    })
}

/// Room for one more: forget gone and finished ones past [`MAX_KEPT`];
/// refuse a second one on the same radio.
fn make_room(s: &mut Session, radio: &IfName) -> Result<()> {
    let kept: Vec<(u64, IfName, &'static str)> = s
        .ext::<WifiSniffers>()
        .map(|w| w.0.iter().map(|(id, e)| (*id, e.radio.clone(), e.kind)).collect())
        .unwrap_or_default();
    let mut gone = Vec::new();
    let mut finished = Vec::new();
    for (id, r, kind) in &kept {
        if !s.task_kept(*id) {
            gone.push(*id);
        } else if s.task_running(*id, kind).unwrap_or(false) {
            if r == radio {
                return Err(EngineError::bad(
                    "interface",
                    format!("a sniffer runs on '{radio}' already (task {id}); stop it first (tool.task.stop)"),
                ));
            }
        } else {
            finished.push(*id);
        }
    }
    let Some(w) = s.ext_mut::<WifiSniffers>() else {
        return Err(EngineError::Hal("the sniffers' state is unavailable".into()));
    };
    for id in gone {
        w.0.remove(&id);
    }
    for id in finished {
        if w.0.len() < MAX_KEPT {
            break;
        }
        w.0.remove(&id);
    }
    if w.0.len() >= MAX_KEPT {
        return Err(EngineError::Hal(format!(
            "{MAX_KEPT} Wi-Fi sniffers are running already; stop one first (tool.task.stop)"
        )));
    }
    Ok(())
}

fn start(s: &mut Session, p: &Value, capture: Option<Capture>) -> Result<Value> {
    let plan = plan(s, p)?;
    make_room(s, &plan.radio)?;
    let monitor = s.hal().wifi_monitor().map_err(EngineError::Hal)?;
    let kind = if capture.is_some() { SNIFFER } else { SNOOPER };
    let shared: Shared = Arc::default();
    let abort: Arc<AtomicBool> = Arc::default();
    let mode = plan.spec.mode;
    let channel = plan.spec.freq_mhz;
    let hop = plan.hop.clone();
    let job = SnoopJob {
        spec: plan.spec,
        hop: plan.hop,
        channel_time: plan.channel_time,
        duration: plan.duration,
        capture,
        start_unix: s.now(),
        shared: Arc::clone(&shared),
        abort: Arc::clone(&abort),
    };
    let name = plan.radio.clone();
    let title = format!("{} {name}", if kind == SNIFFER { "sniffer" } else { "snooper" });
    let id = s.start_task(kind, title, move |ctx| wifi_snoop::run(job, monitor, ctx))?;
    if let Some(w) = s.ext_mut::<WifiSniffers>() {
        w.0.insert(
            id,
            Entry {
                radio: name.clone(),
                kind,
                mode,
                shared,
                abort,
            },
        );
    }
    let note = if mode == MonitorMode::Exclusive {
        format!("monitor on {name} ({}) until task {id} ends", channel.map(|c| format!("{c} MHz")).unwrap_or_default())
    } else {
        format!("monitor beside the station of {name}, on its channel (task {id})")
    };
    s.wifi_note(&name, "sniffer", note);
    Ok(json!({
        "id": id,
        "task_id": id,
        "radio": name.to_string(),
        "mode": mode.as_str(),
        "monitor": corerouter_hal::wifi_monitor::monitor_name(name.as_str()),
        "channel": channel,
        "hop": hop,
    }))
}

fn snooper_start(s: &mut Session, p: &Value) -> Result<Value> {
    start(s, p, None)
}

fn sniffer_start(s: &mut Session, p: &Value) -> Result<Value> {
    let mut filter = WifiFilter {
        bssid: opt_mac(p, "bssid")?,
        mac: opt_mac(p, "mac_address")?,
        eapol: opt_bool(p, "eapol")?.unwrap_or(false),
        ..WifiFilter::default()
    };
    if let Some(ssid) = opt_str(p, "ssid")?.filter(|x| !x.is_empty()) {
        if ssid.len() > 32 {
            return Err(EngineError::bad("ssid", "at most 32 bytes"));
        }
        filter.ssid = Some(ssid.to_owned());
    }
    frame_types(p, &mut filter)?;
    let kib = ranged(p, "file_limit", 1, MAX_FILE_KIB)?.unwrap_or(DEFAULT_FILE_KIB);
    let limit = usize::try_from(kib).unwrap_or(0).saturating_mul(1024).max(crate::tools::sniffer::MIN_LIMIT);
    start(s, p, Some(Capture { filter, limit }))
}

fn entry(s: &mut Session, id: u64) -> Result<(bool, &Entry)> {
    let kind = s
        .ext::<WifiSniffers>()
        .and_then(|w| w.0.get(&id))
        .map(|e| e.kind)
        .ok_or_else(|| EngineError::bad("id", format!("task {id} is not a Wi-Fi sniffer or snooper")))?;
    // Checks that the caller may drive the task (and counts as a poll).
    let running = s.task_running(id, kind)?;
    let e = s
        .ext::<WifiSniffers>()
        .and_then(|w| w.0.get(&id))
        .ok_or_else(|| EngineError::bad("id", format!("task {id} is gone")))?;
    Ok((running, e))
}

fn snooper_print(s: &mut Session, p: &Value) -> Result<Value> {
    let id = u64::from(req_u32(p, "id")?);
    let (running, e) = entry(s, id)?;
    let st = e.shared.lock().unwrap_or_else(PoisonError::into_inner);
    let mut out = match &st.table {
        Value::Object(_) => st.table.clone(),
        _ => json!({"networks": [], "unassociated": [], "channels": [], "frames": 0}),
    };
    if let Value::Object(o) = &mut out {
        o.insert("id".into(), json!(id));
        o.insert("radio".into(), json!(e.radio.as_str()));
        o.insert("mode".into(), json!(e.mode.as_str()));
        o.insert("monitor".into(), json!(st.monitor));
        o.insert("running".into(), json!(running));
        if !o.contains_key("channel") {
            o.insert("channel".into(), json!(st.channel));
        }
    }
    Ok(out)
}

fn sniffer_packets(s: &mut Session, p: &Value) -> Result<Value> {
    let id = u64::from(req_u32(p, "id")?);
    let after = p.get("after_seq").and_then(Value::as_u64).unwrap_or(0);
    let max = ranged(p, "max", 1, u32::try_from(wifi_snoop::MAX_RECENT).unwrap_or(512))?.unwrap_or(100);
    let (running, e) = entry(s, id)?;
    if e.kind != SNIFFER {
        return Err(EngineError::bad("id", format!("task {id} is a snooper: it keeps no frames")));
    }
    let st = e.shared.lock().unwrap_or_else(PoisonError::into_inner);
    let newer: Vec<Value> = st
        .recent
        .iter()
        .rev()
        .filter(|r| r.seq > after)
        .take(usize::try_from(max).unwrap_or(100))
        .map(wifi_snoop::Recent::json)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok(json!({
        "id": id,
        "running": running,
        "last_seq": st.recent.back().map_or(0, |r| r.seq),
        "packets": newer,
    }))
}

fn sniffer_download(s: &mut Session, p: &Value) -> Result<Value> {
    let id = u64::from(req_u32(p, "id")?);
    let offset = match p.get("offset") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| EngineError::bad("offset", "must be a non-negative integer"))?,
    };
    let length = ranged(p, "length", 1, MAX_CHUNK)?.unwrap_or(MAX_CHUNK);
    let (running, e) = entry(s, id)?;
    if e.kind != SNIFFER {
        return Err(EngineError::bad("id", format!("task {id} is a snooper: it has no capture file")));
    }
    let radio = e.radio.clone();
    let st = e.shared.lock().unwrap_or_else(PoisonError::into_inner);
    let total = st.file.len() as u64;
    if offset > total {
        return Err(EngineError::bad(
            "offset",
            format!("past the end of the file ({total} bytes)"),
        ));
    }
    let from = usize::try_from(offset).unwrap_or(usize::MAX);
    let to = from.saturating_add(usize::try_from(length).unwrap_or(0)).min(st.file.len());
    let chunk = st.file.get(from..to).unwrap_or(&[]);
    Ok(json!({
        "id": id,
        "file_name": format!("wifi-{radio}-{id}.pcap"),
        "offset": offset,
        "length": chunk.len(),
        "total": total,
        "complete": !running,
        "data": base64::engine::general_purpose::STANDARD.encode(chunk),
    }))
}

/// An exclusive monitor whose radio is enabled again stops at once (Safe
/// Mode undid the disable, or the operator enabled it): the station gets
/// the radio back. Called by the Wi-Fi service on every tick.
pub(crate) fn watch(s: &mut Session) {
    let Some(w) = s.ext::<WifiSniffers>() else {
        return;
    };
    let cfg = s.store().running();
    for e in w.0.values() {
        if e.mode != MonitorMode::Exclusive || e.abort.load(Ordering::Relaxed) {
            continue;
        }
        let enabled = cfg.interfaces.get(&e.radio).is_some_and(|i| !i.disabled);
        if enabled {
            e.abort.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::test_runner;
    use std::thread;

    fn lab() -> Session {
        let hal = corerouter_hal::virt::VirtualHal::new(4).with_wifi(1);
        let mut s = Session::new(Box::new(hal));
        s.set_runner(test_runner::sim());
        // The tick adopts the radio (its name held for three polls).
        for t in 0..4 {
            s.tick(1_000 + t);
        }
        s
    }

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..2000 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("task {id} did not finish");
    }

    fn radio(s: &Session) -> String {
        s.store()
            .running()
            .interfaces
            .iter()
            .find(|(_, i)| matches!(i.kind, InterfaceKind::Wifi(_)))
            .map(|(n, _)| n.to_string())
            .expect("the lab has a radio")
    }

    #[test]
    fn the_snooper_on_a_disabled_radio_hops_and_prints() {
        let mut s = lab();
        let r = radio(&s);
        let rev = s.store().current_revision();
        let journal = s.journal().len();
        let out = s
            .execute(
                "interface.wifi.snooper.start",
                &json!({"interface": r, "hop": true, "channels": "36,44,1", "duration": 6}),
            )
            .unwrap();
        assert_eq!(out["mode"], "exclusive");
        assert_eq!(out["hop"], json!([5180, 5220, 2412]));
        let id = out["task_id"].as_u64().unwrap();
        let p = until_done(&mut s, id);
        assert_eq!(p["kind"], "wifi-snooper");
        assert_eq!(p["summary"]["end"], "duration reached");
        let t = s.execute("interface.wifi.snooper.print", &json!({"id": id})).unwrap();
        assert_eq!(t["running"], false);
        assert_eq!(t["radio"], r);
        let nets = t["networks"].as_array().unwrap();
        assert!(nets.iter().any(|n| n["ssid"] == "CoreRouter-Lab"));
        assert_eq!(t["channels"].as_array().unwrap().len(), 3);
        // Operational: nothing in the journal, no new revision.
        assert_eq!(s.journal().len(), journal);
        assert_eq!(s.store().current_revision(), rev);
        // A snooper has no frames nor file.
        assert!(s.execute("interface.wifi.sniffer.packets", &json!({"id": id})).is_err());
        assert!(s.execute("interface.wifi.sniffer.download", &json!({"id": id})).is_err());
    }

    #[test]
    fn the_sniffer_records_radiotap_frames_for_wireshark() {
        let mut s = lab();
        let r = radio(&s);
        let out = s
            .execute(
                "interface.wifi.sniffer.start",
                &json!({"interface": r, "channel": 44, "frame_types": "mgmt", "duration": 2}),
            )
            .unwrap();
        let id = out["task_id"].as_u64().unwrap();
        let p = until_done(&mut s, id);
        assert!(p["summary"]["kept"].as_u64().unwrap() > 20, "{}", p["summary"]);
        let d = s
            .execute("interface.wifi.sniffer.download", &json!({"id": id, "length": 1_000_000}))
            .unwrap();
        assert_eq!(d["complete"], true);
        assert_eq!(d["file_name"], format!("wifi-{r}-{id}.pcap"));
        let file = base64::engine::general_purpose::STANDARD
            .decode(d["data"].as_str().unwrap())
            .unwrap();
        assert_eq!(&file[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(u32::from_le_bytes(file[20..24].try_into().unwrap()), 127);
        let k = s
            .execute("interface.wifi.sniffer.packets", &json!({"id": id, "max": 5}))
            .unwrap();
        let pk = k["packets"].as_array().unwrap();
        assert_eq!(pk.len(), 5);
        assert!(pk.iter().all(|x| x["kind"] == "mgmt"));
        let last = k["last_seq"].as_u64().unwrap();
        let none = s
            .execute("interface.wifi.sniffer.packets", &json!({"id": id, "after_seq": last}))
            .unwrap();
        assert!(none["packets"].as_array().unwrap().is_empty());
        assert!(s
            .execute("interface.wifi.sniffer.download", &json!({"id": id, "offset": file.len() as u64 + 1}))
            .is_err());
    }

    fn enable(s: &mut Session, r: &str) {
        s.execute("interface.wifi.country.set", &json!({"country": "BR"})).unwrap();
        s.execute("interface.wifi.set", &json!({"name": r, "ssid": "CoreRouter-Lab", "passphrase": corerouter_hal::lab_wifi::LAB_PASSPHRASE, "disabled": false}))
            .unwrap();
    }

    #[test]
    fn an_enabled_radio_is_never_taken_off_its_network() {
        let mut s = lab();
        let r = radio(&s);
        enable(&mut s, &r);
        for p in [
            json!({"interface": r, "mode": "exclusive"}),
            json!({"interface": r, "channel": 1}),
            json!({"interface": r, "hop": true}),
        ] {
            let e = s.execute("interface.wifi.snooper.start", &p).unwrap_err().to_string();
            assert!(e.contains("never takes it off its network"), "{e}");
            assert!(e.contains("interface.wifi.disable"), "{e}");
        }
        // Beside the station: allowed, on its channel.
        let out = s
            .execute("interface.wifi.snooper.start", &json!({"interface": r, "duration": 1}))
            .unwrap();
        assert_eq!(out["mode"], "shared");
        assert_eq!(out["channel"], Value::Null);
        let id = out["task_id"].as_u64().unwrap();
        until_done(&mut s, id);
        // One per radio.
        let a = s
            .execute("interface.wifi.snooper.start", &json!({"interface": r, "duration": 60}))
            .unwrap();
        let e = s
            .execute("interface.wifi.snooper.start", &json!({"interface": r}))
            .unwrap_err();
        assert!(e.to_string().contains("runs on"), "{e}");
        s.execute("tool.task.stop", &json!({"id": a["task_id"]})).unwrap();
    }

    #[test]
    fn enabling_the_radio_again_stops_an_exclusive_sniffer() {
        let mut s = lab();
        let r = radio(&s);
        let out = s
            .execute("interface.wifi.snooper.start", &json!({"interface": r, "channel": 36, "duration": 600}))
            .unwrap();
        let id = out["task_id"].as_u64().unwrap();
        // What Safe Mode's undo does: the interface enabled again.
        enable(&mut s, &r);
        s.wifi_service(1_000);
        let p = until_done(&mut s, id);
        assert_eq!(p["summary"]["end"], "the radio went back to its network");
    }

    #[test]
    fn bad_parameters_are_refused_without_starting() {
        let mut s = lab();
        let r = radio(&s);
        let journal = s.journal().len();
        for p in [
            json!({}),
            json!({"interface": "nope0"}),
            json!({"interface": "ether1"}),
            json!({"interface": r, "mode": "promiscuous"}),
            json!({"interface": r, "channel": 15}),
            json!({"interface": r, "channel": 5935}),
            json!({"interface": r, "channel": 165}),
            json!({"interface": r, "hop": true, "channels": "36"}),
            json!({"interface": r, "hop": true, "channels": "36,x"}),
            json!({"interface": r, "channels": "36,44"}),
            json!({"interface": r, "channel_time": 10}),
            json!({"interface": r, "duration": 0}),
            json!({"interface": r, "extra": 1}),
        ] {
            assert!(s.execute("interface.wifi.snooper.start", &p).is_err(), "accepted {p}");
        }
        for p in [
            json!({"interface": r, "bssid": "aa:bb"}),
            json!({"interface": r, "mac_address": "zz:bb:cc:dd:ee:ff"}),
            json!({"interface": r, "frame_types": "mgmt,beacons"}),
            json!({"interface": r, "file_limit": 0}),
            json!({"interface": r, "file_limit": 70_000}),
            json!({"interface": r, "ssid": "x".repeat(33)}),
        ] {
            assert!(s.execute("interface.wifi.sniffer.start", &p).is_err(), "accepted {p}");
        }
        assert!(s.task_list().as_array().unwrap().is_empty());
        assert!(s.execute("interface.wifi.snooper.print", &json!({"id": 99})).is_err());
        assert_eq!(s.journal().len(), journal);
    }

    #[test]
    fn channels_by_number_or_mhz() {
        assert_eq!(mhz_of("c", 1).unwrap(), 2412);
        assert_eq!(mhz_of("c", 14).unwrap(), 2484);
        assert_eq!(mhz_of("c", 36).unwrap(), 5180);
        assert_eq!(mhz_of("c", 5955).unwrap(), 5955);
        assert!(mhz_of("c", 0).is_err() && mhz_of("c", 200).is_err() && mhz_of("c", 2000).is_err());
        let l = channel_list(&json!({"channels": [1, 2412, 6]})).unwrap().unwrap();
        assert_eq!(l, vec![2412, 2437]);
    }
}

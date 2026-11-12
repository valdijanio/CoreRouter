//! The Wi-Fi radios at run time (G1.30): what the running configuration
//! says each one joins, told to the platform once, and what came of it.
//!
//! The clock that drives the DHCP and PPPoE clients drives this too
//! ([`Session::wifi_service`]). Per radio and per call the work is one
//! read of the platform's events, which is empty almost always; a join, a
//! scan and a status read happen on a change or every [`STATUS_EVERY_MS`].
//! Nothing here grows with traffic: the data path is the kernel's.
//!
//! The passphrase is opened from its seal only to hand it to the platform's
//! `join`, and is in no state kept here: what tells one configuration from
//! another is the sealed box itself.

use std::collections::{BTreeMap, VecDeque};

use corerouter_hal::wifi::{
    FourAddr, JoinSecurity, MAX_SPECTRAL_PENDING, WifiBss, WifiEvent, WifiFailure, WifiNetwork, WifiPort,
    WifiRadio, WifiState, WifiStatus, WifiSurvey,
};
use corerouter_model::wifi::{BridgeProtocol, Country, WifiConfig, WifiMode, WifiSecurity};
use corerouter_model::{Config, IfName, InterfaceKind};
use serde_json::{Value, json};

use crate::Session;

/// Events kept for `interface.wifi.history`.
pub const MAX_HISTORY: usize = 256;
/// Radios driven at most (a hostile config).
pub const MAX_RADIOS: usize = 16;
/// Before a radio whose port did not open is tried again.
const OPEN_RETRY_MS: u64 = 5_000;
/// How often a radio's link (signal, rate) is read.
const STATUS_EVERY_MS: u64 = 2_000;
/// A scan nobody heard the end of is over after this long.
const SCAN_TIMEOUT_MS: u64 = 15_000;

/// One line of `interface.wifi.history`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub seq: u64,
    pub time: Option<u64>,
    pub name: IfName,
    pub event: &'static str,
    pub message: String,
}

/// What a radio was last told: everything of its network but the key in
/// clear (the sealed box stands for it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Told {
    ssid: String,
    security: WifiSecurity,
    key_box: String,
    hidden: bool,
    band: Option<(u32, u32)>,
    bssid: Option<String>,
    /// G1.30m: a station-bridge's four addresses, and its bridge.
    four_addr: Option<FourAddr>,
    bridge: Option<String>,
}

/// G1.30m: the four addresses `st` asks for (`None`: a plain station).
fn four_addr(st: &WifiConfig) -> Option<FourAddr> {
    (st.mode == WifiMode::StationBridge).then_some(match st.bridge_protocol {
        BridgeProtocol::MultiAp => FourAddr::MultiAp,
        BridgeProtocol::Wds => FourAddr::Wds,
    })
}

fn told(st: &WifiConfig, bridge: Option<&IfName>) -> Told {
    let fa = four_addr(st);
    Told {
        ssid: st.ssid.clone(),
        security: st.security,
        key_box: st.passphrase.stored().to_owned(),
        hidden: st.hidden,
        band: st.band.map(|b| b.range_mhz()),
        bssid: st.bssid.map(|m| m.to_string().to_ascii_lowercase()),
        four_addr: fa,
        // Only a station-bridge is a bridge port.
        bridge: fa.and(bridge).map(ToString::to_string),
    }
}

fn join_security(s: WifiSecurity) -> JoinSecurity {
    match s {
        WifiSecurity::Auto => JoinSecurity::Auto,
        WifiSecurity::Wpa3 => JoinSecurity::Wpa3,
        WifiSecurity::Wpa2 => JoinSecurity::Wpa2,
        WifiSecurity::Open => JoinSecurity::Open,
    }
}

/// One radio at run time.
#[derive(Default)]
pub(crate) struct Radio {
    port: Option<Box<dyn WifiPort>>,
    retry_at: u64,
    /// Why the platform could not open the radio or take the last order.
    pub(crate) error: Option<String>,
    told: Option<Told>,
    pub(crate) status: WifiStatus,
    status_at: u64,
    pub(crate) failure: Option<(WifiFailure, Option<u64>)>,
    pub(crate) connected_since_ms: Option<u64>,
    pub(crate) reconnects: u32,
    pub(crate) scan: Vec<WifiBss>,
    /// Unix time of the last finished scan.
    pub(crate) scanned_at: Option<u64>,
    pub(crate) scan_started_ms: Option<u64>,
    pub(crate) scan_error: Option<String>,
    pub(crate) hardware: Option<WifiRadio>,
    /// G1.30i: the channels' survey as of the last scan.
    pub(crate) survey: Vec<WifiSurvey>,
    /// G1.30i: the last spectral scan, running or not.
    pub(crate) spectrum: Option<crate::wifi_spectrum::Spectrum>,
}

/// The session's radios.
#[derive(Default)]
pub struct WifiRuntime {
    pub(crate) radios: BTreeMap<IfName, Radio>,
    history: VecDeque<HistoryEntry>,
    seq: u64,
    /// What the platform was last asked for (`Some(None)`: the world
    /// domain); `None`: nothing yet.
    country_asked: Option<Option<Country>>,
    pub(crate) country_error: Option<String>,
    pub(crate) now_ms: u64,
    /// G1.30a: the radios in access point mode.
    pub(crate) aps: BTreeMap<IfName, crate::wifi_ap::ApRadio>,
}

impl WifiRuntime {
    pub fn history(&self) -> impl DoubleEndedIterator<Item = &HistoryEntry> {
        self.history.iter()
    }
}

/// The Wi-Fi interfaces of `cfg`: name, off (disabled, or no country), the
/// network to be on (or, G1.30a, to announce) and the mode.
fn wanted(cfg: &Config) -> Vec<(IfName, bool, Option<WifiConfig>, WifiMode)> {
    let no_country = cfg.system.wifi.country.is_none();
    cfg.interfaces
        .values()
        .filter_map(|i| match &i.kind {
            InterfaceKind::Wifi(st) => {
                let off = i.disabled || no_country;
                let net = (!off && !st.ssid.is_empty()).then(|| (**st).clone());
                Some((i.name.clone(), off, net, st.mode))
            }
            _ => None,
        })
        .take(MAX_RADIOS)
        .collect()
}

/// How often a sweep asks the radio for a scan, ms: each scan visits every
/// channel once (some 3 s for both bands), and the spectral samples come
/// while it does.
const SWEEP_SCAN_MS: u64 = 4_000;

/// G1.30i: one tick of a radio's spectral scan: the samples into this
/// tick's row, the scans of a sweep, the end when its time is up.
fn spectral_step(r: &mut Radio, now: u64) {
    let (Some(sp), Some(p)) = (r.spectrum.as_mut(), r.port.as_mut()) else {
        return;
    };
    let Some(until) = sp.until_ms else {
        return;
    };
    let samples = p.spectral_samples(MAX_SPECTRAL_PENDING);
    sp.feed(&samples);
    sp.end_frame();
    if now >= until {
        p.spectral_stop();
        sp.until_ms = None;
        return;
    }
    if sp.range.band().is_some() && now >= sp.next_scan_ms && r.scan_started_ms.is_none() {
        sp.next_scan_ms = now.saturating_add(SWEEP_SCAN_MS);
        if p.scan().is_ok() {
            r.scan_started_ms = Some(now);
        }
    }
}

/// A Wi-Fi channel number from its centre frequency.
pub fn channel(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 => Some((mhz - 2407) / 5),
        5160..=5885 => Some((mhz - 5000) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        _ => None,
    }
}

impl Session {
    pub(crate) fn wifi_rt(&mut self) -> Option<&mut WifiRuntime> {
        self.ext_mut::<WifiRuntime>()
    }

    /// The runtime, read-only (commands).
    pub(crate) fn wifi(&self) -> Option<&WifiRuntime> {
        self.ext::<WifiRuntime>()
    }

    /// Drive the radios: open and close them as the running configuration
    /// says, tell each its network once, read what happened. `now_ms`: a
    /// monotonic clock.
    pub fn wifi_service(&mut self, now_ms: u64) {
        // G1.30j: an exclusive sniffer gives the radio back to its station.
        crate::cmd::wifi_sniffer::watch(self);
        let want = wanted(self.store().running());
        let idle = self
            .wifi()
            .is_none_or(|rt| rt.radios.is_empty() && rt.aps.is_empty());
        if want.is_empty() && idle {
            return;
        }
        if let Some(rt) = self.wifi_rt() {
            rt.now_ms = now_ms;
        }
        self.wifi_country_sync();
        // Radios that left the configuration.
        let gone: Vec<IfName> = self
            .wifi()
            .map(|rt| {
                rt.radios
                    .keys()
                    .chain(rt.aps.keys())
                    .filter(|n| !want.iter().any(|(w, _, _, _)| w == *n))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for name in gone {
            if let Some(mut r) = self.wifi_rt().and_then(|rt| rt.radios.remove(&name))
                && let Some(p) = r.port.as_mut()
            {
                let _ = p.leave();
            }
            self.wifi_ap_step(&name, None, now_ms);
        }
        for (name, off, net, mode) in want {
            match mode {
                // G1.30m: a station-bridge is a station that asks for four
                // addresses (`wifi_network`).
                WifiMode::Station | WifiMode::StationBridge => {
                    self.wifi_ap_step(&name, None, now_ms);
                    self.wifi_step(&name, off, net.as_ref(), now_ms);
                }
                // G1.30a: the station lets go of the radio first.
                WifiMode::Ap => {
                    self.wifi_step(&name, true, None, now_ms);
                    self.wifi_ap_step(&name, net.as_ref(), now_ms);
                }
            }
        }
    }

    /// Ask the platform for the configured country when it changed.
    fn wifi_country_sync(&mut self) {
        let country = self.store().running().system.wifi.country;
        let asked = self.wifi().and_then(|rt| rt.country_asked);
        if asked == Some(country) {
            return;
        }
        // None set and none ever asked for: the kernel is on the world
        // domain already.
        if asked.is_none() && country.is_none() {
            if let Some(rt) = self.wifi_rt() {
                rt.country_asked = Some(None);
            }
            return;
        }
        let r = self
            .hal_mut()
            .wifi_country(country.as_ref().map(Country::as_str));
        let err = r.err().map(|e| e.to_string());
        if let Some(rt) = self.wifi_rt() {
            rt.country_asked = Some(country);
            rt.country_error.clone_from(&err);
        }
        let name = country.map_or_else(|| "the world domain".to_owned(), |c| c.to_string());
        match err {
            Some(e) => self.wifi_log("warning", format!("wifi: country {name}: {e}"), json!({})),
            None => self.wifi_log("info", format!("wifi: country {name} asked for"), json!({})),
        }
    }

    fn wifi_step(&mut self, name: &IfName, off: bool, net: Option<&WifiConfig>, now: u64) {
        let unix = self.now();
        let mut notes: Vec<(&'static str, String)> = Vec::new();
        // 1. A radio that is off has no port.
        let has_port = {
            let Some(r) = self.wifi_rt().map(|rt| rt.radios.entry(name.clone()).or_default())
            else {
                return;
            };
            if off {
                if let Some(mut p) = r.port.take() {
                    let _ = p.leave();
                    if r.status.state == WifiState::Connected {
                        notes.push(("disconnected", "left: the interface is off".into()));
                    }
                }
                r.told = None;
                r.status = WifiStatus::default();
                r.connected_since_ms = None;
                r.error = None;
                r.scan_started_ms = None;
                if let Some(sp) = r.spectrum.as_mut() {
                    sp.until_ms = None;
                }
            }
            r.port.is_some()
        };
        if off {
            self.wifi_notes(name, notes);
            return;
        }
        // 2. Open it.
        if !has_port {
            let due = self
                .wifi()
                .and_then(|rt| rt.radios.get(name))
                .is_some_and(|r| r.retry_at <= now);
            if !due {
                return;
            }
            let opened = self.hal_mut().wifi_port(name);
            let hardware = self.hal_mut().wifi_radio(name);
            let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) else {
                return;
            };
            match opened {
                Ok(p) => {
                    r.port = Some(p);
                    r.hardware = hardware;
                    r.error = None;
                    r.told = None;
                }
                Err(e) => {
                    let msg = e.to_string();
                    r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                    if r.error.as_deref() != Some(msg.as_str()) {
                        notes.push(("error", format!("cannot open the radio: {msg}")));
                        r.error = Some(msg);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
            }
        }
        // 3. Tell it its network, once per change.
        let bridge = self
            .store()
            .running()
            .interfaces
            .get(name)
            .and_then(|i| i.bridge.clone());
        let want = net.map(|st| told(st, bridge.as_ref()));
        let order = self
            .wifi()
            .and_then(|rt| rt.radios.get(name))
            .is_some_and(|r| r.told != want);
        if order {
            let join = match net {
                Some(st) => self.wifi_network(name, st).map(Some),
                None => Ok(None),
            };
            let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) else {
                return;
            };
            let Some(p) = r.port.as_mut() else { return };
            let done = match &join {
                Ok(Some(n)) => p.join(n).map_err(|e| e.to_string()),
                Ok(None) => p.leave().map_err(|e| e.to_string()),
                Err(e) => Err(e.clone()),
            };
            match done {
                Ok(()) => {
                    r.told = want;
                    r.error = None;
                    r.failure = None;
                    r.status_at = 0;
                    // Leaving because it was told to is not a lost link.
                    r.connected_since_ms = None;
                    if let Some(st) = net {
                        notes.push(("joining", format!("joining '{}'", st.ssid)));
                    }
                }
                Err(e) => {
                    // The port is dropped: the next round opens it again.
                    r.port = None;
                    r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                    if r.error.as_deref() != Some(e.as_str()) {
                        notes.push(("error", e.clone()));
                        r.error = Some(e);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
            }
        }
        // 4. What happened.
        if let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) {
            let events = r.port.as_mut().map(|p| p.events()).unwrap_or_default();
            let mut refresh = !events.is_empty();
            for e in events {
                match e {
                    WifiEvent::Connected { bssid } => {
                        r.failure = None;
                        r.connected_since_ms = Some(now);
                        let ssid = r.told.as_ref().map(|t| t.ssid.clone()).unwrap_or_default();
                        notes.push(("connected", format!("connected to '{ssid}' ({bssid})")));
                    }
                    WifiEvent::Disconnected { reason } => {
                        if r.connected_since_ms.take().is_some() {
                            r.reconnects = r.reconnects.saturating_add(1);
                        }
                        notes.push(("disconnected", format!("disconnected: {reason}")));
                    }
                    // With no network to look for, a scan that ends "found
                    // none" (the supplicant says so after every scan) is not
                    // a failure of anything.
                    WifiEvent::Failed(WifiFailure::NotFound) if r.told.is_none() => {}
                    WifiEvent::Failed(f) => {
                        // A cause the access point gave (wrong key, refused)
                        // has consequences in the supplicant: it leaves that
                        // access point alone for a while, so its next scan
                        // "finds none" with the network on the list, and
                        // then it pauses the network. The cause stays.
                        let heard = r
                            .told
                            .as_ref()
                            .is_some_and(|t| r.scan.iter().any(|b| b.ssid == t.ssid));
                        let caused = matches!(
                            r.failure,
                            Some((WifiFailure::WrongKey | WifiFailure::Rejected(_), _))
                        ) && match f {
                            WifiFailure::NoAnswer => true,
                            WifiFailure::NotFound => heard,
                            _ => false,
                        };
                        if caused {
                            if let Some((_, at)) = r.failure.as_mut() {
                                *at = unix;
                            }
                            continue;
                        }
                        // Said once: the supplicant repeats it at every retry.
                        if r.failure.as_ref().map(|(old, _)| old) != Some(&f) {
                            notes.push(("failed", f.text()));
                        }
                        r.failure = Some((f, unix));
                    }
                    WifiEvent::ScanDone => {
                        r.scan_started_ms = None;
                        r.scan_error = None;
                        match r.port.as_mut().map(|p| p.scan_results()) {
                            Some(Ok(seen)) => {
                                r.scan = seen;
                                r.scanned_at = unix;
                                r.survey = r.port.as_mut().map(|p| p.survey()).unwrap_or_default();
                            }
                            Some(Err(e)) => r.scan_error = Some(e.to_string()),
                            None => {}
                        }
                    }
                    WifiEvent::ScanFailed(why) => {
                        r.scan_started_ms = None;
                        r.scan_error = Some(why);
                    }
                    // The domain in force is read from the platform when
                    // asked (`interface.wifi.country.get`).
                    WifiEvent::Country(_) => {}
                    WifiEvent::Blocked(true) => {
                        notes.push((
                            "blocked",
                            "the radio is blocked (a switch, the airplane-mode key or the firmware)"
                                .into(),
                        ));
                    }
                    WifiEvent::Blocked(false) => notes.push(("unblocked", "the radio is unblocked".into())),
                }
            }
            spectral_step(r, now);
            if r.scan_started_ms.is_some_and(|t| now.saturating_sub(t) > SCAN_TIMEOUT_MS) {
                r.scan_started_ms = None;
                r.scan_error = Some("the scan did not end".into());
            }
            refresh |= now.saturating_sub(r.status_at) >= STATUS_EVERY_MS || r.status_at == 0;
            if refresh && let Some(p) = r.port.as_mut() {
                r.status_at = now.max(1);
                match p.status() {
                    Ok(st) => r.status = st,
                    Err(e) => {
                        // The supplicant died or the radio went away: start over.
                        let msg = e.to_string();
                        r.port = None;
                        r.told = None;
                        r.status = WifiStatus::default();
                        r.connected_since_ms = None;
                        r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                        if r.error.as_deref() != Some(msg.as_str()) {
                            notes.push(("error", format!("the radio stopped answering: {msg}")));
                            r.error = Some(msg);
                        }
                    }
                }
            }
        }
        self.wifi_notes(name, notes);
    }

    /// The network of `st` as the platform takes it, the passphrase opened.
    fn wifi_network(&mut self, name: &IfName, st: &WifiConfig) -> Result<WifiNetwork, String> {
        let key = if st.security.keyed() {
            let k = crate::sealing::key(self)?;
            k.open(&st.passphrase).ok_or_else(|| {
                format!(
                    "the passphrase of '{name}' cannot be opened (the router's secret key \
                     changed): set it again with interface.wifi.set"
                )
            })?
        } else {
            String::new()
        };
        let bridge = self
            .store()
            .running()
            .interfaces
            .get(name)
            .and_then(|i| i.bridge.clone());
        let t = told(st, bridge.as_ref());
        // G1.30m: a backhaul is WPA3 only (`auto` means WPA3 there).
        let security = if t.four_addr.is_some() && st.security == WifiSecurity::Auto {
            JoinSecurity::Wpa3
        } else {
            join_security(st.security)
        };
        Ok(WifiNetwork {
            ssid: t.ssid,
            security,
            key,
            hidden: t.hidden,
            band_mhz: t.band,
            bssid: t.bssid,
            four_addr: t.four_addr,
            bridge: t.bridge,
        })
    }

    pub(crate) fn wifi_notes(&mut self, name: &IfName, notes: Vec<(&'static str, String)>) {
        for (event, message) in notes {
            self.wifi_note(name, event, message);
        }
    }

    fn wifi_log(&mut self, level: &str, message: String, detail: Value) {
        if matches!(level, "warning" | "error") {
            log::warn!("{message}");
        } else {
            log::info!("{message}");
        }
        self.log_event(&["wireless", level], crate::logging::DAEMON, message, detail);
    }

    /// One event of radio `name`: the router's log and the history.
    pub(crate) fn wifi_note(&mut self, name: &IfName, event: &'static str, message: String) {
        let level = if matches!(event, "error" | "failed" | "blocked" | "disconnected") {
            "warning"
        } else {
            "info"
        };
        self.wifi_log(
            level,
            format!("{name}: {message}"),
            json!({"interface": name, "event": event}),
        );
        let time = self.now();
        let Some(rt) = self.wifi_rt() else { return };
        rt.seq = rt.seq.saturating_add(1);
        rt.history.push_back(HistoryEntry {
            seq: rt.seq,
            time,
            name: name.clone(),
            event,
            message,
        });
        while rt.history.len() > MAX_HISTORY {
            rt.history.pop_front();
        }
    }

    /// Start a scan on radio `name`; why not, if it cannot.
    pub(crate) fn wifi_scan(&mut self, name: &IfName) -> Result<(), String> {
        let now = self.wifi().map_or(0, |rt| rt.now_ms);
        let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) else {
            return Err(format!("'{name}' has no radio running yet"));
        };
        let Some(p) = r.port.as_mut() else {
            return Err(r.error.clone().unwrap_or_else(|| {
                format!("the radio of '{name}' is not open yet: try again in a moment")
            }));
        };
        if r.scan_started_ms.is_some() {
            return Ok(());
        }
        p.scan().map_err(|e| e.to_string())?;
        r.scan_started_ms = Some(now);
        r.scan_error = None;
        Ok(())
    }

    /// G1.30i: start a spectral scan of `range` on radio `name` for `secs`.
    pub(crate) fn wifi_spectral_start(
        &mut self,
        name: &IfName,
        range: crate::wifi_spectrum::Range,
        secs: u32,
    ) -> Result<(), String> {
        let now = self.wifi().map_or(0, |rt| rt.now_ms);
        let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) else {
            return Err(format!("'{name}' has no radio running yet"));
        };
        let Some(p) = r.port.as_mut() else {
            return Err(r.error.clone().unwrap_or_else(|| {
                format!("the radio of '{name}' is not open yet: try again in a moment")
            }));
        };
        p.spectral_stop();
        p.spectral_start(secs, range.band()).map_err(|e| e.to_string())?;
        r.spectrum = Some(crate::wifi_spectrum::Spectrum::new(
            range,
            now.saturating_add(u64::from(secs) * 1000),
        ));
        Ok(())
    }

    /// G1.30i: stop the spectral scan of radio `name` (its data stays).
    pub(crate) fn wifi_spectral_stop(&mut self, name: &IfName) {
        if let Some(r) = self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) {
            if let Some(p) = r.port.as_mut() {
                p.spectral_stop();
            }
            if let Some(sp) = r.spectrum.as_mut() {
                sp.until_ms = None;
            }
        }
    }

    /// Leave and join again, forgetting the last failure.
    pub(crate) fn wifi_rejoin(&mut self, name: &IfName) -> bool {
        match self.wifi_rt().and_then(|rt| rt.radios.get_mut(name)) {
            Some(r) => {
                r.told = None;
                r.failure = None;
                r.retry_at = 0;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels() {
        for (mhz, ch) in [
            (2412, 1),
            (2437, 6),
            (2472, 13),
            (2484, 14),
            (5180, 36),
            (5220, 44),
            (5745, 149),
            (5955, 1),
            (6115, 33),
        ] {
            assert_eq!(channel(mhz), Some(ch), "{mhz}");
        }
        assert_eq!(channel(900), None);
        assert_eq!(channel(0), None);
    }
}

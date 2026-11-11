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
    JoinSecurity, WifiBss, WifiEvent, WifiFailure, WifiNetwork, WifiPort, WifiRadio, WifiState,
    WifiStatus,
};
use corerouter_model::wifi::{Country, WifiSecurity, WifiStation};
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
}

fn told(st: &WifiStation) -> Told {
    Told {
        ssid: st.ssid.clone(),
        security: st.security,
        key_box: st.passphrase.stored().to_owned(),
        hidden: st.hidden,
        band: st.band.map(|b| b.range_mhz()),
        bssid: st.bssid.map(|m| m.to_string().to_ascii_lowercase()),
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
}

impl WifiRuntime {
    pub fn history(&self) -> impl DoubleEndedIterator<Item = &HistoryEntry> {
        self.history.iter()
    }
}

/// The Wi-Fi interfaces of `cfg`: name, off (disabled, or no country), and
/// the network to be on.
fn wanted(cfg: &Config) -> Vec<(IfName, bool, Option<WifiStation>)> {
    let no_country = cfg.system.wifi.country.is_none();
    cfg.interfaces
        .values()
        .filter_map(|i| match &i.kind {
            InterfaceKind::Wifi(st) => {
                let off = i.disabled || no_country;
                let net = (!off && !st.ssid.is_empty()).then(|| (**st).clone());
                Some((i.name.clone(), off, net))
            }
            _ => None,
        })
        .take(MAX_RADIOS)
        .collect()
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
    fn wifi_rt(&mut self) -> Option<&mut WifiRuntime> {
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
        let want = wanted(self.store().running());
        let idle = self.wifi().is_none_or(|rt| rt.radios.is_empty());
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
                    .filter(|n| !want.iter().any(|(w, _, _)| w == *n))
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
        }
        for (name, off, net) in want {
            self.wifi_step(&name, off, net.as_ref(), now_ms);
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

    fn wifi_step(&mut self, name: &IfName, off: bool, net: Option<&WifiStation>, now: u64) {
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
        let want = net.map(told);
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
    fn wifi_network(&mut self, name: &IfName, st: &WifiStation) -> Result<WifiNetwork, String> {
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
        let t = told(st);
        Ok(WifiNetwork {
            ssid: t.ssid,
            security: join_security(st.security),
            key,
            hidden: t.hidden,
            band_mhz: t.band,
            bssid: t.bssid,
        })
    }

    fn wifi_notes(&mut self, name: &IfName, notes: Vec<(&'static str, String)>) {
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

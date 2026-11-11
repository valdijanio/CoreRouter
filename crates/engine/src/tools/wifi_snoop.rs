//! Wi-Fi snooper and 802.11 capture (G1.30j): what a radio in monitor mode
//! hears, per network and per station, and the frames into a pcap file
//! (radiotap, link type 127) for Wireshark. RouterOS v7's
//! `/interface/wifi/sniffer` and the legacy `/interface/wireless/snooper`.
//!
//! The work per frame is the parsers of `corerouter_hal::ieee80211` and
//! two hash-map lookups (the transmitter, and the station a data frame
//! belongs to): nothing grows with the number of stations or networks.
//! The table is turned into JSON once a second, bounded
//! ([`MAX_NETWORKS_SHOWN`], [`MAX_STATIONS_SHOWN`]), off the session lock:
//! the job runs on a task thread and shares only [`SnoopState`] with the
//! commands that read it.
//!
//! What is counted is what the radio heard: frames sent at a rate or on a
//! channel width the card does not receive, and frames on the other
//! channels while hopping, are not. Airtime is the frames' own duration,
//! estimated from the size and the rate (`ieee80211::airtime_us`), over
//! the time the radio listened to that channel.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use corerouter_hal::capture::{FrameBatch, PCAP_RECORD_HEADER_LEN, pcap_header_for, pcap_record};
use corerouter_hal::ieee80211::{
    self, Info, Kind, LINKTYPE_IEEE802_11_RADIOTAP, Mac, Phy, Radiotap, Ssid, is_group, is_local,
    mac_text,
};
use corerouter_hal::wifi::BssSecurity;
use corerouter_hal::wifi_monitor::{MonitorMode, MonitorSpec, SharedWifiMonitor};
use serde_json::{Value, json};

use crate::tasks::TaskCtx;

/// Stations and networks remembered (a busy airport; more is counted as
/// `overflow`, not kept).
pub const MAX_STATIONS: usize = 4096;
pub const MAX_NETWORKS: usize = 1024;
/// What one `interface.wifi.snooper.print` shows at most.
pub const MAX_NETWORKS_SHOWN: usize = 200;
pub const MAX_STATIONS_SHOWN: usize = 64;
/// Frames kept for `interface.wifi.sniffer.packets`.
pub const MAX_RECENT: usize = 512;
/// Frames read per call.
const BATCH: usize = 1024;
const MAX_WAIT: Duration = Duration::from_millis(100);
/// The pcap file's snap length: frames are never cut.
pub const SNAPLEN: u32 = corerouter_hal::capture::MAX_SNAPLEN_RADIO as u32;

/// Deauthentications in one second that make a "flood".
const FLOOD: u32 = 10;

/// What a transmitter sent.
#[derive(Debug, Clone, Copy, Default)]
struct Tx {
    frames: u64,
    retries: u64,
    airtime_us: u64,
    signal_sum: i64,
    signal_n: u64,
    /// The last data rate seen, kbit/s, and how it was sent.
    kbps: u32,
    phy: Phy,
    mcs: Option<u8>,
    nss: Option<u8>,
    width: Option<u16>,
}

impl Tx {
    fn add(&mut self, r: &Radiotap, retry: bool, airtime: u32, data: bool) {
        self.frames += 1;
        self.retries += u64::from(retry);
        self.airtime_us += u64::from(airtime);
        if let Some(s) = r.signal_dbm {
            self.signal_sum += i64::from(s);
            self.signal_n += 1;
        }
        // The rate of data frames: management goes at the basic rate.
        if data && let Some(k) = ieee80211::rate_kbps(r) {
            self.kbps = k;
            self.phy = r.phy;
            self.mcs = r.mcs;
            self.nss = r.nss;
            self.width = r.width_mhz;
        }
    }

    fn signal(&self) -> Option<i64> {
        (self.signal_n > 0).then(|| self.signal_sum / i64::try_from(self.signal_n).unwrap_or(1))
    }

    fn retry_pct(&self) -> f64 {
        if self.frames == 0 {
            0.0
        } else {
            (self.retries as f64 * 1000.0 / self.frames as f64).round() / 10.0
        }
    }

    fn rate_text(&self) -> Option<String> {
        if self.kbps == 0 {
            return None;
        }
        let mbps = f64::from(self.kbps) / 1000.0;
        Some(match (self.phy, self.mcs) {
            (Phy::Legacy, _) | (_, None) => format!("{mbps:.1} Mb/s"),
            (phy, Some(m)) => format!(
                "{mbps:.0} Mb/s {} MCS{m}{}{}",
                phy.as_str().to_uppercase(),
                self.nss.map(|n| format!(" {n}SS")).unwrap_or_default(),
                self.width.map(|w| format!(" {w}MHz")).unwrap_or_default(),
            ),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct Bss {
    ssid: Option<Ssid>,
    hidden: bool,
    /// The name of a hidden network, and what gave it away.
    revealed: Option<(Ssid, &'static str)>,
    freq: u32,
    security: Option<BssSecurity>,
    beacons: u64,
    tx: Tx,
    /// Deauthentications and disassociations sent to everyone.
    broadcast_leave: u32,
}

#[derive(Debug, Clone, Default)]
struct Sta {
    bss: Option<Mac>,
    freq: u32,
    /// What it sent, and what its access point sent to it (data): both
    /// are its airtime.
    tx: Tx,
    down: Tx,
    deauth: u32,
    disassoc: u32,
    /// The last (deauth?, reason) heard about it.
    last_reason: Option<(bool, Option<u16>)>,
    /// EAPOL-Key messages of the 4-way handshake seen (bit n-1: message n).
    eapol: u8,
    /// The last network it asked for by name.
    probed: Option<Ssid>,
    flood_sec: u64,
    flood_n: u32,
    flood_max: u32,
}

impl Sta {
    /// Both directions of its link: the frames, retries and airtime of
    /// each, and the rate the access point sends it at (the one it picked
    /// for this station), else the station's own.
    fn link(&self) -> Tx {
        let rate = if self.down.kbps > 0 { &self.down } else { &self.tx };
        Tx {
            frames: self.tx.frames + self.down.frames,
            retries: self.tx.retries + self.down.retries,
            airtime_us: self.tx.airtime_us + self.down.airtime_us,
            signal_sum: self.tx.signal_sum,
            signal_n: self.tx.signal_n,
            kbps: rate.kbps,
            phy: rate.phy,
            mcs: rate.mcs,
            nss: rate.nss,
            width: rate.width,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Chan {
    frames: u64,
    airtime_us: u64,
    dwell_us: u64,
    noise_sum: i64,
    noise_n: u64,
}

/// One frame, as the snooper read it (for the capture's filter and list).
#[derive(Debug, Clone, Copy)]
pub struct Heard {
    pub kind: Kind,
    pub type_name: &'static str,
    pub freq: u32,
    pub ta: Option<Mac>,
    pub ra: Mac,
    pub addr3: Option<Mac>,
    pub bssid: Option<Mac>,
    pub signal: Option<i8>,
    pub kbps: Option<u32>,
    pub retry: bool,
    pub protected: bool,
    pub info: Info,
    /// The 802.11 frame's length (without the radiotap header).
    pub len: usize,
}

/// The table: networks and stations by MAC, channels by frequency.
#[derive(Debug, Default)]
pub struct Snooper {
    bss: HashMap<Mac, Bss>,
    sta: HashMap<Mac, Sta>,
    chan: BTreeMap<u32, Chan>,
    pub frames: u64,
    pub bad_fcs: u64,
    /// Frames that were not radiotap + 802.11.
    pub unparsed: u64,
    /// New MACs past the bounds.
    pub overflow: u64,
}

impl Snooper {
    /// The radio listened to `freq` for `us` microseconds.
    pub fn dwell(&mut self, freq: u32, us: u64) {
        if freq == 0 {
            return;
        }
        if self.chan.len() < 64 || self.chan.contains_key(&freq) {
            self.chan.entry(freq).or_default().dwell_us += us;
        }
    }

    fn sta_mut(&mut self, m: Mac) -> Option<&mut Sta> {
        if !self.sta.contains_key(&m) && (self.sta.len() >= MAX_STATIONS || is_group(&m)) {
            if !is_group(&m) {
                self.overflow += 1;
            }
            return None;
        }
        Some(self.sta.entry(m).or_default())
    }

    fn bss_mut(&mut self, m: Mac) -> Option<&mut Bss> {
        if !self.bss.contains_key(&m) && (self.bss.len() >= MAX_NETWORKS || is_group(&m)) {
            if !is_group(&m) {
                self.overflow += 1;
            }
            return None;
        }
        Some(self.bss.entry(m).or_default())
    }

    /// The name of network `bssid`, as far as known (revealed included).
    pub fn ssid_of(&self, bssid: &Mac) -> Option<Ssid> {
        let b = self.bss.get(bssid)?;
        b.revealed.map(|(s, _)| s).or(b.ssid.filter(|s| !s.is_hidden()))
    }

    /// Take one captured frame (radiotap + 802.11) heard at `at_us` while
    /// tuned to `tuned` MHz.
    pub fn add(&mut self, at_us: u64, data: &[u8], tuned: u32) -> Option<Heard> {
        self.frames += 1;
        let Some(r) = ieee80211::radiotap(data) else {
            self.unparsed += 1;
            return None;
        };
        let freq = r.freq_mhz.map_or(tuned, u32::from);
        if r.bad_fcs() {
            self.bad_fcs += 1;
            return None;
        }
        let Some(f) = ieee80211::frame(data.get(r.len..).unwrap_or(&[]), r.fcs_len()) else {
            self.unparsed += 1;
            return None;
        };
        let len = data.len().saturating_sub(r.len);
        let airtime = ieee80211::airtime_us(&r, len);
        if let Some(c) = self.chan.get_mut(&freq) {
            c.frames += 1;
            c.airtime_us += u64::from(airtime);
            if let Some(n) = r.noise_dbm {
                c.noise_sum += i64::from(n);
                c.noise_n += 1;
            }
        } else if self.chan.len() < 64 {
            self.chan.insert(
                freq,
                Chan {
                    frames: 1,
                    airtime_us: u64::from(airtime),
                    ..Chan::default()
                },
            );
        }
        let info = ieee80211::info(&f);
        let bssid = f.bssid();
        let (ta, ra) = (f.addr2, f.addr1);
        // The station a frame is about: the side that is not the network.
        let station = match (bssid, ta) {
            (Some(b), Some(t)) if t == b => Some(ra),
            (_, Some(t)) => Some(t),
            _ => None,
        }
        .filter(|m| !is_group(m));
        match info {
            Info::Announce {
                probe_resp,
                elements,
                security,
            } => {
                if let Some(b) = bssid.and_then(|b| self.bss_mut(b)) {
                    b.freq = freq;
                    b.security = Some(security);
                    if !probe_resp {
                        b.beacons += 1;
                    }
                    match elements.ssid {
                        Some(s) if s.is_hidden() => b.hidden = true,
                        Some(s) => {
                            if probe_resp && b.hidden && b.revealed.is_none() {
                                b.revealed = Some((s, "probe response"));
                            }
                            if !b.hidden {
                                b.ssid = Some(s);
                            }
                        }
                        None => {}
                    }
                }
            }
            Info::AssocReq(ssid) => {
                if let (Some(b), Some(s)) = (bssid, ssid)
                    && let Some(bss) = self.bss_mut(b)
                    && bss.hidden
                    && bss.revealed.is_none()
                    && !s.is_hidden()
                {
                    bss.revealed = Some((s, "association request"));
                }
            }
            Info::ProbeReq(Some(s)) => {
                if let Some(st) = ta.and_then(|t| self.sta_mut(t)) {
                    st.probed = Some(s);
                    st.freq = freq;
                }
            }
            Info::Leave { deauth, reason } => match station {
                Some(m) => {
                    if let Some(st) = self.sta_mut(m) {
                        if deauth {
                            st.deauth += 1;
                        } else {
                            st.disassoc += 1;
                        }
                        st.last_reason = Some((deauth, reason));
                        let sec = at_us / 1_000_000;
                        if st.flood_sec != sec {
                            st.flood_sec = sec;
                            st.flood_n = 0;
                        }
                        st.flood_n += 1;
                        st.flood_max = st.flood_max.max(st.flood_n);
                    }
                }
                None => {
                    if let Some(b) = bssid.and_then(|b| self.bss_mut(b)) {
                        b.broadcast_leave += 1;
                    }
                }
            },
            Info::EapolKey(Some(msg)) => {
                if let Some(st) = station.and_then(|m| self.sta_mut(m)) {
                    st.eapol |= 1 << (msg.saturating_sub(1) & 3);
                }
            }
            _ => {}
        }
        // The station joins its network: data frames say which.
        if f.kind == Kind::Data
            && let (Some(b), Some(m)) = (bssid, station)
            && m != b
        {
            if let Some(st) = self.sta_mut(m) {
                st.bss = Some(b);
                st.freq = freq;
            }
            if !self.bss.contains_key(&b)
                && let Some(bss) = self.bss_mut(b)
            {
                bss.freq = freq;
            }
        }
        // What the transmitter sent. Data from an access point to a
        // station is the station's airtime.
        if let Some(t) = ta {
            let data = f.kind == Kind::Data;
            let down = (data && f.from_ds() && !f.to_ds() && !is_group(&ra))
                .then(|| self.sta.get_mut(&ra))
                .flatten();
            if let Some(st) = down {
                st.down.add(&r, f.retry(), airtime, data);
            } else if let Some(b) = self.bss.get_mut(&t) {
                b.tx.add(&r, f.retry(), airtime, data);
            } else if let Some(st) = self.sta_mut(t) {
                st.tx.add(&r, f.retry(), airtime, data);
                if st.freq == 0 {
                    st.freq = freq;
                }
            }
        }
        Some(Heard {
            kind: f.kind,
            type_name: f.type_name(),
            freq,
            ta,
            ra,
            addr3: f.addr3,
            bssid,
            signal: r.signal_dbm,
            kbps: ieee80211::rate_kbps(&r),
            retry: f.retry(),
            protected: f.protected(),
            info,
            len,
        })
    }

    fn pct(&self, airtime_us: u64, freq: u32) -> f64 {
        let dwell = self.chan.get(&freq).map_or(0, |c| c.dwell_us);
        if dwell == 0 {
            return 0.0;
        }
        (airtime_us as f64 * 1000.0 / dwell as f64).round().min(1000.0) / 10.0
    }

    fn station_json(&self, m: &Mac, st: &Sta) -> Value {
        let mut notes = Vec::new();
        let both = st.link();
        let retry = both.retry_pct();
        let signal = st.tx.signal();
        if both.frames >= 20
            && retry >= 20.0
            && (both.kbps <= 24_000 || signal.is_some_and(|s| s <= -75))
        {
            notes.push(note(
                "far-slow",
                "amber",
                format!(
                    "far, slow: {retry:.0}% retries at {:.0} Mb/s{}",
                    f64::from(both.kbps) / 1000.0,
                    signal.map(|s| format!(", {s} dBm")).unwrap_or_default()
                ),
            ));
        }
        if st.flood_max >= FLOOD {
            notes.push(note(
                "deauth-flood",
                "red",
                format!("deauth flood: {} in one second (an attack, or a broken access point)", st.flood_max),
            ));
        }
        let reason = st.last_reason.map(|(_, r)| match r {
            Some(code) => format!("reason {code}: {}", ieee80211::reason_text(code)),
            None => "reason ciphered (protected management frames)".into(),
        });
        if st.deauth > 0 {
            notes.push(note(
                "deauth",
                "amber",
                format!("deauth ×{}{}", st.deauth, reason.as_ref().map(|r| format!(" ({r})")).unwrap_or_default()),
            ));
        }
        if st.disassoc > 0 {
            notes.push(note(
                "disassoc",
                "amber",
                format!("disassoc ×{}{}", st.disassoc, reason.as_ref().map(|r| format!(" ({r})")).unwrap_or_default()),
            ));
        }
        let handshake = st.eapol.count_ones();
        if handshake == 4 {
            notes.push(note(
                "handshake",
                "green",
                "4-way handshake captured: Wireshark decrypts this station with the passphrase".into(),
            ));
        } else if handshake > 0 {
            notes.push(note("handshake-partial", "neutral", format!("handshake {handshake}/4")));
        }
        if st.bss.is_none()
            && let Some(p) = st.probed
        {
            notes.push(note("probing", "neutral", format!("looking for '{}'", p.text())));
        }
        json!({
            "mac": mac_text(m),
            "random_mac": is_local(m),
            "frequency": st.freq,
            "airtime_pct": self.pct(both.airtime_us, st.freq),
            "frames": both.frames,
            "retry_pct": retry,
            "rate_mbps": (both.kbps > 0).then(|| (f64::from(both.kbps) / 100.0).round() / 10.0),
            "rate": both.rate_text(),
            "signal": signal,
            "deauth": st.deauth,
            "disassoc": st.disassoc,
            "reason": reason,
            "handshake": handshake,
            "notes": notes,
        })
    }

    /// Networks that share a name, for the twin check: name → BSSIDs.
    fn by_name(&self) -> HashMap<Vec<u8>, Vec<Mac>> {
        let mut out: HashMap<Vec<u8>, Vec<Mac>> = HashMap::new();
        for (m, b) in &self.bss {
            if let Some(s) = b.ssid.filter(|s| !s.is_hidden()) {
                out.entry(s.as_bytes().to_vec()).or_default().push(*m);
            }
        }
        out
    }

    fn twin_note(&self, m: &Mac, b: &Bss, names: &HashMap<Vec<u8>, Vec<Mac>>) -> Option<Value> {
        let s = b.ssid.filter(|s| !s.is_hidden())?;
        let others: Vec<&Bss> = names
            .get(s.as_bytes())?
            .iter()
            .filter(|o| *o != m)
            .filter_map(|o| self.bss.get(o))
            .collect();
        if others.is_empty() {
            return None;
        }
        let mine = b.security?;
        let weak = |x: BssSecurity| matches!(x, BssSecurity::Open | BssSecurity::Legacy);
        let other_secs: Vec<BssSecurity> = others.iter().filter_map(|o| o.security).collect();
        if let Some(other) = other_secs.iter().find(|o| **o != mine) {
            let (code, level) = if weak(mine) && !weak(*other) {
                ("evil-twin", "red")
            } else {
                ("other-security", "amber")
            };
            return Some(note(
                code,
                level,
                format!(
                    "same SSID as {} other access point(s), with {} instead of {}: evil twin?",
                    others.len(),
                    mine.as_str(),
                    other.as_str()
                ),
            ));
        }
        // The same name from another vendor (OUI), both with factory MACs.
        if !is_local(m) {
            let oui = |x: &Mac| [x[0], x[1], x[2]];
            let names_bssids = names.get(s.as_bytes())?;
            if names_bssids
                .iter()
                .any(|o| o != m && !is_local(o) && oui(o) != oui(m))
            {
                return Some(note(
                    "other-vendor",
                    "amber",
                    format!(
                        "same SSID, another vendor ({:02x}:{:02x}:{:02x}): a second access point of the network, or a twin",
                        m[0], m[1], m[2]
                    ),
                ));
            }
        }
        None
    }

    /// The table, for `interface.wifi.snooper.print`.
    pub fn snapshot(&self) -> Value {
        let names = self.by_name();
        // Stations under their network.
        let mut members: HashMap<Mac, Vec<(&Mac, &Sta)>> = HashMap::new();
        let mut alone: Vec<(&Mac, &Sta)> = Vec::new();
        for (m, st) in &self.sta {
            match st.bss.filter(|b| self.bss.contains_key(b)) {
                Some(b) => members.entry(b).or_default().push((m, st)),
                None => alone.push((m, st)),
            }
        }
        let mut nets: Vec<(&Mac, &Bss, u64)> = self
            .bss
            .iter()
            .map(|(m, b)| {
                let own = b.tx.airtime_us;
                let theirs: u64 = members
                    .get(m)
                    .map(|v| v.iter().map(|(_, s)| s.link().airtime_us).sum())
                    .unwrap_or(0);
                (m, b, own + theirs)
            })
            .collect();
        nets.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)));
        let networks: Vec<Value> = nets
            .iter()
            .take(MAX_NETWORKS_SHOWN)
            .map(|(m, b, airtime)| {
                let mut stations = members.get(*m).cloned().unwrap_or_default();
                stations.sort_by(|x, y| y.1.link().airtime_us.cmp(&x.1.link().airtime_us).then(x.0.cmp(y.0)));
                let count = stations.len();
                let mut notes = Vec::new();
                match (b.hidden, b.revealed) {
                    (true, Some((s, how))) => notes.push(note(
                        "hidden-revealed",
                        "amber",
                        format!("hidden network; a {how} gave its name away: '{}'", s.text()),
                    )),
                    (true, None) => notes.push(note("hidden", "neutral", "hidden network: the beacons carry no name".into())),
                    _ => {}
                }
                if let Some(n) = self.twin_note(m, b, &names) {
                    notes.push(n);
                }
                if b.broadcast_leave > 0 {
                    notes.push(note(
                        "broadcast-deauth",
                        "amber",
                        format!("deauth/disassoc to everyone ×{}", b.broadcast_leave),
                    ));
                }
                let retry_frames: u64 = stations.iter().map(|(_, s)| s.link().frames).sum::<u64>() + b.tx.frames;
                let retries: u64 = stations.iter().map(|(_, s)| s.link().retries).sum::<u64>() + b.tx.retries;
                json!({
                    "bssid": mac_text(m),
                    "ssid": self.ssid_of(m).map(|s| s.text()),
                    "hidden": b.hidden,
                    "frequency": b.freq,
                    "channel": ieee80211::channel_of(b.freq),
                    "band": ieee80211::band_of(b.freq),
                    "security": b.security.map(BssSecurity::as_str),
                    "signal": b.tx.signal(),
                    "airtime_pct": self.pct(*airtime, b.freq),
                    "frames": retry_frames,
                    "retry_pct": if retry_frames == 0 { 0.0 } else { (retries as f64 * 1000.0 / retry_frames as f64).round() / 10.0 },
                    "rate": b.tx.rate_text(),
                    "beacons": b.beacons,
                    "station_count": count,
                    "notes": notes,
                    "stations": stations.iter().take(MAX_STATIONS_SHOWN).map(|(m, s)| self.station_json(m, s)).collect::<Vec<_>>(),
                })
            })
            .collect();
        alone.sort_by(|x, y| y.1.tx.frames.cmp(&x.1.tx.frames).then(x.0.cmp(y.0)));
        let channels: Vec<Value> = self
            .chan
            .iter()
            .map(|(f, c)| {
                json!({
                    "frequency": f,
                    "channel": ieee80211::channel_of(*f),
                    "band": ieee80211::band_of(*f),
                    "frames": c.frames,
                    "dwell_ms": c.dwell_us / 1000,
                    "airtime_pct": self.pct(c.airtime_us, *f),
                    "noise": (c.noise_n > 0).then(|| c.noise_sum / i64::try_from(c.noise_n).unwrap_or(1)),
                    "networks": self.bss.values().filter(|b| b.freq == *f).count(),
                    "stations": self.sta.values().filter(|s| s.freq == *f).count(),
                })
            })
            .collect();
        json!({
            "networks": networks,
            "network_count": self.bss.len(),
            "unassociated": alone.iter().take(MAX_STATIONS_SHOWN).map(|(m, s)| self.station_json(m, s)).collect::<Vec<_>>(),
            "station_count": self.sta.len(),
            "channels": channels,
            "frames": self.frames,
            "bad_fcs": self.bad_fcs,
            "unparsed": self.unparsed,
            "overflow": self.overflow,
        })
    }
}

fn note(code: &str, level: &str, text: String) -> Value {
    json!({"code": code, "level": level, "text": text})
}

// ---------------------------------------------------------------------------
// The capture's filter.

/// Which frames go into the pcap file and the live list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiFilter {
    /// Only this network's frames.
    pub bssid: Option<Mac>,
    /// Only the networks of this name (known from their beacons).
    pub ssid: Option<String>,
    /// Frames to or from this address (any of the three).
    pub mac: Option<Mac>,
    /// Frame types kept; all three `false` = all.
    pub mgmt: bool,
    pub control: bool,
    pub data: bool,
    /// Only what Wireshark needs to decrypt: the EAPOL frames and one
    /// beacon or probe response per network (for its name).
    pub eapol: bool,
}

impl WifiFilter {
    fn kind_ok(&self, k: Kind) -> bool {
        if !(self.mgmt || self.control || self.data) {
            return true;
        }
        match k {
            Kind::Mgmt => self.mgmt,
            Kind::Control => self.control,
            Kind::Data => self.data,
            Kind::Extension => false,
        }
    }

    /// Does `h` pass? `named` gives a network's name; `announced` holds
    /// the networks whose beacon is in the file already (EAPOL mode).
    fn keeps(&self, h: &Heard, named: impl Fn(&Mac) -> Option<Ssid>, announced: &mut HashSet<Mac>) -> bool {
        let addrs = [Some(h.ra), h.ta, h.addr3];
        if let Some(b) = self.bssid
            && h.bssid != Some(b)
            && !addrs.contains(&Some(b))
        {
            return false;
        }
        if let Some(m) = self.mac
            && !addrs.contains(&Some(m))
        {
            return false;
        }
        if let Some(want) = &self.ssid {
            let by_bss = h.bssid.and_then(|b| named(&b)).is_some_and(|s| s.as_bytes() == want.as_bytes());
            let by_probe = matches!(h.info, Info::ProbeReq(Some(s)) if s.as_bytes() == want.as_bytes());
            if !by_bss && !by_probe {
                return false;
            }
        }
        if self.eapol {
            return match h.info {
                Info::EapolKey(_) | Info::Eapol => true,
                Info::Announce { .. } => h.bssid.is_some_and(|b| announced.insert(b)),
                _ => false,
            };
        }
        self.kind_ok(h.kind)
    }
}

/// One frame of the live list.
#[derive(Debug, Clone, Copy)]
pub struct Recent {
    pub seq: u64,
    /// Since the capture started.
    pub at: Duration,
    pub len: u32,
    pub heard: Heard,
}

impl Recent {
    pub fn json(&self) -> Value {
        let h = &self.heard;
        let info = match h.info {
            Info::Announce { elements, security, .. } => {
                let name = elements.ssid.map(|s| if s.is_hidden() { "(hidden)".to_owned() } else { s.text() });
                format!("{} {}", name.unwrap_or_default(), security.as_str())
            }
            Info::ProbeReq(Some(s)) | Info::AssocReq(Some(s)) => format!("'{}'", s.text()),
            Info::ProbeReq(None) => "any network".into(),
            Info::AssocReq(None) => String::new(),
            Info::Auth { seq, status, .. } => format!("seq {seq}, status {status}"),
            Info::Leave { reason: Some(r), .. } => format!("reason {r}: {}", ieee80211::reason_text(r)),
            Info::Leave { reason: None, .. } => "reason ciphered".into(),
            Info::EapolKey(Some(m)) => format!("EAPOL-Key message {m}/4"),
            Info::EapolKey(None) => "EAPOL-Key group".into(),
            Info::Eapol => "EAPOL".into(),
            Info::Other => String::new(),
        };
        json!({
            "seq": self.seq,
            "t_ms": u64::try_from(self.at.as_millis()).unwrap_or(u64::MAX),
            "frequency": h.freq,
            "channel": ieee80211::channel_of(h.freq),
            "kind": h.kind.as_str(),
            "type": h.type_name,
            "ta": h.ta.as_ref().map(mac_text),
            "ra": mac_text(&h.ra),
            "bssid": h.bssid.as_ref().map(mac_text),
            "signal": h.signal,
            "rate_mbps": h.kbps.map(|k| (f64::from(k) / 100.0).round() / 10.0),
            "retry": h.retry,
            "protected": h.protected,
            "length": h.len,
            "info": info,
        })
    }
}

/// What the job shares with the commands.
#[derive(Debug, Default)]
pub struct SnoopState {
    /// The last [`Snooper::snapshot`], with the channel now.
    pub table: Value,
    pub recent: VecDeque<Recent>,
    pub file: Vec<u8>,
    /// The monitor interface and the channel it is on.
    pub monitor: String,
    pub channel: Option<u32>,
}

pub type Shared = Arc<Mutex<SnoopState>>;

/// The capture side of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub filter: WifiFilter,
    /// The file stops growing here (bytes, header included).
    pub limit: usize,
}

pub struct SnoopJob {
    pub spec: MonitorSpec,
    /// Channels to go round, MHz (empty: stay).
    pub hop: Vec<u32>,
    pub channel_time: Duration,
    pub duration: Duration,
    /// `None`: the snooper only.
    pub capture: Option<Capture>,
    pub start_unix: Option<u64>,
    pub shared: Shared,
    /// Set by the engine when an exclusive monitor's radio goes back to
    /// its network (the interface enabled again: by hand, or by Safe Mode
    /// undoing the disable).
    pub abort: Arc<AtomicBool>,
}

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, SnoopState> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run until the duration or a stop.
pub fn run(job: SnoopJob, monitor: SharedWifiMonitor, ctx: &TaskCtx) -> Result<(), String> {
    let mut sock = monitor.open(&job.spec).map_err(|e| e.to_string())?;
    let mut snoop = Snooper::default();
    let mut tuned = sock.channel().or(job.spec.freq_mhz).unwrap_or(0);
    let pcap = job.capture.is_some();
    {
        let mut st = lock(&job.shared);
        st.file.clear();
        if pcap {
            st.file.extend_from_slice(&pcap_header_for(SNAPLEN, LINKTYPE_IEEE802_11_RADIOTAP));
        }
        st.monitor = sock.interface();
        st.channel = Some(tuned).filter(|c| *c != 0);
    }
    let base = Duration::from_secs(job.start_unix.unwrap_or(0));
    let mut batch = FrameBatch::new(BATCH);
    let start = ctx.now();
    let mut next = start.saturating_add(Duration::from_secs(1));
    let mut on_channel_since = start;
    let mut hop_at = start.saturating_add(job.channel_time);
    let mut hop_i = job.hop.iter().position(|f| *f == tuned).unwrap_or(0);
    let mut hopping = job.spec.mode == MonitorMode::Exclusive && job.hop.len() > 1;
    let mut note: Option<String> = None;
    let (mut kept, mut skipped, mut seq) = (0u64, 0u64, 0u64);
    let mut announced = HashSet::new();
    let mut record = Vec::new();
    let limit = job.capture.as_ref().map_or(0, |c| c.limit);
    let summary = |snoop: &Snooper, kept: u64, skipped: u64, size: usize, channel: u32, hopping: bool, note: &Option<String>, end: Option<&str>| {
        json!({
            "radio": job.spec.radio,
            "mode": job.spec.mode.as_str(),
            "channel": channel,
            "hopping": hopping,
            "frames": snoop.frames,
            "networks": snoop.bss.len(),
            "stations": snoop.sta.len(),
            "kept": kept,
            "file_size": size,
            "limit": limit,
            "dropped_by_limit": skipped,
            "bad_fcs": snoop.bad_fcs,
            "duration_s": job.duration.as_secs(),
            "note": note,
            "end": end,
        })
    };
    loop {
        let now = ctx.now();
        let end = if ctx.stopped() {
            Some("stopped")
        } else if job.abort.load(Ordering::Relaxed) {
            Some("the radio went back to its network")
        } else if now.saturating_sub(start) >= job.duration {
            Some("duration reached")
        } else {
            None
        };
        // Time on the channel, and a hop when it is due.
        if end.is_some() || (hopping && now >= hop_at) || now >= next {
            let us = u64::try_from(now.saturating_sub(on_channel_since).as_micros()).unwrap_or(0);
            snoop.dwell(tuned, us);
            on_channel_since = now;
        }
        if end.is_none() && hopping && now >= hop_at {
            hop_i = (hop_i + 1) % job.hop.len().max(1);
            let want = job.hop.get(hop_i).copied().unwrap_or(tuned);
            match sock.set_channel(want) {
                Ok(()) => tuned = want,
                Err(e) => {
                    // The station came back up (Safe Mode undid the
                    // disable): the monitor follows it now.
                    hopping = false;
                    note = Some(format!("stopped hopping: {e}"));
                    tuned = sock.channel().unwrap_or(tuned);
                }
            }
            hop_at = now.saturating_add(job.channel_time);
        }
        if end.is_some() || now >= next {
            if !hopping && let Some(c) = sock.channel() {
                tuned = c;
            }
            let mut table = snoop.snapshot();
            if let Value::Object(o) = &mut table {
                o.insert("channel".into(), json!(tuned));
                o.insert("hopping".into(), json!(hopping));
                o.insert("seconds".into(), json!(now.saturating_sub(start).as_secs()));
            }
            let size = {
                let mut st = lock(&job.shared);
                st.table = table;
                st.channel = Some(tuned);
                st.file.len()
            };
            if end.is_none() {
                next = next.saturating_add(Duration::from_secs(1)).max(now);
                ctx.emit(json!({
                    "t": now.saturating_sub(start).as_secs(),
                    "frames": snoop.frames,
                    "kept": kept,
                    "file_size": size,
                    "channel": tuned,
                }));
            }
            ctx.summary(summary(&snoop, kept, skipped, size, tuned, hopping, &note, end));
            if end.is_some() {
                return Ok(());
            }
        }
        let mut wait = next.saturating_sub(now).min(MAX_WAIT);
        if hopping {
            wait = wait.min(hop_at.saturating_sub(now));
        }
        batch.clear();
        sock.recv(wait, &mut batch).map_err(|e| e.to_string())?;
        if !batch.is_empty() {
            let mut st = if pcap { Some(lock(&job.shared)) } else { None };
            for (meta, data) in batch.iter() {
                let at_us = u64::try_from(meta.at.as_micros()).unwrap_or(u64::MAX);
                let Some(heard) = snoop.add(at_us, data, tuned) else {
                    continue;
                };
                let (Some(cap), Some(st)) = (job.capture.as_ref(), st.as_mut()) else {
                    continue;
                };
                if !cap.filter.keeps(&heard, |b| snoop.ssid_of(b), &mut announced) {
                    continue;
                }
                if st.file.len() + PCAP_RECORD_HEADER_LEN + data.len() > cap.limit {
                    skipped += 1;
                } else {
                    record.clear();
                    pcap_record(&mut record, base.saturating_add(meta.at), data, meta.wire_len);
                    st.file.extend_from_slice(&record);
                    kept += 1;
                }
                seq += 1;
                if st.recent.len() >= MAX_RECENT {
                    st.recent.pop_front();
                }
                st.recent.push_back(Recent {
                    seq,
                    at: meta.at,
                    len: meta.wire_len,
                    heard,
                });
            }
        }
        if !sock.blocks() {
            let spent = ctx.now().saturating_sub(now);
            if spent < wait && !ctx.sleep(wait.saturating_sub(spent)) {
                // Stopped while sleeping: the next turn ends it.
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use corerouter_hal::lab_wifi::LabWifi;
    use corerouter_hal::lab_wifi_air::{LabMonitor, TWIN_BSSID};
    use corerouter_hal::capture::PCAP_HEADER_LEN;
    use std::sync::atomic::AtomicU64;

    struct FakeClock(AtomicU64);

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            Duration::from_micros(self.0.load(Ordering::Relaxed))
        }
        fn sleep(&self, d: Duration) {
            self.0.fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        }
    }

    fn monitor() -> SharedWifiMonitor {
        let w = LabWifi::default();
        w.add_radio("wifi1".parse().unwrap());
        Arc::new(LabMonitor::new(w))
    }

    fn job(freq: u32, hop: Vec<u32>, secs: u64, capture: Option<Capture>) -> (SnoopJob, Shared) {
        let shared: Shared = Arc::default();
        (
            SnoopJob {
                spec: MonitorSpec {
                    radio: "wifi1".into(),
                    mode: MonitorMode::Exclusive,
                    freq_mhz: Some(freq),
                    width_mhz: 20,
                },
                hop,
                channel_time: Duration::from_millis(200),
                duration: Duration::from_secs(secs),
                capture,
                start_unix: Some(1_700_000_000),
                shared: Arc::clone(&shared),
                abort: Arc::default(),
            },
            shared,
        )
    }

    fn run_job(j: SnoopJob) -> Value {
        let cell = TaskCell::for_test();
        let clock = FakeClock(AtomicU64::new(0));
        run(j, monitor(), &TaskCtx::new(&cell, &clock)).unwrap();
        cell.snapshot().1
    }

    fn network<'a>(t: &'a Value, bssid: &str) -> &'a Value {
        t["networks"].as_array().unwrap().iter().find(|n| n["bssid"] == bssid).unwrap()
    }

    fn station<'a>(n: &'a Value, mac: &str) -> &'a Value {
        n["stations"].as_array().unwrap().iter().find(|s| s["mac"] == mac).unwrap()
    }

    fn codes(v: &Value) -> Vec<&str> {
        v["notes"].as_array().unwrap().iter().map(|n| n["code"].as_str().unwrap()).collect()
    }

    #[test]
    fn the_snooper_reads_the_lab_network() {
        let (j, shared) = job(5220, vec![], 21, None);
        let summary = run_job(j);
        assert_eq!(summary["end"], "duration reached");
        let t = lock(&shared).table.clone();
        let lab = network(&t, "02:c0:fe:00:00:01");
        assert_eq!(lab["ssid"], "CoreRouter-Lab");
        assert_eq!(lab["security"], "wpa2-wpa3");
        assert_eq!(lab["channel"], 44);
        // The laptop has most of the airtime, the printer is far and slow.
        let laptop = station(lab, "02:5e:10:00:00:11");
        let printer = station(lab, "02:5e:10:00:00:13");
        assert_eq!(lab["stations"][0]["mac"], "02:5e:10:00:00:11", "{lab}");
        assert!(laptop["rate"].as_str().unwrap().contains("HE MCS9 2SS 80MHz"), "{laptop}");
        assert!(codes(laptop).is_empty(), "{laptop}");
        assert!(codes(printer).contains(&"far-slow"), "{printer}");
        assert!(printer["retry_pct"].as_f64().unwrap() > 30.0);
        // The TV was thrown out and came back: deauth with the reason, and
        // the whole handshake.
        let tv = station(lab, "02:5e:10:00:00:14");
        assert_eq!(tv["deauth"], 6);
        assert!(tv["reason"].as_str().unwrap().starts_with("reason 7"), "{tv}");
        assert_eq!(tv["handshake"], 4);
        assert!(codes(tv).contains(&"deauth") && codes(tv).contains(&"handshake"));
        // The twin: the lab's name, open.
        let twin = network(&t, &mac_text(&TWIN_BSSID));
        assert!(codes(twin).contains(&"evil-twin"), "{twin}");
        assert!(codes(lab).contains(&"other-security"), "{lab}");
        let pct = lab["airtime_pct"].as_f64().unwrap();
        assert!(pct > 1.0 && pct < 100.0, "{pct}");
        let ch = &t["channels"][0];
        assert_eq!(ch["frequency"], 5220);
        assert!(ch["dwell_ms"].as_u64().unwrap() >= 20_000, "{ch}");
    }

    #[test]
    fn hopping_finds_the_hidden_name() {
        let (j, shared) = job(5180, vec![5180, 5220, 2412], 12, None);
        let summary = run_job(j);
        assert_eq!(summary["hopping"], true);
        let t = lock(&shared).table.clone();
        let hidden = network(&t, "02:c0:fe:00:00:06");
        assert_eq!(hidden["ssid"], "Oculta");
        assert_eq!(hidden["hidden"], true);
        assert!(codes(hidden).contains(&"hidden-revealed"), "{hidden}");
        let freqs: Vec<u64> = t["channels"].as_array().unwrap().iter().map(|c| c["frequency"].as_u64().unwrap()).collect();
        assert_eq!(freqs, vec![2412, 5180, 5220]);
        // Each got about a third of the time.
        for c in t["channels"].as_array().unwrap() {
            let d = c["dwell_ms"].as_u64().unwrap();
            assert!((3_000..=5_000).contains(&d), "{c}");
        }
    }

    /// The records of a pcap file: (count, every one a radiotap frame).
    fn records(f: &[u8]) -> Vec<Vec<u8>> {
        assert_eq!(&f[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(u32::from_le_bytes(f[20..24].try_into().unwrap()), 127);
        let mut at = PCAP_HEADER_LEN;
        let mut out = Vec::new();
        while at < f.len() {
            let incl = u32::from_le_bytes(f[at + 8..at + 12].try_into().unwrap()) as usize;
            out.push(f[at + 16..at + 16 + incl].to_vec());
            at += 16 + incl;
        }
        assert_eq!(at, f.len());
        out
    }

    #[test]
    fn the_capture_keeps_what_the_filter_asks() {
        let cap = Capture {
            filter: WifiFilter {
                mac: Some([2, 0x5e, 0x10, 0, 0, 0x14]),
                mgmt: true,
                ..WifiFilter::default()
            },
            limit: 16 << 20,
        };
        let (j, shared) = job(5220, vec![], 5, Some(cap));
        let summary = run_job(j);
        let st = lock(&shared);
        let recs = records(&st.file);
        assert_eq!(recs.len() as u64, summary["kept"].as_u64().unwrap());
        // The TV's management frames: 6 deauth, 2 auth, assoc req/resp.
        assert_eq!(recs.len(), 10, "{summary}");
        for r in &recs {
            let rt = ieee80211::radiotap(r).unwrap();
            let f = ieee80211::frame(&r[rt.len..], 0).unwrap();
            assert_eq!(f.kind, Kind::Mgmt);
        }
        assert_eq!(st.recent.len(), 10);
        assert!(st.recent.iter().any(|r| r.json()["info"].as_str().unwrap().contains("reason 7")));
    }

    #[test]
    fn eapol_mode_keeps_the_handshake_and_one_beacon_per_network() {
        let cap = Capture {
            filter: WifiFilter {
                eapol: true,
                ..WifiFilter::default()
            },
            limit: 16 << 20,
        };
        let (j, shared) = job(5220, vec![], 5, Some(cap));
        run_job(j);
        let st = lock(&shared);
        let recs = records(&st.file);
        let mut eapol = 0;
        let mut beacons = 0;
        for r in &recs {
            let rt = ieee80211::radiotap(r).unwrap();
            let f = ieee80211::frame(&r[rt.len..], 0).unwrap();
            match ieee80211::info(&f) {
                Info::EapolKey(Some(_)) => eapol += 1,
                Info::Announce { .. } => beacons += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((eapol, beacons), (4, 2));
    }

    #[test]
    fn the_file_stops_at_its_limit_and_the_table_goes_on() {
        let cap = Capture {
            filter: WifiFilter::default(),
            limit: 50_000,
        };
        let (j, shared) = job(5220, vec![], 3, Some(cap));
        let summary = run_job(j);
        assert!(summary["dropped_by_limit"].as_u64().unwrap() > 0);
        assert_eq!(summary["end"], "duration reached");
        let st = lock(&shared);
        assert!(st.file.len() <= 50_000);
        records(&st.file);
        assert!(summary["frames"].as_u64().unwrap() > 1000);
    }

    #[test]
    fn hostile_frames_are_counted_not_kept() {
        let mut s = Snooper::default();
        assert!(s.add(0, &[1, 2, 3], 5180).is_none());
        assert!(s.add(0, &[0, 0, 8, 0, 0, 0, 0, 0], 5180).is_none());
        // A frame whose card says the FCS was wrong.
        let mut d = Vec::new();
        ieee80211::build_radiotap(&mut d, &ieee80211::RadioSpec { flags: ieee80211::RT_FLAG_BAD_FCS, freq_mhz: 5180, ..Default::default() });
        d.extend_from_slice(&[0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(s.add(0, &d, 5180).is_none());
        assert_eq!((s.frames, s.unparsed, s.bad_fcs), (3, 2, 1));
        // Past the bound, new stations are counted, not kept.
        for i in 0..(MAX_STATIONS as u32 + 10) {
            let m = i.to_be_bytes();
            let sta = [2, 0, m[0], m[1], m[2], m[3]];
            let mut d = Vec::new();
            ieee80211::build_radiotap(&mut d, &ieee80211::RadioSpec { freq_mhz: 5180, rate_500k: 12, ..Default::default() });
            d.extend_from_slice(&[0x40, 0, 0, 0]);
            d.extend_from_slice(&[0xff; 6]);
            d.extend_from_slice(&sta);
            d.extend_from_slice(&[0xff; 6]);
            d.extend_from_slice(&[0, 0]);
            s.add(0, &d, 5180);
        }
        assert_eq!(s.sta.len(), MAX_STATIONS);
        assert_eq!(s.overflow, 10);
        let t = s.snapshot();
        assert!(t["unassociated"].as_array().unwrap().len() <= MAX_STATIONS_SHOWN);
    }
}

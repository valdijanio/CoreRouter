//! The virtual lab's air, frame by frame (G1.30j): what a monitor on a
//! lab radio hears. Radiotap headers and 802.11 frames built as a card
//! would hand them over, so the engine's snooper and capture run the same
//! parsers as on a real radio, and the windows and tests have something to
//! show without a card.
//!
//! On each channel: the beacons of the lab's networks
//! ([`crate::lab_wifi::default_networks`]) ten times a second, and a few
//! made-up stations, each a case the snooper must notice:
//! - a laptop on Wi-Fi 6 at 2×2, few retries, most of the airtime;
//! - a phone on Wi-Fi 5;
//! - a printer far away at 6 Mbit/s with 45 % retries ("far, slow");
//! - a TV the access point throws out every 20 s (deauthentication, reason
//!   7), which comes back with the whole join: authentication,
//!   association and the 4-way handshake in EAPOL;
//! - a station that asks for the hidden network by name every 5 s, and
//!   gets a probe response that gives the name away;
//! - an open access point named like the lab's own network, with another
//!   security (an "evil twin");
//! - stations of the neighbours' networks on 2.4 GHz.
//!
//! Deterministic: the same waits give the same frames. Time is simulated
//! (the sum of the waits), like `capture::SimCapture`.

use std::time::Duration;

use corerouter_model::IfName;

use crate::capture::{CaptureError, Dir, FrameBatch};
use crate::ieee80211::{BROADCAST, Mac, Phy, RadioSpec, build_radiotap};
use crate::lab_wifi::LabWifi;
use crate::wifi::BssSecurity;
use crate::wifi_monitor::{MonitorMode, MonitorSocket, MonitorSpec, WifiMonitor, monitor_name};

/// Where a lab monitor starts when its radio is on no network.
const DEFAULT_FREQ: u32 = 5220;
/// The twin's BSSID: another vendor, the lab network's name, no security.
pub const TWIN_BSSID: Mac = [0x3c, 0x77, 0xe6, 0x00, 0x00, 0x99];

/// Monitors on the lab's radios.
#[derive(Debug, Clone)]
pub struct LabMonitor {
    wifi: LabWifi,
}

impl LabMonitor {
    pub fn new(wifi: LabWifi) -> Self {
        Self { wifi }
    }
}

fn mac(s: &str) -> Mac {
    crate::ieee80211::parse_mac(s).unwrap_or([2, 0, 0, 0, 0, 0])
}

struct Ap {
    bssid: Mac,
    ssid: String,
    hidden: bool,
    freq: u32,
    signal: i8,
    security: BssSecurity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Act {
    Normal,
    /// Thrown out every 20 s, and back.
    Kicked,
    /// Asks for the hidden network every 5 s.
    Prober,
}

struct Sta {
    mac: Mac,
    bssid: Mac,
    signal: i8,
    radio: RadioSpec,
    /// Data frames per second, from the access point and to it.
    down_pps: f64,
    up_pps: f64,
    size: usize,
    retry_pct: u64,
    act: Act,
}

fn spec(phy: Phy, rate_500k: u8, mcs: u8, nss: u8, width: u16) -> RadioSpec {
    RadioSpec {
        phy,
        rate_500k,
        mcs,
        nss,
        width_mhz: width,
        noise_dbm: -95,
        ..RadioSpec::default()
    }
}

/// The made-up stations (their access points are the lab's networks).
fn stations() -> Vec<Sta> {
    let lab5 = mac("02:c0:fe:00:00:01");
    let sta = |m: &str,
               bssid: Mac,
               signal: i8,
               radio: RadioSpec,
               down: f64,
               up: f64,
               size: usize,
               retry: u64,
               act: Act| Sta {
        mac: mac(m),
        bssid,
        signal,
        radio,
        down_pps: down,
        up_pps: up,
        size,
        retry_pct: retry,
        act,
    };
    vec![
        sta(
            "02:5e:10:00:00:11",
            lab5,
            -47,
            spec(Phy::He, 0, 9, 2, 80),
            120.0,
            40.0,
            1200,
            2,
            Act::Normal,
        ),
        sta(
            "02:5e:10:00:00:12",
            lab5,
            -63,
            spec(Phy::Vht, 0, 7, 1, 80),
            30.0,
            10.0,
            900,
            6,
            Act::Normal,
        ),
        sta(
            "02:5e:10:00:00:13",
            lab5,
            -84,
            spec(Phy::Legacy, 12, 0, 1, 20),
            12.0,
            6.0,
            300,
            45,
            Act::Normal,
        ),
        sta(
            "02:5e:10:00:00:14",
            lab5,
            -70,
            spec(Phy::Ht, 0, 5, 1, 20),
            20.0,
            8.0,
            700,
            10,
            Act::Kicked,
        ),
        sta(
            "02:5e:10:00:00:15",
            mac("02:c0:fe:00:00:02"),
            -75,
            spec(Phy::Legacy, 2, 0, 1, 20),
            4.0,
            4.0,
            120,
            15,
            Act::Normal,
        ),
        sta(
            "02:5e:10:00:00:21",
            mac("02:c0:fe:00:00:06"),
            -66,
            spec(Phy::Vht, 0, 4, 1, 40),
            10.0,
            5.0,
            600,
            4,
            Act::Prober,
        ),
        sta(
            "02:5e:10:00:00:31",
            mac("02:c0:fe:00:00:04"),
            -80,
            spec(Phy::Ht, 0, 7, 1, 20),
            15.0,
            6.0,
            800,
            20,
            Act::Normal,
        ),
        sta(
            "02:5e:10:00:00:41",
            mac("02:c0:fe:00:00:05"),
            -72,
            spec(Phy::Ht, 0, 3, 1, 20),
            10.0,
            4.0,
            500,
            8,
            Act::Normal,
        ),
    ]
}

impl WifiMonitor for LabMonitor {
    fn describe(&self) -> String {
        "the lab's air (synthetic radiotap frames)".into()
    }

    fn open(&self, spec: &MonitorSpec) -> Result<Box<dyn MonitorSocket>, CaptureError> {
        let name: IfName = spec
            .radio
            .parse()
            .map_err(|e| CaptureError::NoDevice(format!("'{}': {e}", spec.radio)))?;
        if !self.wifi.has_radio(&name) {
            return Err(CaptureError::NoDevice(format!(
                "no Wi-Fi radio '{name}' in the lab"
            )));
        }
        let freq = match spec.mode {
            MonitorMode::Exclusive => spec.freq_mhz.unwrap_or(DEFAULT_FREQ),
            MonitorMode::Shared => self.wifi.frequency(&name).unwrap_or(DEFAULT_FREQ),
        };
        let mut aps: Vec<Ap> = self
            .wifi
            .networks()
            .into_iter()
            .map(|n| Ap {
                bssid: mac(&n.bssid),
                ssid: n.ssid,
                hidden: n.hidden,
                freq: n.frequency_mhz,
                signal: i8::try_from(n.signal_dbm).unwrap_or(-90),
                security: n.security,
            })
            .collect();
        aps.push(Ap {
            bssid: TWIN_BSSID,
            ssid: "CoreRouter-Lab".into(),
            hidden: false,
            freq: 5220,
            signal: -71,
            security: BssSecurity::Open,
        });
        let stations = stations();
        let due = vec![false; stations.len()];
        let owed = vec![0.0; stations.len() * 2 + aps.len()];
        Ok(Box::new(LabSocket {
            radio: spec.radio.clone(),
            mode: spec.mode,
            freq,
            t: Duration::ZERO,
            aps,
            stations,
            owed,
            counter: 0,
            frame: Vec::new(),
            due,
        }))
    }
}

struct LabSocket {
    radio: String,
    mode: MonitorMode,
    freq: u32,
    t: Duration,
    aps: Vec<Ap>,
    stations: Vec<Sta>,
    /// Fractional frames each source still owes.
    owed: Vec<f64>,
    counter: u64,
    frame: Vec<u8>,
    /// A station's kick or probe that is due: it happens on its network's
    /// channel, when the monitor is there (a station probes on every
    /// channel; only its access point's answer counts here).
    due: Vec<bool>,
}

/// Times a `period` boundary falls in `[from, to)`.
fn ticks(from: Duration, to: Duration, period: Duration) -> u64 {
    let p = period.as_micros().max(1);
    let n = |t: Duration| t.as_micros() / p;
    u64::try_from(n(to).saturating_sub(n(from))).unwrap_or(0)
}

fn channel_of(freq: u32) -> u8 {
    crate::ieee80211::channel_of(freq)
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(0)
}

/// An RSN element for `sec` (version 1, CCMP).
fn rsne(out: &mut Vec<u8>, sec: BssSecurity) {
    let akms: &[u8] = match sec {
        BssSecurity::Wpa2 => &[2],
        BssSecurity::Wpa3 => &[8],
        BssSecurity::Wpa2Wpa3 => &[2, 8],
        BssSecurity::Enterprise => &[1],
        BssSecurity::Owe => &[18],
        BssSecurity::Open | BssSecurity::Legacy => return,
    };
    let mut r = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4];
    r.extend_from_slice(&u16::try_from(akms.len()).unwrap_or(0).to_le_bytes());
    for a in akms {
        r.extend_from_slice(&[0x00, 0x0f, 0xac, *a]);
    }
    r.extend_from_slice(&[0, 0]);
    out.push(48);
    out.push(u8::try_from(r.len()).unwrap_or(0));
    out.extend_from_slice(&r);
}

fn ssid_ie(out: &mut Vec<u8>, ssid: &[u8]) {
    let s = ssid.get(..ssid.len().min(32)).unwrap_or(&[]);
    out.push(0);
    out.push(u8::try_from(s.len()).unwrap_or(0));
    out.extend_from_slice(s);
}

impl LabSocket {
    fn jitter(&mut self) -> i8 {
        self.counter = self.counter.wrapping_add(1);
        i8::try_from(self.counter.wrapping_mul(7919) % 7).unwrap_or(0) - 3
    }

    fn seq(&self) -> [u8; 2] {
        u16::try_from((self.counter % 4096) << 4)
            .unwrap_or(0)
            .to_le_bytes()
    }

    /// Start a frame: the radiotap header, then Frame Control, duration
    /// and the three addresses (and the sequence number).
    fn head(&mut self, radio: RadioSpec, signal: i8, fc: [u8; 2], a: [Mac; 3]) {
        let jitter = self.jitter();
        let r = RadioSpec {
            freq_mhz: u16::try_from(self.freq).unwrap_or(0),
            signal_dbm: signal.saturating_add(jitter),
            noise_dbm: -95,
            ..radio
        };
        self.frame.clear();
        build_radiotap(&mut self.frame, &r);
        self.frame.extend_from_slice(&fc);
        self.frame.extend_from_slice(&[0x2c, 0x00]);
        for m in a {
            self.frame.extend_from_slice(&m);
        }
        let seq = self.seq();
        self.frame.extend_from_slice(&seq);
    }

    fn basic_rate(&self) -> RadioSpec {
        // Management and control frames go at a basic rate: 1 Mbit/s on
        // 2.4 GHz, 6 on 5 GHz.
        spec(
            Phy::Legacy,
            if self.freq >= 4900 { 12 } else { 2 },
            0,
            1,
            20,
        )
    }

    fn push(&self, batch: &mut FrameBatch, at: Duration) {
        let len = u32::try_from(self.frame.len()).unwrap_or(u32::MAX);
        batch.push(at, Dir::Rx, None, len, &self.frame);
    }

    fn announce(&mut self, batch: &mut FrameBatch, at: Duration, ap: usize, to: Option<Mac>) {
        let Some(a) = self.aps.get(ap) else { return };
        let (bssid, signal, security, hidden) = (a.bssid, a.signal, a.security, a.hidden);
        let ssid = a.ssid.clone().into_bytes();
        let radio = self.basic_rate();
        let fc = if to.is_some() { [0x50, 0] } else { [0x80, 0] };
        self.head(radio, signal, fc, [to.unwrap_or(BROADCAST), bssid, bssid]);
        self.frame.extend_from_slice(&[0; 8]);
        self.frame.extend_from_slice(&100u16.to_le_bytes());
        let cap: u16 = if security == BssSecurity::Open {
            0x0001
        } else {
            0x0011
        };
        self.frame.extend_from_slice(&cap.to_le_bytes());
        // A hidden network's beacons carry no name; its probe responses do.
        ssid_ie(
            &mut self.frame,
            if hidden && to.is_none() { &[] } else { &ssid },
        );
        let ch = channel_of(self.freq);
        self.frame.extend_from_slice(&[3, 1, ch]);
        rsne(&mut self.frame, security);
        self.push(batch, at);
    }

    fn ap_index(&self, bssid: Mac) -> Option<usize> {
        self.aps.iter().position(|a| a.bssid == bssid)
    }

    fn ack(&mut self, batch: &mut FrameBatch, at: Duration, to: Mac, signal: i8) {
        let jitter = self.jitter();
        let r = RadioSpec {
            freq_mhz: u16::try_from(self.freq).unwrap_or(0),
            signal_dbm: signal.saturating_add(jitter),
            ..self.basic_rate()
        };
        self.frame.clear();
        build_radiotap(&mut self.frame, &r);
        self.frame.extend_from_slice(&[0xd4, 0x00, 0, 0]);
        self.frame.extend_from_slice(&to);
        self.push(batch, at);
    }

    /// A QoS data frame of station `i`, down (from the access point) or
    /// up; protected unless the network is open.
    fn data(&mut self, batch: &mut FrameBatch, at: Duration, i: usize, down: bool) {
        let Some(s) = self.stations.get(i) else {
            return;
        };
        let (m, bssid, radio, size, retry_pct) = (s.mac, s.bssid, s.radio, s.size, s.retry_pct);
        let ap = self.ap_index(bssid);
        let (ap_signal, open) = ap.and_then(|a| self.aps.get(a)).map_or((-60, false), |a| {
            (a.signal, a.security == BssSecurity::Open)
        });
        let signal = if down { ap_signal } else { s.signal };
        let retry = self.counter.wrapping_mul(37) % 100 < retry_pct;
        let mut flags = if down { 0x02 } else { 0x01 };
        if retry {
            flags |= 0x08;
        }
        if !open {
            flags |= 0x40;
        }
        let addrs = if down {
            [m, bssid, bssid]
        } else {
            [bssid, m, bssid]
        };
        self.head(radio, signal, [0x88, flags], addrs);
        self.frame.extend_from_slice(&[0x00, 0x00]);
        let body = size.saturating_sub(self.frame.len()).max(16);
        if open {
            // In the clear: LLC/SNAP, then an IPv4/UDP header to port 443.
            let ip_len = u16::try_from(body.saturating_sub(8)).unwrap_or(0);
            self.frame
                .extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
            self.frame.extend_from_slice(&[
                0x45,
                0,
                (ip_len >> 8) as u8,
                ip_len as u8,
                0,
                0,
                0x40,
                0,
                64,
                17,
                0,
                0,
            ]);
            self.frame.extend_from_slice(&[192, 168, 5, 41, 1, 1, 1, 1]);
            self.frame.extend_from_slice(&[0xc3, 0x50, 0x01, 0xbb]);
            let udp_len = ip_len.saturating_sub(20);
            self.frame
                .extend_from_slice(&[(udp_len >> 8) as u8, udp_len as u8, 0, 0]);
            self.frame
                .extend(std::iter::repeat_n(0u8, body.saturating_sub(36)));
        } else {
            // CCMP: the 8-byte header, then ciphertext and the MIC.
            let fill = (self.counter % 251) as u8;
            self.frame.extend(std::iter::repeat_n(fill, body));
        }
        self.push(batch, at);
        // The receiver acknowledges it, with its own signal.
        let (to, ack_signal) = if down {
            (bssid, s_signal(&self.stations, i))
        } else {
            (m, ap_signal)
        };
        self.ack(batch, at, to, ack_signal);
    }

    fn mgmt(
        &mut self,
        batch: &mut FrameBatch,
        at: Duration,
        subtype: u8,
        from_sta: bool,
        i: usize,
        body: &[u8],
    ) {
        let Some(s) = self.stations.get(i) else {
            return;
        };
        let (m, bssid, sig) = (s.mac, s.bssid, s.signal);
        let ap_signal = self
            .ap_index(bssid)
            .and_then(|a| self.aps.get(a))
            .map_or(-60, |a| a.signal);
        let radio = self.basic_rate();
        let fc = [subtype << 4, 0];
        let (signal, addrs) = if from_sta {
            (sig, [bssid, m, bssid])
        } else {
            (ap_signal, [m, bssid, bssid])
        };
        self.head(radio, signal, fc, addrs);
        self.frame.extend_from_slice(body);
        self.push(batch, at);
    }

    /// One message of the 4-way handshake (unprotected QoS data).
    fn eapol(&mut self, batch: &mut FrameBatch, at: Duration, i: usize, msg: u16) {
        let Some(s) = self.stations.get(i) else {
            return;
        };
        let (m, bssid, radio, sig) = (s.mac, s.bssid, s.radio, s.signal);
        let from_ap = msg % 2 == 1;
        let (flags, addrs) = if from_ap {
            (0x02, [m, bssid, bssid])
        } else {
            (0x01, [bssid, m, bssid])
        };
        self.head(radio, sig, [0x88, flags], addrs);
        self.frame.extend_from_slice(&[0x07, 0x00]);
        self.frame
            .extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]);
        let ki: u16 = match msg {
            1 => 0x008a,
            2 => 0x010a,
            3 => 0x13ca,
            _ => 0x030a,
        };
        self.frame.extend_from_slice(&[2, 3, 0, 95, 2]);
        self.frame.extend_from_slice(&ki.to_be_bytes());
        // Key length, replay counter, nonce, IV, RSC, ID, MIC, data length.
        self.frame.extend_from_slice(&16u16.to_be_bytes());
        self.frame
            .extend_from_slice(&u64::from(msg.div_ceil(2)).to_be_bytes());
        let nonce = (self.counter as u8).wrapping_mul(13);
        self.frame.extend(std::iter::repeat_n(nonce, 32));
        self.frame.extend_from_slice(&[0; 16 + 8 + 8 + 16]);
        self.frame.extend_from_slice(&[0, 0]);
        self.push(batch, at);
    }

    /// The TV's exit and return.
    fn kicked(&mut self, batch: &mut FrameBatch, at: Duration, i: usize) {
        for _ in 0..6 {
            self.mgmt(batch, at, 12, false, i, &7u16.to_le_bytes());
        }
        self.mgmt(batch, at, 11, true, i, &[0, 0, 1, 0, 0, 0]);
        self.mgmt(batch, at, 11, false, i, &[0, 0, 2, 0, 0, 0]);
        let mut assoc = vec![0x11, 0x00, 0x0a, 0x00];
        ssid_ie(&mut assoc, b"CoreRouter-Lab");
        self.mgmt(batch, at, 0, true, i, &assoc);
        self.mgmt(batch, at, 1, false, i, &[0x11, 0x00, 0, 0, 0x01, 0xc0]);
        for msg in 1..=4 {
            self.eapol(batch, at, i, msg);
        }
    }

    /// A probe for the hidden network, and the answer that names it.
    fn probe(&mut self, batch: &mut FrameBatch, at: Duration, i: usize) {
        let Some(s) = self.stations.get(i) else {
            return;
        };
        let (m, sig, bssid) = (s.mac, s.signal, s.bssid);
        let radio = self.basic_rate();
        self.head(radio, sig, [0x40, 0], [BROADCAST, m, BROADCAST]);
        if let Some(name) = self
            .ap_index(bssid)
            .and_then(|a| self.aps.get(a))
            .map(|a| a.ssid.clone())
        {
            ssid_ie(&mut self.frame, name.as_bytes());
        }
        self.push(batch, at);
        if let Some(ap) = self.ap_index(bssid) {
            self.announce(batch, at, ap, Some(m));
        }
    }
}

fn s_signal(stations: &[Sta], i: usize) -> i8 {
    stations.get(i).map_or(-70, |s| s.signal)
}

impl MonitorSocket for LabSocket {
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError> {
        let start = self.t;
        let end = start.saturating_add(wait);
        self.t = end;
        let secs = wait.as_secs_f64();
        let mid = |k: u64, n: u64| start + wait.mul_f64(k as f64 / n.max(1) as f64);
        // Beacons: every 102.4 ms (100 TU).
        let beacon = Duration::from_micros(102_400);
        for ap in 0..self.aps.len() {
            let here = self.aps.get(ap).is_some_and(|a| a.freq == self.freq);
            if !here {
                continue;
            }
            let n = ticks(start, end, beacon);
            for k in 0..n {
                if batch.is_full() {
                    return Ok(());
                }
                self.announce(batch, mid(k, n), ap, None);
            }
        }
        for i in 0..self.stations.len() {
            let Some(s) = self.stations.get(i) else {
                continue;
            };
            let (down, up, act) = (s.down_pps, s.up_pps, s.act);
            // Kicked 3 s into each 20 s; probing at 1 s into each 5 s.
            let (shift, period) = match act {
                Act::Kicked => (17, 20),
                Act::Prober => (4, 5),
                Act::Normal => (0, 0),
            };
            if period > 0 {
                let shifted = |t: Duration| t.saturating_add(Duration::from_secs(shift));
                if ticks(shifted(start), shifted(end), Duration::from_secs(period)) > 0
                    && let Some(d) = self.due.get_mut(i)
                {
                    *d = true;
                }
            }
            let on = self
                .ap_index(s.bssid)
                .and_then(|a| self.aps.get(a))
                .map(|a| a.freq);
            if on != Some(self.freq) {
                continue;
            }
            for (k, pps, dir_down) in [(i * 2, down, true), (i * 2 + 1, up, false)] {
                let Some(owed) = self.owed.get_mut(k) else {
                    continue;
                };
                *owed += pps * secs;
                let n = owed.floor();
                *owed -= n;
                let n = n as u64;
                for j in 0..n {
                    if batch.is_full() {
                        return Ok(());
                    }
                    self.data(batch, mid(j, n), i, dir_down);
                }
            }
            if self.due.get(i).copied().unwrap_or(false) {
                if let Some(d) = self.due.get_mut(i) {
                    *d = false;
                }
                match act {
                    Act::Kicked => self.kicked(batch, mid(1, 2), i),
                    Act::Prober => self.probe(batch, mid(1, 2), i),
                    Act::Normal => {}
                }
            }
        }
        Ok(())
    }

    fn set_channel(&mut self, freq_mhz: u32) -> Result<(), CaptureError> {
        if self.mode == MonitorMode::Shared {
            return Err(CaptureError::Unavailable(
                "a monitor beside the station stays on the station's channel".into(),
            ));
        }
        self.freq = freq_mhz;
        Ok(())
    }

    fn channel(&mut self) -> Option<u32> {
        Some(self.freq)
    }

    fn interface(&self) -> String {
        monitor_name(&self.radio)
    }

    fn blocks(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ieee80211::{Info, frame, info, radiotap};

    fn lab() -> (LabWifi, LabMonitor) {
        let w = LabWifi::default();
        w.add_radio("wifi1".parse().unwrap());
        let m = LabMonitor::new(w.clone());
        (w, m)
    }

    fn open(m: &LabMonitor, mode: MonitorMode, freq: Option<u32>) -> Box<dyn MonitorSocket> {
        m.open(&MonitorSpec {
            radio: "wifi1".into(),
            mode,
            freq_mhz: freq,
            width_mhz: 20,
        })
        .unwrap()
    }

    /// Every frame of `secs` seconds, parsed.
    fn hear(s: &mut dyn MonitorSocket, secs: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for _ in 0..secs * 10 {
            let mut b = FrameBatch::new(4096);
            s.recv(Duration::from_millis(100), &mut b).unwrap();
            out.extend(b.iter().map(|(_, d)| d.to_vec()));
        }
        out
    }

    #[test]
    fn the_air_of_the_lab_network() {
        let (_, m) = lab();
        let mut s = open(&m, MonitorMode::Exclusive, Some(5220));
        assert_eq!(s.interface(), "wifi1mon");
        let frames = hear(s.as_mut(), 21);
        let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
        let (mut retries, mut eapol, mut deauth) = (0, 0, 0);
        for d in &frames {
            let r = radiotap(d).unwrap();
            assert_eq!(r.freq_mhz, Some(5220));
            let f = frame(&d[r.len..], r.fcs_len()).unwrap();
            *kinds.entry(f.type_name()).or_default() += 1;
            retries += usize::from(f.retry());
            match info(&f) {
                Info::EapolKey(Some(_)) => eapol += 1,
                Info::Leave {
                    deauth: true,
                    reason: Some(7),
                } => deauth += 1,
                _ => {}
            }
        }
        // Two access points (the lab's and the twin) ten times a second.
        assert!((400..=420).contains(&kinds["beacon"]), "{kinds:?}");
        assert!(kinds["qos-data"] > 3000 && kinds["ack"] > 3000, "{kinds:?}");
        assert!(retries > 100);
        assert_eq!((eapol, deauth), (4, 6), "one kick in 21 s");
    }

    #[test]
    fn hopping_and_the_hidden_network() {
        let (_, m) = lab();
        let mut s = open(&m, MonitorMode::Exclusive, Some(5180));
        let frames = hear(s.as_mut(), 6);
        let named = frames.iter().any(|d| {
            let r = radiotap(d).unwrap();
            let f = frame(&d[r.len..], 0).unwrap();
            matches!(info(&f), Info::Announce { probe_resp: true, elements, .. }
                if elements.ssid.is_some_and(|s| s.as_bytes() == b"Oculta"))
        });
        assert!(named, "the probe response gives the hidden name away");
        s.set_channel(2412).unwrap();
        assert_eq!(s.channel(), Some(2412));
        let frames = hear(s.as_mut(), 1);
        assert!(
            frames
                .iter()
                .all(|d| radiotap(d).unwrap().freq_mhz == Some(2412))
        );
        assert!(!frames.is_empty());
    }

    #[test]
    fn a_shared_monitor_stays_on_the_station_channel() {
        let (_, m) = lab();
        let mut s = open(&m, MonitorMode::Shared, None);
        assert!(s.set_channel(2412).is_err());
        assert_eq!(s.channel(), Some(DEFAULT_FREQ));
        assert!(
            m.open(&MonitorSpec {
                radio: "wifi9".into(),
                mode: MonitorMode::Shared,
                freq_mhz: None,
                width_mhz: 20,
            })
            .is_err()
        );
    }
}

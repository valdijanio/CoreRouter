//! The virtual lab's Wi-Fi (G1.30): radios and an "air" with a handful of
//! made-up networks, so the commands, the windows and the tests have a
//! station to drive without a card. A radio takes one poll to find a network
//! and one more to get in (or to be refused), which is what the engine sees
//! of a real one, only faster.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_model::IfName;

use crate::HalError;
use crate::wifi::spectral::{SpectralSample, encode_ath10k, parse_stream};
use crate::wifi::{
    BssSecurity, JoinSecurity, MAX_EVENTS, MAX_SPECTRAL_SECS, WifiBand, WifiBss, WifiChannel,
    WifiEvent, WifiFailure, WifiLink, WifiNetwork, WifiPort, WifiRadio, WifiRate, WifiState,
    WifiStatus, WifiSurvey,
};

/// The passphrase of the lab's main network (`CoreRouter-Lab`).
pub const LAB_PASSPHRASE: &str = "corerouter-lab";

/// One network of the lab's air.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabNetwork {
    pub ssid: String,
    pub bssid: String,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub security: BssSecurity,
    pub key: String,
    /// Does not announce its name: a scan shows it nameless.
    pub hidden: bool,
    /// G1.30i: the information elements its beacons carry ([`elements`]).
    pub ies: Vec<u8>,
}

/// The lab network's channel: the width and centre of the whole channel,
/// the generation, the BSS Load (stations, utilization 0..=255).
#[derive(Debug, Clone, Copy)]
pub struct LabChannel {
    pub width_mhz: u32,
    pub center_mhz: u32,
    pub generation: u8,
    pub load: Option<(u16, u8)>,
}

fn ch_of(mhz: u32) -> u8 {
    let n = match mhz {
        2484 => 14,
        0..=2500 => mhz.saturating_sub(2407) / 5,
        2501..=5925 => mhz.saturating_sub(5000) / 5,
        _ => mhz.saturating_sub(5950) / 5,
    };
    u8::try_from(n).unwrap_or(0)
}

/// The elements an access point on `primary_mhz` writes for `c`, in the
/// layouts of IEEE 802.11-2020 §9.4.2 (the same ones a real scan brings).
pub fn elements(primary_mhz: u32, c: LabChannel) -> Vec<u8> {
    let mut b = Vec::new();
    let mut el = |id: u8, body: &[u8]| {
        b.push(id);
        b.push(u8::try_from(body.len()).unwrap_or(0));
        b.extend_from_slice(body);
    };
    let six = primary_mhz > 5925;
    let five = (5150..=5925).contains(&primary_mhz);
    if let Some((stations, util)) = c.load {
        let s = stations.to_le_bytes();
        el(11, &[s[0], s[1], util, 0, 0]);
    }
    if c.generation >= 4 && !six {
        el(45, &[0; 26]);
        let mut op = [0u8; 22];
        op[0] = ch_of(primary_mhz);
        if c.width_mhz >= 40 {
            op[1] = if c.center_mhz > primary_mhz {
                0b101
            } else {
                0b111
            };
        }
        el(61, &op);
    }
    if c.generation >= 5 && five {
        el(191, &[0; 12]);
        let center = ch_of(c.center_mhz);
        let info = match c.width_mhz {
            80 => [1, center, 0],
            160 => {
                let primary80 = if primary_mhz < c.center_mhz {
                    c.center_mhz - 40
                } else {
                    c.center_mhz + 40
                };
                [1, ch_of(primary80), center]
            }
            _ => [0, 0, 0],
        };
        el(192, &[info[0], info[1], info[2], 0xfc, 0xff]);
    }
    if c.generation >= 6 {
        el(255, &[35, 0, 0, 0, 0, 0, 0]);
        if six {
            let control = match c.width_mhz {
                20 => 0,
                40 => 1,
                80 => 2,
                _ => 3,
            };
            let (c0, c1) = if c.width_mhz == 160 {
                let primary80 = if primary_mhz < c.center_mhz {
                    c.center_mhz - 40
                } else {
                    c.center_mhz + 40
                };
                (ch_of(primary80), ch_of(c.center_mhz))
            } else {
                (ch_of(c.center_mhz), 0)
            };
            el(
                255,
                &[
                    36,
                    0,
                    0,
                    0b10,
                    1,
                    0xfc,
                    0xff,
                    ch_of(primary_mhz),
                    control,
                    c0,
                    c1,
                    6,
                ],
            );
        } else {
            el(255, &[36, 0, 0, 0, 1, 0xfc, 0xff]);
        }
    }
    if c.generation >= 7 {
        el(255, &[108, 0, 0]);
    }
    b
}

fn net(
    ssid: &str,
    last: u8,
    frequency_mhz: u32,
    signal_dbm: i32,
    security: BssSecurity,
    key: &str,
) -> LabNetwork {
    LabNetwork {
        ssid: ssid.into(),
        bssid: format!("02:c0:fe:00:00:{last:02x}"),
        frequency_mhz,
        signal_dbm,
        security,
        key: key.into(),
        hidden: false,
        ies: Vec::new(),
    }
}

/// `n` on channel `c`: its elements written.
fn on(
    mut n: LabNetwork,
    width_mhz: u32,
    center_mhz: u32,
    generation: u8,
    load: Option<(u16, u8)>,
) -> LabNetwork {
    n.ies = elements(
        n.frequency_mhz,
        LabChannel {
            width_mhz,
            center_mhz,
            generation,
            load,
        },
    );
    n
}

/// What a lab radio hears. Two access points of one network on two bands,
/// a WPA3-only one, a neighbour's, an open one, a hidden one and an
/// enterprise one (which the router cannot join yet); G1.30i: the
/// neighbours of a block of flats, so the channels have something to show
/// (2.4 GHz on 1, 4, 6 and 11 with one 40 MHz network, 5 GHz with 80 and
/// 160 MHz channels that overlap, one 6 GHz network).
pub fn default_networks() -> Vec<LabNetwork> {
    let mut hidden = on(
        net("Oculta", 6, 5180, -65, BssSecurity::Wpa2, "rede-escondida"),
        20,
        5180,
        5,
        None,
    );
    hidden.hidden = true;
    vec![
        on(
            net(
                "CoreRouter-Lab",
                1,
                5220,
                -52,
                BssSecurity::Wpa2Wpa3,
                LAB_PASSPHRASE,
            ),
            80,
            5210,
            6,
            Some((4, 38)),
        ),
        on(
            net(
                "CoreRouter-Lab",
                2,
                2437,
                -61,
                BssSecurity::Wpa2Wpa3,
                LAB_PASSPHRASE,
            ),
            20,
            2437,
            6,
            Some((2, 51)),
        ),
        on(
            net(
                "Lab-WPA3",
                3,
                5745,
                -58,
                BssSecurity::Wpa3,
                "wpa3-only-pass",
            ),
            80,
            5775,
            6,
            None,
        ),
        on(
            net(
                "Vizinho_2G",
                4,
                2462,
                -78,
                BssSecurity::Wpa2,
                "outro-segredo",
            ),
            40,
            2452,
            4,
            None,
        ),
        on(
            net("Cafe", 5, 2412, -80, BssSecurity::Open, ""),
            20,
            2412,
            4,
            Some((23, 204)),
        ),
        hidden,
        on(
            net("Corp", 7, 5500, -70, BssSecurity::Enterprise, ""),
            160,
            5570,
            6,
            Some((31, 97)),
        ),
        on(
            net("Apto-301", 8, 2427, -69, BssSecurity::Wpa2, "x"),
            20,
            2427,
            4,
            None,
        ),
        on(
            net("Loja", 9, 2437, -74, BssSecurity::Wpa2, "x"),
            20,
            2437,
            5,
            Some((7, 120)),
        ),
        on(
            net("Vizinho_5G", 10, 5180, -71, BssSecurity::Wpa2, "x"),
            80,
            5210,
            5,
            Some((3, 25)),
        ),
        on(
            net("Lab-6E", 11, 6115, -67, BssSecurity::Wpa3, "x"),
            160,
            6185,
            7,
            Some((1, 8)),
        ),
    ]
}

#[derive(Debug, Default)]
struct Radio {
    want: Option<WifiNetwork>,
    /// Polls since `want` was set.
    polls: u32,
    state: WifiState,
    on: Option<LabNetwork>,
    events: Vec<WifiEvent>,
    scanned: Option<Vec<WifiBss>>,
    scanning: bool,
    joins: u32,
    /// G1.30i: the survey of the last scan.
    survey: Vec<WifiSurvey>,
    /// A spectral scan: the band (`None`: the channel in use), the samples
    /// left to send, where the sweep is and the random state.
    spectral: Option<(Option<(u32, u32)>, u64)>,
    spectral_step: u64,
    rng: u64,
}

#[derive(Debug)]
struct Air {
    networks: Vec<LabNetwork>,
    radios: BTreeMap<IfName, Radio>,
    country: Option<String>,
    blocked: bool,
    country_calls: u32,
    /// Radios without spectral scan (a test's).
    no_spectral: Vec<IfName>,
}

/// The lab's air: shared by the HAL, its radios and a test that wants to
/// change what is in range.
#[derive(Debug, Clone)]
pub struct LabWifi(Arc<Mutex<Air>>);

impl Default for LabWifi {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Air {
            networks: default_networks(),
            radios: BTreeMap::new(),
            country: None,
            blocked: false,
            country_calls: 0,
            no_spectral: Vec::new(),
        })))
    }
}

fn push(events: &mut Vec<WifiEvent>, e: WifiEvent) {
    if events.len() < MAX_EVENTS {
        events.push(e);
    }
}

/// Does `n` fit what the station was told to join?
fn offers(n: &LabNetwork, want: &WifiNetwork) -> bool {
    let named = n.ssid == want.ssid && (!n.hidden || want.hidden);
    let band = want
        .band_mhz
        .is_none_or(|(lo, hi)| (lo..=hi).contains(&n.frequency_mhz));
    let bssid = want
        .bssid
        .as_ref()
        .is_none_or(|b| b.eq_ignore_ascii_case(&n.bssid));
    let security = match want.security {
        JoinSecurity::Open => n.security == BssSecurity::Open,
        JoinSecurity::Wpa2 => matches!(n.security, BssSecurity::Wpa2 | BssSecurity::Wpa2Wpa3),
        JoinSecurity::Wpa3 => matches!(n.security, BssSecurity::Wpa3 | BssSecurity::Wpa2Wpa3),
        JoinSecurity::Auto => matches!(
            n.security,
            BssSecurity::Wpa2 | BssSecurity::Wpa2Wpa3 | BssSecurity::Wpa3
        ),
    };
    named && band && bssid && security
}

/// The survey a driver that counts every channel (ath9k, ath10k) leaves
/// after a scan: some 110 ms on each, busy as the networks heard there
/// make it, plus a little noise; the channel in use with its own long
/// count.
fn lab_survey(seen: &[WifiBss], in_use: Option<u32>) -> Vec<WifiSurvey> {
    let channels = (0..13).map(|i| 2412 + 5 * i).chain([
        5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5500, 5520, 5540, 5560, 5745, 5765, 5785,
        5805,
    ]);
    channels
        .map(|mhz| {
            let busy_share: u64 = seen
                .iter()
                .filter(|b| {
                    let w = b.width_mhz.unwrap_or(20);
                    let c = b.center_mhz.unwrap_or(b.frequency_mhz);
                    c.abs_diff(mhz) < (w + 20) / 2
                })
                // Stronger and busier networks fill more of the time.
                .map(|b| {
                    u64::from(b.utilization.unwrap_or(40)) * 20 / 255
                        + u64::try_from(b.signal_dbm + 95).unwrap_or(0) / 8
                })
                .sum();
            let active = if in_use == Some(mhz) { 60_000 } else { 110 };
            let busy = active * (3 + busy_share).min(92) / 100;
            WifiSurvey {
                frequency_mhz: mhz,
                noise_dbm: Some(if mhz < 3000 { -91 } else { -95 }),
                in_use: in_use == Some(mhz),
                active_ms: Some(active),
                busy_ms: Some(busy),
                rx_ms: Some(busy * 2 / 3),
                tx_ms: Some(if in_use == Some(mhz) { active / 50 } else { 0 }),
            }
        })
        .collect()
}

/// xorshift64: the lab's spectrum varies from sample to sample without a
/// clock or a crate.
fn next(state: &mut u64) -> u64 {
    let mut x = (*state).max(1);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// One FFT of the lab's air over `width` MHz around `center`: the networks
/// that overlap it, each sending in a share of the samples as busy as it
/// is (an OFDM block 2 MHz narrower than its channel, its signal spread
/// over its width), and, on 2.4 GHz, a microwave oven (2450–2470 MHz, half
/// the time), a Bluetooth-like hopper (1 MHz, anywhere) and a continuous
/// carrier at 2417 MHz; on 5 GHz a carrier at 5232 MHz. Written in
/// ath10k's format and read back by the parser a real radio's goes
/// through.
fn lab_fft(
    networks: &[LabNetwork],
    center: u32,
    width: u32,
    tsf: u64,
    rng: &mut u64,
) -> Option<SpectralSample> {
    let bins = (width as usize * 64 / 20).clamp(64, 256);
    let span = f64::from(width);
    let lo = f64::from(center) - span / 2.0;
    let step = span / bins as f64;
    let noise = -95.0;
    let mut mw = vec![0.0f64; bins];
    let mut add = |from: f64, to: f64, dbm_per_bin: f64| {
        for (i, p) in mw.iter_mut().enumerate() {
            let f = lo + step * (i as f64 + 0.5);
            if f >= from && f <= to {
                *p += 10f64.powf(dbm_per_bin / 10.0);
            }
        }
    };
    for n in networks {
        let op = crate::wifi::ie::parse(&n.ies, n.frequency_mhz);
        let duty = u64::from(op.utilization.unwrap_or(60)).max(25);
        if next(rng) % 255 > duty {
            continue;
        }
        let w = f64::from(op.width_mhz);
        let c = f64::from(op.center_mhz);
        let per_bin = f64::from(n.signal_dbm) - 10.0 * (w / step).log10();
        add(c - w / 2.0 + 1.0, c + w / 2.0 - 1.0, per_bin);
    }
    if center < 3000 {
        if next(rng).is_multiple_of(2) {
            let wander = (next(rng) % 6) as f64;
            add(2450.0 + wander, 2466.0 + wander, -58.0);
        }
        let hop = 2402.0 + (next(rng) % 79) as f64;
        add(hop - 0.5, hop + 0.5, -62.0);
        add(2416.8, 2417.2, -70.0);
    } else {
        add(5231.8, 5232.2, -72.0);
    }
    let dbm: Vec<f64> = mw
        .iter()
        .map(|p| {
            let jitter = (next(rng) % 40) as f64 / 10.0 - 2.0;
            10.0 * (p + 10f64.powf((noise + jitter) / 10.0)).log10()
        })
        .collect();
    let tlv = encode_ath10k(
        u16::try_from(center).ok()?,
        u8::try_from(width).ok()?,
        -95,
        tsf,
        &dbm,
    );
    let mut out = Vec::new();
    parse_stream(&tlv, &mut out, 1);
    out.pop()
}

impl Air {
    /// One step of radio `name` towards its network.
    fn step(&mut self, name: &IfName) {
        let blocked = self.blocked;
        let networks = &self.networks;
        let Some(r) = self.radios.get_mut(name) else {
            return;
        };
        if r.scanning {
            r.scanning = false;
            let mut seen: Vec<WifiBss> = networks
                .iter()
                .map(|n| {
                    WifiBss {
                        ssid: if n.hidden {
                            String::new()
                        } else {
                            n.ssid.clone()
                        },
                        bssid: n.bssid.clone(),
                        frequency_mhz: n.frequency_mhz,
                        signal_dbm: n.signal_dbm,
                        security: n.security,
                        ..WifiBss::default()
                    }
                    .with_elements(&n.ies)
                })
                .collect();
            seen.sort_by_key(|b| std::cmp::Reverse(b.signal_dbm));
            r.survey = lab_survey(&seen, r.on.as_ref().map(|n| n.frequency_mhz));
            r.scanned = Some(seen);
            push(&mut r.events, WifiEvent::ScanDone);
        }
        if blocked {
            if r.state != WifiState::Blocked {
                r.state = WifiState::Blocked;
                r.on = None;
                push(&mut r.events, WifiEvent::Blocked(true));
            }
            return;
        }
        if r.state == WifiState::Blocked {
            r.state = WifiState::Idle;
            r.polls = 0;
            push(&mut r.events, WifiEvent::Blocked(false));
        }
        let Some(want) = r.want.clone() else {
            return;
        };
        if r.state == WifiState::Connected {
            // The access point went away (a test took it off the air).
            if !r.on.as_ref().is_some_and(|on| networks.contains(on)) {
                r.on = None;
                r.state = WifiState::Searching;
                r.polls = 0;
                push(
                    &mut r.events,
                    WifiEvent::Disconnected {
                        reason: "the access point stopped answering (beacon loss)".into(),
                    },
                );
            }
            return;
        }
        r.polls = r.polls.saturating_add(1);
        let best = networks
            .iter()
            .filter(|n| offers(n, &want))
            .max_by_key(|n| n.signal_dbm);
        match (r.polls, best) {
            // Looking for a network starts with a scan, and its end is said
            // like any other (the supplicant's `CTRL-EVENT-SCAN-RESULTS`).
            (1, _) => {
                r.state = WifiState::Searching;
                r.scanning = true;
            }
            (_, None) => {
                // Keeps looking, and says so once per round of the scan.
                if r.polls == 2 {
                    push(&mut r.events, WifiEvent::Failed(WifiFailure::NotFound));
                }
                r.state = WifiState::Searching;
            }
            (2, Some(_)) => r.state = WifiState::Connecting,
            (_, Some(n)) if n.key == want.key => {
                r.state = WifiState::Connected;
                r.on = Some(n.clone());
                push(
                    &mut r.events,
                    WifiEvent::Connected {
                        bssid: n.bssid.clone(),
                    },
                );
            }
            (3, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::WrongKey));
                r.state = WifiState::Searching;
            }
            // What the supplicant does after a wrong key: it leaves that
            // access point alone, so its next scan "finds none" with the
            // network on the list, and then it pauses the network.
            (4, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::NotFound));
                r.state = WifiState::Searching;
            }
            (5, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::NoAnswer));
                r.state = WifiState::Searching;
            }
            (_, Some(_)) => r.state = WifiState::Searching,
        }
    }
}

impl LabWifi {
    fn air(&self) -> MutexGuard<'_, Air> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Put radio `name` in the lab.
    pub fn add_radio(&self, name: IfName) {
        self.air().radios.entry(name).or_default();
    }

    pub fn has_radio(&self, name: &IfName) -> bool {
        self.air().radios.contains_key(name)
    }

    pub fn radio_names(&self) -> Vec<IfName> {
        self.air().radios.keys().cloned().collect()
    }

    /// The radio's port.
    pub fn port(&self, name: &IfName) -> Result<Box<dyn WifiPort>, HalError> {
        if !self.has_radio(name) {
            return Err(HalError::Unsupported(format!(
                "'{name}' is not a Wi-Fi radio of the lab"
            )));
        }
        Ok(Box::new(LabPort {
            air: self.clone(),
            name: name.clone(),
        }))
    }

    pub fn radio(&self, name: &IfName) -> Option<WifiRadio> {
        let spectral = !self.air().no_spectral.contains(name);
        self.has_radio(name).then(|| {
            // G1.30g: a 2x2 Wi-Fi 6 card, the shape of the common laptop ones.
            let ch = |mhz: u32, max: i32, radar: bool| WifiChannel {
                mhz,
                max_power_dbm: Some(max),
                radar,
                disabled: false,
            };
            WifiRadio {
                driver: Some("lab_wifi".into()),
                self_managed: false,
                phy: Some("phy0".into()),
                firmware: Some("lab 1.0".into()),
                bands: vec![
                    WifiBand {
                        band: "2ghz".into(),
                        standards: ["b", "g", "n", "ax"].map(String::from).to_vec(),
                        max_width_mhz: Some(40),
                        channels: (0..13).map(|i| ch(2412 + 5 * i, 20, false)).collect(),
                    },
                    WifiBand {
                        band: "5ghz".into(),
                        standards: ["a", "n", "ac", "ax"].map(String::from).to_vec(),
                        max_width_mhz: Some(80),
                        channels: [
                            5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5745, 5765, 5785, 5805,
                        ]
                        .into_iter()
                        .map(|f| ch(f, if f < 5250 { 23 } else { 30 }, (5260..5700).contains(&f)))
                        .collect(),
                    },
                ],
                antennas_tx: Some(2),
                antennas_rx: Some(2),
                tx_power_dbm: Some(20),
                blocked: None,
                spectral_scan: spectral,
                spectral_why_not: (!spectral).then(|| {
                    "this lab radio has no spectral scan (like a Realtek or MediaTek card): it \
                     needs a Qualcomm Atheros chip (ath9k, ath10k, ath11k)"
                        .to_owned()
                }),
            }
        })
    }

    /// The regulatory domain the lab was asked for.
    pub fn country(&self) -> Option<String> {
        self.air().country.clone()
    }

    pub fn set_country(&self, country: Option<&str>) {
        let mut air = self.air();
        air.country = country.map(str::to_owned);
        air.country_calls = air.country_calls.saturating_add(1);
        let c = air.country.clone();
        for r in air.radios.values_mut() {
            push(&mut r.events, WifiEvent::Country(c.clone()));
        }
    }

    /// How many times the domain was asked for (a test's: once per change).
    pub fn country_calls(&self) -> u32 {
        self.air().country_calls
    }

    /// Is radio `name` on a network now?
    pub fn connected(&self, name: &IfName) -> bool {
        self.air()
            .radios
            .get(name)
            .is_some_and(|r| r.state == WifiState::Connected)
    }

    /// Times radio `name` was told to join (a test's: no rejoin on a tick).
    pub fn joins(&self, name: &IfName) -> u32 {
        self.air().radios.get(name).map_or(0, |r| r.joins)
    }

    /// Take the networks named `ssid` off the air (a test's).
    pub fn remove_network(&self, ssid: &str) {
        self.air().networks.retain(|n| n.ssid != ssid);
    }

    pub fn add_network(&self, n: LabNetwork) {
        self.air().networks.push(n);
    }

    /// Radio `name` has no spectral scan (as a Realtek or MediaTek card).
    pub fn without_spectral(&self, name: &IfName) {
        self.air().no_spectral.push(name.clone());
    }

    /// Block or unblock every radio, as an airplane-mode key does.
    pub fn set_blocked(&self, blocked: bool) {
        self.air().blocked = blocked;
    }
}

struct LabPort {
    air: LabWifi,
    name: IfName,
}

impl WifiPort for LabPort {
    fn join(&mut self, net: &WifiNetwork) -> Result<(), HalError> {
        let mut air = self.air.air();
        let Some(r) = air.radios.get_mut(&self.name) else {
            return Err(HalError::Io(format!("radio '{}' is gone", self.name)));
        };
        if r.state == WifiState::Connected {
            push(
                &mut r.events,
                WifiEvent::Disconnected {
                    reason: "left for another network".into(),
                },
            );
        }
        r.want = Some(net.clone());
        r.polls = 0;
        r.on = None;
        r.state = WifiState::Searching;
        r.joins = r.joins.saturating_add(1);
        Ok(())
    }

    fn leave(&mut self) -> Result<(), HalError> {
        let mut air = self.air.air();
        if let Some(r) = air.radios.get_mut(&self.name) {
            if r.state == WifiState::Connected {
                push(
                    &mut r.events,
                    WifiEvent::Disconnected {
                        reason: "left (told to)".into(),
                    },
                );
            }
            r.want = None;
            r.on = None;
            if r.state != WifiState::Blocked {
                r.state = WifiState::Idle;
            }
        }
        Ok(())
    }

    fn scan(&mut self) -> Result<(), HalError> {
        let mut air = self.air.air();
        if air.blocked {
            return Err(HalError::Rejected("the radio is blocked (rfkill)".into()));
        }
        match air.radios.get_mut(&self.name) {
            Some(r) => {
                r.scanning = true;
                Ok(())
            }
            None => Err(HalError::Io(format!("radio '{}' is gone", self.name))),
        }
    }

    fn scan_results(&mut self) -> Result<Vec<WifiBss>, HalError> {
        let air = self.air.air();
        Ok(air
            .radios
            .get(&self.name)
            .and_then(|r| r.scanned.clone())
            .unwrap_or_default())
    }

    fn status(&mut self) -> Result<WifiStatus, HalError> {
        let air = self.air.air();
        let Some(r) = air.radios.get(&self.name) else {
            return Err(HalError::Io(format!("radio '{}' is gone", self.name)));
        };
        let on = r.on.as_ref();
        Ok(WifiStatus {
            state: r.state,
            ssid: on
                .map(|n| n.ssid.clone())
                .or_else(|| r.want.as_ref().map(|w| w.ssid.clone())),
            bssid: on.map(|n| n.bssid.clone()),
            frequency_mhz: on.map(|n| n.frequency_mhz),
            signal_dbm: on.map(|n| n.signal_dbm),
            rate_mbps: on.map(|n| if n.frequency_mhz > 5000 { 866 } else { 144 }),
            security: on.map(|n| {
                match (n.security, r.want.as_ref().map(|w| w.security)) {
                    (BssSecurity::Open, _) => "open",
                    (BssSecurity::Wpa2, _) | (_, Some(JoinSecurity::Wpa2)) => "wpa2",
                    _ => "wpa3",
                }
                .to_owned()
            }),
            pmf: on.map(|n| matches!(n.security, BssSecurity::Wpa3 | BssSecurity::Wpa2Wpa3)),
            // G1.30g: what a 2x2 Wi-Fi 6 link reads like.
            noise_dbm: on.map(|_| -92),
            width_mhz: on.map(|n| crate::wifi::ie::parse(&n.ies, n.frequency_mhz).width_mhz),
            center_mhz: on.map(|n| crate::wifi::ie::parse(&n.ies, n.frequency_mhz).center_mhz),
            generation: on.map(|_| 6),
            cipher: on.map(|n| {
                if n.security == BssSecurity::Open {
                    "NONE"
                } else {
                    "CCMP"
                }
                .to_owned()
            }),
            link: on.map(|n| {
                let wide = n.frequency_mhz > 5000;
                let rate = |kbps: u32, mcs: u8| WifiRate {
                    kbps: Some(kbps),
                    mode: Some("he".into()),
                    mcs: Some(mcs),
                    nss: Some(2),
                    width_mhz: Some(if wide { 80 } else { 20 }),
                    guard_ns: Some(800),
                };
                WifiLink {
                    tx: Some(if wide {
                        rate(864_800, 9)
                    } else {
                        rate(229_400, 11)
                    }),
                    rx: Some(if wide {
                        rate(1_201_000, 11)
                    } else {
                        rate(206_500, 10)
                    }),
                    signal_avg_dbm: Some(n.signal_dbm),
                    beacon_signal_dbm: Some(n.signal_dbm - 2),
                    chain_signal_dbm: vec![n.signal_dbm - 1, n.signal_dbm - 3],
                    tx_packets: Some(3084),
                    rx_packets: Some(4207),
                    tx_retries: Some(65),
                    tx_failed: Some(0),
                    beacon_loss: Some(0),
                    connected_secs: None,
                    inactive_ms: Some(40),
                }
            }),
        })
    }

    fn survey(&mut self) -> Vec<WifiSurvey> {
        self.air
            .air()
            .radios
            .get(&self.name)
            .map(|r| r.survey.clone())
            .unwrap_or_default()
    }

    fn spectral_start(&mut self, secs: u32, range: Option<(u32, u32)>) -> Result<(), HalError> {
        let mut air = self.air.air();
        if air.no_spectral.contains(&self.name) {
            return Err(HalError::Unsupported(
                "this lab radio has no spectral scan".into(),
            ));
        }
        let Some(r) = air.radios.get_mut(&self.name) else {
            return Err(HalError::Io(format!("radio '{}' is gone", self.name)));
        };
        if range.is_none() && r.on.is_none() {
            return Err(HalError::Rejected(
                "not on a channel: connect to a network first, or scan a band".into(),
            ));
        }
        // Some 40 samples a second, as the engine reads them (4 a tick).
        let secs = u64::from(secs.clamp(1, MAX_SPECTRAL_SECS));
        r.spectral = Some((range, secs * 40));
        Ok(())
    }

    fn spectral_stop(&mut self) {
        if let Some(r) = self.air.air().radios.get_mut(&self.name) {
            r.spectral = None;
        }
    }

    fn spectral_samples(&mut self, max: usize) -> Vec<SpectralSample> {
        let mut air = self.air.air();
        let networks = air.networks.clone();
        let Some(r) = air.radios.get_mut(&self.name) else {
            return Vec::new();
        };
        let Some((range, left)) = r.spectral else {
            return Vec::new();
        };
        let n = max.min(4).min(usize::try_from(left).unwrap_or(0));
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            r.spectral_step = r.spectral_step.wrapping_add(1);
            let (center, width) = match (range, r.on.as_ref()) {
                // A sweep: each channel of the band in turn, 20 MHz around
                // its centre, as ath9k's `chanscan` hands them while the
                // radio scans.
                (Some((lo, hi)), _) => {
                    let centers: Vec<u32> = (1..=13)
                        .map(|c| 2407 + 5 * c)
                        .chain((0..8).map(|k| 5180 + 20 * k))
                        .chain((0..12).map(|k| 5500 + 20 * k))
                        .chain((0..5).map(|k| 5745 + 20 * k))
                        .filter(|f| (lo..=hi).contains(f))
                        .collect();
                    let n = centers.len().max(1) as u64;
                    let k = usize::try_from(r.spectral_step % n).unwrap_or(0);
                    (centers.get(k).copied().unwrap_or(lo + 10), 20)
                }
                (None, Some(on)) => {
                    let op = crate::wifi::ie::parse(&on.ies, on.frequency_mhz);
                    (op.center_mhz, op.width_mhz.min(80))
                }
                (None, None) => break,
            };
            let tsf = r.spectral_step.wrapping_mul(25_000);
            if let Some(s) = lab_fft(&networks, center, width, tsf, &mut r.rng) {
                out.push(s);
            }
        }
        let left = left.saturating_sub(n as u64);
        r.spectral = (left > 0).then_some((range, left));
        out
    }

    fn events(&mut self) -> Vec<WifiEvent> {
        let mut air = self.air.air();
        air.step(&self.name);
        air.radios
            .get_mut(&self.name)
            .map(|r| std::mem::take(&mut r.events))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> (LabWifi, Box<dyn WifiPort>, IfName) {
        let lab = LabWifi::default();
        let name: IfName = "wifi1".parse().unwrap();
        lab.add_radio(name.clone());
        let port = lab.port(&name).unwrap();
        (lab, port, name)
    }

    fn want(ssid: &str, key: &str, security: JoinSecurity) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.into(),
            security,
            key: key.into(),
            hidden: false,
            band_mhz: None,
            bssid: None,
        }
    }

    fn settle(p: &mut dyn WifiPort) -> Vec<WifiEvent> {
        // Without the scan every search starts with.
        (0..6)
            .flat_map(|_| p.events())
            .filter(|e| *e != WifiEvent::ScanDone)
            .collect()
    }

    #[test]
    fn joins_the_strongest_access_point_of_the_network() {
        let (lab, mut p, name) = lab();
        assert_eq!(p.status().unwrap().state, WifiState::Idle);
        p.join(&want("CoreRouter-Lab", LAB_PASSPHRASE, JoinSecurity::Auto))
            .unwrap();
        assert_eq!(p.status().unwrap().state, WifiState::Searching);
        let ev = settle(&mut *p);
        assert_eq!(
            ev,
            [WifiEvent::Connected {
                bssid: "02:c0:fe:00:00:01".into()
            }]
        );
        let st = p.status().unwrap();
        assert_eq!(st.state, WifiState::Connected);
        assert_eq!((st.frequency_mhz, st.signal_dbm), (Some(5220), Some(-52)));
        assert_eq!(st.security.as_deref(), Some("wpa3"));
        assert!(lab.connected(&name));
        // Held to 2.4 GHz, it takes the other access point.
        let mut n = want("CoreRouter-Lab", LAB_PASSPHRASE, JoinSecurity::Auto);
        n.band_mhz = Some((2400, 2500));
        p.join(&n).unwrap();
        settle(&mut *p);
        assert_eq!(p.status().unwrap().frequency_mhz, Some(2437));
        p.leave().unwrap();
        assert_eq!(p.status().unwrap().state, WifiState::Idle);
        assert!(!lab.connected(&name));
    }

    #[test]
    fn says_why_it_did_not_get_in() {
        let (lab, mut p, _) = lab();
        p.join(&want("CoreRouter-Lab", "senha-errada", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(
            settle(&mut *p),
            [
                WifiEvent::Failed(WifiFailure::WrongKey),
                WifiEvent::Failed(WifiFailure::NotFound),
                WifiEvent::Failed(WifiFailure::NoAnswer)
            ],
            "the cause, then what the supplicant does about it"
        );
        p.join(&want("Nao-Existe", "12345678", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        // WPA3 only against a WPA2-only network: not offered.
        p.join(&want("Vizinho_2G", "outro-segredo", JoinSecurity::Wpa3))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        // A hidden network answers only a probe by name.
        p.join(&want("Oculta", "rede-escondida", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        let mut hidden = want("Oculta", "rede-escondida", JoinSecurity::Auto);
        hidden.hidden = true;
        p.join(&hidden).unwrap();
        assert!(matches!(settle(&mut *p)[..], [WifiEvent::Connected { .. }]));
        // The access point goes away; the radio looks for it again.
        lab.remove_network("Oculta");
        assert!(matches!(
            settle(&mut *p)[..],
            [WifiEvent::Disconnected { .. }, ..]
        ));
        assert_eq!(p.status().unwrap().state, WifiState::Searching);
    }

    #[test]
    fn scans_and_is_blocked() {
        let (lab, mut p, _) = lab();
        assert!(p.scan_results().unwrap().is_empty());
        p.scan().unwrap();
        assert_eq!(p.events(), [WifiEvent::ScanDone]);
        let seen = p.scan_results().unwrap();
        assert_eq!(seen.len(), default_networks().len());
        // G1.30i: the channel from the elements, and the survey.
        let lab5 = seen
            .iter()
            .find(|b| b.bssid == "02:c0:fe:00:00:01")
            .unwrap();
        assert_eq!(
            (lab5.width_mhz, lab5.center_mhz, lab5.stations),
            (Some(80), Some(5210), Some(4))
        );
        let six = seen.iter().find(|b| b.ssid == "Lab-6E").unwrap();
        assert_eq!(
            (six.width_mhz, six.center_mhz, six.generation),
            (Some(160), Some(6185), Some(7))
        );
        assert!(p.survey().iter().all(|s| s.busy_ms <= s.active_ms));
        assert_eq!(seen[0].ssid, "CoreRouter-Lab");
        assert!(seen.windows(2).all(|w| w[0].signal_dbm >= w[1].signal_dbm));
        assert!(
            seen.iter().any(|b| b.ssid.is_empty()),
            "the hidden one has no name"
        );
        lab.set_blocked(true);
        assert!(p.scan().is_err());
        assert_eq!(p.events(), [WifiEvent::Blocked(true)]);
        assert_eq!(p.status().unwrap().state, WifiState::Blocked);
        lab.set_blocked(false);
        assert_eq!(p.events(), [WifiEvent::Blocked(false)]);
        lab.set_country(Some("BR"));
        assert_eq!(p.events(), [WifiEvent::Country(Some("BR".into()))]);
        assert_eq!(lab.country().as_deref(), Some("BR"));
        assert!(lab.port(&"ether1".parse().unwrap()).is_err());
    }
}

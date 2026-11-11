//! A Wi-Fi radio in station mode, as the platform offers it (G1.30).
//!
//! The engine says which network an interface joins and reads what became
//! of it; the platform does the joining. On Linux that is `wpa_supplicant`
//! (the authentication runs in user space on every driver of the image) and
//! nl80211; the virtual lab has a radio with three made-up networks. The
//! data path is the kernel's: nothing here sees a data frame.
//!
//! The passphrase crosses this boundary in clear and is kept by neither
//! side longer than the call: the config has it sealed.

use serde::Serialize;

use crate::HalError;

pub mod ie;
pub mod spectral;

pub use spectral::SpectralSample;

/// How a network is secured, as the station is told to join it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinSecurity {
    /// WPA3 if the access point offers it, else WPA2.
    Auto,
    Wpa3,
    Wpa2,
    Open,
}

/// The network a radio is told to join.
#[derive(Clone, PartialEq, Eq)]
pub struct WifiNetwork {
    pub ssid: String,
    pub security: JoinSecurity,
    /// The passphrase (8 to 63 characters) or the 64-digit key; empty for
    /// an open network.
    pub key: String,
    /// Probe for the name (the network does not announce it).
    pub hidden: bool,
    /// Scan and join only between these frequencies, MHz, inclusive.
    pub band_mhz: Option<(u32, u32)>,
    /// Only this access point, `aa:bb:cc:dd:ee:ff`.
    pub bssid: Option<String>,
}

/// Never the key: a `{:?}` goes to logs.
impl std::fmt::Debug for WifiNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WifiNetwork")
            .field("ssid", &self.ssid)
            .field("security", &self.security)
            .field("key", &if self.key.is_empty() { "" } else { "***" })
            .field("hidden", &self.hidden)
            .field("band_mhz", &self.band_mhz)
            .field("bssid", &self.bssid)
            .finish()
    }
}

/// What a network in range offers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BssSecurity {
    #[default]
    Open,
    /// Opportunistic encryption without a passphrase (RFC 8110).
    Owe,
    /// WEP, or WPA with TKIP only: broken, never joined.
    Legacy,
    Wpa2,
    /// Both (the access point's transition mode).
    Wpa2Wpa3,
    Wpa3,
    /// 802.1X (a user and a password, or a certificate): not supported yet.
    Enterprise,
}

impl BssSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owe => "owe",
            Self::Legacy => "legacy",
            Self::Wpa2 => "wpa2",
            Self::Wpa2Wpa3 => "wpa2-wpa3",
            Self::Wpa3 => "wpa3",
            Self::Enterprise => "enterprise",
        }
    }
}

/// One access point a scan heard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiBss {
    /// Empty: the network hides its name.
    pub ssid: String,
    pub bssid: String,
    /// The primary channel.
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub security: BssSecurity,
    /// G1.30i, from its elements ([`ie::parse`]): the width of the whole
    /// channel, MHz; `None` when the elements were not read.
    pub width_mhz: Option<u32>,
    /// Centre of the whole channel (of the first segment of 80+80), MHz.
    pub center_mhz: Option<u32>,
    /// The second 80 MHz segment of an 80+80 channel.
    pub center2_mhz: Option<u32>,
    /// 4 (802.11n), 5 (ac), 6 (ax), 7 (be).
    pub generation: Option<u8>,
    /// BSS Load: stations associated with it.
    pub stations: Option<u16>,
    /// BSS Load: share of time it found the channel busy, 0..=255.
    pub utilization: Option<u8>,
}

impl WifiBss {
    /// Fill the channel and load fields from the elements `ies`.
    pub fn with_elements(mut self, ies: &[u8]) -> Self {
        let op = ie::parse(ies, self.frequency_mhz);
        self.width_mhz = Some(op.width_mhz);
        self.center_mhz = Some(op.center_mhz);
        self.center2_mhz = op.center2_mhz;
        self.generation = op.generation;
        self.stations = op.stations;
        self.utilization = op.utilization;
        self
    }
}

/// How busy one channel was, as the driver counted it (nl80211 survey,
/// `NL80211_CMD_GET_SURVEY`). The times add up since the driver began
/// counting; many drivers fill only the channel in use, and leave the
/// others at zero or out (measured on mt7925e: only the one in use).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiSurvey {
    pub frequency_mhz: u32,
    /// The noise floor, dBm.
    pub noise_dbm: Option<i32>,
    /// The radio is on this channel now.
    pub in_use: bool,
    /// Time the radio listened here, ms.
    pub active_ms: Option<u64>,
    /// Of it, time the channel was busy (anybody sending, or noise above
    /// the energy-detect level), ms.
    pub busy_ms: Option<u64>,
    /// Of it, receiving and sending, ms.
    pub rx_ms: Option<u64>,
    pub tx_ms: Option<u64>,
}

/// Where a radio is on its way to a network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WifiState {
    /// Not trying: no network was given, or it was told to leave.
    #[default]
    Idle,
    /// Looking for the network.
    Searching,
    /// Found it: authenticating, associating, exchanging keys.
    Connecting,
    Connected,
    /// The radio is blocked by a switch, a key or the firmware (rfkill).
    Blocked,
}

impl WifiState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Searching => "searching",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Blocked => "blocked",
        }
    }
}

/// Why the last attempt did not end in `Connected`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum WifiFailure {
    /// The key exchange failed. With WPA2 the access point never says the
    /// passphrase is wrong, it just stops answering: weak signal or a MAC
    /// filter look the same. "Probably", then.
    WrongKey,
    /// No access point with that name (and security) answered the scan.
    NotFound,
    /// The access point refused: its status or reason code, in words.
    Rejected(String),
    /// Several attempts in a row ended in nothing and the platform paused
    /// the network for a while. After a `WrongKey` or a `Rejected` it is
    /// their consequence, not a new cause.
    NoAnswer,
    /// Anything else, as the platform said it.
    Other(String),
}

impl WifiFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongKey => "wrong-key",
            Self::NotFound => "not-found",
            Self::Rejected(_) => "rejected",
            Self::NoAnswer => "no-answer",
            Self::Other(_) => "error",
        }
    }

    /// What the operator reads.
    pub fn text(&self) -> String {
        match self {
            Self::WrongKey => "the key exchange failed: probably a wrong passphrase (a very weak \
                               signal or a MAC filter on the access point look the same)"
                .into(),
            Self::NotFound => "no access point with that name and security answered the scan \
                               (out of range, another band, a hidden network without hidden=yes, \
                               or a channel the country does not allow)"
                .into(),
            Self::Rejected(why) => format!("the access point refused: {why}"),
            Self::NoAnswer => "several attempts in a row failed (the access point does not \
                               answer, or refuses without saying why)"
                .into(),
            Self::Other(why) => why.clone(),
        }
    }
}

/// A radio's link right now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiStatus {
    pub state: WifiState,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub frequency_mhz: Option<u32>,
    pub signal_dbm: Option<i32>,
    /// The transmit rate the driver reports, Mbit/s.
    pub rate_mbps: Option<u32>,
    /// What was negotiated: `wpa2`, `wpa3`, `open`.
    pub security: Option<String>,
    /// Management frame protection in use.
    pub pmf: Option<bool>,
    /// G1.30g: the noise floor the driver measures, dBm (many do not).
    pub noise_dbm: Option<i32>,
    /// Width of the channel in use, MHz (20, 40, 80, 160, 320).
    pub width_mhz: Option<u32>,
    /// Centre of the whole channel, MHz (differs from `frequency_mhz` on
    /// 40 MHz and wider).
    pub center_mhz: Option<u32>,
    /// The Wi-Fi generation negotiated: 4 (802.11n), 5 (ac), 6 (ax), 7 (be).
    pub generation: Option<u8>,
    /// The pairwise cipher: `CCMP`, `GCMP-256`.
    pub cipher: Option<String>,
    /// What the driver keeps about the link to the access point (nl80211
    /// station info); `None` when not connected or not readable.
    pub link: Option<WifiLink>,
}

/// One direction's rate as the driver reports it (nl80211 rate info).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiRate {
    /// kbit/s (the kernel's unit is 100 kbit/s: 5.5 Mbit/s is 5500).
    pub kbps: Option<u32>,
    /// `legacy`, `ht` (802.11n), `vht` (ac), `he` (ax), `eht` (be).
    pub mode: Option<String>,
    /// Modulation and coding scheme index of `mode`.
    pub mcs: Option<u8>,
    /// Spatial streams (VHT, HE, EHT; HT folds them into the MCS).
    pub nss: Option<u8>,
    pub width_mhz: Option<u32>,
    /// Guard interval, ns: 800 or 400 (HT/VHT short GI); 800, 1600, 3200 (HE).
    pub guard_ns: Option<u32>,
}

/// The station's view of its link to the access point.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiLink {
    pub tx: Option<WifiRate>,
    pub rx: Option<WifiRate>,
    /// Average of the frames heard from the access point, dBm.
    pub signal_avg_dbm: Option<i32>,
    /// Average of its beacons, dBm.
    pub beacon_signal_dbm: Option<i32>,
    /// Per receive chain (antenna), dBm.
    pub chain_signal_dbm: Vec<i32>,
    pub tx_packets: Option<u64>,
    pub rx_packets: Option<u64>,
    /// Frames sent again (no acknowledgement the first time).
    pub tx_retries: Option<u64>,
    /// Frames given up on after every retry.
    pub tx_failed: Option<u64>,
    /// Beacons expected and not heard.
    pub beacon_loss: Option<u64>,
    /// Seconds since this association began.
    pub connected_secs: Option<u64>,
    /// Milliseconds since anything was heard from the access point.
    pub inactive_ms: Option<u64>,
}

/// Something that happened to a radio since the last [`WifiPort::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiEvent {
    Connected {
        bssid: String,
    },
    /// Lost or left; `reason` in words.
    Disconnected {
        reason: String,
    },
    Failed(WifiFailure),
    /// A scan ended: [`WifiPort::scan_results`] has what it heard.
    ScanDone,
    ScanFailed(String),
    /// The regulatory domain in force changed (`None`: the world domain).
    Country(Option<String>),
    /// Blocked or unblocked by a switch or a key.
    Blocked(bool),
}

/// Bounds on what a platform hands back (a scan in a dense place).
pub const MAX_SCAN_RESULTS: usize = 256;
pub const MAX_EVENTS: usize = 64;
/// Channels of a survey at most (2.4, 5 and 6 GHz have some 100).
pub const MAX_SURVEY: usize = 256;
/// Spectral samples a platform keeps for the engine's next read; the
/// older ones are dropped (a radio sends thousands a second).
pub const MAX_SPECTRAL_PENDING: usize = 4096;
/// The longest spectral scan, s.
pub const MAX_SPECTRAL_SECS: u32 = 600;

/// One radio. Calls return at once: joining a network takes seconds, and
/// its outcome comes through [`events`](Self::events) and
/// [`status`](Self::status).
pub trait WifiPort: Send {
    /// Join `net`, leaving whatever it was on.
    fn join(&mut self, net: &WifiNetwork) -> Result<(), HalError>;
    /// Leave, and stop trying.
    fn leave(&mut self) -> Result<(), HalError>;
    /// Start a scan. `ScanDone` says when; a radio that is connected stays
    /// connected (the driver scans between the network's beacons).
    fn scan(&mut self) -> Result<(), HalError>;
    /// What the last scan heard, strongest first, at most
    /// [`MAX_SCAN_RESULTS`].
    fn scan_results(&mut self) -> Result<Vec<WifiBss>, HalError>;
    fn status(&mut self) -> Result<WifiStatus, HalError>;
    /// What happened since the last call, oldest first, at most
    /// [`MAX_EVENTS`].
    fn events(&mut self) -> Vec<WifiEvent>;
    /// G1.30i: the channels' survey as of the last scan, at most
    /// [`MAX_SURVEY`]. Empty: the driver gives none.
    fn survey(&mut self) -> Vec<WifiSurvey> {
        Vec::new()
    }
    /// G1.30i: start a spectral scan for `secs` seconds (at most
    /// [`MAX_SPECTRAL_SECS`]): of the channel in use (`range` `None`), or
    /// of the channels of `range` (MHz) the radio visits while it scans
    /// (the engine asks for the scans). Only on radios with
    /// [`WifiRadio::spectral_scan`].
    fn spectral_start(&mut self, secs: u32, range: Option<(u32, u32)>) -> Result<(), HalError> {
        let _ = (secs, range);
        Err(HalError::Unsupported(
            "this radio has no spectral scan".into(),
        ))
    }
    /// Stop the spectral scan now.
    fn spectral_stop(&mut self) {}
    /// The samples since the last call, oldest first, at most `max`.
    fn spectral_samples(&mut self, max: usize) -> Vec<SpectralSample> {
        let _ = max;
        Vec::new()
    }
}

/// What a platform knows about a radio's hardware.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiRadio {
    /// The kernel's driver (`iwlwifi`, `rtw89_8852be`, `mac80211_hwsim`).
    pub driver: Option<String>,
    /// The card decides its own channels and power (Intel's firmware reads
    /// the country from the air and its own tables): the configured country
    /// is asked for and not necessarily followed.
    pub self_managed: bool,
    /// G1.30g: the wiphy (`phy0`).
    pub phy: Option<String>,
    /// The firmware the card runs, as the driver announced it.
    pub firmware: Option<String>,
    /// What the radio can do in each band.
    pub bands: Vec<WifiBand>,
    /// Antennas (chains) the card has for sending and receiving.
    pub antennas_tx: Option<u32>,
    pub antennas_rx: Option<u32>,
    /// Transmit power in use now, dBm.
    pub tx_power_dbm: Option<i32>,
    /// Off by a switch or key: `soft` (rfkill in software), `hard` (a
    /// physical switch); `None`: free (or not known).
    pub blocked: Option<String>,
    /// G1.30i: the radio hands over FFT samples (Qualcomm Atheros:
    /// ath9k, ath10k, ath11k, through debugfs).
    pub spectral_scan: bool,
    /// Why not, in words, when it does not.
    pub spectral_why_not: Option<String>,
    /// G1.30j: the driver offers monitor mode (`None`: not known).
    pub monitor: Option<bool>,
    /// G1.30j: a monitor interface runs beside the station, which stays
    /// connected (mac80211 drivers: monitor is a software interface type).
    pub monitor_shared: Option<bool>,
}

/// One band of a radio (nl80211 wiphy bands).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiBand {
    /// `2ghz`, `5ghz`, `6ghz`.
    pub band: String,
    /// IEEE 802.11 amendments it speaks: `b`, `g`, `a`, `n`, `ac`, `ax`, `be`.
    pub standards: Vec<String>,
    /// Widest channel, MHz.
    pub max_width_mhz: Option<u32>,
    /// The channels the regulatory domain in force allows, with their power.
    pub channels: Vec<WifiChannel>,
}

/// One channel of a band.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiChannel {
    pub mhz: u32,
    /// Most the regulatory domain allows here, dBm.
    pub max_power_dbm: Option<i32>,
    /// Radar detection (DFS) required before sending.
    pub radar: bool,
    /// Not allowed in the domain in force.
    pub disabled: bool,
}

/// Bounds on what a platform reports about one radio.
pub const MAX_BANDS: usize = 4;
pub const MAX_CHANNELS: usize = 128;
pub const MAX_CHAINS: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_never_printed() {
        let n = WifiNetwork {
            ssid: "Casa".into(),
            security: JoinSecurity::Auto,
            key: "segredo-de-verdade".into(),
            hidden: false,
            band_mhz: None,
            bssid: None,
        };
        let text = format!("{n:?}");
        assert!(text.contains("Casa") && text.contains("***"), "{text}");
        assert!(!text.contains("segredo"), "{text}");
    }

    #[test]
    fn failures_have_a_code_and_words() {
        for f in [
            WifiFailure::WrongKey,
            WifiFailure::NotFound,
            WifiFailure::Rejected("too many stations".into()),
            WifiFailure::Other("the supplicant is not running".into()),
        ] {
            assert!(!f.code().is_empty());
            assert!(f.text().len() > 10, "{f:?}");
        }
        assert!(WifiFailure::WrongKey.text().contains("probably"));
        assert!(BssSecurity::Wpa3 > BssSecurity::Open);
        assert_eq!(WifiState::default(), WifiState::Idle);
    }
}

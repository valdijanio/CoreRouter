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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BssSecurity {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WifiBss {
    /// Empty: the network hides its name.
    pub ssid: String,
    pub bssid: String,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub security: BssSecurity,
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
}

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

//! A Wi-Fi radio as an access point, as the platform offers it (G1.30a).
//!
//! The engine says which network the radio announces (name, security,
//! channel, width, country, bridge) and reads what became of it: whether
//! it is up, waiting on radar detection, or failed, and the stations
//! associated with it. On Linux that is `hostapd` (the authentication runs
//! in user space) and nl80211; the virtual lab has an access point that a
//! few made-up clients join. The data path is the kernel's.
//!
//! The passphrase crosses this boundary in clear and is kept by neither
//! side longer than the call: the config has it sealed.

use serde::Serialize;

use crate::HalError;
use crate::wifi::WifiLink;

/// How the access point secures its network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApSecurity {
    /// WPA2 and WPA3 together (the transition mode): WPA3 clients use SAE
    /// with management frame protection, older ones WPA2-PSK.
    Wpa2Wpa3,
    /// WPA3-Personal only (SAE, management frame protection required).
    Wpa3,
    /// WPA2-Personal only.
    Wpa2,
    /// No encryption.
    Open,
}

/// The network an access point announces.
#[derive(Clone, PartialEq, Eq)]
pub struct WifiAp {
    pub ssid: String,
    pub security: ApSecurity,
    /// The passphrase (8 to 63 characters) or the 64-digit key (WPA2
    /// only); empty for an open network.
    pub key: String,
    /// Beacons without the name (clients must know it).
    pub hidden: bool,
    /// The primary channel's centre, MHz.
    pub frequency_mhz: u32,
    /// The whole channel: 20, 40, 80 or 160 MHz.
    pub width_mhz: u32,
    /// Centre of the whole channel, MHz (equal to `frequency_mhz` at 20).
    pub center_mhz: u32,
    /// ISO 3166-1 alpha-2, as the regulatory domain names it.
    pub country: String,
    /// The bridge the access point is a port of: its clients' frames go
    /// there.
    pub bridge: Option<String>,
    /// What the radio speaks in this band: 802.11n, ac (5 GHz), ax.
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    /// Radar detection is needed before sending (a DFS channel).
    pub radar: bool,
    /// G1.30m: takes station-bridges (`None`: clients only).
    pub backhaul: Option<ApBackhaul>,
}

/// G1.30m: an access point that takes station-bridges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApBackhaul {
    /// The registered peers only (no plain clients).
    pub only: bool,
    /// Who gets four addresses; any other station that asks is sent away.
    pub peers: Vec<ApPeer>,
}

/// G1.30m: a registered peer: its MAC (`aa:bb:cc:dd:ee:ff`) and the name
/// its link gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApPeer {
    pub mac: String,
    pub name: String,
}

/// Never the key: a `{:?}` goes to logs.
impl std::fmt::Debug for WifiAp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WifiAp")
            .field("ssid", &self.ssid)
            .field("security", &self.security)
            .field("key", &if self.key.is_empty() { "" } else { "***" })
            .field("hidden", &self.hidden)
            .field("frequency_mhz", &self.frequency_mhz)
            .field("width_mhz", &self.width_mhz)
            .field("center_mhz", &self.center_mhz)
            .field("country", &self.country)
            .field("bridge", &self.bridge)
            .field("ht", &self.ht)
            .field("vht", &self.vht)
            .field("he", &self.he)
            .field("radar", &self.radar)
            .field("backhaul", &self.backhaul)
            .finish()
    }
}

/// Where an access point is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApState {
    /// Not started (or stopped).
    #[default]
    Stopped,
    /// Started; not sending beacons yet.
    Starting,
    /// Listening for radar before it may send (DFS channel availability
    /// check: 60 s, 10 min on the weather radar channels).
    RadarCheck,
    /// The channel may not be used to start a network here (no-IR).
    NoIr,
    /// Up: sending beacons and taking clients.
    Running,
    /// It would not start, or stopped by itself (radar heard, driver
    /// gone): the error says why.
    Failed,
}

impl ApState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::RadarCheck => "radar-check",
            Self::NoIr => "no-ir",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }
}

/// One station associated with the access point (the registration table).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiClient {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// Through the 4-way handshake (or SAE): it may send data.
    pub authorized: bool,
    /// What it joined with: `wpa3`, `wpa2`, `open`.
    pub security: Option<String>,
    /// G1.30m: a registered peer's name, when it is one with its
    /// four-address link up.
    pub peer: Option<String>,
    /// The Wi-Fi generation it speaks with the access point: 4 (n), 5
    /// (ac), 6 (ax), 7 (be).
    pub generation: Option<u8>,
    /// What the driver keeps about the link (nl80211 station info).
    pub link: WifiLink,
}

/// An access point right now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WifiApStatus {
    pub state: ApState,
    /// The primary channel in use, MHz.
    pub frequency_mhz: Option<u32>,
    pub width_mhz: Option<u32>,
    /// Seconds of radar check left (state `radar-check`).
    pub radar_check_secs: Option<u32>,
    /// Why it failed or stopped, in words.
    pub error: Option<String>,
    /// At most [`MAX_CLIENTS`], strongest first.
    pub clients: Vec<WifiClient>,
}

/// Something that happened to an access point since the last
/// [`WifiApPort::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiApEvent {
    /// Beacons are going out.
    Up,
    /// Stopped by itself; `reason` in words.
    Down {
        reason: String,
    },
    /// Radar check started on a DFS channel (`secs` long).
    RadarCheck {
        secs: u32,
    },
    /// Radar heard on the channel: the access point must leave it.
    Radar {
        frequency_mhz: u32,
    },
    /// A station joined (`authorized`: through the handshake).
    Joined {
        mac: String,
    },
    Left {
        mac: String,
    },
    /// A station failed the handshake (a wrong passphrase, most often).
    Refused {
        mac: String,
        reason: String,
    },
    /// It would not start.
    Failed(String),
    /// G1.30m: a registered peer's four-address link is up, as `name`.
    PeerUp {
        mac: String,
        name: String,
    },
    /// G1.30m: and gone.
    PeerDown {
        mac: String,
        name: String,
    },
}

/// Stations reported at most (a crowded access point).
pub const MAX_CLIENTS: usize = 256;
/// Events kept between two reads.
pub const MAX_AP_EVENTS: usize = 64;

/// One radio as an access point. Calls return at once: starting takes a
/// second (or a minute of radar check), and what came of it comes through
/// [`events`](Self::events) and [`status`](Self::status).
pub trait WifiApPort: Send {
    /// Announce `ap`, replacing whatever was announced (its clients leave).
    fn start(&mut self, ap: &WifiAp) -> Result<(), HalError>;
    /// Stop announcing; the clients leave.
    fn stop(&mut self) -> Result<(), HalError>;
    fn status(&mut self) -> Result<WifiApStatus, HalError>;
    /// What happened since the last call, oldest first, at most
    /// [`MAX_AP_EVENTS`].
    fn events(&mut self) -> Vec<WifiApEvent>;
}

/// The centre of the whole channel and whether the 40 MHz pair lies above
/// the primary (`HT40+`), for a primary of `mhz` and a width of `width`
/// MHz; `None`: no such channel (IEEE 802.11-2020 Annex E, the 20 MHz
/// channels each width spans in the 2.4 and 5 GHz bands).
pub fn channel_block(mhz: u32, width: u32) -> Option<ChannelBlock> {
    let primaries = |lo: u32, n: u32| (0..n).map(move |i| lo + 20 * i);
    match (mhz, width) {
        (_, 20) => Some(ChannelBlock {
            center_mhz: mhz,
            above: None,
            members: vec![mhz],
        }),
        // 2.4 GHz: HT40 with the secondary 4 channels (20 MHz) above or
        // below; above while there is room (channels 1 to 7 in most
        // countries), else below.
        (2412..=2472, 40) => {
            let above = mhz + 20 <= 2472;
            let second = if above {
                mhz + 20
            } else {
                mhz.checked_sub(20)?
            };
            if second < 2412 {
                return None;
            }
            Some(ChannelBlock {
                center_mhz: (mhz + second) / 2,
                above: Some(above),
                members: vec![mhz.min(second), mhz.max(second)],
            })
        }
        (5170..=5895, 40 | 80 | 160) => {
            // The blocks of the 5 GHz band: their lowest 20 MHz channel and
            // how many they have.
            let blocks: &[(u32, u32)] = match width {
                40 => &[
                    (5180, 2),
                    (5220, 2),
                    (5260, 2),
                    (5300, 2),
                    (5500, 2),
                    (5540, 2),
                    (5580, 2),
                    (5620, 2),
                    (5660, 2),
                    (5700, 2),
                    (5745, 2),
                    (5785, 2),
                    (5825, 2),
                ],
                80 => &[
                    (5180, 4),
                    (5260, 4),
                    (5500, 4),
                    (5580, 4),
                    (5660, 4),
                    (5745, 4),
                    (5825, 4),
                ],
                _ => &[(5180, 8), (5500, 8), (5745, 8)],
            };
            let (lo, n) = blocks
                .iter()
                .copied()
                .find(|(lo, n)| primaries(*lo, *n).any(|f| f == mhz))?;
            let members: Vec<u32> = primaries(lo, n).collect();
            let center = lo + 10 * (n - 1);
            // The 40 MHz pair the primary is in: above if it is the lower.
            let above = (mhz - lo).is_multiple_of(40);
            Some(ChannelBlock {
                center_mhz: center,
                above: Some(above),
                members,
            })
        }
        _ => None,
    }
}

/// The 20 MHz channels a channel of some width covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBlock {
    pub center_mhz: u32,
    /// HT40: the secondary channel is above the primary (`None` at 20).
    pub above: Option<bool>,
    /// Every 20 MHz channel's centre, low to high.
    pub members: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_blocks() {
        // 2.4 GHz: channel 1 pairs up, 11 down.
        let b = channel_block(2412, 40).unwrap();
        assert_eq!((b.center_mhz, b.above), (2422, Some(true)));
        let b = channel_block(2462, 40).unwrap();
        assert_eq!((b.center_mhz, b.above), (2452, Some(false)));
        // 5 GHz 80 MHz: 36..48 → centre 42 (5210), 149..161 → 155 (5775).
        let b = channel_block(5200, 80).unwrap();
        assert_eq!(b.center_mhz, 5210);
        assert_eq!(b.members, vec![5180, 5200, 5220, 5240]);
        assert_eq!(b.above, Some(false), "40 is the upper of 36/40");
        assert_eq!(channel_block(5745, 80).unwrap().center_mhz, 5775);
        // 40 MHz: 44/48 → 46 (5230).
        let b = channel_block(5220, 40).unwrap();
        assert_eq!((b.center_mhz, b.above), (5230, Some(true)));
        // 160: 36..64 → 50 (5250).
        assert_eq!(channel_block(5300, 160).unwrap().center_mhz, 5250);
        // 149..177 (the 5.9 GHz extension) → 163 (5815); channel 14 has no
        // 40 MHz pair, 2.4 GHz no 80.
        assert_eq!(channel_block(5825, 160).unwrap().center_mhz, 5815);
        assert!(channel_block(2484, 40).is_none());
        assert!(channel_block(2437, 80).is_none());
        assert_eq!(channel_block(5180, 20).unwrap().members, vec![5180]);
    }

    #[test]
    fn the_key_is_never_printed() {
        let ap = WifiAp {
            ssid: "Casa".into(),
            security: ApSecurity::Wpa2Wpa3,
            key: "segredo-123".into(),
            hidden: false,
            frequency_mhz: 5180,
            width_mhz: 80,
            center_mhz: 5210,
            country: "BR".into(),
            bridge: None,
            ht: true,
            vht: true,
            he: true,
            radar: false,
            backhaul: None,
        };
        assert!(!format!("{ap:?}").contains("segredo"));
    }
}

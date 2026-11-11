//! nl80211 (G1.30g): what the kernel keeps about a radio and its link —
//! the rates and counters of the link to the access point
//! (`NL80211_CMD_GET_STATION`), what the card can do in each band
//! (`NL80211_CMD_GET_WIPHY`), its transmit power
//! (`NL80211_CMD_GET_INTERFACE`) and, G1.30i, how busy each channel was
//! (`NL80211_CMD_GET_SURVEY`). All four are read-only.
//!
//! The parsers are pure and walk hostile bytes: every value is read only
//! when its attribute has exactly the kernel's size, a nest that ends early
//! yields fewer attributes ([`crate::genl::attrs`]), and every list is cut
//! at the bounds of `corerouter_hal::wifi`.
//!
//! The numbers are those of Linux 6.18.59 (the image's kernel),
//! `include/uapi/linux/nl80211.h`; they are ABI and never change.

use std::collections::BTreeMap;

use corerouter_hal::wifi::{
    MAX_BANDS, MAX_CHAINS, MAX_CHANNELS, MAX_SURVEY, WifiBand, WifiChannel, WifiLink, WifiRate,
    WifiSurvey,
};

use crate::genl::{Attr, Attrs, attrs, find};

// `enum nl80211_commands` (nl80211.h l. 1387).
pub(crate) const CMD_GET_WIPHY: u8 = 1;
pub(crate) const CMD_GET_INTERFACE: u8 = 5;
pub(crate) const CMD_GET_STATION: u8 = 17;
/// G1.30i (checked compiling the header: 50).
pub(crate) const CMD_GET_SURVEY: u8 = 50;

// `enum nl80211_attrs` (l. 3077).
const ATTR_WIPHY: u16 = 1;
const ATTR_WIPHY_NAME: u16 = 2;
pub(crate) const ATTR_IFINDEX: u16 = 3;
const ATTR_MAC: u16 = 6;
const ATTR_STA_INFO: u16 = 21;
const ATTR_WIPHY_BANDS: u16 = 22;
/// G1.30i: the nest of a survey reply (84).
const ATTR_SURVEY_INFO: u16 = 84;
/// Signed mBm (l. 2028).
const ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const ATTR_WIPHY_ANTENNA_AVAIL_TX: u16 = 113;
const ATTR_WIPHY_ANTENNA_AVAIL_RX: u16 = 114;
/// A flag: the wiphy in many messages, with every band (l. 3361).
pub(crate) const ATTR_SPLIT_WIPHY_DUMP: u16 = 174;

// `enum nl80211_sta_info` (l. 4171): u32 counters, u8 signals (dBm, signed).
const STA_INFO_INACTIVE_TIME: u16 = 1;
const STA_INFO_TX_BITRATE: u16 = 8;
const STA_INFO_RX_PACKETS: u16 = 9;
const STA_INFO_TX_PACKETS: u16 = 10;
const STA_INFO_TX_RETRIES: u16 = 11;
const STA_INFO_TX_FAILED: u16 = 12;
const STA_INFO_SIGNAL_AVG: u16 = 13;
const STA_INFO_RX_BITRATE: u16 = 14;
const STA_INFO_CONNECTED_TIME: u16 = 16;
const STA_INFO_BEACON_LOSS: u16 = 18;
const STA_INFO_CHAIN_SIGNAL: u16 = 25;
const STA_INFO_BEACON_SIGNAL_AVG: u16 = 30;

// `enum nl80211_survey_info` (l. 4954): frequency u32, noise a u8
// holding a signed dBm, in-use a flag, the times u64 ms.
const SURVEY_FREQUENCY: u16 = 1;
const SURVEY_NOISE: u16 = 2;
const SURVEY_IN_USE: u16 = 3;
const SURVEY_TIME: u16 = 4;
const SURVEY_TIME_BUSY: u16 = 5;
const SURVEY_TIME_RX: u16 = 7;
const SURVEY_TIME_TX: u16 = 8;

// `enum nl80211_rate_info` (l. 4018).
const RATE_INFO_BITRATE: u16 = 1;
const RATE_INFO_MCS: u16 = 2;
const RATE_INFO_40_MHZ_WIDTH: u16 = 3;
const RATE_INFO_SHORT_GI: u16 = 4;
const RATE_INFO_BITRATE32: u16 = 5;
const RATE_INFO_VHT_MCS: u16 = 6;
const RATE_INFO_VHT_NSS: u16 = 7;
const RATE_INFO_80_MHZ_WIDTH: u16 = 8;
/// "unused - 80+80 is treated the same as 160" (l. 3980).
const RATE_INFO_80P80_MHZ_WIDTH: u16 = 9;
const RATE_INFO_160_MHZ_WIDTH: u16 = 10;
const RATE_INFO_HE_MCS: u16 = 13;
const RATE_INFO_HE_NSS: u16 = 14;
/// `enum nl80211_he_gi` (l. 3853): 0 = 0.8 µs, 1 = 1.6, 2 = 3.2.
const RATE_INFO_HE_GI: u16 = 15;
const RATE_INFO_320_MHZ_WIDTH: u16 = 18;
const RATE_INFO_EHT_MCS: u16 = 19;
const RATE_INFO_EHT_NSS: u16 = 20;
/// `enum nl80211_eht_gi` (l. 3897): as HE's.
const RATE_INFO_EHT_GI: u16 = 21;

// `enum nl80211_band` (l. 5769); 60 GHz (2) and the others are left out.
const BAND_2GHZ: u16 = 0;
const BAND_5GHZ: u16 = 1;
const BAND_6GHZ: u16 = 3;

// `enum nl80211_band_attr` (l. 4433).
const BAND_ATTR_FREQS: u16 = 1;
/// u16, the HT Capabilities Info field.
const BAND_ATTR_HT_CAPA: u16 = 4;
/// u32, the VHT Capabilities Info field.
const BAND_ATTR_VHT_CAPA: u16 = 8;
const BAND_ATTR_IFTYPE_DATA: u16 = 9;

// `enum nl80211_band_iftype_attr` (l. 4381).
const BAND_IFTYPE_ATTR_IFTYPES: u16 = 1;
const BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
const BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
/// `enum nl80211_iftype` (l. 3758).
const IFTYPE_STATION: u16 = 2;

// `enum nl80211_frequency_attr` (l. 4590).
const FREQUENCY_ATTR_FREQ: u16 = 1;
const FREQUENCY_ATTR_DISABLED: u16 = 2;
const FREQUENCY_ATTR_RADAR: u16 = 5;
/// u32, mBm.
const FREQUENCY_ATTR_MAX_TX_POWER: u16 = 6;

// Capability bits, Linux 6.18.59 `include/linux/ieee80211-{ht,vht,he,eht}.h`.
/// `IEEE80211_HT_CAP_SUP_WIDTH_20_40`.
const HT_CAP_40: u16 = 0x0002;
/// `IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK`: 160, or 160 and 80+80.
const VHT_CAP_160: u32 = 0x0000_000C;
/// `IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G`.
const HE_PHY0_40_2G: u8 = 0x02;
/// `…_40MHZ_80MHZ_IN_5G` (5 and 6 GHz).
const HE_PHY0_80: u8 = 0x04;
/// `…_160MHZ_IN_5G` | `…_80PLUS80_MHZ_IN_5G`.
const HE_PHY0_160: u8 = 0x18;
/// `IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ`.
const EHT_PHY0_320: u8 = 0x02;

/// Messages of a wiphy's split dump taken at most: one per channel of every
/// band and a dozen more (a tri-band card is some 120).
pub(crate) const MAX_WIPHY_MESSAGES: usize = 512;
/// Characters of a wiphy's name kept (`phy0`; the kernel allows 64).
const MAX_PHY_NAME: usize = 32;

/// A value of exactly the kernel's size (`nla_put_u8`/`u16`/`u32`): one of
/// another size is not this attribute.
fn exact<const N: usize>(a: &Attr<'_>) -> Option<[u8; N]> {
    a.data.try_into().ok()
}

fn u8_of(a: &Attr<'_>) -> Option<u8> {
    exact::<1>(a).map(|[b]| b)
}

fn u16_of(a: &Attr<'_>) -> Option<u16> {
    exact(a).map(u16::from_ne_bytes)
}

fn u32_of(a: &Attr<'_>) -> Option<u32> {
    exact(a).map(u32::from_ne_bytes)
}

/// A counter: u32 (the kernel's), or u64 should it grow.
fn counter(a: &Attr<'_>) -> Option<u64> {
    match a.data.len() {
        4 => u32_of(a).map(u64::from),
        8 => exact(a).map(u64::from_ne_bytes),
        _ => None,
    }
}

/// A signal: a u8 holding a signed dBm. 0 and above is no reading.
fn dbm(a: &Attr<'_>) -> Option<i32> {
    let v = i32::from(i8::from_ne_bytes([u8_of(a)?]));
    (v < 0).then_some(v)
}

/// mBm (hundredths of dBm, signed in a u32) → dBm.
fn mbm(raw: u32) -> i32 {
    i32::from_ne_bytes(raw.to_ne_bytes()) / 100
}

/// Guard interval of `enum nl80211_he_gi` / `nl80211_eht_gi`, ns.
fn he_guard(gi: u8) -> Option<u32> {
    match gi {
        0 => Some(800),
        1 => Some(1600),
        2 => Some(3200),
        _ => None,
    }
}

/// A nested `NL80211_STA_INFO_TX_BITRATE`/`RX_BITRATE` (the kernel's
/// `nl80211_put_sta_rate`). `None`: nothing in it.
pub(crate) fn rate(nest: Attrs<'_>) -> Option<WifiRate> {
    let (mut bitrate, mut bitrate32) = (None, None);
    let (mut ht, mut vht, mut he, mut eht) = (None, None, None, None);
    let (mut vht_nss, mut he_nss, mut eht_nss) = (None, None, None);
    let (mut he_gi, mut eht_gi, mut short_gi) = (None, None, false);
    let mut width = 20;
    for a in nest {
        match a.kind {
            RATE_INFO_BITRATE => bitrate = u16_of(&a),
            RATE_INFO_BITRATE32 => bitrate32 = u32_of(&a),
            RATE_INFO_MCS => ht = u8_of(&a),
            RATE_INFO_VHT_MCS => vht = u8_of(&a),
            RATE_INFO_VHT_NSS => vht_nss = u8_of(&a),
            RATE_INFO_HE_MCS => he = u8_of(&a),
            RATE_INFO_HE_NSS => he_nss = u8_of(&a),
            RATE_INFO_HE_GI => he_gi = u8_of(&a),
            RATE_INFO_EHT_MCS => eht = u8_of(&a),
            RATE_INFO_EHT_NSS => eht_nss = u8_of(&a),
            RATE_INFO_EHT_GI => eht_gi = u8_of(&a),
            RATE_INFO_SHORT_GI => short_gi = true,
            RATE_INFO_40_MHZ_WIDTH => width = width.max(40),
            RATE_INFO_80_MHZ_WIDTH => width = width.max(80),
            RATE_INFO_80P80_MHZ_WIDTH | RATE_INFO_160_MHZ_WIDTH => width = width.max(160),
            RATE_INFO_320_MHZ_WIDTH => width = width.max(320),
            _ => {}
        }
    }
    // 100 kbit/s; the u16 one is left out when the rate does not fit.
    let kbps = bitrate32
        .or(bitrate.map(u32::from))
        .filter(|r| *r > 0)
        .map(|r| r.saturating_mul(100));
    let ht_guard = Some(if short_gi { 400 } else { 800 });
    let (mode, mcs, nss, guard_ns) = if let Some(m) = eht {
        ("eht", Some(m), eht_nss, eht_gi.and_then(he_guard))
    } else if let Some(m) = he {
        ("he", Some(m), he_nss, he_gi.and_then(he_guard))
    } else if let Some(m) = vht {
        ("vht", Some(m), vht_nss, ht_guard)
    } else if let Some(m) = ht {
        ("ht", Some(m), None, ht_guard)
    } else if kbps.is_some() {
        ("legacy", None, None, None)
    } else {
        return None;
    };
    Some(WifiRate {
        kbps,
        mode: Some(mode.to_owned()),
        mcs,
        nss,
        width_mhz: Some(width),
        guard_ns,
    })
}

/// A nested `NL80211_ATTR_STA_INFO`.
pub(crate) fn link(info: Attrs<'_>) -> WifiLink {
    let mut l = WifiLink::default();
    for a in info {
        match a.kind {
            STA_INFO_TX_BITRATE => l.tx = rate(a.nested()),
            STA_INFO_RX_BITRATE => l.rx = rate(a.nested()),
            STA_INFO_SIGNAL_AVG => l.signal_avg_dbm = dbm(&a),
            STA_INFO_BEACON_SIGNAL_AVG => l.beacon_signal_dbm = dbm(&a),
            STA_INFO_CHAIN_SIGNAL => {
                l.chain_signal_dbm = a
                    .nested()
                    .filter_map(|c| dbm(&c))
                    .take(MAX_CHAINS)
                    .collect();
            }
            STA_INFO_TX_PACKETS => l.tx_packets = counter(&a),
            STA_INFO_RX_PACKETS => l.rx_packets = counter(&a),
            STA_INFO_TX_RETRIES => l.tx_retries = counter(&a),
            STA_INFO_TX_FAILED => l.tx_failed = counter(&a),
            STA_INFO_BEACON_LOSS => l.beacon_loss = counter(&a),
            STA_INFO_CONNECTED_TIME => l.connected_secs = counter(&a),
            STA_INFO_INACTIVE_TIME => l.inactive_ms = counter(&a),
            _ => {}
        }
    }
    l
}

/// `aa:bb:cc:dd:ee:ff` of a 6-byte `NL80211_ATTR_MAC`.
fn mac_text(a: &Attr<'_>) -> Option<String> {
    let b: [u8; 6] = exact(a)?;
    Some(
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The link to the access point among the messages of a station dump: the
/// entry of `bssid`, or the only one there is.
pub(crate) fn station<'a>(
    messages: impl IntoIterator<Item = &'a [u8]>,
    bssid: Option<&str>,
) -> Option<WifiLink> {
    let mut only = None;
    let mut count = 0usize;
    for m in messages {
        let Some(info) = find(attrs(m), ATTR_STA_INFO) else {
            continue;
        };
        let mac = find(attrs(m), ATTR_MAC).and_then(|a| mac_text(&a));
        if bssid.is_some_and(|b| mac.as_deref() == Some(b)) {
            return Some(link(info.nested()));
        }
        count = count.saturating_add(1);
        only = Some(info);
    }
    (count == 1)
        .then_some(only)
        .flatten()
        .map(|i| link(i.nested()))
}

/// G1.30i: one channel of a survey dump; `None` without a frequency.
/// A time of zero is no measure (the drivers leave the channels they did
/// not count at zero), and busy beyond active is not believed.
pub(crate) fn survey(message: &[u8]) -> Option<WifiSurvey> {
    let info = find(attrs(message), ATTR_SURVEY_INFO)?;
    let mut s = WifiSurvey::default();
    for a in info.nested() {
        let ms = || counter(&a).filter(|v| *v > 0);
        match a.kind {
            SURVEY_FREQUENCY => s.frequency_mhz = u32_of(&a)?,
            SURVEY_NOISE => s.noise_dbm = dbm(&a),
            SURVEY_IN_USE => s.in_use = true,
            SURVEY_TIME => s.active_ms = ms(),
            SURVEY_TIME_BUSY => s.busy_ms = ms(),
            SURVEY_TIME_RX => s.rx_ms = ms(),
            SURVEY_TIME_TX => s.tx_ms = ms(),
            _ => {}
        }
    }
    if s.frequency_mhz == 0 {
        return None;
    }
    if s.active_ms.is_none() || s.busy_ms > s.active_ms {
        s.busy_ms = None;
    }
    Some(s)
}

/// `NL80211_ATTR_WIPHY_TX_POWER_LEVEL` of a `GET_INTERFACE` reply, dBm.
pub(crate) fn tx_power(message: &[u8]) -> Option<i32> {
    find(attrs(message), ATTR_WIPHY_TX_POWER_LEVEL)
        .and_then(|a| u32_of(&a))
        .map(mbm)
}

/// What a band of the wiphy says, gathered over the messages of the dump.
#[derive(Debug, Default)]
struct Band {
    ht: Option<u16>,
    vht: Option<u32>,
    /// Byte 0 of the HE PHY capabilities for a station.
    he: Option<u8>,
    eht: Option<u8>,
    channels: Vec<WifiChannel>,
}

impl Band {
    fn add(&mut self, nest: Attrs<'_>) {
        for a in nest {
            match a.kind {
                BAND_ATTR_HT_CAPA => self.ht = u16_of(&a).or(self.ht),
                BAND_ATTR_VHT_CAPA => self.vht = u32_of(&a).or(self.vht),
                BAND_ATTR_IFTYPE_DATA => self.iftype_data(a.nested()),
                BAND_ATTR_FREQS => {
                    for f in a.nested() {
                        self.channel(f.nested());
                    }
                }
                _ => {}
            }
        }
    }

    /// The HE/EHT capabilities the card has as a station.
    fn iftype_data(&mut self, entries: Attrs<'_>) {
        for e in entries {
            let station = find(e.nested(), BAND_IFTYPE_ATTR_IFTYPES)
                .is_some_and(|t| t.nested().any(|f| f.kind == IFTYPE_STATION));
            if !station {
                continue;
            }
            for a in e.nested() {
                match a.kind {
                    BAND_IFTYPE_ATTR_HE_CAP_PHY => {
                        self.he = a.data.first().copied().or(self.he);
                    }
                    BAND_IFTYPE_ATTR_EHT_CAP_PHY => {
                        self.eht = a.data.first().copied().or(self.eht);
                    }
                    _ => {}
                }
            }
        }
    }

    fn channel(&mut self, nest: Attrs<'_>) {
        let mut ch = WifiChannel::default();
        for a in nest {
            match a.kind {
                FREQUENCY_ATTR_FREQ => ch.mhz = u32_of(&a).unwrap_or(0),
                FREQUENCY_ATTR_DISABLED => ch.disabled = true,
                FREQUENCY_ATTR_RADAR => ch.radar = true,
                FREQUENCY_ATTR_MAX_TX_POWER => ch.max_power_dbm = u32_of(&a).map(mbm),
                _ => {}
            }
        }
        let fits = self.channels.len() < MAX_CHANNELS;
        if ch.mhz > 0 && fits && !self.channels.iter().any(|c| c.mhz == ch.mhz) {
            self.channels.push(ch);
        }
    }

    fn standards(&self, band: u16) -> Vec<String> {
        let mut out: Vec<&str> = match band {
            BAND_2GHZ => vec!["b", "g"],
            BAND_5GHZ => vec!["a"],
            _ => Vec::new(),
        };
        if self.ht.is_some() && band != BAND_6GHZ {
            out.push("n");
        }
        if self.vht.is_some() && band == BAND_5GHZ {
            out.push("ac");
        }
        if self.he.is_some() {
            out.push("ax");
        }
        if self.eht.is_some() {
            out.push("be");
        }
        out.into_iter().map(str::to_owned).collect()
    }

    fn max_width(&self, band: u16) -> u32 {
        let he = self.he.unwrap_or(0);
        let mut w = 20;
        if self.ht.is_some_and(|c| c & HT_CAP_40 != 0) {
            w = 40;
        }
        if band == BAND_2GHZ {
            return if he & HE_PHY0_40_2G != 0 { 40 } else { w };
        }
        // VHT has 80 MHz always (IEEE 802.11-2020 §21.1.1).
        if (self.vht.is_some() && band == BAND_5GHZ) || he & HE_PHY0_80 != 0 {
            w = 80;
        }
        if self.vht.is_some_and(|c| c & VHT_CAP_160 != 0) || he & HE_PHY0_160 != 0 {
            w = 160;
        }
        if band == BAND_6GHZ && self.eht.is_some_and(|c| c & EHT_PHY0_320 != 0) {
            w = 320;
        }
        w
    }
}

/// A wiphy as its split dump describes it, message by message.
#[derive(Debug, Default)]
pub(crate) struct Wiphy {
    /// `NL80211_ATTR_WIPHY` of the first message: the others must match.
    index: Option<u32>,
    pub name: Option<String>,
    pub antennas_tx: Option<u32>,
    pub antennas_rx: Option<u32>,
    bands: BTreeMap<u16, Band>,
}

impl Wiphy {
    /// One message of the dump.
    pub fn add(&mut self, message: &[u8]) {
        if let Some(i) = find(attrs(message), ATTR_WIPHY).and_then(|a| u32_of(&a)) {
            if self.index.is_some_and(|mine| mine != i) {
                return;
            }
            self.index = Some(i);
        }
        for a in attrs(message) {
            match a.kind {
                ATTR_WIPHY_NAME => {
                    let name = a.str().filter(|n| {
                        !n.is_empty()
                            && n.len() <= MAX_PHY_NAME
                            && n.bytes().all(|b| b.is_ascii_graphic())
                    });
                    self.name = name.or(self.name.take());
                }
                // A bitmask of antennas: how many.
                ATTR_WIPHY_ANTENNA_AVAIL_TX => {
                    self.antennas_tx = u32_of(&a)
                        .map(u32::count_ones)
                        .filter(|n| *n > 0)
                        .or(self.antennas_tx);
                }
                ATTR_WIPHY_ANTENNA_AVAIL_RX => {
                    self.antennas_rx = u32_of(&a)
                        .map(u32::count_ones)
                        .filter(|n| *n > 0)
                        .or(self.antennas_rx);
                }
                ATTR_WIPHY_BANDS => {
                    for b in a.nested() {
                        if !matches!(b.kind, BAND_2GHZ | BAND_5GHZ | BAND_6GHZ) {
                            continue;
                        }
                        let known = self.bands.contains_key(&b.kind);
                        if !known && self.bands.len() >= MAX_BANDS {
                            continue;
                        }
                        self.bands.entry(b.kind).or_default().add(b.nested());
                    }
                }
                _ => {}
            }
        }
    }

    /// The bands, lowest first.
    pub fn bands(&self) -> Vec<WifiBand> {
        self.bands
            .iter()
            .map(|(&kind, b)| WifiBand {
                band: match kind {
                    BAND_2GHZ => "2ghz",
                    BAND_5GHZ => "5ghz",
                    _ => "6ghz",
                }
                .to_owned(),
                standards: b.standards(kind),
                max_width_mhz: Some(b.max_width(kind)),
                channels: b.channels.clone(),
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
pub(crate) use io::Nl80211;

#[cfg(target_os = "linux")]
mod io {
    use corerouter_hal::wifi::WifiLink;

    use super::{
        ATTR_IFINDEX, ATTR_SPLIT_WIPHY_DUMP, CMD_GET_INTERFACE, CMD_GET_STATION, CMD_GET_SURVEY,
        CMD_GET_WIPHY, MAX_SURVEY, MAX_WIPHY_MESSAGES, Wiphy, station, survey, tx_power,
    };
    use crate::genl::{Genl, GenlError, Msg};
    use corerouter_hal::wifi::WifiSurvey;

    /// cfg80211 in the kernel (see `crate::wifi_links`: asking for the
    /// family without it makes the kernel load it).
    const CFG80211: &str = "/sys/module/cfg80211";
    /// Stations of a station dump taken at most (one: the access point;
    /// a few with MLO).
    const MAX_STATIONS: usize = 16;

    /// A generic netlink socket with the nl80211 family looked up.
    pub(crate) struct Nl80211 {
        genl: Genl,
        family: u16,
    }

    impl Nl80211 {
        /// `None`: no cfg80211 in the kernel (no radio), or no socket.
        pub fn open() -> Option<Self> {
            if !std::path::Path::new(CFG80211).exists() {
                return None;
            }
            let mut genl = Genl::open().ok()?;
            let family = genl.family("nl80211").ok()?;
            Some(Self { genl, family })
        }

        /// The link to `bssid` of the station on `ifindex`.
        pub fn station(
            &mut self,
            ifindex: u32,
            bssid: Option<&str>,
        ) -> Result<Option<WifiLink>, GenlError> {
            let seq = self.genl.next_seq();
            let mut m = Msg::dump(self.family, CMD_GET_STATION, 0, seq);
            m.u32(ATTR_IFINDEX, ifindex);
            let replies = self.genl.call_up_to(m.finish(), seq, MAX_STATIONS)?;
            Ok(station(replies.iter().map(|(_, a)| a.as_slice()), bssid))
        }

        /// G1.30i: the survey of the radio behind `ifindex`, a channel per
        /// message, at most [`MAX_SURVEY`].
        pub fn survey(&mut self, ifindex: u32) -> Result<Vec<WifiSurvey>, GenlError> {
            let seq = self.genl.next_seq();
            let mut m = Msg::dump(self.family, CMD_GET_SURVEY, 0, seq);
            m.u32(ATTR_IFINDEX, ifindex);
            let replies = self.genl.call_up_to(m.finish(), seq, MAX_SURVEY)?;
            Ok(replies.iter().filter_map(|(_, a)| survey(a)).collect())
        }

        /// The transmit power of the interface, dBm.
        pub fn tx_power(&mut self, ifindex: u32) -> Result<Option<i32>, GenlError> {
            let seq = self.genl.next_seq();
            let mut m = Msg::new(self.family, CMD_GET_INTERFACE, 0, seq);
            m.u32(ATTR_IFINDEX, ifindex);
            let replies = self.genl.call(m.finish(), seq)?;
            Ok(replies.iter().find_map(|(_, a)| tx_power(a)))
        }

        /// The wiphy behind `ifindex`: the split dump (without it the
        /// kernel leaves out the 6 GHz band, `nl80211_send_wiphy`), filtered
        /// by the interface (`nl80211_dump_wiphy_parse`).
        pub fn wiphy(&mut self, ifindex: u32) -> Result<Wiphy, GenlError> {
            let seq = self.genl.next_seq();
            let mut m = Msg::dump(self.family, CMD_GET_WIPHY, 0, seq);
            m.u32(ATTR_IFINDEX, ifindex).flag(ATTR_SPLIT_WIPHY_DUMP);
            let replies = self.genl.call_up_to(m.finish(), seq, MAX_WIPHY_MESSAGES)?;
            let mut w = Wiphy::default();
            for (_, a) in &replies {
                w.add(a);
            }
            Ok(w)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One attribute, padded to 4 bytes.
    fn nla(kind: u16, data: &[u8]) -> Vec<u8> {
        let len = u16::try_from(4 + data.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(4) * 4, 0);
        out
    }

    fn nest(kind: u16, parts: &[Vec<u8>]) -> Vec<u8> {
        nla(kind | 0x8000, &parts.concat())
    }

    fn u8a(kind: u16, v: u8) -> Vec<u8> {
        nla(kind, &[v])
    }

    fn u16a(kind: u16, v: u16) -> Vec<u8> {
        nla(kind, &v.to_ne_bytes())
    }

    fn u32a(kind: u16, v: u32) -> Vec<u8> {
        nla(kind, &v.to_ne_bytes())
    }

    fn s8a(kind: u16, v: i8) -> Vec<u8> {
        nla(kind, &v.to_ne_bytes())
    }

    fn flag(kind: u16) -> Vec<u8> {
        nla(kind, &[])
    }

    const AP: [u8; 6] = [0xd8, 0x47, 0x32, 0xaa, 0xbb, 0xcc];

    /// One message of a station dump: the MAC and the station info.
    fn station_msg(mac: [u8; 6], info: &[Vec<u8>]) -> Vec<u8> {
        [
            u32a(ATTR_IFINDEX, 4),
            nla(ATTR_MAC, &mac),
            nest(ATTR_STA_INFO, info),
        ]
        .concat()
    }

    fn u64a(kind: u16, v: u64) -> Vec<u8> {
        nla(kind, &v.to_ne_bytes())
    }

    #[test]
    fn a_survey_with_one_channel_counted() {
        // As mt7925e answers (measured on the host, 2026-11-11): the
        // channel in use counted, the others at zero.
        let used = nest(
            ATTR_SURVEY_INFO,
            &[
                u32a(SURVEY_FREQUENCY, 5500),
                s8a(SURVEY_NOISE, -92),
                flag(SURVEY_IN_USE),
                u64a(SURVEY_TIME, 60_000),
                u64a(SURVEY_TIME_BUSY, 9_000),
                u64a(SURVEY_TIME_RX, 7_000),
                u64a(SURVEY_TIME_TX, 500),
            ],
        );
        let s = survey(&[u32a(ATTR_IFINDEX, 4), used].concat()).unwrap();
        assert_eq!(
            s,
            WifiSurvey {
                frequency_mhz: 5500,
                noise_dbm: Some(-92),
                in_use: true,
                active_ms: Some(60_000),
                busy_ms: Some(9_000),
                rx_ms: Some(7_000),
                tx_ms: Some(500),
            }
        );
        let zero = nest(
            ATTR_SURVEY_INFO,
            &[
                u32a(SURVEY_FREQUENCY, 2412),
                u64a(SURVEY_TIME, 0),
                u64a(SURVEY_TIME_BUSY, 0),
            ],
        );
        let s = survey(&zero).unwrap();
        assert_eq!((s.active_ms, s.busy_ms, s.in_use), (None, None, false));
        // Busy beyond active, and no frequency.
        let odd = nest(
            ATTR_SURVEY_INFO,
            &[
                u32a(SURVEY_FREQUENCY, 2412),
                u64a(SURVEY_TIME, 10),
                u64a(SURVEY_TIME_BUSY, 99),
            ],
        );
        assert_eq!(survey(&odd).unwrap().busy_ms, None);
        assert_eq!(
            survey(&nest(ATTR_SURVEY_INFO, &[flag(SURVEY_IN_USE)])),
            None
        );
    }

    #[test]
    fn a_station_with_he_rates() {
        let info = vec![
            u32a(STA_INFO_INACTIVE_TIME, 120),
            u32a(STA_INFO_RX_PACKETS, 50_000),
            u32a(STA_INFO_TX_PACKETS, 40_000),
            u32a(STA_INFO_TX_RETRIES, 321),
            u32a(STA_INFO_TX_FAILED, 3),
            s8a(STA_INFO_SIGNAL_AVG, -48),
            s8a(STA_INFO_BEACON_SIGNAL_AVG, -50),
            u32a(STA_INFO_CONNECTED_TIME, 3600),
            u32a(STA_INFO_BEACON_LOSS, 2),
            nest(
                STA_INFO_CHAIN_SIGNAL,
                &[s8a(0, -47), s8a(1, -52), u16a(2, 7)],
            ),
            nest(
                STA_INFO_TX_BITRATE,
                &[
                    u16a(RATE_INFO_BITRATE, 12010),
                    u32a(RATE_INFO_BITRATE32, 12010),
                    u8a(RATE_INFO_HE_MCS, 11),
                    u8a(RATE_INFO_HE_NSS, 2),
                    u8a(RATE_INFO_HE_GI, 0),
                    u8a(16, 0), // HE_DCM: not used
                    flag(RATE_INFO_80_MHZ_WIDTH),
                ],
            ),
            nest(
                STA_INFO_RX_BITRATE,
                &[
                    u32a(RATE_INFO_BITRATE32, 8647),
                    u8a(RATE_INFO_HE_MCS, 9),
                    u8a(RATE_INFO_HE_NSS, 2),
                    u8a(RATE_INFO_HE_GI, 1),
                    flag(RATE_INFO_80_MHZ_WIDTH),
                ],
            ),
        ];
        let msg = station_msg(AP, &info);
        let l = station([msg.as_slice()], Some("d8:47:32:aa:bb:cc")).unwrap();
        let tx = l.tx.clone().unwrap();
        assert_eq!(
            tx,
            WifiRate {
                kbps: Some(1_201_000),
                mode: Some("he".into()),
                mcs: Some(11),
                nss: Some(2),
                width_mhz: Some(80),
                guard_ns: Some(800),
            }
        );
        let rx = l.rx.clone().unwrap();
        assert_eq!(
            (rx.kbps, rx.mcs, rx.guard_ns),
            (Some(864_700), Some(9), Some(1600))
        );
        assert_eq!(
            (l.signal_avg_dbm, l.beacon_signal_dbm),
            (Some(-48), Some(-50))
        );
        // The chain with a u16 is not a chain reading.
        assert_eq!(l.chain_signal_dbm, vec![-47, -52]);
        assert_eq!(
            (l.tx_packets, l.rx_packets, l.tx_retries, l.tx_failed),
            (Some(40_000), Some(50_000), Some(321), Some(3))
        );
        assert_eq!(
            (l.beacon_loss, l.connected_secs, l.inactive_ms),
            (Some(2), Some(3600), Some(120))
        );
    }

    #[test]
    fn vht_ht_eht_and_legacy_rates() {
        let vht = rate(attrs(
            &[
                u32a(RATE_INFO_BITRATE32, 8667),
                u8a(RATE_INFO_VHT_MCS, 9),
                u8a(RATE_INFO_VHT_NSS, 2),
                flag(RATE_INFO_SHORT_GI),
                flag(RATE_INFO_80_MHZ_WIDTH),
            ]
            .concat(),
        ))
        .unwrap();
        assert_eq!(
            (
                vht.mode.as_deref(),
                vht.mcs,
                vht.nss,
                vht.width_mhz,
                vht.guard_ns
            ),
            (Some("vht"), Some(9), Some(2), Some(80), Some(400))
        );
        let ht = rate(attrs(
            &[
                u16a(RATE_INFO_BITRATE, 1500),
                u8a(RATE_INFO_MCS, 15),
                flag(RATE_INFO_40_MHZ_WIDTH),
            ]
            .concat(),
        ))
        .unwrap();
        assert_eq!(
            (
                ht.kbps,
                ht.mode.as_deref(),
                ht.mcs,
                ht.nss,
                ht.width_mhz,
                ht.guard_ns
            ),
            (
                Some(150_000),
                Some("ht"),
                Some(15),
                None,
                Some(40),
                Some(800)
            )
        );
        let eht = rate(attrs(
            &[
                u32a(RATE_INFO_BITRATE32, 57_647),
                u8a(RATE_INFO_EHT_MCS, 13),
                u8a(RATE_INFO_EHT_NSS, 2),
                u8a(RATE_INFO_EHT_GI, 2),
                flag(RATE_INFO_160_MHZ_WIDTH),
                flag(RATE_INFO_320_MHZ_WIDTH),
            ]
            .concat(),
        ))
        .unwrap();
        assert_eq!(
            (eht.mode.as_deref(), eht.width_mhz, eht.guard_ns),
            (Some("eht"), Some(320), Some(3200))
        );
        // 5.5 Mbit/s of 802.11b.
        let legacy = rate(attrs(&u16a(RATE_INFO_BITRATE, 55))).unwrap();
        assert_eq!(
            legacy,
            WifiRate {
                kbps: Some(5500),
                mode: Some("legacy".into()),
                mcs: None,
                nss: None,
                width_mhz: Some(20),
                guard_ns: None,
            }
        );
        assert_eq!(rate(attrs(&[])), None);
        // A u8 MCS sent as a u32 is not an MCS.
        assert_eq!(rate(attrs(&u32a(RATE_INFO_MCS, 7))), None);
    }

    #[test]
    fn the_access_point_among_several_stations() {
        let other = station_msg([2, 0, 0, 0, 0, 1], &[s8a(STA_INFO_SIGNAL_AVG, -80)]);
        let ap = station_msg(AP, &[s8a(STA_INFO_SIGNAL_AVG, -40)]);
        let both = [other.as_slice(), ap.as_slice()];
        let l = station(both, Some("d8:47:32:aa:bb:cc")).unwrap();
        assert_eq!(l.signal_avg_dbm, Some(-40));
        // Two and none is the BSSID: no guess.
        assert_eq!(station(both, Some("00:11:22:33:44:55")), None);
        assert_eq!(station(both, None), None);
        // One: it, whatever its MAC.
        let l = station([other.as_slice()], Some("00:11:22:33:44:55")).unwrap();
        assert_eq!(l.signal_avg_dbm, Some(-80));
        assert_eq!(station([&[][..]], None), None);
    }

    #[test]
    fn hostile_station_info_is_bounded() {
        // 40 chains, a truncated last attribute, sizes that do not fit.
        let chains: Vec<Vec<u8>> = (0..40).map(|i| s8a(i, -60)).collect();
        let mut info = vec![
            nest(STA_INFO_CHAIN_SIGNAL, &chains),
            u8a(STA_INFO_TX_PACKETS, 9),
            u16a(STA_INFO_SIGNAL_AVG, 0xFFFF),
            s8a(STA_INFO_BEACON_SIGNAL_AVG, 20),
            nla(STA_INFO_RX_PACKETS, &[1, 2, 3, 4, 5, 6, 7, 8]),
        ];
        let mut tail = u32a(STA_INFO_TX_RETRIES, 5);
        tail.truncate(6);
        info.push(tail);
        let msg = station_msg(AP, &info);
        let l = station([msg.as_slice()], None).unwrap();
        assert_eq!(l.chain_signal_dbm.len(), MAX_CHAINS);
        assert_eq!(l.tx_packets, None);
        assert_eq!(l.signal_avg_dbm, None);
        assert_eq!(l.beacon_signal_dbm, None, "a positive dBm is no reading");
        assert_eq!(
            l.rx_packets,
            Some(u64::from_ne_bytes([1, 2, 3, 4, 5, 6, 7, 8]))
        );
        assert_eq!(l.tx_retries, None);
        // Cut anywhere: no panic.
        for n in 0..msg.len() {
            let _ = station([msg.get(..n).unwrap()], Some("d8:47:32:aa:bb:cc"));
        }
    }

    /// A channel of `NL80211_BAND_ATTR_FREQS`.
    fn channel(i: u16, mhz: u32, mbm: u32, extra: &[Vec<u8>]) -> Vec<u8> {
        let mut parts = vec![
            u32a(FREQUENCY_ATTR_FREQ, mhz),
            u32a(FREQUENCY_ATTR_MAX_TX_POWER, mbm),
        ];
        parts.extend_from_slice(extra);
        nest(i, &parts)
    }

    /// HE/EHT data for a station (and an AP entry that says otherwise).
    fn iftype_data(he0: u8, eht0: Option<u8>) -> Vec<u8> {
        let mut sta = vec![
            nest(BAND_IFTYPE_ATTR_IFTYPES, &[flag(IFTYPE_STATION)]),
            nla(
                BAND_IFTYPE_ATTR_HE_CAP_PHY,
                &[he0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ),
        ];
        if let Some(e) = eht0 {
            sta.push(nla(
                BAND_IFTYPE_ATTR_EHT_CAP_PHY,
                &[e, 0, 0, 0, 0, 0, 0, 0, 0],
            ));
        }
        let ap = vec![
            nest(BAND_IFTYPE_ATTR_IFTYPES, &[flag(3)]),
            nla(BAND_IFTYPE_ATTR_HE_CAP_PHY, &[0xFF; 11]),
        ];
        nest(BAND_ATTR_IFTYPE_DATA, &[nest(0, &ap), nest(1, &sta)])
    }

    /// The messages of a split dump, as the kernel cuts it: the
    /// capabilities of a band in one, then one channel per message.
    fn wiphy_dump() -> Vec<Vec<u8>> {
        let head = |rest: &[Vec<u8>]| {
            let mut m = vec![u32a(ATTR_WIPHY, 0), nla(ATTR_WIPHY_NAME, b"phy0\0")];
            m.extend_from_slice(rest);
            m.concat()
        };
        let bands = |band: u16, inner: &[Vec<u8>]| nest(ATTR_WIPHY_BANDS, &[nest(band, inner)]);
        vec![
            head(&[]),
            head(&[
                u32a(ATTR_WIPHY_ANTENNA_AVAIL_TX, 0b11),
                u32a(ATTR_WIPHY_ANTENNA_AVAIL_RX, 0b11),
            ]),
            head(&[bands(
                BAND_2GHZ,
                &[u16a(BAND_ATTR_HT_CAPA, 0x19e3), iftype_data(0x02, None)],
            )]),
            head(&[bands(
                BAND_2GHZ,
                &[nest(BAND_ATTR_FREQS, &[channel(0, 2412, 2000, &[])])],
            )]),
            head(&[bands(
                BAND_2GHZ,
                &[nest(
                    BAND_ATTR_FREQS,
                    &[channel(13, 2484, 2000, &[flag(FREQUENCY_ATTR_DISABLED)])],
                )],
            )]),
            head(&[bands(
                BAND_5GHZ,
                &[
                    u16a(BAND_ATTR_HT_CAPA, 0x19e3),
                    u32a(BAND_ATTR_VHT_CAPA, 0x339b_79fa),
                    iftype_data(0x0c, None),
                ],
            )]),
            head(&[bands(
                BAND_5GHZ,
                &[nest(BAND_ATTR_FREQS, &[channel(0, 5180, 2300, &[])])],
            )]),
            head(&[bands(
                BAND_5GHZ,
                &[nest(
                    BAND_ATTR_FREQS,
                    &[channel(
                        4,
                        5260,
                        2300,
                        &[flag(FREQUENCY_ATTR_RADAR), flag(3 /* NO_IR */)],
                    )],
                )],
            )]),
            // 60 GHz: left out.
            head(&[bands(
                2,
                &[nest(BAND_ATTR_FREQS, &[channel(0, 58_320, 4000, &[])])],
            )]),
            // Another wiphy's message: not this one.
            [
                u32a(ATTR_WIPHY, 1),
                u32a(ATTR_WIPHY_ANTENNA_AVAIL_TX, 0b1111),
            ]
            .concat(),
        ]
    }

    #[test]
    fn a_wiphy_with_two_bands() {
        let mut w = Wiphy::default();
        for m in wiphy_dump() {
            w.add(&m);
        }
        assert_eq!(w.name.as_deref(), Some("phy0"));
        assert_eq!((w.antennas_tx, w.antennas_rx), (Some(2), Some(2)));
        let bands = w.bands();
        assert_eq!(bands.len(), 2, "{bands:?}");
        let two = &bands[0];
        assert_eq!(two.band, "2ghz");
        assert_eq!(two.standards, ["b", "g", "n", "ax"]);
        assert_eq!(two.max_width_mhz, Some(40));
        assert_eq!(
            two.channels,
            [
                WifiChannel {
                    mhz: 2412,
                    max_power_dbm: Some(20),
                    radar: false,
                    disabled: false,
                },
                WifiChannel {
                    mhz: 2484,
                    max_power_dbm: Some(20),
                    radar: false,
                    disabled: true,
                },
            ]
        );
        let five = &bands[1];
        assert_eq!(five.band, "5ghz");
        assert_eq!(five.standards, ["a", "n", "ac", "ax"]);
        // VHT supported channel width 160 (bits 2-3 of 0x339b79fa).
        assert_eq!(five.max_width_mhz, Some(160));
        assert_eq!(five.channels.len(), 2);
        assert!(five.channels[1].radar && five.channels[1].max_power_dbm == Some(23));
    }

    #[test]
    fn a_six_ghz_band_and_widths() {
        let mut b = Band {
            he: Some(HE_PHY0_80),
            eht: Some(EHT_PHY0_320),
            ..Band::default()
        };
        assert_eq!(b.standards(BAND_6GHZ), ["ax", "be"]);
        assert_eq!(b.max_width(BAND_6GHZ), 320);
        b.eht = Some(0);
        assert_eq!(b.max_width(BAND_6GHZ), 80);
        // 802.11a/g only.
        let plain = Band::default();
        assert_eq!(plain.standards(BAND_5GHZ), ["a"]);
        assert_eq!(plain.max_width(BAND_5GHZ), 20);
        assert_eq!(plain.standards(BAND_2GHZ), ["b", "g"]);
        // HT 20 MHz only, then VHT without 160.
        let ht = Band {
            ht: Some(0x0001),
            ..Band::default()
        };
        assert_eq!(ht.max_width(BAND_5GHZ), 20);
        let vht = Band {
            ht: Some(HT_CAP_40),
            vht: Some(0),
            ..Band::default()
        };
        assert_eq!(vht.max_width(BAND_5GHZ), 80);
        assert_eq!(vht.max_width(BAND_2GHZ), 40);
    }

    #[test]
    fn hostile_wiphy_dumps_are_bounded() {
        // 300 channels in one band and ten bands: cut at the bounds.
        let chans: Vec<Vec<u8>> = (0..300u16)
            .map(|i| channel(i, 5000 + u32::from(i) * 5, 2000, &[]))
            .collect();
        let many = nest(
            ATTR_WIPHY_BANDS,
            &[nest(BAND_5GHZ, &[nest(BAND_ATTR_FREQS, &chans)])],
        );
        let mut w = Wiphy::default();
        w.add(&many);
        w.add(&many);
        let bands: Vec<Vec<u8>> = (0..10)
            .map(|b| nest(b, &[u16a(BAND_ATTR_HT_CAPA, 2)]))
            .collect();
        w.add(&nest(ATTR_WIPHY_BANDS, &bands));
        let out = w.bands();
        assert!(out.len() <= MAX_BANDS);
        assert!(out.iter().all(|b| b.channels.len() <= MAX_CHANNELS));
        assert_eq!(out[1].channels.len(), MAX_CHANNELS);
        // Wrong sizes: a u16 HT capability sent as a u8, a name too long.
        let mut w = Wiphy::default();
        w.add(
            &[
                nla(ATTR_WIPHY_NAME, &[b'x'; 200]),
                nest(
                    ATTR_WIPHY_BANDS,
                    &[nest(BAND_2GHZ, &[u8a(BAND_ATTR_HT_CAPA, 2)])],
                ),
            ]
            .concat(),
        );
        assert_eq!(w.name, None);
        assert_eq!(w.bands()[0].standards, ["b", "g"]);
        // Every cut of a real dump: no panic.
        for m in wiphy_dump() {
            for n in 0..m.len() {
                Wiphy::default().add(m.get(..n).unwrap());
            }
        }
    }

    #[test]
    fn transmit_power_in_dbm() {
        assert_eq!(tx_power(&u32a(ATTR_WIPHY_TX_POWER_LEVEL, 2200)), Some(22));
        // Signed mBm.
        let minus = u32::from_ne_bytes((-300i32).to_ne_bytes());
        assert_eq!(tx_power(&u32a(ATTR_WIPHY_TX_POWER_LEVEL, minus)), Some(-3));
        assert_eq!(tx_power(&u16a(ATTR_WIPHY_TX_POWER_LEVEL, 2200)), None);
        assert_eq!(tx_power(&[]), None);
    }

    proptest! {
        /// Whatever the kernel (or a bug) hands back: no panic, bounds kept.
        #[test]
        fn hostile_nl80211_bytes(buf in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = survey(&buf);
            if let Some(l) = station([buf.as_slice()], Some("d8:47:32:aa:bb:cc")) {
                prop_assert!(l.chain_signal_dbm.len() <= MAX_CHAINS);
            }
            let _ = rate(attrs(&buf));
            let _ = tx_power(&buf);
            let mut w = Wiphy::default();
            w.add(&buf);
            let bands = w.bands();
            prop_assert!(bands.len() <= MAX_BANDS);
            prop_assert!(bands.iter().all(|b| b.channels.len() <= MAX_CHANNELS));
        }
    }
}

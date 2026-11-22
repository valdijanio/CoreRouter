//! What a Wi-Fi scan says about the air (G1.30i): which networks overlap,
//! which of them share airtime, how busy each channel is, and the channel
//! with the least on it. The commands of `cmd/wifi_scan.rs` show it; the
//! GUI only draws it.
//!
//! **Overlap.** Each network takes the span of its whole channel
//! (`center ± width/2`, from its elements, `corerouter_hal::wifi::ie`).
//! On 2.4 GHz a 20 MHz channel is taken as 22 MHz wide, the DSSS mask
//! (IEEE 802.11-2020 §16.3.6.2) every 2.4 GHz radio still answers to, so
//! channels less than 5 apart overlap (1 and 5 do, 1 and 6 do not), as the
//! operators' "1, 6, 11" rule says.
//!
//! **Airtime.** A station transmits only when its clear channel assessment
//! (CCA) finds the primary channel idle. It defers to a Wi-Fi frame whose
//! preamble it decodes at −82 dBm or more on its primary 20 MHz, and to any
//! energy at −62 dBm or more (IEEE 802.11-2020 §17.3.10.6 for OFDM, §19.3.19.5
//! for HT, §21.3.18.5 for VHT; 802.11ax-2021 clause 27 keeps them for HE
//! on the primary 20). So another network shares this one's airtime when:
//! - this network's primary channel lies inside the other's span (the same
//!   primary, or the other sends wide frames over it, with a preamble
//!   duplicated on every 20 MHz) and it is heard at −82 dBm or more; or
//! - the spans only overlap (a partly overlapping 2.4 GHz channel, or the
//!   other on this one's secondary channels) and it is heard at −62 dBm or
//!   more: the preamble cannot be decoded there, only its energy counts.
//!
//! The level is the one this radio hears, which stands for what the access
//! point next to it hears: an estimate, and said as one.
//!
//! Per scan the work is O(n²) in the networks heard (at most
//! `MAX_SCAN_RESULTS` = 256: some 65 000 span comparisons, well under a
//! millisecond), done when a command asks, not per tick.

use corerouter_hal::wifi::{WifiBss, WifiSurvey};

/// Preamble detection on the primary 20 MHz, dBm (IEEE 802.11-2020
/// §17.3.10.6).
pub const CCA_PREAMBLE_DBM: i32 = -82;
/// Energy detection, dBm (20 dB above the preamble level, same clause).
pub const CCA_ENERGY_DBM: i32 = -62;

/// The band of a frequency.
pub fn band(mhz: u32) -> Option<&'static str> {
    match mhz {
        2400..=2500 => Some("2ghz"),
        5150..=5925 => Some("5ghz"),
        5926..=7125 => Some("6ghz"),
        _ => None,
    }
}

/// The channel number of a centre frequency (any band; 6 GHz numbered
/// from 5950).
pub fn channel(mhz: u32) -> Option<u32> {
    crate::wifi::channel(mhz)
}

/// The centre of channel `ch` of `band`.
pub fn channel_mhz(band: &str, ch: u32) -> u32 {
    match band {
        "2ghz" if ch == 14 => 2484,
        "2ghz" => 2407 + 5 * ch,
        "6ghz" => 5950 + 5 * ch,
        _ => 5000 + 5 * ch,
    }
}

/// The spans a network takes, MHz: one, or two with 80+80; on 2.4 GHz
/// 1 MHz wider each side (the DSSS mask).
pub fn spans(b: &WifiBss) -> Vec<(u32, u32)> {
    spans_padded(b, b.frequency_mhz < 3000)
}

/// The spans of its channel, exactly (no DSSS padding).
fn channel_spans(b: &WifiBss) -> Vec<(u32, u32)> {
    spans_padded(b, false)
}

fn spans_padded(b: &WifiBss, pad: bool) -> Vec<(u32, u32)> {
    let width = b.width_mhz.unwrap_or(20);
    let center = b.center_mhz.unwrap_or(b.frequency_mhz);
    let half = if pad { width / 2 + 1 } else { width / 2 };
    match b.center2_mhz {
        Some(c2) => vec![(center - 40, center + 40), (c2 - 40, c2 + 40)],
        None => vec![(center.saturating_sub(half), center + half)],
    }
}

fn overlap(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    a.iter().any(|(alo, ahi)| b.iter().any(|(blo, bhi)| alo < bhi && blo < ahi))
}

/// Is the 20 MHz channel at `mhz` one of the 20 MHz parts of `b`'s wider
/// channel (where `b`'s wide frames carry a duplicated preamble)?
fn covers(b: &WifiBss, mhz: u32) -> bool {
    b.width_mhz.unwrap_or(20) > 20
        && channel_spans(b)
            .iter()
            .any(|(lo, hi)| *lo < mhz && mhz < *hi && (mhz - lo) % 20 == 10)
}

/// How another network bears on one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// The same primary channel.
    SameChannel,
    /// This one's primary inside the other's span.
    Covered,
    /// The spans overlap, the primaries apart.
    Overlap,
}

/// What the air means for one network of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Air {
    /// The primary channels of the networks that overlap it on another
    /// primary, sorted, each once.
    pub overlaps: Vec<u32>,
    /// Networks on the same primary channel.
    pub same_channel: usize,
    /// Indexes (into the scan) of the networks that share its airtime.
    pub contenders: Vec<usize>,
}

/// How `other` bears on `this`, if at all.
pub fn relation(this: &WifiBss, other: &WifiBss) -> Option<Relation> {
    if band(this.frequency_mhz) != band(other.frequency_mhz) {
        return None;
    }
    let (a, b) = (spans(this), spans(other));
    if this.frequency_mhz == other.frequency_mhz {
        Some(Relation::SameChannel)
    } else if covers(other, this.frequency_mhz) {
        Some(Relation::Covered)
    } else if overlap(&a, &b) {
        Some(Relation::Overlap)
    } else {
        None
    }
}

/// Does `other`, heard at its level, take airtime from `this`?
pub fn contends(this: &WifiBss, other: &WifiBss) -> bool {
    match relation(this, other) {
        Some(Relation::SameChannel | Relation::Covered) => other.signal_dbm >= CCA_PREAMBLE_DBM,
        Some(Relation::Overlap) => other.signal_dbm >= CCA_ENERGY_DBM,
        None => false,
    }
}

/// The air of every network of `scan`, in its order. Two access points of
/// one network (the same SSID on the same channel, a mesh) still share the
/// air, and count.
pub fn analyse(scan: &[WifiBss]) -> Vec<Air> {
    scan.iter()
        .enumerate()
        .map(|(i, this)| {
            let mut air = Air::default();
            for (j, other) in scan.iter().enumerate() {
                if i == j || other.bssid.eq_ignore_ascii_case(&this.bssid) {
                    continue;
                }
                match relation(this, other) {
                    Some(Relation::SameChannel) => air.same_channel += 1,
                    Some(_) => {
                        if let Some(ch) = channel(other.frequency_mhz) {
                            air.overlaps.push(ch);
                        }
                    }
                    None => continue,
                }
                if contends(this, other) {
                    air.contenders.push(j);
                }
            }
            air.overlaps.sort_unstable();
            air.overlaps.dedup();
            air
        })
        .collect()
}

/// One channel as a frequency scan reports it (RouterOS
/// `/interface/wifi/frequency-scan`: channel, networks, load, nf,
/// max-signal, min-signal; the P and S flags as `primary` and `secondary`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChannelLoad {
    pub band: &'static str,
    pub channel: u32,
    pub frequency_mhz: u32,
    /// Networks whose primary channel this is.
    pub primary: usize,
    /// Networks that cover it with a wider channel.
    pub secondary: usize,
    pub max_signal: Option<i32>,
    pub min_signal: Option<i32>,
    /// Busy share of the time the radio listened, %, from the survey;
    /// `None` where the driver did not count (most drivers count only the
    /// channel in use).
    pub load: Option<f64>,
    pub noise: Option<i32>,
    pub in_use: bool,
}

/// The 20 MHz channels of a band worth listing: those a network or the
/// survey touches.
pub fn channels(scan: &[WifiBss], survey: &[WifiSurvey]) -> Vec<ChannelLoad> {
    let mut out: Vec<ChannelLoad> = Vec::new();
    /// The entry of the channel at `mhz`, made when missing.
    fn slot(out: &mut Vec<ChannelLoad>, mhz: u32) -> Option<&mut ChannelLoad> {
        let b = band(mhz)?;
        let ch = channel(mhz)?;
        match out.iter().position(|c| c.frequency_mhz == mhz) {
            Some(i) => out.get_mut(i),
            None => {
                out.push(ChannelLoad { band: b, channel: ch, frequency_mhz: mhz, ..ChannelLoad::default() });
                out.last_mut()
            }
        }
    }
    for s in survey {
        if let Some(c) = slot(&mut out, s.frequency_mhz) {
            c.noise = s.noise_dbm;
            c.in_use = s.in_use;
            c.load = s
                .busy_ms
                .zip(s.active_ms)
                .filter(|(_, a)| *a > 0)
                .map(|(b, a)| (b as f64 * 1000.0 / a as f64).round() / 10.0);
        }
    }
    for b in scan {
        if let Some(c) = slot(&mut out, b.frequency_mhz) {
            c.primary += 1;
            c.max_signal = Some(c.max_signal.map_or(b.signal_dbm, |m| m.max(b.signal_dbm)));
            c.min_signal = Some(c.min_signal.map_or(b.signal_dbm, |m| m.min(b.signal_dbm)));
        }
    }
    // The secondary channels of the wide ones: every 20 MHz of their span.
    let wide: Vec<(u32, Vec<(u32, u32)>)> = scan
        .iter()
        .filter(|b| b.width_mhz.unwrap_or(20) > 20)
        .map(|b| (b.frequency_mhz, channel_spans(b)))
        .collect();
    for (primary, sp) in &wide {
        for (lo, hi) in sp {
            let mut f = lo + 10;
            while f < *hi {
                if f != *primary
                    && let Some(c) = slot(&mut out, f)
                {
                    c.secondary += 1;
                }
                f += 20;
            }
        }
    }
    out.sort_by_key(|c| c.frequency_mhz);
    out
}

/// The channel a band has the least on ([`suggest`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Suggestion {
    pub band: &'static str,
    pub channel: u32,
    pub frequency_mhz: u32,
    /// Networks whose span covers it.
    pub networks: usize,
    /// The share of airtime the networks there are estimated to take, 0..=1.
    pub score: f64,
    pub dfs: bool,
}

/// The channel of `band` with the least on it, from `allowed` (MHz, with
/// radar detection: the radio's channels the country allows) or the usual
/// ones. The score of a 20 MHz candidate is what it would share: each
/// network whose span covers it, weighted by how loud it is here (−95 dBm
/// nothing, −50 dBm all) and how busy it says it is (BSS Load; half when
/// unknown), plus the survey's busy share. On 2.4 GHz only 1, 6 and 11 are
/// candidates: the others overlap two of them. Channels with radar
/// detection (DFS) lose ties.
pub fn suggest(
    band_name: &'static str,
    scan: &[WifiBss],
    survey: &[WifiSurvey],
    allowed: &[(u32, bool)],
) -> Option<Suggestion> {
    let defaults: Vec<(u32, bool)> = match band_name {
        "2ghz" => vec![(2412, false), (2437, false), (2462, false)],
        "5ghz" => [36, 40, 44, 48, 149, 153, 157, 161, 165]
            .iter()
            .map(|c| (5000 + 5 * c, false))
            .collect(),
        _ => (0..24).map(|i| (5955 + 20 * i, false)).collect(),
    };
    let candidates: Vec<(u32, bool)> = if allowed.is_empty() {
        defaults
    } else if band_name == "2ghz" {
        allowed.iter().copied().filter(|(f, _)| matches!(f, 2412 | 2437 | 2462)).collect()
    } else {
        allowed.iter().copied().filter(|(f, _)| band(*f) == Some(band_name)).collect()
    };
    candidates
        .into_iter()
        .map(|(f, dfs)| {
            let me = WifiBss { frequency_mhz: f, width_mhz: Some(20), center_mhz: Some(f), ..WifiBss::default() };
            let mine = spans(&me);
            let near: Vec<&WifiBss> = scan.iter().filter(|b| band(b.frequency_mhz) == Some(band_name) && overlap(&mine, &spans(b))).collect();
            let air: f64 = near
                .iter()
                .map(|b| {
                    // How loud, 0..1: −95 dBm nothing, −50 dBm all of it.
                    let loud = (f64::from(b.signal_dbm + 95) / 45.0).clamp(0.05, 1.0);
                    let busy = b.utilization.map_or(0.5, |u| f64::from(u) / 255.0);
                    loud * busy
                })
                .sum();
            let surveyed = survey
                .iter()
                .find(|s| s.frequency_mhz == f)
                .and_then(|s| s.busy_ms.zip(s.active_ms))
                .filter(|(_, a)| *a > 0)
                .map_or(0.0, |(b, a)| b as f64 / a as f64);
            Suggestion {
                band: band_name,
                channel: channel(f).unwrap_or(0),
                frequency_mhz: f,
                networks: near.len(),
                score: (air + surveyed).min(1.0),
                dfs,
            }
        })
        .min_by(|a, b| {
            a.score
                .total_cmp(&b.score)
                .then(a.dfs.cmp(&b.dfs))
                .then(a.networks.cmp(&b.networks))
                .then(a.frequency_mhz.cmp(&b.frequency_mhz))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bss(mac: u8, mhz: u32, width: u32, center: u32, dbm: i32) -> WifiBss {
        WifiBss {
            ssid: format!("n{mac}"),
            bssid: format!("02:00:00:00:00:{mac:02x}"),
            frequency_mhz: mhz,
            signal_dbm: dbm,
            width_mhz: Some(width),
            center_mhz: Some(center),
            ..WifiBss::default()
        }
    }

    #[test]
    fn two_point_four_overlaps_less_than_five_apart() {
        let ch = |c: u32, dbm| bss(u8::try_from(c).unwrap(), 2407 + 5 * c, 20, 2407 + 5 * c, dbm);
        let (one, five, six) = (ch(1, -60), ch(5, -60), ch(6, -60));
        assert_eq!(relation(&one, &five), Some(Relation::Overlap));
        assert_eq!(relation(&one, &six), None);
        assert_eq!(relation(&one, &ch(4, -60)), Some(Relation::Overlap));
        // Partly overlapping: only its energy counts (−62).
        assert!(contends(&one, &ch(3, -61)));
        assert!(!contends(&one, &ch(3, -70)));
        // The same channel: its preamble (−82).
        let other = bss(9, 2412, 20, 2412, -80);
        assert_eq!(relation(&one, &other), Some(Relation::SameChannel));
        assert!(contends(&one, &other));
        assert!(!contends(&one, &bss(9, 2412, 20, 2412, -85)));
    }

    #[test]
    fn wide_channels_on_five_ghz() {
        // An 80 MHz network on 36–48 (primary 44) and a 20 MHz one on 36.
        let wide = bss(1, 5220, 80, 5210, -70);
        let narrow = bss(2, 5180, 20, 5180, -70);
        // 36 lies inside the wide one: its wide frames hold 36's primary.
        assert_eq!(relation(&narrow, &wide), Some(Relation::Covered));
        assert!(contends(&narrow, &wide));
        // From the wide one's side the narrow one is on a secondary: energy.
        assert_eq!(relation(&wide, &narrow), Some(Relation::Overlap));
        assert!(!contends(&wide, &narrow));
        // 52 is outside 36–48.
        assert_eq!(relation(&wide, &bss(3, 5260, 20, 5260, -40)), None);
        // 80+80: two spans.
        let split = WifiBss { center2_mhz: Some(5775), ..bss(4, 5180, 160, 5210, -60) };
        assert_eq!(relation(&bss(5, 5785, 20, 5785, -60), &split), Some(Relation::Covered));
        // Other bands never meet.
        assert_eq!(relation(&bss(6, 5955, 20, 5955, -40), &bss(7, 5925, 20, 5925, -40)), None);
    }

    #[test]
    fn the_air_of_a_scan_and_the_channels() {
        let scan = [
            bss(1, 2412, 20, 2412, -60),
            bss(2, 2412, 20, 2412, -75),
            bss(3, 2427, 20, 2427, -55),
            bss(4, 2462, 40, 2452, -70),
        ];
        let air = analyse(&scan);
        let first = air.first().unwrap();
        assert_eq!((first.same_channel, first.overlaps.as_slice()), (1, &[4][..]));
        assert_eq!(first.contenders, [1, 2], "ch 1 at −75 (preamble) and ch 4 at −55 (energy)");
        let ch = channels(&scan, &[]);
        let one = ch.iter().find(|c| c.channel == 1).unwrap();
        assert_eq!((one.primary, one.max_signal, one.min_signal, one.load), (2, Some(-60), Some(-75), None));
        // The 40 MHz one's secondary is ch 7 (2442).
        assert_eq!(ch.iter().find(|c| c.channel == 7).map(|c| c.secondary), Some(1));
    }

    #[test]
    fn partial_survey_and_suggestion() {
        let scan = [bss(1, 2412, 20, 2412, -50), bss(2, 2437, 20, 2437, -80)];
        let survey = [
            WifiSurvey { frequency_mhz: 2437, in_use: true, active_ms: Some(1000), busy_ms: Some(250), ..WifiSurvey::default() },
            WifiSurvey { frequency_mhz: 2462, ..WifiSurvey::default() },
        ];
        let ch = channels(&scan, &survey);
        let six = ch.iter().find(|c| c.channel == 6).unwrap();
        assert_eq!((six.load, six.in_use), (Some(25.0), true));
        assert_eq!(ch.iter().find(|c| c.channel == 11).unwrap().load, None, "not counted");
        let s = suggest("2ghz", &scan, &survey, &[]).unwrap();
        assert_eq!((s.channel, s.networks), (11, 0));
        // DFS loses ties.
        let s = suggest("5ghz", &[], &[], &[(5260, true), (5180, false)]).unwrap();
        assert_eq!(s.channel, 36);
    }
}

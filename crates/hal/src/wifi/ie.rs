//! The information elements of a beacon or probe response (G1.30i): what
//! an access point says about its channel (width and centre), its
//! generation and its load. The scan of `wpa_supplicant` hands them over as
//! hex (`BSS <n>`, `ie=`); the virtual lab writes its own.
//!
//! The layouts are IEEE 802.11-2020's, chapter 9.4.2, and IEEE
//! 802.11be-2024's for EHT; each parser below names its subclause. The
//! input is hostile (any station in range writes it): every element is
//! read only when its body has the length the standard gives, an element
//! that runs past the end ends the walk, and nothing is allocated but the
//! decoded hex (bounded by [`MAX_IE_BYTES`]).

/// The most bytes of elements looked at: a frame body is at most 2304
/// bytes (IEEE 802.11-2020 §9.2.4.8) and `wpa_supplicant`'s reply to
/// `BSS <n>` is 4096 bytes of text, half of it hex at most.
pub const MAX_IE_BYTES: usize = 2304;

/// Element IDs (IEEE 802.11-2020 Table 9-92).
const BSS_LOAD: u8 = 11;
const HT_CAPABILITIES: u8 = 45;
const HT_OPERATION: u8 = 61;
const VHT_CAPABILITIES: u8 = 191;
const VHT_OPERATION: u8 = 192;
const EXTENSION: u8 = 255;
/// Element ID Extensions.
const EXT_HE_CAPABILITIES: u8 = 35;
const EXT_HE_OPERATION: u8 = 36;
const EXT_EHT_OPERATION: u8 = 106;
const EXT_EHT_CAPABILITIES: u8 = 108;

/// What the elements say about a network's channel and load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BssOperation {
    /// Width of the whole channel, MHz (20, 40, 80, 160, 320). With 80+80
    /// it is 160 and [`center2_mhz`](Self::center2_mhz) has the second
    /// segment.
    pub width_mhz: u32,
    /// Centre of the whole channel (of the first 80 MHz segment with
    /// 80+80), MHz.
    pub center_mhz: u32,
    /// Centre of the second 80 MHz segment of an 80+80 channel.
    pub center2_mhz: Option<u32>,
    /// 4 (802.11n), 5 (ac), 6 (ax), 7 (be): the newest capability element.
    pub generation: Option<u8>,
    /// BSS Load: stations associated.
    pub stations: Option<u16>,
    /// BSS Load: the share of time the access point found the medium busy,
    /// 0..=255 for 0..=100 %.
    pub utilization: Option<u8>,
}

/// The band of a primary channel at `mhz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Band {
    G2,
    G5,
    G6,
}

fn band(mhz: u32) -> Option<Band> {
    match mhz {
        2400..=2500 => Some(Band::G2),
        5150..=5925 => Some(Band::G5),
        5926..=7125 => Some(Band::G6),
        _ => None,
    }
}

/// The centre frequency of channel `ch` of `band` (IEEE 802.11-2020
/// §E.1: 2407 + 5n on 2.4 GHz, 2484 for 14; 5000 + 5n; 5950 + 5n on 6 GHz).
fn channel_mhz(band: Band, ch: u8) -> u32 {
    let ch = u32::from(ch);
    match band {
        Band::G2 if ch == 14 => 2484,
        Band::G2 => 2407 + 5 * ch,
        Band::G5 => 5000 + 5 * ch,
        Band::G6 => 5950 + 5 * ch,
    }
}

/// Hex text (`3000dd05…`) as bytes; `None` on anything but hex digit pairs.
/// At most [`MAX_IE_BYTES`] are decoded: the rest is left out.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim().as_bytes();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| char::from(c).to_digit(16);
    t.as_chunks::<2>()
        .0
        .iter()
        .take(MAX_IE_BYTES)
        .map(|[h, l]| u8::try_from(digit(*h)? * 16 + digit(*l)?).ok())
        .collect()
}

/// The elements of `ies`: (id, extension id for 255, body). A truncated
/// element ends the walk.
fn elements(ies: &[u8]) -> impl Iterator<Item = (u8, Option<u8>, &[u8])> {
    let mut rest = ies.get(..ies.len().min(MAX_IE_BYTES)).unwrap_or(&[]);
    std::iter::from_fn(move || {
        let (&id, after) = rest.split_first()?;
        let (&len, after) = after.split_first()?;
        let body = after.get(..usize::from(len))?;
        rest = after.get(usize::from(len)..).unwrap_or(&[]);
        Some(if id == EXTENSION {
            match body.split_first() {
                Some((&ext, b)) => (id, Some(ext), b),
                None => (id, None, body),
            }
        } else {
            (id, None, body)
        })
    })
}

/// A channel: width and centre, the second segment of 80+80.
type Channel = (u32, u32, Option<u32>);

/// HT Operation (IEEE 802.11-2020 §9.4.2.56, Figure 9-339): primary
/// channel, then the Secondary Channel Offset (B0–B1: 1 above, 3 below)
/// and the STA Channel Width (B2: 0 = 20 MHz only).
fn ht_operation(body: &[u8], band: Band) -> Option<Channel> {
    let [primary, info, ..] = *body else {
        return None;
    };
    if body.len() != 22 {
        return None;
    }
    let p = channel_mhz(band, primary);
    let any_width = info & 0b100 != 0;
    match info & 0b11 {
        1 if any_width => Some((40, p + 10, None)),
        3 if any_width => Some((40, p.saturating_sub(10), None)),
        _ => Some((20, p, None)),
    }
}

/// The VHT Operation Information (IEEE 802.11-2020 §9.4.2.158, Table
/// 9-274): Channel Width, CCFS0 and CCFS1, with the 2016 signalling of 160
/// and 80+80 (width 1 with CCFS1 set) and the deprecated one (widths 2, 3).
/// `None` for width 0 (20 or 40: the HT Operation says which).
fn vht_info(width: u8, ccfs0: u8, ccfs1: u8, band: Band) -> Option<Channel> {
    let c0 = channel_mhz(band, ccfs0);
    let c1 = channel_mhz(band, ccfs1);
    let apart = ccfs0.abs_diff(ccfs1);
    match width {
        1 if ccfs1 == 0 => Some((80, c0, None)),
        1 if apart == 8 => Some((160, c1, None)),
        1 if apart > 16 => Some((160, c0, Some(c1))),
        // CCFS1 that is neither: as 80, the part that is sure.
        1 => Some((80, c0, None)),
        2 => Some((160, c0, None)),
        3 => Some((160, c0, Some(c1))),
        _ => None,
    }
}

/// VHT Operation (§9.4.2.158, Figure 9-589): the 3 octets of information,
/// then the Basic VHT-MCS and NSS Set.
fn vht_operation(body: &[u8], band: Band) -> Option<Channel> {
    match *body {
        [w, c0, c1, _, _] => vht_info(w, c0, c1, band),
        _ => None,
    }
}

/// The 6 GHz Operation Information (§9.4.2.249, Figure 9-788k):
/// primary channel, Control (B0–B1 Channel Width: 20, 40, 80, 160 or
/// 80+80), CCFS0, CCFS1, Minimum Rate. 160 and 80+80 as in VHT.
fn six_ghz_info(info: &[u8]) -> Option<Channel> {
    let [_primary, control, ccfs0, ccfs1, _min_rate] = *info else {
        return None;
    };
    let c0 = channel_mhz(Band::G6, ccfs0);
    let c1 = channel_mhz(Band::G6, ccfs1);
    Some(match control & 0b11 {
        0 => (20, c0, None),
        1 => (40, c0, None),
        2 => (80, c0, None),
        _ if ccfs0.abs_diff(ccfs1) == 8 => (160, c1, None),
        _ if ccfs1 != 0 => (160, c0, Some(c1)),
        _ => (160, c0, None),
    })
}

/// HE Operation (§9.4.2.249, Figure 9-788a): HE Operation Parameters (3
/// octets; B14 VHT Operation Information Present, B15 Co-Hosted BSS, B17 6
/// GHz Operation Information Present), BSS Color (1), Basic HE-MCS and NSS
/// Set (2), then the optional parts in that order. On 5 GHz the VHT part
/// stands for a VHT Operation element an HE-only access point leaves out;
/// on 6 GHz the 6 GHz part is the channel.
fn he_operation(body: &[u8], band: Band) -> Option<Channel> {
    let [p0, p1, p2, ..] = *body else { return None };
    let params = u32::from(p0) | u32::from(p1) << 8 | u32::from(p2) << 16;
    let mut rest = body.get(6..)?;
    let mut vht = None;
    if params & (1 << 14) != 0 {
        let [w, c0, c1, ..] = *rest else { return None };
        vht = vht_info(w, c0, c1, band);
        rest = rest.get(3..)?;
    }
    if params & (1 << 15) != 0 {
        rest = rest.get(1..)?;
    }
    if params & (1 << 17) != 0 && band == Band::G6 {
        return six_ghz_info(rest.get(..5)?);
    }
    if band == Band::G5 { vht } else { None }
}

/// EHT Operation (IEEE 802.11be-2024 §9.4.2.311, Figure 9-1074ae): EHT
/// Operation Parameters (B0: EHT Operation Information Present), the Basic
/// EHT-MCS And Nss Set (4), then the information: Control (B0–B2 Channel
/// Width: 20, 40, 80, 160, 320), CCFS0, CCFS1. For 160 and 320 CCFS1 is
/// the centre of the whole channel and CCFS0 that of the primary half.
fn eht_operation(body: &[u8], band: Band) -> Option<Channel> {
    let (&params, rest) = body.split_first()?;
    if params & 1 == 0 {
        return None;
    }
    let [control, ccfs0, ccfs1, ..] = *rest.get(4..)? else {
        return None;
    };
    let c0 = channel_mhz(band, ccfs0);
    let c1 = channel_mhz(band, ccfs1);
    match control & 0b111 {
        0 => Some((20, c0, None)),
        1 => Some((40, c0, None)),
        2 => Some((80, c0, None)),
        3 => Some((160, if ccfs1 == 0 { c0 } else { c1 }, None)),
        4 => Some((320, c1, None)),
        _ => None,
    }
}

/// BSS Load (IEEE 802.11-2024 §9.4.2.26, as the kernel's
/// `include/linux/ieee80211.h` cites it): Station Count (2 octets, little
/// endian), Channel Utilization (1), Available Admission Capacity (2).
fn bss_load(body: &[u8]) -> Option<(u16, u8)> {
    match *body {
        [s0, s1, util, _, _] => Some((u16::from_le_bytes([s0, s1]), util)),
        _ => None,
    }
}

/// What `ies` say about the network whose primary channel is at
/// `primary_mhz`. A channel no element widens is 20 MHz on the primary.
/// The widest element of the newest generation wins: EHT, then the 6 GHz
/// information, then VHT (only on 5 GHz: some 2.4 GHz access points send
/// VHT elements a 2.4 GHz channel cannot have), then HT.
pub fn parse(ies: &[u8], primary_mhz: u32) -> BssOperation {
    let mut out = BssOperation {
        width_mhz: 20,
        center_mhz: primary_mhz,
        ..BssOperation::default()
    };
    let Some(band) = band(primary_mhz) else {
        return out;
    };
    let (mut ht, mut vht, mut he, mut eht) = (None, None, None, None);
    let mut generation = None::<u8>;
    let mut seen = |g: u8| generation = Some(generation.map_or(g, |o| o.max(g)));
    for (id, ext, body) in elements(ies) {
        match (id, ext) {
            (BSS_LOAD, _) => {
                if let Some((s, u)) = bss_load(body) {
                    out.stations = Some(s);
                    out.utilization = Some(u);
                }
            }
            (HT_CAPABILITIES, _) => seen(4),
            (HT_OPERATION, _) => ht = ht.or_else(|| ht_operation(body, band)),
            (VHT_CAPABILITIES, _) if band == Band::G5 => seen(5),
            (VHT_OPERATION, _) if band == Band::G5 => {
                vht = vht.or_else(|| vht_operation(body, band))
            }
            (EXTENSION, Some(EXT_HE_CAPABILITIES)) => seen(6),
            (EXTENSION, Some(EXT_HE_OPERATION)) => he = he.or_else(|| he_operation(body, band)),
            (EXTENSION, Some(EXT_EHT_CAPABILITIES)) => seen(7),
            (EXTENSION, Some(EXT_EHT_OPERATION)) => eht = eht.or_else(|| eht_operation(body, band)),
            _ => {}
        }
    }
    out.generation = generation;
    // 6 GHz has no HT nor VHT: an HE access point there says 6.
    if band == Band::G6 && he.is_some() {
        out.generation = Some(out.generation.unwrap_or(6).max(6));
    }
    let picked = match band {
        Band::G6 => eht.or(he),
        Band::G5 => eht.or(vht).or(he).or(ht),
        Band::G2 => eht.filter(|c| c.0 <= 40).or(ht),
    };
    if let Some((w, c, c2)) = picked.filter(|c| sane(c, primary_mhz)) {
        out.width_mhz = w;
        out.center_mhz = c;
        out.center2_mhz = c2;
    }
    out
}

/// The channel must hold the primary one: a centre that does not is a
/// broken element (or a lie), and the 20 MHz on the primary is surer.
fn sane(&(width, center, second): &Channel, primary_mhz: u32) -> bool {
    let half = 40.min(width) / 2;
    let holds = |c: u32, w: u32| c.saturating_sub(w / 2) < primary_mhz && primary_mhz < c + w / 2;
    match second {
        Some(c2) => holds(center, 80) || holds(c2, 80),
        None => holds(center, width.max(2 * half)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex(text: &str) -> Vec<u8> {
        from_hex(text).unwrap()
    }

    /// A real access point on channel 100 (5500 MHz), 160 MHz wide, Wi-Fi 7
    /// (a home router, scanned from a laptop on 2026-11-11 with `iw`'s
    /// scan dump); the name changed, the vendor elements and the reduced
    /// neighbour report (MAC addresses, the model) left out.
    const AP_160: &str = concat!(
        "00054c61622d3701088c129824b048606c071055530424041e340418640c1895051e002001002302120030180100000f",
        "ac040100000fac040200000fac02000fac088c00460573da00000c2d1aef0903ffff0000000000000000000001000000",
        "000000000000003d16640504000000000000000000000000000000000000007f0804000f0200000040bf0cf6f98133fa",
        "ff0000faff0020c005016a72fcffc3050330303030f40120ff21230901081a40100c634088fd499d1c110a00fafffaff",
        "fafffaff791cc7711cc771ff0724f43f0007fcffff022703ff0e260003a4ff27a4ff4243ff6232ffff126c0500e01f09",
        "e01875803600222222222222ff066a4411000000",
    );

    #[test]
    fn a_real_160_mhz_access_point() {
        let ies = hex(AP_160);
        let op = parse(&ies, 5500);
        // VHT: width 1, CCFS0 106, CCFS1 114 (8 apart): 160 MHz at ch 114.
        assert_eq!(
            (op.width_mhz, op.center_mhz, op.center2_mhz),
            (160, 5570, None)
        );
        assert_eq!(op.generation, Some(7));
        assert_eq!((op.stations, op.utilization), (None, None));
    }

    #[test]
    fn ht40_above_and_below_and_twenty() {
        let ht = |info: u8, ch: u8| {
            let mut b = vec![HT_OPERATION, 22, ch, info];
            b.extend([0u8; 20]);
            b
        };
        let mut ies = ht(0b101, 1);
        ies.extend([HT_CAPABILITIES, 0]);
        let op = parse(&ies, 2412);
        assert_eq!(
            (op.width_mhz, op.center_mhz, op.generation),
            (40, 2422, Some(4))
        );
        assert_eq!(parse(&ht(0b111, 11), 2462).center_mhz, 2452);
        // Offset set, STA width 20 only: 20.
        assert_eq!(parse(&ht(0b001, 1), 2412).width_mhz, 20);
        assert_eq!(parse(&ht(0b100, 6), 2437).width_mhz, 20);
        // Nothing: 20 on the primary.
        assert_eq!(
            parse(&[], 2437),
            BssOperation {
                width_mhz: 20,
                center_mhz: 2437,
                ..Default::default()
            }
        );
    }

    #[test]
    fn vht_80_and_80_plus_80_and_old_160() {
        let vht = |w: u8, c0: u8, c1: u8| vec![VHT_OPERATION, 5, w, c0, c1, 0xfc, 0xff];
        let op = parse(&vht(1, 42, 0), 5180);
        assert_eq!((op.width_mhz, op.center_mhz), (80, 5210));
        let op = parse(&vht(1, 42, 155), 5180);
        assert_eq!(
            (op.width_mhz, op.center_mhz, op.center2_mhz),
            (160, 5210, Some(5775))
        );
        assert_eq!(parse(&vht(2, 50, 0), 5180).center_mhz, 5250);
        // Width 0: 20/40 from HT; VHT on 2.4 GHz is ignored.
        assert_eq!(parse(&vht(0, 0, 0), 5180).width_mhz, 20);
        assert_eq!(parse(&vht(1, 42, 0), 2412).width_mhz, 20);
        // A centre that leaves the primary out is not believed.
        assert_eq!(parse(&vht(1, 155, 0), 5180).width_mhz, 20);
    }

    #[test]
    fn he_six_ghz_and_eht_320() {
        // HE Operation with the 6 GHz information: primary 37, 160 MHz,
        // CCFS0 39 (primary 80), CCFS1 47.
        let he = vec![
            EXTENSION,
            12,
            EXT_HE_OPERATION,
            0,
            0,
            0b10,
            0x01,
            0xfc,
            0xff,
            37,
            0b11,
            39,
            47,
            6,
        ];
        let op = parse(&he, 5950 + 5 * 37);
        assert_eq!(
            (op.width_mhz, op.center_mhz, op.generation),
            (160, 5950 + 5 * 47, Some(6))
        );
        // EHT 320 on top: CCFS1 63.
        let mut ies = he.clone();
        ies.extend([EXTENSION, 9, EXT_EHT_OPERATION, 1, 0, 0, 0, 0, 4, 47, 63]);
        ies.extend([EXTENSION, 1, EXT_EHT_CAPABILITIES]);
        let op = parse(&ies, 5950 + 5 * 37);
        assert_eq!(
            (op.width_mhz, op.center_mhz, op.generation),
            (320, 5950 + 5 * 63, Some(7))
        );
        // HE on 5 GHz with the VHT information inside (an HE-only AP).
        let he5 = vec![
            EXTENSION,
            10,
            EXT_HE_OPERATION,
            0,
            0x40,
            0,
            0x01,
            0xfc,
            0xff,
            1,
            58,
            0,
        ];
        assert_eq!(parse(&he5, 5260).width_mhz, 80);
    }

    #[test]
    fn bss_load() {
        let ies = [BSS_LOAD, 5, 0x12, 0x00, 128, 0, 0];
        let op = parse(&ies, 2437);
        assert_eq!((op.stations, op.utilization), (Some(18), Some(128)));
        // The wrong length is not read.
        assert_eq!(parse(&[BSS_LOAD, 4, 1, 0, 9, 0], 2437).stations, None);
    }

    #[test]
    fn hex_and_truncation() {
        assert_eq!(from_hex("0a0B"), Some(vec![10, 11]));
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(
            from_hex(&"00".repeat(MAX_IE_BYTES + 10)).map(|v| v.len()),
            Some(MAX_IE_BYTES)
        );
        // An element running past the end ends the walk, after the good ones.
        let ies = [BSS_LOAD, 5, 1, 0, 2, 0, 0, HT_OPERATION, 22, 1];
        assert_eq!(parse(&ies, 2412).stations, Some(1));
        assert_eq!(parse(&ies, 2412).width_mhz, 20);
        // Out of every band: nothing read.
        assert_eq!(parse(&ies, 900).stations, None);
    }

    proptest! {
        #[test]
        fn hostile_elements(bytes in proptest::collection::vec(any::<u8>(), 0..3000), mhz in 2300u32..7200) {
            let op = parse(&bytes, mhz);
            prop_assert!(matches!(op.width_mhz, 20 | 40 | 80 | 160 | 320));
            prop_assert!(op.center_mhz.abs_diff(mhz) <= 160);
            prop_assert!(op.generation.is_none_or(|g| (4..=7).contains(&g)));
        }

        #[test]
        fn hostile_hex(text in ".{0,600}") {
            let _ = from_hex(&text).map(|b| parse(&b, 5180));
        }
    }
}

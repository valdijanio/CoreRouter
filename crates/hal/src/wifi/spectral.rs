//! Spectral scan samples (G1.30i): the FFT reports a Qualcomm Atheros
//! radio hands to user space, as power per frequency bin.
//!
//! The format is the kernel's (`drivers/net/wireless/ath/spectral_common.h`,
//! Linux 6.18.59): a stream of TLVs (type u8, length big-endian u16 of what
//! follows) read from the debugfs relay files `spectral_scan<cpu>`. Four
//! types: ath9k's HT20 (56 bins) and HT20/40 (128 bins, each half with its
//! own noise and RSSI), ath10k's and ath11k's (a header and 16 to 512
//! bins). The bins are FFT magnitudes, shifted right by `max_exp`; the
//! power of bin `i` in dBm is the one the drivers' authors use in
//! `FFT_eval` (github.com/simonwunderlich/FFT_eval):
//!
//! `noise + rssi + 20·log10(bin << max_exp) − 10·log10(Σ (bin << max_exp)²)`
//!
//! that is, the whole power the radio measured (`noise + rssi`, dBm)
//! shared among the bins as their squared magnitudes are. The frequency of
//! bin `i` is `centre − span/2 + span·(i + ½)/bins`. ath9k's HT20 span is
//! 22·56/64 MHz (the 56 inner bins of a 64-point FFT at 22 MHz).
//!
//! The input is hostile like any other (a debugfs file is the kernel's,
//! but a corrupt relay buffer is not unheard of): every TLV is read only
//! with the length its type has, unknown types are skipped by their
//! length, and a length beyond what any type has makes the parser move on
//! byte by byte until it finds a TLV again.

/// Bins in a sample at most (ath11k's 512).
pub const MAX_BINS: usize = 512;
/// The longest TLV body looked at: ath11k's header and 512 bins.
const MAX_TLV: usize = 19 + MAX_BINS;

const HT20: u8 = 1;
const HT20_40: u8 = 2;
const ATH10K: u8 = 3;
const ATH11K: u8 = 4;
/// `enum nl80211_channel_type` (nl80211.h).
const CHAN_HT40MINUS: u8 = 2;
const CHAN_HT40PLUS: u8 = 3;

/// One FFT: the power of each bin and where the bins are.
#[derive(Debug, Clone, PartialEq)]
pub struct SpectralSample {
    /// The radio's timestamp (TSF), µs.
    pub tsf: u64,
    /// Centre of the first bin, MHz.
    pub start_mhz: f32,
    /// From one bin to the next, MHz.
    pub step_mhz: f32,
    /// Power of each bin, dBm (clamped to −128..=0).
    pub dbm: Vec<i8>,
}

impl SpectralSample {
    /// Centre of bin `i`, MHz.
    pub fn bin_mhz(&self, i: usize) -> f32 {
        self.start_mhz + self.step_mhz * i as f32
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn s8(b: &[u8], at: usize) -> Option<i32> {
    b.get(at).map(|&v| i32::from(v.cast_signed()))
}

/// The power of `bins` in dBm, the whole being `total_dbm`.
fn powers(bins: &[u8], max_exp: u8, total_dbm: f64) -> Vec<i8> {
    let shift = u32::from(max_exp.min(8));
    let mag = |b: u8| f64::from((u32::from(b) << shift).max(1));
    let sum: f64 = bins.iter().map(|&b| mag(b) * mag(b)).sum();
    let norm = 10.0 * sum.max(1.0).log10();
    bins.iter()
        .map(|&b| {
            let dbm = total_dbm + 20.0 * mag(b).log10() - norm;
            // Clamped, then a whole number: the cast cannot overflow.
            dbm.clamp(-128.0, 0.0).round() as i8
        })
        .collect()
}

/// `bins` spread over `span` MHz around `center`.
fn sample(tsf: u64, center: f64, span: f64, n: usize, dbm: Vec<i8>) -> Option<SpectralSample> {
    if n == 0 || !(1.0..=400.0).contains(&span) || !(2000.0..=8000.0).contains(&center) {
        return None;
    }
    let step = span / n as f64;
    Some(SpectralSample {
        tsf,
        start_mhz: (center - span / 2.0 + step / 2.0) as f32,
        step_mhz: step as f32,
        dbm,
    })
}

/// `struct fft_sample_ht20`: max_exp, freq, rssi, noise, max_magnitude,
/// max_index, bitmap_weight, tsf, 56 bins.
fn ht20(b: &[u8]) -> Option<SpectralSample> {
    let bins = b.get(17..17 + 56)?;
    if b.len() != 17 + 56 {
        return None;
    }
    let max_exp = *b.first()?;
    let freq = f64::from(be16(b, 1)?);
    let total = f64::from(s8(b, 4)? + s8(b, 3)?);
    sample(
        be64(b, 9)?,
        freq,
        22.0 * 56.0 / 64.0,
        56,
        powers(bins, max_exp, total),
    )
}

/// `struct fft_sample_ht20_40`: channel_type, freq (the primary), lower
/// and upper rssi, tsf, lower and upper noise, magnitudes, indexes and
/// weights, max_exp, 128 bins (64 per 20 MHz half).
fn ht20_40(b: &[u8]) -> Option<SpectralSample> {
    let bins = b.get(24..24 + 128)?;
    if b.len() != 24 + 128 {
        return None;
    }
    let freq = f64::from(be16(b, 1)?);
    let center = match *b.first()? {
        CHAN_HT40PLUS => freq + 10.0,
        CHAN_HT40MINUS => freq - 10.0,
        _ => return None,
    };
    let max_exp = *b.get(23)?;
    let (lower, upper) = bins.split_at(64);
    let mut dbm = powers(lower, max_exp, f64::from(s8(b, 13)? + s8(b, 3)?));
    dbm.extend(powers(upper, max_exp, f64::from(s8(b, 14)? + s8(b, 4)?)));
    sample(be64(b, 5)?, center, 40.0, 128, dbm)
}

/// `struct fft_sample_ath10k`: chan_width_mhz, freq1, freq2, noise
/// (signed), max_magnitude, total_gain_db, base_pwr_db, tsf, max_index,
/// rssi, relpwr_db, avgpwr_db, max_exp, then 64, 128 or 256 bins.
fn ath10k(b: &[u8]) -> Option<SpectralSample> {
    let bins = b.get(26..)?;
    if !matches!(bins.len(), 64 | 128 | 256) {
        return None;
    }
    let width = f64::from(*b.first()?);
    let noise = be16(b, 5)?.cast_signed();
    if noise == 0 {
        // The firmware had no noise floor yet: the power is not known.
        return None;
    }
    let total = f64::from(noise) + f64::from(*b.get(22)?);
    let max_exp = *b.get(25)?;
    sample(
        be64(b, 13)?,
        f64::from(be16(b, 1)?),
        width,
        bins.len(),
        powers(bins, max_exp, total),
    )
}

/// `struct fft_sample_ath11k`: chan_width_mhz, max_index, max_exp, freq1,
/// freq2, max_magnitude, rssi (signed 16), tsf (32), noise (signed 32),
/// then 16 to 512 bins.
fn ath11k(b: &[u8]) -> Option<SpectralSample> {
    let bins = b.get(19..)?;
    if !(16..=MAX_BINS).contains(&bins.len()) || !bins.len().is_power_of_two() {
        return None;
    }
    let width = f64::from(*b.first()?);
    let max_exp = *b.get(2)?;
    let rssi = f64::from(be16(b, 9)?.cast_signed());
    let noise = f64::from(be32(b, 15)?.cast_signed());
    let tsf = u64::from(be32(b, 11)?);
    sample(
        tsf,
        f64::from(be16(b, 3)?),
        width,
        bins.len(),
        powers(bins, max_exp, noise + rssi),
    )
}

/// One TLV's body.
fn decode(kind: u8, body: &[u8]) -> Option<SpectralSample> {
    match kind {
        HT20 => ht20(body),
        HT20_40 => ht20_40(body),
        ATH10K => ath10k(body),
        ATH11K => ath11k(body),
        _ => None,
    }
}

/// The samples at the start of `buf`, at most `max`, into `out`; returns
/// how many bytes were used. What is left is a TLV cut short (the rest
/// comes with the next read) or nothing.
pub fn parse_stream(buf: &[u8], out: &mut Vec<SpectralSample>, max: usize) -> usize {
    let mut at = 0;
    while out.len() < max {
        let Some(head) = buf.get(at..at + 3) else {
            break;
        };
        let (kind, len) = match *head {
            [k, h, l] => (k, usize::from(u16::from_be_bytes([h, l]))),
            _ => break,
        };
        if !(1..=4).contains(&kind) || len > MAX_TLV {
            // Not a TLV: look for one at the next byte.
            at += 1;
            continue;
        }
        let Some(body) = buf.get(at + 3..at + 3 + len) else {
            break;
        };
        if let Some(s) = decode(kind, body) {
            out.push(s);
        }
        at += 3 + len;
    }
    at
}

/// An ath10k TLV for `dbm` per bin over `width` MHz around `center` (the
/// lab's radio, and tests): the inverse of the parser, as close as eight
/// bits of magnitude get (48 dB below the strongest bin is the floor).
pub fn encode_ath10k(center: u16, width: u8, noise: i16, tsf: u64, dbm: &[f64]) -> Vec<u8> {
    let lin: Vec<f64> = dbm.iter().map(|d| 10f64.powf(d / 10.0)).collect();
    let total = 10.0 * lin.iter().sum::<f64>().max(1e-30).log10();
    let top = lin.iter().copied().fold(0.0, f64::max).max(1e-30);
    let bins: Vec<u8> = lin
        .iter()
        // Clamped to 1..=255 before the cast.
        .map(|p| ((p / top).sqrt() * 255.0).round().clamp(1.0, 255.0) as u8)
        .collect();
    let rssi = (total - f64::from(noise)).round().clamp(0.0, 255.0) as u8;
    let mut b = vec![ATH10K];
    b.extend(u16::try_from(26 + bins.len()).unwrap_or(0).to_be_bytes());
    b.push(width);
    b.extend(center.to_be_bytes());
    b.extend(0u16.to_be_bytes());
    b.extend(noise.to_be_bytes());
    b.extend([0u8; 6]);
    b.extend(tsf.to_be_bytes());
    b.extend([0, rssi, 0, 0, 0]);
    b.extend(bins);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ath10k_round_trip() {
        // A 20 MHz Wi-Fi signal at −50 dBm per bin over the middle 52 bins
        // of 64, the rest at −90.
        let dbm: Vec<f64> = (0..64)
            .map(|i| if (6..58).contains(&i) { -50.0 } else { -90.0 })
            .collect();
        let tlv = encode_ath10k(2437, 20, -95, 7, &dbm);
        let mut out = Vec::new();
        assert_eq!(parse_stream(&tlv, &mut out, 10), tlv.len());
        let [s] = out.as_slice() else {
            panic!("{out:?}")
        };
        assert_eq!(s.tsf, 7);
        assert_eq!(s.dbm.len(), 64);
        assert!(
            (s.bin_mhz(0) - (2427.0 + 20.0 / 128.0)).abs() < 0.01,
            "{}",
            s.bin_mhz(0)
        );
        assert!((s.bin_mhz(63) - (2447.0 - 20.0 / 128.0)).abs() < 0.01);
        for (got, want) in s.dbm.iter().zip(&dbm) {
            assert!((f64::from(*got) - want).abs() <= 2.0, "{got} {want}");
        }
    }

    #[test]
    fn ht20_and_ht40_as_the_kernel_writes_them() {
        // `struct fft_sample_ht20`, every bin equal: each is the total
        // (noise −95 + rssi 30 = −65 dBm) less 10·log10(56) ≈ 17.5 dB.
        let mut b = vec![HT20, 0, 73, 0];
        b.extend(2412u16.to_be_bytes());
        b.extend([30u8, (-95i8).cast_unsigned()]);
        b.extend([0, 100, 0, 0]);
        b.extend(5u64.to_be_bytes());
        b.extend([100u8; 56]);
        let mut out = Vec::new();
        assert_eq!(parse_stream(&b, &mut out, 10), b.len());
        let s = out.first().unwrap();
        assert!(s.dbm.iter().all(|&d| d == -82), "{:?}", s.dbm);
        assert!((s.bin_mhz(0) - (2412.0 - 9.625 + 0.171_875)).abs() < 0.01);

        // HT40+: the centre 10 MHz above the primary; the halves apart.
        let mut b = vec![HT20_40, 0, 152, CHAN_HT40PLUS];
        b.extend(2412u16.to_be_bytes());
        b.extend([20u8, 40]);
        b.extend(9u64.to_be_bytes());
        b.extend([(-95i8).cast_unsigned(), (-95i8).cast_unsigned()]);
        b.extend([0u8; 9]);
        b.extend([10u8; 128]);
        out.clear();
        parse_stream(&b, &mut out, 10);
        let s = out.first().unwrap();
        assert!((s.bin_mhz(64) - (2422.0 + 40.0 / 256.0)).abs() < 0.01);
        let (lo, hi) = (
            s.dbm.first().copied().unwrap(),
            s.dbm.last().copied().unwrap(),
        );
        assert_eq!(hi - lo, 20, "upper rssi 20 dB more");
        // HT20 channel type in an HT40 sample: not a sample.
        let mut bad = b.clone();
        if let Some(t) = bad.get_mut(3) {
            *t = 1;
        }
        out.clear();
        parse_stream(&bad, &mut out, 10);
        assert!(out.is_empty());
    }

    #[test]
    fn ath11k_header() {
        let mut b = vec![ATH11K, 0, 19 + 32, 20, 0, 0];
        b.extend(5180u16.to_be_bytes());
        b.extend(5180u16.to_be_bytes());
        b.extend(0u16.to_be_bytes());
        b.extend(10i16.to_be_bytes());
        b.extend(3u32.to_be_bytes());
        b.extend((-96i32).to_be_bytes());
        b.extend([50u8; 32]);
        let mut out = Vec::new();
        parse_stream(&b, &mut out, 10);
        let s = out.first().unwrap();
        // −86 dBm over 32 equal bins: −86 − 15 = −101 each.
        assert_eq!(s.dbm.first(), Some(&-101));
        assert_eq!(s.tsf, 3);
    }

    #[test]
    fn a_cut_tlv_waits_and_junk_is_skipped() {
        let dbm = [-60.0; 64];
        let tlv = encode_ath10k(5180, 20, -95, 1, &dbm);
        let mut stream = vec![0u8, 0, 0, 9, 9];
        stream.extend(&tlv);
        stream.extend(tlv.get(..10).unwrap());
        let mut out = Vec::new();
        let used = parse_stream(&stream, &mut out, 10);
        assert_eq!(out.len(), 1);
        assert_eq!(
            used,
            stream.len() - 10,
            "the cut TLV is left for the next read"
        );
        // `max` is kept.
        let two = [tlv.clone(), tlv].concat();
        out.clear();
        assert_eq!(parse_stream(&two, &mut out, 1), two.len() / 2);
    }

    proptest! {
        #[test]
        fn hostile_streams(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut out = Vec::new();
            let used = parse_stream(&bytes, &mut out, 64);
            prop_assert!(used <= bytes.len());
            for s in &out {
                prop_assert!(s.dbm.len() <= MAX_BINS);
                prop_assert!(s.step_mhz > 0.0 && s.start_mhz > 1900.0);
            }
        }

        #[test]
        fn typed_garbage(kind in 1u8..=4, body in proptest::collection::vec(any::<u8>(), 0..600)) {
            let mut b = vec![kind];
            b.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
            b.extend(&body);
            let mut out = Vec::new();
            parse_stream(&b, &mut out, 4);
        }
    }
}

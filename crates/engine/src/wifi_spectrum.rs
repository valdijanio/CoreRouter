//! A spectral scan as the engine keeps it (G1.30i): the samples a radio
//! hands over (`corerouter_hal::wifi::SpectralSample`, power per FFT bin)
//! laid on a fixed frequency grid, one row per tick of the clock (250 ms),
//! for the views airView made usual: the waterfall (rows over time), the
//! real-time, average and peak traces, the use of each channel and what
//! the energy looks like (Wi-Fi, a continuous carrier, a microwave oven, a
//! frequency hopper).
//!
//! **Memory.** At most [`MAX_POINTS`] points a row and [`MAX_ROWS`] rows,
//! one byte (dBm) a point: 1024 × 240 = 240 KiB for a scan, plus three
//! traces of `f32`/`i8`; one scan per radio, kept after it ends until the
//! next one or until the radio closes.
//!
//! **Cost.** Per tick the work is one pass over the samples that arrived
//! (each bin to its point: O(samples × bins), some 40 × 64 in the lab and a
//! few thousand × 64 on an ath9k in background mode) and one over the row.
//! The classification runs when a command asks for it, over the last
//! [`CLASSIFY_ROWS`] rows.

use std::collections::VecDeque;

use corerouter_hal::wifi::SpectralSample;
use corerouter_hal::wifi::WifiBss;

use crate::wifi_air::{self, CCA_PREAMBLE_DBM};

/// Points of a row at most.
pub const MAX_POINTS: usize = 1024;
/// Rows kept: 60 s at four a second.
pub const MAX_ROWS: usize = 240;
/// Rows the classification looks at: the last 10 s.
pub const CLASSIFY_ROWS: usize = 40;
/// A point with no sample yet.
pub const NONE: i8 = i8::MIN;

/// What is scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// The channel in use, at the radio's own resolution.
    Current,
    /// A band, the radio sweeping it while it scans.
    Band(u32, u32),
}

impl Range {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "" | "current" | "current-channel" => Some(Self::Current),
            "2ghz" | "2.4ghz" => Some(Self::Band(2400, 2500)),
            "5ghz" => Some(Self::Band(5150, 5895)),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Band(lo, _) if lo < 3000 => "2ghz",
            Self::Band(..) => "5ghz",
        }
    }

    /// The span the radio is asked to sweep.
    pub fn band(self) -> Option<(u32, u32)> {
        match self {
            Self::Current => None,
            Self::Band(lo, hi) => Some((lo, hi)),
        }
    }
}

/// A spectral scan's data.
#[derive(Debug, Clone)]
pub struct Spectrum {
    pub range: Range,
    /// Centre of the first point, MHz; step between points, MHz.
    pub start_mhz: f32,
    pub step_mhz: f32,
    pub points: usize,
    /// The bin width of the radio's samples, MHz (for the power of a
    /// channel: a point is a bin's power, not a density).
    bin_mhz: f32,
    rows: VecDeque<(u64, Vec<i8>)>,
    seq: u64,
    /// This tick's maximum per point.
    frame: Vec<i8>,
    /// Running averages (dBm) and the peak hold.
    pub average: Vec<f32>,
    pub peak: Vec<i8>,
    /// Samples taken, and those the radio dropped before the engine read
    /// them (said by the platform; 0 when it does not say).
    pub samples: u64,
    /// Until when it runs (the clock's ms); `None`: stopped.
    pub until_ms: Option<u64>,
    /// When the next sweep scan is due (a band range).
    pub next_scan_ms: u64,
    /// Why it stopped early, if it did.
    pub error: Option<String>,
    /// Per 20 MHz channel: samples over it, and those that found it busy.
    usage: Vec<Usage>,
    /// The noise floor the usage counts against, dBm (−95 until the rows
    /// say better).
    noise_est: i32,
}

/// dBm (whole, as the samples are) to mW, from a table of the 256 values.
fn mw(dbm: i8) -> f64 {
    static TABLE: std::sync::OnceLock<Vec<f64>> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| (0..=255u8).map(|b| 10f64.powf(f64::from(b.cast_signed()) / 10.0)).collect());
    t.get(usize::from(dbm.cast_unsigned())).copied().unwrap_or(0.0)
}

/// The samples one channel saw.
#[derive(Debug, Clone)]
struct Usage {
    mhz: u32,
    seen: u64,
    busy: u64,
}

/// The 20 MHz channels: 1–13 on 2.4 GHz; on 5 GHz 36–64, 100–144 and
/// 149–165; on 6 GHz 1, 5, 9… (every 20 MHz from 5955).
fn usage_channels() -> Vec<Usage> {
    (1..=13)
        .map(|c| 2407 + 5 * c)
        .chain((0..8).map(|k| 5180 + 20 * k))
        .chain((0..12).map(|k| 5500 + 20 * k))
        .chain((0..5).map(|k| 5745 + 20 * k))
        .chain((0..59).map(|k| 5955 + 20 * k))
        .map(|mhz| Usage { mhz, seen: 0, busy: 0 })
        .collect()
}

/// The grid of a range, or of the first sample of the channel in use.
fn grid(range: Range, first: Option<&SpectralSample>) -> Option<(f32, f32, usize)> {
    let (lo, hi, step) = match range {
        Range::Band(lo, hi) => {
            let span = (hi - lo) as f32;
            let step = if span <= 200.0 { 0.25 } else { 1.0 };
            (lo as f32, hi as f32, step)
        }
        Range::Current => {
            let s = first?;
            let lo = (s.start_mhz - s.step_mhz / 2.0).floor();
            let hi = (s.bin_mhz(s.dbm.len()) - s.step_mhz / 2.0).ceil();
            (lo, hi, if hi - lo > 200.0 { 1.0 } else { 0.25 })
        }
    };
    let points = (((hi - lo) / step).round() as usize).clamp(1, MAX_POINTS);
    Some((lo + step / 2.0, step, points))
}

impl Spectrum {
    pub fn new(range: Range, until_ms: u64) -> Self {
        let (start_mhz, step_mhz, points) = grid(range, None).unwrap_or((0.0, 1.0, 0));
        Self {
            range,
            start_mhz,
            step_mhz,
            points,
            bin_mhz: step_mhz,
            rows: VecDeque::new(),
            seq: 0,
            frame: vec![NONE; points],
            average: vec![f32::NAN; points],
            peak: vec![NONE; points],
            samples: 0,
            until_ms: Some(until_ms),
            next_scan_ms: 0,
            error: None,
            usage: usage_channels(),
            noise_est: -95,
        }
    }

    pub fn running(&self) -> bool {
        self.until_ms.is_some()
    }

    /// The frequency of point `i`, MHz.
    pub fn point_mhz(&self, i: usize) -> f32 {
        self.start_mhz + self.step_mhz * i as f32
    }

    fn point_of(&self, mhz: f32) -> Option<usize> {
        let p = ((mhz - self.start_mhz) / self.step_mhz).round();
        (p >= 0.0 && (p as usize) < self.points).then_some(p as usize)
    }

    /// Lay `samples` on this tick's row.
    pub fn feed(&mut self, samples: &[SpectralSample]) {
        if self.points == 0 {
            // The channel in use: the grid comes with the first sample.
            let Some((start, step, points)) = grid(self.range, samples.first()) else {
                return;
            };
            (self.start_mhz, self.step_mhz, self.points) = (start, step, points);
            self.frame = vec![NONE; points];
            self.average = vec![f32::NAN; points];
            self.peak = vec![NONE; points];
        }
        for s in samples {
            self.bin_mhz = s.step_mhz.max(0.01);
            self.count_usage(s);
            for (i, &d) in s.dbm.iter().enumerate() {
                if let Some(p) = self.point_of(s.bin_mhz(i))
                    && let Some(slot) = self.frame.get_mut(p)
                {
                    *slot = (*slot).max(d);
                }
            }
        }
        self.samples = self.samples.saturating_add(samples.len() as u64);
    }

    /// End the tick: this tick's row into the history (points no sample
    /// reached keep the row before's value, or a neighbour's), the traces
    /// updated. A tick without samples adds nothing.
    pub fn end_frame(&mut self) {
        if self.frame.iter().all(|&v| v == NONE) {
            return;
        }
        let mut row = std::mem::replace(&mut self.frame, vec![NONE; self.points]);
        let last = self.rows.back().map(|(_, r)| r.clone());
        // Bins coarser than the grid leave gaps between them: the nearest
        // neighbour within two points fills them.
        let filled: Vec<i8> = (0..row.len())
            .map(|i| match row.get(i).copied() {
                Some(v) if v != NONE => v,
                _ => [i.wrapping_sub(1), i + 1, i.wrapping_sub(2), i + 2]
                    .iter()
                    .filter_map(|&j| row.get(j).copied())
                    .find(|&v| v != NONE)
                    .or_else(|| last.as_ref().and_then(|l| l.get(i).copied()))
                    .unwrap_or(NONE),
            })
            .collect();
        row = filled;
        for (i, &v) in row.iter().enumerate() {
            if v == NONE {
                continue;
            }
            if let Some(a) = self.average.get_mut(i) {
                *a = if a.is_nan() { f32::from(v) } else { *a * 0.9 + f32::from(v) * 0.1 };
            }
            if let Some(p) = self.peak.get_mut(i) {
                *p = (*p).max(v);
            }
        }
        self.seq = self.seq.saturating_add(1);
        self.rows.push_back((self.seq, row));
        while self.rows.len() > MAX_ROWS {
            self.rows.pop_front();
        }
        // The floor the usage counts against, once a second.
        if self.seq % 4 == 1
            && let Some(n) = self.noise()
        {
            self.noise_est = n;
        }
    }

    /// The rows after `since`, oldest first.
    pub fn rows_since(&self, since: u64) -> impl Iterator<Item = &(u64, Vec<i8>)> {
        self.rows.iter().filter(move |(seq, _)| *seq > since)
    }

    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    /// The real-time trace: the last row.
    pub fn realtime(&self) -> Option<&[i8]> {
        self.rows.back().map(|(_, r)| r.as_slice())
    }

    /// The noise floor: the 10th percentile of every point of the last
    /// [`CLASSIFY_ROWS`] rows (the quiet moments of even a busy channel).
    pub fn noise(&self) -> Option<i32> {
        let mut v: Vec<i8> = self
            .rows
            .iter()
            .rev()
            .take(CLASSIFY_ROWS)
            .flat_map(|(_, r)| r.iter().copied())
            .filter(|&x| x != NONE)
            .collect();
        if v.is_empty() {
            return None;
        }
        let k = v.len() / 10;
        v.select_nth_unstable(k);
        v.get(k).map(|&n| i32::from(n))
    }

    /// Each 20 MHz channel a sample covered: the share of the samples
    /// over it in which the power above the noise floor, its bins summed,
    /// reached the CCA preamble level, −82 dBm: as often as a station there
    /// would find the channel busy if all of it were Wi-Fi (airView's
    /// "channel usage", the share of time). Counted per sample as they
    /// arrive, not per row: a row holds the maximum of a quarter of a
    /// second, and a hopper lands somewhere in most of them.
    pub fn channel_usage(&self) -> Vec<(u32, u32, f64)> {
        self.usage
            .iter()
            .filter(|u| u.seen > 0)
            .map(|u| {
                let ch = wifi_air::channel(u.mhz).unwrap_or(0);
                (ch, u.mhz, (u.busy as f64 * 1000.0 / u.seen as f64).round() / 10.0)
            })
            .collect()
    }

    /// Count `s` into the usage of the channels it covers whole: the power
    /// of each bin above the floor (from a table: a `powf` a bin was 90 %
    /// of a tick, **measured**), summed per channel over its bins.
    fn count_usage(&mut self, s: &SpectralSample) {
        let lo = s.start_mhz - s.step_mhz / 2.0;
        let hi = s.bin_mhz(s.dbm.len()) - s.step_mhz / 2.0;
        if !self.usage.iter().any(|u| u.mhz as f32 - 10.0 >= lo - 0.5 && u.mhz as f32 + 10.0 <= hi + 0.5) {
            return;
        }
        let floor = mw(self.noise_est.clamp(-128, 127) as i8);
        let excess: Vec<f64> = s.dbm.iter().map(|&v| (mw(v) - floor).max(0.0)).collect();
        let step = s.step_mhz.max(0.001);
        for u in self.usage.iter_mut() {
            let (a, b) = (u.mhz as f32 - 10.0, u.mhz as f32 + 10.0);
            if a < lo - 0.5 || b > hi + 0.5 {
                continue;
            }
            // Bins whose centre is in [a, b).
            let first = ((a - s.start_mhz) / step).ceil().max(0.0) as usize;
            let last = (((b - s.start_mhz) / step).ceil().max(0.0) as usize).min(excess.len());
            let mw: f64 = excess.get(first..last).map_or(0.0, |e| e.iter().sum());
            u.seen = u.seen.saturating_add(1);
            if 10.0 * mw.max(1e-30).log10() >= f64::from(CCA_PREAMBLE_DBM) {
                u.busy = u.busy.saturating_add(1);
            }
        }
    }

    /// What the energy of the last [`CLASSIFY_ROWS`] rows looks like.
    /// An estimate from its shape in frequency and time, MikroTik's
    /// classes where they fit:
    /// - `cw`: a carrier under 1.5 MHz wide, on in most rows, 10 dB above
    ///   the points 2 MHz to each side;
    /// - `bluetooth` (2.4 GHz) or `fhss`: narrow bursts, each in few rows,
    ///   spread over 20 MHz or more (a hopper);
    /// - `wifi`: energy inside the span of a network the scan heard, or a
    ///   block 15 MHz or wider;
    /// - `mwo`: a microwave oven, 2440–2480 MHz, 6 to 30 MHz wide, on about
    ///   half the time and wandering.
    pub fn classify(&self, scan: &[WifiBss]) -> Vec<Interference> {
        let rows: Vec<&Vec<i8>> = self.rows.iter().rev().take(CLASSIFY_ROWS).map(|(_, r)| r).collect();
        let (Some(noise), false) = (self.noise(), rows.is_empty()) else {
            return Vec::new();
        };
        let n = rows.len() as f64;
        let on = |i: usize, above: i32| rows.iter().filter(|r| r.get(i).is_some_and(|&v| v != NONE && i32::from(v) >= noise + above)).count() as f64 / n;
        let occ: Vec<f64> = (0..self.points).map(|i| on(i, 6)).collect();
        let max: Vec<i32> = (0..self.points)
            .map(|i| rows.iter().filter_map(|r| r.get(i).copied()).map(i32::from).max().unwrap_or(-128))
            .collect();
        let mean = |i: usize| -> f64 {
            let v: Vec<f64> = rows.iter().filter_map(|r| r.get(i).copied()).filter(|&v| v != NONE).map(f64::from).collect();
            if v.is_empty() { -128.0 } else { v.iter().sum::<f64>() / v.len() as f64 }
        };
        let two = (2.0 / self.step_mhz).round().max(1.0) as usize;
        let mut out = Vec::new();
        let mut used = vec![false; self.points];

        // Carriers: steady, narrow, standing out of their sides.
        let mut i = 0;
        while i < self.points {
            let side = mean(i.saturating_sub(two)).max(mean((i + two).min(self.points - 1)));
            if occ.get(i).is_some_and(|&o| o >= 0.8) && mean(i) >= side + 10.0 {
                let mut j = i;
                while j + 1 < self.points && occ.get(j + 1).is_some_and(|&o| o >= 0.8) && mean(j + 1) >= side + 10.0 {
                    j += 1;
                }
                let width = (j - i + 1) as f32 * self.step_mhz;
                if width <= 1.5 {
                    out.push(Interference::new("cw", self.point_mhz(i) + width / 2.0 - self.step_mhz / 2.0, width, max.get(i).copied()));
                    for u in used.iter_mut().take(j + 1).skip(i) {
                        *u = true;
                    }
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }

        // Hoppers: narrow peaks well above the floor, each seldom on.
        let hops: Vec<usize> = (0..self.points)
            .filter(|&i| !used.get(i).copied().unwrap_or(true))
            .filter(|&i| {
                let o = occ.get(i).copied().unwrap_or(0.0);
                let m = max.get(i).copied().unwrap_or(-128);
                let sides = max.get(i.saturating_sub(two)).copied().unwrap_or(-128).min(max.get((i + two).min(self.points - 1)).copied().unwrap_or(-128));
                o > 0.0 && o < 0.35 && m >= noise + 15 && m >= sides + 6
            })
            .collect();
        if let (Some(&a), Some(&b)) = (hops.first(), hops.last()) {
            let spread = self.point_mhz(b) - self.point_mhz(a);
            if hops.len() >= 5 && spread >= 20.0 {
                let kind = if self.point_mhz(a) < 2500.0 { "bluetooth" } else { "fhss" };
                let top = hops.iter().filter_map(|&i| max.get(i).copied()).max();
                out.push(Interference::new(kind, (self.point_mhz(a) + self.point_mhz(b)) / 2.0, spread, top));
                for &h in &hops {
                    if let Some(u) = used.get_mut(h) {
                        *u = true;
                    }
                }
            }
        }

        // Blocks of energy: Wi-Fi where a network heard at about that level
        // is, an oven where it fits. A point counts as on when it or a
        // point within 1 MHz was on in a tenth of the rows (the bursts of
        // one transmitter do not all land on every point).
        let mhz1 = (1.0 / self.step_mhz).round().max(1.0) as usize;
        let near_occ = |i: usize| (i.saturating_sub(mhz1)..=(i + mhz1).min(self.points - 1)).filter_map(|k| occ.get(k).copied()).fold(0.0, f64::max);
        let busy = |i: usize| !used.get(i).copied().unwrap_or(true) && near_occ(i) >= 0.1;
        // The level each network heard would show per point: its signal
        // spread over its width in bins.
        let expected: Vec<(f32, f32, f64)> = scan
            .iter()
            .flat_map(|b| {
                let w = f64::from(b.width_mhz.unwrap_or(20));
                let per_bin = f64::from(b.signal_dbm) - 10.0 * (w / f64::from(self.bin_mhz)).log10();
                wifi_air::spans(b).into_iter().map(move |(lo, hi)| (lo as f32, hi as f32, per_bin))
            })
            .collect();
        // The level of a point while on.
        let on_level = |i: usize| -> Option<f64> {
            let v: Vec<f64> = rows
                .iter()
                .filter_map(|r| r.get(i).copied())
                .filter(|&v| v != NONE && i32::from(v) >= noise + 6)
                .map(f64::from)
                .collect();
            (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
        };
        let mut i = 0;
        while i < self.points {
            if !busy(i) {
                i += 1;
                continue;
            }
            let mut j = i;
            while j + 1 < self.points && busy(j + 1) {
                j += 1;
            }
            let (a, b) = (self.point_mhz(i), self.point_mhz(j));
            let width = b - a + self.step_mhz;
            let center = (a + b) / 2.0;
            let levels: Vec<f64> = (i..=j).filter_map(on_level).collect();
            let level = if levels.is_empty() { -128.0 } else { levels.iter().sum::<f64>() / levels.len() as f64 };
            let known = expected
                .iter()
                .any(|(lo, hi, per_bin)| (*lo..*hi).contains(&center) && (level - per_bin).abs() <= 10.0);
            let duty = (i..=j).filter_map(|k| occ.get(k)).sum::<f64>() / (j - i + 1) as f64;
            let top = (i..=j).filter_map(|k| max.get(k).copied()).max();
            let kind = if known {
                Some("wifi")
            } else if (2440.0..=2480.0).contains(&center) && (6.0..=30.0).contains(&width) && (0.2..=0.8).contains(&duty) {
                Some("mwo")
            } else if width >= 15.0 {
                Some("wifi")
            } else if width >= 2.0 {
                Some("unknown")
            } else {
                None
            };
            if let Some(k) = kind {
                out.push(Interference { duty: (duty * 100.0).round(), ..Interference::new(k, center, width, top) });
            }
            i = j + 1;
        }
        // The skirts of a carrier (the FFT smears it over a few bins) are
        // the carrier.
        let carriers: Vec<f32> = out.iter().filter(|i| i.kind == "cw").map(|i| i.frequency_mhz).collect();
        out.retain(|i| i.kind != "unknown" || !carriers.iter().any(|c| (c - i.frequency_mhz).abs() <= 3.0));
        out.sort_by(|a, b| a.frequency_mhz.total_cmp(&b.frequency_mhz));
        out
    }
}

/// A source of energy the classification found.
#[derive(Debug, Clone, PartialEq)]
pub struct Interference {
    /// `wifi`, `cw`, `mwo`, `bluetooth`, `fhss`, `unknown`.
    pub kind: &'static str,
    pub frequency_mhz: f32,
    pub width_mhz: f32,
    /// The strongest point, dBm.
    pub peak_dbm: Option<i32>,
    /// Share of rows it was on, %.
    pub duty: f64,
}

impl Interference {
    fn new(kind: &'static str, frequency_mhz: f32, width_mhz: f32, peak_dbm: Option<i32>) -> Self {
        Self { kind, frequency_mhz, width_mhz, peak_dbm, duty: 0.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(center: f32, dbm: impl Fn(f32) -> i8) -> SpectralSample {
        let step = 20.0 / 64.0;
        let start = center - 10.0 + step / 2.0;
        SpectralSample { tsf: 0, start_mhz: start, step_mhz: step, dbm: (0..64).map(|i| dbm(start + step * i as f32)).collect() }
    }

    #[test]
    fn rows_traces_and_bounds() {
        let mut sp = Spectrum::new(Range::Band(2400, 2500), 1000);
        assert_eq!(sp.points, 400);
        for k in 0..(MAX_ROWS + 10) {
            sp.feed(&[sample(2437.0, |f| if (2428.0..2446.0).contains(&f) { -60 } else { -95 })]);
            if k % 2 == 0 {
                sp.feed(&[sample(2412.0, |_| -94)]);
            }
            sp.end_frame();
        }
        assert_eq!(sp.rows_since(0).count(), MAX_ROWS);
        assert_eq!(sp.rows_since(sp.last_seq() - 3).count(), 3);
        let rt = sp.realtime().unwrap();
        let at = |f: f32| rt.get(sp.point_of(f).unwrap()).copied().unwrap();
        assert_eq!(at(2437.0), -60);
        assert_eq!(at(2412.0), -94, "kept from the row before");
        assert_eq!(at(2480.0), NONE, "never reached");
        // Channel 6 busy every row (its power is far above −82), 1 never.
        let usage = sp.channel_usage();
        assert_eq!(usage.iter().find(|u| u.0 == 6).map(|u| u.2), Some(100.0));
        assert_eq!(usage.iter().find(|u| u.0 == 1).map(|u| u.2), Some(0.0));
        // An empty tick adds no row.
        let seq = sp.last_seq();
        sp.end_frame();
        assert_eq!(sp.last_seq(), seq);
    }

    #[test]
    fn the_channel_in_use_takes_its_grid_from_the_first_sample() {
        let mut sp = Spectrum::new(Range::Current, 1000);
        assert_eq!(sp.points, 0);
        sp.feed(&[sample(5180.0, |_| -90)]);
        assert_eq!(sp.points, 80);
        assert!((sp.point_mhz(0) - 5170.125).abs() < 0.01);
    }

    #[test]
    fn carriers_hoppers_ovens_and_wifi() {
        let mut sp = Spectrum::new(Range::Band(2400, 2500), 1000);
        let mut rng = 7u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for k in 0..CLASSIFY_ROWS {
            let oven = k % 2 == 0;
            let wander = (next() % 6) as f32;
            let hop = 2402.0 + (next() % 79) as f32;
            let wifi = next() % 3 != 0;
            let air = |f: f32| -> i8 {
                if (2416.8..=2417.2).contains(&f) {
                    -70
                } else if (hop - 0.5..=hop + 0.5).contains(&f) {
                    -62
                } else if oven && (2450.0 + wander..=2466.0 + wander).contains(&f) {
                    -60
                } else if wifi && (2428.0..=2446.0).contains(&f) {
                    -75
                } else {
                    -95
                }
            };
            for c in (0..5).map(|i| 2412.0 + 20.0 * i as f32) {
                sp.feed(&[sample(c, air)]);
            }
            sp.end_frame();
        }
        let scan = [WifiBss { frequency_mhz: 2437, width_mhz: Some(20), center_mhz: Some(2437), signal_dbm: -60, ..WifiBss::default() }];
        let found = sp.classify(&scan);
        let kinds: Vec<&str> = found.iter().map(|i| i.kind).collect();
        assert!(kinds.contains(&"cw"), "{found:#?}");
        assert!(kinds.contains(&"mwo"), "{found:#?}");
        assert!(kinds.contains(&"wifi"), "{found:#?}");
        assert!(kinds.contains(&"bluetooth"), "{found:#?}");
        let cw = found.iter().find(|i| i.kind == "cw").unwrap();
        assert!((cw.frequency_mhz - 2417.0).abs() < 0.5, "{cw:?}");
    }
}

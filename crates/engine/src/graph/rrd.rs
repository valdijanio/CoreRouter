//! A round-robin database of fixed size (RRDtool's idea, our own format):
//! one value per second goes in, and four rings keep it at decreasing
//! resolution — 1 s for an hour, 1 min for a day, 5 min for a week, 1 h for
//! a year. Each ring slot of the coarser tiers holds the average and the
//! maximum of the seconds it covers, so a year graph still shows the peaks.
//!
//! - A slot belongs to bucket `k = t / step` (aligned on the Unix epoch, so
//!   1 h slots are whole UTC hours) and lives at `k % rows`: no head
//!   pointer, the time says where.
//! - A bucket closes when the first second of a later one arrives. Its
//!   average is unknown (`NaN`) when fewer than half of its seconds were
//!   known (RRDtool's `xff = 0.5`); buckets nobody wrote become `NaN`.
//! - Time that goes backwards (a clock stepped back) is ignored until it
//!   passes the newest bucket again: history is never rewritten.
//!
//! On disk (little-endian), [`Rrd::encode`]:
//!
//! | offset | size | |
//! |---|---|---|
//! | 0 | 8 | magic `CRGRAPH1` |
//! | 8 | 4 | format version (1) |
//! | 12 | 4 | values per slot (data sources) |
//! | 16 | 4 | tiers |
//! | 20 | 4 | reserved |
//! | 24 | 64 | series key, UTF-8, zero padded |
//! | 88 | 32 × tiers | per tier: step, rows, has-max (u32 each), reserved u32, newest closed bucket (u64, 0: none), reserved u64 |
//! | … | | per tier: averages (`rows × ds` f32), then maxima when kept |
//!
//! A slot is a row of all data sources, so what a store writes (the
//! buckets closed since the last one) is one contiguous range per ring, or
//! two when it wraps ([`Rrd::take_writes`]).

use std::ops::Range;

pub const MAGIC: &[u8; 8] = b"CRGRAPH1";
pub const VERSION: u32 = 1;
pub const KEY_BYTES: usize = 64;
const HEADER: usize = 88;
const TIER_HEADER: usize = 32;
/// Most data sources a series may have.
pub const MAX_DS: usize = 16;

/// One ring: `rows` slots of `step` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierSpec {
    pub step: u64,
    pub rows: usize,
    /// Keep the maximum next to the average (pointless at 1 s).
    pub max: bool,
}

impl TierSpec {
    /// Seconds the ring covers.
    pub fn window(&self) -> u64 {
        self.step.saturating_mul(self.rows as u64)
    }
}

/// The resolutions every series keeps (the approved layout of G4.5).
pub const TIERS: [TierSpec; 4] = [
    TierSpec { step: 1, rows: 3600, max: false },
    TierSpec { step: 60, rows: 1440, max: true },
    TierSpec { step: 300, rows: 2016, max: true },
    TierSpec { step: 3600, rows: 8760, max: true },
];

/// Sum of the known seconds of the open bucket.
#[derive(Debug, Clone, Copy)]
struct Acc {
    sum: f64,
    n: u32,
    max: f32,
}

impl Default for Acc {
    fn default() -> Self {
        Self { sum: 0.0, n: 0, max: f32::NAN }
    }
}

#[derive(Debug, Clone)]
struct Tier {
    spec: TierSpec,
    avg: Vec<f32>,
    max: Vec<f32>,
    /// The bucket being filled; `None` before the first value.
    open: Option<u64>,
    acc: Vec<Acc>,
    /// Newest bucket written to the ring (0: none).
    closed: u64,
    /// Newest bucket the last [`Rrd::take_writes`] handed out.
    stored: u64,
}

impl Tier {
    fn new(spec: TierSpec, ds: usize) -> Self {
        let n = spec.rows * ds;
        Self {
            spec,
            avg: vec![f32::NAN; n],
            max: if spec.max { vec![f32::NAN; n] } else { Vec::new() },
            open: None,
            acc: vec![Acc::default(); ds],
            closed: 0,
            stored: 0,
        }
    }

    fn slot(&self, k: u64) -> usize {
        (k % self.spec.rows as u64) as usize
    }

    /// Write bucket `k` (averages and maxima of one row).
    fn put(&mut self, k: u64, ds: usize, row: impl Fn(usize) -> (f32, f32)) {
        let base = self.slot(k) * ds;
        for d in 0..ds {
            let (a, m) = row(d);
            if let Some(v) = self.avg.get_mut(base + d) {
                *v = a;
            }
            if let Some(v) = self.max.get_mut(base + d) {
                *v = m;
            }
        }
        self.closed = k;
    }

    /// Close the open bucket and blank the ones skipped up to `k`.
    fn close_until(&mut self, k: u64, ds: usize) {
        let Some(open) = self.open else { return };
        let half = (self.spec.step as u32).div_ceil(2);
        let acc = std::mem::take(&mut self.acc);
        self.put(open, ds, |d| match acc.get(d) {
            Some(a) if a.n >= half && a.n > 0 => ((a.sum / f64::from(a.n)) as f32, a.max),
            Some(a) => (f32::NAN, a.max),
            None => (f32::NAN, f32::NAN),
        });
        self.acc = vec![Acc::default(); ds];
        let gap = k.saturating_sub(open).saturating_sub(1);
        if gap >= self.spec.rows as u64 {
            self.avg.fill(f32::NAN);
            self.max.fill(f32::NAN);
            self.closed = k - 1;
        } else {
            for skipped in open + 1..k {
                self.put(skipped, ds, |_| (f32::NAN, f32::NAN));
            }
        }
        self.open = Some(k);
    }

    /// The bucket `k` as stored: `None` outside the ring's window.
    fn row(&self, k: u64, ds: usize) -> Option<(&[f32], Option<&[f32]>)> {
        let rows = self.spec.rows as u64;
        if self.closed == 0 || k > self.closed || k + rows <= self.closed {
            return None;
        }
        let base = self.slot(k) * ds;
        let avg = self.avg.get(base..base + ds)?;
        let max = if self.spec.max {
            self.max.get(base..base + ds)
        } else {
            None
        };
        Some((avg, max))
    }
}

/// A byte range of the file to (re)write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Rrd {
    key: String,
    ds: usize,
    tiers: Vec<Tier>,
}

impl Rrd {
    /// An empty database of `ds` values per slot (1..=[`MAX_DS`]).
    pub fn new(key: &str, ds: usize) -> Self {
        let ds = ds.clamp(1, MAX_DS);
        Self {
            key: key.chars().take(KEY_BYTES).collect(),
            ds,
            tiers: TIERS.iter().map(|t| Tier::new(*t, ds)).collect(),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn ds(&self) -> usize {
        self.ds
    }

    /// Bytes of a database of `ds` values per slot: in memory and on disk.
    pub fn size_for(ds: usize) -> usize {
        HEADER
            + TIERS.len() * TIER_HEADER
            + TIERS
                .iter()
                .map(|t| t.rows * ds * 4 * if t.max { 2 } else { 1 })
                .sum::<usize>()
    }

    pub fn size(&self) -> usize {
        Self::size_for(self.ds)
    }

    /// The newest second seen (0: none).
    pub fn last(&self) -> u64 {
        self.tiers
            .first()
            .and_then(|t| t.open)
            .unwrap_or(0)
    }

    /// The value of second `t` (`NaN` for unknown). Earlier than the open
    /// bucket of a tier: ignored by that tier.
    pub fn update(&mut self, t: u64, values: &[f32]) {
        let ds = self.ds;
        for tier in &mut self.tiers {
            let k = t / tier.spec.step;
            match tier.open {
                Some(open) if k < open || k <= tier.closed => continue,
                Some(open) if k > open => tier.close_until(k, ds),
                Some(_) => {}
                None if k <= tier.closed => continue,
                // After a load: the buckets since the newest stored one are
                // unknown, not what the ring held a lap ago.
                None if tier.closed > 0 => {
                    tier.open = Some(tier.closed + 1);
                    if k > tier.closed + 1 {
                        tier.close_until(k, ds);
                    }
                }
                None => tier.open = Some(k),
            }
            for (acc, v) in tier.acc.iter_mut().zip(values) {
                if v.is_finite() {
                    acc.sum += f64::from(*v);
                    acc.n += 1;
                    acc.max = if acc.max.is_nan() { *v } else { acc.max.max(*v) };
                }
            }
        }
    }

    /// The tiers' specs, finest first.
    pub fn tiers(&self) -> impl Iterator<Item = TierSpec> + '_ {
        self.tiers.iter().map(|t| t.spec)
    }

    /// Newest closed bucket of tier `i` (0: none).
    pub fn closed(&self, i: usize) -> u64 {
        self.tiers.get(i).map_or(0, |t| t.closed)
    }

    /// Bucket `k` of tier `i`: averages and, when kept, maxima.
    pub fn row(&self, i: usize, k: u64) -> Option<(&[f32], Option<&[f32]>)> {
        self.tiers.get(i)?.row(k, self.ds)
    }

    /// The whole file.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&(self.ds as u32).to_le_bytes());
        out.extend_from_slice(&(self.tiers.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let mut key = [0u8; KEY_BYTES];
        for (dst, src) in key.iter_mut().zip(self.key.as_bytes()) {
            *dst = *src;
        }
        out.extend_from_slice(&key);
        for t in &self.tiers {
            out.extend_from_slice(&tier_header(t, t.closed));
        }
        for t in &self.tiers {
            put_f32s(&mut out, &t.avg);
            put_f32s(&mut out, &t.max);
        }
        out
    }

    /// Read a file written by [`Self::encode`] (or patched by
    /// [`Self::take_writes`]). A file of another layout is refused: the
    /// caller starts the series again.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let u32_at = |o: usize| -> Result<u32, String> {
            bytes
                .get(o..o + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(|| "file too short".to_string())
        };
        let u64_at = |o: usize| -> Result<u64, String> {
            bytes
                .get(o..o + 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or_else(|| "file too short".to_string())
        };
        if bytes.get(..8) != Some(&MAGIC[..]) {
            return Err("not a graph file".into());
        }
        let version = u32_at(8)?;
        if version != VERSION {
            return Err(format!("format version {version}, this build reads {VERSION}"));
        }
        let ds = u32_at(12)? as usize;
        if ds == 0 || ds > MAX_DS {
            return Err(format!("{ds} values per slot"));
        }
        if u32_at(16)? as usize != TIERS.len() {
            return Err("another tier layout".into());
        }
        let key_bytes = bytes.get(24..24 + KEY_BYTES).ok_or("file too short")?;
        let end = key_bytes.iter().position(|b| *b == 0).unwrap_or(KEY_BYTES);
        let key = std::str::from_utf8(key_bytes.get(..end).unwrap_or_default())
            .map_err(|_| "series key is not UTF-8".to_string())?
            .to_owned();
        if bytes.len() != Self::size_for(ds) {
            return Err(format!(
                "{} bytes, the layout needs {}",
                bytes.len(),
                Self::size_for(ds)
            ));
        }
        let mut rrd = Self::new(&key, ds);
        let mut data = HEADER + TIERS.len() * TIER_HEADER;
        for (i, tier) in rrd.tiers.iter_mut().enumerate() {
            let h = HEADER + i * TIER_HEADER;
            let spec = tier.spec;
            if u64::from(u32_at(h)?) != spec.step
                || u32_at(h + 4)? as usize != spec.rows
                || (u32_at(h + 8)? != 0) != spec.max
            {
                return Err("another tier layout".into());
            }
            tier.closed = u64_at(h + 16)?;
            tier.stored = tier.closed;
            data = get_f32s(bytes, data, &mut tier.avg)?;
            if spec.max {
                data = get_f32s(bytes, data, &mut tier.max)?;
            }
            // Nothing is open: the next value opens the bucket after the
            // newest closed one (an older one is history).
            tier.open = None;
        }
        rrd.reopen();
        Ok(rrd)
    }

    /// After a load: refill the open buckets of the coarser tiers from the
    /// seconds the 1 s ring still holds, so a restart within a bucket does
    /// not lose its first part.
    fn reopen(&mut self) {
        let ds = self.ds;
        let Some((first, rest)) = self.tiers.split_first_mut() else {
            return;
        };
        let newest = first.closed;
        if newest == 0 {
            return;
        }
        first.open = Some(newest + 1);
        for tier in rest {
            let k = newest / tier.spec.step;
            if k <= tier.closed {
                continue;
            }
            tier.open = Some(k);
            for t in k * tier.spec.step..=newest {
                let Some((avg, _)) = first.row(t, ds) else {
                    continue;
                };
                for (acc, v) in tier.acc.iter_mut().zip(avg) {
                    if v.is_finite() {
                        acc.sum += f64::from(*v);
                        acc.n += 1;
                        acc.max = if acc.max.is_nan() { *v } else { acc.max.max(*v) };
                    }
                }
            }
        }
    }

    /// What changed since the last call, as byte ranges of the file: the
    /// buckets closed since, and the tier headers. The 1 s ring only when
    /// `seconds` (it changes every second; a store writes it on a clean
    /// shutdown, and a crash costs that hour at 1 s, which the 1 min ring
    /// still has).
    pub fn take_writes(&mut self, seconds: bool) -> Vec<Write> {
        let ds = self.ds;
        let mut out = Vec::new();
        let mut data = (HEADER + TIERS.len() * TIER_HEADER) as u64;
        for (i, tier) in self.tiers.iter_mut().enumerate() {
            let rows = tier.spec.rows;
            let ring = (rows * ds * 4) as u64;
            let avg_at = data;
            let max_at = data + ring;
            data += ring * if tier.spec.max { 2 } else { 1 };
            if i == 0 && !seconds {
                continue;
            }
            if tier.closed == tier.stored {
                continue;
            }
            for r in dirty_slots(tier.stored, tier.closed, rows) {
                let span = r.start * ds..r.end * ds;
                let offset = (r.start * ds * 4) as u64;
                out.push(Write {
                    offset: avg_at + offset,
                    bytes: f32_bytes(tier.avg.get(span.clone()).unwrap_or_default()),
                });
                if tier.spec.max {
                    out.push(Write {
                        offset: max_at + offset,
                        bytes: f32_bytes(tier.max.get(span).unwrap_or_default()),
                    });
                }
            }
            tier.stored = tier.closed;
            out.push(Write {
                offset: (HEADER + i * TIER_HEADER) as u64,
                bytes: tier_header(tier, tier.closed).to_vec(),
            });
        }
        out
    }

    /// Everything counts as stored (the whole file was just written).
    pub fn mark_stored(&mut self) {
        for t in &mut self.tiers {
            t.stored = t.closed;
        }
    }
}

fn tier_header(t: &Tier, closed: u64) -> [u8; TIER_HEADER] {
    let mut h = [0u8; TIER_HEADER];
    let fields: [&[u8]; 3] = [
        &(t.spec.step as u32).to_le_bytes(),
        &(t.spec.rows as u32).to_le_bytes(),
        &u32::from(t.spec.max).to_le_bytes(),
    ];
    for (i, f) in fields.iter().enumerate() {
        if let Some(dst) = h.get_mut(i * 4..i * 4 + 4) {
            dst.copy_from_slice(f);
        }
    }
    if let Some(dst) = h.get_mut(16..24) {
        dst.copy_from_slice(&closed.to_le_bytes());
    }
    h
}

/// The slots of buckets `stored+1 ..= closed`, as one or two ranges.
fn dirty_slots(stored: u64, closed: u64, rows: usize) -> Vec<Range<usize>> {
    let n = closed.saturating_sub(stored);
    if stored == 0 || n >= rows as u64 {
        return std::iter::once(0..rows).collect();
    }
    let first = ((stored + 1) % rows as u64) as usize;
    let last = (closed % rows as u64) as usize;
    if first <= last {
        std::iter::once(first..last + 1).collect()
    } else {
        [first..rows, 0..last + 1].into_iter().collect()
    }
}

fn put_f32s(out: &mut Vec<u8>, v: &[f32]) {
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

fn f32_bytes(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    put_f32s(&mut out, v);
    out
}

fn get_f32s(bytes: &[u8], at: usize, into: &mut [f32]) -> Result<usize, String> {
    let end = at + into.len() * 4;
    let src = bytes.get(at..end).ok_or("file too short")?;
    for (dst, b) in into.iter_mut().zip(src.as_chunks::<4>().0) {
        *dst = f32::from_le_bytes(*b);
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_800_000_000; // a whole hour (divisible by 3600)

    fn fill(r: &mut Rrd, from: u64, to: u64, v: impl Fn(u64) -> f32) {
        for t in from..to {
            r.update(t, &[v(t), 1.0]);
        }
    }

    #[test]
    fn size_is_fixed_and_small() {
        // 2 values a slot: 3600×4 + (1440+2016+8760)×8 + headers per value.
        assert_eq!(Rrd::size_for(1), 88 + 128 + 3600 * 4 + (1440 + 2016 + 8760) * 8);
        let r = Rrd::new("x", 6);
        assert_eq!(r.encode().len(), r.size());
    }

    #[test]
    fn minutes_average_and_keep_the_peak() {
        let mut r = Rrd::new("if", 2);
        fill(&mut r, T0, T0 + 121, |t| if t == T0 + 30 { 600.0 } else { 0.0 });
        let k = T0 / 60;
        let (avg, max) = r.row(1, k).unwrap();
        assert_eq!(avg[0], 10.0, "600 in one second of sixty");
        assert_eq!(max.unwrap()[0], 600.0);
        assert_eq!(r.row(1, k + 1).unwrap().0[0], 0.0);
        assert!(r.row(1, k + 2).is_none(), "the open minute is not a row yet");
        assert_eq!(r.row(0, T0 + 30).unwrap().0[0], 600.0);
    }

    #[test]
    fn half_known_or_unknown() {
        let mut r = Rrd::new("if", 2);
        // 29 known seconds of a minute: unknown average, known peak.
        fill(&mut r, T0, T0 + 29, |_| 5.0);
        r.update(T0 + 60, &[1.0, 1.0]);
        let (avg, max) = r.row(1, T0 / 60).unwrap();
        assert!(avg[0].is_nan());
        assert_eq!(max.unwrap()[0], 5.0);
    }

    #[test]
    fn gaps_are_unknown_and_a_long_one_clears_the_ring() {
        let mut r = Rrd::new("if", 2);
        fill(&mut r, T0, T0 + 10, |_| 1.0);
        r.update(T0 + 20, &[2.0, 2.0]);
        r.update(T0 + 21, &[2.0, 2.0]);
        assert!(r.row(0, T0 + 15).unwrap().0[0].is_nan());
        assert_eq!(r.row(0, T0 + 20).unwrap().0[0], 2.0);
        // Two hours later: the 1 s ring holds nothing older.
        r.update(T0 + 7200, &[3.0, 3.0]);
        r.update(T0 + 7201, &[3.0, 3.0]);
        assert!(r.row(0, T0 + 5).is_none(), "outside the window");
        assert!(r.row(0, T0 + 7199).unwrap().0[0].is_nan());
        assert_eq!(r.row(0, T0 + 7200).unwrap().0[0], 3.0);
    }

    #[test]
    fn time_going_back_is_ignored() {
        let mut r = Rrd::new("if", 2);
        fill(&mut r, T0, T0 + 5, |_| 1.0);
        r.update(T0 + 2, &[9.0, 9.0]);
        r.update(T0 + 5, &[1.0, 1.0]);
        r.update(T0 + 6, &[1.0, 1.0]);
        assert_eq!(r.row(0, T0 + 2).unwrap().0[0], 1.0);
    }

    #[test]
    fn round_trip_and_patches_rebuild_the_file() {
        let mut r = Rrd::new("interface:ether1", 2);
        fill(&mut r, T0, T0 + 400, |t| (t % 7) as f32);
        let mut file = r.encode();
        r.mark_stored();
        fill(&mut r, T0 + 400, T0 + 4000, |t| (t % 11) as f32);
        for w in r.take_writes(true) {
            let at = w.offset as usize;
            file[at..at + w.bytes.len()].copy_from_slice(&w.bytes);
        }
        let back = Rrd::decode(&file).unwrap();
        assert_eq!(back.key(), "interface:ether1");
        for i in 0..TIERS.len() {
            assert_eq!(back.closed(i), r.closed(i), "tier {i}");
        }
        assert_eq!(back.encode(), {
            let mut x = r.clone();
            x.mark_stored();
            x.encode()
        });
        assert!(r.take_writes(true).is_empty(), "nothing new");
    }

    #[test]
    fn a_restart_keeps_the_open_buckets() {
        let mut r = Rrd::new("if", 2);
        // 30 minutes of an hour, stored with the seconds (clean stop).
        fill(&mut r, T0, T0 + 1800, |_| 4.0);
        let _ = r.take_writes(true);
        let mut back = Rrd::decode(&r.encode()).unwrap();
        fill(&mut back, T0 + 1800, T0 + 3601, |_| 4.0);
        let (avg, _) = back.row(3, T0 / 3600).unwrap();
        assert_eq!(avg[0], 4.0, "the hour has all its seconds");
    }

    #[test]
    fn after_a_load_the_gap_is_unknown_not_last_laps_data() {
        let mut r = Rrd::new("if", 2);
        fill(&mut r, T0, T0 + 3700, |_| 7.0);
        let mut back = Rrd::decode(&r.encode()).unwrap();
        back.update(T0 + 3710, &[1.0, 1.0]);
        back.update(T0 + 3711, &[1.0, 1.0]);
        assert!(back.row(0, T0 + 3705).unwrap().0[0].is_nan());
        assert_eq!(back.row(0, T0 + 3710).unwrap().0[0], 1.0);
        assert_eq!(back.row(0, T0 + 3690).unwrap().0[0], 7.0);
    }

    #[test]
    fn bad_files_are_refused() {
        let r = Rrd::new("k", 3);
        let good = r.encode();
        assert!(Rrd::decode(&good).is_ok());
        assert!(Rrd::decode(&good[..100]).is_err());
        assert!(Rrd::decode(b"nope").is_err());
        let mut v = good.clone();
        v[8] = 9;
        assert!(Rrd::decode(&v).unwrap_err().contains("version"));
        let mut v = good;
        v[88] = 2; // tier 0 step
        assert!(Rrd::decode(&v).is_err());
    }

    #[test]
    fn dirty_ranges_wrap() {
        assert_eq!(dirty_slots(0, 5, 10), vec![0..10]);
        assert_eq!(dirty_slots(3, 5, 10), vec![4..6]);
        assert_eq!(dirty_slots(8, 12, 10), vec![9..10, 0..3]);
        assert_eq!(dirty_slots(1, 30, 10), vec![0..10]);
    }
}

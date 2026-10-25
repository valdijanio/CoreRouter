//! The OS log's lines kept in the session (G4.8b), for `log.os.print`:
//! a ring of the newest [`CAPACITY`] rows where a line that repeats one
//! seen in the last ten minutes (same source, unit, severity and message
//! but for its numbers) does not add a row: the row counts it and moves
//! to the newest place ("repetido 37× em 10 min").
//!
//! Fed by the daemon's `oslog` service (which reads the host on its own
//! thread and only takes the session lock to hand lines over) or, without
//! it, by the backend's `Hal::os_log` (the lab's made-up lines).

use std::collections::{BTreeMap, HashMap};

use corerouter_hal::oslog::{MAX_MESSAGE, MAX_UNIT, OsLine, OsLogBatch, SourceState, clean};

/// Rows kept.
pub const CAPACITY: usize = 20_000;
/// A line repeats a row whose last time is at most this far from it.
pub const REPEAT_WINDOW_US: u64 = 600 * 1_000_000;

/// One row: a line and how many times it came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Stable while the row lives (its first number).
    pub id: u64,
    /// Changes when the row changes (a repeat): `since` asks by it.
    pub seq: u64,
    /// The newest of its lines.
    pub line: OsLine,
    pub count: u32,
    /// Time of its first line, µs.
    pub first_us: u64,
    key: u64,
}

/// What [`OsLogBook::push`] did with a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    New(u64),
    Repeat(u64),
}

/// Rows by the three level chips of the window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Severity 0–3 (emergency … error).
    pub error: u64,
    pub warning: u64,
    /// 5–7 (notice, info, debug).
    pub info: u64,
}

#[derive(Debug, Default)]
pub struct OsLogBook {
    entries: BTreeMap<u64, Entry>,
    by_key: HashMap<u64, u64>,
    seq: u64,
    counts: Counts,
    capacity: usize,
    /// How each source is (the newest batch's word).
    pub sources: Vec<SourceState>,
    /// The boot running now.
    pub boot: String,
    /// The daemon feeds the book: commands do not ask the backend.
    pub fed: bool,
    /// Lines pushed and of them repeats folded into a row.
    pub lines_in: u64,
    pub repeats: u64,
}

/// FNV-1a: stable, so tests (and two runs) agree on keys.
fn fnv(h: &mut u64, bytes: &[u8]) {
    for b in bytes {
        *h ^= u64::from(*b);
        *h = h.wrapping_mul(0x0100_0000_01b3);
    }
}

/// The message with its numbers taken out: a digit run that starts a
/// token (after a space, `=`, `(`, `[`, `:`, `.`, `/`…) is `#`, one inside
/// a name (`eth0`, `nvme0n1`) stays. So "rx_missed 12" and "rx_missed 13"
/// are the same line, "ether1" and "ether2" are not.
pub fn normalized(message: &str) -> String {
    let mut out = String::with_capacity(message.len().min(256));
    let mut prev_alpha = false;
    let mut in_num = false;
    for c in message.chars().take(256) {
        if c.is_ascii_digit() {
            if in_num {
                continue;
            }
            if prev_alpha {
                out.push(c);
                continue;
            }
            in_num = true;
            out.push('#');
            continue;
        }
        // Hex digits of a number already started (0x1f, 7fdd7ae0) go with it.
        if in_num && (c.is_ascii_hexdigit() || (c == 'x' && out.ends_with('#'))) {
            continue;
        }
        in_num = false;
        prev_alpha = c.is_alphabetic() || c == '_';
        out.push(c);
    }
    out
}

fn key_of(l: &OsLine) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    fnv(&mut h, l.source.name().as_bytes());
    fnv(&mut h, &[0, l.severity, 0]);
    fnv(&mut h, l.unit.as_bytes());
    fnv(&mut h, &[0]);
    fnv(&mut h, normalized(&l.message).as_bytes());
    h
}

fn bucket(severity: u8) -> usize {
    match severity {
        0..=3 => 0,
        4 => 1,
        _ => 2,
    }
}

impl Counts {
    fn add(&mut self, severity: u8, n: i64) {
        let c = match bucket(severity) {
            0 => &mut self.error,
            1 => &mut self.warning,
            _ => &mut self.info,
        };
        *c = c.saturating_add_signed(n);
    }
}

impl OsLogBook {
    /// A book of `capacity` rows (tests use small ones).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            ..Self::default()
        }
    }

    fn cap(&self) -> usize {
        if self.capacity == 0 { CAPACITY } else { self.capacity }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// The newest `seq` given out (0: none yet).
    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    /// Rows changed after `since`, oldest change first.
    pub fn since(&self, since: u64) -> impl DoubleEndedIterator<Item = &Entry> {
        self.entries
            .range(since.saturating_add(1)..)
            .map(|(_, e)| e)
    }

    /// Add one line (cut to the book's limits).
    pub fn push(&mut self, mut line: OsLine) -> Pushed {
        line.message = clean(&line.message, MAX_MESSAGE);
        line.unit = clean(&line.unit, MAX_UNIT);
        line.device = clean(&line.device, MAX_UNIT);
        line.severity = line.severity.min(7);
        self.lines_in = self.lines_in.saturating_add(1);
        self.seq = self.seq.saturating_add(1);
        let seq = self.seq;
        let key = key_of(&line);
        if let Some(old_seq) = self.by_key.get(&key).copied()
            && let Some(old) = self.entries.get(&old_seq)
            && old.line.time_us.abs_diff(line.time_us) <= REPEAT_WINDOW_US
            && let Some(mut e) = self.entries.remove(&old_seq)
        {
            // Lines may come out of order (the journal's backlog after
            // kmsg's): the row keeps the newest one and the oldest time.
            e.first_us = e.first_us.min(line.time_us);
            if line.time_us >= e.line.time_us {
                e.line = line;
            }
            e.count = e.count.saturating_add(1);
            e.seq = seq;
            let id = e.id;
            self.entries.insert(seq, e);
            self.by_key.insert(key, seq);
            self.repeats = self.repeats.saturating_add(1);
            return Pushed::Repeat(id);
        }
        self.counts.add(line.severity, 1);
        self.entries.insert(
            seq,
            Entry {
                id: seq,
                seq,
                first_us: line.time_us,
                line,
                count: 1,
                key,
            },
        );
        self.by_key.insert(key, seq);
        while self.entries.len() > self.cap() {
            let Some((s, old)) = self.entries.pop_first() else {
                break;
            };
            self.counts.add(old.line.severity, -1);
            if self.by_key.get(&old.key) == Some(&s) {
                self.by_key.remove(&old.key);
            }
        }
        Pushed::New(seq)
    }

    /// Add a batch and take its word on the sources and the boot; gives
    /// what happened to each line, in order.
    pub fn ingest(&mut self, batch: OsLogBatch) -> Vec<Pushed> {
        if !batch.boot.is_empty() {
            self.boot = batch.boot;
        }
        if !batch.sources.is_empty() {
            self.sources = batch.sources;
        }
        batch.lines.into_iter().map(|l| self.push(l)).collect()
    }

    pub fn get(&self, id: u64) -> Option<&Entry> {
        let seq = *self.by_key.values().find(|s| {
            self.entries.get(s).is_some_and(|e| e.id == id)
        })?;
        self.entries.get(&seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::oslog::OsSource;

    fn line(t: u64, sev: u8, unit: &str, msg: &str) -> OsLine {
        OsLine {
            time_us: t * 1_000_000,
            severity: sev,
            source: OsSource::Kernel,
            unit: unit.into(),
            device: String::new(),
            pid: None,
            message: msg.into(),
            boot: "b".into(),
        }
    }

    #[test]
    fn numbers_do_not_make_a_new_line_names_do() {
        assert_eq!(normalized("rx_missed 12 at 0x1f"), "rx_missed # at #");
        assert_eq!(normalized("ether1: Link is Down"), "ether1: Link is Down");
        assert_eq!(
            normalized("audit(1792800123.456:41001): pid=4242"),
            "audit(#.#:#): pid=#"
        );
        assert_eq!(normalized("nvme0n1p7 sda1"), "nvme0n1p7 sda1");
        assert_ne!(normalized("ether1 down"), normalized("ether2 down"));
    }

    #[test]
    fn repeats_fold_into_one_row_that_moves_to_the_end() {
        let mut b = OsLogBook::default();
        let a = b.push(line(100, 4, "r8169", "ether2: rx_missed 1"));
        b.push(line(101, 6, "r8169", "ether1: Link is Up"));
        let Pushed::New(id) = a else { panic!() };
        for i in 0..36 {
            assert_eq!(b.push(line(110 + i * 16, 4, "r8169", &format!("ether2: rx_missed {i}"))), Pushed::Repeat(id));
        }
        assert_eq!(b.len(), 2);
        let rows: Vec<&Entry> = b.since(0).collect();
        let last = rows.last().unwrap();
        assert_eq!((last.id, last.count), (id, 37));
        assert_eq!(last.first_us, 100_000_000);
        assert_eq!(last.line.message, "ether2: rx_missed 35", "the newest text");
        assert_eq!(b.since(last.seq - 1).count(), 1, "since: only what changed");
        assert_eq!((b.lines_in, b.repeats), (38, 36));
        assert_eq!(b.get(id).map(|e| e.count), Some(37));
        // Another severity, unit or source: another row.
        b.push(line(700, 3, "r8169", "ether2: rx_missed 1"));
        b.push(line(700, 4, "igb", "ether2: rx_missed 1"));
        assert_eq!(b.len(), 4);
        // Out of the window: a new row.
        b.push(line(100 + 36 * 16 + 601, 4, "r8169", "ether2: rx_missed 9"));
        assert_eq!(b.len(), 5);
        assert_eq!(b.counts(), Counts { error: 1, warning: 3, info: 1 });
    }

    #[test]
    fn out_of_order_lines_keep_the_oldest_time_and_newest_text() {
        let mut b = OsLogBook::default();
        b.push(line(500, 4, "u", "x 2"));
        b.push(line(400, 4, "u", "x 1"));
        let e = b.since(0).next().unwrap();
        assert_eq!((e.first_us, e.line.time_us, e.line.message.as_str(), e.count), (400_000_000, 500_000_000, "x 2", 2));
    }

    #[test]
    fn ring_is_bounded_and_counts_follow() {
        let mut b = OsLogBook::with_capacity(1000);
        for i in 0..5000u64 {
            b.push(line(i, u8::try_from(i % 8).unwrap(), "u", &format!("m{i}")));
        }
        assert_eq!(b.len(), 1000);
        let c = b.counts();
        assert_eq!(c.error + c.warning + c.info, 1000);
        assert_eq!(b.since(0).next().unwrap().line.message, "m4000");
        // The keys of evicted rows are gone: the same line again is new.
        assert!(matches!(b.push(line(4999, 1, "u", "m4001")), Pushed::New(_)));
        assert!(b.by_key.len() <= 1001);
    }

    #[test]
    fn hundred_thousand_lines_through_the_ring() {
        // 100 k lines: a storm of one repeated message and many distinct.
        let mut b = OsLogBook::default();
        let t = std::time::Instant::now();
        for i in 0..100_000u64 {
            let msg = if i % 2 == 0 {
                "ether2: rx_missed 1".to_owned()
            } else {
                format!("conn {i:x} reset by peer z{}", i % 30_011)
            };
            b.push(line(1_000 + i / 100, u8::try_from(i % 8).unwrap(), "u", &msg));
        }
        let took = t.elapsed();
        assert_eq!(b.len(), CAPACITY);
        assert_eq!(b.lines_in, 100_000);
        assert!(b.repeats >= 49_900, "{}", b.repeats);
        let since = std::time::Instant::now();
        let n = b.since(b.last_seq() - 500).count();
        // Rows whose last change is among the newest 500 lines.
        assert!(n > 0 && n <= 500, "{n}");
        eprintln!(
            "oslog ring: 100000 lines in {took:?} ({:.0} ns/line), since() of 500 in {:?}",
            took.as_nanos() as f64 / 100_000.0,
            since.elapsed()
        );
    }

    #[test]
    fn hostile_lines_are_cut() {
        let mut b = OsLogBook::default();
        let mut l = line(1, 99, &"u".repeat(500), &"\u{202E}x".repeat(5000));
        l.device = "d".repeat(500);
        b.push(l);
        let e = b.since(0).next().unwrap();
        assert_eq!(e.line.severity, 7);
        assert!(e.line.unit.chars().count() <= MAX_UNIT + 1);
        assert!(e.line.message.chars().count() <= MAX_MESSAGE + 1);
        assert!(!e.line.message.contains('\u{202E}'));
    }
}

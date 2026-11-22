//! A hashed timer wheel (Varghese & Lauck) for one engine thread: insert
//! and expiry are O(1) per timer, so 1 000 sessions at 50 ms (60 000
//! timer events per second) cost the same per event as 10.
//!
//! Lazy: a session keeps its own deadline and the wheel only says "look at
//! key K about now". A timer that moved later is not removed; when the old
//! entry fires the caller sees the session has nothing due and inserts the
//! new deadline (a stale entry costs one lookup).

/// The wheel. `tick_us` is the slot width (the timing granularity);
/// `slots` × `tick_us` the horizon (later timers wait in the last slot and
/// are re-filed when it comes round).
#[derive(Debug, Clone)]
pub struct Wheel {
    tick_us: u64,
    slots: Vec<Vec<(u64, u32)>>,
    /// The tick the next `advance` starts from.
    cursor: u64,
    len: usize,
}

impl Wheel {
    pub fn new(tick_us: u64, slots: usize, now: u64) -> Self {
        let tick_us = tick_us.max(1);
        Self {
            tick_us,
            slots: vec![Vec::new(); slots.max(2)],
            cursor: now / tick_us,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot_of(&self, tick: u64) -> usize {
        (tick % self.slots.len() as u64) as usize
    }

    /// Files `key` to fire at `at` (µs). A time already past fires on the
    /// next `advance`.
    pub fn insert(&mut self, at: u64, key: u32) {
        let n = self.slots.len() as u64;
        let tick = (at / self.tick_us).clamp(self.cursor, self.cursor + n - 1);
        let i = self.slot_of(tick);
        if let Some(s) = self.slots.get_mut(i) {
            s.push((at, key));
            self.len += 1;
        }
    }

    /// Moves the wheel to `now`, appending to `due` every key whose time
    /// came. Entries of a later round stay (or are re-filed).
    pub fn advance(&mut self, now: u64, due: &mut Vec<u32>) {
        let target = now / self.tick_us;
        let n = self.slots.len() as u64;
        // Never more than one full turn: the slots behind are the same.
        let from = self.cursor.max(target.saturating_sub(n - 1));
        let mut refile: Vec<(u64, u32)> = Vec::new();
        for tick in from..=target {
            let i = self.slot_of(tick);
            let Some(slot) = self.slots.get_mut(i) else {
                continue;
            };
            let mut k = 0;
            while let Some(&(at, key)) = slot.get(k) {
                if at <= now {
                    due.push(key);
                    slot.swap_remove(k);
                    self.len -= 1;
                } else if at / self.tick_us > target {
                    refile.push((at, key));
                    slot.swap_remove(k);
                    self.len -= 1;
                } else {
                    k += 1;
                }
            }
        }
        self.cursor = target;
        for (at, key) in refile {
            self.insert(at, key);
        }
    }

    /// The time of the earliest slot with entries, scanning at most
    /// `limit` slots from the cursor (the thread's poll timeout).
    pub fn next_due(&self, limit: usize) -> Option<u64> {
        let n = self.slots.len().min(limit.max(1));
        (0..n as u64).find_map(|d| {
            let tick = self.cursor + d;
            let slot = self.slots.get(self.slot_of(tick))?;
            slot.iter()
                .map(|&(at, _)| at)
                .filter(|&at| at / self.tick_us <= tick)
                .min()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_in_order_of_slots() {
        let mut w = Wheel::new(1_000, 64, 0);
        w.insert(5_500, 1);
        w.insert(2_000, 2);
        w.insert(500_000, 3); // beyond the 64 ms horizon
        let mut due = vec![];
        w.advance(1_999, &mut due);
        assert!(due.is_empty());
        w.advance(2_000, &mut due);
        assert_eq!(due, vec![2]);
        assert_eq!(w.next_due(64), Some(5_500));
        due.clear();
        w.advance(10_000, &mut due);
        assert_eq!(due, vec![1]);
        due.clear();
        for t in (10_000..=499_000).step_by(7_000) {
            w.advance(t, &mut due);
        }
        assert!(due.is_empty());
        w.advance(500_000, &mut due);
        assert_eq!(due, vec![3]);
        assert!(w.is_empty());
    }

    #[test]
    fn a_long_jump_fires_everything_once() {
        let mut w = Wheel::new(1_000, 16, 0);
        for k in 0..100u32 {
            w.insert(u64::from(k) * 3_000, k);
        }
        let mut due = vec![];
        w.advance(1_000_000, &mut due);
        due.sort_unstable();
        assert_eq!(due, (0..100).collect::<Vec<_>>());
        assert!(w.is_empty());
    }

    #[test]
    fn past_times_fire_next() {
        let mut w = Wheel::new(1_000, 16, 50_000);
        w.insert(10, 7);
        let mut due = vec![];
        w.advance(50_000, &mut due);
        assert_eq!(due, vec![7]);
    }
}

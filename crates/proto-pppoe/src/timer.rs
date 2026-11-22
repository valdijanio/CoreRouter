//! The explicit clock and a hashed timing wheel.
//!
//! The machines never read a clock: every entry point takes `now`
//! ([`Millis`], monotonic milliseconds from the caller). Each session keeps
//! its own deadlines and holds at most one live wheel entry, for the
//! earliest; entries that went stale (the session moved its deadline or was
//! freed) are recognised by their generation and skipped when they fire.

/// Monotonic milliseconds supplied by the caller (`Hal::now`-style).
pub type Millis = u64;

/// One scheduled wake-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub deadline: Millis,
    /// Slab index of the owner.
    pub slot: u32,
    /// The owner's generation when scheduled.
    pub gen_: u32,
}

/// Slot width: 16 ms, below the RFC 1661 timers' resolution (seconds).
const TICK_MS: u64 = 16;
/// 4096 slots × 16 ms ≈ 65 s per turn; later deadlines wait in their slot
/// for their turn (checked on every visit).
const SLOTS: usize = 4096;

pub struct Wheel {
    slots: Vec<Vec<Entry>>,
    /// Tick last processed.
    cur: u64,
    len: usize,
}

impl Wheel {
    pub fn new(now: Millis) -> Wheel {
        Wheel {
            slots: (0..SLOTS).map(|_| Vec::new()).collect(),
            cur: now / TICK_MS,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert(&mut self, e: Entry) {
        let tick = (e.deadline / TICK_MS).max(self.cur);
        let i = (tick % SLOTS as u64) as usize;
        if let Some(s) = self.slots.get_mut(i) {
            s.push(e);
            self.len += 1;
        }
    }

    /// Moves every entry due at `now` into `due`.
    pub fn expire(&mut self, now: Millis, due: &mut Vec<Entry>) {
        let target = now / TICK_MS;
        if target < self.cur {
            return;
        }
        let steps = (target - self.cur + 1).min(SLOTS as u64);
        for k in 0..steps {
            let i = ((self.cur + k) % SLOTS as u64) as usize;
            let Some(s) = self.slots.get_mut(i) else {
                continue;
            };
            let before = s.len();
            s.retain(|e| {
                if e.deadline <= now {
                    due.push(*e);
                    false
                } else {
                    true
                }
            });
            self.len -= before - s.len();
        }
        self.cur = target;
    }

    /// The earliest deadline in the next turn of the wheel (an upper bound
    /// on how long the caller may sleep), or `None` when empty.
    pub fn next_deadline(&self) -> Option<Millis> {
        if self.len == 0 {
            return None;
        }
        for k in 0..SLOTS as u64 {
            let i = ((self.cur + k) % SLOTS as u64) as usize;
            let turn_end = (self.cur + k + 1) * TICK_MS;
            if let Some(m) = self
                .slots
                .get(i)
                .and_then(|s| s.iter().map(|e| e.deadline).filter(|d| *d < turn_end).min())
            {
                return Some(m);
            }
        }
        // Everything is more than a turn away: wake at the end of this turn.
        Some((self.cur + SLOTS as u64) * TICK_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(deadline: Millis, slot: u32) -> Entry {
        Entry {
            deadline,
            slot,
            gen_: 0,
        }
    }

    #[test]
    fn fires_in_order_of_time_not_insertion() {
        let mut w = Wheel::new(0);
        w.insert(e(3000, 1));
        w.insert(e(1000, 2));
        w.insert(e(200_000, 3)); // beyond one turn
        let mut due = Vec::new();
        w.expire(999, &mut due);
        assert!(due.is_empty());
        assert_eq!(w.next_deadline(), Some(1000));
        w.expire(1000, &mut due);
        assert_eq!(due, vec![e(1000, 2)]);
        due.clear();
        w.expire(150_000, &mut due);
        assert_eq!(due, vec![e(3000, 1)]);
        due.clear();
        w.expire(199_999, &mut due);
        assert!(due.is_empty());
        w.expire(200_000, &mut due);
        assert_eq!(due, vec![e(200_000, 3)]);
        assert!(w.is_empty());
        assert_eq!(w.next_deadline(), None);
    }

    #[test]
    fn past_deadlines_fire_on_next_expire() {
        let mut w = Wheel::new(10_000);
        w.insert(e(5, 9));
        let mut due = Vec::new();
        w.expire(10_000, &mut due);
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn time_going_backwards_is_ignored() {
        let mut w = Wheel::new(10_000);
        w.insert(e(10_500, 1));
        let mut due = Vec::new();
        w.expire(5, &mut due);
        assert!(due.is_empty());
        assert_eq!(w.len(), 1);
    }
}

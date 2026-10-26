// SPDX-License-Identifier: GPL-2.0-or-later
//! G4.9b / G4.3cc on the host: the shaper and the policer against their
//! bounds, RouterOS's burst semantics in the long run, and other CPUs
//! racing on the same state between a read and its compare-and-swap.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use corerouter_dataplane_ebpf_common::policer::{self, NANOS, Rate};
use corerouter_dataplane_ebpf_common::shaper::{self, FULL, KIND_FIFO, Queue, Verdict};
use corerouter_dataplane_ebpf_common::words::Words;
use proptest::prelude::*;

/// State words that let "other CPUs" move them between this CPU's read and
/// its compare-and-swap: before each `cas`, `others` packets (if any are
/// left) are admitted on the same state, so the swap sees a value that
/// changed under it — the race the BPF atomics must survive.
struct Racy<const N: usize> {
    st: [u64; N],
    others: Vec<u64>,
    other_passed: u64,
    rate: Rate,
    now: u64,
    nested: bool,
    /// Races lost by the current packet: at most three (four in a row is
    /// the documented drop, not a race to survive).
    lost: usize,
}

impl<const N: usize> Words for Racy<N> {
    fn get(&self, i: usize) -> u64 {
        self.st.get(i)
    }
    fn set(&mut self, i: usize, v: u64) {
        self.st.set(i, v)
    }
    fn cas(&mut self, i: usize, old: u64, new: u64) -> bool {
        if !self.nested
            && self.lost < 3
            && let Some(b) = self.others.pop()
        {
            self.lost += 1;
            // Another CPU's whole packet, in this instant.
            self.nested = true;
            let r = self.rate;
            let now = self.now;
            if policer::admit(&mut self.st, &r, now, b) {
                self.other_passed += b;
            }
            self.nested = false;
        }
        self.st.cas(i, old, new)
    }
    fn add(&mut self, i: usize, v: u64) {
        self.st.add(i, v)
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// G4.3cc: with up to 16 "CPUs" interleaving on one subscriber, the
    /// policer never passes more than its bucket plus the rate, and under
    /// load still passes the rate (a lost swap retries, it does not double
    /// count; four lost swaps in a row drop the packet).
    #[test]
    fn policer_exact_under_races(
        rate_k in 256u64..100_000,
        cpus in 1usize..16,
        size in 64u64..1500,
        secs in 1u64..4,
    ) {
        let r = Rate::mikrotik(rate_k * 1000, 0, 0, 0);
        let mut racy = Racy::<{ policer::STATE_WORDS }> {
            st: policer::fresh(&r, 0),
            others: Vec::new(),
            other_passed: 0,
            rate: r,
            now: 0,
            nested: false,
            lost: 0,
        };
        // Three times the rate offered, `cpus` packets per instant.
        let step = (NANOS * size * cpus as u64 / (3 * r.rate)).max(1);
        let (mut t, mut passed) = (0u64, 0u64);
        while t < secs * NANOS {
            racy.now = t;
            racy.lost = 0;
            racy.others = vec![size; cpus - 1];
            if policer::admit(&mut racy, &r, t, size) {
                passed += size;
            }
            // Whatever the race did not consume goes in after.
            while let Some(b) = racy.others.pop() {
                if policer::admit(&mut racy.st, &r, t, b) {
                    passed += b;
                }
            }
            t += step;
        }
        passed += racy.other_passed;
        let upper = r.depth + r.rate * secs;
        prop_assert!(passed <= upper, "{passed} > {upper}");
        let lower = (r.rate * secs).saturating_sub(cpus as u64 * size + r.rate * step / NANOS);
        prop_assert!(passed >= lower, "{passed} < {lower}");
    }

    /// The shaper's departures never run ahead of bucket + rate × time,
    /// and nothing waits past the queue's limit.
    #[test]
    fn shaper_bounds(
        rate_k in 256u64..100_000,
        over in 11u64..40,
        size in 64u64..1500,
        limit_ms in 2u64..200,
    ) {
        let r = Rate::mikrotik(rate_k * 1000, 0, 0, 0);
        let q = Queue { kind: KIND_FIFO, limit_ns: limit_ms * 1_000_000, ..Queue::default() };
        let mut st = shaper::fresh(&r, 0);
        let step = (NANOS * size * 10 / (over * r.rate)).max(1);
        let (mut t, mut last, mut sent) = (1u64, 0u64, 0u64);
        while t < 2 * NANOS {
            match shaper::depart(&mut st, FULL, &r, &q, t, size, 0) {
                Verdict::Drop => {}
                v => {
                    let at = v.time().filter(|x| *x > 0).unwrap_or(t);
                    prop_assert!(at - t <= q.limit_ns, "waited {} > {}", at - t, q.limit_ns);
                    last = last.max(at);
                    sent += size;
                    // Bytes that left by `at` never exceed bucket + rate × at.
                    let allowed = r.depth + size + r.rate * at / NANOS;
                    prop_assert!(sent <= allowed, "{sent} > {allowed} at {at}");
                }
            }
            t += step;
        }
        // The rate is used: what left by the end is at least rate × time
        // minus a packet and the clock's last step (and the 1e-4 the clock
        // loses by rounding each packet's time up).
        let lower = (r.rate * last / NANOS * 9_999 / 10_000).saturating_sub(3 * size);
        prop_assert!(sent >= lower, "{sent} < {lower}");
    }

    /// RouterOS burst semantics (help.mikrotik.com, Queues: the burst is on
    /// while the average over burst-time is under the threshold): under a
    /// load above the burst rate the long-run average sits at the
    /// threshold, never under the plain rate nor over the burst rate.
    #[test]
    fn routeros_burst_long_run_average(
        rate_m in 1u64..20,
        burst_x in 2u64..4,
        thr_pct in 20u64..90,
        time_s in 2u64..10,
    ) {
        let rate = rate_m * 1_000_000;
        let burst = rate * burst_x;
        let threshold = rate + (burst - rate) * thr_pct / 100;
        let r = Rate::mikrotik(rate, burst, threshold, time_s * NANOS);
        let mut st = policer::fresh(&r, 0);
        let secs = 12 * time_s;
        let step = NANOS * 1500 / (2 * r.burst_rate);
        let (mut t, mut tail, mut tail_from) = (0u64, 0u64, 0u64);
        tail_from += 4 * time_s * NANOS;
        while t < secs * NANOS {
            if policer::admit(&mut st, &r, t, 1500) && t >= tail_from {
                tail += 1500;
            }
            t += step;
        }
        let avg = tail * 8 * NANOS / (secs * NANOS - tail_from);
        // RouterOS samples the average in 16 slots; ±8% covers the
        // sawtooth of a 2× burst over the window.
        prop_assert!(avg.abs_diff(threshold) <= threshold * 8 / 100, "avg {avg} threshold {threshold}");
        prop_assert!(avg >= rate * 98 / 100 && avg <= burst * 102 / 100);
    }
}

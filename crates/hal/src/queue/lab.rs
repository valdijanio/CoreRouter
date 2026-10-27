//! The virtual lab's shaper (G4.9g): it shapes nothing, but counts as if
//! each queue carried traffic, so the Queues window, its "Queue <name>"
//! modal and the queue histories move in the lab and in screenshots.
//!
//! Deterministic: every call to [`LabShaper::status`] is one second, and
//! the demand of a queue is a triangle between 40 % and 110 % of its
//! max-limit (a phase per queue key), so it spends part of each two minutes
//! at its limit (queueing and dropping), and a queue with a burst-limit
//! bursts for the first seconds of each cycle.

use std::collections::BTreeMap;

use super::{DirSpec, QueueCounters, ShaperPlan, ShaperStatus};

/// Seconds of one demand cycle.
const CYCLE: u64 = 120;
/// The rate a queue without a max-limit is counted at, bits/s.
const UNLIMITED: u64 = 10_000_000;
/// Bytes of the average lab packet.
const PACKET: u64 = 1000;

#[derive(Debug, Clone, Default)]
pub struct LabShaper {
    /// Key → (upload, download, PCQ).
    queues: Vec<(String, DirSpec, DirSpec)>,
    counters: BTreeMap<String, QueueCounters>,
    second: u64,
}

fn phase(key: &str) -> u64 {
    key.bytes()
        .fold(7u64, |h, b| h.wrapping_mul(31).wrapping_add(u64::from(b)))
}

impl LabShaper {
    pub fn apply(&mut self, plan: &ShaperPlan) {
        self.queues = plan
            .queues
            .iter()
            .map(|q| (q.key.clone(), q.upload, q.download))
            .collect();
        self.counters
            .retain(|k, _| plan.queues.iter().any(|q| q.key == *k));
    }

    /// One more second of counting.
    pub fn status(&mut self) -> ShaperStatus {
        self.second = self.second.wrapping_add(1);
        let t = self.second;
        for (key, up, down) in &self.queues {
            let p = phase(key);
            let c = self.counters.entry(key.clone()).or_default();
            for (i, d) in [up, down].into_iter().enumerate() {
                let limit = if d.rate_bps == 0 {
                    UNLIMITED
                } else {
                    d.rate_bps
                };
                let x = (t + p / (i as u64 + 1)) % CYCLE;
                let tri = if x < CYCLE / 2 { x } else { CYCLE - x };
                // Demand, thousandths of the limit: 400..=1100.
                let demand = 400 + tri * 700 / (CYCLE / 2);
                let mut rate = limit.saturating_mul(demand.min(1000)) / 1000;
                if d.burst_bps > d.rate_bps && x < 6 {
                    rate = d.burst_bps;
                }
                let pkts = rate / 8 / PACKET;
                let (Some(r), Some(b), Some(n), Some(dr), Some(q)) = (
                    c.rate_bps.get_mut(i),
                    c.bytes.get_mut(i),
                    c.packets.get_mut(i),
                    c.dropped.get_mut(i),
                    c.queued_us.get_mut(i),
                ) else {
                    continue;
                };
                *r = rate;
                *b = b.wrapping_add(rate / 8);
                *n = n.wrapping_add(pkts);
                // Over the limit: the excess is dropped; near it, packets
                // wait (download is a queue, upload a policer).
                if demand > 1000 {
                    *dr = dr.wrapping_add(pkts * (demand - 1000) / 1000);
                }
                *q = if i == 1 && demand > 900 {
                    (demand - 900) * 200
                } else {
                    0
                };
            }
            c.pcq_queues = if up.pcq.is_some() || down.pcq.is_some() {
                3 + (p % 20) as u32
            } else {
                0
            };
        }
        ShaperStatus {
            queues: self.counters.iter().map(|(k, c)| (k.clone(), *c)).collect(),
            unavailable: Some("virtual lab: simulated shaper counters, nothing is shaped".into()),
            ..ShaperStatus::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::QueueSpec;

    #[test]
    fn counts_a_cycle_at_and_below_the_limit() {
        let mut lab = LabShaper::default();
        let spec = DirSpec {
            rate_bps: 2_000_000,
            ..DirSpec::default()
        };
        lab.apply(&ShaperPlan {
            queues: vec![QueueSpec {
                key: "*1".into(),
                upload: spec,
                download: spec,
            }],
            ..ShaperPlan::default()
        });
        let mut max = 0;
        let mut min = u64::MAX;
        let mut last = QueueCounters::default();
        for _ in 0..CYCLE {
            let st = lab.status();
            last = st.queues[0].1;
            max = max.max(last.rate_bps[1]);
            min = min.min(last.rate_bps[1]);
        }
        assert_eq!(max, 2_000_000, "never above the max-limit");
        assert_eq!(min, 800_000);
        assert!(last.dropped[1] > 0 && last.bytes[1] > 0);
        assert_eq!(last.queued_us[0], 0, "upload is policed, nothing waits");
    }
}

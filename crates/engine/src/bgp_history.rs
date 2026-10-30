//! The flap history of each BGP session (G3.3, with G3.2c): when it went
//! down and came back, why, and how long it had been up. Built from the
//! samples the daemon's `frr` service takes every 2 s
//! ([`Session::set_routing_status`]), so a session that went down and up,
//! or up and down, between two samples is still caught by its flap counter.
//!
//! A ring per session ([`MAX_EVENTS`]) and a bound on sessions
//! ([`MAX_SESSIONS`]): operational state, never saved, gone on restart.

use std::collections::{HashMap, VecDeque};

use corerouter_model::routing_state::BgpSession;
use serde::Serialize;

use crate::Session;

pub const MAX_EVENTS: usize = 64;
pub const MAX_SESSIONS: usize = 10_000;
const MAX_REASON: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlapEvent {
    /// Unix time of the sample that saw it.
    pub at: Option<u64>,
    /// `down`, `up`, or `flap` (down and up again between two samples). A
    /// session that came up and went down again between two samples (a
    /// max-prefix Cease right after Established) is a `down`.
    pub event: &'static str,
    pub state: String,
    /// The last NOTIFICATION or the daemon's reason, for `down`/`flap`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How long it had been up before going down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
}

#[derive(Debug, Default)]
struct Seen {
    established: bool,
    flaps: Option<u64>,
    uptime: Option<u64>,
}

#[derive(Debug, Default)]
pub struct BgpHistory {
    seen: HashMap<String, Seen>,
    events: HashMap<String, VecDeque<FlapEvent>>,
    /// The key → connection and address, for the answer.
    names: HashMap<String, (Option<String>, String)>,
}

fn key(b: &BgpSession) -> String {
    format!("{}/{}", b.instance, b.remote_address)
}

fn reason(b: &BgpSession) -> Option<String> {
    b.last_error
        .as_deref()
        .or(b.reason.as_deref())
        .filter(|r| !r.is_empty())
        .map(|r| crate::logging::cut(r, MAX_REASON))
}

impl BgpHistory {
    /// Compare a new sample with the last one.
    pub fn record(&mut self, sample: &[BgpSession], now: Option<u64>) {
        for b in sample {
            let k = key(b);
            if !self.seen.contains_key(&k) && self.seen.len() >= MAX_SESSIONS {
                continue;
            }
            let prev = self.seen.remove(&k);
            let mut push = |e: FlapEvent| {
                let ring = self.events.entry(k.clone()).or_default();
                if ring.len() >= MAX_EVENTS {
                    ring.pop_front();
                }
                ring.push_back(e);
            };
            if let Some(p) = &prev {
                let more_flaps = matches!((p.flaps, b.flaps), (Some(a), Some(n)) if n > a);
                let event = match (p.established, b.established) {
                    (true, false) => Some("down"),
                    (false, true) => Some("up"),
                    (true, true) if more_flaps => Some("flap"),
                    (false, false) if more_flaps => Some("down"),
                    _ => None,
                };
                if let Some(event) = event {
                    push(FlapEvent {
                        at: now,
                        event,
                        state: b.state.clone(),
                        reason: (event != "up").then(|| reason(b)).flatten(),
                        uptime_secs: (event != "up").then_some(p.uptime).flatten(),
                    });
                }
            }
            self.names
                .insert(k.clone(), (b.connection.clone(), b.remote_address.clone()));
            self.seen.insert(
                k,
                Seen {
                    established: b.established,
                    flaps: b.flaps,
                    uptime: b.established.then_some(b.uptime_secs).flatten(),
                },
            );
        }
    }

    /// Events, newest first, of every session or of one connection.
    pub fn list(&self, connection: Option<&str>) -> Vec<(Option<String>, String, FlapEvent)> {
        let mut out = Vec::new();
        for (k, ring) in &self.events {
            let (conn, addr) = self.names.get(k).cloned().unwrap_or_default();
            if connection.is_some_and(|c| conn.as_deref() != Some(c)) {
                continue;
            }
            for e in ring {
                out.push((conn.clone(), addr.clone(), e.clone()));
            }
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.2.at));
        out
    }
}

impl Session {
    pub(crate) fn record_bgp_history(&mut self, sample: &[BgpSession]) {
        let now = self.now();
        if let Some(h) = self.ext_mut::<BgpHistory>() {
            h.record(sample, now);
        }
    }

    pub(crate) fn bgp_history(&self) -> Option<&BgpHistory> {
        self.ext::<BgpHistory>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(established: bool, flaps: u64, uptime: u64) -> BgpSession {
        BgpSession {
            instance: "default".into(),
            remote_address: "192.0.2.1".into(),
            connection: Some("up1".into()),
            state: if established { "established" } else { "active" }.into(),
            established,
            flaps: Some(flaps),
            uptime_secs: Some(uptime),
            last_error: (!established).then(|| "Hold Timer Expired".into()),
            ..BgpSession::default()
        }
    }

    #[test]
    fn downs_ups_and_flaps_between_samples() {
        let mut h = BgpHistory::default();
        h.record(&[s(true, 0, 100)], Some(1));
        assert!(h.list(None).is_empty(), "the first sample is the baseline");
        h.record(&[s(false, 1, 3)], Some(3));
        h.record(&[s(true, 1, 1)], Some(5));
        // Down and up again between two samples: only the counter moved.
        h.record(&[s(true, 2, 1)], Some(7));
        let l = h.list(Some("up1"));
        let events: Vec<&str> = l.iter().map(|e| e.2.event).collect();
        assert_eq!(events, ["flap", "up", "down"]);
        let down = &l[2].2;
        assert_eq!((down.uptime_secs, down.reason.as_deref()), (Some(100), Some("Hold Timer Expired")));
        assert!(h.list(Some("other")).is_empty());
    }

    #[test]
    fn up_and_down_between_two_samples_is_a_down() {
        // Found against FRR (scripts/bgp-crcr-userns.sh maxprefix): the
        // session comes up and the prefix limit closes it within 2 s, so
        // both samples say idle and only the counter moved.
        let mut h = BgpHistory::default();
        let idle = |flaps, why: &str| BgpSession {
            last_error: Some(why.into()),
            uptime_secs: None,
            ..s(false, flaps, 0)
        };
        h.record(&[idle(0, "No AFI/SAFI activated for peer")], Some(1));
        h.record(&[idle(1, "Reached received prefix count")], Some(3));
        h.record(&[idle(1, "Reached received prefix count")], Some(5));
        let l = h.list(Some("up1"));
        let got: Vec<_> = l.iter().map(|e| (e.2.event, e.2.reason.as_deref(), e.2.uptime_secs)).collect();
        assert_eq!(got, [("down", Some("Reached received prefix count"), None)]);
    }

    #[test]
    fn the_ring_is_bounded() {
        let mut h = BgpHistory::default();
        for i in 0..(MAX_EVENTS as u64 * 2) {
            h.record(&[s(i % 2 == 0, i, 1)], Some(i));
        }
        assert_eq!(h.list(None).len(), MAX_EVENTS);
    }
}

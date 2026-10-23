//! The lab's conntrack events (G4.4b): the lab table (`lab_conntrack`)
//! comes alive for the flow exporter. Every call to `recv` is a step:
//! the counters of the connections grow, a few connections end (a
//! `DESTROY` with their counters) and are replaced by new ones (a `NEW`
//! with a fresh id), so `IP › Traffic Flow` has flows, NAT events and top
//! talkers to show without a kernel. Deterministic, no clock (the caller
//! paces the steps).

use std::sync::{Arc, Mutex, PoisonError};

use crate::HalError;
use crate::conntrack::{Conn, Event, EventKind, EventSource, TableReader};

/// Connections that end (and start) per step.
const TURNOVER: usize = 4;

#[derive(Debug, Default)]
struct Lab {
    conns: Vec<Conn>,
    step: u64,
    next_id: u32,
    cursor: usize,
}

fn mix(x: u64) -> u64 {
    x.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
        >> 33
}

impl Lab {
    fn step(&mut self, max: usize, out: &mut Vec<Event>) {
        self.step += 1;
        let step = self.step;
        for (i, c) in self.conns.iter_mut().enumerate() {
            let h = mix(step ^ (i as u64).wrapping_mul(0x9e37));
            // Most connections trickle; one in 16 is a heavy download.
            let (up, down) = if i % 16 == 0 {
                (h % 4, 40 + h % 40)
            } else {
                (h % 2, h % 3)
            };
            c.orig_packets += up;
            c.orig_bytes += up * (60 + h % 400);
            c.reply_packets += down;
            c.reply_bytes += down * (600 + h % 900);
        }
        if self.conns.is_empty() {
            return;
        }
        for _ in 0..TURNOVER.min(max / 2) {
            let at = self.cursor % self.conns.len();
            self.cursor = self.cursor.wrapping_add(7);
            let Some(slot) = self.conns.get_mut(at) else {
                continue;
            };
            let mut ended = slot.clone();
            // TCP leaves in time-wait, the rest by timeout.
            if ended.tcp_state.is_some() {
                ended.tcp_state = Some(7);
            }
            self.next_id = self.next_id.wrapping_add(1);
            slot.id = self.next_id;
            slot.orig_packets = 1;
            slot.orig_bytes = 60;
            slot.reply_packets = 0;
            slot.reply_bytes = 0;
            let fresh = slot.clone();
            out.push(Event {
                kind: EventKind::Destroy,
                conn: ended,
                start_ns: None,
                stop_ns: None,
            });
            out.push(Event {
                kind: EventKind::New,
                conn: fresh,
                start_ns: None,
                stop_ns: None,
            });
        }
    }
}

pub struct LabEvents {
    lab: Arc<Mutex<Lab>>,
}

impl LabEvents {
    pub fn new(conns: Vec<Conn>) -> Self {
        let next_id = conns.iter().map(|c| c.id).max().unwrap_or(0);
        Self {
            lab: Arc::new(Mutex::new(Lab {
                conns,
                next_id,
                ..Lab::default()
            })),
        }
    }
}

impl EventSource for LabEvents {
    fn recv(&mut self, _wait_ms: u32, max: usize, out: &mut Vec<Event>) -> Result<(), HalError> {
        self.lab
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .step(max, out);
        Ok(())
    }

    fn table_reader(&self) -> Box<dyn TableReader> {
        Box::new(LabTable(self.lab.clone()))
    }

    fn lost(&self) -> u64 {
        0
    }

    fn name(&self) -> &'static str {
        "lab"
    }
}

struct LabTable(Arc<Mutex<Lab>>);

impl TableReader for LabTable {
    fn read(&mut self) -> Result<(Vec<Conn>, bool), HalError> {
        let lab = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Ok((lab.conns.clone(), true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::{Tuple, status};

    #[test]
    fn steps_end_and_open_connections_with_growing_counters() {
        let c = Conn {
            id: 5,
            protocol: 6,
            orig: Tuple {
                src: "100.64.0.1".parse().unwrap(),
                dst: "192.0.2.1".parse().unwrap(),
                src_port: 1000,
                dst_port: 443,
            },
            reply: Tuple {
                src: "192.0.2.1".parse().unwrap(),
                dst: "203.0.113.1".parse().unwrap(),
                src_port: 443,
                dst_port: 2000,
            },
            status: status::SRC_NAT,
            timeout: 10,
            tcp_state: Some(3),
            mark: 0,
            orig_packets: 0,
            orig_bytes: 0,
            reply_packets: 0,
            reply_bytes: 0,
        };
        let mut src = LabEvents::new(vec![c]);
        let mut out = Vec::new();
        src.recv(0, 100, &mut out).unwrap();
        src.recv(0, 100, &mut out).unwrap();
        assert!(out.len() >= 4);
        assert_eq!(out[0].kind, EventKind::Destroy);
        assert_eq!(out[0].conn.tcp_state, Some(7));
        assert_eq!(out[1].kind, EventKind::New);
        assert_eq!(out[1].conn.id, 6);
        let (table, complete) = src.table_reader().read().unwrap();
        assert!(complete);
        assert_eq!(table.len(), 1);
    }
}

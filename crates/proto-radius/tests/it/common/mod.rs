//! A virtual network for the client and the test server: datagrams with
//! latency and loss, delivered in time order, no sockets and no clock.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;

use corerouter_proto_radius::client::{Client, Event, SocketKey, Transmit};
use corerouter_proto_radius::testserver::TestServer;

pub struct Sent {
    pub t: Transmit,
    pub bytes: Vec<u8>,
    pub at: u64,
}

pub struct Net {
    pub now: u64,
    pub servers: Vec<(SocketAddr, TestServer)>,
    pub latency_ms: u64,
    /// Percent lost on the way to the servers and back.
    pub loss_up: u8,
    pub loss_down: u8,
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    dgrams: HashMap<u64, (Dest, SocketAddr, Vec<u8>)>,
    seq: u64,
    rng: u64,
    local: HashMap<SocketAddr, SocketKey>,
    pub sent: u64,
    pub lost: u64,
}

#[derive(Clone, Copy)]
enum Dest {
    Server(usize),
    Client(SocketKey),
}

pub fn local_addr(k: SocketKey) -> SocketAddr {
    SocketAddr::from(([10, 255, k.server as u8, 1], 40_000 + k.socket))
}

impl Net {
    pub fn new(servers: Vec<(SocketAddr, TestServer)>, seed: u64) -> Self {
        Self {
            now: 1_000,
            servers,
            latency_ms: 5,
            loss_up: 0,
            loss_down: 0,
            queue: BinaryHeap::new(),
            dgrams: HashMap::new(),
            seq: 0,
            rng: seed | 1,
            local: HashMap::new(),
            sent: 0,
            lost: 0,
        }
    }

    pub fn server(&mut self, addr: SocketAddr) -> &mut TestServer {
        &mut self.servers.iter_mut().find(|(a, _)| *a == addr).unwrap().1
    }

    fn lose(&mut self, pct: u8) -> bool {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        pct > 0 && self.rng % 100 < u64::from(pct)
    }

    fn push(&mut self, at: u64, dest: Dest, from: SocketAddr, bytes: Vec<u8>) {
        self.seq += 1;
        self.dgrams.insert(self.seq, (dest, from, bytes));
        self.queue.push(Reverse((at, self.seq)));
    }

    /// Send what the client has queued; `on_send` sees every datagram.
    pub fn flush(&mut self, c: &mut Client, on_send: &mut dyn FnMut(&Sent)) {
        let mut buf = Vec::new();
        while let Some(t) = c.poll_transmit(&mut buf) {
            on_send(&Sent {
                t,
                bytes: buf.clone(),
                at: self.now,
            });
            self.sent += 1;
            let from = local_addr(t.from);
            self.local.insert(from, t.from);
            if self.lose(self.loss_up) {
                self.lost += 1;
                continue;
            }
            let Some(i) = self.servers.iter().position(|(a, _)| *a == t.dest) else {
                continue;
            };
            let at = self.now + self.latency_ms;
            self.push(at, Dest::Server(i), from, buf.clone());
        }
    }

    /// Advance to the next event (or `until`), deliver, fire timers.
    /// Returns false when nothing is left before `until`.
    pub fn step(
        &mut self,
        c: &mut Client,
        until: u64,
        events: &mut dyn FnMut(Event),
        on_send: &mut dyn FnMut(&Sent),
    ) -> bool {
        drain(c, events);
        self.flush(c, on_send);
        let next_dgram = self.queue.peek().map(|Reverse((t, _))| *t);
        let next = match (next_dgram, c.poll_timeout()) {
            (Some(a), Some(b)) => a.min(b),
            (a, b) => match a.or(b) {
                Some(t) => t,
                None => return false,
            },
        };
        if next > until {
            self.now = until;
            return false;
        }
        self.now = self.now.max(next);
        while let Some(Reverse((t, s))) = self.queue.peek().copied() {
            if t > self.now {
                break;
            }
            self.queue.pop();
            let (dest, from, bytes) = self.dgrams.remove(&s).unwrap();
            match dest {
                Dest::Server(i) => {
                    let (addr, srv) = &mut self.servers[i];
                    let addr = *addr;
                    if let Some(r) = srv.handle(from, &bytes, self.now) {
                        if self.lose(self.loss_down) {
                            self.lost += 1;
                            continue;
                        }
                        let key = self.local[&r.to];
                        self.push(r.at_ms + self.latency_ms, Dest::Client(key), addr, r.bytes);
                    }
                }
                Dest::Client(k) => {
                    let _ = c.handle_input(k, from, &bytes, self.now);
                    drain(c, events);
                    self.flush(c, on_send);
                }
            }
        }
        c.handle_timeout(self.now);
        drain(c, events);
        self.flush(c, on_send);
        true
    }

    /// Run until nothing is pending or `until`.
    pub fn run(
        &mut self,
        c: &mut Client,
        until: u64,
        events: &mut dyn FnMut(Event),
        on_send: &mut dyn FnMut(&Sent),
    ) {
        while self.step(c, until, events, on_send) {}
    }
}

pub fn drain(c: &mut Client, events: &mut dyn FnMut(Event)) {
    while let Some(e) = c.poll_event() {
        events(e);
    }
}

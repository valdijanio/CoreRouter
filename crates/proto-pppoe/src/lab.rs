//! In-memory lab: N [`Client`]s against one or more [`Server`] shards over a
//! simulated access network with a fake clock, packet loss, duplication,
//! reordering and delay. Authentication and addressing are answered like a
//! RADIUS server and an IP pool would (with latency). The mass tests and the
//! benchmarks drive it; G4.3g replaces it with BNG Blaster on real links.
#![doc(hidden)]

use crate::client::{Client, ClientConfig, ClientEvent, ClientOutput, ClientPhase};
use crate::eth;
use crate::layers::AuthSet;
use crate::lcp::AuthProto;
use crate::server::{
    AuthVerdict, Authorization, Event, Ipv4Assignment, Server, ServerConfig, ServerOutput,
    SessionRef,
};
use crate::timer::Millis;
use crate::wire::Mac;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::Ipv4Addr;

/// Deterministic generator for the network's dice.
#[derive(Debug, Clone)]
pub struct Dice(u64);

impl Dice {
    pub fn new(seed: u64) -> Dice {
        // splitmix64 of the seed: every seed its own (non-zero) state.
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Dice((z ^ (z >> 31)) | 1)
    }
    pub fn roll(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// True with probability `ppm` per million.
    pub fn hit(&mut self, ppm: u32) -> bool {
        ppm != 0 && (self.roll() % 1_000_000) < u64::from(ppm)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.roll() % n }
    }
}

#[derive(Debug, Clone)]
pub struct LabConfig {
    pub clients: usize,
    /// Servers (one SESSION_ID space each), one per simulated access port.
    pub shards: usize,
    pub server: ServerConfig,
    /// Per million frames.
    pub loss_ppm: u32,
    pub dup_ppm: u32,
    pub reorder_ppm: u32,
    /// One-way latency, plus up to `jitter_ms` for reordered frames.
    pub delay_ms: u64,
    pub jitter_ms: u64,
    /// RADIUS-like answer latency.
    pub answer_ms: u64,
    /// Authentication protocols, cycled over the clients.
    pub auth_cycle: Vec<AuthProto>,
    /// Every n-th client uses a wrong password (0 = none).
    pub bad_password_every: usize,
    /// Spread of the clients' start times.
    pub start_spread_ms: u64,
    pub ipv6: bool,
    /// Clients start over 1–3 s after their session ends, as a CPE does.
    pub reconnect: bool,
    /// Prints every frame to or from this MAC (debugging a simulation).
    pub trace: Option<Mac>,
    /// Frames toward the servers for which this returns true are copied
    /// into [`Lab::tapped`] (to replay them later).
    pub tap: Option<fn(&[u8]) -> bool>,
    pub seed: u64,
}

impl Default for LabConfig {
    fn default() -> Self {
        LabConfig {
            clients: 10,
            shards: 1,
            server: ServerConfig::default(),
            loss_ppm: 0,
            dup_ppm: 0,
            reorder_ppm: 0,
            delay_ms: 1,
            jitter_ms: 20,
            answer_ms: 5,
            auth_cycle: vec![AuthProto::ChapMd5],
            bad_password_every: 0,
            start_spread_ms: 1000,
            ipv6: false,
            reconnect: true,
            trace: None,
            tap: None,
            seed: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dest {
    Server(usize),
    Client(usize),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Answer {
    /// `Some(success)` when the credentials are right.
    Auth(usize, SessionRef, Option<Option<[u8; 42]>>),
    Address(usize, SessionRef),
}

/// A frame on the wire: arrival time, sequence (FIFO among equals), where.
type InFlight = (Millis, u64, Dest, Vec<u8>);

/// Counters the tests assert on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabStats {
    pub frames: u64,
    pub lost: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub ups: u64,
    pub downs: u64,
    pub client_downs: u64,
    pub auth_rejects: u64,
    /// Why clients stopped / why the servers ended sessions.
    pub client_reasons: std::collections::BTreeMap<String, u64>,
    pub server_reasons: std::collections::BTreeMap<String, u64>,
    /// Client downs other than a server PADT: (time, client, reason).
    pub odd_downs: Vec<(Millis, usize, String)>,
}

pub struct Lab {
    pub now: Millis,
    pub cfg: LabConfig,
    pub servers: Vec<Server>,
    pub clients: Vec<Client>,
    pub stats: LabStats,
    /// Clients whose session is up, by (shard, SID).
    pub up: HashMap<(usize, u16), usize>,
    pub tapped: Vec<Vec<u8>>,
    queue: BinaryHeap<Reverse<InFlight>>,
    answers: BinaryHeap<Reverse<(Millis, u64, Answer)>>,
    client_timers: BinaryHeap<Reverse<(Millis, usize)>>,
    starts: BinaryHeap<Reverse<(Millis, usize)>>,
    server_tick: Millis,
    by_mac: HashMap<Mac, usize>,
    pool_next: u32,
    pool_free: Vec<Ipv4Addr>,
    leased: HashMap<(usize, u16), Ipv4Addr>,
    seq: u64,
    dice: Dice,
    sout: ServerOutput,
    cout: ClientOutput,
}

pub fn client_mac(i: usize) -> Mac {
    let b = (i as u32).to_be_bytes();
    Mac([0x02, 0xcc, b[0], b[1], b[2], b[3]])
}

pub fn ac_mac(shard: usize) -> Mac {
    Mac([0x02, 0xac, 0, 0, 0, shard as u8])
}

fn seed32(seed: u64, i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (d, b) in s
        .iter_mut()
        .zip(seed.to_be_bytes().into_iter().chain(i.to_be_bytes()))
    {
        *d = b;
    }
    s
}

impl Lab {
    pub fn new(cfg: LabConfig) -> Lab {
        let shards = cfg.shards.max(1);
        let servers = (0..shards)
            .map(|k| {
                let mut sc = cfg.server.clone();
                sc.ac_mac = ac_mac(k);
                sc.ipv6 = cfg.ipv6 || sc.ipv6;
                Server::new(sc, seed32(cfg.seed, 1_000_000 + k as u64), 0)
            })
            .collect();
        let cycle = if cfg.auth_cycle.is_empty() {
            vec![AuthProto::ChapMd5]
        } else {
            cfg.auth_cycle.clone()
        };
        let mut by_mac = HashMap::with_capacity(cfg.clients);
        let clients = (0..cfg.clients)
            .map(|i| {
                by_mac.insert(client_mac(i), i);
                let proto = cycle
                    .get(i % cycle.len())
                    .copied()
                    .unwrap_or(AuthProto::ChapMd5);
                Client::new(
                    ClientConfig {
                        mac: client_mac(i),
                        ifindex: (i % shards) as u32 + 1,
                        host_uniq: Some((i as u32).to_be_bytes().to_vec()),
                        username: format!("user{i}").into_bytes(),
                        password: Self::password(&cfg, i),
                        auth: AuthSet::new(&[proto]),
                        ipv6: cfg.ipv6,
                        ..ClientConfig::default()
                    },
                    seed32(cfg.seed, i as u64),
                )
            })
            .collect();
        Lab {
            now: 0,
            dice: Dice::new(cfg.seed),
            cfg,
            servers,
            clients,
            stats: LabStats::default(),
            up: HashMap::new(),
            tapped: Vec::new(),
            queue: BinaryHeap::new(),
            answers: BinaryHeap::new(),
            client_timers: BinaryHeap::new(),
            starts: BinaryHeap::new(),
            server_tick: 0,
            by_mac,
            pool_next: 0,
            pool_free: Vec::new(),
            leased: HashMap::new(),
            seq: 0,
            sout: ServerOutput::new(),
            cout: ClientOutput::new(),
        }
    }

    fn password(cfg: &LabConfig, i: usize) -> String {
        if cfg.bad_password_every != 0 && i % cfg.bad_password_every == cfg.bad_password_every - 1 {
            format!("wrong{i}")
        } else {
            format!("pass{i}")
        }
    }

    pub fn shard_of(&self, i: usize) -> usize {
        i % self.servers.len()
    }

    pub fn leases(&self) -> usize {
        self.leased.len()
    }

    /// Puts a frame on the simulated wire: maybe lost, duplicated or delayed
    /// past later frames.
    fn transmit(&mut self, dest: Dest, frame: &[u8]) {
        self.stats.frames += 1;
        let lost = self.dice.hit(self.cfg.loss_ppm);
        if let Some(t) = self.cfg.trace
            && let Ok(e) = eth::parse(frame)
            && (e.src == t || e.dst == t)
        {
            let ctl = crate::ppp::parse_session(frame).ok().and_then(|s| {
                let c = crate::ppp::parse_control(s.info).ok()?;
                Some((s.protocol, c.code, c.id))
            });
            let disc = crate::discovery::parse(frame)
                .ok()
                .map(|d| (d.code, d.session_id));
            let phase = self
                .by_mac
                .get(&t)
                .and_then(|i| self.clients.get(*i))
                .map(Client::phase);
            eprintln!(
                "trace t={} {dest:?} lost={lost} {ctl:x?} {disc:?} client={phase:?}",
                self.now
            );
        }
        if let (Dest::Server(_), Some(tap)) = (dest, self.cfg.tap)
            && tap(frame)
        {
            self.tapped.push(frame.to_vec());
        }
        if lost {
            self.stats.lost += 1;
            return;
        }
        let copies = if self.dice.hit(self.cfg.dup_ppm) {
            self.stats.duplicated += 1;
            2
        } else {
            1
        };
        for _ in 0..copies {
            let mut at = self.now + self.cfg.delay_ms;
            if self.dice.hit(self.cfg.reorder_ppm) {
                self.stats.reordered += 1;
                at += 1 + self.dice.below(self.cfg.jitter_ms.max(1));
            }
            self.seq += 1;
            self.queue
                .push(Reverse((at, self.seq, dest, frame.to_vec())));
        }
    }

    /// Injects a raw frame toward a server (attack traffic).
    pub fn inject(&mut self, shard: usize, frame: &[u8]) {
        self.seq += 1;
        self.queue.push(Reverse((
            self.now,
            self.seq,
            Dest::Server(shard),
            frame.to_vec(),
        )));
    }

    fn flush_server(&mut self, shard: usize) {
        let out = std::mem::take(&mut self.sout);
        for (_ifindex, f) in out.frames() {
            let Ok(e) = eth::parse(f) else { continue };
            if let Some(&i) = self.by_mac.get(&e.dst) {
                self.transmit(Dest::Client(i), f);
            }
        }
        for ev in &out.events {
            self.server_event(shard, ev);
        }
        self.sout = out;
        self.sout.clear();
    }

    fn flush_client(&mut self, i: usize) {
        let out = std::mem::take(&mut self.cout);
        let shard = self.shard_of(i);
        for (_ifindex, f) in out.frames() {
            self.transmit(Dest::Server(shard), f);
        }
        for ev in &out.events {
            match ev {
                ClientEvent::Up { .. } => {}
                ClientEvent::Down { reason } => {
                    self.stats.client_downs += 1;
                    if !matches!(reason, crate::client::ClientDown::Padt) {
                        self.stats
                            .odd_downs
                            .push((self.now, i, format!("{reason:?}")));
                    }
                    *self
                        .stats
                        .client_reasons
                        .entry(format!("{reason:?}"))
                        .or_default() += 1;
                    if self.cfg.reconnect {
                        let at = self.now + 1000 + self.dice.below(2000);
                        self.starts.push(Reverse((at, i)));
                    }
                }
            }
        }
        self.cout = out;
        self.cout.clear();
        if let Some(c) = self.clients.get(i)
            && let Some(d) = c.next_deadline()
        {
            self.client_timers.push(Reverse((d, i)));
        }
    }

    fn server_event(&mut self, shard: usize, ev: &Event) {
        match ev {
            Event::Authenticate { session, request } => {
                let i = self
                    .by_mac
                    .get(&request.client_mac)
                    .copied()
                    .unwrap_or(usize::MAX);
                let ok = request.verify_local(&format!("pass{i}"));
                self.seq += 1;
                self.answers.push(Reverse((
                    self.now + self.cfg.answer_ms,
                    self.seq,
                    Answer::Auth(shard, *session, ok),
                )));
            }
            Event::NeedAddress { session } => {
                self.seq += 1;
                self.answers.push(Reverse((
                    self.now + self.cfg.answer_ms,
                    self.seq,
                    Answer::Address(shard, *session),
                )));
            }
            Event::Up {
                session,
                descriptor,
            } => {
                self.stats.ups += 1;
                if let Some(&i) = self.by_mac.get(&descriptor.client_mac) {
                    self.up.insert((shard, session.sid), i);
                }
            }
            Event::Changed { .. } => {}
            Event::Down {
                session,
                reason,
                key,
                ..
            } => {
                self.stats.downs += 1;
                *self
                    .stats
                    .server_reasons
                    .entry(format!("{reason:?}"))
                    .or_default() += 1;
                if *reason == crate::server::DownReason::Replaced {
                    let i = self
                        .by_mac
                        .get(&key.client_mac)
                        .copied()
                        .unwrap_or(usize::MAX);
                    self.stats
                        .odd_downs
                        .push((self.now, i, "server Replaced".into()));
                }
                self.up.remove(&(shard, session.sid));
                if let Some(a) = self.leased.remove(&(shard, session.sid)) {
                    self.pool_free.push(a);
                }
            }
        }
    }

    fn lease(&mut self) -> Ipv4Addr {
        if let Some(a) = self.pool_free.pop() {
            return a;
        }
        self.pool_next += 1;
        // 100.64.0.0/10 (RFC 6598), never .0.
        Ipv4Addr::from(0x6440_0000 + self.pool_next)
    }

    fn answer(&mut self, a: Answer) {
        match a {
            Answer::Auth(shard, r, ok) => {
                let verdict = if let Some(sha) = ok {
                    AuthVerdict::Accept(Authorization {
                        mschap2_success: sha,
                        message: b"welcome".as_slice().into(),
                        ..Authorization::default()
                    })
                } else {
                    self.stats.auth_rejects += 1;
                    AuthVerdict::Reject {
                        message: b"bad password".as_slice().into(),
                    }
                };
                let now = self.now;
                if let Some(s) = self.servers.get_mut(shard) {
                    s.auth_reply(now, r, verdict, &mut self.sout);
                }
                self.flush_server(shard);
            }
            Answer::Address(shard, r) => {
                let addr = self.lease();
                let now = self.now;
                let ok = self.servers.get_mut(shard).is_some_and(|s| {
                    s.address_reply(
                        now,
                        r,
                        Some(Ipv4Assignment {
                            address: addr,
                            dns: [Some(Ipv4Addr::new(100, 127, 0, 53)), None],
                            nbns: [None, None],
                        }),
                        &mut self.sout,
                    )
                });
                if ok {
                    self.leased.insert((shard, r.sid), addr);
                } else {
                    self.pool_free.push(addr);
                }
                self.flush_server(shard);
            }
        }
    }

    /// Schedules every client to start within `start_spread_ms` of now.
    pub fn start_all(&mut self) {
        for i in 0..self.clients.len() {
            let at = self.now + self.dice.below(self.cfg.start_spread_ms.max(1));
            self.starts.push(Reverse((at, i)));
        }
    }

    /// Client `i` ends its session with a PADT (or gives up discovery).
    pub fn abort(&mut self, i: usize) {
        if let Some(c) = self.clients.get_mut(i) {
            c.abort(&mut self.cout);
        }
        self.flush_client(i);
    }

    /// Client `i` closes with LCP Terminate, then PADT.
    pub fn close(&mut self, i: usize) {
        let now = self.now;
        if let Some(c) = self.clients.get_mut(i) {
            c.close(now, &mut self.cout);
        }
        self.flush_client(i);
    }

    /// Starts one client now.
    pub fn start(&mut self, i: usize) {
        self.starts.push(Reverse((self.now, i)));
    }

    fn next_event(&self) -> Option<Millis> {
        [
            self.queue.peek().map(|Reverse(e)| e.0),
            self.answers.peek().map(|Reverse(e)| e.0),
            self.starts.peek().map(|Reverse(e)| e.0),
            self.client_timers.peek().map(|Reverse(e)| e.0),
            Some(self.server_tick),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Runs the simulation until `until` (absolute ms).
    pub fn run_until(&mut self, until: Millis) {
        while let Some(t) = self.next_event() {
            if t > until {
                break;
            }
            self.now = self.now.max(t);
            let now = self.now;
            while let Some(Reverse((at, _, _, _))) = self.queue.peek()
                && *at <= now
            {
                let Some(Reverse((_, _, dest, frame))) = self.queue.pop() else {
                    break;
                };
                self.deliver(dest, &frame);
            }
            while let Some(Reverse((at, _, _))) = self.answers.peek()
                && *at <= now
            {
                let Some(Reverse((_, _, a))) = self.answers.pop() else {
                    break;
                };
                self.answer(a);
            }
            while let Some(Reverse((at, _))) = self.starts.peek()
                && *at <= now
            {
                let Some(Reverse((_, i))) = self.starts.pop() else {
                    break;
                };
                if let Some(c) = self.clients.get_mut(i) {
                    c.start(now, &mut self.cout);
                }
                self.flush_client(i);
            }
            while let Some(Reverse((at, _))) = self.client_timers.peek()
                && *at <= now
            {
                let Some(Reverse((at, i))) = self.client_timers.pop() else {
                    break;
                };
                let due = self.clients.get(i).and_then(Client::next_deadline);
                // Only the client's live deadline (entries are lazy).
                if due == Some(at) {
                    if let Some(c) = self.clients.get_mut(i) {
                        c.handle_timers(now, &mut self.cout);
                    }
                    self.flush_client(i);
                }
            }
            if self.server_tick <= now {
                for k in 0..self.servers.len() {
                    if let Some(s) = self.servers.get_mut(k) {
                        s.handle_timers(now, &mut self.sout);
                    }
                    self.flush_server(k);
                }
                self.server_tick = now + 16;
            }
        }
        self.now = self.now.max(until);
    }

    fn deliver(&mut self, dest: Dest, frame: &[u8]) {
        let now = self.now;
        match dest {
            Dest::Server(k) => {
                if let Some(s) = self.servers.get_mut(k) {
                    s.handle_frame(now, k as u32 + 1, frame, &mut self.sout);
                }
                self.flush_server(k);
            }
            Dest::Client(i) => {
                if let Some(c) = self.clients.get_mut(i) {
                    c.handle_frame(now, frame, &mut self.cout);
                }
                self.flush_client(i);
            }
        }
    }

    /// Clients whose PPP reached Up.
    pub fn clients_up(&self) -> usize {
        self.clients
            .iter()
            .filter(|c| c.phase() == ClientPhase::Up)
            .count()
    }

    /// Sessions the servers hold.
    pub fn server_sessions(&self) -> usize {
        self.servers.iter().map(Server::active).sum()
    }

    /// Cross-checks servers, clients and the address pool.
    pub fn check(&self) -> Result<(), String> {
        for s in &self.servers {
            s.check_invariants()?;
        }
        // Every up session belongs to one client, whose SID matches.
        let mut owners = std::collections::HashSet::new();
        for (&(shard, sid), &i) in &self.up {
            if !owners.insert(i) {
                return Err(format!("client {i} owns two sessions"));
            }
            if self.shard_of(i) != shard {
                return Err(format!("client {i} up on shard {shard}"));
            }
            let Some(s) = self.servers.get(shard).and_then(|s| s.session(sid)) else {
                return Err(format!("up session {shard}/{sid} not on the server"));
            };
            if s.client_mac != client_mac(i) {
                return Err(format!("session {shard}/{sid} has another MAC"));
            }
        }
        // Leases only for live sessions; no address twice.
        let mut addrs = std::collections::HashSet::new();
        for (&(shard, sid), a) in &self.leased {
            if self
                .servers
                .get(shard)
                .and_then(|s| s.session(sid))
                .is_none()
            {
                return Err(format!("lease {a} for a dead session {shard}/{sid}"));
            }
            if !addrs.insert(*a) {
                return Err(format!("address {a} leased twice"));
            }
        }
        Ok(())
    }
}

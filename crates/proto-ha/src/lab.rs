//! Two BNGs of a pair in memory: the role machines, the sync stream
//! (through the real codec, with latency, cuts and reconnects), the access
//! hellos (authenticated, droppable) and a witness each node may or may
//! not reach. A fake clock drives everything; the tests in `tests/sim.rs`
//! run failovers, split-brain attempts, link flaps and resyncs with up to
//! 100 000 sessions, and check after every step that two nodes never
//! answer the same subscribers.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::Millis;
use crate::hello::{self, HelloFrame, ReplayGuard};
use crate::msg::{Counters, FrameReader, Heartbeat, Hello, Key, Msg, Role, VERSION};
use crate::record::{Kind, SessionRecord};
use crate::role::{Action, Ha, Path, PeerView, RoleConfig, Transition};
use crate::sync::{Publisher, Replica, SyncConfig};

/// A small deterministic generator (xorshift64*).
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    pub fn chance(&mut self, per_million: u64) -> bool {
        self.below(1_000_000) < per_million
    }
}

/// A realistic session record for subscriber `n`.
pub fn record(n: u32, variant: u32) -> SessionRecord {
    let b = n.to_le_bytes();
    SessionRecord {
        kind: Kind::Pppoe,
        ifindex: 2 + n % 2,
        vlan: 0x1000 | u16::try_from(100 + n % 400).unwrap_or(100),
        sid: u16::try_from(1 + n % 65_000).unwrap_or(1),
        client_mac: [0x02, 0x11, b[3], b[2], b[1], b[0]],
        server_mac: [0x00, 0x00, 0x5e, 0x00, 0x01, 0x01],
        our_magic: n.wrapping_mul(2_654_435_761) | 1,
        peer_magic: n.wrapping_mul(40_503) | 1,
        mru: 1492,
        our_mru: 1480,
        auth_proto: 0xc223,
        auth_algo: 0x81,
        username: format!("cliente{n}").into_bytes().into(),
        ipv4: Some(Ipv4Addr::from(0x6440_0000u32.wrapping_add(n))),
        local_ipv4: Some(Ipv4Addr::new(100, 64, 0, 1)),
        dns: [
            Some(Ipv4Addr::new(1, 1, 1, 1)),
            Some(Ipv4Addr::new(8, 8, 8, 8)),
        ],
        ipv6_iid: Some([2, 0, 0, 0, b[3], b[2], b[1], b[0]]),
        rate_limit: Some(format!("{}M/{}M", 10 + variant % 5, 50 + variant % 5).into()),
        acct_session_id: format!("{n:08x}").into(),
        radius: true,
        acct_interim: Some(300),
        profile: "plano".into(),
        server: "pppoe1".into(),
        pool: Some("clientes".into()),
        started_at: 1_790_000_000 + u64::from(n),
        ..SessionRecord::default()
    }
}

pub struct Node {
    pub ha: Ha,
    pub publisher: Option<Publisher>,
    pub replica: Replica,
    pub alive: bool,
    pub witness: bool,
    pub track: bool,
    cfg: RoleConfig,
    sync_cfg: SyncConfig,
    hello_seq: u64,
    guard: ReplayGuard,
    next_hello: Millis,
    peer_hello: Option<Hello>,
    peer_stream: u64,
    last_view: Option<PeerView>,
    /// When a hello last said the peer is active.
    seen_peer_active: Millis,
    reader: FrameReader,
    pub transitions: Vec<Transition>,
}

impl Node {
    fn new(mut cfg: RoleConfig, sync_cfg: SyncConfig, now: Millis, boot: u64) -> Node {
        cfg.incarnation = boot;
        Node {
            ha: Ha::new(cfg.clone(), now),
            publisher: None,
            replica: Replica::new(sync_cfg.clone()),
            alive: true,
            witness: true,
            track: true,
            cfg,
            sync_cfg,
            hello_seq: 0,
            guard: ReplayGuard::default(),
            next_hello: now,
            peer_hello: None,
            peer_stream: 0,
            last_view: None,
            seen_peer_active: 0,
            reader: FrameReader::new(),
            transitions: Vec::new(),
        }
    }

    fn hello_msg(&self) -> Hello {
        let (stream, applied) = match &self.publisher {
            Some(p) => (p.stream(), p.seq()),
            None => self.replica.position(),
        };
        Hello {
            version: VERSION,
            node_id: self.cfg.node_id,
            epoch: self.ha.epoch(),
            role: self.ha.role(),
            priority: self.cfg.priority,
            hot_standby: self.cfg.hot_standby,
            stream,
            applied,
            sessions: 0,
            sections: vec![],
        }
    }

    fn heartbeat(&self) -> Heartbeat {
        let v = self.ha.view();
        let (stream, seq) = match &self.publisher {
            Some(p) => (p.stream(), p.seq()),
            None => self.replica.position(),
        };
        Heartbeat {
            node_id: v.node_id,
            incarnation: v.incarnation,
            hears: v.hears,
            view_seq: v.view_seq,
            acked: v.acked,
            epoch: v.epoch,
            role: v.role,
            priority: v.priority,
            witness: v.witness,
            in_sync: v.in_sync,
            eligible: v.eligible,
            stream,
            seq,
            sessions: 0,
        }
    }

    /// The table this node would serve with, if it answers.
    pub fn sessions(&self) -> usize {
        self.publisher.as_ref().map_or(0, Publisher::len)
    }
}

#[derive(Debug, Clone)]
pub struct LabConfig {
    pub role: [RoleConfig; 2],
    pub sync: SyncConfig,
    /// One way, both links.
    pub latency_ms: u64,
    /// Sync link bytes per millisecond (125 000 = 1 Gbit/s).
    pub bytes_per_ms: usize,
    pub step_ms: u64,
    /// Access hellos lost, per million.
    pub access_loss: u64,
    pub seed: u64,
    /// Keep a line per event and role change in [`Lab::log`].
    pub trace: bool,
}

impl Default for LabConfig {
    fn default() -> Self {
        let a = RoleConfig {
            node_id: 1,
            priority: 200,
            ..RoleConfig::default()
        };
        let b = RoleConfig {
            node_id: 2,
            priority: 100,
            ..RoleConfig::default()
        };
        LabConfig {
            role: [a, b],
            sync: SyncConfig::default(),
            latency_ms: 1,
            bytes_per_ms: 125_000,
            step_ms: 5,
            access_loss: 0,
            seed: 1,
            trace: false,
        }
    }
}

/// Counted during the run (for the test asserts).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Watch {
    /// Both nodes answered although each had heard the other claim the
    /// role since it took it: neither stepped down, two BNGs on the same
    /// subscribers. Must stay 0.
    pub split_brain_ms: u64,
    /// Both answered while at least one had not heard the other yet (a
    /// partition, each reaching its witness; or the hello after a heal not
    /// arrived yet): counted, resolved by the first hello that passes.
    pub partitioned_both_ms: u64,
    /// Nobody answered (with at least one node alive).
    pub nobody_ms: u64,
}

pub struct Lab {
    pub now: Millis,
    pub cfg: LabConfig,
    pub nodes: [Node; 2],
    pub sync_up: bool,
    pub access_up: bool,
    connected: bool,
    /// (deliver at, to, bytes).
    sync_q: VecDeque<(Millis, usize, Vec<u8>)>,
    access_q: VecDeque<(Millis, usize, Vec<u8>)>,
    key: [u8; 32],
    pub rng: Rng,
    streams: u64,
    pub watch: Watch,
    /// Bytes sent on the sync link (both ways).
    pub sync_bytes: u64,
    /// Events and role changes, with `trace` on.
    pub log: Vec<String>,
}

impl Lab {
    pub fn new(cfg: LabConfig) -> Lab {
        let mut rng = Rng::new(cfg.seed);
        let a = Node::new(cfg.role[0].clone(), cfg.sync.clone(), 0, rng.next_u64());
        let b = Node::new(cfg.role[1].clone(), cfg.sync.clone(), 0, rng.next_u64());
        Lab {
            now: 0,
            nodes: [a, b],
            sync_up: true,
            access_up: true,
            connected: false,
            sync_q: VecDeque::new(),
            access_q: VecDeque::new(),
            key: hello::derive("hello", b"lab secret"),
            rng,
            streams: 0,
            watch: Watch::default(),
            sync_bytes: 0,
            log: Vec::new(),
            cfg,
        }
    }

    fn note(&mut self, what: impl FnOnce() -> String) {
        if self.cfg.trace {
            let line = format!("{:>7} {}", self.now, what());
            self.log.push(line);
        }
    }

    pub fn node(&self, i: usize) -> Option<&Node> {
        self.nodes.get(i)
    }

    /// The node answering subscribers now, if exactly one does.
    pub fn active(&self) -> Option<usize> {
        let a: Vec<usize> = (0..2)
            .filter(|&i| {
                self.nodes
                    .get(i)
                    .is_some_and(|n| n.alive && n.ha.answering())
            })
            .collect();
        match a.as_slice() {
            [i] => Some(*i),
            _ => None,
        }
    }

    pub fn roles(&self) -> [Role; 2] {
        self.nodes.each_ref().map(|n| n.ha.role())
    }

    fn send_sync(&mut self, from: usize, msg: &Msg) {
        if !self.connected {
            return;
        }
        let mut b = Vec::new();
        if msg.encode(&mut b).is_ok() {
            self.sync_bytes += b.len() as u64;
            let at = self.now + self.cfg.latency_ms;
            self.sync_q.push_back((at, 1 - from, b));
        }
    }

    fn connect(&mut self) {
        self.connected = true;
        for n in &mut self.nodes {
            n.next_hello = self.now;
        }
        for i in 0..2 {
            if let Some(h) = self.nodes.get(i).map(Node::hello_msg) {
                self.send_sync(i, &Msg::Hello(h));
            }
        }
    }

    fn disconnect(&mut self) {
        self.connected = false;
        self.sync_q.clear();
        for n in &mut self.nodes {
            n.reader = FrameReader::new();
            n.replica.disconnect();
            n.peer_hello = None;
            if let Some(p) = &mut n.publisher {
                p.disconnect();
            }
        }
    }

    pub fn cut_sync(&mut self) {
        self.note(|| "cut sync".into());
        self.sync_up = false;
        self.disconnect();
    }

    pub fn heal_sync(&mut self) {
        self.note(|| "heal sync".into());
        self.sync_up = true;
    }

    pub fn cut_access(&mut self) {
        self.note(|| "cut access".into());
        self.access_up = false;
        self.access_q.clear();
    }

    pub fn heal_access(&mut self) {
        self.note(|| "heal access".into());
        self.access_up = true;
    }

    /// The process dies (power, panic): nothing more from it.
    pub fn kill(&mut self, i: usize) {
        self.note(|| format!("kill node{i}"));
        if let Some(n) = self.nodes.get_mut(i) {
            n.alive = false;
        }
        self.disconnect();
    }

    /// The process starts again with nothing (a new boot id).
    pub fn restart(&mut self, i: usize) {
        self.note(|| format!("restart node{i}"));
        let boot = self.rng.next_u64();
        let Some(cfg) = self.cfg.role.get(i).cloned() else {
            return;
        };
        let n = Node::new(cfg, self.cfg.sync.clone(), self.now, boot);
        if let Some(slot) = self.nodes.get_mut(i) {
            *slot = n;
        }
        self.disconnect();
    }

    /// `ppp.redundancy.switchover` on node `i`.
    pub fn switchover(&mut self, i: usize, force: bool) -> Result<(), crate::role::Refused> {
        self.note(|| format!("switchover node{i} force={force}"));
        let now = self.now;
        let r = self
            .nodes
            .get_mut(i)
            .map_or(Err(crate::role::Refused::NotActive), |n| {
                n.ha.switchover(now, force)
            });
        self.after_actions(i);
        r
    }

    /// `ppp.redundancy.simulate-failure` on node `i`.
    pub fn simulate_failure(&mut self, i: usize, ms: u64) -> Result<(), crate::role::Refused> {
        self.note(|| format!("simulate failure node{i} {ms} ms"));
        let now = self.now;
        let r = self
            .nodes
            .get_mut(i)
            .map_or(Err(crate::role::Refused::NotActive), |n| {
                n.ha.simulate_failure(now, ms)
            });
        self.after_actions(i);
        r
    }

    pub fn set_witness(&mut self, i: usize, ok: bool) {
        self.note(|| format!("node{i} witness {ok}"));
        if let Some(n) = self.nodes.get_mut(i) {
            n.witness = ok;
        }
    }

    pub fn set_track(&mut self, i: usize, ok: bool) {
        self.note(|| format!("node{i} track {ok}"));
        if let Some(n) = self.nodes.get_mut(i) {
            n.track = ok;
        }
    }

    /// Sessions churn on the active node: `up` new or changed, `down`
    /// ended, `counters` updated, among subscribers `0..pool`.
    pub fn churn(&mut self, pool: u32, up: u32, down: u32, counters: u32) {
        let Some(i) = self.active() else {
            return;
        };
        let now = self.now;
        let mut picks = Vec::new();
        for _ in 0..up + down + counters {
            picks.push(u32::try_from(self.rng.below(u64::from(pool))).unwrap_or(0));
        }
        let variant = u32::try_from(self.rng.below(1000)).unwrap_or(0);
        let Some(p) = self.nodes.get_mut(i).and_then(|n| n.publisher.as_mut()) else {
            return;
        };
        for (j, n) in picks.into_iter().enumerate() {
            let rec = record(n, variant);
            let key = rec.key();
            if j < up as usize {
                if let Ok(b) = rec.to_bytes() {
                    p.upsert(now, key, Arc::from(b));
                }
            } else if j < (up + down) as usize {
                p.remove(now, key);
            } else {
                p.counters(
                    now,
                    key,
                    Counters {
                        rx_bytes: now * 1000 + u64::from(n),
                        tx_bytes: now * 4000,
                        rx_packets: now,
                        tx_packets: now * 3,
                    },
                );
            }
        }
    }

    /// Loads `n` sessions on the active node at once.
    pub fn load(&mut self, n: u32) {
        let Some(i) = self.active() else {
            return;
        };
        let now = self.now;
        let Some(p) = self.nodes.get_mut(i).and_then(|x| x.publisher.as_mut()) else {
            return;
        };
        for s in 0..n {
            let rec = record(s, 0);
            if let Ok(b) = rec.to_bytes() {
                p.upsert(now, rec.key(), Arc::from(b));
            }
        }
    }

    fn deliver_sync(&mut self, to: usize, bytes: &[u8]) {
        let Some(n) = self.nodes.get_mut(to) else {
            return;
        };
        n.reader.push(bytes);
        let mut msgs = Vec::new();
        loop {
            match n.reader.next_msg() {
                Ok(Some(m)) => msgs.push(m),
                Ok(None) => break,
                Err(_) => {
                    self.disconnect();
                    return;
                }
            }
        }
        for m in msgs {
            self.on_sync(to, m);
        }
    }

    fn on_sync(&mut self, to: usize, m: Msg) {
        let now = self.now;
        let mut replies = Vec::new();
        {
            let Some(n) = self.nodes.get_mut(to) else {
                return;
            };
            match &m {
                Msg::Hello(h) => {
                    n.peer_hello = Some(h.clone());
                    if matches!(h.role, Role::Active | Role::Yielding) {
                        n.peer_stream = h.stream;
                    }
                    if let Some(p) = &mut n.publisher {
                        p.connect(h);
                    }
                }
                Msg::Heartbeat(hb) => {
                    n.peer_stream = hb.stream;
                    if hb.role == Role::Active {
                        n.seen_peer_active = now;
                    }
                    n.ha.peer_heard(
                        now,
                        Path::Sync,
                        PeerView {
                            node_id: hb.node_id,
                            incarnation: hb.incarnation,
                            hears: hb.hears,
                            view_seq: hb.view_seq,
                            acked: hb.acked,
                            epoch: hb.epoch,
                            role: hb.role,
                            priority: hb.priority,
                            witness: hb.witness,
                            in_sync: hb.in_sync,
                            eligible: hb.eligible,
                        },
                    );
                }
                Msg::Handover { epoch } => n.ha.handover(now, *epoch),
                Msg::HandoverRequest { epoch } => n.ha.handover_request(now, *epoch),
                Msg::Ack { .. } | Msg::Resync { .. } => {
                    if let Some(p) = &mut n.publisher {
                        p.handle(now, &m);
                    }
                }
                Msg::SnapshotBegin { .. }
                | Msg::SnapshotChunk { .. }
                | Msg::SnapshotEnd { .. }
                | Msg::Delta { .. } => {
                    if n.publisher.is_none() {
                        n.replica.handle(now, &m, &mut replies);
                    }
                }
            }
        }
        for r in replies {
            self.send_sync(to, &r);
        }
        self.after_actions(to);
    }

    /// Applies the role machine's actions of node `i`.
    fn after_actions(&mut self, i: usize) {
        let mut acts = Vec::new();
        if let Some(n) = self.nodes.get_mut(i) {
            n.ha.take_actions(&mut acts);
        }
        for a in acts {
            match a {
                Action::Role(t) => {
                    self.note(|| {
                        format!(
                            "node{i} {:?} -> {:?} ({}, epoch {})",
                            t.from,
                            t.to,
                            t.reason.as_str(),
                            t.epoch
                        )
                    });
                    self.streams += 1;
                    let stream = (self.streams << 8) | (i as u64 + 1);
                    let Some(n) = self.nodes.get_mut(i) else {
                        continue;
                    };
                    n.transitions.push(t);
                    // Tell the peer at once (heartbeat and access hello in
                    // this step; the new active's hello is also the
                    // gratuitous MAC update).
                    n.next_hello = self.now;
                    match t.to {
                        Role::Active => {
                            if n.publisher.is_none() {
                                let mut p = if t.stateful {
                                    Publisher::from_replica(stream, n.sync_cfg.clone(), &n.replica)
                                } else {
                                    Publisher::new(stream, n.sync_cfg.clone())
                                };
                                if let Some(h) = &n.peer_hello {
                                    p.connect(h);
                                }
                                n.publisher = Some(p);
                                n.replica.clear();
                            }
                        }
                        Role::Yielding => {}
                        _ => {
                            if n.publisher.take().is_some() {
                                n.replica.clear();
                            }
                        }
                    }
                    if let Some(h) = self.nodes.get(i).map(Node::hello_msg) {
                        self.send_sync(i, &Msg::Hello(h));
                    }
                }
                Action::Handover { epoch } => self.send_sync(i, &Msg::Handover { epoch }),
                Action::HandoverRequest { epoch } => {
                    self.send_sync(i, &Msg::HandoverRequest { epoch });
                }
            }
        }
    }

    /// One step of the fake clock.
    pub fn step(&mut self) {
        self.now += self.cfg.step_ms;
        let now = self.now;
        let both_alive = self.nodes.iter().all(|n| n.alive);
        if self.sync_up && both_alive && !self.connected {
            self.connect();
        }
        // Deliver what is due.
        while let Some((at, _, _)) = self.sync_q.front() {
            if *at > now {
                break;
            }
            let Some((_, to, b)) = self.sync_q.pop_front() else {
                break;
            };
            if self.connected {
                self.deliver_sync(to, &b);
            }
        }
        while let Some((at, _, _)) = self.access_q.front() {
            if *at > now {
                break;
            }
            let Some((_, to, f)) = self.access_q.pop_front() else {
                break;
            };
            let key = self.key;
            if let Some(n) = self.nodes.get_mut(to)
                && n.alive
                && let Some(body) = f.get(14..)
                && let Ok(h) = HelloFrame::decode(&key, body)
                && n.guard.check(&h).is_ok()
            {
                if h.view.role == Role::Active {
                    n.seen_peer_active = now;
                }
                n.ha.peer_heard(now, Path::Access, h.view);
            }
            self.after_actions(to);
        }
        for i in 0..2 {
            if !self.nodes.get(i).is_some_and(|n| n.alive) {
                continue;
            }
            if let Some(n) = self.nodes.get_mut(i) {
                n.ha.witness(now, n.witness);
                n.ha.track(now, n.track);
                let in_sync = n.publisher.is_none()
                    && n.replica.complete()
                    && n.replica.status().stream == n.peer_stream;
                n.ha.synced(now, in_sync);
                n.ha.tick(now);
            }
            self.after_actions(i);
            // Hellos on both paths.
            let Some(n) = self.nodes.get_mut(i) else {
                continue;
            };
            // Every hello interval, and at once when what it says changes.
            let view = n.ha.view();
            if (now >= n.next_hello || n.last_view != Some(view)) && !n.ha.silent() {
                n.next_hello = now + n.cfg.hello_ms;
                n.last_view = Some(view);
                n.hello_seq += 1;
                let hb = n.heartbeat();
                let f = HelloFrame {
                    view: n.ha.view(),
                    seq: n.hello_seq,
                };
                let src = if n.ha.answering() {
                    [0, 0, 0x5e, 0, 1, 1]
                } else {
                    [2, 0, 0, 0, 0, u8::try_from(i).unwrap_or(0)]
                };
                let frame = f.frame(&self.key, src);
                self.send_sync(i, &Msg::Heartbeat(hb));
                if self.access_up && !self.rng.chance(self.cfg.access_loss) {
                    self.access_q
                        .push_back((now + self.cfg.latency_ms, 1 - i, frame));
                }
            }
            // The sync stream, within the link's budget.
            let budget = self.cfg.bytes_per_ms * self.cfg.step_ms as usize;
            let mut out = Vec::new();
            if let Some(n) = self.nodes.get_mut(i)
                && self.connected
            {
                if let Some(p) = &mut n.publisher {
                    p.poll(budget, &mut out);
                } else {
                    n.replica.poll(now, &mut out);
                }
            }
            for m in out {
                self.send_sync(i, &m);
            }
        }
        // The safety watch.
        let ans: Vec<bool> = self
            .nodes
            .iter()
            .map(|n| n.alive && n.ha.answering())
            .collect();
        let any_alive = self.nodes.iter().any(|n| n.alive);
        if ans.iter().all(|a| *a) {
            let [a, b] = &self.nodes;
            let knew = a.seen_peer_active >= b.ha.since().max(a.ha.since())
                && b.seen_peer_active >= a.ha.since().max(b.ha.since());
            if knew {
                self.watch.split_brain_ms += self.cfg.step_ms;
            } else {
                self.watch.partitioned_both_ms += self.cfg.step_ms;
            }
        } else if any_alive && !ans.iter().any(|a| *a) {
            self.watch.nobody_ms += self.cfg.step_ms;
        }
    }

    pub fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.step();
        }
    }

    /// Runs until `f` holds or `ms` pass; the time it took.
    pub fn run_until(&mut self, ms: u64, f: impl Fn(&Lab) -> bool) -> Option<u64> {
        let start = self.now;
        while self.now < start + ms {
            if f(self) {
                return Some(self.now - start);
            }
            self.step();
        }
        f(self).then_some(self.now - start)
    }

    /// The standby holds exactly the active's table.
    pub fn in_sync(&self) -> bool {
        let Some(a) = self.active() else {
            return false;
        };
        let (Some(act), Some(stb)) = (self.nodes.get(a), self.nodes.get(1 - a)) else {
            return false;
        };
        match &act.publisher {
            Some(p) => {
                stb.alive
                    && stb.ha.role() == Role::Standby
                    && stb.replica.complete()
                    && stb.replica.same_as(p)
            }
            None => false,
        }
    }

    /// Keys of `before` missing or different in node `i`'s table.
    pub fn lost(&self, before: &[(Key, Vec<u8>, Counters)], i: usize) -> usize {
        let Some(p) = self.nodes.get(i).and_then(|n| n.publisher.as_ref()) else {
            return before.len();
        };
        before
            .iter()
            .filter(|(k, v, _)| p.get(k).is_none_or(|(w, _)| w != v.as_slice()))
            .count()
    }

    /// A copy of node `i`'s published table.
    pub fn table(&self, i: usize) -> Vec<(Key, Vec<u8>, Counters)> {
        self.nodes
            .get(i)
            .and_then(|n| n.publisher.as_ref())
            .map(|p| p.iter().map(|(k, v, c)| (*k, v.to_vec(), c)).collect())
            .unwrap_or_default()
    }
}

//! Two BNGs of a pair in memory: two [`Node`]s (the code the daemon runs),
//! the sync stream between them (bytes, with latency, cuts, reconnects and
//! the handshake), the access hellos (authenticated, droppable) and a
//! witness each node may or may not reach. A fake clock drives everything; the tests in `tests/sim.rs`
//! run failovers, split-brain attempts, link flaps and resyncs with up to
//! 100 000 sessions, and check after every step that two nodes never
//! answer the same subscribers.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::Millis;
use crate::hello;
use crate::msg::{Counters, Key, Role};
use crate::node::{Event, Node, NodeConfig};
use crate::record::{Kind, SessionRecord};
use crate::role::{Path, Refused, RoleConfig, Transition};
use crate::sync::SyncConfig;

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

pub struct LabNode {
    pub node: Node,
    pub alive: bool,
    pub witness: bool,
    pub track: bool,
    pub transitions: Vec<Transition>,
    /// BFD to the peer on [sync, access]: up, and when its last packet
    /// arrived (G3.6h).
    pub bfd: [(bool, Millis); 2],
    /// Witness probes asked for (answered after `latency_ms`).
    pub probes: u64,
    probe_due: Option<Millis>,
}

impl LabNode {
    fn new(cfg: &LabConfig, i: usize, now: Millis, incarnation: u64) -> LabNode {
        let mut role = cfg.role.get(i).cloned().unwrap_or_default();
        role.incarnation = incarnation;
        LabNode {
            node: Node::new(
                NodeConfig {
                    role,
                    sync: cfg.sync.clone(),
                    hello_key: hello::derive("hello", b"lab secret"),
                    link_key: hello::derive("link", b"lab secret"),
                    sections: Vec::new(),
                },
                now,
            ),
            alive: true,
            witness: true,
            track: true,
            transitions: Vec::new(),
            bfd: [(false, now); 2],
            probes: 0,
            probe_due: None,
        }
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
    /// BFD detection time on [sync, access] (`None`: no BFD on that
    /// path). A session comes up when the path passes and expires this
    /// long after its last packet.
    pub bfd_ms: [Option<u64>; 2],
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
            bfd_ms: [None, None],
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
    pub nodes: [LabNode; 2],
    pub sync_up: bool,
    pub access_up: bool,
    /// BFD packets lost on [sync, access] until this time while the
    /// hellos still pass (a degraded link that flaps BFD only).
    pub bfd_blocked_until: [Millis; 2],
    connected: bool,
    /// (deliver at, to, bytes).
    sync_q: VecDeque<(Millis, usize, Vec<u8>)>,
    access_q: VecDeque<(Millis, usize, Vec<u8>)>,
    pub rng: Rng,
    pub watch: Watch,
    /// Bytes sent on the sync link (both ways).
    pub sync_bytes: u64,
    /// Events and role changes, with `trace` on.
    pub log: Vec<String>,
}

impl Lab {
    pub fn new(cfg: LabConfig) -> Lab {
        let mut rng = Rng::new(cfg.seed);
        let a = LabNode::new(&cfg, 0, 0, rng.next_u64());
        let b = LabNode::new(&cfg, 1, 0, rng.next_u64());
        Lab {
            now: 0,
            nodes: [a, b],
            sync_up: true,
            access_up: true,
            bfd_blocked_until: [0, 0],
            connected: false,
            sync_q: VecDeque::new(),
            access_q: VecDeque::new(),
            rng,
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
        self.nodes.get(i).map(|n| &n.node)
    }

    /// The node answering subscribers now, if exactly one does.
    pub fn active(&self) -> Option<usize> {
        let a: Vec<usize> = (0..2)
            .filter(|&i| {
                self.nodes
                    .get(i)
                    .is_some_and(|n| n.alive && n.node.answering())
            })
            .collect();
        match a.as_slice() {
            [i] => Some(*i),
            _ => None,
        }
    }

    pub fn roles(&self) -> [Role; 2] {
        self.nodes.each_ref().map(|n| n.node.role())
    }

    fn connect(&mut self) {
        self.connected = true;
        for i in 0..2 {
            let nonce = self.nonce();
            let now = self.now;
            if let Some(n) = self.nodes.get_mut(i) {
                n.node.connected(now, nonce);
            }
            self.drain(i);
        }
    }

    fn nonce(&mut self) -> [u8; 32] {
        let mut n = [0u8; 32];
        for c in n.chunks_mut(8) {
            for (d, s) in c.iter_mut().zip(self.rng.next_u64().to_le_bytes()) {
                *d = s;
            }
        }
        n
    }

    fn disconnect(&mut self) {
        self.connected = false;
        self.sync_q.clear();
        for n in &mut self.nodes {
            n.node.disconnected();
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

    /// The process starts again with nothing (a new incarnation).
    pub fn restart(&mut self, i: usize) {
        self.note(|| format!("restart node{i}"));
        let inc = self.rng.next_u64();
        let n = LabNode::new(&self.cfg, i, self.now, inc);
        if let Some(slot) = self.nodes.get_mut(i) {
            *slot = n;
        }
        self.disconnect();
    }

    /// `ppp.redundancy.switchover` on node `i`.
    pub fn switchover(&mut self, i: usize, force: bool) -> Result<(), Refused> {
        self.note(|| format!("switchover node{i} force={force}"));
        let now = self.now;
        let r = self
            .nodes
            .get_mut(i)
            .map_or(Err(Refused::NotActive), |n| n.node.switchover(now, force));
        self.drain(i);
        r
    }

    /// `ppp.redundancy.simulate-failure` on node `i`.
    pub fn simulate_failure(&mut self, i: usize, ms: u64) -> Result<(), Refused> {
        self.note(|| format!("simulate failure node{i} {ms} ms"));
        let now = self.now;
        let r = self.nodes.get_mut(i).map_or(Err(Refused::NotActive), |n| {
            n.node.simulate_failure(now, ms)
        });
        self.drain(i);
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
        let Some(n) = self.nodes.get_mut(i) else {
            return;
        };
        for (j, s) in picks.into_iter().enumerate() {
            let rec = record(s, variant);
            let key = rec.key();
            if j < up as usize {
                if let Ok(b) = rec.to_bytes() {
                    n.node.upsert(now, key, Arc::from(b));
                }
            } else if j < (up + down) as usize {
                n.node.remove(now, key);
            } else {
                n.node.counters(
                    now,
                    key,
                    Counters {
                        rx_bytes: now * 1000 + u64::from(s),
                        tx_bytes: now * 4000,
                        rx_packets: now,
                        tx_packets: now * 3,
                    },
                );
            }
        }
    }

    /// Loads `n` sessions on the active node at once.
    pub fn load(&mut self, count: u32) {
        let Some(i) = self.active() else {
            return;
        };
        let now = self.now;
        let Some(n) = self.nodes.get_mut(i) else {
            return;
        };
        for s in 0..count {
            let rec = record(s, 0);
            if let Ok(b) = rec.to_bytes() {
                n.node.upsert(now, rec.key(), Arc::from(b));
            }
        }
    }

    /// Node `i`'s output: sync bytes onto the link, hellos onto the access
    /// network, events into the log.
    fn drain(&mut self, i: usize) {
        let now = self.now;
        let mut bytes = Vec::new();
        let mut hellos = Vec::new();
        let mut events = Vec::new();
        let Some(n) = self.nodes.get_mut(i) else {
            return;
        };
        n.node.take_output(&mut bytes);
        n.node.take_access(&mut hellos);
        n.node.take_events(&mut events);
        let roles: Vec<Transition> = events
            .into_iter()
            .filter_map(|e| match e {
                Event::Role(t) => Some(t),
                Event::PeerUp { .. } | Event::Forward { .. } | Event::ForwardReply { .. } => None,
            })
            .collect();
        n.transitions.extend(roles.iter().copied());
        for t in roles {
            {
                self.note(|| {
                    format!(
                        "node{i} {:?} -> {:?} ({}, epoch {})",
                        t.from,
                        t.to,
                        t.reason.as_str(),
                        t.epoch
                    )
                });
            }
        }
        if self.connected && !bytes.is_empty() {
            self.sync_bytes += bytes.len() as u64;
            self.sync_q
                .push_back((now + self.cfg.latency_ms, 1 - i, bytes));
        }
        for (body, _from_vmac) in hellos {
            if self.access_up && !self.rng.chance(self.cfg.access_loss) {
                self.access_q
                    .push_back((now + self.cfg.latency_ms, 1 - i, body));
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
        while let Some((at, _, _)) = self.sync_q.front() {
            if *at > now {
                break;
            }
            let Some((_, to, b)) = self.sync_q.pop_front() else {
                break;
            };
            if !self.connected {
                continue;
            }
            let failed = self
                .nodes
                .get_mut(to)
                .is_some_and(|n| n.alive && n.node.input(now, &b).is_err());
            if failed {
                self.disconnect();
            } else {
                self.drain(to);
            }
        }
        while let Some((at, _, _)) = self.access_q.front() {
            if *at > now {
                break;
            }
            let Some((_, to, body)) = self.access_q.pop_front() else {
                break;
            };
            if let Some(n) = self.nodes.get_mut(to)
                && n.alive
            {
                n.node.access_input(now, &body);
            }
            self.drain(to);
        }
        self.bfd_step(now);
        let budget = self.cfg.bytes_per_ms * self.cfg.step_ms as usize;
        for i in 0..2 {
            if let Some(n) = self.nodes.get_mut(i)
                && n.alive
            {
                // A probe asked for: answered one link latency later.
                if n.probe_due.is_some_and(|t| now >= t) {
                    n.probe_due = None;
                    if n.witness {
                        n.node.witness_answer(now, now);
                    }
                }
                if n.probe_due.is_none() && n.node.wants_witness_probe() {
                    n.probes += 1;
                    n.probe_due = Some(now + 2 * self.cfg.latency_ms);
                }
                n.node.witness(now, n.witness);
                n.node.track(now, n.track);
                n.node.tick(now);
                n.node.poll(now, budget);
            } else {
                continue;
            }
            self.drain(i);
        }
        // The safety watch.
        let ans: Vec<bool> = self
            .nodes
            .iter()
            .map(|n| n.alive && n.node.answering())
            .collect();
        let any_alive = self.nodes.iter().any(|n| n.alive);
        if ans.iter().all(|a| *a) {
            let [a, b] = &self.nodes;
            let (sa, sb) = (a.node.ha().since(), b.node.ha().since());
            let knew =
                a.node.seen_peer_active() >= sb.max(sa) && b.node.seen_peer_active() >= sa.max(sb);
            if knew {
                self.watch.split_brain_ms += self.cfg.step_ms;
            } else {
                self.watch.partitioned_both_ms += self.cfg.step_ms;
            }
        } else if any_alive && !ans.iter().any(|a| *a) {
            self.watch.nobody_ms += self.cfg.step_ms;
        }
    }

    /// The BFD sessions of both nodes: a packet arrives on a path while
    /// the peer is alive, not silent (a simulated failure), and the path
    /// passes; a session expires `bfd_ms` after its last packet.
    fn bfd_step(&mut self, now: Millis) {
        let talking: Vec<bool> = self.nodes.iter().map(|n| n.alive && !n.node.ha().silent()).collect();
        for i in 0..2 {
            for (p, path) in [Path::Sync, Path::Access].into_iter().enumerate() {
                let Some(detect) = self.cfg.bfd_ms.get(p).copied().flatten() else {
                    continue;
                };
                let link = if p == 0 { self.sync_up } else { self.access_up };
                let blocked = self.bfd_blocked_until.get(p).is_some_and(|t| now < *t);
                let passes = link && !blocked && talking.get(1 - i).copied().unwrap_or(false);
                let Some(n) = self.nodes.get_mut(i) else { continue };
                if !n.alive {
                    continue;
                }
                let Some(st) = n.bfd.get_mut(p) else { continue };
                let mut change = None;
                if passes {
                    st.1 = now;
                    if !st.0 {
                        st.0 = true;
                        change = Some(true);
                    }
                } else if st.0 && now.saturating_sub(st.1) >= detect {
                    st.0 = false;
                    change = Some(false);
                }
                if let Some(up) = change {
                    n.node.bfd(now, path, up, !up);
                    self.note(|| format!("node{i} bfd {path:?} {}", if up { "up" } else { "down" }));
                    self.drain(i);
                }
            }
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
        match act.node.publisher() {
            Some(p) => {
                stb.alive
                    && stb.node.role() == Role::Standby
                    && stb.node.replica().complete()
                    && stb.node.replica().same_as(p)
            }
            None => false,
        }
    }

    /// Keys of `before` missing or different in node `i`'s table.
    pub fn lost(&self, before: &[(Key, Vec<u8>, Counters)], i: usize) -> usize {
        let Some(p) = self.node(i).and_then(Node::publisher) else {
            return before.len();
        };
        before
            .iter()
            .filter(|(k, v, _)| p.get(k).is_none_or(|(w, _)| w != v.as_slice()))
            .count()
    }

    /// A copy of node `i`'s published table.
    pub fn table(&self, i: usize) -> Vec<(Key, Vec<u8>, Counters)> {
        self.node(i)
            .and_then(Node::publisher)
            .map(|p| p.iter().map(|(k, v, c)| (*k, v.to_vec(), c)).collect())
            .unwrap_or_default()
    }
}

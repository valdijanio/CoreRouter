//! The BFD engine: N named threads, each owning a share of the sessions
//! (by `discriminator mod N`), its own receive sockets in the reuseport
//! groups, its own transmit sockets and its own timer wheel. Nothing is
//! locked on the packet path: a thread touches only its sessions. What
//! crosses threads goes through bounded queues (commands in, events out,
//! packets that reached the wrong thread) or a snapshot each thread
//! replaces every 250 ms under its own mutex (never the `Session` lock).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use corerouter_model::bfd::{BfdKey, BfdSessionStatus, BfdThreadStatus};
use corerouter_proto_bfd::dampen::{DampConfig, Damper};
use corerouter_proto_bfd::hist::Hist;
use corerouter_proto_bfd::packet::{Diag, MAX_LEN, Packet, State};
use corerouter_proto_bfd::session::{Change, Config, Session};
use corerouter_proto_bfd::wheel::Wheel;
use corerouter_proto_bfd::{PORT_MULTI_HOP, PORT_SINGLE_HOP, ttl_ok};
use nix::poll::{PollFd, PollFlags, ppoll};
use nix::sys::time::TimeSpec;
use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, recv, send, socketpair};

use super::sock::{Datagram, Rx, Tx, nix_io};

/// What one session runs with.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Spec {
    pub key: BfdKey,
    pub cfg: Config,
    pub damp: Option<DampConfig>,
    pub min_ttl: u8,
    pub users: Vec<String>,
    pub profile: String,
}

/// A state change the clients must hear about.
#[derive(Debug, Clone)]
pub(crate) struct Event {
    pub key: BfdKey,
    pub discr: u32,
    /// What the peer said last (for `bfdd`'s `BFD_STATE_CHANGE`).
    pub remote_discr: u32,
    pub remote_desired_tx: u32,
    pub remote_min_rx: u32,
    pub remote_mult: u8,
    pub from: State,
    pub to: State,
    pub diag: Diag,
    /// Up for the clients: Up and not dampened.
    pub client_up: bool,
    pub dampened: bool,
    pub detect_us: u64,
    pub users: Vec<String>,
    pub at_ms: u64,
}

/// A packet that reached another thread's socket.
struct Inbound {
    buf: [u8; 64],
    dg: Datagram,
    multihop: bool,
}

enum Cmd {
    Add(u32, Box<Spec>),
    Update(u32, Box<Spec>),
    Remove(u32),
    Inbound(Box<Inbound>),
}

#[derive(Debug, Clone)]
pub(crate) struct Options {
    pub threads: usize,
    pub bind4: Option<Ipv4Addr>,
    pub bind6: Option<Ipv6Addr>,
    pub port_single: u16,
    pub port_multi: u16,
    /// Where peers listen (the same ports but in tests: two engines on one host).
    pub peer_ports: Option<(u16, u16)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 1,
            bind4: Some(Ipv4Addr::UNSPECIFIED),
            bind6: Some(Ipv6Addr::UNSPECIFIED),
            port_single: PORT_SINGLE_HOP,
            port_multi: PORT_MULTI_HOP,
            peer_ports: None,
        }
    }
}

/// Command and inbound queues per thread; events to the service.
const CMD_QUEUE: usize = 8192;
const EVENT_QUEUE: usize = 8192;
/// Longest poll: commands and the stop flag are seen within it.
const MAX_WAIT_MS: u64 = 20;
const PUBLISH_US: u64 = 250_000;
/// Datagrams read per socket per wake-up (fairness between sockets).
const RX_BURST: usize = 256;
/// Flaps kept for `flaps_24h`.
const MAX_FLAPS: usize = 4096;
const DAY_US: u64 = 86_400_000_000;

#[derive(Default)]
struct Snapshot {
    sessions: Vec<BfdSessionStatus>,
    thread: BfdThreadStatus,
}

struct Shared {
    stop: AtomicBool,
    /// Sessions by address, for packets with Your Discriminator 0.
    demux: RwLock<HashMap<BfdKey, u32>>,
    snaps: Vec<Mutex<Snapshot>>,
}

struct Waker(OwnedFd);

impl Waker {
    fn wake(&self) {
        let _ = send(self.0.as_raw_fd(), &[1], MsgFlags::MSG_DONTWAIT);
    }
}

pub(crate) struct Engine {
    n: usize,
    cmds: Vec<SyncSender<Cmd>>,
    wakers: Vec<Arc<Waker>>,
    pub events: Receiver<Event>,
    shared: Arc<Shared>,
    joins: Vec<JoinHandle<()>>,
    pub steering: &'static str,
    used: std::collections::HashSet<u32>,
}

/// Starts a thread (the service passes the supervisor's `health.spawn`).
pub(crate) type Spawn<'a> = &'a dyn Fn(String, Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>;

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    u64::from_ne_bytes(b)
}

impl Engine {
    pub(crate) fn start(opts: &Options, spawn: Spawn<'_>) -> std::io::Result<Self> {
        let n = opts.threads.clamp(1, 64);
        let mut binds: Vec<IpAddr> = Vec::new();
        if let Some(a) = opts.bind4 {
            binds.push(IpAddr::V4(a));
        }
        if let Some(a) = opts.bind6 {
            binds.push(IpAddr::V6(a));
        }
        // Receive sockets, group by group, members in thread order.
        let mut rx: Vec<Vec<Rx>> = (0..n).map(|_| Vec::new()).collect();
        let mut steered = n > 1;
        for ip in &binds {
            for (port, multihop) in [(opts.port_single, false), (opts.port_multi, true)] {
                let at = SocketAddr::new(*ip, port);
                let mut group = Vec::new();
                for _ in 0..n {
                    match Rx::bind(at, multihop) {
                        Ok(s) => group.push(s),
                        // No IPv6 on this host: IPv4 only.
                        Err(e) if ip.is_ipv6() && group.is_empty() => {
                            log::info!("BFD: no IPv6 socket on {at}: {e}");
                            break;
                        }
                        Err(e) => return Err(std::io::Error::new(e.kind(), format!("BFD: cannot bind {at}: {e}"))),
                    }
                }
                if let Some(first) = group.first()
                    && n > 1
                    && let Err(e) = first.steer(n as u32)
                {
                    log::warn!("BFD: no reuseport program on {at} ({e}); packets are handed between threads");
                    steered = false;
                }
                for (i, s) in group.into_iter().enumerate() {
                    if let Some(v) = rx.get_mut(i) {
                        v.push(s);
                    }
                }
            }
        }
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            demux: RwLock::new(HashMap::new()),
            snaps: (0..n).map(|_| Mutex::new(Snapshot::default())).collect(),
        });
        let (ev_tx, ev_rx) = sync_channel(EVENT_QUEUE);
        let mut cmds = Vec::new();
        let mut cmd_rxs = Vec::new();
        let mut wakers = Vec::new();
        let mut wake_rx = Vec::new();
        for _ in 0..n {
            let (t, r) = sync_channel(CMD_QUEUE);
            cmds.push(t);
            cmd_rxs.push(r);
            let (a, b) = socketpair(
                AddressFamily::Unix,
                SockType::Datagram,
                None,
                SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            )
            .map_err(nix_io)?;
            wakers.push(Arc::new(Waker(a)));
            wake_rx.push(b);
        }
        let epoch = Instant::now();
        let mut joins = Vec::new();
        for (idx, ((rxs, cmd_rx), wake)) in rx.into_iter().zip(cmd_rxs).zip(wake_rx).enumerate() {
            let mut tx4 = None;
            let mut tx6 = None;
            for ip in &binds {
                let start = 49152 + (random_u64() % 16384) as u16;
                let t = Tx::bind(*ip, start)?;
                if ip.is_ipv4() {
                    tx4 = Some(t);
                } else {
                    tx6 = Some(t);
                }
            }
            let w = Worker {
                idx,
                n,
                rx: rxs,
                wake,
                tx4,
                tx6,
                wheel: Wheel::new(1_000, 4096, 0),
                slots: Vec::new(),
                free: Vec::new(),
                by_discr: HashMap::new(),
                cmd_rx,
                peers: cmds.clone(),
                wakers: wakers.clone(),
                events: ev_tx.clone(),
                shared: Arc::clone(&shared),
                epoch,
                stats: BfdThreadStatus {
                    index: idx as u16,
                    ..BfdThreadStatus::default()
                },
                cpu: Cpu::default(),
                seed: random_u64(),
                ports: opts.peer_ports.unwrap_or((opts.port_single, opts.port_multi)),
            };
            joins.push(spawn(format!("bfd-{idx}"), Box::new(move || w.run()))?);
        }
        Ok(Self {
            n,
            cmds,
            wakers,
            events: ev_rx,
            shared,
            joins,
            steering: if n == 1 {
                "single-thread"
            } else if steered {
                "reuseport-cbpf"
            } else {
                "hash"
            },
            used: std::collections::HashSet::new(),
        })
    }

    pub(crate) fn threads(&self) -> usize {
        self.n
    }

    fn post(&self, owner: usize, c: Cmd) -> bool {
        let Some(tx) = self.cmds.get(owner) else {
            return false;
        };
        // The service waits (bounded) rather than lose a command.
        let ok = tx.send(c).is_ok();
        if let Some(w) = self.wakers.get(owner) {
            w.wake();
        }
        ok
    }

    /// A new session; returns its discriminator (random, unique, nonzero,
    /// `≡ owner (mod N)`; RFC 5880 §6.8.1 asks for random and unique).
    pub(crate) fn add(&mut self, spec: Spec, owner_hint: Option<usize>) -> u32 {
        let n = self.n as u32;
        let owner = owner_hint.map_or_else(|| (random_u64() % u64::from(n)) as u32, |o| o as u32 % n);
        let discr = loop {
            let r = (random_u64() >> 32) as u32;
            let d = (r - r % n).wrapping_add(owner);
            if d != 0 && d % n == owner && !self.used.contains(&d) {
                break d;
            }
        };
        self.used.insert(discr);
        self.shared
            .demux
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spec.key.clone(), discr);
        self.post((discr % n) as usize, Cmd::Add(discr, Box::new(spec)));
        discr
    }

    /// A session whose discriminator someone else chose (`bfdd`, data
    /// plane mode): it lives on thread `discr mod N`. False when 0 or taken.
    pub(crate) fn add_with(&mut self, discr: u32, spec: Spec) -> bool {
        if discr == 0 || !self.used.insert(discr) {
            return false;
        }
        self.shared
            .demux
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(spec.key.clone(), discr);
        self.post((discr % self.n as u32) as usize, Cmd::Add(discr, Box::new(spec)));
        true
    }

    pub(crate) fn update(&self, discr: u32, spec: Spec) {
        self.post((discr % self.n as u32) as usize, Cmd::Update(discr, Box::new(spec)));
    }

    pub(crate) fn remove(&mut self, discr: u32, key: &BfdKey) {
        self.used.remove(&discr);
        self.shared.demux.write().unwrap_or_else(PoisonError::into_inner).remove(key);
        self.post((discr % self.n as u32) as usize, Cmd::Remove(discr));
    }

    /// The last snapshot of every thread.
    pub(crate) fn snapshot(&self) -> (Vec<BfdSessionStatus>, Vec<BfdThreadStatus>) {
        let mut sessions = Vec::new();
        let mut threads = Vec::new();
        for m in &self.shared.snaps {
            let s = m.lock().unwrap_or_else(PoisonError::into_inner);
            sessions.extend(s.sessions.iter().cloned());
            threads.push(s.thread.clone());
        }
        (sessions, threads)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for w in &self.wakers {
            w.wake();
        }
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
    }
}

/// CPU time of the calling thread from /proc (clock ticks of 10 ms).
#[derive(Default)]
struct Cpu {
    last_ticks: u64,
    last_at: Option<Instant>,
}

fn thread_ticks() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    let rest = s.get(s.rfind(')')? + 2..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    // Fields 14 and 15 (utime, stime); `rest` starts at field 3.
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

impl Cpu {
    fn percent(&mut self) -> Option<f32> {
        let ticks = thread_ticks()?;
        let now = Instant::now();
        let out = self.last_at.map(|at| {
            let secs = now.duration_since(at).as_secs_f64().max(1e-3);
            ((ticks.saturating_sub(self.last_ticks)) as f64 / 100.0 / secs * 100.0) as f32
        });
        self.last_ticks = ticks;
        self.last_at = Some(now);
        out
    }
}

struct Slot {
    discr: u32,
    spec: Spec,
    s: Session,
    /// Wheel time of the entry that will look at it (`u64::MAX`: none).
    scheduled: u64,
    damper: Damper,
    suppressed: bool,
    client_up: bool,
    dropped: u64,
    changes: u64,
    flaps: VecDeque<u64>,
    last_change: Option<u64>,
    tx_late: Hist,
    rx_gap: Hist,
    last_rx: Option<u64>,
    dst: SocketAddr,
}

struct Worker {
    idx: usize,
    n: usize,
    rx: Vec<Rx>,
    wake: OwnedFd,
    tx4: Option<Tx>,
    tx6: Option<Tx>,
    wheel: Wheel,
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
    by_discr: HashMap<u32, u32>,
    cmd_rx: Receiver<Cmd>,
    peers: Vec<SyncSender<Cmd>>,
    wakers: Vec<Arc<Waker>>,
    events: SyncSender<Event>,
    shared: Arc<Shared>,
    epoch: Instant,
    stats: BfdThreadStatus,
    cpu: Cpu,
    seed: u64,
    /// Where peers listen: (single hop, multihop); the standard ports but in tests.
    ports: (u16, u16),
}

impl Worker {
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_micros() as u64
    }

    fn run(mut self) {
        let mut buf = [0u8; 64];
        let mut due: Vec<u32> = Vec::new();
        let mut next_publish = 0u64;
        let mut ages = 0u64;
        loop {
            if self.shared.stop.load(Ordering::Acquire) {
                return;
            }
            let now = self.now();
            // µs precision (ppoll): poll's milliseconds made every packet
            // up to 1 ms late (p99 1.05 ms → see docs/bfd.md).
            let wait_us = match self.wheel.next_due(64) {
                Some(t) => t.saturating_sub(now).min(MAX_WAIT_MS * 1000),
                None => MAX_WAIT_MS * 1000,
            };
            let ready = {
                let mut fds: Vec<PollFd<'_>> = self.rx.iter().map(|r| PollFd::new(r.fd(), PollFlags::POLLIN)).collect();
                fds.push(PollFd::new(self.wake.as_fd(), PollFlags::POLLIN));
                let t = TimeSpec::from_duration(std::time::Duration::from_micros(wait_us));
                match ppoll(&mut fds, Some(t), None) {
                    Ok(_) => fds
                        .iter()
                        .map(|f| f.revents().is_some_and(|r| !r.is_empty()))
                        .collect::<Vec<bool>>(),
                    Err(_) => vec![true; self.rx.len() + 1],
                }
            };
            if ready.last().copied().unwrap_or(false) {
                let mut b = [0u8; 64];
                while recv(self.wake.as_raw_fd(), &mut b, MsgFlags::MSG_DONTWAIT).is_ok() {}
            }
            for i in 0..self.rx.len() {
                if !ready.get(i).copied().unwrap_or(false) {
                    continue;
                }
                for _ in 0..RX_BURST {
                    let got = match self.rx.get(i) {
                        Some(r) => r.recv(&mut buf).map(|d| d.map(|d| (d, r.multihop))),
                        None => break,
                    };
                    match got {
                        Ok(Some((dg, multihop))) => {
                            self.stats.packets_in += 1;
                            self.datagram(&buf, dg, multihop);
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
            while let Ok(c) = self.cmd_rx.try_recv() {
                self.command(c);
            }
            let now = self.now();
            due.clear();
            self.wheel.advance(now, &mut due);
            for &k in &due {
                self.fire(k, now);
            }
            if now >= next_publish {
                next_publish = now + PUBLISH_US;
                ages += 1;
                // The percentiles cover about the last 2.5 minutes.
                self.publish(now, ages.is_multiple_of(600));
            }
        }
    }

    fn command(&mut self, c: Cmd) {
        let now = self.now();
        match c {
            Cmd::Add(discr, spec) => {
                let port = if spec.key.multihop { self.ports.1 } else { self.ports.0 };
                let dst = SocketAddr::new(spec.key.peer, port);
                self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let s = Session::new(discr, spec.cfg.clone(), now, self.seed ^ u64::from(discr));
                let slot = Slot {
                    discr,
                    spec: *spec,
                    s,
                    scheduled: u64::MAX,
                    damper: Damper::default(),
                    suppressed: false,
                    client_up: false,
                    dropped: 0,
                    changes: 0,
                    flaps: VecDeque::new(),
                    last_change: None,
                    tx_late: Hist::default(),
                    rx_gap: Hist::default(),
                    last_rx: None,
                    dst,
                };
                let k = match self.free.pop() {
                    Some(k) => {
                        if let Some(x) = self.slots.get_mut(k as usize) {
                            *x = Some(slot);
                        }
                        k
                    }
                    None => {
                        self.slots.push(Some(slot));
                        (self.slots.len() - 1) as u32
                    }
                };
                self.by_discr.insert(discr, k);
                self.stats.sessions += 1;
                self.reschedule(k, false);
            }
            Cmd::Update(discr, spec) => {
                let Some(&k) = self.by_discr.get(&discr) else { return };
                let (change, timers) = match self.slots.get_mut(k as usize).and_then(Option::as_mut) {
                    Some(sl) => {
                        // Only new timers or auth start a Poll Sequence.
                        let timers = sl.spec.cfg != spec.cfg;
                        let c = if timers { sl.s.set_config(spec.cfg.clone(), now) } else { None };
                        sl.spec = *spec;
                        (c, timers)
                    }
                    None => return,
                };
                if let Some(c) = change {
                    self.changed(k, c, now);
                }
                if timers {
                    self.transmit(k, false);
                }
                self.reschedule(k, false);
            }
            Cmd::Remove(discr) => {
                let Some(k) = self.by_discr.remove(&discr) else { return };
                if let Some(x) = self.slots.get_mut(k as usize) {
                    *x = None;
                }
                self.free.push(k);
                self.stats.sessions = self.stats.sessions.saturating_sub(1);
            }
            Cmd::Inbound(i) => {
                let Inbound { buf, dg, multihop } = *i;
                self.datagram(&buf, dg, multihop);
            }
        }
    }

    fn datagram(&mut self, buf: &[u8; 64], dg: Datagram, multihop: bool) {
        let raw = buf.get(..dg.len.min(buf.len())).unwrap_or(&[]);
        let Ok(p) = Packet::decode(raw) else {
            return;
        };
        let discr = if p.your_discr != 0 {
            p.your_discr
        } else {
            // RFC 5881 §3 / RFC 5883 §5: by addresses while the peer does
            // not know our discriminator yet.
            let map = self.shared.demux.read().unwrap_or_else(PoisonError::into_inner);
            let exact = BfdKey {
                peer: dg.from,
                multihop,
                local: dg.to,
            };
            let any = BfdKey {
                peer: dg.from,
                multihop,
                local: None,
            };
            match map.get(&exact).or_else(|| map.get(&any)) {
                Some(&d) => d,
                None => return,
            }
        };
        let owner = (discr % self.n as u32) as usize;
        if owner != self.idx {
            self.forward(owner, buf, dg, multihop);
            return;
        }
        let Some(&k) = self.by_discr.get(&discr) else {
            return;
        };
        let now = self.now();
        let Some(sl) = self.slots.get_mut(k as usize).and_then(Option::as_mut) else {
            return;
        };
        // The session's own path and TTL rule (RFC 5881 §5, RFC 5883 §5).
        if sl.spec.key.multihop != multihop
            || sl.spec.key.peer != dg.from
            || !ttl_ok(multihop, dg.ttl.unwrap_or(0), sl.spec.min_ttl)
        {
            sl.dropped += 1;
            return;
        }
        let r = match sl.s.receive(raw, &p, now) {
            Ok(r) => r,
            Err(_) => {
                sl.dropped += 1;
                return;
            }
        };
        if let Some(last) = sl.last_rx {
            sl.rx_gap.record(now.saturating_sub(last));
        }
        sl.last_rx = Some(now);
        if let Some(c) = r.change {
            self.changed(k, c, now);
        }
        if r.send_final {
            self.transmit(k, true);
        } else if r.send_now {
            self.transmit(k, false);
        }
        self.reschedule(k, false);
    }

    fn forward(&mut self, owner: usize, buf: &[u8; 64], dg: Datagram, multihop: bool) {
        let Some(tx) = self.peers.get(owner) else { return };
        let item = Cmd::Inbound(Box::new(Inbound { buf: *buf, dg, multihop }));
        match tx.try_send(item) {
            Ok(()) => {
                self.stats.forwarded += 1;
                if let Some(w) = self.wakers.get(owner) {
                    w.wake();
                }
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
        }
    }

    fn transmit(&mut self, k: u32, final_: bool) {
        let Some(sl) = self.slots.get_mut(k as usize).and_then(Option::as_mut) else {
            return;
        };
        let mut out = [0u8; MAX_LEN];
        let len = sl.s.build(final_, &mut out);
        let tx = if sl.dst.is_ipv4() { self.tx4.as_ref() } else { self.tx6.as_ref() };
        if let (Some(tx), Some(bytes)) = (tx, out.get(..len))
            && tx.send(bytes, sl.dst, sl.spec.key.local).is_ok()
        {
            self.stats.packets_out += 1;
        }
    }

    fn fire(&mut self, k: u32, now: u64) {
        let fired = match self.slots.get_mut(k as usize).and_then(Option::as_mut) {
            Some(sl) => {
                let f = sl.s.on_timer(now);
                if f.send && f.change.is_none() {
                    sl.tx_late.record(f.late_us);
                }
                f
            }
            None => return,
        };
        if let Some(c) = fired.change {
            self.changed(k, c, now);
        }
        if fired.send {
            self.transmit(k, false);
        }
        self.reschedule(k, true);
    }

    fn reschedule(&mut self, k: u32, fired: bool) {
        let Some(sl) = self.slots.get_mut(k as usize).and_then(Option::as_mut) else {
            return;
        };
        if fired {
            sl.scheduled = u64::MAX;
        }
        if let Some(at) = sl.s.next_deadline()
            && at < sl.scheduled
        {
            sl.scheduled = at;
            self.wheel.insert(at, k);
        }
    }

    fn changed(&mut self, k: u32, c: Change, now: u64) {
        let Some(sl) = self.slots.get_mut(k as usize).and_then(Option::as_mut) else {
            return;
        };
        sl.changes += 1;
        sl.last_change = Some(unix_ms() / 1000);
        // A flap: Up → Down not asked by the peer's operator (RFC 5882 §3.2:
        // AdminDown from the peer is not a failure).
        let remote_admin = c.diag == Diag::NeighborSignaledDown && sl.s.remote_state() == State::AdminDown;
        if c.from == State::Up && c.to == State::Down && !remote_admin {
            sl.flaps.push_back(now);
            while sl.flaps.len() > MAX_FLAPS {
                sl.flaps.pop_front();
            }
            if let Some(d) = &sl.spec.damp {
                sl.suppressed = sl.damper.flap(d, now);
            }
        }
        sl.client_up = sl.s.state() == State::Up && !sl.suppressed;
        let ev = Event {
            key: sl.spec.key.clone(),
            discr: sl.discr,
            remote_discr: sl.s.remote_discr(),
            remote_desired_tx: sl.s.remote_desired_tx(),
            remote_min_rx: sl.s.remote_min_rx(),
            remote_mult: sl.s.remote_mult(),
            from: c.from,
            to: c.to,
            diag: c.diag,
            client_up: sl.client_up,
            dampened: sl.suppressed,
            detect_us: sl.s.detection_time(),
            users: sl.spec.users.clone(),
            at_ms: unix_ms(),
        };
        let _ = self.events.try_send(ev);
    }

    fn publish(&mut self, now: u64, age: bool) {
        let mut out = Vec::with_capacity(self.by_discr.len());
        let mut releases = Vec::new();
        for (k, sl) in self.slots.iter_mut().enumerate() {
            let Some(sl) = sl.as_mut() else { continue };
            if sl.suppressed
                && let Some(d) = &sl.spec.damp
                && !sl.damper.suppressed(d, now)
            {
                sl.suppressed = false;
                releases.push(k as u32);
            }
            while sl.flaps.front().is_some_and(|&t| now.saturating_sub(t) > DAY_US) {
                sl.flaps.pop_front();
            }
            if age {
                sl.tx_late.age();
                sl.rx_gap.age();
            }
            let s = &sl.s;
            out.push(BfdSessionStatus {
                peer: Some(sl.spec.key.peer),
                local: sl.spec.key.local,
                multihop: sl.spec.key.multihop,
                users: sl.spec.users.clone(),
                profile: sl.spec.profile.clone(),
                state: s.state().name().to_owned(),
                remote_state: s.remote_state().name().to_owned(),
                diag: s.local_diag().name().to_owned(),
                dampened: sl.suppressed,
                penalty: sl.damper.penalty(),
                local_discr: sl.discr,
                remote_discr: s.remote_discr(),
                tx_interval_us: s.tx_interval(),
                remote_min_rx_us: s.remote_min_rx(),
                remote_desired_tx_us: s.remote_desired_tx(),
                multiplier: s.cfg.detect_mult,
                remote_multiplier: s.remote_mult(),
                detect_time_us: s.detection_time(),
                packets_tx: s.tx_packets,
                packets_rx: s.rx_packets,
                dropped: sl.dropped,
                state_changes: sl.changes,
                flaps_24h: sl.flaps.len() as u32,
                last_change: sl.last_change,
                tx_jitter_p99_us: sl.tx_late.quantile(0.99),
                rx_gap_p99_us: sl.rx_gap.quantile(0.99),
                thread: self.idx as u16,
            });
        }
        for k in releases {
            let Some(sl) = self.slots.get_mut(k as usize).and_then(Option::as_mut) else { continue };
            sl.client_up = sl.s.state() == State::Up;
            let _ = self.events.try_send(Event {
                key: sl.spec.key.clone(),
                discr: sl.discr,
                remote_discr: sl.s.remote_discr(),
                remote_desired_tx: sl.s.remote_desired_tx(),
                remote_min_rx: sl.s.remote_min_rx(),
                remote_mult: sl.s.remote_mult(),
                from: sl.s.state(),
                to: sl.s.state(),
                diag: Diag::None,
                client_up: sl.client_up,
                dampened: false,
                detect_us: sl.s.detection_time(),
                users: sl.spec.users.clone(),
                at_ms: unix_ms(),
            });
        }
        if let Some(p) = self.cpu.percent() {
            self.stats.cpu_percent = p;
        }
        let mut snap = self
            .shared
            .snaps
            .get(self.idx)
            .map(|m| m.lock().unwrap_or_else(PoisonError::into_inner));
        if let Some(s) = snap.as_mut() {
            s.sessions = out;
            s.thread = self.stats.clone();
        }
    }
}

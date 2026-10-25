//! The PPPoE access concentrator (G4.3d) as a service: the I/O around the
//! BNG of `pppoe_bng.rs`, on several cores (G4.3g).
//!
//! - Each worker opens its own `AF_PACKET` sockets on every access port
//!   (`hal-linux::pppoe_io`) with a classic BPF filter that keeps only the
//!   clients whose MAC hashes to it: the kernel hands every frame straight to
//!   its worker, like RSS (a CPE always lands on the same worker, its PADI,
//!   PADR and session alike), with no thread in between.
//! - The service's thread keeps the config, the data plane and, without
//!   XDP, the slow path's `bng0`, whose packets it hands to the worker
//!   holding the address.
//! - Each worker owns a `Bng`: its servers (a lane of every port's
//!   SESSION_IDs), sessions, timers and RADIUS questions, and sends its own
//!   frames. The active table, the history and the address pools are shared.
//! - `interface.pppoe-server.settings.set workers=auto|N` (read when the
//!   service starts).
//!
//! The session lock is taken once a round per worker, and only to run what
//! its BNG asked (XDP map, hooks, address lists, log lines) and read the
//! XDP counters: never while waiting on the network.
//!
//! With the XDP data plane (G4.3c) the subscribers' traffic never reaches
//! these threads: only control frames do (`XDP_PASS`). Without it (virtual
//! lab, a NIC without XDP, the unprivileged namespace tests) the workers
//! carry IPv4 themselves (`pppoe_io::SlowPath`).

pub(crate) const SERVICE: super::Service = super::Service {
    name: "pppoe",
    flags: &[],
    topic: "ppp",
    enable: "interface.pppoe-server.server.add interface=…",
    depends: &["radius"],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let key = ctx.config_dir.as_deref().and_then(iid_key);
    Ok(Box::new(move |health: &super::Health| run(&session, health, key)))
}

/// G4.3e: the RFC 8064 secret of the IPv6CP identifiers, in
/// `<config-dir>/pppoe-ipv6cp.key` (32 bytes, only this user reads it), so
/// a subscriber line keeps its link-local across restarts. Made on first
/// use; `None` (unreadable, no randomness) = one per run.
fn iid_key(dir: &std::path::Path) -> Option<[u8; 32]> {
    let path = dir.join("pppoe-ipv6cp.key");
    if let Ok(b) = std::fs::read(&path) {
        return <[u8; 32]>::try_from(b.as_slice()).ok();
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).ok()?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&path).ok()?;
    std::io::Write::write_all(&mut f, &k).ok()?;
    Some(k)
}

#[cfg(target_os = "linux")]
use linux::run;

/// Without Linux there are no access ports (`AF_PACKET`): the row says why.
#[cfg(not(target_os = "linux"))]
fn run(
    session: &corerouter_engine::Shared,
    health: &super::Health,
    key: Option<[u8; 32]>,
) -> Result<(), String> {
    let _ = (session, key);
    health.disabled(Some("PPPoE needs Linux (AF_PACKET access ports)"));
    while health.sleep(std::time::Duration::from_secs(1)) {
        health.beat();
    }
    Ok(())
}

/// The driver (Linux: `AF_PACKET`, `poll`, the slow path's netlink).
#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, VecDeque};

    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::net::UnixDatagram;
    use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use corerouter_engine::{Shared, lock};
    use corerouter_hal::pppoe::PppoeOp;
    use corerouter_hal_linux::pppoe_io::{PppoePort, SlowPath, SlowTx};
    use corerouter_model::ppp::{PppoeServer, pppoe_workers_auto};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use serde_json::json;

    use super::super::pppoe_bng::{Backend, Bng, Effect, Owner, PortInfo, Snapshot, guard, vlan_ids};

    /// Longest wait for a frame; timers and RADIUS answers are looked at
    /// least this often.
    const WAIT: Duration = Duration::from_millis(20);
    /// The config, the counters and the limits: once a second.
    const SECOND: Duration = Duration::from_secs(1);
    const IDLE: Duration = Duration::from_millis(500);
    /// Frames queued for one worker at most, its own sockets' and the
    /// reader's messages alike (a burst past it is dropped: the CPEs
    /// retransmit, RFC 2516 §5 and RFC 1661 §4.6).
    const QUEUE: usize = 1 << 16;
    /// Messages, and frames, a worker takes in a row before its timers,
    /// RADIUS and sends.
    const BUDGET: usize = 512;
    /// Frames handled between two reads of the sockets: a few milliseconds
    /// of work, while a socket holds ~8700 PADIs. Against a 100 000-PADI
    /// burst at 5 µs a frame, 1 worker reading between frames got 18 756;
    /// with this queue, all of them (`netns_pppoe_lanes`, **medido**).
    const REFILL: usize = 128;

    fn origin() -> Instant {
        static START: OnceLock<Instant> = OnceLock::new();
        *START.get_or_init(Instant::now)
    }

    fn ms() -> u64 {
        u64::try_from(origin().elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        if getrandom::fill(&mut s).is_err() {
            // Not secret material by itself (the AC-Cookie key is drawn from
            // it): the clock still makes two runs differ.
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            for (b, x) in s.iter_mut().zip(t.to_le_bytes().iter().cycle()) {
                *b ^= x;
            }
        }
        s
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    /// An access port the workers have open, and what for.
    struct Open {
        name: corerouter_model::IfName,
        info: PortInfo,
        vlans: Vec<u16>,
        untagged: bool,
        rcvbuf: (usize, usize),
    }

    /// What the reader hands a worker.
    enum Msg {
        /// Slow path: an IPv4 packet the kernel routed to its subscriber.
        Down(Vec<u8>),
        /// Once a second: the config, the ports open and the data plane.
        Config(Box<Snapshot>, HashMap<String, PortInfo>, bool),
        /// The ports changed: the worker's own sockets on them (its lane).
        Ports(Vec<PppoePort>),
        /// The slow path opened: the worker's own sender.
        Slow(Box<SlowTx>),
    }

    /// A worker's queue and the doorbell that wakes its `poll`.
    struct Lane {
        tx: SyncSender<Msg>,
        bell: UnixDatagram,
    }

    impl Lane {
        fn send(&self, m: Msg) -> bool {
            let ok = match self.tx.try_send(m) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => false,
                Err(TrySendError::Disconnected(_)) => return false,
            };
            let _ = self.bell.send(&[1]);
            ok
        }
    }

    /// The reader: ports, plane, config and the workers' queues.
    struct Driver {
        ports: HashMap<String, Open>,
        slow: Option<SlowPath>,
        /// Data plane decided for these access ports: Some(true) XDP,
        /// Some(false) slow path. Decided again when the ports change (for new
        /// sessions; each session keeps the plane it started on).
        plane: Option<bool>,
        plane_for: Vec<corerouter_model::IfName>,
        errors: Vec<String>,
        workers: Vec<Lane>,
        /// Slow-path packets dropped because a worker's queue was full.
        dropped: u64,
    }

    pub(super) fn run(
        session: &Shared,
        health: &super::super::Health,
        iid_key: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let unix_base = unix_now().saturating_sub(ms() / 1000);
        let lanes = {
            let w = lock(session).store().running().ppp.pppoe_workers;
            let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
            if w == 0 { pppoe_workers_auto(cpus) } else { w }
        };
        let first = Bng::first_of(seed(), lanes);
        let shared = first.shared.clone();
        let routes = first.clone_routes();
        let owner = Arc::new(Owner(shared.clone()));
        let mut owner_of: Option<usize> = None;
        lock(session).set_ppp_backend(Arc::new(Backend(shared.clone())));
        let mut bngs = vec![first];
        for lane in 1..lanes {
            if let Some(b) = bngs.first().map(|f| f.sibling(seed(), lane, lanes)) {
                bngs.push(b);
            }
        }
        let mut d = Driver {
            ports: HashMap::new(),
            slow: None,
            plane: None,
            plane_for: Vec::new(),
            errors: Vec::new(),
            workers: Vec::new(),
            dropped: 0,
        };
        let mut handles = Vec::new();
        for (lane, bng) in bngs.into_iter().enumerate() {
            let (tx, rx) = sync_channel::<Msg>(QUEUE);
            let (bell, ring) = UnixDatagram::pair().map_err(|e| format!("PPPoE worker {lane}: {e}"))?;
            let _ = ring.set_nonblocking(true);
            let _ = bell.set_nonblocking(true);
            let s = session.clone();
            let h = health.clone();
            let t = health
                .spawn(&format!("pppoe-{lane}"), move || worker(bng, &rx, &ring, &s, &h))
                .map_err(|e| format!("cannot start PPPoE worker {lane}: {e}"))?;
            d.workers.push(Lane { tx, bell });
            handles.push(t);
        }
        let mut last_second: Option<Instant> = None;
        loop {
            if health.stopping() {
                break;
            }
            health.beat();
            let now = ms();
            if last_second.is_none_or(|t| t.elapsed() >= SECOND) {
                last_second = Some(Instant::now());
                let (ppp, pools, pools6, aaa) = {
                    let s = lock(session);
                    let c = s.store().running();
                    (
                        c.ppp.clone(),
                        c.ip.pools.clone(),
                        c.ipv6.dhcp_server.pools.clone(),
                        s.aaa_backend(),
                    )
                };
                // CoA/Disconnect: one registration per RADIUS service.
                if let Some(a) = &aaa {
                    let key = Arc::as_ptr(a) as *const () as usize;
                    if owner_of != Some(key) {
                        a.register_owner(owner.clone());
                        owner_of = Some(key);
                    }
                }
                let wanted = Bng::wanted(&ppp);
                if wanted.is_empty() {
                    health.disabled(Some("no enabled PPPoE server (interface.pppoe-server.server.add)"));
                } else {
                    health.disabled(None);
                }
                d.errors.clear();
                let infos = d.open_ports(&wanted);
                // system.health.check › Socket buffers: a PADI burst after
                // an outage must fit.
                {
                    let mut s = lock(session);
                    if let Some(t) = s.ext_mut::<corerouter_engine::health_check::SocketBuffers>() {
                        t.sockets.retain(|k, _| !k.starts_with("pppoe "));
                        for o in d.ports.values() {
                            t.sockets.insert(format!("pppoe {}", o.name), o.rcvbuf);
                        }
                    }
                }
                if !wanted.is_empty() {
                    let mut ifaces: Vec<_> = wanted.iter().map(|w| w.interface.clone()).collect();
                    ifaces.sort();
                    d.choose_plane(session, &shared, ifaces);
                }
                let snap = Snapshot { ppp, pools, aaa, unix_base, pools6, iid_key };
                let xdp = d.plane == Some(true);
                for w in &d.workers {
                    let _ = w.send(Msg::Config(Box::new(snap.clone()), infos.clone(), xdp));
                }
                if d.dropped > 0 {
                    d.errors.push(format!("{} slow-path packets dropped: the PPPoE workers are behind", d.dropped));
                    d.dropped = 0;
                }
                if d.errors.is_empty() {
                    health.clear_error();
                } else {
                    health.error(d.errors.join("; "));
                }
                if wanted.is_empty() {
                    if !health.sleep(IDLE) {
                        break;
                    }
                    continue;
                }
            }
            d.wait();
            d.receive_slow(&routes);
            let _ = now;
        }
        // Stopping: the workers tell their subscribers (Terminate, PADT),
        // clean the maps and end when their queue closes.
        d.workers.clear();
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }

    /// One worker: its BNG, its own sockets on the access ports (the
    /// kernel's filter hands it its clients' frames), the reader's
    /// messages (config, slow path) behind a doorbell.
    ///
    /// The frames wait in the worker's own queue ([`QUEUE`]), refilled from
    /// the sockets every [`REFILL`] frames handled: a socket holds ~8700
    /// PADIs (4 MiB, **medido**), and BNG Blaster sends 100 000 in a second
    /// and a half. Read only between frames, the sockets overflowed and the
    /// CPEs sent their PADIs again seconds later (G4.3g, VM round 4: 6
    /// workers 22 400 sessions/s against 57 900 with the single reader's
    /// queue).
    fn worker(mut bng: Bng, rx: &Receiver<Msg>, ring: &UnixDatagram, session: &Shared, health: &super::super::Health) {
        let mut ports: Vec<PppoePort> = Vec::new();
        let mut queue: VecDeque<(u32, Vec<u8>)> = VecDeque::new();
        // Lost in the queue, and by the kernel on sockets closed since.
        let mut lost = 0u64;
        let mut slow: Option<SlowTx> = None;
        let mut configured = false;
        let mut last_tick = Instant::now();
        let mut errors: Vec<String> = Vec::new();
        let mut bell = [0u8; 64];
        loop {
            let now = ms();
            let mut wait = WAIT;
            if let Some(d) = bng.next_deadline() {
                wait = wait.min(Duration::from_millis(d.saturating_sub(now)));
            }
            if bng.waiting_radius() {
                wait = wait.min(Duration::from_millis(2));
            }
            if !queue.is_empty() {
                wait = Duration::ZERO;
            }
            {
                let mut fds: Vec<BorrowedFd<'_>> = ports.iter().flat_map(|p| p.fds()).collect();
                fds.push(ring.as_fd());
                let mut polls: Vec<PollFd<'_>> = fds.into_iter().map(|f| PollFd::new(f, PollFlags::POLLIN)).collect();
                let t = PollTimeout::try_from(wait).unwrap_or(PollTimeout::ZERO);
                let _ = poll(&mut polls, t);
            }
            while ring.recv(&mut bell).is_ok() {}
            let mut open = true;
            for _ in 0..BUDGET {
                match rx.try_recv() {
                    Ok(m) => {
                        let now = ms();
                        match m {
                            Msg::Down(p) => bng.data_down(&p),
                            Msg::Config(snap, infos, xdp) => {
                                bng.xdp = xdp;
                                bng.configure(now, *snap, &infos);
                                configured = true;
                            }
                            Msg::Ports(p) => {
                                lost += ports.iter().map(PppoePort::dropped).sum::<u64>();
                                ports = p;
                            }
                            Msg::Slow(s) => slow = Some(*s),
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        open = false;
                        break;
                    }
                }
            }
            fill(&mut ports, &mut queue, &mut lost, &mut errors);
            let mut now = ms();
            for done in 1..=BUDGET {
                let Some((ifindex, f)) = queue.pop_front() else {
                    break;
                };
                bng.frame(now, ifindex, &f);
                if done % REFILL == 0 {
                    fill(&mut ports, &mut queue, &mut lost, &mut errors);
                    now = ms();
                }
            }
            let now = ms();
            bng.radius(now);
            bng.timers(now);
            bng.requests(now);
            if configured && last_tick.elapsed() >= SECOND {
                last_tick = Instant::now();
                let counters = if bng.xdp {
                    lock(session).pppoe_counters(&bng.xdp_slots())
                } else {
                    Vec::new()
                };
                bng.set_rx_dropped(lost + ports.iter().map(PppoePort::dropped).sum::<u64>());
                bng.tick(now, &counters);
                if !errors.is_empty() {
                    let mut s = lock(session);
                    for e in errors.drain(..).take(10) {
                        s.log_event(&["ppp", "warning"], "pppoe", format!("PPPoE: {e}"), json!({}));
                    }
                }
            }
            flush(&mut bng, &ports, slow.as_ref(), session, &mut errors);
            if !open || health.stopping() {
                break;
            }
        }
        bng.shutdown(ms());
        flush(&mut bng, &ports, slow.as_ref(), session, &mut errors);
    }

    /// What the worker's sockets hold, into its queue (until it is full:
    /// the rest waits in the kernel, which counts what it drops).
    fn fill(ports: &mut [PppoePort], queue: &mut VecDeque<(u32, Vec<u8>)>, lost: &mut u64, errors: &mut Vec<String>) {
        for p in ports.iter_mut() {
            let ifindex = p.ifindex();
            while queue.len() < QUEUE {
                match p.recv(|f| {
                    if queue.len() < QUEUE {
                        queue.push_back((ifindex, f.to_vec()));
                    } else {
                        *lost += 1;
                    }
                }) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => {
                        if errors.len() < 100 {
                            errors.push(format!("{}: {e}", p.name()));
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Send what the BNG made and do what it asked.
    fn flush(
        bng: &mut Bng,
        ports: &[PppoePort],
        slow: Option<&SlowTx>,
        session: &Shared,
        errors: &mut Vec<String>,
    ) {
        for (ifindex, f) in bng.frames.drain(..) {
            if let Some(p) = ports.iter().find(|p| p.ifindex() == ifindex)
                && let Err(e) = p.send(&f)
            {
                log::debug!("pppoe: send on ifindex {ifindex}: {e}");
            }
        }
        if let Some(s) = slow {
            for p in bng.upstream.drain(..) {
                let _ = s.inject(&p);
            }
        } else {
            bng.upstream.clear();
        }
        let effects: Vec<Effect> = std::mem::take(&mut bng.effects);
        if effects.is_empty() {
            return;
        }
        let mut ops: Vec<PppoeOp> = Vec::new();
        let mut routes: Vec<(std::net::Ipv4Addr, bool)> = Vec::new();
        let mut locked: Vec<Effect> = Vec::new();
        for e in effects {
            match e {
                Effect::Xdp(op) => ops.push(op),
                Effect::Route { ip, add } => routes.push((ip, add)),
                other => locked.push(other),
            }
        }
        // The round's /32 routes in one go on the worker's own connection.
        if let Some(s) = slow
            && let Err(e) = s.routes(&routes)
            && errors.len() < 100
        {
            errors.push(e.to_string());
        }
        if ops.is_empty() && locked.is_empty() {
            return;
        }
        let mut lists = Vec::new();
        let mut s = lock(session);
        if !ops.is_empty()
            && let Err(e) = s.pppoe_apply(&ops)
        {
            s.log_event(&["ppp", "error"], "pppoe", format!("PPPoE: mapa XDP: {e}"), json!({}));
        }
        for e in locked {
            match e {
                Effect::Run { command, params } => {
                    if let Err(err) = s.execute(&command, &params) {
                        s.log_event(&["ppp", "warning"], "pppoe", format!("PPP: hook {command}: {err}"), json!({}));
                    }
                }
                Effect::AddressList { list, ip, add, comment } => {
                    // 35 days: the longest dynamic entry (the BNG makes
                    // it again before).
                    lists.push(corerouter_engine::ppp::PppListOp { list, ip, add, timeout_secs: 35 * 86_400, comment });
                }
                Effect::Log { error, text } => {
                    let level = if error { "error" } else { "info" };
                    s.log_event(&["ppp", level], "pppoe", text, json!({}));
                }
                Effect::Xdp(_) | Effect::Route { .. } => {}
            }
        }
        for err in s.ppp_address_lists(&lists) {
            s.log_event(&["ppp", "warning"], "pppoe", format!("PPP: {err}"), json!({}));
        }
    }

    impl Driver {
        /// The ports the servers need, open for the workers (each its own
        /// sockets, filtered to its lane); the open ones by server name.
        /// Opened again, for every worker, when the set changes.
        fn open_ports(&mut self, wanted: &[PppoeServer]) -> HashMap<String, PortInfo> {
            let same = self.ports.len() == wanted.len()
                && wanted.iter().all(|w| {
                    self.ports.get(&w.name).is_some_and(|o| {
                        o.vlans == vlan_ids(w)
                            && o.untagged == (w.pppoe_over_vlan_range.is_empty() || w.accept_untagged)
                            && o.name == w.interface
                    })
                });
            if !same {
                let lanes = u16::try_from(self.workers.len()).unwrap_or(1).max(1);
                let mut by_lane: Vec<Vec<PppoePort>> = (0..lanes).map(|_| Vec::new()).collect();
                self.ports.clear();
                for w in wanted {
                    let vlans = vlan_ids(w);
                    let untagged = w.pppoe_over_vlan_range.is_empty() || w.accept_untagged;
                    let mut first: Option<Open> = None;
                    for (lane, mine) in by_lane.iter_mut().enumerate() {
                        let lane = u16::try_from(lane).unwrap_or(0);
                        match PppoePort::open_lane(&w.interface, &vlans, untagged, lane, lanes) {
                            Ok(port) => {
                                if first.is_none() {
                                    first = Some(Open {
                                        name: w.interface.clone(),
                                        info: PortInfo { ifindex: port.ifindex(), mac: port.mac() },
                                        vlans: vlans.clone(),
                                        untagged,
                                        rcvbuf: port.rcvbuf(),
                                    });
                                }
                                mine.push(port);
                            }
                            Err(e) => {
                                self.errors.push(format!("{}: {e}", w.interface));
                                break;
                            }
                        }
                    }
                    if let Some(o) = first {
                        self.ports.insert(w.name.clone(), o);
                    }
                }
                for (w, ports) in self.workers.iter().zip(by_lane) {
                    let _ = w.send(Msg::Ports(ports));
                }
            }
            self.ports.iter().map(|(k, o)| (k.clone(), o.info)).collect()
        }

        /// XDP when the HAL has it, else the slow path (once).
        fn choose_plane(&mut self, session: &Shared, shared: &Arc<Mutex<super::super::pppoe_bng::Shared>>, ifaces: Vec<corerouter_model::IfName>) {
            if self.plane.is_some() && self.plane_for == ifaces {
                return;
            }
            let r = lock(session).pppoe_dataplane(true, &ifaces);
            self.plane_for = ifaces;
            // `interface.pppoe-server.monitor` shows it.
            guard(shared).stats.dataplane = r.is_ok();
            match r {
                Ok(()) => self.plane = Some(true),
                Err(why) => {
                    self.plane = Some(false);
                    if self.slow.is_some() {
                        return;
                    }
                    match SlowPath::open() {
                        Ok(s) => {
                            for w in &self.workers {
                                match s.sender() {
                                    Ok(tx) => {
                                        let _ = w.send(Msg::Slow(Box::new(tx)));
                                    }
                                    Err(e) => self.errors.push(format!("slow path: {e}")),
                                }
                            }
                            self.slow = Some(s);
                        }
                        Err(e) => self
                            .errors
                            .push(format!("no XDP ({why}) and no slow path ({e}): subscribers get no traffic")),
                    }
                }
            }
        }

        /// The slow path's packets, or a nap (the workers read the ports).
        fn wait(&self) {
            let Some(s) = &self.slow else {
                std::thread::sleep(WAIT);
                return;
            };
            let mut polls = [PollFd::new(s.fd(), PollFlags::POLLIN)];
            let t = PollTimeout::try_from(WAIT).unwrap_or(PollTimeout::ZERO);
            let _ = poll(&mut polls, t);
        }

        /// The slow path's packets to the worker holding the address.
        fn receive_slow(&mut self, routes: &super::super::pppoe_bng::Routes) {
            let workers = &self.workers;
            let mut dropped = 0u64;
            if let Some(s) = self.slow.as_mut()
                && let Err(e) = s.recv(|p| {
                    let dst = p.get(16..20).and_then(|d| <[u8; 4]>::try_from(d).ok());
                    if let Some(lane) = dst.and_then(|d| Bng::route_lane_in(routes, std::net::Ipv4Addr::from(d)))
                        && let Some(w) = workers.get(usize::from(lane))
                        && !w.send(Msg::Down(p.to_vec()))
                    {
                        dropped += 1;
                    }
                })
            {
                self.errors.push(format!("slow path: {e}"));
            }
            self.dropped += dropped;
        }
    }
}

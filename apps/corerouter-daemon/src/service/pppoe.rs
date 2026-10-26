//! The PPPoE access concentrator (G4.3d) as a service: the I/O around the
//! BNG of `pppoe_bng.rs`, on several cores (G4.3g).
//!
//! - The service's thread reads the access ports (`AF_PACKET` through
//!   `hal-linux::pppoe_io`) and, without XDP, the slow path's `bng0`, and
//!   hands each frame to a worker by the client's MAC (like RSS: a CPE always
//!   lands on the same worker, its PADI, PADR and session alike). Its
//!   channels also absorb a power cut's PADI burst. A socket filtered per
//!   worker was measured and set aside: 24 000 sessions/s against this
//!   reader's 57 900 with BNG Blaster (`docs/architecture.md`).
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
    use std::collections::HashMap;

    use std::os::fd::BorrowedFd;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use corerouter_engine::{Shared, lock};
    use corerouter_hal::pppoe::PppoeOp;
    use corerouter_hal_linux::pppoe_io::{Listen, PortSender, PppoePort, SlowPath, SlowTx};
    use corerouter_model::ppp::{PppoeServer, pppoe_workers_auto};
    use corerouter_model::pppoe_vlans::VlanMode;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use serde_json::json;

    use super::super::pppoe_bng::{Backend, Bng, Effect, Owner, PortInfo, Snapshot, guard};

    /// Longest wait for a frame; timers and RADIUS answers are looked at
    /// least this often.
    const WAIT: Duration = Duration::from_millis(20);
    /// The config, the counters and the limits: once a second.
    const SECOND: Duration = Duration::from_secs(1);
    const IDLE: Duration = Duration::from_millis(500);
    /// Frames queued for one worker at most (a burst past it is dropped:
    /// the CPEs retransmit, RFC 2516 §5 and RFC 1661 §4.6).
    const QUEUE: usize = 1 << 16;
    /// Messages a worker takes in a row before its timers and RADIUS.
    const BUDGET: usize = 512;

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

    /// An open access port and what it was opened for.
    struct Open {
        port: PppoePort,
        listen: Vec<Listen>,
    }
    /// The sockets a server's port needs (G4.3l): untagged, one per 802.1Q
    /// VLAN id, or one per S-tag in stacked mode (the C-tag stays in the frame
    /// and `proto-pppoe` checks it).
    fn listens(v: &PppoeServer) -> Vec<Listen> {
        let ids = |r: &[corerouter_model::ppp::VlanRange]| -> Vec<u16> {
            r.iter().flat_map(|x| x.first..=x.last).collect()
        };
        let mut out = Vec::new();
        match v.vlan_mode {
            VlanMode::Stacked => {
                if v.accept_untagged {
                    out.push(Listen::Untagged);
                }
                let tpid = v.outer_tpid.value();
                out.extend(ids(&v.outer_vlan_range).into_iter().map(|outer| Listen::Stacked { outer, tpid }));
            }
            VlanMode::Single => {
                if v.pppoe_over_vlan_range.is_empty() || v.accept_untagged {
                    out.push(Listen::Untagged);
                }
                out.extend(ids(&v.pppoe_over_vlan_range).into_iter().map(Listen::Vlan));
            }
        }
        out
    }


    /// What the reader hands a worker.
    enum Msg {
        /// A frame from a client on access port `ifindex`.
        Frame(u32, Vec<u8>),
        /// Slow path: an IPv4 packet the kernel routed to its subscriber.
        Down(Vec<u8>),
        /// Once a second: the config, the ports open and the data plane.
        Config(Box<Snapshot>, HashMap<String, PortInfo>, bool),
        /// The ports changed: the worker's own senders for them.
        Ports(HashMap<u32, PortSender>),
        /// The slow path opened: the worker's own sender.
        Slow(Box<SlowTx>),
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
        workers: Vec<SyncSender<Msg>>,
        /// Frames dropped because a worker's queue was full (this second;
        /// `lost`: since the start).
        dropped: u64,
        lost: u64,
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
        let routes = (first.clone_routes(), first.clone_routes6());
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
            lost: 0,
        };
        let mut handles = Vec::new();
        for (lane, bng) in bngs.into_iter().enumerate() {
            let (tx, rx) = sync_channel::<Msg>(QUEUE);
            let s = session.clone();
            let h = health.clone();
            let t = health
                .spawn(&format!("pppoe-{lane}"), move || worker(bng, &rx, &s, &h))
                .map_err(|e| format!("cannot start PPPoE worker {lane}: {e}"))?;
            d.workers.push(tx);
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
                let (infos, changed) = d.open_ports(&wanted);
                if changed {
                    d.send_senders();
                }
                // system.health.check › Socket buffers: a PADI burst after
                // an outage must fit.
                {
                    let mut s = lock(session);
                    if let Some(t) = s.ext_mut::<corerouter_engine::health_check::SocketBuffers>() {
                        t.sockets.retain(|k, _| !k.starts_with("pppoe "));
                        for o in d.ports.values() {
                            t.sockets.insert(format!("pppoe {}", o.port.name()), o.port.rcvbuf());
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
                    d.errors.push(format!("{} frames dropped: the PPPoE workers are behind", d.dropped));
                    d.lost += d.dropped;
                    d.dropped = 0;
                }
                // interface.pppoe-server.monitor › rx_dropped: the queues'
                // losses and the kernel's (a socket's buffer full).
                guard(&shared).stats.rx_dropped =
                    d.lost + d.ports.values().map(|o| o.port.dropped()).sum::<u64>();
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
            d.receive(&routes);
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

    /// One worker: its BNG, fed by the reader, sending on its own sockets.
    fn worker(mut bng: Bng, rx: &Receiver<Msg>, session: &Shared, health: &super::super::Health) {
        let mut ports: HashMap<u32, PortSender> = HashMap::new();
        let mut slow: Option<SlowTx> = None;
        let mut configured = false;
        let mut last_tick = Instant::now();
        let mut errors: Vec<String> = Vec::new();
        loop {
            let now = ms();
            let mut wait = WAIT;
            if let Some(d) = bng.next_deadline() {
                wait = wait.min(Duration::from_millis(d.saturating_sub(now)));
            }
            if bng.waiting_radius() {
                wait = wait.min(Duration::from_millis(2));
            }
            let mut open = true;
            let mut first = Some(rx.recv_timeout(wait));
            for _ in 0..BUDGET {
                let next = match first.take() {
                    Some(r) => r,
                    None => rx.try_recv().map_err(|e| match e {
                        std::sync::mpsc::TryRecvError::Empty => RecvTimeoutError::Timeout,
                        std::sync::mpsc::TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
                    }),
                };
                match next {
                    Ok(m) => {
                        let now = ms();
                        match m {
                            Msg::Frame(ifindex, f) => bng.frame(now, ifindex, &f),
                            Msg::Down(p) => bng.data_down(&p),
                            Msg::Config(snap, infos, xdp) => {
                                bng.xdp = xdp;
                                bng.configure(now, *snap, &infos);
                                configured = true;
                            }
                            Msg::Ports(p) => ports = p,
                            Msg::Slow(s) => slow = Some(*s),
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        open = false;
                        break;
                    }
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

    /// Send what the BNG made and do what it asked.
    fn flush(
        bng: &mut Bng,
        ports: &HashMap<u32, PortSender>,
        slow: Option<&SlowTx>,
        session: &Shared,
        errors: &mut Vec<String>,
    ) {
        for (ifindex, f) in bng.frames.drain(..) {
            if let Some(p) = ports.get(&ifindex)
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
        let mut routes6: Vec<(std::net::Ipv6Addr, u8, bool)> = Vec::new();
        let mut locked: Vec<Effect> = Vec::new();
        for e in effects {
            match e {
                Effect::Xdp(op) => ops.push(op),
                Effect::Route { ip, add } => routes.push((ip, add)),
                Effect::Route6 { net, add } => routes6.push((net.network(), net.prefix_len(), add)),
                other => locked.push(other),
            }
        }
        // The round's routes in one go on the worker's own connection.
        if let Some(s) = slow {
            for r in [s.routes(&routes), s.routes6(&routes6)] {
                if let Err(e) = r
                    && errors.len() < 100
                {
                    errors.push(e.to_string());
                }
            }
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
                Effect::Xdp(_) | Effect::Route { .. } | Effect::Route6 { .. } => {}
            }
        }
        for err in s.ppp_address_lists(&lists) {
            s.log_event(&["ppp", "warning"], "pppoe", format!("PPP: {err}"), json!({}));
        }
    }

    impl Driver {
        /// Open the ports the servers need, close the rest; the open ones by
        /// server name, and whether the set changed.
        fn open_ports(&mut self, wanted: &[PppoeServer]) -> (HashMap<String, PortInfo>, bool) {
            let before = self.ports.len();
            self.ports.retain(|name, _| wanted.iter().any(|w| &w.name == name));
            let mut changed = before != self.ports.len();
            let mut infos = HashMap::new();
            for w in wanted {
                let listen = listens(w);
                let same = self
                    .ports
                    .get(&w.name)
                    .is_some_and(|o| o.listen == listen && o.port.name() == &w.interface);
                if !same {
                    self.ports.remove(&w.name);
                    changed = true;
                    match PppoePort::open_for(&w.interface, &listen) {
                        Ok(port) => {
                            self.ports.insert(w.name.clone(), Open { port, listen });
                        }
                        Err(e) => {
                            self.errors.push(format!("{}: {e}", w.interface));
                            continue;
                        }
                    }
                }
                if let Some(o) = self.ports.get(&w.name) {
                    infos.insert(w.name.clone(), PortInfo { ifindex: o.port.ifindex(), mac: o.port.mac() });
                }
            }
            (infos, changed)
        }

        /// Each worker its own senders for the open ports.
        fn send_senders(&mut self) {
            for w in &self.workers {
                let mut m = HashMap::new();
                for o in self.ports.values() {
                    match o.port.sender() {
                        Ok(s) => {
                            m.insert(s.ifindex(), s);
                        }
                        Err(e) => self.errors.push(format!("{}: {e}", o.port.name())),
                    }
                }
                let _ = w.send(Msg::Ports(m));
            }
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

        fn wait(&self) {
            let mut fds: Vec<BorrowedFd<'_>> = self.ports.values().flat_map(|o| o.port.fds()).collect();
            if let Some(s) = &self.slow {
                fds.push(s.fd());
            }
            if fds.is_empty() {
                std::thread::sleep(WAIT);
                return;
            }
            let mut polls: Vec<PollFd<'_>> = fds.into_iter().map(|f| PollFd::new(f, PollFlags::POLLIN)).collect();
            let t = PollTimeout::try_from(WAIT).unwrap_or(PollTimeout::ZERO);
            let _ = poll(&mut polls, t);
        }

        /// Every frame waiting, to the worker of its client's MAC; the slow
        /// path's packets to the worker holding the address.
        fn receive(&mut self, routes: &(super::super::pppoe_bng::Routes, super::super::pppoe_bng::Routes6)) {
            let lanes = u16::try_from(self.workers.len()).unwrap_or(1).max(1);
            let workers = &self.workers;
            let mut dropped = 0u64;
            let mut deliver = |lane: u16, m: Msg| {
                if let Some(w) = workers.get(usize::from(lane))
                    && let Err(TrySendError::Full(_)) = w.try_send(m)
                {
                    dropped += 1;
                }
            };
            for o in self.ports.values_mut() {
                let ifindex = o.port.ifindex();
                if let Err(e) = o
                    .port
                    .recv(|f| deliver(Bng::lane_of(f, lanes), Msg::Frame(ifindex, f.to_vec())))
                {
                    self.errors.push(format!("{}: {e}", o.port.name()));
                }
            }
            if let Some(s) = self.slow.as_mut()
                && let Err(e) = s.recv(|p| {
                    // IPv4 by its /32, IPv6 by the longest prefix (G4.3l).
                    let lane = if p.first().is_some_and(|b| b >> 4 == 6) {
                        let dst = p.get(24..40).and_then(|d| <[u8; 16]>::try_from(d).ok());
                        dst.and_then(|d| Bng::route6_lane_in(&routes.1, std::net::Ipv6Addr::from(d)))
                    } else {
                        let dst = p.get(16..20).and_then(|d| <[u8; 4]>::try_from(d).ok());
                        dst.and_then(|d| Bng::route_lane_in(&routes.0, std::net::Ipv4Addr::from(d)))
                    };
                    if let Some(lane) = lane {
                        deliver(lane, Msg::Down(p.to_vec()));
                    }
                })
            {
                self.errors.push(format!("slow path: {e}"));
            }
            self.dropped += dropped;
        }
    }
}

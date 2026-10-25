//! The PPPoE access concentrator (G4.3d) as a service: the I/O around the
//! BNG of `pppoe_bng.rs`. One thread owns the access ports (`AF_PACKET`
//! through `hal-linux::pppoe_io`), the BNG and, without XDP, the slow
//! path. The session lock is taken once a round, and only to read the
//! config, run what the BNG asked (XDP map, hooks, address lists, log
//! lines) and read the XDP counters: never while waiting on the network.
//!
//! With the XDP data plane (G4.3c) the subscribers' traffic never reaches
//! this thread: only control frames do (`XDP_PASS`). Without it (virtual
//! lab, a NIC without XDP, the unprivileged namespace tests) the thread
//! carries IPv4 itself (`pppoe_io::SlowPath`).

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
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use corerouter_engine::{Shared, lock};
    use corerouter_hal::pppoe::PppoeOp;
    use corerouter_hal_linux::pppoe_io::{PppoePort, SlowPath};
    use corerouter_model::ppp::PppoeServer;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use serde_json::json;

    use super::super::pppoe_bng::{Backend, Bng, Effect, Owner, PortInfo, Snapshot, vlan_ids};

    /// Longest wait for a frame; timers and RADIUS answers are looked at
    /// least this often.
    const WAIT: Duration = Duration::from_millis(20);
    /// The config, the counters and the limits: once a second.
    const SECOND: Duration = Duration::from_secs(1);
    const IDLE: Duration = Duration::from_millis(500);


    fn origin() -> Instant {
        static START: OnceLock<Instant> = OnceLock::new();
        *START.get_or_init(Instant::now)
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
        vlans: Vec<u16>,
        untagged: bool,
    }

    struct Driver {
        bng: Bng,
        ports: HashMap<String, Open>,
        slow: Option<SlowPath>,
        /// Data plane decided for these access ports: Some(true) XDP,
        /// Some(false) slow path. Decided again when the ports change (for new
        /// sessions; each session keeps the plane it started on).
        plane: Option<bool>,
        plane_for: Vec<corerouter_model::IfName>,
        errors: Vec<String>,
    }

    pub(super) fn run(
        session: &Shared,
        health: &super::super::Health,
        iid_key: Option<[u8; 32]>,
    ) -> Result<(), String> {
        let base = origin();
        let ms = move || u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX);
        let unix_base = unix_now().saturating_sub(ms() / 1000);
        let mut d = Driver {
            bng: Bng::new(seed()),
            ports: HashMap::new(),
            slow: None,
            plane: None,
            plane_for: Vec::new(),
            errors: Vec::new(),
        };
        let owner = Arc::new(Owner(d.bng.shared.clone()));
        let mut owner_of: Option<usize> = None;
        lock(session).set_ppp_backend(Arc::new(Backend(d.bng.shared.clone())));
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
                            t.sockets.insert(format!("pppoe {}", o.port.name()), o.port.rcvbuf());
                        }
                    }
                }
                if !wanted.is_empty() {
                    let mut ifaces: Vec<_> = wanted.iter().map(|w| w.interface.clone()).collect();
                    ifaces.sort();
                    d.choose_plane(session, ifaces);
                }
                d.bng.configure(
                    now,
                    Snapshot {
                        ppp,
                        pools,
                        aaa,
                        unix_base,
                        pools6,
                        iid_key,
                    },
                    &infos,
                );
                let counters = if d.plane == Some(true) {
                    lock(session).pppoe_counters(&d.bng.xdp_slots())
                } else {
                    Vec::new()
                };
                d.bng.tick(now, &counters);
                if d.errors.is_empty() {
                    health.clear_error();
                } else {
                    health.error(d.errors.join("; "));
                }
                if wanted.is_empty() {
                    d.flush(session);
                    if !health.sleep(IDLE) {
                        break;
                    }
                    continue;
                }
            }
            d.wait(now, &d.bng);
            let now = ms();
            d.receive(now);
            d.bng.radius(now);
            d.bng.timers(now);
            d.bng.requests(now);
            d.flush(session);
        }
        // Stopping: tell the subscribers (Terminate, PADT) and clean the maps.
        let now = ms();
        d.bng.shutdown(now);
        d.flush(session);
        Ok(())
    }

    impl Driver {
        /// Open the ports the servers need, close the rest; the open ones by
        /// server name.
        fn open_ports(&mut self, wanted: &[PppoeServer]) -> HashMap<String, PortInfo> {
            self.ports.retain(|name, _| wanted.iter().any(|w| &w.name == name));
            let mut infos = HashMap::new();
            for w in wanted {
                let vlans = vlan_ids(w);
                let untagged = w.pppoe_over_vlan_range.is_empty() || w.accept_untagged;
                let same = self
                    .ports
                    .get(&w.name)
                    .is_some_and(|o| o.vlans == vlans && o.untagged == untagged && o.port.name() == &w.interface);
                if !same {
                    self.ports.remove(&w.name);
                    match PppoePort::open(&w.interface, &vlans, untagged) {
                        Ok(port) => {
                            self.ports.insert(w.name.clone(), Open { port, vlans, untagged });
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
            infos
        }

        /// XDP when the HAL has it, else the slow path (once).
        fn choose_plane(&mut self, session: &Shared, ifaces: Vec<corerouter_model::IfName>) {
            if self.plane.is_some() && self.plane_for == ifaces {
                return;
            }
            let r = lock(session).pppoe_dataplane(true, &ifaces);
            self.plane_for = ifaces;
            // `interface.pppoe-server.monitor` shows it.
            super::super::pppoe_bng::guard(&self.bng.shared).stats.dataplane = r.is_ok();
            match r {
                Ok(()) => {
                    self.plane = Some(true);
                    self.bng.xdp = true;
                }
                Err(why) => {
                    self.plane = Some(false);
                    self.bng.xdp = false;
                    if self.slow.is_some() {
                        return;
                    }
                    match SlowPath::open() {
                        Ok(s) => self.slow = Some(s),
                        Err(e) => self
                            .errors
                            .push(format!("no XDP ({why}) and no slow path ({e}): subscribers get no traffic")),
                    }
                }
            }
        }

        fn wait(&self, now: u64, bng: &Bng) {
            let mut fds: Vec<BorrowedFd<'_>> = self.ports.values().flat_map(|o| o.port.fds()).collect();
            if let Some(s) = &self.slow {
                fds.push(s.fd());
            }
            let mut wait = WAIT;
            if let Some(d) = bng.next_deadline() {
                wait = wait.min(Duration::from_millis(d.saturating_sub(now)));
            }
            if bng.waiting_radius() {
                wait = wait.min(Duration::from_millis(2));
            }
            if fds.is_empty() {
                std::thread::sleep(wait);
                return;
            }
            let mut polls: Vec<PollFd<'_>> = fds.into_iter().map(|f| PollFd::new(f, PollFlags::POLLIN)).collect();
            let t = PollTimeout::try_from(wait).unwrap_or(PollTimeout::ZERO);
            let _ = poll(&mut polls, t);
        }

        fn receive(&mut self, now: u64) {
            let bng = &mut self.bng;
            for o in self.ports.values_mut() {
                let ifindex = o.port.ifindex();
                if let Err(e) = o.port.recv(|f| bng.frame(now, ifindex, f)) {
                    self.errors.push(format!("{}: {e}", o.port.name()));
                }
            }
            if let Some(s) = self.slow.as_mut()
                && let Err(e) = s.recv(|p| bng.data_down(p))
            {
                self.errors.push(format!("slow path: {e}"));
            }
        }

        /// Send what the BNG made and do what it asked.
        fn flush(&mut self, session: &Shared) {
            for (ifindex, f) in self.bng.frames.drain(..) {
                if let Some(o) = self.ports.values().find(|o| o.port.ifindex() == ifindex)
                    && let Err(e) = o.port.send(&f)
                {
                    log::debug!("pppoe: send on {}: {e}", o.port.name());
                }
            }
            if let Some(s) = &self.slow {
                for p in self.bng.upstream.drain(..) {
                    let _ = s.inject(&p);
                }
            } else {
                self.bng.upstream.clear();
            }
            let effects: Vec<Effect> = std::mem::take(&mut self.bng.effects);
            if effects.is_empty() {
                return;
            }
            let mut ops: Vec<PppoeOp> = Vec::new();
            let mut locked: Vec<Effect> = Vec::new();
            for e in effects {
                match e {
                    Effect::Xdp(op) => ops.push(op),
                    Effect::Route { ip, add } => {
                        if let Some(s) = &self.slow {
                            let r = if add { s.add_route(ip) } else { s.remove_route(ip) };
                            if let Err(e) = r {
                                self.errors.push(e.to_string());
                            }
                        }
                    }
                    other => locked.push(other),
                }
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
    }
}

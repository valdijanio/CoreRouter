//! BNG redundancy (G4.3h) as a service: the I/O around `proto_ha::node`.
//!
//! - **Sync link:** TLS on `ppp.redundancy listen_port` (the router's own
//!   certificate, as the control channel) and a dialer to `peer`. Only the
//!   node with the lower id keeps the connection it dials (the id is a hash
//!   of each router's certificate, which the dialer sees in the
//!   handshake), so the pair has one link. The peer's certificate is pinned
//!   on first use (`ppp-ha-peer.fingerprint` in the config directory). On
//!   top of TLS, `Node` authenticates both ends with the shared secret.
//! - **Access hellos:** an `AF_PACKET` socket per access port
//!   (`hal-linux::ha_io`), from the virtual MAC while active.
//! - **Witness:** an ICMP echo to each `witness` address every second;
//!   down after 3 misses in a row, up on the first answer.
//! - **Track:** the `track` ports must be running (carrier up).
//!
//! The node sits behind a mutex that every thread takes briefly and never
//! across I/O: the main loop (hellos, timers, every 10 ms), the connection
//! thread (bytes in and out) and the commands (`HaBackend`). What the
//! `pppoe` service reads to answer or keep quiet is [`shared`] (atomics).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::ppp_redundancy::HaBackend;
use corerouter_engine::{Shared, lock};
use corerouter_model::ppp_redundancy::{
    PeerStatus, Redundancy, RedundancyStatus, RoleChange, SyncStatus,
};
use corerouter_proto_ha::hello;
use corerouter_proto_ha::msg::Role;
use corerouter_proto_ha::node::{Event, Node, NodeConfig, section};
use corerouter_proto_ha::role::{RoleConfig, Transition};
use corerouter_proto_ha::sync::SyncConfig;
use serde_json::json;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "ppp-ha",
    flags: &[],
    topic: "ppp",
    enable: "ppp.redundancy.set enabled=yes peer=… secret=… witness=…",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_millis(10);
const HISTORY: usize = 32;

/// What the `pppoe` service reads (G4.3h phase 1): whether this node
/// answers subscribers and the AC MAC and AC-Cookie key of the pair.
pub(crate) struct HaShared {
    /// Redundancy is on: answer only while `answering`.
    pub enabled: AtomicBool,
    pub answering: AtomicBool,
    pub mac: Mutex<[u8; 6]>,
    pub cookie_key: Mutex<Option<[u8; 32]>>,
}

pub(crate) fn shared() -> &'static HaShared {
    static S: OnceLock<HaShared> = OnceLock::new();
    S.get_or_init(|| HaShared {
        enabled: AtomicBool::new(false),
        answering: AtomicBool::new(false),
        mac: Mutex::new([0; 6]),
        cookie_key: Mutex::new(None),
    })
}

/// The node and what the monitor shows about it.
struct Pair {
    node: Node,
    cfg: Redundancy,
    sections: Vec<corerouter_proto_ha::msg::Section>,
    history: VecDeque<RoleChange>,
    last_error: Option<String>,
    /// The current connection's number: a thread whose number is not this
    /// one was replaced and stops.
    conn: u64,
    peer_fingerprint: String,
}

struct Runtime {
    pair: Mutex<Option<Pair>>,
    origin: Instant,
    our_id: Mutex<(u64, String)>,
}

impl Runtime {
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn pair(&self) -> std::sync::MutexGuard<'_, Option<Pair>> {
        self.pair.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn runtime() -> &'static Arc<Runtime> {
    static R: OnceLock<Arc<Runtime>> = OnceLock::new();
    R.get_or_init(|| {
        Arc::new(Runtime {
            pair: Mutex::new(None),
            origin: Instant::now(),
            our_id: Mutex::new((0, String::new())),
        })
    })
}

struct Backend(Arc<Runtime>);

impl HaBackend for Backend {
    fn status(&self) -> RedundancyStatus {
        let now = self.0.now();
        let g = self.0.pair();
        let Some(p) = g.as_ref() else {
            return RedundancyStatus {
                role: "disabled".into(),
                ..RedundancyStatus::default()
            };
        };
        status_of(p, now)
    }

    fn switchover(&self, force: bool) -> Result<(), String> {
        let now = self.0.now();
        let mut g = self.0.pair();
        let p = g.as_mut().ok_or("redundancy is not enabled")?;
        p.node.switchover(now, force).map_err(|r| r.as_str().to_owned())
    }

    fn simulate_failure(&self, secs: u32) -> Result<(), String> {
        let now = self.0.now();
        let mut g = self.0.pair();
        let p = g.as_mut().ok_or("redundancy is not enabled")?;
        p.node
            .simulate_failure(now, u64::from(secs) * 1000)
            .map_err(|r| r.as_str().to_owned())
    }
}

fn status_of(p: &Pair, now: u64) -> RedundancyStatus {
    let s = p.node.status(now);
    let r = &s.role;
    let (sessions, synced, lag, delay, snapshots, snapshot) = match &s.publisher {
        Some(ps) => (
            u64::from(ps.sessions),
            u64::from(s.peer_sessions),
            ps.seq.saturating_sub(ps.acked),
            ps.delay_ms,
            ps.snapshots,
            ps.snapshot,
        ),
        None => (
            u64::from(s.peer_sessions),
            u64::from(s.replica.sessions),
            s.peer_seq.saturating_sub(s.replica.applied),
            0,
            s.replica.snapshots,
            s.replica.snapshot,
        ),
    };
    RedundancyStatus {
        role: r.role.as_str().into(),
        epoch: r.epoch,
        role_since_secs: now.saturating_sub(r.since) / 1000,
        answering: r.role == Role::Active,
        peer: PeerStatus {
            connected: s.link.is_some(),
            role: r.peer.map(|v| v.role.as_str().to_owned()).unwrap_or_default(),
            priority: s.peer_priority,
            sync_path: r.paths[0],
            access_path: r.paths[1],
            witness: r.peer.is_some_and(|v| v.witness),
            fingerprint: p.peer_fingerprint.clone(),
        },
        witness: r.witness,
        track: r.track,
        in_sync: if s.publisher.is_some() {
            r.peer.is_some_and(|v| v.in_sync)
        } else {
            r.synced
        },
        sync: SyncStatus {
            sessions,
            synced,
            lag,
            delay_ms: delay,
            snapshots,
            snapshot,
            gaps: s.replica.gaps,
            bytes_sent: s.bytes_out,
            bytes_received: s.bytes_in,
        },
        drift: s.drift,
        simulating_secs: r.simulating_until.map(|u| u.saturating_sub(now) / 1000),
        duplicate_node_id: r.duplicate_node_id,
        history: p.history.iter().rev().cloned().collect(),
        last_error: p.last_error.clone(),
    }
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let dir = ctx.config_dir.clone();
    let rt = runtime().clone();
    lock(&session).set_ha_backend(Arc::new(Backend(rt.clone())));
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health, &rt, dir.as_deref())
    }))
}

/// A stable id of this router: the first 8 bytes of its certificate's
/// fingerprint (what the dialer sees of the peer, so both agree).
fn id_of(fingerprint: &str) -> u64 {
    section("id", fingerprint.as_bytes()).hash | 1
}

/// Log lines waiting for the engine's lock (the role machine never waits
/// on it: a mass login holds it often, and a node that stops its hellos
/// for 1.2 s gets its role taken). At most [`LOG_QUEUE`] wait.
static LOGS: Mutex<VecDeque<(&'static str, String, serde_json::Value)>> = Mutex::new(VecDeque::new());
const LOG_QUEUE: usize = 256;

fn log(_session: &Shared, level: &'static str, message: String, data: serde_json::Value) {
    let mut q = LOGS.lock().unwrap_or_else(PoisonError::into_inner);
    if q.len() < LOG_QUEUE {
        q.push_back((level, message, data));
    }
}

/// The engine's lock if it is free now.
fn try_session(session: &Shared) -> Option<std::sync::MutexGuard<'_, corerouter_engine::Session>> {
    match session.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

/// Writes the queued log lines, if the engine's lock is free.
fn flush_logs(session: &Shared) {
    let lines: Vec<_> = {
        let mut q = LOGS.lock().unwrap_or_else(PoisonError::into_inner);
        if q.is_empty() {
            return;
        }
        q.drain(..).collect()
    };
    match try_session(session) {
        Some(mut s) => {
            for (level, message, data) in lines {
                s.log_event(&["ppp", level], corerouter_engine::logging::DAEMON, message, data);
            }
        }
        None => {
            let mut q = LOGS.lock().unwrap_or_else(PoisonError::into_inner);
            for l in lines.into_iter().rev() {
                q.push_front(l);
            }
            q.truncate(LOG_QUEUE);
        }
    }
}

/// The config sections the two nodes must agree on, hashed.
fn sections(cfg: &corerouter_model::Config) -> Vec<corerouter_proto_ha::msg::Section> {
    let j = |v: serde_json::Value| serde_json::to_vec(&v).unwrap_or_default();
    vec![
        section("ppp.profile", &j(json!(cfg.ppp.profiles))),
        section("interface.pppoe-server", &j(json!(cfg.ppp.pppoe_servers.iter().map(|s| {
            // The access port's name may differ between the two machines.
            let mut v = json!(s);
            if let Some(o) = v.as_object_mut() {
                o.remove("interface");
                o.remove("id");
            }
            v
        }).collect::<Vec<_>>()))),
        section("ppp.aaa", &j(json!(cfg.ppp.aaa))),
        section("ip.pool", &j(json!(cfg.ip.pools.pools))),
        // Both must run as many workers (`pppoe_bng::ha::LANES`).
        section(
            "pppoe.workers",
            &super::pppoe_bng::ha::LANES
                .load(Ordering::Acquire)
                .to_le_bytes(),
        ),
    ]
}

fn node_config(r: &Redundancy, id: u64, sections: Vec<corerouter_proto_ha::msg::Section>) -> NodeConfig {
    let mut inc = [0u8; 8];
    let _ = getrandom::fill(&mut inc);
    NodeConfig {
        role: RoleConfig {
            node_id: id,
            incarnation: u64::from_le_bytes(inc) | 1,
            priority: r.priority,
            preempt: r.preempt,
            preempt_delay_ms: u64::from(r.preempt_delay) * 1000,
            hello_ms: u64::from(r.hello_interval),
            dead_ms: u64::from(r.dead_interval),
            init_hold_ms: u64::from(r.init_hold) * 1000,
            recover_hold_ms: u64::from(r.recover_hold) * 1000,
            handover_timeout_ms: 2000,
            witness: r.fencing.uses_witness(),
            access_path: r.fencing.uses_access(),
            hot_standby: r.mode == corerouter_model::ppp_redundancy::HaMode::HotStandby,
        },
        sync: SyncConfig::default(),
        hello_key: hello::derive("hello", r.secret.as_bytes()),
        link_key: hello::derive("link", r.secret.as_bytes()),
        sections,
    }
}

/// The `pppoe` workers' changes (hot standby): into the publisher, while
/// this node is the active one (elsewhere `Node` ignores them).
pub(crate) fn publish(changes: Vec<super::pppoe_bng::ha::HaChange>) {
    use super::pppoe_bng::ha::HaChange;
    let rt = runtime();
    let now = rt.now();
    let mut g = rt.pair();
    let Some(p) = g.as_mut() else {
        return;
    };
    for c in changes {
        match c {
            HaChange::Up(k, v) => p.node.upsert(now, k, v),
            HaChange::Gone(k) => p.node.remove(now, k),
            HaChange::Counters(k, c) => p.node.counters(now, k, c),
        }
    }
}

/// This node takes the role: the replica's sessions for the `pppoe`
/// workers to adopt (stateful), or none (they redial). Before the workers
/// may answer: a frame of a session not adopted yet would get a PADT.
fn hand_takeover(p: &Pair, t: &Transition) {
    use super::pppoe_bng::ha::{TAKEOVER, TAKEOVER_GEN};
    let records = t.stateful.then(|| {
        p.node
            .publisher()
            .map(|pb| {
                pb.iter()
                    .filter_map(|(_, v, c)| {
                        corerouter_proto_ha::record::SessionRecord::decode(v).ok().map(|mut r| {
                            r.counters = c;
                            r
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    *TAKEOVER.lock().unwrap_or_else(PoisonError::into_inner) = records.map(Arc::new);
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
}

fn record(p: &mut Pair, t: &Transition) {
    if p.history.len() >= HISTORY {
        p.history.pop_front();
    }
    p.history.push_back(RoleChange {
        at: unix_now(),
        from: t.from.as_str().into(),
        to: t.to.as_str().into(),
        epoch: t.epoch,
        reason: t.reason.as_str().into(),
        stateful: t.stateful,
    });
}

#[cfg(target_os = "linux")]
use linux::run;

#[cfg(not(target_os = "linux"))]
fn run(
    session: &Shared,
    health: &super::Health,
    rt: &Arc<Runtime>,
    dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let _ = (session, rt, dir);
    health.disabled(Some("BNG redundancy needs Linux (AF_PACKET access ports)"));
    while health.sleep(Duration::from_secs(1)) {
        health.beat();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
    use std::path::Path;
    use std::sync::atomic::AtomicU64;

    use corerouter_control::tls;
    use corerouter_hal::probe::{Probe, Prober, ReplyKind, SocketOptions, overhead};
    use corerouter_hal_linux::ha_io::{self, HaPort};
    use corerouter_hal_linux::icmp::HostProber;
    use corerouter_model::IfName;
    use corerouter_model::service::Listen;

    use super::*;

    const PIN_FILE: &str = "ppp-ha-peer.fingerprint";

    /// The witness, as the prober thread last saw it.
    static WITNESS: AtomicBool = AtomicBool::new(false);
    static CONNS: AtomicU64 = AtomicU64::new(0);

    pub(super) fn run(
        session: &Shared,
        health: &super::super::Health,
        rt: &Arc<Runtime>,
        dir: Option<&Path>,
    ) -> Result<(), String> {
        let (identity, _) = match dir {
            Some(d) => tls::load_or_create(d)?,
            None => {
                let (c, k) = tls::generate()?;
                (tls::identity_from_pem(c.as_bytes(), k.as_bytes())?, true)
            }
        };
        let our_id = id_of(&identity.fingerprint);
        *rt.our_id.lock().unwrap_or_else(PoisonError::into_inner) = (our_id, identity.fingerprint.clone());
        let mut ports: Vec<HaPort> = Vec::new();
        let mut listener: Option<(u16, TcpListener)> = None;
        let mut next_cfg = Instant::now();
        let mut next_dial = Instant::now();
        let mut track: Vec<IfName> = Vec::new();
        let mut prober_started = false;
        let mut access_in = Vec::new();
        let mut access_out = Vec::new();
        let mut events = Vec::new();
        loop {
            health.beat();
            flush_logs(session);
            // The config once a second, when the engine's lock is free (a
            // busy engine delays it, never the hellos below).
            let guard_now = if Instant::now() >= next_cfg { try_session(session) } else { None };
            if let Some(s) = guard_now {
                next_cfg = Instant::now() + Duration::from_secs(1);
                let (r, secs, pppoe_ifs) = {
                    let cfg = s.store().running();
                    let ifs: Vec<IfName> = cfg
                        .ppp
                        .pppoe_servers
                        .iter()
                        .filter(|x| !x.disabled)
                        .map(|x| x.interface.clone())
                        .collect();
                    (cfg.ppp.redundancy.clone(), sections(cfg), ifs)
                };
                drop(s);
                let sh = shared();
                if !r.enabled {
                    if rt.pair().take().is_some() {
                        log(session, "info", "ppp redundancy off".into(), json!({}));
                    }
                    ports.clear();
                    listener = None;
                    sh.enabled.store(false, Ordering::Release);
                    sh.answering.store(false, Ordering::Release);
                    health.listen(Vec::new());
                super::super::pppoe_bng::HA_ACTIVE.store(false, Ordering::Release);
                    health.disabled(Some("ppp.redundancy.set enabled=no"));
                    if !health.sleep(Duration::from_millis(200)) {
                        return Ok(());
                    }
                    continue;
                }
                health.disabled(None);
                let rebuild = rt.pair().as_ref().is_none_or(|p| p.cfg != r || p.sections != secs);
                if rebuild {
                    let fp = dir
                        .and_then(|d| std::fs::read_to_string(d.join(PIN_FILE)).ok())
                        .map(|s| s.trim().to_owned())
                        .unwrap_or_default();
                    *rt.pair() = Some(Pair {
                        node: Node::new(node_config(&r, our_id, secs.clone()), rt.now()),
                        cfg: r.clone(),
                        sections: secs,
                        history: VecDeque::new(),
                        last_error: None,
                        conn: CONNS.fetch_add(1, Ordering::AcqRel) + 1,
                        peer_fingerprint: fp,
                    });
                    *sh.mac.lock().unwrap_or_else(PoisonError::into_inner) = r.mac().0;
                    *sh.cookie_key.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(hello::derive("ac-cookie", r.secret.as_bytes()));
                    sh.enabled.store(true, Ordering::Release);
                    sh.answering.store(false, Ordering::Release);
                    let names: Vec<IfName> = if r.interfaces.is_empty() {
                        pppoe_ifs
                    } else {
                        r.interfaces.clone()
                    };
                    ports.clear();
                    for n in &names {
                        match HaPort::open(n) {
                            Ok(p) => ports.push(p),
                            Err(e) => set_error(rt, health, format!("access hello on {n}: {e}")),
                        }
                    }
                    log(
                        session,
                        "info",
                        format!("ppp redundancy on: node {our_id:016x}, group {}, priority {}", r.group, r.priority),
                        json!({"node_id": format!("{our_id:016x}"), "access_ports": names.len()}),
                    );
                }
                let witnesses: Vec<IpAddr> = r.witness.clone();
                track = r.track.clone();
                if listener.as_ref().is_none_or(|(p, _)| *p != r.listen_port) {
                    listener = None;
                    match bind(r.listen_port) {
                        Ok(l) => {
                            health.listen(vec![Listen::new(
                                "tcp",
                                SocketAddr::from(([0u16; 8], r.listen_port)),
                            )]);
                            listener = Some((r.listen_port, l));
                        }
                        Err(e) => set_error(rt, health, e),
                    }
                }
                if !prober_started && !witnesses.is_empty() {
                    prober_started = true;
                    let w = Arc::new(Mutex::new(witnesses.clone()));
                    let w2 = w.clone();
                    let _ = health.spawn("ppp-ha-witness", move || witness_loop(&w2));
                    WITNESS_LIST.get_or_init(|| w);
                }
                if let Some(w) = WITNESS_LIST.get() {
                    *w.lock().unwrap_or_else(PoisonError::into_inner) = witnesses.clone();
                }
            }
            // Accept the peer's connection.
            if let Some((_, l)) = &listener
                && let Ok((tcp, from)) = l.accept()
            {
                let rt2 = rt.clone();
                let config = identity.config.clone();
                let _ = health.spawn("ppp-ha-accept", move || {
                    let _ = tcp.set_nonblocking(false);
                    let _ = tcp.set_read_timeout(Some(tls::HANDSHAKE_TIMEOUT));
                    match tls::accept(tcp, config) {
                        Ok(s) => serve(&rt2, s, format!("from {from}"), false),
                        Err(e) => log::debug!("ppp-ha: TLS from {from}: {e}"),
                    }
                });
            }
            // Dial the peer (the lower id keeps it).
            if Instant::now() >= next_dial {
                next_dial = Instant::now() + Duration::from_secs(2);
                let want = {
                    let g = rt.pair();
                    g.as_ref().and_then(|p| {
                        let peer_fp = &p.peer_fingerprint;
                        let peer_is_lower = !peer_fp.is_empty() && id_of(peer_fp) < our_id;
                        (!p.node.link_up() && !peer_is_lower)
                            .then(|| (p.cfg.peer.clone(), peer_fp.clone()))
                    })
                };
                if let Some((Some(peer), pin)) = want {
                    let rt2 = rt.clone();
                    let dir2 = dir.map(Path::to_path_buf);
                    let _ = health.spawn("ppp-ha-dial", move || dial(&rt2, &peer, &pin, our_id, dir2.as_deref()));
                }
            }
            // Access hellos in, timers, hellos and events out.
            access_in.clear();
            for p in &ports {
                p.recv(|b| access_in.push(b.to_vec()));
            }
            let mac = *shared().mac.lock().unwrap_or_else(PoisonError::into_inner);
            let witness_ok = WITNESS.load(Ordering::Acquire);
            let track_ok = track.iter().all(ha_io::running);
            {
                let now = rt.now();
                let mut g = rt.pair();
                if let Some(p) = g.as_mut() {
                    for b in &access_in {
                        p.node.access_input(now, b);
                    }
                    p.node.witness(now, witness_ok);
                    p.node.track(now, track_ok);
                    p.node.tick(now);
                    p.node.take_access(&mut access_out);
                    p.node.take_events(&mut events);
                    for e in &events {
                        if let Event::Role(t) = e {
                            record(p, t);
                            if t.to == Role::Active {
                                hand_takeover(p, t);
                            }
                        }
                    }
                    shared().answering.store(p.node.answering(), Ordering::Release);
                    super::super::pppoe_bng::HA_ACTIVE.store(p.node.answering(), Ordering::Release);
                }
            }
            for (body, from_vmac) in access_out.drain(..) {
                for port in &ports {
                    let src = if from_vmac { mac } else { port.mac() };
                    if let Err(e) = port.send(src, &body) {
                        log::debug!("ppp-ha: hello on {}: {e}", port.name());
                    }
                }
            }
            for e in events.drain(..) {
                match e {
                    Event::Role(t) => log(
                        session,
                        if t.to == Role::Active || t.from == Role::Active { "warning" } else { "info" },
                        format!(
                            "ppp redundancy: {} → {} ({}, epoch {}{})",
                            t.from.as_str(),
                            t.to.as_str(),
                            t.reason.as_str(),
                            t.epoch,
                            if t.stateful { ", sessions kept" } else { "" }
                        ),
                        json!({"from": t.from.as_str(), "to": t.to.as_str(), "reason": t.reason.as_str(), "epoch": t.epoch, "stateful": t.stateful}),
                    ),
                    Event::PeerUp { node_id } => log(
                        session,
                        "info",
                        format!("ppp redundancy: peer {node_id:016x} connected"),
                        json!({"peer": format!("{node_id:016x}")}),
                    ),
                }
            }
            if !health.sleep(TICK) {
                *rt.pair() = None;
                shared().enabled.store(false, Ordering::Release);
                shared().answering.store(false, Ordering::Release);
                super::super::pppoe_bng::HA_ACTIVE.store(false, Ordering::Release);
                return Ok(());
            }
        }
    }

    static WITNESS_LIST: OnceLock<Arc<Mutex<Vec<IpAddr>>>> = OnceLock::new();

    fn set_error(rt: &Runtime, health: &super::super::Health, e: String) {
        health.error(&e);
        if let Some(p) = rt.pair().as_mut() {
            p.last_error = Some(e);
        }
    }

    fn bind(port: u16) -> Result<TcpListener, String> {
        let l = TcpListener::bind(SocketAddr::from(([0u16; 8], port)))
            .or_else(|_| TcpListener::bind(SocketAddr::from(([0u8; 4], port))))
            .map_err(|e| format!("cannot listen on TCP {port}: {e}"))?;
        l.set_nonblocking(true)
            .map_err(|e| format!("cannot listen on TCP {port}: {e}"))?;
        Ok(l)
    }

    /// One echo per witness per second; down after 3 misses in a row.
    fn witness_loop(list: &Mutex<Vec<IpAddr>>) {
        let prober = match HostProber::detect() {
            Ok(p) => p,
            Err(e) => {
                log::warn!("ppp-ha: witness probe: {e}");
                return;
            }
        };
        let mut misses = 3u32;
        let mut seq: u16 = 0;
        loop {
            let started = Instant::now();
            let targets = list.lock().unwrap_or_else(PoisonError::into_inner).clone();
            let mut ok = false;
            if let Ok(mut sock) = prober.open(&SocketOptions::default()) {
                for dst in &targets {
                    seq = seq.wrapping_add(1);
                    let probe = Probe {
                        dst: *dst,
                        seq,
                        ttl: None,
                        size: overhead(*dst) + 16,
                    };
                    if sock.send(&probe).is_err() {
                        continue;
                    }
                    let until = Instant::now() + Duration::from_millis(500);
                    while let Some(left) = until.checked_duration_since(Instant::now()) {
                        match sock.recv(left) {
                            Ok(Some(r)) if r.seq == seq && r.kind == ReplyKind::Echo => {
                                ok = true;
                                break;
                            }
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                    if ok {
                        break;
                    }
                }
            }
            misses = if ok { 0 } else { misses.saturating_add(1) };
            WITNESS.store(misses < 3, Ordering::Release);
            if let Some(rest) = Duration::from_secs(1).checked_sub(started.elapsed()) {
                std::thread::sleep(rest);
            }
        }
    }

    fn dial(rt: &Arc<Runtime>, peer: &str, pin: &str, our_id: u64, dir: Option<&Path>) {
        let Some(addr) = peer.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
            if let Some(p) = rt.pair().as_mut() {
                p.last_error = Some(format!("peer {peer}: cannot resolve"));
            }
            return;
        };
        let tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(t) => t,
            Err(e) => {
                if let Some(p) = rt.pair().as_mut() {
                    p.last_error = Some(format!("peer {peer}: {e}"));
                }
                return;
            }
        };
        let _ = tcp.set_read_timeout(Some(tls::HANDSHAKE_TIMEOUT));
        let pinned = (!pin.is_empty()).then_some(pin);
        let (stream, fp) = match tls::connect(tcp, pinned) {
            Ok(x) => x,
            Err(e) => {
                if let Some(p) = rt.pair().as_mut() {
                    p.last_error = Some(format!("peer {peer}: {e}"));
                }
                return;
            }
        };
        if pin.is_empty() {
            if let Some(d) = dir {
                let _ = std::fs::write(d.join(PIN_FILE), format!("{fp}\n"));
            }
            if let Some(p) = rt.pair().as_mut() {
                p.peer_fingerprint = fp.clone();
            }
        }
        // The higher id lets the lower one dial: one link for the pair.
        if id_of(&fp) < our_id {
            return;
        }
        serve(rt, stream, format!("to {peer}"), true);
    }

    /// Runs one sync connection until it fails or another replaces it.
    /// `eager` (we dialed): take the node's link at once. An accepted one
    /// takes it only when the peer's first bytes arrive: a dialer that
    /// closes right after TLS (it lets us dial) never breaks the link up.
    fn serve<S: Read + Write + Sock>(rt: &Arc<Runtime>, mut s: S, what: String, eager: bool) {
        let _ = s.tcp().set_read_timeout(Some(Duration::from_millis(20)));
        let _ = s.tcp().set_write_timeout(Some(Duration::from_secs(2)));
        let _ = s.tcp().set_nodelay(true);
        let mut nonce = [0u8; 32];
        if getrandom::fill(&mut nonce).is_err() {
            return;
        }
        let mut buf = vec![0u8; 64 << 10];
        let mut first = 0;
        if !eager {
            let until = Instant::now() + tls::HANDSHAKE_TIMEOUT;
            loop {
                match s.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        first = n;
                        break;
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        if Instant::now() > until {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }
        let me = CONNS.fetch_add(1, Ordering::AcqRel) + 1;
        let dead = {
            let now = rt.now();
            let mut g = rt.pair();
            let Some(p) = g.as_mut() else {
                return;
            };
            p.conn = me;
            p.node.connected(now, nonce);
            if first > 0 && p.node.input(now, buf.get(..first).unwrap_or(&[])).is_err() {
                p.node.disconnected();
                return;
            }
            u64::from(p.cfg.dead_interval) * 3
        };
        log::info!("ppp-ha: sync connection {what}");
        let mut out = Vec::new();
        let mut last_rx = Instant::now();
        let reason = loop {
            {
                let now = rt.now();
                let mut g = rt.pair();
                let Some(p) = g.as_mut() else {
                    break "redundancy off".to_owned();
                };
                if p.conn != me {
                    return;
                }
                p.node.poll(now, (4usize << 20).saturating_sub(out.len()));
                p.node.take_output(&mut out);
            }
            if !out.is_empty() {
                if let Err(e) = s.write_all(&out).and_then(|()| s.flush()) {
                    break format!("write: {e}");
                }
                out.clear();
            }
            match s.read(&mut buf) {
                Ok(0) => break "closed by the peer".to_owned(),
                Ok(n) => {
                    last_rx = Instant::now();
                    let now = rt.now();
                    let mut g = rt.pair();
                    let Some(p) = g.as_mut() else {
                        break "redundancy off".to_owned();
                    };
                    if p.conn != me {
                        return;
                    }
                    if let Err(e) = p.node.input(now, buf.get(..n).unwrap_or(&[])) {
                        p.last_error = Some(e.to_string());
                        break e.to_string();
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(e) => break format!("read: {e}"),
            }
            if last_rx.elapsed() > Duration::from_millis(dead.max(3000)) {
                break "silent".to_owned();
            }
        };
        log::info!("ppp-ha: sync connection {what} closed: {reason}");
        if let Some(p) = rt.pair().as_mut()
            && p.conn == me
        {
            p.node.disconnected();
        }
    }

    /// The TCP socket under a TLS stream (timeouts).
    trait Sock {
        fn tcp(&mut self) -> &mut TcpStream;
    }

    impl Sock for tls::ClientStream {
        fn tcp(&mut self) -> &mut TcpStream {
            &mut self.sock
        }
    }

    impl Sock for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
        fn tcp(&mut self) -> &mut TcpStream {
            &mut self.sock
        }
    }
}

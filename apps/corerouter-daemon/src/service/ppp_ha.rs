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
//! - **CoA/DM of the peer's sessions** (G4.3hb): a request no session
//!   here claims, while this node is not the one answering, goes to the
//!   peer over the sync link ([`PeerForward`]); its owners apply it and
//!   this node answers the RADIUS server with what they said.
//!
//! - **BFD** (G3.6h, [`pair`]): the `bfd` service runs a session to the
//!   peer on the sync path and on the access path; its threads queue each
//!   change for the role machine (no session lock on the way), and a loss
//!   asks the witness thread for a probe at once. Each takeover keeps its
//!   timeline (failure, detection, witness, active, announced, adopted,
//!   first frame, sessions lost), and `test-takeover` runs one on purpose.
//!
//! The node sits behind a mutex that every thread takes briefly and never
//! across I/O: the main loop (hellos, timers, every 10 ms), the connection
//! thread (bytes in and out) and the commands (`HaBackend`). What the
//! `pppoe` service reads to answer or keep quiet is [`shared`] (atomics).

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::ppp_redundancy::HaBackend;
use corerouter_engine::{Shared, lock};
use corerouter_model::radius::{CoaOutcome, CoaRequest};
use corerouter_model::ppp_redundancy::{
    PeerStatus, Redundancy, RedundancyStatus, RoleChange, SyncStatus, Takeover, TakeoverTest, TestCheck,
};
use corerouter_proto_ha::hello;
use corerouter_proto_ha::msg::Role;
use corerouter_proto_ha::node::{Event, Node, NodeConfig, section};
use corerouter_proto_ha::role::{BfdDamp, Path, RoleConfig, Transition};
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
const TAKEOVERS: usize = 16;

#[path = "ppp_ha/pair.rs"]
mod pair;
pub(crate) use pair::{adopted, answering, frame_seen, publish_bfd, routes_installed, silent as bfd_silent, tap as bfd_tap};

/// The witness's last answer (`Runtime::now` ms; 0 = none yet) and a
/// probe asked for now (BFD found the peer silent).
static WITNESS_AT: AtomicU64 = AtomicU64::new(0);
static WITNESS_URGENT: AtomicBool = AtomicBool::new(false);
/// The id of our "last takeover?" question to the peer, and its answer.
static QUERY_ID: AtomicU64 = AtomicU64::new(0);
static PEER_TAKEOVER: Mutex<Option<Takeover>> = Mutex::new(None);
/// Raw answers to the peer's questions (not CoA), for the main loop.
static RAW_REPLIES: Mutex<Vec<(u64, Vec<u8>)>> = Mutex::new(Vec::new());
/// The body of the "last takeover?" question (a CoA request needs
/// `kind`, `from` and `selector`: a peer without G3.6h answers 404).
const QUERY_TAKEOVER: &[u8] = br#"{"ha":"last-takeover"}"#;

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

// ---- G4.3hb: CoA/Disconnect through the pair ----------------------------------

/// Requests handed to the peer: when, and who waits for the answer.
struct Forwards {
    next: u64,
    waiting: BTreeMap<u64, (u64, super::radius_aaa::CoaDone)>,
}

static FORWARDS: Mutex<Forwards> = Mutex::new(Forwards {
    next: 0,
    waiting: BTreeMap::new(),
});
/// Answers to the peer's requests (posted by the RADIUS driver's thread),
/// for the main loop to send.
static PEER_REPLIES: Mutex<Vec<(u64, CoaOutcome)>> = Mutex::new(Vec::new());
/// The RADIUS service's handle: its owners apply the peer's requests.
static AAA: Mutex<Option<super::radius_aaa::Aaa>> = Mutex::new(None);
/// Bounds the forwarded requests in flight (the RADIUS driver's too).
const MAX_FORWARDS: usize = 1024;
/// An answer older than this is not waited for (the driver answered
/// 505 at 2 s already).
const FORWARD_FORGET_MS: u64 = 5000;

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The RADIUS service registers itself (G4.3hb).
pub(crate) fn set_aaa(aaa: Option<super::radius_aaa::Aaa>) {
    *locked(&AAA) = aaa;
}

/// `radius_aaa`'s way to the peer: only while this node is not the one
/// answering subscribers (the active holds every session; a standby
/// asking it is the case of a server that still targets the old active).
pub(crate) struct PeerForward;

impl super::radius_aaa::CoaForward for PeerForward {
    fn forward(&self, req: &CoaRequest, done: super::radius_aaa::CoaDone) -> bool {
        let Ok(body) = serde_json::to_vec(req) else {
            return false;
        };
        let rt = runtime();
        let now = rt.now();
        // In the table before it is sent: the answer cannot overtake it.
        let id = {
            let mut f = locked(&FORWARDS);
            if f.waiting.len() >= MAX_FORWARDS {
                return false;
            }
            f.next += 1;
            let id = f.next;
            f.waiting.insert(id, (now, done));
            id
        };
        let sent = match rt.pair().as_mut() {
            Some(p) if !p.node.answering() => p.node.forward(id, body),
            _ => false,
        };
        if !sent {
            // Dropped unanswered: the caller answers itself.
            drop(locked(&FORWARDS).waiting.remove(&id));
        }
        sent
    }
}

/// The peer asks: its request to our owners, the answer back later.
fn peer_asks(id: u64, body: &[u8]) {
    if body == QUERY_TAKEOVER {
        let last = pair::current();
        let mut q = locked(&RAW_REPLIES);
        if q.len() < MAX_FORWARDS
            && let Ok(b) = serde_json::to_vec(&last)
        {
            q.push((id, b));
        }
        return;
    }
    let reply = move |o: CoaOutcome| locked(&PEER_REPLIES).push((id, o));
    match serde_json::from_slice::<CoaRequest>(body) {
        Ok(req) => match locked(&AAA).clone() {
            Some(aaa) => aaa.peer_coa(req, Box::new(reply)),
            None => reply(CoaOutcome::NotMine),
        },
        // RFC 5176 §3.5 404 Invalid Request.
        Err(_) => reply(CoaOutcome::Nak(404)),
    }
}

/// The peer answered our request `id`.
fn peer_answers(id: u64, body: &[u8]) {
    if id != 0 && QUERY_ID.load(Ordering::Acquire) == id {
        if let Ok(Some(t)) = serde_json::from_slice::<Option<Takeover>>(body) {
            *locked(&PEER_TAKEOVER) = Some(t);
        }
        return;
    }
    let done = locked(&FORWARDS).waiting.remove(&id);
    if let Some((_, done)) = done {
        done(serde_json::from_slice::<CoaOutcome>(body).ok());
    }
}

/// Answers for the peer onto the link, and forwards never answered out
/// of the table.
fn forward_turn(rt: &Runtime) {
    let raw = std::mem::take(&mut *locked(&RAW_REPLIES));
    if !raw.is_empty()
        && let Some(p) = rt.pair().as_mut()
    {
        for (id, b) in raw {
            p.node.forward_reply(id, b);
        }
    }
    let replies = std::mem::take(&mut *locked(&PEER_REPLIES));
    if !replies.is_empty()
        && let Some(p) = rt.pair().as_mut()
    {
        for (id, o) in replies {
            if let Ok(b) = serde_json::to_vec(&o) {
                p.node.forward_reply(id, b);
            }
        }
    }
    let now = rt.now();
    let old: Vec<super::radius_aaa::CoaDone> = {
        let mut f = locked(&FORWARDS);
        let ids: Vec<u64> = f
            .waiting
            .iter()
            .filter(|(_, (at, _))| now.saturating_sub(*at) > FORWARD_FORGET_MS)
            .map(|(id, _)| *id)
            .collect();
        ids.iter().filter_map(|id| f.waiting.remove(id)).map(|(_, d)| d).collect()
    };
    for d in old {
        d(None);
    }
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
    /// Finished takeovers by this node, oldest first (the one under way
    /// is `pair::TRACK`).
    takeovers: VecDeque<Takeover>,
    /// The BFD of [sync, access]: peer and profile.
    bfd: [Option<(std::net::IpAddr, String)>; 2],
    test: Option<RunningTest>,
    /// Alerts already logged (each once until it clears).
    alerted: Vec<String>,
}

/// A takeover test from this node and how to tell its result.
struct RunningTest {
    report: TakeoverTest,
    /// Our epoch when it began: the peer's takeover has a higher one.
    epoch: u64,
    deadline: u64,
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

    fn test_takeover(&self, method: &str, secs: u32, run: bool, force: bool) -> Result<TakeoverTest, String> {
        let now = self.0.now();
        let mut g = self.0.pair();
        let p = g.as_mut().ok_or("redundancy is not enabled")?;
        let checks = test_checks(p, now);
        let ok = checks.iter().all(|c| c.ok);
        let mut report = TakeoverTest {
            started: unix_now(),
            method: method.into(),
            state: "checked".into(),
            checks,
            note: String::new(),
        };
        if !run {
            report.note = if ok {
                "every check passed: run it with confirm=takeover in a maintenance window".into()
            } else {
                "a check failed: fix it first (force=yes runs anyway)".into()
            };
            return Ok(report);
        }
        if !ok && !force {
            report.state = "refused".into();
            report.note = "a check failed: nothing was changed (force=yes runs anyway)".into();
            return Ok(report);
        }
        let epoch = p.node.ha().epoch();
        match method {
            "switchover" => p.node.switchover(now, force).map_err(|r| r.as_str().to_owned())?,
            _ => p
                .node
                .simulate_failure(now, u64::from(secs) * 1000)
                .map_err(|r| r.as_str().to_owned())?,
        }
        *locked(&PEER_TAKEOVER) = None;
        report.state = "running".into();
        report.note = if method == "switchover" {
            "this node handed the role over; the peer's timeline appears here once it is active".into()
        } else {
            format!(
                "this node went silent for {secs} s (no answers, no hellos, no BFD): the peer must detect it as a crash and take over; the result appears here"
            )
        };
        p.test = Some(RunningTest {
            report: report.clone(),
            epoch,
            deadline: now + u64::from(secs) * 1000 + 30_000,
        });
        Ok(report)
    }
}

/// What must hold before a takeover test (`ppp.redundancy.test-takeover`).
fn test_checks(p: &Pair, now: u64) -> Vec<TestCheck> {
    let s = p.node.status(now);
    let r = &s.role;
    let c = |name: &str, ok: bool, detail: String| TestCheck {
        name: name.into(),
        ok,
        detail,
    };
    let peer = r.peer;
    let mut v = vec![
        c("role", r.role == Role::Active, format!("this node is {}", r.role.as_str())),
        c(
            "peer",
            peer.is_some_and(|v| v.role == Role::Standby),
            match peer {
                Some(v) => format!("the peer is {}", v.role.as_str()),
                None => "the peer is not heard".into(),
            },
        ),
        c(
            "paths",
            r.paths[0] && (r.paths[1] || !p.cfg.fencing.uses_access()),
            format!(
                "sync link {}, access hello {}",
                if r.paths[0] { "heard" } else { "silent" },
                if r.paths[1] { "heard" } else if p.cfg.fencing.uses_access() { "silent" } else { "not used" }
            ),
        ),
    ];
    if p.cfg.mode == corerouter_model::ppp_redundancy::HaMode::HotStandby {
        let synced = peer.is_some_and(|v| v.in_sync);
        v.push(c(
            "in-sync",
            synced,
            if synced {
                format!("the peer holds all {} sessions", s.publisher.as_ref().map_or(0, |x| x.sessions))
            } else {
                "the peer's replica is not complete: sessions not synced would redial".into()
            },
        ));
    }
    if p.cfg.fencing.uses_witness() {
        let pw = peer.is_some_and(|v| v.witness);
        v.push(c(
            "witness",
            pw,
            if pw {
                "the peer reaches the witness (it needs it to take over)".into()
            } else {
                "the peer does not reach the witness: it would not take over".into()
            },
        ));
    }
    let snap = pair::bfd_snapshot();
    for (i, path) in ["sync", "access"].into_iter().enumerate() {
        if let Some(Some((addr, prof))) = p.bfd.get(i) {
            let st = snap.iter().find(|x| x.peer == Some(*addr)).map_or("none", |x| x.state.as_str());
            let damped = r.bfd.get(i).is_some_and(|b| b.suppressed);
            v.push(c(
                &format!("bfd-{path}"),
                st == "up" && !damped,
                format!(
                    "BFD {prof} to {addr}: {st}{}",
                    if damped { ", damped (the dead interval would decide)" } else { "" }
                ),
            ));
        }
    }
    if p.bfd.iter().all(Option::is_none) {
        v.push(c(
            "bfd",
            true,
            format!("no BFD: the peer detects the failure by the dead interval ({} ms)", p.cfg.dead_interval),
        ));
    }
    v.push(c(
        "drift",
        s.drift.is_empty(),
        if s.drift.is_empty() { "the pair's config matches".into() } else { format!("differs: {}", s.drift.join(", ")) },
    ));
    v
}

/// A test under way: the peer's takeover with a higher epoch is its
/// result; none by the deadline is a failure.
fn test_turn(p: &mut Pair, now: u64) {
    let Some(t) = p.test.as_mut() else {
        return;
    };
    if t.report.state != "running" {
        return;
    }
    let peer = locked(&PEER_TAKEOVER).clone();
    if let Some(k) = peer.filter(|k| k.epoch > t.epoch) {
        let ms = |v: Option<u64>| v.map_or("-".to_owned(), |x| format!("{x} ms"));
        let pass = k.lost == 0 && k.skipped == 0;
        t.report.state = if pass { "passed" } else { "failed" }.into();
        t.report.note = format!(
            "the peer took over: detected by {} at {}, active at {}, sessions adopted at {}; {} kept, {} lost",
            k.detected_by,
            ms(k.detected_ms),
            ms(k.active_ms),
            ms(k.adopted_ms),
            k.adopted,
            k.lost
        );
    } else if now > t.deadline {
        t.report.state = "failed".into();
        t.report.note = "the peer did not report a takeover in time: check its monitor and log".into();
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
        bfd: bfd_paths(p, &r.bfd),
        confirming: r.confirming,
        witness_age_ms: match WITNESS_AT.load(Ordering::Acquire) {
            0 => None,
            at => Some(now.saturating_sub(at)),
        },
        takeovers: pair::current()
            .into_iter()
            .chain(p.takeovers.iter().rev().cloned())
            .collect(),
        peer_takeover: locked(&PEER_TAKEOVER).clone(),
        alerts: pair::alerts(&bfd_paths(p, &r.bfd)),
        test: p.test.as_ref().map(|t| t.report.clone()),
    }
}

fn bfd_paths(p: &Pair, ha: &[corerouter_proto_ha::role::BfdPathStatus; 2]) -> Vec<corerouter_model::ppp_redundancy::PathBfdStatus> {
    let snap = pair::bfd_snapshot();
    ["sync", "access"]
        .into_iter()
        .zip(p.bfd.iter())
        .zip(ha.iter())
        .filter_map(|((name, b), h)| {
            b.as_ref()
                .map(|(addr, prof)| pair::path_status(name, Some(*addr), prof, h, &snap))
        })
        .collect()
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

fn node_config(
    r: &Redundancy,
    id: u64,
    sections: Vec<corerouter_proto_ha::msg::Section>,
    bfd_damp: Option<BfdDamp>,
) -> NodeConfig {
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
            bfd_damp,
        },
        sync: SyncConfig::default(),
        hello_key: hello::derive("hello", r.secret.as_bytes()),
        link_key: hello::derive("link", r.secret.as_bytes()),
        sections,
    }
}

/// A worker waits for the pair's lock only past this many changes
/// queued (memory bound); below, a busy lock leaves them for its next
/// round.
pub(crate) const PUBLISH_WAIT: usize = 65_536;

/// The `pppoe` workers' changes (hot standby): into the publisher, while
/// this node is the active one (elsewhere `Node` ignores them). The pair's
/// lock may be busy for milliseconds (the sync thread encoding a snapshot
/// into the link): then the changes come back, and the worker goes on
/// serving its subscribers and hands them again next round.
pub(crate) fn publish(
    changes: Vec<super::pppoe_bng::ha::HaChange>,
) -> Option<Vec<super::pppoe_bng::ha::HaChange>> {
    use super::pppoe_bng::ha::HaChange;
    let rt = runtime();
    let now = rt.now();
    let mut g = if changes.len() >= PUBLISH_WAIT {
        rt.pair()
    } else {
        match rt.pair.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Some(changes),
        }
    };
    let p = g.as_mut()?;
    for c in changes {
        match c {
            HaChange::Up(k, v) => p.node.upsert(now, k, v),
            HaChange::Gone(k) => p.node.remove(now, k),
            HaChange::Counters(k, c) => p.node.counters(now, k, c),
        }
    }
    None
}

/// This node takes the role: the replica's sessions for the `pppoe`
/// workers to adopt (stateful), or none (they redial). Before the workers
/// may answer: a frame of a session not adopted yet would get a PADT.
fn hand_takeover(p: &Pair, t: &Transition) -> u64 {
    use super::pppoe_bng::ha::{TAKEOVER, TAKEOVER_GEN};
    let records = t.stateful.then(|| {
        p.node
            .publisher()
            .map(|pb| decode_all(pb.iter().map(|(_, v, c)| (v, c)).collect()))
            .unwrap_or_default()
    });
    let handed = records.as_ref().map_or(0, |r| r.len() as u64);
    *TAKEOVER.lock().unwrap_or_else(PoisonError::into_inner) = records.map(Arc::new);
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
    handed
}

/// G4.3hh: the replica's records decoded on several threads: 100 000 in one
/// were ≈ 10 ms here and more in the lab's VM, before any worker could
/// start adopting. Records below [`DECODE_SPLIT`] stay on this thread.
fn decode_all(
    raw: Vec<(&[u8], corerouter_proto_ha::msg::Counters)>,
) -> Vec<corerouter_proto_ha::record::SessionRecord> {
    use corerouter_proto_ha::record::SessionRecord;
    let one = |part: &[(&[u8], corerouter_proto_ha::msg::Counters)]| -> Vec<SessionRecord> {
        part.iter()
            .filter_map(|(v, c)| {
                SessionRecord::decode(v).ok().map(|mut r| {
                    r.counters = *c;
                    r
                })
            })
            .collect()
    };
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get).min(8);
    if raw.len() < DECODE_SPLIT || threads < 2 {
        return one(&raw);
    }
    let size = raw.len().div_ceil(threads);
    std::thread::scope(|s| {
        let parts: Vec<_> = raw
            .chunks(size)
            .map(|part| {
                std::thread::Builder::new()
                    .name("ppp-ha-decode".into())
                    .spawn_scoped(s, move || one(part))
            })
            .collect();
        let mut out = Vec::with_capacity(raw.len());
        for (part, h) in raw.chunks(size).zip(parts) {
            // A thread that could not start: this one decodes its part.
            match h.map(|h| h.join()) {
                Ok(Ok(v)) => out.extend(v),
                _ => out.extend(one(part)),
            }
        }
        out
    })
}

/// Below this many records the decode stays on one thread.
const DECODE_SPLIT: usize = 8192;

/// A takeover begins: its timeline (the one before it goes to the list).
fn begin_takeover(p: &mut Pair, t: &Transition, handed: u64, now: u64) {
    let peer_sessions = u64::from(p.node.status(now).peer_sessions);
    if let Some(old) = pair::begin(t, handed, if t.stateful { peer_sessions } else { 0 }, false) {
        if p.takeovers.len() >= TAKEOVERS {
            p.takeovers.pop_front();
        }
        p.takeovers.push_back(old.takeover);
    }
}

/// The `bfd` service's state for the pair, and its changes, into the role
/// machine (no session lock).
fn bfd_turn(p: &mut Pair, now: u64) {
    let events = pair::take_bfd_events();
    if events.is_empty() {
        return;
    }
    let snap = pair::bfd_snapshot();
    for e in events {
        let detect = snap
            .iter()
            .find(|s| s.peer == Some(e.peer))
            .map_or(0, |s| s.detect_time_us / 1000);
        for (i, path) in [Path::Sync, Path::Access].into_iter().enumerate() {
            if p.bfd.get(i).and_then(Option::as_ref).is_some_and(|(a, _)| *a == e.peer) {
                p.node.bfd(now, path, e.up, e.expired, detect);
            }
        }
    }
}

/// Once a second: BFD paths that came or went, and a session already up
/// (the role machine was rebuilt, or the service started first).
fn bfd_sync(p: &mut Pair, now: u64) {
    let snap = pair::bfd_snapshot();
    for (i, path) in [Path::Sync, Path::Access].into_iter().enumerate() {
        let st = p.node.ha().bfd_state(path);
        match p.bfd.get(i).and_then(Option::as_ref) {
            None if st.configured => p.node.bfd_off(now, path),
            None => {}
            Some((addr, _)) => {
                let up = snap.iter().any(|s| s.peer == Some(*addr) && s.state == "up");
                if up && !st.up {
                    p.node.bfd(now, path, true, false, 0);
                }
            }
        }
    }
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
        let mut next_query = 0u64;
        loop {
            health.beat();
            flush_logs(session);
            // The config once a second, when the engine's lock is free (a
            // busy engine delays it, never the hellos below).
            let guard_now = if Instant::now() >= next_cfg { try_session(session) } else { None };
            if let Some(s) = guard_now {
                next_cfg = Instant::now() + Duration::from_secs(1);
                let (r, secs, pppoe_ifs, damp) = {
                    let cfg = s.store().running();
                    let r0 = &cfg.ppp.redundancy;
                    let prof = if r0.bfd.is_empty() { &r0.access_bfd } else { &r0.bfd };
                    let damp = cfg.routing.bfd.profile(prof).and_then(|p| {
                        let d = p.dampening;
                        d.enabled.then(|| BfdDamp {
                            half_life_ms: u64::from(d.half_life.max(1)) * 1000,
                            penalty: 1000,
                            suppress: d.suppress,
                            reuse: d.reuse,
                            max_suppress_ms: u64::from(d.max_suppress) * 1000,
                        })
                    });
                    let ifs: Vec<IfName> = cfg
                        .ppp
                        .pppoe_servers
                        .iter()
                        .filter(|x| !x.disabled)
                        .map(|x| x.interface.clone())
                        .collect();
                    (cfg.ppp.redundancy.clone(), sections(cfg), ifs, damp)
                };
                let bfd_want = pair::wanted(&r);
                pair::set_peers(bfd_want.iter().flatten().map(|(a, _)| *a).collect());
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
                // BFD's knobs change in place: a rebuilt role machine
                // starts over in init and would stop answering.
                let no_bfd = |x: &Redundancy| Redundancy {
                    bfd: String::new(),
                    access_bfd: String::new(),
                    access_peer: None,
                    ..x.clone()
                };
                let rebuild = rt
                    .pair()
                    .as_ref()
                    .is_none_or(|p| no_bfd(&p.cfg) != no_bfd(&r) || p.sections != secs);
                if rebuild {
                    let fp = dir
                        .and_then(|d| std::fs::read_to_string(d.join(PIN_FILE)).ok())
                        .map(|s| s.trim().to_owned())
                        .unwrap_or_default();
                    *rt.pair() = Some(Pair {
                        node: Node::new(node_config(&r, our_id, secs.clone(), damp), rt.now()),
                        cfg: r.clone(),
                        sections: secs,
                        history: VecDeque::new(),
                        last_error: None,
                        conn: CONNS.fetch_add(1, Ordering::AcqRel) + 1,
                        peer_fingerprint: fp,
                        takeovers: VecDeque::new(),
                        bfd: bfd_want.clone(),
                        test: None,
                        alerted: Vec::new(),
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
                {
                    let now = rt.now();
                    let mut g = rt.pair();
                    if let Some(p) = g.as_mut() {
                        p.cfg = r.clone();
                        p.bfd = bfd_want;
                        p.node.set_bfd_damp(damp);
                        bfd_sync(p, now);
                        let st = status_of(p, now);
                        let fresh: Vec<String> =
                            st.alerts.iter().filter(|a| !p.alerted.contains(a)).cloned().collect();
                        p.alerted = st.alerts;
                        drop(g);
                        for a in fresh {
                            log(session, "warning", format!("ppp redundancy: {a}"), json!({}));
                        }
                    }
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
                    bfd_turn(p, now);
                    match WITNESS_AT.load(Ordering::Acquire) {
                        0 => {}
                        at => p.node.witness_answer(now, at),
                    }
                    p.node.witness(now, witness_ok);
                    p.node.track(now, track_ok);
                    p.node.tick(now);
                    if p.node.wants_witness_probe() {
                        WITNESS_URGENT.store(true, Ordering::Release);
                    }
                    pair::set_silent(p.node.ha().silent());
                    test_turn(p, now);
                    if now >= next_query {
                        next_query = now + 2000;
                        if p.node.can_forward() {
                            let id = {
                                let mut f = locked(&FORWARDS);
                                f.next += 1;
                                f.next
                            };
                            QUERY_ID.store(id, Ordering::Release);
                            p.node.forward(id, QUERY_TAKEOVER.to_vec());
                        }
                    }
                    p.node.take_access(&mut access_out);
                    p.node.take_events(&mut events);
                    for e in &events {
                        if let Event::Role(t) = e {
                            record(p, t);
                            if t.to == Role::Active {
                                let handed = hand_takeover(p, t);
                                begin_takeover(p, t, handed, now);
                            }
                        }
                    }
                    shared().answering.store(p.node.answering(), Ordering::Release);
                    super::super::pppoe_bng::HA_ACTIVE.store(p.node.answering(), Ordering::Release);
                }
            }
            if access_out.iter().any(|(_, v)| *v) && !ports.is_empty() {
                pair::announced(rt.now());
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
                    Event::Forward { id, body } => super::peer_asks(id, &body),
                    Event::ForwardReply { id, body } => super::peer_answers(id, &body),
                }
            }
            super::forward_turn(rt);
            pair::wait(TICK);
            if health.stopping() {
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
            // A probe asked for (BFD found the peer silent): answers in
            // an RTT, so the wait is short.
            let urgent = WITNESS_URGENT.swap(false, Ordering::AcqRel);
            let wait = Duration::from_millis(if urgent { 200 } else { 500 });
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
                    let until = Instant::now() + wait;
                    while let Some(left) = until.checked_duration_since(Instant::now()) {
                        match sock.recv(left) {
                            Ok(Some(r)) if r.seq == seq && r.kind == ReplyKind::Echo => {
                                ok = true;
                                WITNESS_AT.store(runtime().now().max(1), Ordering::Release);
                                if urgent {
                                    pair::wake();
                                }
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
            // An urgent probe that failed is not a miss of the debounce
            // (the regular one decides that).
            if !urgent || ok {
                misses = if ok { 0 } else { misses.saturating_add(1) };
            }
            WITNESS.store(misses < 3, Ordering::Release);
            // Sleep the rest of the second, in steps that see an urgent
            // probe within 5 ms.
            while started.elapsed() < Duration::from_secs(1) && !WITNESS_URGENT.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
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

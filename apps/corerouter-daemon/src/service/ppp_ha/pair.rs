//! G3.6h: BFD on the pair's two paths, the timeline of each takeover, the
//! takeover test and the early warnings. Everything another thread hands
//! in is queued or atomic: the role machine never waits for the session
//! lock, the `bfd` service loop or a `pppoe` worker.
//!
//! - **BFD in:** the `bfd` engine's threads call [`tap`] on every state
//!   change (a fn pointer in its `Options`): a pair peer's change goes into
//!   [`BFD_EVENTS`] and the `ppp-ha` loop hands it to the role machine on
//!   its next 10 ms turn. Detection to decision: the BFD detection time
//!   plus at most one turn.
//! - **BFD status:** the `bfd` service publishes its sessions every 500 ms
//!   ([`publish_bfd`]); the monitor shows the pair's and the alerts read
//!   their jitter.
//! - **Silent:** a simulated failure (and so the failure test) stops the
//!   pair's BFD sessions too ([`silent`]), so the peer sees a crash.
//! - **Timeline:** the takeover in progress lives in [`TRACK`]; the workers
//!   report their adoption ([`adopted`]) and the first subscriber frame
//!   ([`frame_seen`]: one relaxed load per frame otherwise).

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use corerouter_model::bfd::{BfdKey, BfdSessionStatus};
use corerouter_model::ppp_redundancy::{PathBfdStatus, Redundancy, Takeover};
use corerouter_proto_bfd::packet::{Diag, State};
use corerouter_proto_ha::role::{BfdPathStatus, Transition};

use super::{locked, runtime, unix_now};

/// A pair peer's BFD session changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BfdIn {
    pub peer: IpAddr,
    pub up: bool,
    /// Down because the peer's packets stopped (RFC 5880 diagnostic 1).
    pub expired: bool,
}

const BFD_QUEUE: usize = 256;
/// Wakes the `ppp-ha` loop before its 10 ms tick: a BFD change or a
/// witness answer decides a takeover (8 ms of a 160 ms one, **medido**).
static WAKE: Mutex<bool> = Mutex::new(false);
static WAKE_CV: Condvar = Condvar::new();

pub(crate) fn wake() {
    *locked(&WAKE) = true;
    WAKE_CV.notify_one();
}

/// The loop's sleep: `d`, or less when [`wake`] is called.
pub(crate) fn wait(d: Duration) {
    let g = locked(&WAKE);
    let (mut g, _) = WAKE_CV
        .wait_timeout_while(g, d, |woken| !*woken)
        .unwrap_or_else(PoisonError::into_inner);
    *g = false;
}
static BFD_EVENTS: Mutex<VecDeque<BfdIn>> = Mutex::new(VecDeque::new());
/// The addresses the pair runs BFD to (`Redundancy::bfd_sessions`).
static PEERS: Mutex<Vec<IpAddr>> = Mutex::new(Vec::new());
static ANY_PEER: AtomicBool = AtomicBool::new(false);
static BFD_SNAP: Mutex<Vec<BfdSessionStatus>> = Mutex::new(Vec::new());
/// A simulated failure: the pair's BFD sessions stop.
static SILENT: AtomicBool = AtomicBool::new(false);

/// The `bfd` engine's tap (its threads): queues a pair peer's change.
pub(crate) fn tap(key: &BfdKey, _from: State, to: State, diag: Diag) {
    if !ANY_PEER.load(Ordering::Acquire) || key.multihop || !locked(&PEERS).contains(&key.peer) {
        return;
    }
    let mut q = locked(&BFD_EVENTS);
    if q.len() < BFD_QUEUE {
        q.push_back(BfdIn {
            peer: key.peer,
            up: to == State::Up,
            expired: to == State::Down && diag == Diag::ControlDetectionTimeExpired,
        });
    }
    drop(q);
    wake();
}

pub(crate) fn take_bfd_events() -> Vec<BfdIn> {
    locked(&BFD_EVENTS).drain(..).collect()
}

pub(crate) fn set_peers(peers: Vec<IpAddr>) {
    ANY_PEER.store(!peers.is_empty(), Ordering::Release);
    *locked(&PEERS) = peers;
}

/// The `bfd` service's sessions (every 500 ms): the pair's are kept.
pub(crate) fn publish_bfd(all: &[BfdSessionStatus]) {
    if !ANY_PEER.load(Ordering::Acquire) {
        if !locked(&BFD_SNAP).is_empty() {
            locked(&BFD_SNAP).clear();
        }
        return;
    }
    let peers = locked(&PEERS).clone();
    let mine: Vec<BfdSessionStatus> = all
        .iter()
        .filter(|s| !s.multihop && s.peer.is_some_and(|p| peers.contains(&p)))
        .cloned()
        .collect();
    *locked(&BFD_SNAP) = mine;
}

pub(crate) fn bfd_snapshot() -> Vec<BfdSessionStatus> {
    locked(&BFD_SNAP).clone()
}

/// The pair's BFD sessions must not run now (a simulated failure).
pub(crate) fn silent() -> bool {
    SILENT.load(Ordering::Acquire)
}

pub(crate) fn set_silent(on: bool) {
    SILENT.store(on, Ordering::Release);
}

/// The monitor's view of a path: the role machine's (damping) and the
/// `bfd` service's (state, jitter).
pub(crate) fn path_status(
    path: &str,
    peer: Option<IpAddr>,
    profile: &str,
    ha: &BfdPathStatus,
    snap: &[BfdSessionStatus],
) -> PathBfdStatus {
    let s = peer.and_then(|p| snap.iter().find(|s| s.peer == Some(p)));
    PathBfdStatus {
        path: path.into(),
        peer,
        profile: profile.into(),
        state: s.map_or_else(|| "none".to_owned(), |s| s.state.clone()),
        detect_ms: s.map_or(0, |s| s.detect_time_us / 1000),
        rx_gap_p99_us: s.and_then(|s| s.rx_gap_p99_us),
        tx_jitter_p99_us: s.and_then(|s| s.tx_jitter_p99_us),
        suppressed: ha.suppressed,
        penalty: ha.penalty,
        losses: ha.losses,
        false_alarms: ha.false_alarms,
    }
}

/// Early warnings, in plain words: a path's BFD whose packets arrive with
/// gaps close to the detection time (losses: the link degrades and a
/// false takeover is near), BFD sent late by this node (CPU), a damped
/// path.
pub(crate) fn alerts(paths: &[PathBfdStatus]) -> Vec<String> {
    let mut out = Vec::new();
    for p in paths {
        let detect_us = p.detect_ms.saturating_mul(1000);
        if p.state == "up" && detect_us > 0 {
            // Two of the three packets of the detection time missing at
            // p99: one more loss in a row and the session expires.
            if let Some(g) = p.rx_gap_p99_us
                && g.saturating_mul(3) >= detect_us.saturating_mul(2)
            {
                out.push(format!(
                    "BFD on the {} path: p99 gap between the peer's packets {:.0} ms of a {} ms detection time; the link is losing packets and a takeover nobody needs is close",
                    p.path,
                    g as f64 / 1000.0,
                    p.detect_ms
                ));
            }
            if let Some(j) = p.tx_jitter_p99_us
                && j.saturating_mul(3) >= detect_us
            {
                out.push(format!(
                    "BFD on the {} path: this node sends {:.0} ms late at p99 (CPU load); the peer may see it dead",
                    p.path,
                    j as f64 / 1000.0
                ));
            }
        }
        if p.suppressed {
            out.push(format!(
                "BFD on the {} path is damped after {} losses ({} false alarms): the takeover waits for the hellos' dead interval until it is stable",
                p.path, p.losses, p.false_alarms
            ));
        }
    }
    out
}

// ---- The takeover timeline ------------------------------------------------------

/// The takeover in progress (the workers fill in their part).
#[derive(Debug, Clone, Default)]
pub(crate) struct Track {
    /// The time milestones count from (ms on `runtime().now()`).
    pub base: u64,
    pub takeover: Takeover,
    /// The peer's last session count: what it held when it went silent.
    pub peer_sessions: u64,
}

pub(crate) static TRACK: Mutex<Option<Track>> = Mutex::new(None);
static AWAIT_FRAME: AtomicBool = AtomicBool::new(false);

/// A takeover begins: its first milestones, from the role machine.
pub(crate) fn begin(t: &Transition, handed: u64, peer_sessions: u64, test: bool) -> Option<Track> {
    let base = t.detection.map_or(t.at, |d| d.last_heard);
    let ms = |at: u64| Some(at.saturating_sub(base));
    let detected_by = match t.detection {
        Some(d) if d.by_bfd() => {
            let paths: Vec<&str> = [("sync", d.bfd[0]), ("access", d.bfd[1])]
                .into_iter()
                .filter(|(_, b)| *b)
                .map(|(p, _)| p)
                .collect();
            format!("bfd ({})", paths.join(", "))
        }
        Some(_) => "dead-interval".to_owned(),
        None => t.reason.as_str().to_owned(),
    };
    let tk = Takeover {
        at: unix_now(),
        reason: t.reason.as_str().into(),
        epoch: t.epoch,
        detected_by,
        detected_ms: t.detection.and_then(|d| ms(d.detected)),
        witness_ms: t.detection.and_then(|d| d.witness_at).and_then(ms),
        active_ms: ms(t.at),
        // `hand_takeover` decoded the replica just before.
        handed_ms: ms(runtime().now()),
        stateful: t.stateful,
        handed,
        lost: peer_sessions.saturating_sub(handed),
        test,
        ..Takeover::default()
    };
    AWAIT_FRAME.store(true, Ordering::Release);
    locked(&TRACK).replace(Track {
        base,
        takeover: tk,
        peer_sessions,
    })
}

/// A worker adopted its part of the takeover (`pppoe` lane or IPoE).
pub(crate) fn adopted(sessions: usize, skipped: usize) {
    let now = runtime().now();
    if let Some(t) = locked(&TRACK).as_mut() {
        let k = &mut t.takeover;
        k.adopted += sessions as u64;
        k.skipped += skipped as u64;
        k.adopted_ms = Some(now.saturating_sub(t.base));
        k.lost = t.peer_sessions.max(k.handed).saturating_sub(k.adopted);
    }
}

/// G4.3hh: a worker answers (its share of the takeover indexed, the first
/// chunk adopted).
pub(crate) fn answering() {
    let now = runtime().now();
    if let Some(t) = locked(&TRACK).as_mut() {
        t.takeover.answering_ms = Some(now.saturating_sub(t.base));
    }
}

/// G4.3hh: a worker's routes of the takeover are in the kernel (slow
/// path): `done` taken, `refused` still refused after the second try.
pub(crate) fn routes_installed(done: usize, refused: usize) {
    let now = runtime().now();
    if let Some(t) = locked(&TRACK).as_mut() {
        let k = &mut t.takeover;
        k.routes += done as u64;
        k.routes_refused += refused as u64;
        k.routes_ms = Some(now.saturating_sub(t.base));
    }
}

/// A subscriber frame reached a worker that serves (the first after a
/// takeover is the timeline's last milestone).
pub(crate) fn frame_seen() {
    if AWAIT_FRAME.load(Ordering::Relaxed) && AWAIT_FRAME.swap(false, Ordering::AcqRel) {
        let now = runtime().now();
        if let Some(t) = locked(&TRACK).as_mut() {
            t.takeover.first_frame_ms = Some(now.saturating_sub(t.base));
        }
    }
}

/// The virtual MAC went out (the active's first access hello).
pub(crate) fn announced(now: u64) {
    if let Some(t) = locked(&TRACK).as_mut()
        && t.takeover.announced_ms.is_none()
    {
        t.takeover.announced_ms = Some(now.saturating_sub(t.base));
    }
}

pub(crate) fn current() -> Option<Takeover> {
    locked(&TRACK).as_ref().map(|t| t.takeover.clone())
}

/// What the pair's BFD needs: `(peer, profile)` of [sync, access].
pub(crate) fn wanted(r: &Redundancy) -> [Option<(IpAddr, String)>; 2] {
    let mut out = [None, None];
    for (peer, prof, path) in r.bfd_sessions() {
        let i = usize::from(path == "access");
        if let Some(slot) = out.get_mut(i) {
            *slot = Some((peer, prof.to_owned()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(state: &str, gap_ms: u64) -> PathBfdStatus {
        PathBfdStatus {
            path: "sync".into(),
            state: state.into(),
            detect_ms: 150,
            rx_gap_p99_us: Some(gap_ms * 1000),
            tx_jitter_p99_us: Some(1000),
            ..PathBfdStatus::default()
        }
    }

    #[test]
    fn jitter_close_to_the_detection_time_warns_before_the_link_fails() {
        assert!(alerts(&[path("up", 60)]).is_empty(), "one packet late is normal");
        let a = alerts(&[path("up", 100)]);
        assert!(a.len() == 1 && a[0].contains("p99 gap") && a[0].contains("150 ms"), "{a:?}");
        assert!(alerts(&[path("down", 140)]).is_empty(), "a down session says so itself");
        let mut d = path("up", 10);
        d.suppressed = true;
        d.losses = 3;
        assert!(alerts(&[d])[0].contains("damped"));
    }

    #[test]
    fn the_tap_queues_only_the_pairs_peers_and_flags_expiry() {
        set_peers(vec!["192.0.2.2".parse().unwrap()]);
        let key = |a: &str| BfdKey {
            peer: a.parse().unwrap(),
            multihop: false,
            local: None,
        };
        let _ = take_bfd_events();
        tap(&key("192.0.2.9"), State::Up, State::Down, Diag::ControlDetectionTimeExpired);
        tap(&key("192.0.2.2"), State::Up, State::Down, Diag::NeighborSignaledDown);
        tap(&key("192.0.2.2"), State::Init, State::Up, Diag::None);
        tap(&key("192.0.2.2"), State::Up, State::Down, Diag::ControlDetectionTimeExpired);
        let ev = take_bfd_events();
        assert_eq!(ev.iter().map(|e| (e.up, e.expired)).collect::<Vec<_>>(), [(false, false), (true, false), (false, true)]);
        set_peers(Vec::new());
    }
}

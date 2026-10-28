//! BFD (G3.6): CoreRouter's own BFD engine (`corerouter_proto_bfd`, RFC
//! 5880/5881/5883), not FRR's `bfdd`. This file is the controller: every
//! second it turns the running config (`routing.bfd`) into the sessions
//! the engine runs, and it moves state changes into the history and the
//! log; every 500 ms it copies the engine's snapshots into
//! `ext::<BfdState>` (`routing.bfd.session.list`). The session lock is
//! taken only for those copies, never around I/O.
//!
//! The engine (`bfd/engine.rs`) runs on `--bfd-threads` named threads
//! (`bfd-0`…), sessions split by discriminator, each thread with its own
//! sockets and timer wheel; `bfd/sock.rs` has the Linux sockets. It starts
//! with the first session and stops with the last, so nothing listens on
//! 3784/4784 while BFD is unused. Design and numbers: `docs/bfd.md`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_model::bfd::{
    BfdAuth, BfdConfig, BfdEvent, BfdKey, BfdProfile, BfdState, MAX_HISTORY, wanted_sessions,
};
use corerouter_model::service::Listen;
use corerouter_proto_bfd::auth::AuthConfig;
use corerouter_proto_bfd::dampen::DampConfig;
use corerouter_proto_bfd::packet::State;
use corerouter_proto_bfd::session::Config;

#[cfg(target_os = "linux")]
#[path = "bfd/engine.rs"]
mod engine;
#[cfg(target_os = "linux")]
#[path = "bfd/sock.rs"]
mod sock;
#[cfg(all(test, target_os = "linux"))]
#[path = "bfd/tests.rs"]
mod tests;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "bfd",
    flags: &[super::Flag {
        name: "--bfd-threads",
        value: Some("<n>|auto"),
        help: "BFD engine threads (sessions split by discriminator); auto: see docs/bfd.md",
    }],
    topic: "route",
    enable: "routing.bfd.peer.add",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_millis(100);
const CONFIG_EVERY: Duration = Duration::from_secs(1);
const PUBLISH_EVERY: Duration = Duration::from_millis(500);

/// `auto`: one thread per this many sessions, up to [`AUTO_MAX`] and the
/// cores (docs/bfd.md: one thread carries 1 000 sessions at 50 ms × 3 at
/// a few % of a core, **medido**; more threads buy headroom, not speed).
const AUTO_PER_THREAD: usize = 500;
const AUTO_MAX: usize = 4;

pub(crate) fn auto_threads(sessions: usize) -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    sessions.div_ceil(AUTO_PER_THREAD).clamp(1, AUTO_MAX.min(cores).max(1))
}

/// The engine settings of one session, from its profile.
pub(crate) fn config_of(p: &BfdProfile) -> Config {
    let auth = match p.auth {
        BfdAuth::None => None,
        BfdAuth::KeyedSha1 => AuthConfig::new(false, p.auth_key_id, p.auth_secret.0.as_bytes()),
        BfdAuth::MeticulousKeyedSha1 => AuthConfig::new(true, p.auth_key_id, p.auth_secret.0.as_bytes()),
    };
    Config {
        desired_min_tx: p.min_tx.saturating_mul(1000),
        required_min_rx: p.min_rx.saturating_mul(1000),
        detect_mult: p.multiplier.max(1),
        auth,
        passive: p.passive,
        admin_down: false,
    }
}

pub(crate) fn damp_of(p: &BfdProfile) -> Option<DampConfig> {
    let d = &p.dampening;
    d.enabled.then(|| DampConfig {
        half_life_us: u64::from(d.half_life.max(1)) * 1_000_000,
        penalty: 1000,
        suppress: d.suppress,
        reuse: d.reuse,
        max_suppress_us: u64::from(d.max_suppress) * 1_000_000,
    })
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let threads = match ctx.flag("--bfd-threads").filter(|v| !v.is_empty() && *v != "auto") {
        None => None,
        Some(v) => Some(
            v.parse::<usize>()
                .ok()
                .filter(|n| (1..=64).contains(n))
                .ok_or_else(|| format!("--bfd-threads {v:?}: 1..=64 or auto"))?,
        ),
    };
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, threads, health);
        Ok(())
    }))
}

#[cfg(not(target_os = "linux"))]
fn run(_session: &Shared, _threads: Option<usize>, health: &super::Health) {
    health.disabled(Some("BFD runs on Linux only"));
    while health.sleep(Duration::from_secs(5)) {
        health.beat();
    }
}

#[cfg(target_os = "linux")]
fn run(session: &Shared, threads: Option<usize>, health: &super::Health) {
    let mut ctl = Controller::default();
    let mut cfg_at: Option<Instant> = None;
    let mut pub_at = Instant::now();
    loop {
        if health.stopping() {
            ctl.stop(session);
            return;
        }
        health.beat();
        // Events first: they wait at most TICK.
        let mut events = Vec::new();
        match &ctl.engine {
            Some(e) => {
                if let Ok(ev) = e.events.recv_timeout(TICK) {
                    events.push(ev);
                    while let Ok(ev) = e.events.try_recv() {
                        events.push(ev);
                    }
                }
            }
            None => {
                if !health.sleep(TICK) {
                    ctl.stop(session);
                    return;
                }
            }
        }
        if !events.is_empty() {
            record(session, &events);
        }
        if cfg_at.is_none_or(|t| t.elapsed() >= CONFIG_EVERY) {
            cfg_at = Some(Instant::now());
            let cfg = lock(session).store().running().routing.bfd.clone();
            // A failed start (port taken) is retried every second.
            if ctl.cfg.as_ref() != Some(&cfg) && ctl.reconcile(&cfg, threads, health) {
                ctl.cfg = Some(cfg);
            }
            match &ctl.engine {
                Some(e) => {
                    health.disabled(None);
                    health.listen(vec![
                        Listen::new("udp", std::net::SocketAddr::from(([0, 0, 0, 0], corerouter_proto_bfd::PORT_SINGLE_HOP))),
                        Listen::new("udp", std::net::SocketAddr::from(([0, 0, 0, 0], corerouter_proto_bfd::PORT_MULTI_HOP))),
                    ]);
                    health.event(format!("{} sessions on {} threads ({})", ctl.sessions.len(), e.threads(), e.steering));
                }
                None => {
                    health.listen(vec![]);
                    health.disabled(Some("no BFD session (routing.bfd.peer.add)"));
                }
            }
        }
        if pub_at.elapsed() >= PUBLISH_EVERY {
            pub_at = Instant::now();
            ctl.publish(session);
        }
    }
}

/// History and log lines for state changes (session lock, no I/O).
#[cfg(target_os = "linux")]
fn record(session: &Shared, events: &[engine::Event]) {
    let mut s = lock(session);
    for e in events {
        let released = e.from == e.to;
        let line = if released {
            format!("BFD {}: dampening released, up for its clients again", e.key.peer)
        } else if e.to == State::Down && e.from == State::Up {
            format!(
                "BFD {} down ({}){}; used by {}",
                e.key.peer,
                e.diag.name(),
                if e.dampened { ", dampened" } else { "" },
                e.users.join(", ")
            )
        } else {
            format!("BFD {}: {} → {}", e.key.peer, e.from.name(), e.to.name())
        };
        let level = if e.to == State::Down && e.from == State::Up { "warning" } else { "info" };
        // Up but held down for the clients (dampened): say so.
        let line = if e.to == State::Up && !e.client_up && !released {
            format!("{line} (dampened: still down for its clients)")
        } else {
            line
        };
        if e.to == State::Up || e.from == State::Up || released {
            s.log_event(&["route", level], corerouter_engine::logging::DAEMON, line, serde_json::Value::Null);
        }
        if let Some(st) = s.ext_mut::<BfdState>() {
            st.history.push_back(BfdEvent {
                at_ms: e.at_ms,
                peer: e.key.peer,
                multihop: e.key.multihop,
                from: if released { "dampened".into() } else { e.from.name().into() },
                to: e.to.name().into(),
                diag: e.diag.name().into(),
                users: e.users.clone(),
                detect_time_us: e.detect_us,
                dampened: e.dampened,
            });
            while st.history.len() > MAX_HISTORY {
                st.history.pop_front();
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Controller {
    cfg: Option<BfdConfig>,
    engine: Option<engine::Engine>,
    sessions: BTreeMap<BfdKey, (u32, engine::Spec)>,
}

#[cfg(target_os = "linux")]
impl Controller {
    /// False when the engine could not start.
    fn reconcile(&mut self, cfg: &BfdConfig, threads: Option<usize>, health: &super::Health) -> bool {
        let wanted: BTreeMap<BfdKey, engine::Spec> = wanted_sessions(cfg)
            .into_iter()
            .map(|(key, (prof, users))| {
                let spec = engine::Spec {
                    key: key.clone(),
                    cfg: config_of(&prof),
                    damp: damp_of(&prof),
                    min_ttl: prof.min_ttl,
                    users,
                    profile: prof.name.clone(),
                };
                (key, spec)
            })
            .collect();
        if wanted.is_empty() {
            self.sessions.clear();
            self.engine = None;
            return true;
        }
        if self.engine.is_none() {
            let opts = engine::Options {
                threads: threads.unwrap_or_else(|| auto_threads(wanted.len())),
                ..engine::Options::default()
            };
            let spawn = |name: String, f: Box<dyn FnOnce() + Send>| health.spawn(&name, f);
            match engine::Engine::start(&opts, &spawn) {
                Ok(e) => self.engine = Some(e),
                Err(e) => {
                    health.error(e.to_string());
                    return false;
                }
            }
            health.clear_error();
        }
        let Some(eng) = self.engine.as_mut() else { return false };
        self.sessions.retain(|key, (discr, _)| {
            let keep = wanted.contains_key(key);
            if !keep {
                eng.remove(*discr, key);
            }
            keep
        });
        for (key, spec) in wanted {
            match self.sessions.get_mut(&key) {
                Some((discr, old)) => {
                    if *old != spec {
                        eng.update(*discr, spec.clone());
                        *old = spec;
                    }
                }
                None => {
                    let discr = eng.add(spec.clone(), None);
                    self.sessions.insert(key, (discr, spec));
                }
            }
        }
        true
    }

    fn publish(&self, session: &Shared) {
        let (sessions, threads, steering) = match &self.engine {
            Some(e) => {
                let (s, t) = e.snapshot();
                (s, t, e.steering)
            }
            None => (Vec::new(), Vec::new(), ""),
        };
        let mut s = lock(session);
        if let Some(st) = s.ext_mut::<BfdState>() {
            st.running = self.engine.is_some();
            st.sessions = sessions;
            st.threads = threads;
            st.steering = steering.to_owned();
        }
    }

    fn stop(&mut self, session: &Shared) {
        self.engine = None;
        self.sessions.clear();
        self.publish(session);
    }
}

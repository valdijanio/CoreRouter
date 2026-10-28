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
#[cfg(target_os = "linux")]
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_model::bfd::{
    BfdAuth, BfdConfig, BfdEvent, BfdKey, BfdProfile, BfdState, MAX_HISTORY, route_sessions, wanted_all,
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
#[cfg(target_os = "linux")]
#[path = "bfd/dplane.rs"]
mod dplane;
#[cfg(all(test, target_os = "linux"))]
#[path = "bfd/tests.rs"]
mod tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "bfd/live_bfdd.rs"]
mod live_bfdd;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "bfd",
    flags: &[
        super::Flag {
            name: "--bfd-threads",
            value: Some("<n>|auto"),
            help: "BFD engine threads (sessions split by discriminator); auto: see docs/bfd.md",
        },
        super::Flag {
            name: "--bfd-dplane",
            value: Some("<socket>|off"),
            help: "bfdd's data plane socket (default with --frr: <frr dir>/bfdd_dplane.sock);\n\
                   off: the engine runs only routing.bfd peers itself",
        },
    ],
    topic: "route",
    enable: "routing.bfd.peer.add",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_millis(100);
const DP_TICK: Duration = Duration::from_millis(20);
/// bfdd's `--dplaneaddr unix:` socket, in FRR's state directory.
pub(crate) const DPLANE_SOCKET: &str = "bfdd_dplane.sock";
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
    // G3.6b: with FRR, bfdd hands its sessions to this engine (its data
    // plane); `--bfd-dplane off` keeps the engine on its own.
    let dp_path = match ctx.flag("--bfd-dplane") {
        Some("off") => None,
        Some(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => ctx
            .flag("--frr")
            .filter(|d| !d.is_empty())
            .map(|d| PathBuf::from(d).join(DPLANE_SOCKET)),
    };
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, threads, dp_path.clone(), health);
        Ok(())
    }))
}

#[cfg(not(target_os = "linux"))]
fn run(_session: &Shared, _threads: Option<usize>, _dp: Option<PathBuf>, health: &super::Health) {
    health.disabled(Some("BFD runs on Linux only"));
    while health.sleep(Duration::from_secs(5)) {
        health.beat();
    }
}

#[cfg(target_os = "linux")]
fn run(session: &Shared, threads: Option<usize>, dp_path: Option<PathBuf>, health: &super::Health) {
    let mut ctl = Controller {
        threads,
        dplane: dp_path.is_some(),
        ..Controller::default()
    };
    let (dp_tx, dp_rx) = std::sync::mpsc::sync_channel(dplane::QUEUE);
    if let Some(path) = dp_path {
        let h = health.clone();
        if let Err(e) = health.spawn("bfd-dplane", move || dplane::run(path, dp_tx, h)) {
            health.error(format!("cannot start the bfdd data plane link: {e}"));
        }
    }
    let mut cfg_at: Option<Instant> = None;
    let mut pub_at = Instant::now();
    let mut pair_silent = false;
    loop {
        if health.stopping() {
            ctl.stop(session);
            return;
        }
        health.beat();
        // Events first: they wait at most TICK (less in data plane mode,
        // where bfdd's messages wait too).
        let wait = if ctl.dplane { DP_TICK } else { TICK };
        let mut events = Vec::new();
        match &ctl.engine {
            Some(e) => {
                if let Ok(ev) = e.events.recv_timeout(wait) {
                    events.push(ev);
                    while let Ok(ev) = e.events.try_recv() {
                        events.push(ev);
                    }
                }
            }
            None => {
                if !health.sleep(wait) {
                    ctl.stop(session);
                    return;
                }
            }
        }
        if !events.is_empty() {
            ctl.tell_bfdd(&events);
            record(session, &events);
        }
        let mut msgs = Vec::new();
        while let Ok(m) = dp_rx.try_recv() {
            msgs.push(m);
        }
        if !msgs.is_empty() {
            let cfg = lock(session).store().running().clone();
            for m in msgs {
                ctl.on_bfdd(m, &cfg, health);
            }
        }
        // A simulated failure of the BNG pair silences its sessions now,
        // not at the next config pass.
        if super::ppp_ha::bfd_silent() != pair_silent {
            pair_silent = !pair_silent;
            cfg_at = None;
        }
        if cfg_at.is_none_or(|t| t.elapsed() >= CONFIG_EVERY) {
            cfg_at = Some(Instant::now());
            let cfg = lock(session).store().running().clone();
            // A failed start (port taken) is retried every second.
            // The routes' sessions (G3.6g) and the BNG pair's (G3.6h)
            // are part of what is wanted.
            let mut extra = route_sessions(&cfg);
            extra.extend(pair_sessions(&cfg));
            let wanted = (cfg.routing.bfd.clone(), extra);
            if ctl.cfg.as_ref() != Some(&wanted) && ctl.reconcile(&cfg, health) {
                ctl.cfg = Some(wanted);
            }
            match &ctl.engine {
                Some(e) => {
                    health.disabled(None);
                    health.listen(vec![
                        Listen::new("udp", std::net::SocketAddr::from(([0, 0, 0, 0], corerouter_proto_bfd::PORT_SINGLE_HOP))),
                        Listen::new("udp", std::net::SocketAddr::from(([0, 0, 0, 0], corerouter_proto_bfd::PORT_MULTI_HOP))),
                    ]);
                    let n = ctl.sessions.len() + ctl.dp_sessions.len();
                    let mode = if ctl.dplane { ", bfdd data plane" } else { "" };
                    health.event(format!("{n} sessions on {} threads ({}{mode})", e.threads(), e.steering));
                }
                None => {
                    health.listen(vec![]);
                    health.disabled(Some(if ctl.dplane {
                        "no BFD session (bfdd has none to hand over)"
                    } else {
                        "no BFD session (routing.bfd.peer.add)"
                    }));
                }
            }
        }
        if pub_at.elapsed() >= PUBLISH_EVERY {
            pub_at = Instant::now();
            ctl.publish(session);
        }
    }
}

/// The engine's session for one of bfdd's: bfdd's timers and flags, the
/// matching profile's extras (auth, dampening, minimum TTL).
#[cfg(target_os = "linux")]
fn dp_spec(cfg: &corerouter_model::Config, m: &corerouter_proto_bfd::dplane::DpSession) -> engine::Spec {
    let (prof, users) = corerouter_proto_bfd::frr::users_of(
        cfg,
        m.dst,
        m.multihop(),
        &m.ifname,
        (m.min_tx, m.min_rx, m.detect_mult),
    );
    let local = (!m.src.is_unspecified()).then_some(m.src);
    let mut spec = spec_of(
        BfdKey {
            peer: m.dst,
            multihop: m.multihop(),
            local,
        },
        &prof,
        users,
    );
    spec.cfg.desired_min_tx = m.min_tx;
    spec.cfg.required_min_rx = m.min_rx;
    spec.cfg.detect_mult = m.detect_mult.max(1);
    spec.cfg.passive = m.passive();
    spec.cfg.admin_down = m.shutdown();
    if m.multihop() {
        spec.min_ttl = m.ttl;
    }
    spec
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
            format!("BFD {}: {} » {}", e.key.peer, e.from.name(), e.to.name())
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
        // G3.6g: static routes with check_gateway=bfd follow at once.
        if e.from != e.to || released {
            s.route_check_bfd_event(e.key.peer, e.key.multihop, e.key.local, e.client_up);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Controller {
    threads: Option<usize>,
    /// Where the engine binds (tests: the loopback and other ports).
    opts: engine::Options,
    /// bfdd hands the sessions over (FRR present): the config's peers go
    /// to bfdd too (`proto_bfd::frr::render`), none is started here.
    dplane: bool,
    cfg: Option<(BfdConfig, corerouter_model::bfd::Wanted)>,
    engine: Option<engine::Engine>,
    sessions: BTreeMap<BfdKey, (u32, engine::Spec)>,
    /// bfdd's sessions by its discriminator, and what it last said of each.
    dp_sessions: BTreeMap<u32, (engine::Spec, corerouter_proto_bfd::dplane::DpSession)>,
    dp: Option<std::os::unix::net::UnixStream>,
}

/// The BNG pair's BFD sessions (G3.6h): to the peer on the sync and the
/// access path; none while a simulated failure keeps this node silent.
#[cfg(target_os = "linux")]
fn pair_sessions(cfg: &corerouter_model::Config) -> corerouter_model::bfd::Wanted {
    let mut out = corerouter_model::bfd::Wanted::new();
    if super::ppp_ha::bfd_silent() {
        return out;
    }
    for (peer, prof, path) in cfg.ppp.redundancy.bfd_sessions() {
        let Some(p) = cfg.routing.bfd.profile(prof) else { continue };
        let key = BfdKey { peer, multihop: false, local: None };
        out.insert(key, (p, vec![format!("ppp redundancy {path}")]));
    }
    out
}

#[cfg(target_os = "linux")]
fn spec_of(key: BfdKey, prof: &BfdProfile, users: Vec<String>) -> engine::Spec {
    engine::Spec {
        key,
        cfg: config_of(prof),
        damp: damp_of(prof),
        min_ttl: prof.min_ttl,
        users,
        profile: prof.name.clone(),
    }
}

#[cfg(target_os = "linux")]
impl Controller {
    /// Starts the engine if needed; false when it cannot.
    fn ensure_engine(&mut self, sessions: usize, health: &super::Health) -> bool {
        if self.engine.is_some() {
            return true;
        }
        // bfdd adds its sessions one by one: the engine starts with the
        // first, so in data plane mode `auto` cannot count them (2 threads
        // carry 1000 sessions at 50 ms × 3 with ~7 % each, docs/bfd.md).
        let auto = if self.dplane { auto_threads(AUTO_PER_THREAD + 1) } else { auto_threads(sessions) };
        let opts = engine::Options {
            threads: self.threads.unwrap_or(auto),
            // G3.6h: the BNG pair hears its peer's BFD on the engine thread.
            tap: Some(super::ppp_ha::bfd_tap),
            ..self.opts.clone()
        };
        let spawn = |name: String, f: Box<dyn FnOnce() + Send>| health.spawn(&name, f);
        match engine::Engine::start(&opts, &spawn) {
            Ok(e) => {
                self.engine = Some(e);
                health.clear_error();
                true
            }
            Err(e) => {
                health.error(e.to_string());
                false
            }
        }
    }

    /// False when the engine could not start.
    fn reconcile(&mut self, cfg: &corerouter_model::Config, health: &super::Health) -> bool {
        if self.dplane {
            // bfdd's sessions: the profile's extras (auth, dampening) may
            // have changed.
            let specs: Vec<(u32, engine::Spec)> = self
                .dp_sessions
                .iter()
                .map(|(lid, (_, m))| (*lid, dp_spec(cfg, m)))
                .collect();
            for (lid, spec) in specs {
                if let (Some(eng), Some((old, _))) = (self.engine.as_ref(), self.dp_sessions.get_mut(&lid))
                    && *old != spec
                {
                    eng.update(lid, spec.clone());
                    *old = spec;
                }
            }
        }
        // With bfdd the config's peers are its own; static routes with
        // check_gateway=bfd (G3.6g) run here either way, except a gateway
        // bfdd already has a session to.
        let mut wanted_cfg = if self.dplane { route_sessions(cfg) } else { wanted_all(cfg) };
        // G3.6h: the BNG pair's sessions run here either way.
        for (key, v) in pair_sessions(cfg) {
            wanted_cfg.entry(key).or_insert(v);
        }
        let wanted: BTreeMap<BfdKey, engine::Spec> = wanted_cfg
            .into_iter()
            .filter(|(key, _)| !self.dp_sessions.values().any(|(s, _)| s.key == *key))
            .map(|(key, (prof, users))| (key.clone(), spec_of(key, &prof, users)))
            .collect();
        if wanted.is_empty() {
            if let Some(eng) = self.engine.as_mut() {
                for (key, (discr, _)) in std::mem::take(&mut self.sessions) {
                    eng.remove(discr, &key);
                }
            }
            if self.dp_sessions.is_empty() {
                self.engine = None;
            }
            return true;
        }
        if !self.ensure_engine(wanted.len(), health) {
            return false;
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

    fn write(&mut self, bytes: &[u8]) {
        let failed = self.dp.as_mut().is_some_and(|w| w.write_all(bytes).is_err());
        if failed {
            // The reader sees the end too and reconnects.
            self.dp = None;
        }
    }

    /// A message of bfdd (data plane mode).
    fn on_bfdd(&mut self, m: dplane::DpIn, cfg: &corerouter_model::Config, health: &super::Health) {
        use corerouter_proto_bfd::dplane as dp;
        match m {
            dplane::DpIn::Connected(w) => {
                self.dp = Some(w);
                health.event("connected to bfdd as its data plane");
            }
            dplane::DpIn::Lost(why) => {
                log::warn!("BFD: lost bfdd ({why}); its sessions stop until it is back");
                self.dp = None;
                if let Some(eng) = self.engine.as_mut() {
                    for (lid, (spec, _)) in std::mem::take(&mut self.dp_sessions) {
                        eng.remove(lid, &spec.key);
                    }
                }
            }
            dplane::DpIn::Msg(dp::FromBfdd::AddSession(m)) => {
                let spec = dp_spec(cfg, &m);
                let lid = m.lid;
                if let Some((old, msg)) = self.dp_sessions.get_mut(&lid) {
                    if *old != spec
                        && let Some(eng) = self.engine.as_ref()
                    {
                        eng.update(lid, spec.clone());
                    }
                    *old = spec;
                    *msg = m;
                    return;
                }
                if !self.ensure_engine(self.dp_sessions.len() + 1, health) {
                    return;
                }
                let Some(eng) = self.engine.as_mut() else { return };
                if eng.add_with(lid, spec.clone()) {
                    self.dp_sessions.insert(lid, (spec, m));
                } else {
                    log::warn!("BFD: bfdd session {lid} (to {}) not taken: discriminator in use", m.dst);
                }
            }
            dplane::DpIn::Msg(dp::FromBfdd::DeleteSession(m)) => {
                if let (Some((spec, _)), Some(eng)) = (self.dp_sessions.remove(&m.lid), self.engine.as_mut()) {
                    eng.remove(m.lid, &spec.key);
                }
                if self.dp_sessions.is_empty() && self.sessions.is_empty() {
                    self.engine = None;
                }
            }
            dplane::DpIn::Msg(dp::FromBfdd::RequestCounters { id, lid }) => {
                let row = self
                    .engine
                    .as_ref()
                    .and_then(|e| e.snapshot().0.into_iter().find(|s| s.local_discr == lid));
                let (rx, tx) = row.map_or((0, 0), |r| (r.packets_rx, r.packets_tx));
                // Bytes: 24 per packet (52 with SHA1); the engine counts packets.
                let per = if self.dp_sessions.get(&lid).is_some_and(|(s, _)| s.cfg.auth.is_some()) { 52 } else { 24 };
                let c = dp::Counters {
                    lid,
                    control_input_bytes: rx * per,
                    control_input_packets: rx,
                    control_output_bytes: tx * per,
                    control_output_packets: tx,
                };
                let mut out = Vec::new();
                dp::encode_counters(id, &c, &mut out);
                self.write(&out);
            }
            dplane::DpIn::Msg(dp::FromBfdd::Echo { id, bfdd_time }) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_micros() as u64);
                let mut out = Vec::new();
                dp::encode_echo_reply(id, now, bfdd_time, &mut out);
                self.write(&out);
            }
            dplane::DpIn::Msg(dp::FromBfdd::Other(t)) => log::debug!("BFD: bfdd message type {t} ignored"),
        }
    }

    /// `BFD_STATE_CHANGE` for bfdd's sessions: the state its clients
    /// (bgpd, ospfd) must act on — down while dampened.
    fn tell_bfdd(&mut self, events: &[engine::Event]) {
        use corerouter_proto_bfd::dplane as dp;
        if self.dp.is_none() {
            return;
        }
        let mut out = Vec::new();
        for e in events.iter().filter(|e| self.dp_sessions.contains_key(&e.discr)) {
            let state = if e.to == State::Up && !e.client_up { State::Down } else { e.to };
            dp::encode_state(
                &dp::StateChange {
                    lid: e.discr,
                    rid: e.remote_discr,
                    remote_flags: 0,
                    desired_tx: e.remote_desired_tx,
                    required_rx: e.remote_min_rx,
                    required_echo_rx: 0,
                    state: state as u8,
                    diagnostics: e.diag.code(),
                    detect_mult: e.remote_mult,
                },
                &mut out,
            );
        }
        if !out.is_empty() {
            self.write(&out);
        }
    }

    fn publish(&self, session: &Shared) {
        let (sessions, threads, steering) = match &self.engine {
            Some(e) => {
                let (s, t) = e.snapshot();
                (s, t, e.steering)
            }
            None => (Vec::new(), Vec::new(), ""),
        };
        // Before the session lock: the BNG pair's monitor and alerts.
        super::ppp_ha::publish_bfd(&sessions);
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
        self.dp_sessions.clear();
        self.publish(session);
    }
}

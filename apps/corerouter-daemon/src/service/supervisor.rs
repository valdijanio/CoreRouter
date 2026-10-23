//! The service supervisor (G0.10): runs each service's body on a thread of
//! its own and keeps it running.
//!
//! - **Always restart** (systemd `Restart=always`, Erlang `permanent`): a
//!   body that ends, returns an error or panics (`catch_unwind`) is started
//!   again after a wait that doubles from 1 s to 60 s (systemd
//!   `RestartSteps`/`RestartMaxDelaySec`); a run that lasted 60 s starts
//!   the wait over at 1 s.
//! - **Gives up** after 5 failures in 60 s (systemd `StartLimitBurst` /
//!   `StartLimitIntervalSec`, OTP intensity/period): the service stays
//!   `failed`, with a critical line in the router's log (which remote
//!   syslog forwards), until `system.service.start` or `reset-failures`.
//! - **Dependencies**: a service waits in `starting` until the services in
//!   its `depends` run.
//! - **Commands** reach it through the session: `system.service.*` queue
//!   requests in `ServiceTable`; every tick the supervisor takes them and
//!   publishes the rows back (one short lock; it never holds another lock
//!   meanwhile).
//!
//! A thread cannot be killed: `stop` asks the body (`Health::stopping`) and
//! the row says "stopping" until it returns.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use corerouter_control::Shutdown;
use corerouter_engine::logging::DAEMON;
use corerouter_engine::{Shared, lock};
use corerouter_model::service::{
    Listen, ServiceAction, ServiceRequest, ServiceRow, ServiceState, ServiceTable,
};
use serde_json::json;

use super::{Ctx, Health, Run, Service};

/// The restart policy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy {
    /// First wait before a restart; doubles up to `max_delay`.
    pub first_delay: Duration,
    pub max_delay: Duration,
    /// Failures within `window` that make the supervisor give up.
    pub burst: usize,
    pub window: Duration,
    /// A heartbeat older than this is reported as late.
    pub stall: Duration,
    pub tick: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            burst: 5,
            window: Duration::from_secs(60),
            stall: Duration::from_secs(30),
            tick: Duration::from_millis(200),
        }
    }
}

impl Policy {
    fn text(&self) -> String {
        format!(
            "always; wait {}, doubling up to {}; gives up after {} failures in {}",
            secs(self.first_delay),
            secs(self.max_delay),
            self.burst,
            secs(self.window)
        )
    }
}

fn secs(d: Duration) -> String {
    if d.as_millis().is_multiple_of(1000) {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
}

/// The text of a panic payload.
pub(crate) fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(no message)".into())
}

/// A line for the router's log: (service topic, level, message, detail).
type Note = (&'static str, &'static str, String, serde_json::Value);

/// What a run ended with.
type Outcome = Result<(), String>;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    /// Waiting for its dependencies.
    Waiting,
    /// Its thread runs.
    Running,
    /// Asked to end; then stop (`false`) or start again (`true`).
    Ending { again: bool },
    /// Starts again at this time.
    Backoff(Instant),
    Stopped,
    Failed,
}

struct Slot {
    name: &'static str,
    topic: &'static str,
    enable: &'static str,
    depends: &'static [&'static str],
    run: Arc<Run>,
    phase: Phase,
    health: Health,
    thread: Option<JoinHandle<Outcome>>,
    started: Option<Instant>,
    restarts: u32,
    failures: VecDeque<Instant>,
    delay: Duration,
    last_event: String,
    last_error: Option<String>,
    /// The late heartbeat was logged.
    stalled: bool,
    /// Restart asked for: the next run waits until the last run's helper
    /// threads ended (they may still hold its sockets), or this time.
    drain_until: Option<Instant>,
}

/// Longest a restart waits for the old run's helper threads.
const HELPER_GRACE: Duration = Duration::from_secs(2);

/// The supervisor's state; [`Supervisor::tick`] does one round.
pub(crate) struct Supervisor {
    slots: Vec<Slot>,
    policy: Policy,
    session: Shared,
    shutdown: Shutdown,
    control: Vec<Listen>,
    born: Instant,
}

/// A run's thread could not be created (thread exhaustion): a failure like
/// any other, so a service that can never start ends `failed` after the
/// burst instead of retrying every minute forever.
fn spawn_failed(slot: &mut Slot, policy: &Policy, now: Instant, e: &str) {
    slot.last_error = Some(format!("cannot start its thread: {e}"));
    slot.failures.push_back(now);
    while slot
        .failures
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) > policy.window)
    {
        slot.failures.pop_front();
    }
    if slot.failures.len() >= policy.burst {
        slot.phase = Phase::Failed;
        slot.last_event = format!(
            "gave up: {} failures in {}",
            slot.failures.len(),
            secs(policy.window)
        );
        log::error!("service {}: cannot start its thread ({e}); giving up", slot.name);
        return;
    }
    slot.phase = Phase::Backoff(now + slot.delay);
    slot.restarts = slot.restarts.saturating_add(1);
    slot.delay = (slot.delay * 2).min(policy.max_delay);
    slot.last_event = format!("cannot start its thread: {e}");
}

/// Start the supervisor's thread with every service prepared by `start_all`.
pub(crate) fn spawn(ctx: &Ctx, runs: Vec<(&'static Service, Run)>) -> std::io::Result<()> {
    let mut sup = Supervisor::new(
        ctx.session.clone(),
        ctx.shutdown.clone(),
        ctx.control.clone(),
        Policy::default(),
    );
    for (svc, run) in runs {
        sup.add(svc, run);
    }
    sup.tick(Instant::now());
    thread::Builder::new()
        .name("supervisor".into())
        .spawn(move || sup.run())
        .map(|_| ())
}

impl Supervisor {
    pub(crate) fn new(
        session: Shared,
        shutdown: Shutdown,
        control: Vec<Listen>,
        policy: Policy,
    ) -> Self {
        Self {
            slots: Vec::new(),
            policy,
            session,
            shutdown,
            control,
            born: Instant::now(),
        }
    }

    pub(crate) fn add(&mut self, svc: &'static Service, run: Run) {
        self.slots.push(Slot {
            name: svc.name,
            topic: svc.topic,
            enable: svc.enable,
            depends: svc.depends,
            run: Arc::new(run),
            phase: Phase::Waiting,
            health: Health::new(self.shutdown.clone()),
            thread: None,
            started: None,
            restarts: 0,
            failures: VecDeque::new(),
            delay: self.policy.first_delay,
            last_event: String::new(),
            last_error: None,
            stalled: false,
            drain_until: None,
        });
    }

    fn run(mut self) {
        while !self.shutdown.is_closed() {
            thread::sleep(self.policy.tick);
            self.tick(Instant::now());
        }
        for s in &self.slots {
            s.health.stop();
        }
    }

    /// One round: requests, ended runs, due restarts, then the rows.
    pub(crate) fn tick(&mut self, now: Instant) {
        let requests = {
            let mut s = lock(&self.session);
            s.ext_mut::<ServiceTable>()
                .map(|t| std::mem::take(&mut t.requests))
                .unwrap_or_default()
        };
        let mut notes: Vec<Note> = Vec::new();
        for r in requests {
            notes.extend(self.request(&r, now));
        }
        for i in 0..self.slots.len() {
            self.reap(i, now, &mut notes);
        }
        for i in 0..self.slots.len() {
            self.advance(i, now);
        }
        let rows = self.rows(now);
        let mut s = lock(&self.session);
        for (topic, level, msg, detail) in notes {
            if topic == "system" {
                s.log_event(&["system", level], DAEMON, msg, detail);
            } else {
                s.log_event(&[topic, "system", level], DAEMON, msg, detail);
            }
        }
        if let Some(t) = s.ext_mut::<ServiceTable>() {
            t.supervised = true;
            t.rows = rows;
        }
    }

    /// A `system.service.*` command; what it did goes to the router's log
    /// (the service's topic), so Log and the Services window show it.
    fn request(&mut self, r: &ServiceRequest, now: Instant) -> Option<Note> {
        let Some(slot) = self.slots.iter_mut().find(|s| s.name == r.name) else {
            return None; // `control`: nothing to do (stop/restart are refused).
        };
        log::info!("service {}: {} (command)", slot.name, r.action.as_str());
        let before = slot.phase;
        match r.action {
            ServiceAction::Stop => match slot.phase {
                Phase::Running | Phase::Ending { .. } => {
                    slot.health.stop();
                    slot.phase = Phase::Ending { again: false };
                    slot.last_event = "stopping (command)".into();
                }
                Phase::Waiting | Phase::Backoff(_) | Phase::Failed => {
                    slot.phase = Phase::Stopped;
                    slot.last_event = "stopped (command)".into();
                }
                Phase::Stopped => {}
            },
            ServiceAction::Restart => match slot.phase {
                Phase::Running | Phase::Ending { .. } => {
                    slot.health.stop();
                    slot.phase = Phase::Ending { again: true };
                    slot.last_event = "restarting (command)".into();
                }
                _ => fresh_start(slot),
            },
            ServiceAction::Start => match slot.phase {
                Phase::Running | Phase::Waiting => {}
                Phase::Ending { .. } => slot.phase = Phase::Ending { again: true },
                Phase::Backoff(_) | Phase::Stopped | Phase::Failed => fresh_start(slot),
            },
            ServiceAction::ResetFailures => {
                slot.restarts = 0;
                slot.failures.clear();
                slot.delay = self.policy.first_delay;
                slot.last_error = None;
                if slot.phase == Phase::Failed {
                    fresh_start(slot);
                } else if let Phase::Backoff(_) = slot.phase {
                    slot.phase = Phase::Backoff(now);
                }
            }
        }
        let what = match (r.action, before, slot.phase) {
            (_, _, Phase::Ending { again: false }) => "parando",
            (_, _, Phase::Ending { again: true }) => "reiniciando",
            (_, _, Phase::Stopped) if before == Phase::Stopped => "já estava parado",
            (_, _, Phase::Stopped) => "parado",
            (ServiceAction::ResetFailures, _, _) => "falhas zeradas",
            (_, Phase::Running | Phase::Waiting, Phase::Running | Phase::Waiting) => {
                "já estava rodando"
            }
            (_, _, Phase::Waiting) => "iniciando",
            _ => "sem mudança",
        };
        Some((
            slot.topic,
            "info",
            format!("Serviço {}: {what} ({} por comando).", slot.name, r.action.as_str()),
            json!({"service": slot.name, "action": r.action.as_str()}),
        ))
    }

    /// A run whose thread ended: what next.
    fn reap(
        &mut self,
        i: usize,
        now: Instant,
        notes: &mut Vec<Note>,
    ) {
        let policy = self.policy;
        let closing = self.shutdown.is_closed();
        let Some(slot) = self.slots.get_mut(i) else {
            return;
        };
        if !slot.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            return;
        }
        let Some(t) = slot.thread.take() else {
            return;
        };
        let outcome = t
            .join()
            .unwrap_or_else(|p| Err(format!("panic: {}", panic_text(p.as_ref()))));
        // Helpers of that run stop too.
        slot.health.stop();
        let report = slot.health.snapshot();
        let lasted = slot.started.map_or(Duration::ZERO, |s| now.saturating_duration_since(s));
        slot.started = None;
        match slot.phase {
            Phase::Ending { again: false } => {
                slot.phase = Phase::Stopped;
                slot.last_event = "stopped (command)".into();
                notes.push((
                    slot.topic,
                    "info",
                    format!("Serviço {}: parado (stop por comando).", slot.name),
                    json!({"service": slot.name, "action": "stop"}),
                ));
                return;
            }
            Phase::Ending { again: true } => {
                slot.phase = Phase::Waiting;
                slot.drain_until = Some(now + HELPER_GRACE);
                return;
            }
            _ if closing => {
                slot.phase = Phase::Stopped;
                return;
            }
            _ => {}
        }
        let why = match outcome {
            Err(e) => e,
            Ok(()) => "ended without being asked to".to_owned(),
        };
        slot.last_error = Some(why.clone());
        if lasted >= policy.window {
            slot.delay = policy.first_delay;
        }
        slot.failures.push_back(now);
        while slot
            .failures
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > policy.window)
        {
            slot.failures.pop_front();
        }
        let detail = json!({
            "service": slot.name,
            "error": why,
            "last_event": report.event,
            "ran_secs": lasted.as_secs(),
        });
        if slot.failures.len() >= policy.burst {
            slot.phase = Phase::Failed;
            slot.last_event = format!("gave up: {} failures in {}", slot.failures.len(), secs(policy.window));
            log::error!(
                "service {} failed {} times in {}; not restarting it (system.service.start or \
                 reset-failures tries again): {why}",
                slot.name,
                slot.failures.len(),
                secs(policy.window)
            );
            notes.push((
                slot.topic,
                "critical",
                format!(
                    "Serviço {} parou de vez: {} falhas em {} ({why}). \
                     system.service.start tenta de novo.",
                    slot.name,
                    slot.failures.len(),
                    secs(policy.window)
                ),
                detail,
            ));
            return;
        }
        let wait = slot.delay;
        slot.phase = Phase::Backoff(now + wait);
        slot.restarts = slot.restarts.saturating_add(1);
        slot.delay = (slot.delay * 2).min(policy.max_delay);
        slot.last_event = format!("failed: {why}; restarting in {}", secs(wait));
        log::warn!("service {} failed: {why}; restarting in {}", slot.name, secs(wait));
        notes.push((
            slot.topic,
            "error",
            format!(
                "Serviço {} falhou ({why}); reinicia em {}.",
                slot.name,
                secs(wait)
            ),
            detail,
        ));
    }

    /// Start what is due and whose dependencies run.
    fn advance(&mut self, i: usize, now: Instant) {
        if self.shutdown.is_closed() {
            return;
        }
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let due = match slot.phase {
            Phase::Waiting => true,
            Phase::Backoff(at) => now >= at,
            _ => false,
        };
        if !due {
            return;
        }
        // A restart: the old run's helpers (a listener's accept thread)
        // first let go of its sockets, or the new run fails to bind.
        if slot.health.helpers() > 0 && slot.drain_until.is_some_and(|t| now < t) {
            return;
        }
        let missing: Vec<&str> = slot
            .depends
            .iter()
            .copied()
            .filter(|d| !self.is_running(d))
            .collect();
        let shutdown = self.shutdown.clone();
        let Some(slot) = self.slots.get_mut(i) else {
            return;
        };
        if !missing.is_empty() {
            slot.phase = Phase::Waiting;
            slot.last_event = format!("waiting for {}", missing.join(", "));
            return;
        }
        let health = Health::new(shutdown);
        let run = slot.run.clone();
        let body = health.clone();
        let spawned = thread::Builder::new()
            .name(format!("svc-{}", slot.name))
            .spawn(move || {
                catch_unwind(AssertUnwindSafe(|| run(&body)))
                    .unwrap_or_else(|p| Err(format!("panic: {}", panic_text(p.as_ref()))))
            });
        slot.drain_until = None;
        match spawned {
            Ok(t) => {
                slot.health = health;
                slot.thread = Some(t);
                slot.started = Some(now);
                slot.phase = Phase::Running;
                slot.stalled = false;
                slot.last_event = "started".into();
            }
            Err(e) => spawn_failed(slot, &self.policy, now, &e.to_string()),
        }
    }

    fn is_running(&self, name: &str) -> bool {
        self.slots.iter().any(|s| {
            s.name == name && s.phase == Phase::Running && s.health.snapshot().beat.is_some()
        })
    }

    fn rows(&mut self, now: Instant) -> Vec<ServiceRow> {
        let policy = self.policy;
        let text = policy.text();
        let mut rows: Vec<ServiceRow> = Vec::with_capacity(self.slots.len() + 1);
        rows.push(ServiceRow {
            name: "control".into(),
            state: ServiceState::Running,
            uptime_secs: Some(now.saturating_duration_since(self.born).as_secs()),
            listen: self.control.clone(),
            last_event: "carries the GUI, CLI and MCP sessions".into(),
            enable: "corerouter-daemon --control/--listen/--ws".into(),
            topic: "system".into(),
            policy: "runs as long as the daemon".into(),
            protected: true,
            ..ServiceRow::default()
        });
        for slot in &mut self.slots {
            let report = slot.health.snapshot();
            let age = report.beat.map(|b| now.saturating_duration_since(b));
            let mut reason = None;
            let mut restart_in = None;
            let state = match slot.phase {
                Phase::Waiting => {
                    reason = Some(slot.last_event.clone()).filter(|e| e.starts_with("waiting"));
                    ServiceState::Starting
                }
                Phase::Running | Phase::Ending { .. } if report.beat.is_none() => {
                    ServiceState::Starting
                }
                Phase::Running | Phase::Ending { .. } => {
                    let state = match &report.disabled {
                        Some(why) => {
                            reason = Some(why.clone());
                            ServiceState::Disabled
                        }
                        None => ServiceState::Running,
                    };
                    // A stop on its way says so, whatever the config.
                    if let Phase::Ending { again } = slot.phase {
                        reason = Some(if again { "restarting" } else { "stopping" }.into());
                    }
                    state
                }
                Phase::Backoff(at) => {
                    restart_in = Some(at.saturating_duration_since(now).as_millis().div_ceil(1000))
                        .map(|s| u64::try_from(s).unwrap_or(u64::MAX));
                    ServiceState::Restarting
                }
                Phase::Stopped => ServiceState::Stopped,
                Phase::Failed => ServiceState::Failed,
            };
            let running = matches!(slot.phase, Phase::Running | Phase::Ending { .. });
            if running {
                if let Some(e) = &report.event {
                    slot.last_event.clone_from(e);
                }
                if report.error.is_some() {
                    slot.last_error.clone_from(&report.error);
                }
                if age.is_some_and(|a| a > policy.stall) {
                    let a = age.unwrap_or_default().as_secs();
                    if !slot.stalled {
                        slot.stalled = true;
                        log::warn!("service {}: no heartbeat for {a} s (stuck?)", slot.name);
                    }
                    reason = Some(format!("no heartbeat for {a} s"));
                }
            }
            rows.push(ServiceRow {
                name: slot.name.into(),
                state,
                reason,
                restart_in_secs: restart_in,
                uptime_secs: slot
                    .started
                    .filter(|_| running)
                    .map(|s| now.saturating_duration_since(s).as_secs()),
                restarts: slot.restarts,
                recent_failures: u32::try_from(slot.failures.len()).unwrap_or(u32::MAX),
                threads: if running { 1 + slot.health.helpers() } else { 0 },
                heartbeat_age_ms: age
                    .filter(|_| running)
                    .map(|a| u64::try_from(a.as_millis()).unwrap_or(u64::MAX)),
                listen: if running { report.listen } else { Vec::new() },
                last_event: slot.last_event.clone(),
                last_error: slot.last_error.clone(),
                depends: slot.depends.iter().map(|d| (*d).to_owned()).collect(),
                enable: slot.enable.into(),
                turn_on: turn_on(slot.enable),
                topic: slot.topic.into(),
                policy: text.clone(),
                protected: false,
            });
        }
        rows
    }
}

/// Start again with a clean failure window (the admin asked).
/// `enable` ("ip.dns.set allow_remote_requests=yes") as `{id, params}` when
/// it is a whole command; `None` when it has a placeholder (`…`) or is prose
/// ("always on").
fn turn_on(enable: &str) -> Option<serde_json::Value> {
    if enable.contains('…') {
        return None;
    }
    let mut words = enable.split_whitespace();
    let id = words.next().filter(|w| w.contains('.'))?;
    let mut params = serde_json::Map::new();
    for w in words {
        let (k, v) = w.split_once('=')?;
        let v = match v {
            "yes" => json!(true),
            "no" => json!(false),
            _ => v.parse::<u64>().map_or_else(|_| json!(v), |n| json!(n)),
        };
        params.insert(k.to_owned(), v);
    }
    Some(json!({ "id": id, "params": params }))
}

fn fresh_start(slot: &mut Slot) {
    slot.failures.clear();
    slot.phase = Phase::Waiting;
    slot.last_event = "starting (command)".into();
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn quick() -> Policy {
        Policy {
            first_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(80),
            burst: 5,
            window: Duration::from_secs(10),
            stall: Duration::from_secs(10),
            tick: Duration::from_millis(5),
        }
    }

    fn leak(name: &'static str, depends: &'static [&'static str]) -> &'static Service {
        Box::leak(Box::new(Service {
            name,
            flags: &[],
            topic: "system",
            enable: "always on",
            depends,
            start: |_| Err("not used".into()),
        }))
    }

    fn sup() -> (Supervisor, Shared) {
        let session = shared(Session::virtual_lab());
        let s = Supervisor::new(session.clone(), Shutdown::default(), Vec::new(), quick());
        (s, session)
    }

    /// Tick until `done` holds for the row of `name` (or 5 s).
    fn until(sup: &mut Supervisor, name: &str, done: impl Fn(&ServiceRow) -> bool) -> ServiceRow {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            sup.tick(Instant::now());
            let row = lock(&sup.session)
                .ext::<ServiceTable>()
                .and_then(|t| t.row(name).cloned())
                .unwrap();
            if done(&row) {
                return row;
            }
            assert!(Instant::now() < end, "timed out; last row {row:?}");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// A loop that beats until stopped.
    fn steady() -> Run {
        Box::new(|h: &Health| {
            while h.sleep(Duration::from_millis(5)) {
                h.beat();
            }
            Ok(())
        })
    }

    #[test]
    fn failure_backs_off_then_gives_up_and_reset_starts_again() {
        let (mut sup, session) = sup();
        let runs = Arc::new(AtomicU32::new(0));
        let n = runs.clone();
        sup.add(
            leak("flaky", &[]),
            Box::new(move |h: &Health| {
                n.fetch_add(1, Ordering::SeqCst);
                h.beat();
                Err("bind: address in use".into())
            }),
        );
        let r = until(&mut sup, "flaky", |r| r.state == ServiceState::Restarting);
        assert_eq!(r.restarts, 1);
        assert!(r.last_event.contains("restarting in 20 ms"), "{}", r.last_event);
        assert_eq!(r.last_error.as_deref(), Some("bind: address in use"));
        // The wait doubles: 20, 40, 80, 80 ms.
        let r = until(&mut sup, "flaky", |r| r.restarts == 2 && r.state == ServiceState::Restarting);
        assert!(r.last_event.contains("40 ms"), "{}", r.last_event);
        let r = until(&mut sup, "flaky", |r| r.state == ServiceState::Failed);
        assert_eq!(runs.load(Ordering::SeqCst), 5);
        assert_eq!(r.restarts, 4);
        assert!(r.last_event.contains("gave up"), "{}", r.last_event);
        assert!(r.policy.contains("gives up after 5 failures"));
        // It stays failed.
        thread::sleep(Duration::from_millis(200));
        sup.tick(Instant::now());
        assert_eq!(runs.load(Ordering::SeqCst), 5);
        let log = lock(&session).log_since(0);
        assert!(
            log.iter().any(|e| e.topics.contains(&"critical".into())
                && e.message.contains("flaky")),
            "{log:?}"
        );
        // reset-failures: counters cleared, started again.
        lock(&session)
            .execute("system.service.reset-failures", &json!({"name": "flaky"}))
            .unwrap();
        let r = until(&mut sup, "flaky", |r| r.state != ServiceState::Failed);
        assert_eq!(r.restarts, 0);
        until(&mut sup, "flaky", |_| runs.load(Ordering::SeqCst) == 6);
    }

    #[test]
    fn a_panic_is_contained_and_restarted() {
        let (mut sup, _) = sup();
        let runs = Arc::new(AtomicU32::new(0));
        let n = runs.clone();
        sup.add(
            leak("panicky", &[]),
            Box::new(move |h: &Health| {
                if n.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("index out of range");
                }
                while h.sleep(Duration::from_millis(5)) {
                    h.beat();
                }
                Ok(())
            }),
        );
        let r = until(&mut sup, "panicky", |r| r.state == ServiceState::Running);
        assert_eq!(r.restarts, 1);
        assert_eq!(r.last_error.as_deref(), Some("panic: index out of range"));
        assert_eq!(r.threads, 1);
        assert!(r.uptime_secs.is_some() && r.heartbeat_age_ms.is_some());
    }

    #[test]
    fn stop_start_and_restart_by_command() {
        let (mut sup, session) = sup();
        sup.add(leak("steady", &[]), steady());
        until(&mut sup, "steady", |r| r.state == ServiceState::Running);
        let run = |id: &str| {
            lock(&session)
                .execute(&format!("system.service.{id}"), &json!({"name": "steady"}))
                .unwrap();
        };
        run("stop");
        let r = until(&mut sup, "steady", |r| r.state == ServiceState::Stopped);
        assert_eq!(r.restarts, 0, "a stop is not a failure");
        assert_eq!(r.threads, 0);
        run("start");
        until(&mut sup, "steady", |r| r.state == ServiceState::Running);
        run("restart");
        let r = until(&mut sup, "steady", |r| {
            r.state == ServiceState::Running && r.last_event == "started"
        });
        assert_eq!(r.restarts, 0, "an admin restart does not count");
        // What each command did is in the router's log, not only on stderr.
        let log = lock(&session).execute("log.print", &json!({})).unwrap();
        let text = log.to_string();
        for want in ["steady: parando (stop", "steady: parado (stop", "steady: iniciando (start", "steady: reiniciando (restart"] {
            assert!(text.contains(want), "{want} not in {text}");
        }
        // The protected row is listed and its stop refused.
        let e = lock(&session)
            .execute("system.service.stop", &json!({"name": "control"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("protected"), "{e}");
    }

    /// audit-services #12a: a failed thread spawn was never counted, so the
    /// service retried forever and never reached `failed`.
    #[test]
    fn spawn_failures_count_and_give_up() {
        let (mut sup, _) = sup();
        sup.add(leak("nothread", &[]), steady());
        let policy = sup.policy;
        let slot = sup.slots.first_mut().unwrap();
        let now = Instant::now();
        for i in 1..policy.burst {
            spawn_failed(slot, &policy, now, "Resource temporarily unavailable");
            assert!(matches!(slot.phase, Phase::Backoff(_)));
            assert_eq!(slot.restarts as usize, i);
        }
        spawn_failed(slot, &policy, now, "Resource temporarily unavailable");
        assert_eq!(slot.phase, Phase::Failed);
        assert!(slot.last_event.contains("gave up"), "{}", slot.last_event);
    }

    /// audit-services #12b: a restart started the new run while the old
    /// run's helper still held its port, so the new bind failed.
    #[test]
    fn a_restart_waits_for_the_old_helpers() {
        let (mut sup, session) = sup();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        sup.add(
            leak("listener", &[]),
            Box::new(move |h: &Health| {
                let l = std::net::TcpListener::bind(("127.0.0.1", port))
                    .map_err(|e| format!("bind: {e}"))?;
                let helper = h.clone();
                h.spawn("accept", move || {
                    while !helper.stopping() {
                        thread::sleep(Duration::from_millis(5));
                    }
                    // Notices the stop late (a POLL timeout), then lets go.
                    thread::sleep(Duration::from_millis(150));
                    drop(l);
                })
                .map_err(|e| e.to_string())?;
                while h.sleep(Duration::from_millis(5)) {
                    h.beat();
                }
                Ok(())
            }),
        );
        until(&mut sup, "listener", |r| r.state == ServiceState::Running);
        lock(&session)
            .execute("system.service.restart", &json!({"name": "listener"}))
            .unwrap();
        let r = until(&mut sup, "listener", |r| {
            r.state == ServiceState::Running && r.last_event == "started"
        });
        assert_eq!(r.restarts, 0, "{r:?}");
        assert_eq!(r.last_error, None, "{r:?}");
    }

    #[test]
    fn a_dependent_waits_and_disabled_is_reported() {
        let (mut sup, _) = sup();
        sup.add(
            leak("server", &["resolver"]),
            Box::new(|h: &Health| {
                while h.sleep(Duration::from_millis(5)) {
                    h.beat();
                    h.disabled(Some("allow_remote_requests=no"));
                    h.listen(vec![Listen::new("udp", "0.0.0.0:53".parse().unwrap())]);
                }
                Ok(())
            }),
        );
        let r = until(&mut sup, "server", |r| r.reason.is_some());
        assert_eq!(r.state, ServiceState::Starting);
        assert_eq!(r.reason.as_deref(), Some("waiting for resolver"));
        sup.add(leak("resolver", &[]), steady());
        let r = until(&mut sup, "server", |r| r.state == ServiceState::Disabled);
        assert_eq!(r.reason.as_deref(), Some("allow_remote_requests=no"));
        assert_eq!(r.listen.len(), 1);
        assert_eq!(r.depends, ["resolver"]);
    }

    #[test]
    fn a_run_that_returns_by_itself_is_a_failure() {
        let (mut sup, _) = sup();
        sup.add(leak("quitter", &[]), Box::new(|_: &Health| Ok(())));
        let r = until(&mut sup, "quitter", |r| r.restarts >= 1);
        assert_eq!(r.last_error.as_deref(), Some("ended without being asked to"));
    }

    #[test]
    fn turn_on_is_the_enable_text_when_it_is_a_whole_command() {
        assert_eq!(
            turn_on("ip.dns.set allow_remote_requests=yes"),
            Some(json!({"id": "ip.dns.set", "params": {"allow_remote_requests": true}}))
        );
        assert_eq!(
            turn_on("ip.service.metrics.set enabled=yes port=9100"),
            Some(json!({"id": "ip.service.metrics.set", "params": {"enabled": true, "port": 9100}}))
        );
        assert_eq!(turn_on("ip.dhcp-server.add interface=… address_pool=…"), None);
        assert_eq!(turn_on("always on (ip.dns.set servers=…)"), None);
        assert_eq!(turn_on("always on"), None);
        assert_eq!(turn_on("system.logging.action.add + system.logging.add"), None);
    }
}

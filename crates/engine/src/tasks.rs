//! Background tasks of the diagnostic tools (ping, MTU discovery, MTR, and
//! later traceroute, torch, bandwidth-test).
//!
//! A tool command (`tool.ping.start`) validates its parameters and starts a
//! job; the job runs on a thread of the app's [`Runner`] — never under the
//! session lock — and writes events and a running summary into its
//! [`TaskCell`]. Clients read them with `tool.task.poll {id, after_seq}` and
//! end the job with `tool.task.stop`. Tasks are operational, like the
//! neighbor table: no journal entry, no revision, nothing saved.
//!
//! The engine has no threads and no clock (it compiles for wasm32): the
//! runner supplies both. Without a runner (the in-browser lab) the tool
//! commands are disabled with the reason.
//!
//! Bounds, so a forgotten client cannot exhaust the router:
//! - at most [`MAX_RUNNING`] running tasks and [`MAX_KEPT`] kept in all;
//! - each keeps its last [`MAX_EVENTS`] events (a ring: a slow poller sees
//!   `lost`); the summary is never lost;
//! - a running task nobody polled for [`ABANDON_SECS`] is stopped, and a
//!   finished one is dropped [`KEEP_SECS`] after its last poll (both by the
//!   session clock, [`Session::tick`]).

use std::collections::{BTreeMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::{EngineError, Result, Session};

pub const MAX_RUNNING: usize = 8;
pub const MAX_KEPT: usize = 32;
pub const MAX_EVENTS: usize = 1024;
/// Events one `tool.task.poll` returns at most.
pub const MAX_POLL: usize = 256;
pub const ABANDON_SECS: u64 = 60;
pub const KEEP_SECS: u64 = 300;
/// Longest a job sleeps without looking at its stop flag.
const SLICE: Duration = Duration::from_millis(50);

/// Monotonic time and sleep, from the runner (the engine has neither).
pub trait Clock {
    /// Time since the job started.
    fn elapsed(&self) -> Duration;
    fn sleep(&self, d: Duration);
}

pub type Job = Box<dyn FnOnce(&dyn Clock) + Send>;

/// Runs jobs on their own threads; installed by the app
/// ([`Session::set_runner`]), e.g. `corerouter_control::ThreadRunner`.
pub trait Runner: Send + Sync {
    fn spawn(&self, name: &str, job: Job) -> std::result::Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Running,
    /// The job finished by itself (count reached, answer found).
    Done,
    /// Stopped by `tool.task.stop`, or abandoned.
    Stopped,
    Failed,
}

#[derive(Debug)]
struct TaskData {
    state: TaskState,
    /// Why it failed or was stopped.
    reason: Option<String>,
    events: VecDeque<Value>,
    /// Sequence number the next event gets (the first is 1).
    next_seq: u64,
    summary: Value,
}

/// What a job and its pollers share.
#[derive(Debug)]
pub struct TaskCell {
    stop: AtomicBool,
    data: Mutex<TaskData>,
}

impl TaskCell {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            data: Mutex::new(TaskData {
                state: TaskState::Running,
                reason: None,
                events: VecDeque::new(),
                next_seq: 1,
                summary: Value::Null,
            }),
        }
    }

    fn data(&self) -> MutexGuard<'_, TaskData> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn state(&self) -> TaskState {
        self.data().state.clone()
    }

    /// Ask the job to stop; it notices within [`SLICE`] or one probe wait.
    fn request_stop(&self, reason: &str) {
        self.stop.store(true, Ordering::Relaxed);
        let mut d = self.data();
        if d.state == TaskState::Running && d.reason.is_none() {
            d.reason = Some(reason.to_owned());
        }
    }

    fn finish(&self, outcome: std::result::Result<(), String>) {
        let stopped = self.stop.load(Ordering::Relaxed);
        let mut d = self.data();
        if d.state != TaskState::Running {
            return;
        }
        match outcome {
            Ok(()) if stopped => d.state = TaskState::Stopped,
            Ok(()) => d.state = TaskState::Done,
            Err(e) => {
                d.state = TaskState::Failed;
                d.reason = Some(e);
            }
        }
    }
}

#[cfg(test)]
impl TaskCell {
    pub(crate) fn for_test() -> Self {
        Self::new()
    }

    /// Every event kept, and the summary.
    pub(crate) fn snapshot(&self) -> (Vec<Value>, Value) {
        let d = self.data();
        (d.events.iter().cloned().collect(), d.summary.clone())
    }
}

/// A job's view of its task: events out, stop flag in, time.
pub struct TaskCtx<'a> {
    cell: &'a TaskCell,
    clock: &'a dyn Clock,
}

impl<'a> TaskCtx<'a> {
    pub fn new(cell: &'a TaskCell, clock: &'a dyn Clock) -> Self {
        Self { cell, clock }
    }

    pub fn stopped(&self) -> bool {
        self.cell.stop.load(Ordering::Relaxed)
    }

    pub fn now(&self) -> Duration {
        self.clock.elapsed()
    }

    /// Sleep `d` in slices; `false` if a stop came in meanwhile.
    pub fn sleep(&self, d: Duration) -> bool {
        let end = self.now().saturating_add(d);
        loop {
            if self.stopped() {
                return false;
            }
            let left = end.saturating_sub(self.now());
            if left.is_zero() {
                return true;
            }
            self.clock.sleep(left.min(SLICE));
        }
    }

    /// Append an event (an object; `seq` is added). The oldest is dropped
    /// past [`MAX_EVENTS`].
    pub fn emit(&self, mut event: Value) {
        let mut d = self.cell.data();
        let seq = d.next_seq;
        d.next_seq = seq.saturating_add(1);
        if let Value::Object(o) = &mut event {
            o.insert("seq".into(), json!(seq));
        }
        d.events.push_back(event);
        while d.events.len() > MAX_EVENTS {
            d.events.pop_front();
        }
    }

    /// Replace the running summary.
    pub fn summary(&self, summary: Value) {
        self.cell.data().summary = summary;
    }
}

struct Entry {
    kind: &'static str,
    title: String,
    owner: String,
    /// Who started it: only they (or group write and up) poll or stop it.
    principal: crate::auth::Principal,
    /// Who started it, as the log shows it (G4.6d).
    origin: String,
    /// Its end is in the log already.
    logged_end: bool,
    /// Session clock (Unix seconds) at start and at the last poll; `None`
    /// without a clock (then nothing expires by time).
    started: Option<u64>,
    seen: Option<u64>,
    cell: Arc<TaskCell>,
}

/// The session's tasks.
#[derive(Default)]
pub struct Tasks {
    runner: Option<Arc<dyn Runner>>,
    entries: BTreeMap<u64, Entry>,
    next_id: u64,
}

impl Tasks {
    pub fn running(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.cell.state() == TaskState::Running)
            .count()
    }

    /// Stop the abandoned, drop the stale (called by [`Session::tick`]).
    fn expire(&mut self, now: u64) {
        self.entries.retain(|id, e| {
            let idle = e.seen.map_or(0, |s| now.saturating_sub(s));
            match e.cell.state() {
                TaskState::Running if idle >= ABANDON_SECS => {
                    log::info!("task {id} ({}) abandoned: not polled for {idle} s", e.title);
                    e.cell
                        .request_stop(&format!("abandoned: nobody polled it for {ABANDON_SECS} s"));
                    true
                }
                TaskState::Running => true,
                _ => idle < KEEP_SECS,
            }
        });
    }

    /// Room for one more: drop the oldest finished tasks past [`MAX_KEPT`].
    fn make_room(&mut self) {
        while self.entries.len() >= MAX_KEPT {
            let oldest = self
                .entries
                .iter()
                .find(|(_, e)| e.cell.state() != TaskState::Running)
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => {
                    self.entries.remove(&id);
                }
                None => break,
            }
        }
    }
}

/// "Ping" and " para uol.com.br" of a task, for the log.
fn tool_words(kind: &str, title: &str) -> (String, String) {
    let (name, verb, prep) = match kind {
        "ping" => ("Ping", "ping ", " para "),
        "mtu" => ("Descoberta de MTU", "mtu ", " para "),
        "mtr" => ("MTR", "mtr ", " para "),
        "cable-test" => ("Teste de cabo", "cable test ", " em "),
        "torch" => ("Torch", "torch ", " em "),
        "sniffer" => ("Sniffer", "sniffer ", " em "),
        "bandwidth-test" => ("Bandwidth test", "bandwidth-test ", " com "),
        other => (other, "", " "),
    };
    let target = title.strip_prefix(verb).unwrap_or(title);
    let target = if target.is_empty() {
        String::new()
    } else {
        format!("{prep}{target}")
    };
    (name.to_owned(), target)
}

/// ": 4 enviados, 4 recebidos, 0% perdidos" from a ping summary (one
/// target), or nothing.
fn outcome(summary: &Value) -> String {
    let targets = summary.get("targets").and_then(Value::as_array);
    let Some([t]) = targets.map(Vec::as_slice) else {
        return String::new();
    };
    match (
        t.get("sent").and_then(Value::as_u64),
        t.get("received").and_then(Value::as_u64),
        t.get("loss_pct").and_then(Value::as_f64),
    ) {
        (Some(sent), Some(received), Some(loss)) => {
            format!(": {sent} enviados, {received} recebidos, {loss:.0}% perdidos")
        }
        _ => String::new(),
    }
}

/// `{sent, received, loss_pct}` of each target of a ping summary.
fn totals(summary: &Value) -> Value {
    let targets = summary.get("targets").and_then(Value::as_array);
    Value::Array(
        targets
            .map(|t| {
                t.iter()
                    .take(8)
                    .map(|t| {
                        json!({
                            "host": t.get("host"),
                            "sent": t.get("sent"),
                            "received": t.get("received"),
                            "loss_pct": t.get("loss_pct"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// Why tool commands are disabled here, if they are.
pub(crate) fn can_start(s: &Session) -> std::result::Result<(), String> {
    if s.tasks.runner.is_none() {
        return Err("this build runs no background tasks (the in-browser lab): \
             connect the GUI to a daemon"
            .into());
    }
    s.hal().prober().map(|_| ())
}

/// Why task commands that need no prober (the cable test) are disabled.
pub(crate) fn can_run(s: &Session) -> std::result::Result<(), String> {
    if s.tasks.runner.is_none() {
        return Err("this build runs no background tasks (the in-browser lab): \
             connect the GUI to a daemon"
            .into());
    }
    Ok(())
}

/// One task as `tool.task.list` shows it.
fn row(id: u64, e: &Entry, now: Option<u64>) -> Value {
    let d = e.cell.data();
    json!({
        "id": id,
        "kind": e.kind,
        "title": e.title,
        "state": d.state,
        "reason": d.reason,
        "owner": e.owner,
        "events": d.next_seq.saturating_sub(1),
        "age_secs": now.zip(e.started).map(|(n, s)| n.saturating_sub(s)),
    })
}

impl Session {
    /// Let tool commands run jobs on `runner` (the daemon and the native
    /// GUI install `corerouter_control::ThreadRunner`).
    pub fn set_runner(&mut self, runner: Arc<dyn Runner>) {
        self.tasks.runner = Some(runner);
    }

    pub(crate) fn expire_tasks(&mut self) {
        self.log_finished_tasks();
        if let Some(now) = self.now() {
            self.tasks.expire(now);
        }
    }

    /// Start `job` as a new task of `kind`; returns its id.
    pub(crate) fn start_task(
        &mut self,
        kind: &'static str,
        title: String,
        job: impl FnOnce(&TaskCtx) -> std::result::Result<(), String> + Send + 'static,
    ) -> Result<u64> {
        let runner = self
            .tasks
            .runner
            .clone()
            .ok_or_else(|| EngineError::Hal("no task runner".into()))?;
        self.expire_tasks();
        if self.tasks.running() >= MAX_RUNNING {
            return Err(EngineError::Hal(format!(
                "{MAX_RUNNING} tasks are running already; stop one first \
                 (tool.task.list, tool.task.stop)"
            )));
        }
        self.tasks.make_room();
        self.tasks.next_id = self.tasks.next_id.saturating_add(1);
        let id = self.tasks.next_id;
        let cell = Arc::new(TaskCell::new());
        let shared = Arc::clone(&cell);
        let wrapped: Job = Box::new(move |clock: &dyn Clock| {
            let ctx = TaskCtx::new(&shared, clock);
            let outcome = catch_unwind(AssertUnwindSafe(|| job(&ctx)))
                .unwrap_or_else(|_| Err("internal error: the task crashed".into()));
            shared.finish(outcome);
        });
        runner
            .spawn(&format!("{kind}-{id}"), wrapped)
            .map_err(|e| EngineError::Hal(format!("cannot start the task: {e}")))?;
        let now = self.now();
        self.tasks.entries.insert(
            id,
            Entry {
                kind,
                title: title.clone(),
                owner: self.caller().name.clone(),
                principal: self.caller().principal.clone(),
                origin: crate::logging::origin(self.caller()),
                logged_end: false,
                started: now,
                seen: now,
                cell,
            },
        );
        let origin = crate::logging::origin(self.caller());
        let (name, target) = tool_words(kind, &title);
        self.log_event(
            &["tool", "info"],
            &origin,
            format!("{name}{target} iniciado (tarefa {id})"),
            json!({ "task": id, "kind": kind, "title": title }),
        );
        Ok(id)
    }

    /// Log the end of tasks that finished since the last look: `tool,info`
    /// when done or stopped, `tool,warning` with the reason when failed.
    fn log_finished_tasks(&mut self) {
        let mut ended = Vec::new();
        for (id, e) in &mut self.tasks.entries {
            if e.logged_end {
                continue;
            }
            let d = e.cell.data();
            if d.state == TaskState::Running {
                continue;
            }
            e.logged_end = true;
            ended.push((
                *id,
                e.kind,
                e.title.clone(),
                e.origin.clone(),
                d.state.clone(),
                d.reason.clone(),
                d.summary.clone(),
            ));
        }
        for (id, kind, title, origin, state, reason, summary) in ended {
            let (name, target) = tool_words(kind, &title);
            let head = format!("{name}{target}");
            let (level, message) = match state {
                TaskState::Failed => (
                    "warning",
                    format!(
                        "{head} falhou (tarefa {id}): {}",
                        reason.as_deref().unwrap_or("motivo desconhecido")
                    ),
                ),
                TaskState::Stopped => (
                    "info",
                    format!("{head} parado (tarefa {id}){}", outcome(&summary)),
                ),
                _ => (
                    "info",
                    format!("{head} terminou (tarefa {id}){}", outcome(&summary)),
                ),
            };
            self.log_event(
                &["tool", level],
                &origin,
                message,
                // The summary itself stays in the tool's window (it can be
                // large): the log keeps what it says in numbers.
                json!({ "task": id, "kind": kind, "state": state, "reason": reason, "totals": totals(&summary) }),
            );
        }
    }

    pub(crate) fn task_list(&mut self) -> Value {
        self.expire_tasks();
        let now = self.now();
        Value::Array(
            self.tasks
                .entries
                .iter()
                .map(|(id, e)| row(*id, e, now))
                .collect(),
        )
    }

    /// Task `id`, if the caller may drive it: its owner, or group write
    /// and up. A read-only account could otherwise stop anyone's MTR, or
    /// keep an abandoned task alive by polling it (audit #12).
    fn task(&mut self, id: u64) -> Result<&mut Entry> {
        let mine = self
            .tasks
            .entries
            .get(&id)
            .map(|e| e.principal == self.caller().principal);
        let writer = self.permit(crate::auth::Group::Write).is_ok();
        if mine == Some(false) && !writer {
            return Err(EngineError::Denied {
                id: "tool.task".into(),
                reason: format!(
                    "task {id} is not yours (started by another account); \
                     group write may stop or poll any task"
                ),
            });
        }
        self.tasks.entries.get_mut(&id).ok_or_else(|| {
            EngineError::bad(
                "id",
                format!("no task {id} (finished tasks are kept {KEEP_SECS} s; see tool.task.list)"),
            )
        })
    }

    /// Events after `after_seq` (at most `max`), the summary and the state.
    pub(crate) fn task_poll(&mut self, id: u64, after_seq: u64, max: usize) -> Result<Value> {
        self.log_finished_tasks();
        let now = self.now();
        let e = self.task(id)?;
        if now.is_some() {
            e.seen = now;
        }
        let (kind, title) = (e.kind, e.title.clone());
        let d = e.cell.data();
        let oldest = d.next_seq.saturating_sub(d.events.len() as u64);
        let lost = oldest.saturating_sub(after_seq.saturating_add(1));
        let events: Vec<Value> = d
            .events
            .iter()
            .filter(|ev| ev.get("seq").and_then(Value::as_u64).unwrap_or(0) > after_seq)
            .take(max.clamp(1, MAX_POLL))
            .cloned()
            .collect();
        let last = events
            .last()
            .and_then(|ev| ev.get("seq").and_then(Value::as_u64))
            .unwrap_or(after_seq.min(d.next_seq.saturating_sub(1)));
        let more = d.next_seq.saturating_sub(1) > last;
        Ok(json!({
            "id": id,
            "kind": kind,
            "title": title,
            "state": d.state,
            "done": d.state != TaskState::Running && !more,
            "reason": d.reason,
            "summary": d.summary,
            "events": events,
            "next_seq": last,
            "more": more,
            "lost": lost,
        }))
    }

    /// Whether task `id` of `kind` still runs, if the caller may drive it
    /// (the sniffer's download).
    pub(crate) fn task_running(&mut self, id: u64, kind: &str) -> Result<bool> {
        let e = self.task(id)?;
        if e.kind != kind {
            return Err(EngineError::bad("id", format!("task {id} is a {}, not a {kind}", e.kind)));
        }
        Ok(e.cell.state() == TaskState::Running)
    }

    /// Whether task `id` is still kept (running or finished).
    pub(crate) fn task_kept(&self, id: u64) -> bool {
        self.tasks.entries.contains_key(&id)
    }

    pub(crate) fn task_stop(&mut self, id: u64) -> Result<Value> {
        let by = self.caller().name.clone();
        let e = self.task(id)?;
        e.cell.request_stop(&format!("stopped by {by}"));
        Ok(json!({ "id": id, "state": e.cell.state(), "stopping": true }))
    }
}

#[cfg(test)]
pub(crate) mod test_runner {
    //! A thread runner for engine tests (the real one lives in `control`).

    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{Clock, Job, Runner};

    pub struct Threads;

    struct Wall(Instant);

    impl Clock for Wall {
        fn elapsed(&self) -> Duration {
            self.0.elapsed()
        }
        fn sleep(&self, d: Duration) {
            thread::sleep(d);
        }
    }

    impl Runner for Threads {
        fn spawn(&self, name: &str, job: Job) -> Result<(), String> {
            thread::Builder::new()
                .name(name.into())
                .spawn(move || job(&Wall(Instant::now())))
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }

    pub fn threads() -> Arc<dyn Runner> {
        Arc::new(Threads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn session() -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        s
    }

    fn wait_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..400 {
            let p = s.task_poll(id, 0, MAX_POLL).unwrap();
            if p["state"] != "running" {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    #[test]
    fn events_are_numbered_and_polled_incrementally() {
        let mut s = session();
        let id = s
            .start_task("test", "count".into(), |ctx| {
                for i in 0..5 {
                    ctx.emit(json!({ "i": i }));
                }
                ctx.summary(json!({ "total": 5 }));
                Ok(())
            })
            .unwrap();
        let all = wait_done(&mut s, id);
        assert_eq!(all["state"], "done");
        assert_eq!(all["events"].as_array().unwrap().len(), 5);
        assert_eq!(all["summary"]["total"], 5);
        let tail = s.task_poll(id, 3, MAX_POLL).unwrap();
        let seqs: Vec<u64> = tail["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, vec![4, 5]);
        assert_eq!(tail["done"], true);
        assert_eq!(tail["lost"], 0);
    }

    #[test]
    fn the_ring_keeps_the_newest_and_reports_what_was_lost() {
        let mut s = session();
        let n = MAX_EVENTS + 100;
        let id = s
            .start_task("test", "flood".into(), move |ctx| {
                for i in 0..n {
                    ctx.emit(json!({ "i": i }));
                }
                Ok(())
            })
            .unwrap();
        wait_done(&mut s, id);
        let p = s.task_poll(id, 0, 10).unwrap();
        assert_eq!(p["lost"], 100);
        assert_eq!(p["events"][0]["seq"], 101);
        assert_eq!(p["more"], true);
        assert_eq!(p["done"], false, "not done while events are unread");
    }

    #[test]
    fn stop_ends_a_sleeping_job_promptly() {
        let mut s = session();
        let id = s
            .start_task("test", "forever".into(), |ctx| {
                while ctx.sleep(Duration::from_secs(3600)) {}
                Ok(())
            })
            .unwrap();
        assert_eq!(s.task_list()[0]["state"], "running");
        s.task_stop(id).unwrap();
        let p = wait_done(&mut s, id);
        assert_eq!(p["state"], "stopped");
        assert!(p["reason"].as_str().unwrap().contains("stopped by"));
    }

    #[test]
    fn failures_and_crashes_are_reported() {
        let mut s = session();
        let id = s
            .start_task("test", "bad".into(), |_| Err("no route".into()))
            .unwrap();
        let p = wait_done(&mut s, id);
        assert_eq!(p["state"], "failed");
        assert_eq!(p["reason"], "no route");
        // The log has its start and, once looked at, its failure (G4.6d).
        s.task_list();
        let log = s.log_since(0);
        let msgs: Vec<(&str, &str)> = log
            .iter()
            .map(|e| (e.topics[1].as_str(), e.message.as_str()))
            .collect();
        assert_eq!(
            msgs,
            [
                ("info", "test bad iniciado (tarefa 1)"),
                ("warning", "test bad falhou (tarefa 1): no route"),
            ]
        );
        assert_eq!(log[0].origin, "local");
        #[allow(clippy::panic)]
        let id = s
            .start_task("test", "crash".into(), |_| panic!("boom"))
            .unwrap();
        let p = wait_done(&mut s, id);
        assert_eq!(p["state"], "failed");
        assert!(p["reason"].as_str().unwrap().contains("crashed"));
    }

    #[test]
    fn running_tasks_are_capped() {
        let mut s = session();
        let forever = |ctx: &TaskCtx| {
            while ctx.sleep(Duration::from_secs(3600)) {}
            Ok(())
        };
        for _ in 0..MAX_RUNNING {
            s.start_task("test", "x".into(), forever).unwrap();
        }
        let err = s.start_task("test", "x".into(), forever).unwrap_err();
        assert!(err.to_string().contains("stop one first"), "{err}");
        for id in 1..=MAX_RUNNING as u64 {
            s.task_stop(id).unwrap();
        }
    }

    #[test]
    fn abandoned_tasks_stop_and_finished_ones_expire() {
        let mut s = session();
        s.tick(1_000);
        let id = s
            .start_task("test", "forever".into(), |ctx| {
                while ctx.sleep(Duration::from_secs(3600)) {}
                Ok(())
            })
            .unwrap();
        s.tick(1_000 + ABANDON_SECS - 1);
        assert_eq!(s.task_list()[0]["state"], "running");
        s.task_poll(id, 0, 1).unwrap();
        // Polled at T+59: abandoned only 60 s after that.
        s.tick(1_000 + ABANDON_SECS + 30);
        assert_eq!(s.task_list()[0]["state"], "running");
        s.tick(1_000 + 2 * ABANDON_SECS);
        let p = wait_done(&mut s, id);
        assert_eq!(p["state"], "stopped");
        assert!(p["reason"].as_str().unwrap().contains("abandoned"));
        // wait_done polled it: kept KEEP_SECS after the clock time it was polled.
        s.tick(1_000 + 2 * ABANDON_SECS + KEEP_SECS);
        assert!(s.task_list().as_array().unwrap().is_empty());
        assert!(s.task_poll(id, 0, 1).is_err());
    }

    /// Audit #12: stop and poll were plain queries with no owner check.
    #[test]
    fn only_the_owner_or_a_writer_stops_or_polls_a_task() {
        use crate::{Caller, Principal};
        let mut s = session();
        for (name, group) in [("op", "write"), ("noc", "read")] {
            s.execute(
                "user.add",
                &json!({"name": name, "group": group, "password": "s3cret-Passw0rd"}),
            )
            .unwrap();
        }
        let id = s
            .start_task("test", "forever".into(), |ctx| {
                while ctx.sleep(Duration::from_secs(3600)) {}
                Ok(())
            })
            .unwrap();
        let noc = Caller::new(5, "tcp 10.0.0.9:1").with_principal(Principal::User("noc".into()));
        let op = Caller::new(6, "tcp 10.0.0.8:1").with_principal(Principal::User("op".into()));
        for cmd in ["tool.task.stop", "tool.task.poll"] {
            let err = s.execute_as(&noc, cmd, &json!({"id": id})).unwrap_err();
            assert!(err.to_string().contains("not yours"), "{cmd}: {err}");
        }
        assert_eq!(s.task_list()[0]["state"], "running");
        s.execute_as(&op, "tool.task.poll", &json!({"id": id}))
            .unwrap();
        s.execute_as(&op, "tool.task.stop", &json!({"id": id}))
            .unwrap();
        assert_eq!(wait_done(&mut s, id)["state"], "stopped");
    }

    #[test]
    fn without_a_runner_tools_are_disabled_with_the_reason() {
        let s = Session::virtual_lab();
        assert!(can_start(&s).unwrap_err().contains("connect the GUI"));
        assert!(can_start(&session()).is_ok());
    }
}

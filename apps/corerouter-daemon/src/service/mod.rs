//! Services the daemon runs next to the control channel: DNS resolver, NTP
//! client, remote syslog, Prometheus metrics… One file each,
//! `src/service/<name>.rs`, with a
//! `pub(crate) const SERVICE: Service`; `build.rs` finds them. A service
//! declares its own command-line flags, so a new one does not touch
//! `main.rs` (the hot spot of parallel features).
//!
//! # Writing a service (G0.10: under the supervisor)
//!
//! Every service runs under [`supervisor`]: it is restarted when it ends,
//! returns an error or panics (always, waiting 1 s, 2 s, 4 s… up to 60 s;
//! after 5 failures in 60 s it is left `failed`, with a line in the log),
//! and `system.service.print` shows its state. A service has two parts:
//!
//! - `start(&Ctx) -> Result<Run, String>` runs once, at boot: read the
//!   flags, open what a bad flag should refuse (`Err` stops the daemon),
//!   and return the body.
//! - the body, `Fn(&Health) -> Result<(), String>`, runs on a thread of the
//!   supervisor, again after each failure. Its main loop:
//!
//! ```ignore
//! let run: Run = Box::new(move |health: &Health| {
//!     while health.sleep(TICK) {        // false once stopped: return
//!         health.beat();                // "alive" (the row's heartbeat)
//!         // … the work …
//!         health.listen(vec![Listen::new("udp", addr)]);
//!         health.disabled(None);        // or Some("allow_remote_requests=no")
//!     }
//!     Ok(())                            // asked to stop: not a failure
//! });
//! ```
//!
//! `health.event(…)` / `health.error(…)` set the row's last event, and
//! `health.spawn(name, f)` starts a helper thread that is counted in the
//! row and sees `health.stopping()` like the loop. A body that returns while
//! not asked to stop counts as a failure (`Restart=always`). Set `depends`
//! when the body needs another service running first, `enable` to the
//! config command that turns it on, and `topic` to its log topic.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Shutdown;
use corerouter_engine::Shared;
use corerouter_model::service::{Listen, MAX_EVENT};

// `supervisor.rs` is a module like the services (build.rs lists it).

/// A command-line flag a service takes.
pub(crate) struct Flag {
    pub name: &'static str,
    /// The value's placeholder in the help (`[<addr>:]<port>`); `None` for a
    /// switch without value.
    pub value: Option<&'static str>,
    /// Help text; continuation lines are indented by `usage`.
    pub help: &'static str,
}

/// The body the supervisor runs (again after every failure).
pub(crate) type Run = Box<dyn Fn(&Health) -> Result<(), String> + Send + Sync>;

pub(crate) struct Service {
    /// Kebab-case, as `system.service.stop name=…` takes it.
    pub name: &'static str,
    pub flags: &'static [Flag],
    /// Topic of its lines in the router's log (one of the model's `TOPICS`).
    pub topic: &'static str,
    /// The config command that turns it on, for people ("always on" when
    /// nothing does).
    pub enable: &'static str,
    /// Services that must be running before this one starts.
    pub depends: &'static [&'static str],
    /// Reads the flags and returns the body. `Err` stops the daemon (a bad
    /// flag); what can fail later belongs in the body.
    pub start: fn(&Ctx) -> Result<Run, String>,
}

/// What a service gets at start.
pub(crate) struct Ctx {
    pub session: Shared,
    pub shutdown: Shutdown,
    /// The service flags given on the command line (value, or "" for a switch).
    pub flags: BTreeMap<&'static str, String>,
    /// Where the control channel listens (the protected `control` row).
    pub control: Vec<Listen>,
    /// `--config-dir` when the config is on disk (services keep their own
    /// files under it, like the graph history).
    pub config_dir: Option<std::path::PathBuf>,
    /// The login gate of the TLS endpoints (shared, so login limits hold
    /// across them).
    pub remote_gate: corerouter_control::Gate,
    /// The router's certificate, when the daemon made or loaded one.
    pub tls: Option<corerouter_control::tls::ServerIdentity>,
}

impl Ctx {
    pub(crate) fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }
}

include!(concat!(env!("OUT_DIR"), "/services.rs"));

/// The service flag named `name`, if one service declares it.
pub(crate) fn flag(name: &str) -> Option<&'static Flag> {
    ALL.iter().flat_map(|s| s.flags).find(|f| f.name == name)
}

/// Prepare every service, in order (the first `Err` stops the daemon), then
/// hand them to the supervisor's thread.
pub(crate) fn start_all(ctx: &Ctx) -> Result<(), String> {
    let mut runs = Vec::new();
    for s in ALL {
        let run = (s.start)(ctx).map_err(|e| format!("{}: {e}", s.name))?;
        runs.push((*s, run));
    }
    supervisor::spawn(ctx, runs).map_err(|e| format!("cannot start the supervisor: {e}"))
}

/// The services' flags, for `--help`.
pub(crate) fn usage() -> String {
    let mut out = String::new();
    for f in ALL.iter().flat_map(|s| s.flags) {
        let head = match f.value {
            Some(v) => format!("{} {v}", f.name),
            None => f.name.to_owned(),
        };
        let mut lines = f.help.lines();
        let first = lines.next().unwrap_or_default();
        out.push_str(&format!("\n  {head:<20}  {first}"));
        for l in lines {
            out.push_str(&format!("\n{:24}{}", "", l.trim_start()));
        }
    }
    out
}

/// What one run of a service reports, and how it is told to stop. Cheap to
/// clone; a new run gets a new one, so a thread left over from an old run
/// stops and its reports go nowhere.
#[derive(Clone)]
pub(crate) struct Health(Arc<HealthInner>);

struct HealthInner {
    shutdown: Shutdown,
    stop: AtomicBool,
    /// Helper threads alive (`spawn`).
    helpers: AtomicU32,
    report: Mutex<Report>,
}

#[derive(Default, Clone)]
pub(crate) struct Report {
    pub beat: Option<Instant>,
    pub listen: Vec<Listen>,
    pub event: Option<String>,
    pub error: Option<String>,
    pub disabled: Option<String>,
}

/// How often `sleep` looks at the stop flag.
const SLICE: Duration = Duration::from_millis(50);

fn cut(s: &str) -> String {
    if s.len() <= MAX_EVENT {
        return s.to_owned();
    }
    let mut end = MAX_EVENT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", s.get(..end).unwrap_or_default())
}

impl Health {
    pub(crate) fn new(shutdown: Shutdown) -> Self {
        Self(Arc::new(HealthInner {
            shutdown,
            stop: AtomicBool::new(false),
            helpers: AtomicU32::new(0),
            report: Mutex::new(Report::default()),
        }))
    }

    fn report(&self) -> MutexGuard<'_, Report> {
        self.0.report.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The daemon is closing or the supervisor asked this run to end.
    pub(crate) fn stopping(&self) -> bool {
        self.0.stop.load(Ordering::Acquire) || self.0.shutdown.is_closed()
    }

    pub(crate) fn stop(&self) {
        self.0.stop.store(true, Ordering::Release);
    }

    /// Sleep `d`, waking early to stop; `false` when stopping.
    pub(crate) fn sleep(&self, d: Duration) -> bool {
        let until = Instant::now() + d;
        loop {
            if self.stopping() {
                return false;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            thread::sleep(left.min(SLICE));
        }
    }

    /// The main loop is alive.
    pub(crate) fn beat(&self) {
        self.report().beat = Some(Instant::now());
    }

    pub(crate) fn listen(&self, at: Vec<Listen>) {
        let mut r = self.report();
        if r.listen != at {
            r.listen = at;
        }
    }

    pub(crate) fn event(&self, what: impl AsRef<str>) {
        self.report().event = Some(cut(what.as_ref()));
    }

    /// An error the service lives with (it retries on its own).
    pub(crate) fn error(&self, what: impl AsRef<str>) {
        let what = cut(what.as_ref());
        let mut r = self.report();
        r.event = Some(what.clone());
        r.error = Some(what);
    }

    /// The error went away.
    pub(crate) fn clear_error(&self) {
        self.report().error = None;
    }

    /// Idle because the config turns it off (`Some(reason)`), or not.
    pub(crate) fn disabled(&self, reason: Option<&str>) {
        let mut r = self.report();
        let now = reason.map(cut);
        if r.disabled != now {
            r.event = Some(match &now {
                Some(why) => format!("idle: {why}"),
                None => "turned on by the config".into(),
            });
            r.disabled = now;
        }
    }

    pub(crate) fn snapshot(&self) -> Report {
        self.report().clone()
    }

    pub(crate) fn helpers(&self) -> u32 {
        self.0.helpers.load(Ordering::Acquire)
    }

    /// A helper thread of this run, counted while it lives. A panic in it
    /// is contained and reported; the run goes on.
    pub(crate) fn spawn<F>(&self, name: &str, f: F) -> std::io::Result<thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        struct Count(Health);
        impl Drop for Count {
            fn drop(&mut self) {
                self.0.0.helpers.fetch_sub(1, Ordering::AcqRel);
            }
        }
        self.0.helpers.fetch_add(1, Ordering::AcqRel);
        let count = Count(self.clone());
        let label = name.to_owned();
        let spawned = thread::Builder::new().name(name.into()).spawn(move || {
            let count = count;
            if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
                let why = supervisor::panic_text(p.as_ref());
                log::error!("thread {label} panicked: {why}");
                count.0.error(format!("thread {label} panicked: {why}"));
            }
        });
        if spawned.is_err() {
            // The closure (and its count) never ran.
            self.0.helpers.fetch_sub(1, Ordering::AcqRel);
        }
        spawned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_are_found_and_flags_are_unique() {
        let names: Vec<&str> = ALL.iter().map(|s| s.name).collect();
        for want in [
            "dns-adlist",
            "dns-resolver",
            "dns-server",
            "metrics",
            "ntp-client",
            "remote-logging",
        ] {
            assert!(names.contains(&want), "{want} not in {names:?}");
        }
        for s in ALL {
            assert!(
                corerouter_model::logging::TOPICS.contains(&s.topic),
                "{}: topic {}",
                s.name,
                s.topic
            );
            for d in s.depends {
                assert!(names.contains(d), "{} depends on unknown {d}", s.name);
            }
            assert!(
                s.name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{} is not kebab-case",
                s.name
            );
        }
        let mut flags: Vec<&str> = ALL.iter().flat_map(|s| s.flags).map(|f| f.name).collect();
        let n = flags.len();
        flags.sort_unstable();
        flags.dedup();
        assert_eq!(flags.len(), n, "a flag is declared twice");
        assert!(usage().contains("--metrics"));
    }

    #[test]
    fn health_counts_helpers_and_stops_them() {
        let h = Health::new(Shutdown::default());
        let inner = h.clone();
        let t = h
            .spawn(
                "helper",
                move || {
                    while inner.sleep(Duration::from_millis(5)) {}
                },
            )
            .unwrap();
        assert_eq!(h.helpers(), 1);
        h.stop();
        t.join().unwrap();
        assert_eq!(h.helpers(), 0);
        assert!(
            !h.sleep(Duration::from_secs(5)),
            "returns at once when stopping"
        );
    }

    #[test]
    fn a_helper_panic_is_contained_and_reported() {
        let h = Health::new(Shutdown::default());
        let t = h.spawn("boom", || panic!("helper went wrong")).unwrap();
        assert!(t.join().is_ok(), "the panic did not escape the thread");
        assert_eq!(h.helpers(), 0);
        let r = h.snapshot();
        assert!(r.error.unwrap().contains("helper went wrong"));
    }
}

//! Threads for the engine's background tasks (diagnostic tools, G6.1). The
//! engine has no threads and no clock (wasm32); every process that owns a
//! session installs this runner: `session.set_runner(thread_runner())`.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, Job, Runner};

/// One named std thread per task; the job's clock starts with it.
#[derive(Debug, Default, Clone, Copy)]
pub struct ThreadRunner;

struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for ThreadRunner {
    fn spawn(&self, name: &str, job: Job) -> Result<(), String> {
        thread::Builder::new()
            .name(name.chars().take(15).collect())
            .spawn(move || job(&Wall(Instant::now())))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

pub fn thread_runner() -> Arc<dyn Runner> {
    Arc::new(ThreadRunner)
}

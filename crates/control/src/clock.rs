//! Wall clock for a shared session. The engine has none (it compiles for
//! wasm32), so the process that owns the session ticks it: Safe Mode
//! timeouts (G1.4) and revision timestamps use this time.

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};

const PERIOD: Duration = Duration::from_secs(1);

/// Tick `session` now and then every second, on a background thread.
pub fn spawn_clock(session: Shared) -> std::io::Result<thread::JoinHandle<()>> {
    tick(&session);
    thread::Builder::new().name("clock".into()).spawn(move || {
        loop {
            thread::sleep(PERIOD);
            tick(&session);
        }
    })
}

fn tick(session: &Shared) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => lock(session).tick(d.as_secs()),
        Err(e) => log::warn!("clock before 1970, not ticking: {e}"),
    }
}

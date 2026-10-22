//! Wall clock for a shared session. The engine has none (it compiles for
//! wasm32), so the process that owns the session ticks it: Safe Mode
//! timeouts (G1.4) and revision timestamps use this time. The same thread
//! drives the DHCP clients (G4.7) four times a second, on a monotonic clock
//! (a wall-clock jump must not expire a lease).

use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};

const PERIOD: Duration = Duration::from_secs(1);
/// How often the DHCP clients look at their sockets and timers.
const SERVICE: Duration = Duration::from_millis(250);

/// Tick `session` now and then every second, and run its services every
/// [`SERVICE`], on a background thread.
pub fn spawn_clock(session: Shared) -> std::io::Result<thread::JoinHandle<()>> {
    let start = Instant::now();
    tick(&session);
    service(&session, start);
    thread::Builder::new().name("clock".into()).spawn(move || {
        let mut last_tick = Instant::now();
        loop {
            thread::sleep(SERVICE);
            if last_tick.elapsed() >= PERIOD {
                last_tick = Instant::now();
                tick(&session);
            }
            service(&session, start);
        }
    })
}

fn tick(session: &Shared) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => lock(session).tick(d.as_secs()),
        Err(e) => log::warn!("clock before 1970, not ticking: {e}"),
    }
}

fn service(session: &Shared, start: Instant) {
    let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    lock(session).dhcp_service(ms);
}

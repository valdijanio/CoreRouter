//! Wall clock for a shared session. The engine has none (it compiles for
//! wasm32), so the process that owns the session ticks it: Safe Mode
//! timeouts (G1.4) and revision timestamps use this time. The same thread
//! drives the DHCP clients (G4.7) four times a second, on a monotonic clock
//! (a wall-clock jump must not expire a lease).
//!
//! The tick's link poll reads every link of the platform (on a BNG, one per
//! subscriber: ~200 ms with 10 000, **medido**). It is read here with the
//! session unlocked and only folded in under the lock (G1.3f), so commands,
//! the GUI and MCP do not wait for the kernel. The route lines its route
//! watch looks at are built the same way when a commit made them stale
//! (G0.31g: 60 000 routes, ~26 ms, **medido**).

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
    // The reader and the route build are taken under the lock; they run
    // with it released.
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            log::warn!("clock before 1970, not ticking: {e}");
            return;
        }
    };
    let (reader, routes) = {
        let mut s = lock(session);
        (s.link_reader(), s.route_job(now))
    };
    let links = reader.map(|mut r| r.read());
    if let Some(job) = routes {
        job.run();
    }
    lock(session).tick_sampled(now, links);
    // What the route cache let go of is freed with the lock released.
    let garbage = lock(session).route_garbage();
    drop(garbage);
}

fn service(session: &Shared, start: Instant) {
    let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    lock(session).dhcp_service(ms);
}

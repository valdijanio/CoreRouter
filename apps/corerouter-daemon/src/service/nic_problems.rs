//! Network cards the kernel could not bring up in full (G1.6ja): looks at the
//! machine every [`EVERY`] on its own thread, outside the session lock (the
//! number per device is in `corerouter_hal_linux::nic_scan`), and hands the
//! reading over, under the lock only for that. The engine judges and words it
//! (`corerouter_engine::nic_problems`).
//!
//! No events to wait on: a card without a driver makes no link, and the
//! kernel announces nothing we could not read a moment later. A card plugged
//! in shows up on the next look.

use std::time::Duration;

use corerouter_engine::Shared;
#[cfg(target_os = "linux")]
use corerouter_engine::lock;

/// Between two looks.
const EVERY: Duration = if cfg!(test) { Duration::from_millis(50) } else { Duration::from_secs(10) };

pub(crate) const SERVICE: super::Service = super::Service {
    name: "nic-problems",
    flags: &[],
    topic: "interface",
    enable: "always on with --backend linux",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

fn idle(health: &super::Health, why: &str) {
    health.disabled(Some(why));
    while health.sleep(Duration::from_secs(1)) {
        health.beat();
    }
}

#[cfg(not(target_os = "linux"))]
fn run(session: &Shared, health: &super::Health) {
    let _ = (session, EVERY);
    idle(health, "no reader of the machine's cards on this platform");
}

#[cfg(target_os = "linux")]
fn run(session: &Shared, health: &super::Health) {
    use corerouter_hal_linux::nic_scan::{NicScanner, Paths};
    if lock(session).backend().starts_with("virtual lab") {
        return idle(health, "the virtual lab's own cards (--backend linux reads this machine's)");
    }
    let mut scanner = NicScanner::new(Paths::default());
    loop {
        health.beat();
        let reading = scanner.scan();
        let devices = reading.devices.len();
        lock(session).nic_reading_feed(reading);
        health.event(format!("{devices} network devices"));
        // Sleeps in slices so a stop is prompt.
        if !health.sleep(EVERY) {
            return;
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use corerouter_engine::{Session, shared};

    use super::*;

    #[test]
    fn idles_on_the_virtual_lab() {
        let session = shared(Session::virtual_lab());
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        health.stop();
        run(&session, &health);
        assert!(health.snapshot().disabled.is_some_and(|d| d.contains("virtual lab")));
    }
}

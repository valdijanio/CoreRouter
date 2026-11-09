//! G4.6b: in a `--map-root-user` namespace the clock is out of reach. The
//! kernel checks `capable(CAP_SYS_TIME)` against the initial user namespace
//! (`timekeeping_validate_timex`, kernel 6.18), so every change is `EPERM`
//! and the host's clock cannot move, whoever runs this. The real changes are
//! tested in `clock_root.rs`, in the lab VM.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_clock
//! ```
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, SystemTime};

use corerouter_hal::clock::{ClockError, SystemClock};
use corerouter_hal_linux::clock::LinuxClock;

#[test]
fn a_user_namespace_cannot_touch_the_clock() {
    if std::env::var_os("COREROUTER_NETNS_TESTS").is_none_or(|v| v != "1") {
        eprintln!("skipped: run with COREROUTER_NETNS_TESTS=1 (cargo xtask netns)");
        return;
    }
    let mut clock = LinuxClock::realtime();
    let frequency = clock.frequency_ppm().expect("reading needs no capability");

    let before = SystemTime::now();
    assert_eq!(clock.step(3_600_000_000_000), Err(ClockError::NoPermission));
    assert_eq!(
        clock.step(-3_600_000_000_000),
        Err(ClockError::NoPermission)
    );
    let after = SystemTime::now();
    let moved = after.duration_since(before).unwrap();
    assert!(
        moved < Duration::from_secs(60),
        "the clock moved by {moved:?}"
    );

    assert_eq!(
        clock.set_frequency_ppm(100.0),
        Err(ClockError::NoPermission)
    );
    assert_eq!(clock.frequency_ppm(), Ok(frequency));
    assert_eq!(
        clock.synchronized(1_000, 1_000),
        Err(ClockError::NoPermission)
    );
    assert_eq!(clock.take_over(), Err(ClockError::NoPermission));
}

//! G4.6b: the real clock, as root, in the lab VM only. Moves `CLOCK_REALTIME`
//! and puts it back; never run it on a machine that matters.
//!
//! ```sh
//! cargo xtask vm-lab run -- 'systemctl stop systemd-timesyncd chrony; \
//!     COREROUTER_CLOCK_ROOT=1 cargo test -p corerouter-hal-linux --test clock_root -- --test-threads=1'
//! ```
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_hal::clock::{HardwareClock, SystemClock};
use corerouter_hal_linux::clock::LinuxClock;
use rustix::time::{ClockId, clock_gettime};

fn enabled() -> bool {
    let on = std::env::var_os("COREROUTER_CLOCK_ROOT").is_some_and(|v| v == "1");
    if !on {
        eprintln!("skipped: lab VM only, set COREROUTER_CLOCK_ROOT=1");
    }
    on
}

/// Nanoseconds on the crystal, which no adjustment moves.
fn raw() -> i128 {
    let t = clock_gettime(ClockId::MonotonicRaw);
    i128::from(t.tv_sec) * 1_000_000_000 + i128::from(t.tv_nsec)
}

fn wall() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap())
        .unwrap()
}

/// Wall clock minus the crystal.
fn gap() -> i128 {
    wall() - raw()
}

#[test]
fn steps_move_the_clock_by_exactly_that_much() {
    if !enabled() {
        return;
    }
    let mut clock = LinuxClock::realtime();
    clock.take_over().unwrap();
    for offset in [250_000_000i64, -250_000_000, -1_750_000_000, 1_750_000_000] {
        let before = gap();
        clock.step(offset).unwrap();
        let moved = gap() - before;
        let error = (moved - i128::from(offset)).abs();
        eprintln!("step {offset} ns: moved {moved} ns, error {error} ns");
        // Scheduling between the two readings, not the step.
        assert!(error < 5_000_000, "step {offset}: moved {moved}");
    }
}

#[test]
fn frequency_makes_the_clock_run_fast_and_slow() {
    if !enabled() {
        return;
    }
    let mut clock = LinuxClock::realtime();
    clock.take_over().unwrap();
    clock.set_frequency_ppm(0.0).unwrap();
    sleep(Duration::from_millis(100));
    let idle = {
        let a = gap();
        sleep(Duration::from_secs(5));
        (gap() - a) as f64 / 5e3
    };
    for ppm in [300.0, -300.0] {
        clock.set_frequency_ppm(ppm).unwrap();
        assert!((clock.frequency_ppm().unwrap() - ppm).abs() < 0.01);
        let a = gap();
        sleep(Duration::from_secs(5));
        let rate = (gap() - a) as f64 / 5e3 - idle;
        eprintln!("asked {ppm} ppm: ran {rate:.1} ppm (idle {idle:.1})");
        assert!((rate - ppm).abs() < 15.0, "asked {ppm}, ran {rate}");
    }
    clock.set_frequency_ppm(0.0).unwrap();
    // The values above the kernel's limit are clamped, not an error.
    clock.set_frequency_ppm(5000.0).unwrap();
    assert!(clock.frequency_ppm().unwrap() <= 500.0);
    clock.set_frequency_ppm(0.0).unwrap();
    clock
        .synchronized(1_000_000, 10_000_000, HardwareClock::Follow)
        .unwrap();
}

/// The RTC, in seconds since 1970 as the kernel reads it (as UTC).
fn rtc() -> i64 {
    std::fs::read_to_string("/sys/class/rtc/rtc0/since_epoch")
        .expect("the lab VM has an RTC")
        .trim()
        .parse()
        .unwrap()
}

fn wall_secs() -> i64 {
    i64::try_from(wall() / 1_000_000_000).unwrap()
}

/// Waits until the kernel's RTC write would have run: `ntp_notify_cmos_timer`
/// queues `sync_hw_clock` at once, which waits for the right half second
/// (kernel 6.18 `kernel/time/ntp.c`); 3 s covers it.
fn rtc_after_sync() -> i64 {
    sleep(Duration::from_secs(3));
    rtc() - wall_secs()
}

/// G4.6o: `LeaveAlone` sets the clock and never the RTC; `Follow` lets the
/// kernel write it (the installed router, as before).
#[test]
fn leave_alone_keeps_the_rtc_and_follow_writes_it() {
    if !enabled() {
        return;
    }
    let mut clock = LinuxClock::realtime();
    clock.take_over().unwrap();
    clock.set_frequency_ppm(0.0).unwrap();
    // Start from an RTC that agrees with the system clock.
    clock
        .synchronized(1_000_000, 10_000_000, HardwareClock::Follow)
        .unwrap();
    let start = rtc_after_sync();
    eprintln!("RTC − system at the start: {start} s");
    assert!(start.abs() <= 2, "the RTC should follow: {start} s");

    // 100 s forward, as the live image's first sync of a 2 h 50 min RTC.
    clock.step(100_000_000_000).unwrap();
    clock
        .synchronized(1_000_000, 10_000_000, HardwareClock::LeaveAlone)
        .unwrap();
    let left = rtc_after_sync();
    eprintln!("LeaveAlone after +100 s: RTC − system = {left} s");
    assert!((left + 100).abs() <= 2, "the RTC moved: {left} s");

    // Follow: the kernel writes it.
    clock
        .synchronized(1_000_000, 10_000_000, HardwareClock::Follow)
        .unwrap();
    let followed = rtc_after_sync();
    eprintln!("Follow: RTC − system = {followed} s");
    assert!(followed.abs() <= 2, "the RTC did not follow: {followed} s");

    // Put the clock and the RTC back.
    clock.step(-100_000_000_000).unwrap();
    clock
        .synchronized(1_000_000, 10_000_000, HardwareClock::Follow)
        .unwrap();
    let back = rtc_after_sync();
    eprintln!("back: RTC − system = {back} s");
    assert!(back.abs() <= 2, "{back} s");
}

//! The real clock (G4.6b), through `clock_adjtime` on `CLOCK_REALTIME`.
//!
//! Kernel 6.18 `kernel/time/timekeeping.c`, `timekeeping_validate_timex`:
//! every change needs `capable(CAP_SYS_TIME)`, which looks at the initial
//! user namespace. So a `--map-root-user` namespace gets `EPERM` and cannot
//! move the host's clock (`tests/netns_clock.rs` holds that), and a time
//! namespace does not help either: it only shifts `CLOCK_MONOTONIC` and
//! `CLOCK_BOOTTIME`, never `CLOCK_REALTIME`.
//!
//! - `ADJ_FREQUENCY` (`time_freq` in `kernel/time/ntp.c`) keeps its value
//!   with `STA_PLL` off and is clamped to ±500 ppm;
//! - `ADJ_SETOFFSET` is one relative step in the kernel, without the
//!   read-add-write race of `clock_settime`;
//! - clearing `STA_UNSYNC` turns on the kernel's 11-minute write to the
//!   hardware clock (`sync_hw_clock`, with `CONFIG_RTC_SYSTOHC`), and
//!   `time_maxerror` puts it back by itself after 16 s of accumulated error
//!   (`NTP_PHASE_LIMIT`), so a client that went silent stops claiming sync.

use std::time::Duration;

use clock_steering::unix::{Error, UnixClock};
use clock_steering::{Clock, LeapIndicator, TimeOffset};
use corerouter_hal::clock::{ClockError, SystemClock};

/// `CLOCK_REALTIME`.
pub struct LinuxClock(UnixClock);

impl LinuxClock {
    pub fn realtime() -> Self {
        Self(UnixClock::CLOCK_REALTIME)
    }

    /// The kernel's current frequency, in ppm (reading needs no capability).
    pub fn frequency_ppm(&self) -> Result<f64, ClockError> {
        self.0.get_frequency().map_err(error)
    }
}

fn error(e: Error) -> ClockError {
    match e {
        Error::NoPermission => ClockError::NoPermission,
        other => ClockError::Other(other.to_string()),
    }
}

/// `tv_sec` + a non-negative `tv_nsec`, as `ADJ_SETOFFSET` requires
/// (`timekeeping_validate_timex`): −0.2 s is −1 s + 800 000 000 ns.
fn split(offset_nanos: i64) -> TimeOffset {
    TimeOffset {
        seconds: offset_nanos.div_euclid(1_000_000_000),
        nanos: u32::try_from(offset_nanos.rem_euclid(1_000_000_000)).unwrap_or(0),
    }
}

impl SystemClock for LinuxClock {
    fn take_over(&mut self) -> Result<(), ClockError> {
        self.0.disable_kernel_ntp_algorithm().map_err(error)
    }

    fn set_frequency_ppm(&mut self, ppm: f64) -> Result<(), ClockError> {
        self.0.set_frequency(ppm).map(|_| ()).map_err(error)
    }

    fn step(&mut self, offset_nanos: i64) -> Result<(), ClockError> {
        self.0
            .step_clock(split(offset_nanos))
            .map(|_| ())
            .map_err(error)
    }

    fn synchronized(&mut self, estimated_nanos: u64, maximum_nanos: u64) -> Result<(), ClockError> {
        self.0
            .set_leap_seconds(LeapIndicator::NoWarning)
            .map_err(error)?;
        self.0
            .error_estimate_update(
                Duration::from_nanos(estimated_nanos),
                Duration::from_nanos(maximum_nanos),
            )
            .map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_offsets_have_a_positive_fraction() {
        let s = split(-200_000_000);
        assert_eq!((s.seconds, s.nanos), (-1, 800_000_000));
        let s = split(1_500_000_000);
        assert_eq!((s.seconds, s.nanos), (1, 500_000_000));
        let s = split(-2_000_000_000);
        assert_eq!((s.seconds, s.nanos), (-2, 0));
        let s = split(i64::MIN);
        assert!(s.nanos < 1_000_000_000);
    }
}

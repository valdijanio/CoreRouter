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
//!   (`NTP_PHASE_LIMIT`), so a client that went silent stops claiming sync;
//! - G4.6o: kernel 6.18.59 `kernel/time/ntp.c`, `sync_hw_clock` (line 643)
//!   and `ntp_notify_cmos_timer` (line 683) write the RTC only when
//!   `ntp_synced()`, both through `update_persistent_clock64` (x86 CMOS,
//!   `CONFIG_GENERIC_CMOS_UPDATE`) and `update_rtc` (`CONFIG_RTC_SYSTOHC`).
//!   So [`HardwareClock::LeaveAlone`] keeps `STA_UNSYNC` set: the system
//!   clock is still stepped and slewed, the RTC is never written. A step
//!   (`ADJ_SETOFFSET`) sets `STA_UNSYNC` by itself (`ntp_clear`, through
//!   `TK_CLEAR_NTP` in `timekeeping.c`), so nothing else clears it.

use std::time::Duration;

use clock_steering::unix::{Error, UnixClock};
use clock_steering::{Clock, LeapIndicator, TimeOffset};
use corerouter_hal::clock::{ClockError, HardwareClock, SystemClock};

/// The first RTC's time as the kernel reads it (`rtc_cmos` and the rest
/// take the chip as UTC), world-readable, never written here (G4.6p).
pub const RTC_SINCE_EPOCH: &str = "/sys/class/rtc/rtc0/since_epoch";

/// Seconds since 1970 in an RTC's `since_epoch` (a few bytes, read whole).
pub fn read_rtc(path: &std::path::Path) -> Result<i64, corerouter_hal::HalError> {
    use corerouter_hal::HalError;
    let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => HalError::Unsupported("this machine has no RTC".into()),
        _ => HalError::Io(format!("{}: {e}", path.display())),
    })?;
    let t = text.trim();
    t.parse()
        .map_err(|_| HalError::Io(format!("{}: not a number: {:.32}", path.display(), t)))
}

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

    fn synchronized(
        &mut self,
        estimated_nanos: u64,
        maximum_nanos: u64,
        hardware: HardwareClock,
    ) -> Result<(), ClockError> {
        // `set_leap_seconds` writes the status bits: `NoWarning` clears
        // STA_UNSYNC (the RTC follows), `Unknown` sets it (left alone); both
        // clear the leap bits (clock-steering 0.2.1, `unix.rs` line 440).
        let leap = match hardware {
            HardwareClock::Follow => LeapIndicator::NoWarning,
            HardwareClock::LeaveAlone => LeapIndicator::Unknown,
        };
        self.0.set_leap_seconds(leap).map_err(error)?;
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
    fn the_rtc_reads_whole_seconds_and_says_why_not() {
        let dir = std::env::temp_dir().join(format!("cr-rtc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("since_epoch");
        std::fs::write(&f, "1794450000\n").unwrap();
        assert_eq!(read_rtc(&f), Ok(1_794_450_000));
        std::fs::write(&f, "garbage").unwrap();
        assert!(matches!(read_rtc(&f), Err(corerouter_hal::HalError::Io(_))));
        assert!(matches!(
            read_rtc(&dir.join("absent")),
            Err(corerouter_hal::HalError::Unsupported(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

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

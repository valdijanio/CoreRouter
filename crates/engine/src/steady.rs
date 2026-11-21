//! The clock of deadlines and elapsed times (G0.13).
//!
//! The wall clock (`Hal::now_unix`) jumps when NTP steps it: a router
//! without a battery-backed clock boots in 1970 and jumps 56 years ahead
//! at its first NTP answer; a wrong server or an operator can step it back.
//! Measured against it, a step ahead ends every countdown at once (tasks
//! "abandoned", dynamic address-list entries gone from the data plane's
//! mirror) and a step back stops them for as long as the step.
//!
//! [`Session::steady_now`] is [`Hal::monotonic_secs`](corerouter_hal::Hal::monotonic_secs)
//! when the platform has one (`CLOCK_MONOTONIC` on Linux: only elapsed
//! time moves it), else the wall clock as before. Times shown to the
//! operator (since, last seen) stay on the wall clock; only durations and
//! deadlines use this one. Values of the two clocks are never mixed: a
//! platform has a monotonic clock from start to end or never.

use crate::Session;

impl Session {
    /// Seconds on the clock of deadlines: monotonic when the platform has
    /// one, else the wall clock; `None` without either (the wasm lab).
    pub fn steady_now(&self) -> Option<u64> {
        self.hal().monotonic_secs().or_else(|| self.now())
    }
}

//! The system clock as the NTP client sees it (G4.6b). The policy (when to
//! slew, step or wait) is `corerouter_proto_ntp::discipline`; a backend only
//! carries it out. Calls never block.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The process lacks `CAP_SYS_TIME`.
    NoPermission,
    Other(String),
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPermission => {
                f.write_str("no permission to set the clock (needs CAP_SYS_TIME)")
            }
            Self::Other(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for ClockError {}

pub trait SystemClock: Send {
    /// Makes this client the only one steering the clock (the kernel's own
    /// loops off). Called once before the first change.
    fn take_over(&mut self) -> Result<(), ClockError>;

    /// How fast the clock runs relative to its crystal, in ppm (positive:
    /// faster). Absolute, not relative to the last call.
    fn set_frequency_ppm(&mut self, ppm: f64) -> Result<(), ClockError>;

    /// Moves the clock by `offset_nanos` at once (positive: forward).
    fn step(&mut self, offset_nanos: i64) -> Result<(), ClockError>;

    /// Tells the system the clock is synchronized, and how far off it may be.
    fn synchronized(&mut self, estimated_nanos: u64, maximum_nanos: u64) -> Result<(), ClockError>;
}

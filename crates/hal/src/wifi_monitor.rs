//! A Wi-Fi radio in monitor mode (G1.30j): every frame in the air of one
//! channel, with the radiotap header that says how it was heard. The
//! engine's snooper and its 802.11 capture read it; the platform makes the
//! monitor interface and moves it between channels.
//!
//! Two ways to get one, and the engine picks:
//! - [`MonitorMode::Shared`]: a monitor interface beside the radio's
//!   station, which stays connected. It hears the station's channel only:
//!   the kernel refuses to move a monitor while another interface of the
//!   radio is up (`cfg80211_set_monitor_channel` → `-EBUSY` unless
//!   `cfg80211_has_monitors_only`, Linux 6.18 `net/wireless/chan.c`).
//! - [`MonitorMode::Exclusive`]: the radio alone, its station down (the
//!   interface disabled in the configuration): any channel, and hopping.
//!
//! Nothing here takes a station off its network: that would cut the
//! router's management when it comes through the radio. The engine only
//! asks for `Exclusive` on a radio the configuration has disabled.

use std::sync::Arc;
use std::time::Duration;

use crate::capture::{CaptureError, FrameBatch};

/// How the monitor sits on the radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorMode {
    /// Beside the station, on its channel.
    Shared,
    /// The radio alone: any channel.
    Exclusive,
}

impl MonitorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Exclusive => "exclusive",
        }
    }
}

/// What to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSpec {
    /// The radio's interface (`wifi1`).
    pub radio: String,
    pub mode: MonitorMode,
    /// Where to start (exclusive only), MHz.
    pub freq_mhz: Option<u32>,
    /// The width to listen with (exclusive only): 20, 40, 80 or 160 MHz
    /// around each channel, as `ieee80211::center_mhz` places it. A radio
    /// on 20 MHz does not decode a wider network's data frames, only its
    /// beacons (sent on 20 MHz).
    pub width_mhz: u32,
}

/// An open monitor.
pub trait MonitorSocket: Send {
    /// Append the frames heard within `wait` to `batch`, each the radiotap
    /// header and the 802.11 frame, as [`FrameBatch`] frames (`Dir::Rx`).
    /// Like [`crate::capture::CaptureSocket::recv`]: a simulated socket
    /// does not block and says so in [`Self::blocks`].
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError>;

    /// Move to `freq_mhz`, with the spec's width (20 MHz where the plan
    /// has no wider channel there). An exclusive monitor only; a shared
    /// one, or one whose radio's station came back up, answers
    /// [`CaptureError::Unavailable`].
    fn set_channel(&mut self, freq_mhz: u32) -> Result<(), CaptureError>;

    /// The channel it is on now, MHz, when the platform knows.
    fn channel(&mut self) -> Option<u32>;

    /// The name of the monitor interface (`wifi1mon`), for the operator.
    fn interface(&self) -> String;

    /// Whether [`Self::recv`] waits for frames (false: simulated).
    fn blocks(&self) -> bool {
        true
    }
}

/// Opens monitors. Shared with task threads.
pub trait WifiMonitor: Send + Sync {
    /// "nl80211 monitor interface, AF_PACKET", "the lab's air"…
    fn describe(&self) -> String;

    fn open(&self, spec: &MonitorSpec) -> Result<Box<dyn MonitorSocket>, CaptureError>;
}

pub type SharedWifiMonitor = Arc<dyn WifiMonitor>;

/// The longest name a monitor interface gets (`IFNAMSIZ` - 1).
pub const MAX_IFNAME: usize = 15;

/// The monitor interface of radio `radio`: `<radio>mon`, cut to fit.
pub fn monitor_name(radio: &str) -> String {
    let keep = MAX_IFNAME - 3;
    let base: String = radio.chars().take(keep).collect();
    format!("{base}mon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_names_fit_the_kernel() {
        assert_eq!(monitor_name("wifi1"), "wifi1mon");
        let long = monitor_name("wlp195s0abcdefgh");
        assert_eq!(long.len(), MAX_IFNAME);
        assert!(long.ends_with("mon"));
    }
}

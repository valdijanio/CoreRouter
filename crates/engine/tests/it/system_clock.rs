//! G4.6p — `system.clock.print` on a backend with a real clock and an RTC:
//! where the time came from, and what the RTC says beside it (G4.6o: never
//! written on the live image).
#![allow(clippy::unwrap_used)]

use corerouter_engine::Session;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use corerouter_model::ntp::{ClockState, NtpState, NtpStatus};
use serde_json::{Value, json};

/// 2026-11-12 14:02:31 UTC.
const NOW: u64 = 1_794_492_151;

/// A machine whose system clock reads `NOW` and whose RTC is `rtc_off`
/// seconds from it.
struct Machine {
    inner: VirtualHal,
    rtc_off: Option<i64>,
}

impl Hal for Machine {
    fn describe(&self) -> String {
        "test machine".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.inner.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        Some(NOW)
    }
    fn hardware_clock(&self) -> Result<i64, HalError> {
        self.rtc_off
            .map(|o| NOW as i64 + o)
            .ok_or_else(|| HalError::Unsupported("no RTC".into()))
    }
}

fn session(rtc_off: Option<i64>) -> Session {
    Session::new(Box::new(Machine {
        inner: VirtualHal::new(2),
        rtc_off,
    }))
}

fn print(s: &mut Session) -> Value {
    s.execute("system.clock.print", &json!({})).unwrap()
}

fn synced(s: &mut Session) {
    s.execute(
        "system.ntp.client.set",
        &json!({"enabled": true, "servers": ["192.0.2.1"]}),
    )
    .unwrap();
    s.set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        synced_server: Some("192.0.2.1".into()),
        last_sync: Some(NOW - 60),
        clock: ClockState::Stepped,
        ..NtpStatus::default()
    });
}

/// The notebook of the audit before NTP: the RTC in Brazil's local time
/// (UTC−3) read as UTC. The time is the RTC's, and the RTC says its zone.
#[test]
fn before_ntp_the_time_is_the_rtcs_and_its_zone_shows() {
    let mut s = session(Some(-3 * 3_600));
    let r = print(&mut s);
    assert_eq!(
        (r["date"].as_str(), r["time"].as_str()),
        (Some("2026-11-12"), Some("14:02:31"))
    );
    assert_eq!(r["source"], "rtc", "{r}");
    let hw = &r["hardware_clock"];
    assert_eq!(hw["available"], true);
    assert_eq!(hw["time"], "11:02:31");
    assert_eq!(hw["offset_secs"], -10_800);
    assert_eq!(hw["local_time_offset"], "−03:00");
    assert_eq!(hw["written"], "not-written");
}

/// Installed and synchronized: the kernel writes the RTC (every ~11 min).
#[test]
fn installed_and_synced_the_rtc_follows() {
    let mut s = session(Some(0));
    synced(&mut s);
    let r = print(&mut s);
    assert_eq!(r["source"], "ntp");
    assert_eq!(r["ntp_server"], "192.0.2.1");
    assert_eq!(r["last_sync"], NOW - 60);
    assert_eq!(r["hardware_clock"]["written"], "follows-system");
    assert!(r["hardware_clock"]["local_time_offset"].is_null());
}

/// G4.6o: the live image never writes it, synchronized or not.
#[test]
fn on_the_live_image_the_rtc_is_left_alone() {
    let mut s = session(Some(-3 * 3_600));
    synced(&mut s);
    corerouter_engine::live::set(&mut s);
    let r = print(&mut s);
    assert_eq!(r["source"], "ntp");
    assert_eq!(r["hardware_clock"]["written"], "left-alone", "{r}");
}

#[test]
fn a_machine_without_rtc_says_so() {
    let mut s = session(None);
    let r = print(&mut s);
    assert_eq!(r["source"], "rtc");
    assert_eq!(r["hardware_clock"]["available"], false);
    assert_eq!(r["hardware_clock"]["written"], "none");
}

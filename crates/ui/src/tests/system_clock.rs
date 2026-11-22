//! System › Clock (G4.6p) and the Clock line of System › NTP Client.

use super::*;
use crate::system_clock::WIN;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use corerouter_model::ntp::{ClockState, NtpState, NtpStatus};

/// 2026-11-12 14:02:31 UTC.
const NOW: u64 = 1_794_492_151;

/// A machine whose RTC is in Brazil's local time (UTC−3), read as UTC.
struct Notebook(VirtualHal);

impl Hal for Notebook {
    fn describe(&self) -> String {
        "notebook".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        Some(NOW)
    }
    fn hardware_clock(&self) -> Result<i64, HalError> {
        Ok(NOW as i64 - 3 * 3_600)
    }
}

fn open(s: Session, win: Win) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(win);
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
    h
}

#[test]
fn the_clock_window_shows_the_lab_hosts_time() {
    let mut s = Session::virtual_lab();
    s.tick(NOW);
    let h = open(s, Win::Panel(WIN));
    assert!(h.has_text("14:02:31"));
    assert!(h.has_text("2026-11-12"));
    assert!(h.has_text("UTC (+00:00)"));
    assert!(h.has_text("host"), "the lab's source");
    assert!(h.has_text("none"), "the lab has no RTC");
}

/// The audit's notebook: the RTC 3 h behind in local time, the hint says
/// why; after NTP, the source is NTP and the RTC follows.
#[test]
fn the_clock_window_shows_the_rtc_and_its_zone() {
    let s = Session::new(Box::new(Notebook(VirtualHal::new(2))));
    let mut h = open(s, Win::Panel(WIN));
    assert!(h.has_text("rtc"));
    assert!(h.has_text("2026-11-12 11:02:31"));
    assert!(h.has_text("(−3 h)"));
    assert!(h.has_text("not-written"));
    assert!(h.has_text_containing("UTC−03:00"));

    {
        let mut s = lock(&h.session);
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
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.has_text("ntp"));
    assert!(h.has_text("set by the NTP client from 192.0.2.1"));
    assert!(h.has_text("follows-system"));
    assert!(h.has_text("2026-11-12 14:01:31 UTC"), "last sync");
}

#[test]
fn the_ntp_client_window_starts_with_the_clock() {
    let mut s = Session::virtual_lab();
    s.tick(NOW);
    let h = open(s, Win::Panel(crate::ntp_client::WIN));
    assert!(h.has_text("2026-11-12 14:02:31 UTC"));
    assert!(h.has_text("host"));
}

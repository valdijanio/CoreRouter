//! System › NTP Client (G4.6e), a panel: settings form and live status.

use super::*;
use crate::ntp_client::{NtpPanel, WIN, utc};
use corerouter_model::ntp::{NtpState, NtpStatus};

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn ntp_window_shows_live_status_and_applies() {
    let mut s = Session::virtual_lab();
    s.execute(
        "system.ntp.client.set",
        &json!({"enabled": true, "servers": ["pool.ntp.org", "192.0.2.1"]}),
    )
    .unwrap();
    let mut h = open(s);
    assert!(h.has_text("NTP Client"));
    assert!(h.has_text("stopped") || h.has_text("waiting"), "status row");
    let form = h.app.panel_mut::<NtpPanel>().unwrap().form.clone();
    assert!(form.enabled);
    assert_eq!(form.servers, "pool.ntp.org\n192.0.2.1");

    // The daemon reports a good round: the window follows on its own.
    lock(&h.session).set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        synced_server: Some("pool.ntp.org".into()),
        synced_address: Some("203.0.113.7".into()),
        synced_stratum: Some(2),
        system_offset_ms: Some(-1.25),
        round_trip_ms: Some(12.5),
        last_sync: Some(1_792_674_309),
        last_error: None,
        poll_secs: Some(64),
    });
    refresh(&mut h);
    assert!(h.has_text("synchronized"));
    assert!(h.has_text("pool.ntp.org (203.0.113.7)"));
    assert!(h.has_text("-1.250 ms"));
    assert!(h.has_text("2026-10-22 13:05:09 UTC"));

    // Edit the servers and Apply: the engine has them.
    h.app.panel_mut::<NtpPanel>().unwrap().form.servers = "time.example.net".into();
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let got = lock(&h.session)
        .execute("system.ntp.client.get", &Value::Null)
        .unwrap();
    assert_eq!(got["servers"], json!(["time.example.net"]), "{:?}", h.app.log());
    let p = h.app.panel_mut::<NtpPanel>().unwrap();
    assert_eq!(p.form.servers, "time.example.net", "form follows the router");
    assert!(p.error.is_none());
}

#[test]
fn ntp_window_keeps_the_edit_and_shows_the_refusal() {
    let mut h = open(Session::virtual_lab());
    h.app.panel_mut::<NtpPanel>().unwrap().form.min_poll = "20".into();
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let p = h.app.panel_mut::<NtpPanel>().unwrap();
    let err = p.error.clone().unwrap_or_default();
    assert!(err.contains("min_poll"), "{err}");
    assert_eq!(p.form.min_poll, "20", "the typed value stays after a refresh");
    assert!(h.has_text_containing("min_poll"), "error shown under the form");
    // Revert puts back what the router has.
    h.click(h.text("Revert"));
    assert_eq!(h.app.panel_mut::<NtpPanel>().unwrap().form.min_poll, "6");
}

#[test]
fn utc_formats_unix_seconds() {
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(utc(1_792_674_309), "2026-10-22 13:05:09 UTC");
}

//! System › NTP Client (G4.6e), a panel: settings form and live status.

use super::*;
use crate::ntp_client::{NtpPanel, WIN, utc};
use corerouter_model::ntp::{ClockState, NtpState, NtpStatus};

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
        ..NtpStatus::default()
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

/// G4.6b: the clock's state, the drift and the confirmation of a big step.
#[test]
fn ntp_window_shows_the_clock_and_confirms_a_step() {
    let mut s = Session::virtual_lab();
    s.execute(
        "system.ntp.client.set",
        &json!({"enabled": true, "servers": ["192.0.2.1"]}),
    )
    .unwrap();
    s.set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        clock: ClockState::Slewing,
        last_adjustment_ms: Some(3.5),
        freq_drift_ppm: Some(12.25),
        dynamic_servers: vec!["198.51.100.9".into()],
        ..NtpStatus::default()
    });
    let mut h = open(s);
    assert!(h.has_text("slewing"));
    assert!(h.has_text("3.500 ms"));
    assert!(h.has_text("+12.250 ppm"));
    assert!(h.has_text("198.51.100.9"));
    assert!(!h.has_text("Confirm Clock Step"), "nothing to confirm");

    lock(&h.session).set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        clock: ClockState::AwaitingConfirmation,
        pending_step_ms: Some(5_000_000.0),
        clock_error: Some("no permission".into()),
        ..NtpStatus::default()
    });
    refresh(&mut h);
    assert!(h.has_text("awaiting-confirmation"));
    assert!(h.has_text_containing("+5000 s"));
    assert!(h.has_text("no permission"));
    h.click(h.text("Confirm Clock Step"));
    refresh(&mut h);
    assert!(
        lock(&h.session).take_ntp_step_confirmation(),
        "the button confirmed: {:?}",
        h.app.log()
    );
}

/// G4.6b: VRF and Set System Clock go to the engine.
#[test]
fn ntp_window_applies_vrf_and_clock_switch() {
    let mut s = Session::virtual_lab();
    s.execute("ip.vrf.add", &json!({"name": "red"})).unwrap();
    let mut h = open(s);
    let p = h.app.panel_mut::<NtpPanel>().unwrap();
    assert!(p.form.set_system_clock, "on by default");
    p.form.vrf = "red".into();
    p.form.set_system_clock = false;
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let got = lock(&h.session)
        .execute("system.ntp.client.get", &Value::Null)
        .unwrap();
    assert_eq!(got["vrf"], "red", "{:?}", h.app.log());
    assert_eq!(got["set_system_clock"], false);
}

#[test]
fn utc_formats_unix_seconds() {
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(utc(1_792_674_309), "2026-10-22 13:05:09 UTC");
}

//! System › NTP Server (G4.6c), a panel: settings form and live counters.

use super::*;
use crate::ntp_server::{NtpServerPanel, WIN};
use corerouter_model::ntp::{NtpServerStats, NtpServing};

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
fn window_shows_the_state_and_applies() {
    let mut h = open(Session::virtual_lab());
    assert!(h.has_text("NTP Server"));
    let form = h.app.panel_mut::<NtpServerPanel>().unwrap().form.clone();
    assert!(!form.enabled, "off by default");
    assert!(form.rate_limit);
    assert_eq!(form.local_clock_stratum, "5");
    assert!(form.allowed.contains("192.168.0.0/16"));

    lock(&h.session).set_ntp_server_stats(NtpServerStats {
        listening: true,
        serving: NtpServing::Upstream,
        stratum: Some(3),
        requests: 1234,
        replies: 1200,
        kisses: 7,
        ..NtpServerStats::default()
    });
    refresh(&mut h);
    assert!(h.has_text("upstream"));
    assert!(h.has_text("1234"));
    assert!(h.has_text("7"));
    assert!(!h.has_text("Empty Lists"));
    lock(&h.session).set_ntp_server_stats(NtpServerStats {
        empty_lists: vec!["ghost".into()],
        ..NtpServerStats::default()
    });
    refresh(&mut h);
    assert!(h.has_text("ghost"), "a list that lets nobody in is shown");

    let p = h.app.panel_mut::<NtpServerPanel>().unwrap();
    p.form.enabled = true;
    p.form.allowed = "10.0.0.0/8\nlan-clients".into();
    p.form.use_local_clock = true;
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let got = lock(&h.session)
        .execute("system.ntp.server.get", &Value::Null)
        .unwrap();
    assert_eq!(got["enabled"], true, "{:?}", h.app.log());
    assert_eq!(got["use_local_clock"], true);
    assert_eq!(got["allowed"], json!(["10.0.0.0/8", "lan-clients"]));
}

#[test]
fn window_keeps_the_edit_and_shows_the_refusal() {
    let mut h = open(Session::virtual_lab());
    h.app.panel_mut::<NtpServerPanel>().unwrap().form.local_clock_stratum = "16".into();
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let p = h.app.panel_mut::<NtpServerPanel>().unwrap();
    let err = p.error.clone().unwrap_or_default();
    assert!(err.contains("1..=15"), "{err}");
    assert_eq!(p.form.local_clock_stratum, "16", "the typed value stays");
    h.click(h.text("Revert"));
    assert_eq!(
        h.app.panel_mut::<NtpServerPanel>().unwrap().form.local_clock_stratum,
        "5"
    );
}

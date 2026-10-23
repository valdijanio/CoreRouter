//! System › Analytics (G4.4f), a panel: exporter state, settings, schema.

use super::*;
use crate::analytics::{AnalyticsPanel, Form, Tab, WIN};
use corerouter_model::analytics::{AnalyticsState, AnalyticsStatus};

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn analytics_window_applies_settings_without_showing_secrets() {
    let mut h = open(Session::virtual_lab());
    assert!(h.has_text("Analytics"));
    assert!(h.has_text("stopped"), "state chip");
    assert!(h.has_text("no rule"), "logs on, no logging rule yet");
    {
        let p = h.app.panel_mut::<AnalyticsPanel>().unwrap();
        p.form.url = "https://ch.isp.example:8443".into();
        p.form.password = "s3cret-pw".into();
        p.form.enabled = true;
        p.form.batch_size = "20000".into();
    }
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let got = lock(&h.session).execute("system.analytics.print", &json!({})).unwrap();
    assert_eq!(got["url"], "https://ch.isp.example:8443", "{:?}", h.app.log());
    assert_eq!(got["batch_size"], 20000);
    assert_eq!(got["password"], "***");
    assert_eq!(lock(&h.session).store().running().system.analytics.password, "s3cret-pw");
    let p = h.app.panel_mut::<AnalyticsPanel>().unwrap();
    assert!(p.form.password.is_empty(), "the field empties after Apply");
    assert!(p.error.is_none(), "{:?}", p.error);
    assert!(p.form.set_params(&Form::default()).is_some());

    // Add rules: the four levels go to the analytics action.
    h.click(h.text("Add rules"));
    refresh(&mut h);
    let rules = lock(&h.session).execute("system.logging.list", &json!({})).unwrap();
    let n = rules.as_array().unwrap().iter().filter(|r| r["action"] == "analytics").count();
    assert_eq!(n, 4, "{rules}");
    assert!(!h.has_text("no rule"));
}


#[test]
fn analytics_window_shows_the_exporter_status_and_test() {
    let mut s = Session::virtual_lab();
    s.execute("system.analytics.set", &json!({"url": "http://192.0.2.20:8123", "enabled": true}))
        .unwrap();
    let mut h = open(s);
    // The lab has no exporter: Test Connection is off, with the reason.
    assert!(lock(&h.session).execute("system.analytics.test", &json!({})).is_err());
    if let Some(st) = lock(&h.session).ext_mut::<AnalyticsStatus>() {
        st.exporter = true;
        st.state = AnalyticsState::Retrying;
        st.dropped_rows = 12;
        st.queued_rows = 3400;
        st.queued_bytes = 2 << 20;
        st.retries = 5;
        st.retry_in = Some(16);
        st.last_error = Some("logs: 192.0.2.20:8123: Connection refused".into());
        st.test.requested = 1;
        st.test.done = 1;
        st.test.message = "ClickHouse 26.9.25.15: connected, schema in place".into();
        st.test.ok = true;
        st.test.ms = 4;
    }
    refresh(&mut h);
    for t in ["retrying", "dropped 12", "retry in 16 s", "3400 rows, 2.0 MiB", "logs: 192.0.2.20:8123: Connection refused", "schema in place (4 ms)"] {
        assert!(h.has_text_containing(t), "{t}");
    }
    h.click(h.text("Test Connection"));
    refresh(&mut h);
    let st = lock(&h.session).execute("system.analytics.print", &json!({})).unwrap();
    assert_eq!(st["test"]["requested"], 2);
    assert!(h.has_text("testing…"));
}

#[test]
fn analytics_schema_tab_shows_the_sql() {
    let mut h = open(Session::virtual_lab());
    h.app.panel_mut::<AnalyticsPanel>().unwrap().tab = Tab::Schema;
    refresh(&mut h);
    refresh(&mut h);
    let sql = h.app.panel_mut::<AnalyticsPanel>().unwrap().schema.clone().unwrap();
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS corerouter.nat_events"));
    assert!(h.has_text("Copy"));
}

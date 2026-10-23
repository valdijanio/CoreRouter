//! System › Services (G0.10), a panel: rows from the supervisor, chips,
//! selection, detail and the actions.

use super::*;
use crate::services::{ServicesPanel, WIN};
use corerouter_model::service::{
    Listen, ServiceAction, ServiceRow, ServiceState, ServiceTable,
};

fn supervised() -> Session {
    let mut s = Session::virtual_lab();
    if let Some(t) = s.ext_mut::<ServiceTable>() {
        t.supervised = true;
        t.rows = vec![
            ServiceRow {
                name: "control".into(),
                state: ServiceState::Running,
                uptime_secs: Some(3_700),
                listen: vec![Listen::new("tcp", "127.0.0.1:7979".parse().unwrap())],
                protected: true,
                topic: "system".into(),
                enable: "corerouter-daemon --control".into(),
                ..ServiceRow::default()
            },
            ServiceRow {
                name: "dns-server".into(),
                state: ServiceState::Running,
                uptime_secs: Some(61),
                restarts: 2,
                threads: 3,
                heartbeat_age_ms: Some(400),
                listen: vec![
                    Listen::new("udp", "0.0.0.0:53".parse().unwrap()),
                    Listen::new("tcp", "0.0.0.0:53".parse().unwrap()),
                ],
                last_event: "started".into(),
                depends: vec!["dns-resolver".into()],
                enable: "ip.dns.set allow_remote_requests=yes".into(),
                topic: "dns".into(),
                policy: "always; wait 1 s → 60 s".into(),
                ..ServiceRow::default()
            },
            ServiceRow {
                name: "ntp-client".into(),
                state: ServiceState::Failed,
                restarts: 4,
                last_event: "gave up: 5 failures in 60 s".into(),
                last_error: Some("bind: address in use".into()),
                topic: "ntp".into(),
                ..ServiceRow::default()
            },
        ];
    }
    s.log_event(&["dns", "info"], "daemon", "DNS: answering the LAN".into(), Value::Null);
    s
}

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
fn services_window_lists_rows_with_chips() {
    let mut h = open(supervised());
    assert!(h.has_text("Services"));
    assert!(h.has_text("dns-server"));
    assert!(h.has_text("2 running"), "summary chip");
    assert!(h.has_text("1 failed"));
    assert!(h.has_text("failed"), "state chip");
    assert!(h.has_text("udp 0.0.0.0:53"));
    assert!(h.has_text("all"), "reach chip of 0.0.0.0");
    assert!(h.has_text("local"), "reach chip of loopback");
    assert!(h.has_text("+1"));
    assert!(h.has_text("00:01:01"), "uptime");
    let p = h.app.panel_mut::<ServicesPanel>().unwrap();
    assert_eq!(p.summary(), (2, 0, 1));

    // Select a row: the detail and its log topic.
    h.click(h.text("dns-server"));
    refresh(&mut h);
    assert_eq!(
        h.app.panel_mut::<ServicesPanel>().unwrap().selected.as_deref(),
        Some("dns-server")
    );
    assert!(h.has_text("ip.dns.set allow_remote_requests=yes"));
    assert!(h.has_text("dns-resolver"), "depends on");
    assert!(h.has_text("0.4 s ago"), "heartbeat");
    assert!(h.has_text("Log · dns"));
    assert!(h.has_text("DNS: answering the LAN"));

    // Restart reaches the supervisor's queue.
    h.click(h.text("Restart"));
    refresh(&mut h);
    let queued: Vec<_> = lock(&h.session)
        .ext::<ServiceTable>()
        .unwrap()
        .requests
        .iter()
        .map(|r| (r.name.clone(), r.action))
        .collect();
    assert_eq!(queued, [("dns-server".to_owned(), ServiceAction::Restart)]);
    // The window says the command went (the row follows with the refresh).
    assert!(h.has_text("restart sent to dns-server"));
}

#[test]
fn control_cannot_be_stopped_from_the_window() {
    let mut h = open(supervised());
    h.click(h.text("control"));
    refresh(&mut h);
    h.click(h.text("Stop"));
    refresh(&mut h);
    assert!(
        lock(&h.session).ext::<ServiceTable>().unwrap().requests.is_empty(),
        "Stop is greyed out for a protected service"
    );
}

#[test]
fn without_a_daemon_the_window_says_so() {
    let h = open(Session::virtual_lab());
    assert!(h.has_text(
        "No supervised services: this session has no daemon (lab or browser). \
         Connect to corerouter-daemon to see them."
    ));
}

/// A service its config keeps off: Start is grey with why; Enable turns the
/// switch on through the config command; Open settings opens its window.
#[test]
fn a_service_off_in_the_config_offers_enable_and_settings() {
    let mut s = Session::virtual_lab();
    if let Some(t) = s.ext_mut::<ServiceTable>() {
        t.supervised = true;
        t.rows = vec![ServiceRow {
            name: "dns-server".into(),
            state: ServiceState::Disabled,
            reason: Some("ip.dns allow_remote_requests=no".into()),
            enable: "ip.dns.set allow_remote_requests=yes".into(),
            turn_on: Some(json!({"id": "ip.dns.set", "params": {"allow_remote_requests": true}})),
            topic: "dns".into(),
            ..ServiceRow::default()
        }];
    }
    let mut h = open(s);
    h.click(h.text("dns-server"));
    refresh(&mut h);
    h.tooltip_at(h.text("Start"));
    assert!(h.has_text_containing("its config turns it off"), "Start explains");
    h.click(h.text("Enable"));
    refresh(&mut h);
    let on = lock(&h.session)
        .execute("ip.dns.get", &json!({}))
        .unwrap()["allow_remote_requests"]
        .clone();
    assert_eq!(on, json!(true), "Enable ran ip.dns.set");
    assert!(h.has_text_containing("turned on in the config"));
    h.click(h.text("Open settings"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(crate::dns::WIN)));
}

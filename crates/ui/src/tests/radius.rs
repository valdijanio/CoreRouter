//! RADIUS (G4.3j): servers in the list pattern, the modal, Incoming,
//! Monitor and the Test dialog against a stand-in AAA service.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
use corerouter_engine::{Clock, Job, Runner};
use corerouter_model::ItemId;
use corerouter_model::radius::{
    AcctRequest, Attribute, AuthOutcome, AuthReply, AuthRequest, RadiusStatus, ServerMonitor,
    ServerState,
};
use serde_json::json;

use super::*;
use crate::radius::{RadiusPanel, Tab, WIN};

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

/// The daemon's AAA service, as the window sees it.
struct Fake;

fn monitor(id: u32, state: ServerState, accepts: u64, timeouts: u64) -> ServerMonitor {
    let mut m: ServerMonitor = serde_json::from_value(json!({
        "id": format!("*{id}"), "address": null, "state": "up", "pending": 0, "requests": accepts + timeouts,
        "accepts": accepts, "rejects": 1, "acct_responses": 4, "resends": 2, "timeouts": timeouts,
        "bad_replies": 0, "unsolicited": 0, "last_request_rtt": 3, "sockets": 1}))
    .unwrap();
    m.state = state;
    m
}

impl AaaBackend for Fake {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        let mut r = AuthReply::failed(AuthOutcome::Accept, "");
        r.message = None;
        r.server = Some(ItemId(1));
        r.server_address = Some("10.0.0.10".parse().unwrap());
        r.rtt_ms = Some(4);
        r.attributes = vec![
            Attribute::new("Mikrotik-Rate-Limit", "50M/100M"),
            Attribute::new("Framed-IP-Address", "100.64.0.20"),
            Attribute::new("User-Name", req.user),
        ];
        done(r);
    }
    fn account(&self, _: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        Ok(())
    }
    fn register_owner(&self, _: Arc<dyn SessionOwner>) {}
    fn status(&self) -> RadiusStatus {
        let mut st = RadiusStatus {
            servers: vec![monitor(1, ServerState::Up, 120, 0), monitor(2, ServerState::Probing, 0, 9)],
            ..RadiusStatus::default()
        };
        st.incoming.listening = Some("udp [::]:3799".into());
        st.incoming.requests = 5;
        st.incoming.naks = 5;
        st
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.execute("radius.add", &json!({"address": "10.0.0.10", "service": "ppp,login", "secret": "s3cr3t", "status_server": true}))
        .unwrap();
    s.execute("radius.add", &json!({"address": "10.0.0.11", "service": "ppp", "secret": "s3cr3t", "timeout": 3000, "comment": "backup DC"}))
        .unwrap();
    s.execute("radius.add", &json!({"address": "10.9.9.9", "service": "hotspot", "secret": "x", "disabled": true}))
        .unwrap();
    s.set_aaa_backend(Arc::new(Fake));
    s
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn servers_show_state_services_and_a_hidden_secret() {
    let mut h = open(lab());
    assert!(h.has_text("RADIUS"));
    assert!(h.has_text("10.0.0.10"));
    assert!(h.has_text_containing("backup DC"));
    let p = h.app.panel_mut::<RadiusPanel>().unwrap();
    assert_eq!(p.servers.len(), 3);
    assert!(p.servers.iter().all(|r| r["secret"] == "***"));
    let rows: Vec<_> = p.servers.clone().iter().map(|r| p.server_row(r)).collect();
    let state = |i: usize| crate::chip::split(&rows[i].cells[0]).1;
    assert_eq!(state(0), vec![(crate::chip::Kind::Green, "up")]);
    assert_eq!(state(1), vec![(crate::chip::Kind::Amber, "probing")]);
    assert_eq!(state(2), vec![(crate::chip::Kind::Neutral, "disabled")]);
    assert!(rows[2].dimmed);
    let services = crate::chip::split(&rows[0].cells[2]).1;
    assert_eq!(services.iter().map(|(_, t)| *t).collect::<Vec<_>>(), ["ppp", "login"]);
    assert!(rows[1].cells[4].contains("3000 ms"));
}

#[test]
fn the_modal_adds_a_server_through_the_preview() {
    let mut h = open(lab());
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<RadiusPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, crate::list::Act::Add, ui));
        })
        .unwrap();
    h.idle();
    {
        let p = h.app.panel_mut::<RadiusPanel>().unwrap();
        let m = p.modal.as_mut().expect("the modal is open");
        m.values.insert("address", "10.0.0.12".into());
        m.values.insert("secret", "novo".into());
        m.values.insert("timeout", "2000".into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.app.panel_mut::<RadiusPanel>().unwrap().modal.as_ref().and_then(|m| m.preview.clone()).is_none_or(|p| p["commands"].as_array().is_none_or(Vec::is_empty)) {
        assert!(Instant::now() < deadline);
        h.time += 0.5;
        h.idle();
    }
    assert!(h.has_text_containing("New RADIUS Server"));
    let pv = h.app.panel_mut::<RadiusPanel>().unwrap().modal.as_ref().and_then(|m| m.preview.clone());
    assert!(h.has_text_containing("ppp #3"), "the failover position: {pv:?}");
    // The secret never shows in the preview of the commands.
    assert!(!h.has_text_containing("novo"));
    for _ in 0..30 {
        h.idle();
    }
    h.click(h.text("OK"));
    for _ in 0..30 {
        h.idle();
    }
    let rows = lock(&h.session).execute("radius.list", &json!({})).unwrap();
    assert_eq!(rows[3]["address"], "10.0.0.12", "{:?}", h.app.log());
    assert_eq!(rows[3]["timeout"], 2000);
    assert_eq!(lock(&h.session).store().running().radius.servers[3].secret, "novo");
}

#[test]
fn incoming_shows_the_port_and_applies() {
    let mut h = open(lab());
    h.app.panel_mut::<RadiusPanel>().unwrap().tab = Tab::Incoming;
    refresh(&mut h);
    assert!(h.has_text("udp [::]:3799"));
    assert!(h.has_text_containing("MikroTik: 1700"));
    assert!(h.has_text("10.0.0.11"), "allowed sources: the enabled entries");
    let form = h.app.panel_mut::<RadiusPanel>().unwrap().form.clone();
    assert_eq!(form.port, "3799");
    assert!(!form.accept, "off by default");
    {
        let p = h.app.panel_mut::<RadiusPanel>().unwrap();
        p.form.accept = true;
        p.form.port = "1700".into();
    }
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let inc = &lock(&h.session).store().running().radius.incoming.clone();
    assert!(inc.accept);
    assert_eq!(inc.port, 1700, "{:?}", h.app.log());
}

#[test]
fn monitor_counts_per_server() {
    let mut h = open(lab());
    h.app.panel_mut::<RadiusPanel>().unwrap().tab = Tab::Monitor;
    refresh(&mut h);
    assert!(h.has_text("Bad Replies"));
    assert!(h.has_text("120"));
    assert!(h.has_text_containing("probing"));
}

#[test]
fn the_test_dialog_shows_the_reply_decoded() {
    let mut h = open(lab());
    h.app.with_panel_as::<RadiusPanel, _>(|p, app| p.open_test(app)).unwrap();
    h.idle();
    {
        let t = h.app.panel_mut::<RadiusPanel>().unwrap().test.as_mut().unwrap();
        t.user = "cliente1".into();
        t.password = "senha1".into();
    }
    h.idle();
    h.click(h.text("Send Access-Request"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while h.app.panel_mut::<RadiusPanel>().unwrap().test.as_ref().and_then(|t| t.answer.clone()).is_none() {
        assert!(Instant::now() < deadline, "{:?}", h.app.log());
        thread::sleep(Duration::from_millis(30));
        refresh(&mut h);
    }
    h.idle();
    assert!(h.has_text("accept"));
    assert!(h.has_text("Mikrotik-Rate-Limit"));
    assert!(h.has_text("50M/100M"));
    assert!(h.has_text_containing("10.0.0.10"));
}

#[test]
fn every_label_has_an_explanation_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    for key in [
        "menu.radius", "radius.state", "radius.address", "radius.service", "radius.ports", "radius.timeout",
        "radius.src_address", "radius.vrf", "radius.require_message_auth", "radius.secret",
        "radius.authentication_port", "radius.accounting_port", "radius.realm", "radius.called_id",
        "radius.accounting_backup", "radius.status_server", "radius.disabled", "radius.server",
        "radius.incoming", "radius.monitor", "radius.test", "radius.test.user", "radius.test.password",
        "radius.incoming.listening", "radius.incoming.accept", "radius.incoming.port", "radius.incoming.vrf",
        "radius.incoming.replay_window", "radius.incoming.require_event_timestamp",
        "radius.incoming.require_message_auth", "radius.incoming.allowed", "radius.monitor.pending",
        "radius.monitor.requests", "radius.monitor.accepts", "radius.monitor.rejects",
        "radius.monitor.acct_responses", "radius.monitor.resends", "radius.monitor.timeouts",
        "radius.monitor.bad_replies", "radius.monitor.last_request_rtt", "radius.monitor.sockets",
    ] {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
}

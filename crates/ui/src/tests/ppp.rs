//! PPP (G4.3d): the tabs against a stand-in `pppoe` service, the secret
//! modal through the engine's preview, the "drops N sessions" question,
//! Why? and every explanation in both languages.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use corerouter_engine::ppp::PppBackend;
use corerouter_model::MacAddr;
use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Stage, Why};
use serde_json::json;

use super::*;
use crate::ppp::{PppPanel, Tab, WIN};

/// The daemon's `pppoe` service, as the window sees it.
#[derive(Default)]
struct Fake {
    up: Mutex<Vec<ActiveSession>>,
}

fn session(i: u16, name: &str) -> ActiveSession {
    ActiveSession {
        id: format!("*1-{i}"),
        name: name.into(),
        service: "pppoe".into(),
        caller_id: format!("AA:BB:CC:00:00:{i:02X}"),
        address: Some(std::net::Ipv4Addr::new(100, 64, 0, i as u8)),
        uptime_secs: 3723,
        session_id: i,
        server: "pppoe-ether2".into(),
        interface: "ether2".into(),
        vlan: Some(110),
        rate_limit: Some("50M/100M".into()),
        profile: "plano".into(),
        encoding: "mschap2".into(),
        radius: i == 2,
        rx_bytes: 1_500_000,
        tx_bytes: 9_000_000,
        ..ActiveSession::default()
    }
}

impl PppBackend for Fake {
    fn active(&self) -> Vec<ActiveSession> {
        self.up.lock().unwrap().clone()
    }
    fn terminate(&self, ids: &[String]) -> usize {
        let mut up = self.up.lock().unwrap();
        let n = up.len();
        up.retain(|a| !ids.contains(&a.id));
        n - up.len()
    }
    fn history(&self) -> Vec<HistoryEntry> {
        vec![HistoryEntry {
            at: 1_792_000_000,
            name: "bloqueado".into(),
            caller_id: "AA:BB:CC:00:00:09".into(),
            server: "pppoe-ether2".into(),
            event: "failed".into(),
            stage: Some(Stage::Auth),
            reason: "auth-failed".into(),
            hint: "Usuário ou senha recusados".into(),
            reply_message: Some("Inadimplente".into()),
            ..HistoryEntry::default()
        }]
    }
    fn why(&self, name: Option<&str>, _: Option<MacAddr>) -> Why {
        Why {
            query: name.unwrap_or_default().into(),
            attempts: vec![(Stage::Padi, 4), (Stage::Padr, 4), (Stage::Lcp, 4), (Stage::Auth, 4)],
            last_stage: Some(Stage::Auth),
            last: self.history().into_iter().next(),
            ..Why::default()
        }
    }
    fn stats(&self) -> ServiceStats {
        ServiceStats { sessions: self.up.lock().unwrap().len() as u64, padi: 40, pado: 38, padr: 30, pads: 30, auth_accept: 26, auth_reject: 4, throttled: 2, ..ServiceStats::default() }
    }
}

fn lab() -> (Session, Arc<Fake>) {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        ("ip.pool.add", json!({"name": "clientes", "ranges": "100.64.0.0/22"})),
        ("ppp.profile.add", json!({"name": "plano", "remote_address": "clientes", "rate_limit": "50M/100M", "address_list": "assinantes"})),
        ("ppp.secret.add", json!({"name": "joao", "password": "x", "profile": "plano", "comment": "João da Silva"})),
        ("interface.pppoe-server.server.add", json!({"interface": "ether2", "pppoe_over_vlan_range": "100-115"})),
    ] {
        s.execute(id, &p).unwrap();
    }
    let fake = Arc::new(Fake::default());
    *fake.up.lock().unwrap() = vec![session(1, "joao"), session(2, "maria"), session(3, "ana")];
    s.set_ppp_backend(fake.clone());
    (s, fake)
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

fn tab(h: &mut Harness, t: Tab) {
    h.app.panel_mut::<PppPanel>().unwrap().tab = t;
    refresh(h);
}

#[test]
fn active_connections_show_the_login_rate_and_counters() {
    let (s, _) = lab();
    let mut h = open(s);
    assert!(h.has_text("PPP"));
    assert!(h.has_text("Active Connections"));
    assert!(h.has_text_containing("100.64.0.2"));
    let p = h.app.panel_mut::<PppPanel>().unwrap();
    let rows: Vec<_> = p.active["rows"].as_array().unwrap().iter().map(|r| PppPanel::active_row(r, None)).collect();
    assert_eq!(rows.len(), 3);
    let name = crate::chip::split(&rows[0].cells[0]).1;
    assert!(name[0].1.contains("ana"), "sorted by name, the identity chip: {name:?}");
    let maria = rows.iter().find(|r| r.cells[0].contains("maria")).unwrap();
    assert!(crate::chip::split(&maria.cells[0]).1.iter().any(|(_, t)| *t == "R"), "RADIUS mark");
    assert!(crate::chip::split(&rows[0].cells[5]).1.iter().any(|(_, t)| *t == "50M/100M"));
    assert_eq!(rows[0].cells[4], "1h2m3s");
    assert_eq!(rows[0].cells[6], "1.4 MiB");
}

#[test]
fn every_tab_draws() {
    let (s, _) = lab();
    let mut h = open(s);
    tab(&mut h, Tab::Interface);
    assert!(h.has_text_containing("slow path") || h.has_text_containing("XDP"));
    tab(&mut h, Tab::Servers);
    assert!(h.has_text_containing("pppoe-ether2"));
    assert!(h.has_text_containing("100-115"));
    tab(&mut h, Tab::Secrets);
    assert!(h.has_text_containing("joao"));
    assert!(h.has_text_containing("João da Silva"));
    assert!(!h.has_text_containing("\"password\""));
    tab(&mut h, Tab::Profiles);
    assert!(h.has_text_containing("plano"));
    assert!(h.has_text_containing("default-encryption"));
    tab(&mut h, Tab::Aaa);
    assert!(h.has_text("Use RADIUS"));
    tab(&mut h, Tab::Radius);
    assert!(h.has_text("Open RADIUS"));
    tab(&mut h, Tab::History);
    assert!(h.has_text_containing("bloqueado"));
    assert!(h.has_text_containing("auth-failed"));
}

#[test]
fn why_shows_the_stages_and_the_reason() {
    let (s, _) = lab();
    let mut h = open(s);
    h.app.with_panel_as::<PppPanel, _>(|p, app| p.open_why(app, "bloqueado".into(), String::new())).unwrap();
    refresh(&mut h);
    refresh(&mut h);
    assert!(h.has_text_containing("Auth 4"), "the stages with their counts");
    assert!(h.has_text_containing("Inadimplente"), "the RADIUS Reply-Message");
    assert!(h.has_text_containing("Usuário ou senha recusados"), "the hint, in Portuguese");
}

#[test]
fn the_secret_modal_adds_through_the_preview() {
    let (s, _) = lab();
    let mut h = open(s);
    tab(&mut h, Tab::Secrets);
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<PppPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act(app, Tab::Secrets, crate::list::Act::Add, &[], ui));
        })
        .unwrap();
    h.idle();
    {
        let p = h.app.panel_mut::<PppPanel>().unwrap();
        let (_, m) = p.modal.as_mut().expect("the modal is open");
        m.values.insert("name", "carla".into());
        m.values.insert("password", "s3nh4".into());
        m.values.insert("profile", "plano".into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.app.panel_mut::<PppPanel>().unwrap().modal.as_ref().and_then(|(_, m)| m.preview.clone()).is_none_or(|p| p["commands"].as_array().is_none_or(Vec::is_empty)) {
        assert!(Instant::now() < deadline);
        h.time += 0.5;
        h.idle();
    }
    assert!(h.has_text_containing("New PPP Secret"));
    assert!(h.has_text_containing("from pool clientes"), "what the login gets");
    assert!(!h.has_text_containing("s3nh4"));
    for _ in 0..30 {
        h.idle();
    }
    h.click(h.text("OK"));
    for _ in 0..30 {
        h.idle();
    }
    let s = lock(&h.session);
    let sec = s.store().running().ppp.secret("carla").cloned();
    assert_eq!(sec.map(|x| x.password).as_deref(), Some("s3nh4"), "{:?}", h.app.log());
}

#[test]
fn disabling_a_server_with_sessions_asks_first() {
    let (s, _) = lab();
    let mut h = open(s);
    tab(&mut h, Tab::Servers);
    let id = h.app.panel_mut::<PppPanel>().unwrap().servers[0]["id"].as_str().unwrap().to_owned();
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<PppPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act(app, Tab::Servers, crate::list::Act::Disable(vec![id.clone()]), &[], ui));
        })
        .unwrap();
    for _ in 0..10 {
        h.idle();
    }
    assert!(h.app.panel_mut::<PppPanel>().unwrap().drops.is_some(), "the router refused: it drops 3 sessions");
    assert!(h.has_text_containing("drops 3 active session"));
    assert!(!lock(&h.session).store().running().ppp.pppoe_servers[0].disabled);
    h.click(h.text("Apply anyway"));
    for _ in 0..10 {
        h.idle();
    }
    assert!(lock(&h.session).store().running().ppp.pppoe_servers[0].disabled, "{:?}", h.app.log());
}

#[test]
fn every_explanation_exists_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    let keys = [
        "menu.ppp",
        "ppp.aaa",
        "ppp.aaa.accounting",
        "ppp.aaa.enable_ipv6_accounting",
        "ppp.aaa.interim_jitter",
        "ppp.aaa.interim_update",
        "ppp.aaa.radius_servers",
        "ppp.aaa.use_circuit_id_in_nas_port_id",
        "ppp.aaa.use_radius",
        "ppp.active",
        "ppp.active.address",
        "ppp.active.caller_id",
        "ppp.active.circuit_id",
        "ppp.active.name",
        "ppp.active.rate_limit",
        "ppp.active.rx",
        "ppp.active.service",
        "ppp.active.traffic",
        "ppp.active.tx",
        "ppp.active.uptime",
        "ppp.active.vlan",
        "ppp.history",
        "ppp.history.at",
        "ppp.history.event",
        "ppp.history.reason",
        "ppp.interface",
        "ppp.monitor.auth_accept",
        "ppp.monitor.auth_reject",
        "ppp.monitor.dataplane",
        "ppp.monitor.padi",
        "ppp.monitor.pado",
        "ppp.monitor.padr",
        "ppp.monitor.pads",
        "ppp.monitor.padt_rx",
        "ppp.monitor.padt_tx",
        "ppp.monitor.running",
        "ppp.monitor.sessions",
        "ppp.monitor.throttled",
        "ppp.profile.address_list",
        "ppp.profile.change_tcp_mss",
        "ppp.profile.dns_server",
        "ppp.profile.idle_timeout",
        "ppp.profile.local_address",
        "ppp.profile.name",
        "ppp.profile.on_down",
        "ppp.profile.on_up",
        "ppp.profile.only_one",
        "ppp.profile.rate_limit",
        "ppp.profile.remote_address",
        "ppp.profile.secrets",
        "ppp.profile.session_timeout",
        "ppp.profiles",
        "ppp.radius",
        "ppp.secret.caller_id",
        "ppp.secret.disabled",
        "ppp.secret.limit_bytes",
        "ppp.secret.local_address",
        "ppp.secret.name",
        "ppp.secret.password",
        "ppp.secret.profile",
        "ppp.secret.remote_address",
        "ppp.secret.service",
        "ppp.secret.state",
        "ppp.secrets",
        "ppp.server.ac_cookie",
        "ppp.server.accept_untagged",
        "ppp.server.admission",
        "ppp.server.authentication",
        "ppp.server.default_profile",
        "ppp.server.disabled",
        "ppp.server.interface",
        "ppp.server.keepalive_timeout",
        "ppp.server.mac_padi_limit",
        "ppp.server.max_mru",
        "ppp.server.max_mtu",
        "ppp.server.max_sessions",
        "ppp.server.mrru",
        "ppp.server.name",
        "ppp.server.new_session_rate",
        "ppp.server.one_session_per_host",
        "ppp.server.padi_limit",
        "ppp.server.pado_delay",
        "ppp.server.pado_delay_by_load",
        "ppp.server.pppoe_over_vlan_range",
        "ppp.server.service_name",
        "ppp.server.sessions",
        "ppp.servers",
        "ppp.why",
        "ppp.why.mac",
        "ppp.why.name",
        "ppp.why.reply_message",
        "ppp.why.stage",
    ];
    for key in keys {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
    // Every key the window names is one of them.
    let src = include_str!("../ppp.rs");
    for pat in [".help(\"", "help: \"", "HelpView::new(\""] {
        for part in src.split(pat).skip(1) {
            let key = part.split('"').next().unwrap_or_default();
            if key.starts_with("ppp.") {
                assert!(keys.contains(&key), "{key} has no explanation");
            }
        }
    }
}

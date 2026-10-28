//! Routing › BFD (G3.6c): the Sessions tab with users, states (dampened
//! over up) and timings, the engine line, the Profiles list with the modal
//! fed by the engine's preview, the History tab, and the ⓘ of every label.

use super::*;
use crate::bfd::{BfdPanel, Tab, What};
use crate::list::Act;
use corerouter_model::bfd::{BfdEvent, BfdSessionStatus, BfdState, BfdThreadStatus};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("routing.bfd.peer.add", &json!({"name": "core1", "address": "192.0.2.2", "profile": "fast"})).unwrap();
    s.execute("routing.bfd.peer.add", &json!({"name": "rr", "address": "198.51.100.9", "multihop": true, "local_address": "192.0.2.1"})).unwrap();
    let status = |peer: &str, users: &[&str], state: &str, dampened: bool| BfdSessionStatus {
        peer: Some(peer.parse().unwrap()),
        users: users.iter().map(|u| (*u).to_owned()).collect(),
        profile: "fast".into(),
        state: state.into(),
        remote_state: state.into(),
        dampened,
        tx_interval_us: 50_000,
        remote_min_rx_us: 50_000,
        multiplier: 3,
        detect_time_us: 150_000,
        tx_jitter_p99_us: Some(69),
        flaps_24h: if dampened { 4 } else { 0 },
        ..BfdSessionStatus::default()
    };
    if let Some(st) = s.ext_mut::<BfdState>() {
        st.running = true;
        st.steering = "reuseport-cbpf".into();
        st.threads = vec![BfdThreadStatus {
            index: 0,
            sessions: 2,
            cpu_percent: 1.5,
            ..BfdThreadStatus::default()
        }];
        st.sessions = vec![
            status("192.0.2.2", &["peer core1", "BGP upstream-a"], "up", false),
            status("192.0.2.6", &["OSPF ether1"], "up", true),
        ];
        st.history.push_back(BfdEvent {
            at_ms: 1_761_000_000_000,
            peer: "192.0.2.6".parse().unwrap(),
            multihop: false,
            from: "up".into(),
            to: "down".into(),
            diag: "control-detection-time-expired".into(),
            users: vec!["OSPF ether1".into()],
            detect_time_us: 150_000,
            dampened: true,
        });
    }
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::bfd::WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

fn panel(h: &mut Harness) -> &mut BfdPanel {
    h.app.panel_mut::<BfdPanel>().unwrap()
}

fn act(h: &mut Harness, what: What, a: Act) {
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<BfdPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, what, a.clone(), ui));
        })
        .unwrap();
    h.idle();
}

#[test]
fn sessions_show_users_states_and_timings() {
    let h = open(lab());
    for t in [
        "Sessions", "192.0.2.2", "peer core1", "BGP upstream-a", "OSPF ether1", "up", "dampened", "50 ms / 50 ms", "150 ms", "0.07 ms",
        "4", "198.51.100.9", "multihop", "inactive", "3 sessions", "1 dampened", "1 threads", "bfd-0 1.5 %", "reuseport-cbpf",
    ] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn use_bfd_everywhere_sends_attach() {
    let mut s = lab();
    s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
    s.execute("routing.bgp.connection.add", &json!({"name": "upstream-a", "remote_address": "192.0.2.6", "remote_as": 64500})).unwrap();
    let mut h = open(s);
    h.click(h.text("Use BFD Everywhere"));
    settle(&mut h);
    let c = lock(&h.session).store().candidate().routing.bgp_connections.get("upstream-a").cloned().unwrap();
    assert_eq!(c.params.bfd.as_deref(), Some("default"));
    assert!(h.has_text("BFD (default) on 1 BGP connections and 0 OSPF templates"), "{:?}", h.app.log());
}

#[test]
fn profiles_list_and_the_modal_adds_through_the_preview() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Profiles;
    refresh(&mut h);
    for t in ["default", "fast", "built-in", "300 ms", "900 ms", "150 ms", "dampening", "peer core1", "2 profiles"] {
        assert!(h.has_text(t), "{t}");
    }
    act(&mut h, What::Profile, Act::Add);
    settle(&mut h);
    assert!(h.has_text("New BFD Profile"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("name", "edge".into());
    m.values.insert("min_tx", "20".into());
    m.values.insert("min_rx", "20".into());
    settle(&mut h);
    for t in ["60 ms (3 × 20 ms)", "50 each way per session"] {
        assert!(h.has_text(t), "{t}");
    }
    h.click(h.text("OK"));
    settle(&mut h);
    let p = lock(&h.session).store().candidate().routing.bfd.profile("edge");
    assert_eq!(p.map(|p| p.min_tx), Some(20), "{:?}", h.app.log());
    assert!(panel(&mut h).modal.is_none(), "OK closes");
}

#[test]
fn the_peer_modal_adds_a_peer() {
    let mut h = open(lab());
    act(&mut h, What::Peer, Act::Add);
    settle(&mut h);
    assert!(h.has_text("New BFD Peer"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("address", "203.0.113.7".into());
    settle(&mut h);
    assert!(h.has_text("203.0.113.7, UDP 3784 (single hop, RFC 5881: TTL 255)"));
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(lock(&h.session).store().candidate().routing.bfd.peers.contains_key("203.0.113.7"), "{:?}", h.app.log());
}

#[test]
fn history_lists_the_changes() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::History;
    refresh(&mut h);
    for t in ["192.0.2.6", "control-detection-time-expired", "OSPF ether1", "1 changes", "1 down"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in BfdPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}

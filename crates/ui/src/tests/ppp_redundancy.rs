//! PPP › Redundancy (G4.3h): the tab against a stand-in `ppp-ha` service,
//! Apply through `ppp.redundancy.set`, Switchover and Simular falha asking
//! first, and every explanation in both languages.

use std::sync::{Arc, Mutex};

use corerouter_engine::ppp_redundancy::HaBackend;
use corerouter_model::ppp_redundancy::{PeerStatus, RedundancyStatus, RoleChange, SyncStatus};
use serde_json::json;

use super::*;
use crate::ppp::{PppPanel, Tab, WIN};

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
}

impl HaBackend for Fake {
    fn status(&self) -> RedundancyStatus {
        RedundancyStatus {
            role: "active".into(),
            epoch: 3,
            answering: true,
            peer: PeerStatus {
                connected: true,
                role: "standby".into(),
                priority: 100,
                sync_path: true,
                access_path: false,
                ..PeerStatus::default()
            },
            witness: true,
            track: true,
            in_sync: true,
            sync: SyncStatus { sessions: 48_213, synced: 48_213, lag: 2, delay_ms: 4, ..SyncStatus::default() },
            drift: vec!["ppp.profile".into()],
            history: vec![RoleChange {
                at: 1_792_000_000,
                from: "standby".into(),
                to: "active".into(),
                epoch: 3,
                reason: "peer-dead".into(),
                stateful: true,
            }],
            ..RedundancyStatus::default()
        }
    }
    fn switchover(&self, force: bool) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("switchover {force}"));
        Ok(())
    }
    fn simulate_failure(&self, secs: u32) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("simulate {secs}"));
        Ok(())
    }
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open() -> (Harness, Arc<Fake>) {
    let mut s = Session::virtual_lab();
    s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
    s.execute(
        "ppp.redundancy.set",
        &json!({"enabled": true, "peer": "10.0.0.2:8730", "secret": "segredo-do-par-123", "witness": ["10.0.0.254"]}),
    )
    .unwrap();
    let fake = Arc::new(Fake::default());
    s.set_ha_backend(fake.clone());
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<PppPanel>().unwrap().tab = Tab::Redundancy;
    refresh(&mut h);
    refresh(&mut h);
    (h, fake)
}

#[test]
fn the_tab_shows_the_pair_and_its_sync() {
    let (mut h, _) = open();
    assert!(h.has_text("Redundancy"));
    assert!(h.has_text("Peer (TLS)"));
    assert!(h.has_text("Virtual MAC"));
    assert!(h.has_text("active"), "this node's role chip");
    assert!(h.has_text("standby"), "the peer's");
    assert!(h.has_text("48213/48213"), "sessions synced N/N");
    assert!(h.has_text_containing("delay 4 ms"));
    assert!(h.has_text("ppp.profile"), "config drift");
    assert!(h.has_text("peer-dead"));
    assert!(h.has_text("sessions kept"));
    let p = h.app.panel_mut::<PppPanel>().unwrap();
    assert_eq!(p.redundancy.form.peer, "10.0.0.2:8730");
    assert!(p.redundancy.form.secret.is_empty(), "the secret never comes back");
    refresh(&mut h);
}

#[test]
fn apply_sends_only_what_changed() {
    let (mut h, _) = open();
    h.app.panel_mut::<PppPanel>().unwrap().redundancy.form.priority = "200".into();
    refresh(&mut h);
    h.click(h.text("Apply"));
    for _ in 0..10 {
        h.idle();
    }
    let s = lock(&h.session);
    let r = &s.store().running().ppp.redundancy;
    assert_eq!(r.priority, 200);
    assert_eq!(r.secret, "segredo-do-par-123", "an empty secret field changes nothing");
}

#[test]
fn switchover_and_simulate_failure_ask_first() {
    let (mut h, fake) = open();
    h.click(h.text("Switchover"));
    for _ in 0..5 {
        h.idle();
    }
    assert!(h.has_text_containing("hands every session to the peer"));
    assert!(fake.calls.lock().unwrap().is_empty(), "nothing before OK");
    h.click(h.text("OK"));
    for _ in 0..10 {
        h.idle();
    }
    h.click(h.text("Simulate Failure"));
    for _ in 0..5 {
        h.idle();
    }
    assert!(h.has_text_containing("behaves as dead"));
    h.click(h.text("OK"));
    for _ in 0..10 {
        h.idle();
    }
    assert_eq!(*fake.calls.lock().unwrap(), ["switchover false", "simulate 30"]);
}

#[test]
fn every_explanation_exists_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    let keys = [
        "ppp.redundancy",
        "ppp_ha.actions",
        "ppp_ha.drift",
        "ppp_ha.enabled",
        "ppp_ha.fencing",
        "ppp_ha.group",
        "ppp_ha.history",
        "ppp_ha.holds",
        "ppp_ha.interfaces",
        "ppp_ha.mode",
        "ppp_ha.paths",
        "ppp_ha.peer",
        "ppp_ha.peer_state",
        "ppp_ha.preempt",
        "ppp_ha.priority",
        "ppp_ha.role",
        "ppp_ha.secret",
        "ppp_ha.sync",
        "ppp_ha.timers",
        "ppp_ha.track",
        "ppp_ha.virtual_mac",
        "ppp_ha.witness",
        "ppp_ha.witness_state",
    ];
    for k in keys {
        for l in [Lang::Pt, Lang::En] {
            let found = explain(Langs { labels: l, help: l }, k);
            assert_eq!(found.map(|(got, _)| got), Some(l), "{k} in {l:?}");
        }
    }
}

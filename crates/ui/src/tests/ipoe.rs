//! IPoE (G4.3f) in the PPP window: the `ipoe` service's sessions next to
//! the PPPoE ones in Active Connections (a chip per service), Why? with the
//! DHCP stages, and `ipoe` among a secret's services.

use std::sync::Arc;

use corerouter_engine::ppp::PppBackend;
use corerouter_model::MacAddr;
use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Stage, Why};
use serde_json::json;

use super::*;
use crate::ppp::{PppPanel, WIN};

/// The daemon's `ipoe` service, as the window sees it.
struct Ipoe;

impl PppBackend for Ipoe {
    fn active(&self) -> Vec<ActiveSession> {
        vec![ActiveSession {
            id: "*i1".into(),
            name: "02:30:00:00:64:01".into(),
            service: "ipoe".into(),
            caller_id: "02:30:00:00:64:01".into(),
            address: Some(std::net::Ipv4Addr::new(10, 64, 1, 7)),
            uptime_secs: 61,
            server: "dhcp1".into(),
            interface: "ether3".into(),
            circuit_id: Some("olt1/1/3".into()),
            rate_limit: Some("10M/50M".into()),
            profile: "default".into(),
            encoding: "dhcp".into(),
            radius: true,
            mtu: 1500,
            ..ActiveSession::default()
        }]
    }
    fn terminate(&self, _: &[String]) -> usize {
        0
    }
    fn history(&self) -> Vec<HistoryEntry> {
        Vec::new()
    }
    fn why(&self, name: Option<&str>, _: Option<MacAddr>) -> Why {
        Why {
            query: name.unwrap_or_default().into(),
            attempts: vec![(Stage::Dhcp, 3), (Stage::Auth, 3)],
            last_stage: Some(Stage::Auth),
            last: Some(HistoryEntry {
                at: 1_792_000_000,
                name: name.unwrap_or_default().into(),
                caller_id: "02:30:00:00:64:09".into(),
                server: "dhcp1".into(),
                event: "failed".into(),
                stage: Some(Stage::Auth),
                reason: "rejected".into(),
                hint: "o RADIUS recusou este cliente".into(),
                reply_message: Some("Inadimplente".into()),
                ..HistoryEntry::default()
            }),
            ..Why::default()
        }
    }
    fn stats(&self) -> ServiceStats {
        ServiceStats { sessions: 1, ..ServiceStats::default() }
    }
}

fn open() -> Harness {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "10.64.0.1/16", "interface": "ether3"})).unwrap();
    s.set_ipoe_sessions(Arc::new(Ipoe));
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
    h
}

#[test]
fn ipoe_sessions_show_with_their_service_chip() {
    let mut h = open();
    assert!(h.has_text_containing("10.64.1.7"));
    let p = h.app.panel_mut::<PppPanel>().unwrap();
    let rows: Vec<_> = p.active["rows"].as_array().unwrap().iter().map(|r| PppPanel::active_row(r, None)).collect();
    assert_eq!(rows.len(), 1);
    let service = crate::chip::split(&rows[0].cells[1]).1;
    assert_eq!(service.first().map(|(_, t)| *t), Some("ipoe"), "{service:?}");
    assert!(rows[0].cells.iter().any(|c| c == "olt1/1/3"), "the circuit id");
}

#[test]
fn why_shows_the_dhcp_stages() {
    let mut h = open();
    h.app
        .with_panel_as::<PppPanel, _>(|p, app| p.open_why(app, "02:30:00:00:64:09".into(), String::new()))
        .unwrap();
    for _ in 0..6 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
    assert!(h.has_text_containing("DHCP 3"), "the IPoE stages");
    assert!(!h.has_text_containing("PADI"), "no PPPoE stages for an IPoE subscriber");
    assert!(h.has_text_containing("Inadimplente"));
}

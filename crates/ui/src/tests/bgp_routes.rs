//! Routing › BGP Routes and Routing › RPKI (G3.2c): the received list with
//! its RPKI badges and shares, "Why this route?", the flap history, and
//! the validators with the policy and `rpki-check`.

use std::sync::Arc;

use super::*;
use crate::bgp_routes::{self, RoutesPanel, Tab};
use crate::rpki::RpkiPanel;
use corerouter_engine::{Clock, Job, Runner};
use corerouter_hal::HalError;
use corerouter_hal::routing::{RoutingDaemon, RoutingReader};
use corerouter_model::Config;
use corerouter_model::bgp_rib::{AsSegment, BgpAttrs, BgpPath, BgpPrefix, BgpRib, BgpRoute, Direction, PeerKind, SegmentKind};
use corerouter_model::routing_state::{BgpSession, RoutingStatus};
use corerouter_proto_bgp::rpki::{Vrp, VrpTable};

struct Inline;
struct NoClock;
impl Clock for NoClock {
    fn elapsed(&self) -> std::time::Duration {
        std::time::Duration::from_millis(7)
    }
    fn sleep(&self, _: std::time::Duration) {}
}
impl Runner for Inline {
    fn spawn(&self, _: &str, job: Job) -> std::result::Result<(), String> {
        job(&NoClock);
        Ok(())
    }
}

#[derive(Clone)]
struct Fake;

impl RoutingDaemon for Fake {
    fn describe(&self) -> String {
        "fake".into()
    }
    fn apply(&mut self, _: &Config, _: &Config) -> std::result::Result<(), HalError> {
        Ok(())
    }
    fn reader(&self) -> Box<dyn RoutingReader> {
        Box::new(self.clone())
    }
}

fn path(peer: &str, lp: u32, best: bool) -> BgpPath {
    BgpPath {
        peer: peer.into(),
        peer_router_id: peer.parse().ok(),
        peer_kind: PeerKind::Internal,
        segments: vec![AsSegment { kind: SegmentKind::Sequence, asns: vec![64502, 64502] }],
        as_path: "64502 64502".into(),
        local_pref: Some(lp),
        valid: true,
        next_hop_reachable: true,
        best,
        ..BgpPath::default()
    }
}

impl RoutingReader for Fake {
    fn bgp_sessions(&mut self, _: &Config) -> std::result::Result<Vec<BgpSession>, HalError> {
        Ok(Vec::new())
    }
    fn version(&mut self) -> std::result::Result<String, HalError> {
        Ok("fake".into())
    }
    fn bgp_routes(&mut self, _: &str, _: &str, _: Direction) -> std::result::Result<BgpRib, HalError> {
        let attrs = vec![
            BgpAttrs { as_path: "64502 13335".into(), local_pref: Some(200), communities: vec!["65000:100".into()], ..BgpAttrs::default() },
            BgpAttrs { as_path: "64502 64666".into(), ..BgpAttrs::default() },
        ];
        let routes = vec![
            BgpRoute { prefix: "10.66.0.0/24".parse().unwrap(), attrs: 1, flags: BgpRoute::FILTERED },
            BgpRoute { prefix: "10.30.2.0/24".parse().unwrap(), attrs: 0, flags: BgpRoute::BEST },
        ];
        Ok(BgpRib { routes, attrs, pre_policy: true, warnings: vec![] })
    }
    fn bgp_prefix(&mut self, _: &str, _: &str) -> std::result::Result<BgpPrefix, HalError> {
        Ok(BgpPrefix {
            prefix: "10.20.1.0/24".into(),
            paths: vec![path("198.51.100.18", 200, true), path("198.51.100.22", 100, false)],
            default_local_pref: Some(100),
            local_as: Some(65000),
        })
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Inline));
    let _ = s.attach_routing(Box::new(Fake));
    s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
    s.execute("routing.bgp.connection.add", &json!({"name": "rr2", "remote_address": "198.51.100.18", "remote_as": 65000})).unwrap();
    s.execute("routing.bgp.connection.add", &json!({"name": "rr3", "remote_address": "198.51.100.22", "remote_as": 65000})).unwrap();
    s.execute("routing.rpki.add", &json!({"name": "lab", "address": "127.0.0.1", "port": 3323})).unwrap();
    let t = VrpTable::build(&[
        Vrp::new("10.66.0.0".parse().unwrap(), 16, 16, 64502).unwrap(),
        Vrp::new("10.30.0.0".parse().unwrap(), 16, 24, 13335).unwrap(),
    ]);
    s.set_rpki_table(Some(Arc::new(t)));
    s
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

#[test]
fn received_routes_show_rpki_and_why_this_route() {
    let mut h = Harness::with_session(lab());
    h.app.open.clear();
    bgp_routes::open_routes(&mut h.app, "rr2", Tab::Received);
    refresh(&mut h);
    assert!(h.has_text("Routes"), "the BGP window's Routes tab");
    assert!(h.has_text("10.66.0.0/24"), "{:?}", h.app.panel_mut::<RoutesPanel>().unwrap().answer);
    assert!(h.has_text("filtered"));
    assert!(h.has_text_containing("invalid 50.0%"), "the share of each state");
    assert!(h.has_text_containing("valid 50.0%"));
    assert!(h.has_text("AS13335"), "origin AS chip");
    // Why this route?
    bgp_routes::open_explain(&mut h.app, "10.20.1.0/24");
    refresh(&mut h);
    assert!(h.has_text_containing("Why this route? 10.20.1.0/24"));
    assert!(h.has_text_containing("local-pref"), "the step that decided");
    let p = h.app.panel_mut::<RoutesPanel>().unwrap();
    let a = p.explain.as_ref().unwrap().answer.clone().unwrap();
    assert_eq!(a["paths"][1]["lost_at"]["step"], "local-pref");
    // History of a flap.
    {
        let mut s = lock(&h.session);
        let one = |up: bool| RoutingStatus {
            backend: "fake".into(),
            updated: Some(1),
            error: None,
            bgp_sessions: vec![BgpSession {
                instance: "default".into(),
                remote_address: "198.51.100.18".into(),
                connection: Some("rr2".into()),
                state: if up { "established" } else { "active" }.into(),
                established: up,
                uptime_secs: Some(3_700),
                last_error: (!up).then(|| "Hold Timer Expired".into()),
                ..BgpSession::default()
            }],
            ..RoutingStatus::default()
        };
        s.set_routing_status(one(true));
        s.set_routing_status(one(false));
    }
    bgp_routes::open_routes(&mut h.app, "rr2", Tab::History);
    refresh(&mut h);
    assert!(h.has_text("Hold Timer Expired"), "the reason of the down");
}

#[test]
fn rpki_window_shows_the_policy_and_checks_a_prefix() {
    let mut h = Harness::with_session(lab());
    h.app.open.clear();
    h.app.open(Win::Bgp);
    h.app.panel_mut::<crate::bgp::BgpPanel>().unwrap().tab = crate::bgp::Tab::Rpki;
    refresh(&mut h);
    assert!(h.has_text("on: invalid routes rejected"));
    assert!(h.has_text("127.0.0.1:3323"));
    assert!(h.has_text("2 reject"), "rr2 and rr3 are iBGP");
    {
        let p = h.app.panel_mut::<RpkiPanel>().unwrap();
        p.prefix = "10.66.0.0/24".into();
        p.origin = "64502".into();
    }
    h.idle();
    h.click(h.text("Check"));
    refresh(&mut h);
    let p = h.app.panel_mut::<RpkiPanel>().unwrap();
    assert_eq!(p.check.as_ref().unwrap()["state"], "invalid");
    assert!(h.has_text_containing("10.66.0.0/16-16 AS64502"));
}

#[test]
fn session_detail_shows_the_rpki_share_and_links() {
    let mut s = lab();
    s.set_routing_status(RoutingStatus {
        backend: "fake".into(),
        updated: Some(1),
        error: None,
        bgp_sessions: vec![BgpSession {
            instance: "default".into(),
            remote_address: "198.51.100.18".into(),
            connection: Some("rr2".into()),
            state: "established".into(),
            established: true,
            ..BgpSession::default()
        }],
        ..RoutingStatus::default()
    });
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Bgp);
    refresh(&mut h);
    h.click(h.text("rr2"));
    refresh(&mut h);
    assert!(h.has_text("RPKI In"));
    h.click(h.text("read the routes"));
    refresh(&mut h);
    assert!(h.has_text_containing("valid 50%"), "three badges once the table is read");
    assert!(h.has_text_containing("invalid 50%"));
    assert!(h.has_text_containing("unknown 0%"));
    h.click(h.text("why this route?"));
    refresh(&mut h);
    assert!(h.has_text_containing("Type a prefix"));
    h.click(h.text("received routes"));
    refresh(&mut h);
    assert_eq!(h.app.panel_mut::<crate::bgp::BgpPanel>().unwrap().tab, crate::bgp::Tab::Routes);
    assert!(h.has_text("10.66.0.0/24"));
}

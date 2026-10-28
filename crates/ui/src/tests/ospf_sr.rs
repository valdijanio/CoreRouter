//! Routing › OSPF › Segment Routing (G3.4f): the switch with its preview
//! (what moves to labels, Safe Mode), this router's SIDs, the network's
//! SIDs and the SR routers, over the virtual lab's sample.

use super::*;
use crate::ospf::{OspfPanel, Tab};
use crate::ospf_sr::SrView;

/// v2 in the backbone: ether1 and the loopback lo0 (10.255.0.1/32).
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        ("interface.loopback.add", json!({"name": "lo0"})),
        ("ip.address.add", json!({"address": "10.255.0.1/32", "interface": "lo0"})),
        ("ip.address.add", json!({"address": "10.0.1.1/30", "interface": "ether1"})),
        ("routing.ospf.instance.add", json!({"name": "v2", "router_id": "10.255.0.1"})),
        ("routing.ospf.area.add", json!({"name": "backbone", "instance": "v2", "area_id": "0.0.0.0"})),
        ("routing.ospf.interface-template.add", json!({"area": "backbone", "interfaces": "lo0", "passive": true})),
        ("routing.ospf.interface-template.add", json!({"area": "backbone", "interfaces": "ether1", "type": "ptp"})),
    ] {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ospf::WIN));
    panel(&mut h).tab = Tab::SegmentRouting;
    settle(&mut h);
    h
}

fn settle(h: &mut Harness) {
    for _ in 0..6 {
        h.app.cache.refreshed_at = None;
        for _ in 0..5 {
            h.idle();
        }
    }
}

fn panel(h: &mut Harness) -> &mut OspfPanel {
    h.app.panel_mut::<OspfPanel>().unwrap()
}

#[test]
fn turning_sr_on_goes_through_the_preview() {
    let mut h = open(lab());
    for t in ["SR off", "Turn On…"] {
        assert!(h.has_text(t), "{t}");
    }
    h.click(h.text("Turn On…"));
    settle(&mut h);
    assert!(panel(&mut h).modal.is_some());
    for t in ["10.255.0.1/32 gets index 1", "Safe Mode", "24000-1048575"] {
        assert!(h.has_text_containing(t), "{t}");
    }
    // The traffic moves to labels: OK waits for the operator's yes.
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(lock(&h.session).store().running().routing.ospf.segment_routing.is_none());
    panel(&mut h).modal.as_mut().unwrap().1.accept_risk = true;
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let sr = &lock(&h.session).store().running().routing.ospf.clone();
    assert!(sr.segment_routing.is_some(), "{:?}", h.app.log());
    assert_eq!(sr.prefix_sids.len(), 1);
}

#[test]
fn the_tab_shows_this_router_the_network_and_the_routers() {
    let mut s = lab();
    s.execute("routing.ospf.segment-routing.set", &json!({})).unwrap();
    let mut h = open(s);
    for t in ["SR on", "16000-23999", "15000-15999", "24000-1048575", "10.255.0.1/32", "lo0", "16001", "php", "virtual lab sample"] {
        assert!(h.has_text(t), "{t}");
    }
    panel(&mut h).sr_view = SrView::Network;
    settle(&mut h);
    for t in ["this router", "16100", "implicit-null (pop)", "ether1"] {
        assert!(h.has_text(t), "{t}: {}", panel(&mut h).sr);
    }
    panel(&mut h).sr_view = SrView::Routers;
    settle(&mut h);
    for t in ["10.255.0.1", "16000-23999", "10.250.0.2"] {
        assert!(h.has_text(t), "{t}");
    }
}

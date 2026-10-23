//! IP › Traffic Flow (G4.4b): state, settings, targets, top talkers.

use super::*;
use crate::traffic_flow::{Tab, TrafficFlowPanel, WIN, target_row};
use corerouter_model::ItemId;
use corerouter_model::traffic_flow::{FlowState, TargetState, TargetStatus, TrafficFlowStatus};
use corerouter_proto_flow::{Direction, EndReason, Flow, Record};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn flow(sub: &str, octets: u64, dir: Direction, t: u64) -> Record {
    let s: std::net::IpAddr = sub.parse().unwrap();
    let srv: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    let (src, dst, post_dst) = match dir {
        Direction::Initiator => (s, srv, srv),
        Direction::Reverse => (srv, "203.0.113.1".parse().unwrap(), s),
    };
    Record::Flow(Flow {
        start_ms: t,
        end_ms: t,
        protocol: 6,
        src,
        dst,
        src_port: 40_000,
        dst_port: 443,
        post_src: src,
        post_dst,
        post_src_port: 2100,
        post_dst_port: 443,
        octets,
        packets: 10,
        ingress: 1,
        egress: 2,
        end_reason: EndReason::End,
        direction: dir,
    })
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("ip.traffic-flow.set", &json!({"enabled": true})).unwrap();
    let id = s
        .execute("ip.traffic-flow.target.add", &json!({"dst_address": "192.0.2.10", "version": 9}))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = 1_792_700_000_000;
    s.traffic_flow_store(
        &[
            flow("100.64.0.7", 9_000_000, Direction::Reverse, now),
            flow("100.64.0.7", 300_000, Direction::Initiator, now),
            flow("100.64.0.9", 1_000, Direction::Initiator, now),
        ],
        now,
    );
    s.traffic_flow_set_status(TrafficFlowStatus {
        state: FlowState::Running,
        source: "lab".into(),
        events: 1234,
        accounting: Some(true),
        timestamps: Some(false),
        records_per_min: 42,
        targets: vec![TargetStatus {
            id: id.parse::<ItemId>().unwrap(),
            state: TargetState::Error,
            records: 300,
            messages: 9,
            bytes: 9000,
            records_per_min: 42,
            template_sends: 2,
            last_template: Some(1_792_700_000),
            queue: 0,
            dropped: 3,
            send_errors: 3,
            last_error: Some("send to 192.0.2.10:2055: Connection refused".into()),
        }],
        ..TrafficFlowStatus::default()
    });
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn the_window_shows_state_and_applies_settings() {
    let mut h = open(lab());
    assert!(h.has_text("Traffic Flow"));
    assert!(h.has_text("running"));
    assert!(h.has_text("lab"));
    assert!(h.has_text("timestamps off"), "the kernel's stamps are off: an amber chip");
    assert!(h.has_text("Active Flow Timeout"));
    let form = h.app.panel_mut::<TrafficFlowPanel>().unwrap().form.clone();
    assert!(form.enabled);
    assert_eq!(form.active_flow_timeout, "1800");
    assert!(!form.nat_events_destination, "Marco Civil art. 14: off by default");

    h.app.panel_mut::<TrafficFlowPanel>().unwrap().form.inactive_flow_timeout = "30".into();
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let got = lock(&h.session).execute("ip.traffic-flow.get", &json!({})).unwrap();
    assert_eq!(got["inactive_flow_timeout"], 30, "{:?}", h.app.log());

    // A refusal stays on screen with the typed value.
    h.app.panel_mut::<TrafficFlowPanel>().unwrap().form.cache_entries = "5".into();
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let p = h.app.panel_mut::<TrafficFlowPanel>().unwrap();
    assert!(p.error.clone().unwrap_or_default().contains("cache_entries"));
    assert_eq!(p.form.cache_entries, "5");
}

#[test]
fn targets_show_rate_templates_and_loss() {
    let mut h = open(lab());
    h.app.panel_mut::<TrafficFlowPanel>().unwrap().tab = Tab::Targets;
    refresh(&mut h);
    assert!(h.has_text("192.0.2.10:2055"));
    assert!(h.has_text_containing("NetFlow v9"));
    assert!(h.has_text_containing("Connection refused"));
    let p = h.app.panel_mut::<TrafficFlowPanel>().unwrap();
    let row = target_row(&p.targets[0]);
    assert!(row.cells[0].contains("error"));
    assert_eq!(crate::chip::split(&row.cells[7]).1, vec![(crate::chip::Kind::Red, "6")], "{:?}", row.cells);
}

#[test]
fn top_talkers_rank_subscribers_from_the_routers_own_records() {
    let mut h = open(lab());
    h.app.panel_mut::<TrafficFlowPanel>().unwrap().tab = Tab::Top;
    // The lab's clock is not the records' time: ask over the last hour.
    h.app.panel_mut::<TrafficFlowPanel>().unwrap().minutes = 60;
    refresh(&mut h);
    let p = h.app.panel_mut::<TrafficFlowPanel>().unwrap();
    assert_eq!(p.top.first().map(|r| r["address"].clone()), Some(json!("100.64.0.7")), "{:?}", p.top);
    assert!(h.has_text_containing("100.64.0.7"));
    assert!(h.has_text("8.9 MiB"), "down bytes of the heavy one");
}

#[test]
fn every_label_has_an_explanation_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    for key in [
        "traffic-flow.state",
        "traffic-flow.enabled",
        "traffic-flow.interfaces",
        "traffic-flow.cache_entries",
        "traffic-flow.active_flow_timeout",
        "traffic-flow.inactive_flow_timeout",
        "traffic-flow.sampling_interval",
        "traffic-flow.retention_hours",
        "traffic-flow.retention_records",
        "traffic-flow.nat_events",
        "traffic-flow.nat_events_destination",
        "traffic-flow.top",
        "traffic-flow.target",
        "traffic-flow.target.dst_address",
        "traffic-flow.target.version",
        "traffic-flow.stats.kernel_overruns",
    ] {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
}

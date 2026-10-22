//! IP › DNS › Statistics (G4.1e): the button of the DNS window opens it,
//! the counters of a real forwarder show up, Reset zeroes them.

use super::*;
use crate::dns_statistics::{DnsStatsPanel, WIN};
use corerouter_proto_dns::resolver::{Resolver, Settings};
use corerouter_proto_dns::server::{Forwarder, Start, Statistics};
use std::net::IpAddr;
use std::sync::Arc;

/// A query for `name`, type A, in wire format (RFC 1035 §4.1).
fn ask(name: &str) -> Vec<u8> {
    let mut m = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(u8::try_from(label.len()).unwrap());
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn statistics_window_shows_the_forwarder_and_resets() {
    let mut s = Session::virtual_lab();
    s.execute("ip.dns.static.add", &json!({"name": "nas.lan", "address": "192.168.88.2"}))
        .unwrap();
    s.execute("ip.dns.set", &json!({"allow_remote_requests": true}))
        .unwrap();
    let cfg = s.store().running().clone();
    let f = Forwarder::new(Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[]))));
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    s.set_dns_statistics(f.state::<Statistics>());
    for from in [[192, 168, 88, 10], [192, 168, 88, 10], [203, 0, 113, 9]] {
        assert!(matches!(
            f.start(&ask("nas.lan"), IpAddr::from(from), false, 1000),
            Start::Done(_)
        ));
    }

    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns::WIN));
    refresh(&mut h);
    h.click(h.text("Statistics"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)), "the button opens it");
    assert!(h.has_text("DNS Statistics"));
    assert!(h.has_text("3 queries"));
    assert!(h.has_text("Static") && h.has_text("Refused"));
    assert!(h.has_text("192.168.88.10"), "top client");
    assert!(h.has_text("NOERROR") && h.has_text("REFUSED"));
    assert!(!h.has_text("lab") && !h.has_text("forwarder off"), "no chip: counting");

    h.click(h.text("Reset Statistics"));
    refresh(&mut h);
    assert!(h.has_text("0 queries"), "{:?}", h.app.log());
    assert!(h.app.panel_mut::<DnsStatsPanel>().unwrap().error.is_none());
}

#[test]
fn statistics_window_in_the_lab_says_why_it_is_empty() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text("0 queries"));
    assert!(h.has_text("lab"), "chip: no daemon counting");
}

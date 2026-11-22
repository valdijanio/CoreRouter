//! IP › DNS › Statistics (G4.1e, G4.1h): the button of the DNS window
//! opens it, the counters of a real forwarder show up in its three tabs,
//! Reset zeroes them, and every explanation and warning has its text.

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
    assert!(h.has_text("Static / Adlist") && h.has_text("Refused / Limit"));
    assert!(h.has_text("UDP IPv4") && h.has_text("Truncated (TC)"), "transport group");
    assert!(h.has_text("counting"), "state chip");
    assert!(h.has_text("NOERROR") && h.has_text("REFUSED"));
    assert!(!h.has_text("lab") && !h.has_text("forwarder off"), "counting");

    // The other tabs.
    h.click(h.text("Names"));
    refresh(&mut h);
    assert!(h.has_text("Top names") && h.has_text("nas.lan"), "the name asked");
    assert!(h.has_text("Failing domains (NXDOMAIN / SERVFAIL)"));
    h.click(h.text("Clients"));
    refresh(&mut h);
    assert!(h.has_text("192.168.88.10"), "the client");
    assert!(h.has_text("live") && h.has_text("NXDOMAIN %") && h.has_text("Last seen"));
    assert!(!h.has_text("nas.lan"), "no name next to a client");
    h.click(h.text("Upstreams"));
    refresh(&mut h);
    assert!(h.has_text_containing("No upstream server asked yet"));
    assert!(h.has_text(">1600"), "the ends of the histogram always show");
    h.click(h.text("Cache"));
    refresh(&mut h);
    assert!(h.has_text("Asked by type") && h.has_text("Evictions"));
    h.click(h.text("Overview"));
    refresh(&mut h);

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

#[test]
fn every_explanation_label_and_warning_has_its_text() {
    use crate::i18n::{Lang, Langs, explain, template};
    for key in crate::dns_statistics::HELP_KEYS {
        for lang in [Lang::En, Lang::Pt] {
            let (got, text) = explain(Langs { labels: lang, help: lang }, key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(got, lang, "{key}");
            assert!(text.starts_with("## "), "{key}");
        }
    }
    for key in crate::dns_statistics::WARNINGS {
        let w = json!({"key": key, "text": "english", "args": {"server": "192.0.2.53", "percent": "12",
            "count": "7", "max": "100", "domain": "victim.com.br", "names": "900", "rate": "41"}});
        let pt = crate::dns_statistics::warning_text(Lang::Pt, &w);
        assert_ne!(pt, "english", "{key} has a Portuguese template");
        assert!(!pt.contains('{'), "{key}: every argument filled: {pt}");
        let _ = template(Lang::En, key, &[], "x");
    }
    for key in ["graphs.queries", "graphs.cache_hit", "graphs.servfail", "graphs.latency_p50", "graphs.latency_p99", "graphs.in_flight"] {
        for lang in [Lang::En, Lang::Pt] {
            assert!(explain(Langs { labels: lang, help: lang }, key).is_some_and(|(l, _)| l == lang), "{key}");
        }
    }
}

#[test]
fn warnings_of_the_engine_show_in_the_overview() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text("none in the last minute"));
    let p = h.app.panel_mut::<DnsStatsPanel>().unwrap();
    p.stats = Some(json!({"queries": 10, "resolver": "router", "allow_remote_requests": true,
        "warnings": [{"key": "upstream_down", "severity": "error", "text": "Upstream 192.0.2.53 is down",
            "args": {"server": "192.0.2.53"}}],
        "upstreams": [{"server": "192.0.2.53", "via": "doh", "state": "down", "state_secs": 90,
            "rtt_ranges": [0, 3, 0, 0, 0, 2]}],
        "rtt_ranges": [{"range": "<1", "replies": 0}, {"range": "1-10", "replies": 3}]}));
    h.idle();
    assert!(h.has_text_containing("Servidor 192.0.2.53 fora"), "in the explanations' language (Portuguese by default)");
    assert!(h.has_text("error"), "severity chip");
    h.click(h.text("Upstreams"));
    h.idle();
    h.idle();
    assert!(h.has_text("DOH"));
    assert!(h.has_text("all servers"));
}

#[test]
fn a_random_subdomain_attack_shows_in_the_names_tab() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    let p = h.app.panel_mut::<DnsStatsPanel>().unwrap();
    p.tab = crate::dns_statistics::Tab::Names;
    p.stats = Some(json!({"queries": 1000, "resolver": "router", "allow_remote_requests": true,
        "names": [{"name": "www.example.com", "queries": 40, "queries_per_sec": 2.0, "error": 0}],
        "names_tracked": 1,
        "failing_domains": [{"domain": "victim.com.br", "nxdomain": 950, "servfail": 0, "failures_per_sec": 95.0,
            "names": 930, "error": 0, "random": true}],
        "domains_tracked": 1,
        "warnings": [
            {"key": "random_subdomain", "severity": "warning", "text": "Domain victim.com.br: about 930 different names failed",
                "args": {"domain": "victim.com.br", "names": "930", "rate": "95"}},
            {"key": "socket_drops", "severity": "warning", "text": "drops", "args": {"count": "3"}}]}));
    h.idle();
    h.idle();
    assert!(h.has_text("www.example.com"));
    assert!(h.has_text("random names"), "chip on the domain");
    assert!(h.has_text("≈930"));
    assert!(h.has_text_containing("Domínio victim.com.br: cerca de 930 nomes diferentes"), "footer warning");
    assert!(!h.has_text_containing("descartou"), "only the Names tab's warnings");
}

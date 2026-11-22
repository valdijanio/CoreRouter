//! IP › DNS › Query Log (G4.1zd): the button of the DNS window opens it,
//! the rows of the router's log show newest first with Older / Newer, the
//! filters reach the engine, Settings turns the log on only with the
//! acknowledgement of the law, Clear deletes, and every explanation has its
//! text in both languages.

use std::sync::{Arc, Mutex};

use corerouter_engine::dns_log::{Cleared, DnsLogBackend, Found, LogStatus};
use corerouter_proto_dns::querylog::format::{Client, Mode, Record};
use corerouter_proto_dns::querylog::{ClientMatch, Filter};

use super::*;
use crate::dns_query_log::{QueryLogPanel, WIN};

#[derive(Default)]
struct Fake {
    asked: Mutex<Vec<(Filter, Option<String>)>>,
    cleared: Mutex<Vec<(Option<u64>, Option<ClientMatch>)>>,
}

fn record(i: u64) -> (Record, Mode) {
    (
        Record {
            at_ms: 1_763_000_000_000 + i,
            client: Client::Addr("100.64.12.0".parse().unwrap()),
            name: format!("host{i}.example.com"),
            qtype: 28,
            rcode: if i == 1 { 3 } else { 0 },
            flags: 0,
            by: 1,
            ede: None,
            latency_us: 1200,
        },
        Mode::Truncated { v4: 24, v6: 56 },
    )
}

impl DnsLogBackend for Fake {
    fn status(&self) -> LogStatus {
        LogStatus { writing: true, files: 3, bytes: 300 << 20, budget_bytes: 1 << 30, oldest_ms: Some(1_763_000_000_000), ..LogStatus::default() }
    }
    fn search(&self, f: &Filter, _: usize, cursor: Option<&str>, _: u64) -> Result<Found, String> {
        self.asked.lock().unwrap().push((f.clone(), cursor.map(str::to_owned)));
        // Page 1: hosts 3, 2; page 2 (cursor "7:0:0"): host 1.
        let rows = if cursor.is_some() { vec![record(1)] } else { vec![record(3), record(2)] };
        let next = cursor.is_none().then(|| "7:0:0".to_owned());
        Ok(Found { rows, next, scanned: 3, partial: false })
    }
    fn clear(&self, before: Option<u64>, client: Option<&ClientMatch>) -> Result<Cleared, String> {
        self.cleared.lock().unwrap().push((before, client.cloned()));
        Ok(Cleared { files: 0, bytes: 4 << 20, queries: 12 })
    }
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness() -> (Harness, Arc<Fake>) {
    let mut s = Session::virtual_lab();
    let fake = Arc::new(Fake::default());
    s.set_dns_log_backend(fake.clone());
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    (h, fake)
}

#[test]
fn query_log_window_pages_and_filters() {
    let (mut h, fake) = harness();
    h.app.open(Win::Panel(crate::dns::WIN));
    refresh(&mut h);
    h.click(h.text("Query Log"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)), "the DNS window's button opens it");
    assert!(h.has_text("off"), "off by default");
    assert!(h.has_text_containing("Marco Civil art. 14"));
    assert!(h.has_text("host3.example.com") && h.has_text("host2.example.com"));
    assert!(h.has_text("100.64.12.0/24"), "the truncated client");
    assert!(h.has_text_containing("300 MiB"), "disk used against the ceiling");
    h.click(h.text("Older"));
    refresh(&mut h);
    assert!(h.has_text("host1.example.com") && !h.has_text("host3.example.com"));
    assert!(h.has_text("NXDOMAIN"));
    h.click(h.text("Newer"));
    refresh(&mut h);
    assert!(h.has_text("host3.example.com"));

    // Filters reach the engine.
    h.app
        .with_panel_as::<QueryLogPanel, _>(|p, _| {
            p.client = "100.64.12.34".into();
            p.name = "*.example.com".into();
            p.qtype = "aaaa".into();
        })
        .unwrap();
    h.click(h.text("NXDOMAIN"));
    refresh(&mut h);
    let (f, _) = fake.asked.lock().unwrap().last().cloned().unwrap();
    assert_eq!(f.client, Some(ClientMatch::parse("100.64.12.34").unwrap()));
    assert_eq!((f.name.as_deref(), f.qtype, f.rcode), (Some("*.example.com"), Some(28), Some(3)));
    assert!(f.from_ms.is_some(), "the period (last 15 min)");
}

#[test]
fn turning_it_on_needs_the_acknowledgement() {
    let (mut h, _) = harness();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h.click(h.text("Settings…"));
    refresh(&mut h);
    h.app
        .with_panel_as::<QueryLogPanel, _>(|p, _| {
            let d = p.settings.as_mut().unwrap();
            d.form.enabled = true;
            d.form.max_age_hours = "48".into();
        })
        .unwrap();
    refresh(&mut h);
    assert!(h.has_text_containing("Marco Civil art. 14 forbids"), "the law, said in the dialog");
    let p = h.app.panel_mut::<QueryLogPanel>().unwrap();
    let d = p.settings.as_ref().unwrap();
    let params = d.form.params(&d.base).unwrap();
    assert!(params.get("acknowledge").is_none(), "not ticked: no acknowledgement sent");
    // Ticked: OK sends it and the engine turns the log on.
    p.settings.as_mut().unwrap().form.acknowledged = true;
    let d = p.settings.as_ref().unwrap();
    let params = d.form.params(&d.base).unwrap();
    assert_eq!(params["acknowledge"], "marco-civil-art14");
    assert_eq!(params["max_age_hours"], 48);
    h.app.run(params_cmd(), params);
    refresh(&mut h);
    let g = h.app.panel_mut::<QueryLogPanel>().unwrap().get.clone().unwrap();
    assert_eq!(g["enabled"], true);
    assert_eq!(g["max_age_hours"], 48);
    assert!(h.has_text("logging"), "the chip says it writes");
}

fn params_cmd() -> &'static str {
    "ip.dns.log.set"
}

#[test]
fn clear_by_client() {
    let (mut h, fake) = harness();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h.click(h.text("Clear…"));
    refresh(&mut h);
    h.app
        .with_panel_as::<QueryLogPanel, _>(|p, _| p.clear.as_mut().unwrap().client = "100.64.12.34".into())
        .unwrap();
    refresh(&mut h);
    h.click(h.text("OK"));
    refresh(&mut h);
    let c = fake.cleared.lock().unwrap().clone();
    assert_eq!(c, vec![(None, Some(ClientMatch::parse("100.64.12.34").unwrap()))]);
    assert!(h.has_text_containing("12 queries deleted"));
}

#[test]
fn query_log_in_the_lab_says_why_it_is_empty() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text_containing("No daemon"));
}

#[test]
fn every_explanation_has_its_text() {
    use crate::i18n::{Lang, Langs, explain};
    for key in crate::dns_query_log::HELP_KEYS {
        for lang in [Lang::En, Lang::Pt] {
            let (got, text) = explain(Langs { labels: lang, help: lang }, key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(got, lang, "{key}");
            assert!(text.starts_with("## "), "{key}");
        }
    }
}

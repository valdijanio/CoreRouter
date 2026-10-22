//! Tools › DNS Lookup (G6.6): `tool.dns.query` as a task, the answer with
//! its chips and AS pills, and the compare and trace tables.

use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::dns::DnsBackend;
use corerouter_engine::dns_lookup::{Exchanged, LookupServer};
use corerouter_engine::{Clock, Job, Runner};
use corerouter_proto_dns::resolver::ResolveError;

use super::*;
use crate::dns_lookup::{LookupPanel, WIN};
use crate::panel::PanelState;

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

/// The router's chain answering from its cache: one A record.
struct Cached;

/// `query` turned into its reply: QR and RA set, the OPT record dropped,
/// one A record (a pointer to the question's name) for 192.0.2.7.
fn reply(query: &[u8]) -> Vec<u8> {
    let mut end = 12;
    while let Some(&len) = query.get(end) {
        end += 1 + usize::from(len);
        if len == 0 {
            break;
        }
    }
    let mut r = query[..end + 4].to_vec();
    r[2] |= 0x80;
    r[3] |= 0x80;
    r[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
    r
}

impl DnsBackend for Cached {
    fn lookup(&self, _: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Err(ResolveError::NoServers)
    }
    fn cache_rows(&self) -> Vec<corerouter_model::dns::CacheRow> {
        Vec::new()
    }
    fn cache_used_bytes(&self) -> usize {
        0
    }
    fn flush(&self) {}
    fn exchange(&self, to: &LookupServer, q: &[u8], _: bool) -> Result<Exchanged, String> {
        assert_eq!(*to, LookupServer::Router);
        Ok(Exchanged {
            bytes: reply(q),
            server: "127.0.0.1#53(router)".into(),
            transport: "UDP".into(),
            ms: 0,
            stage: Some("cache".into()),
            source: Some("cache".into()),
        })
    }
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.idle();
    h.idle();
    h
}

#[test]
fn lookup_window_runs_the_task_and_shows_the_answer() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.set_dns_backend(Arc::new(Cached));
    s.tick(1_000);
    let mut h = open(s);
    assert!(h.has_text("recursion") && h.has_text("compare"), "option chips");
    h.app.panel_mut::<LookupPanel>().unwrap().name = "www.example.com".into();
    h.idle();
    h.click(h.text("Start"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !(h.has_text("NOERROR") && h.app.panel_mut::<LookupPanel>().unwrap().done) {
        assert!(Instant::now() < deadline, "no answer: {:?}", h.app.log());
        thread::sleep(Duration::from_millis(20));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    h.idle();
    assert!(h.has_text("from cache · etapa cache"), "the stage chip");
    assert!(h.has_text("qr rd ra"), "flags");
    assert!(h.has_text("router · UDP"));
    assert!(h.has_text("Answer"));
    assert!(h.has_text("192.0.2.7"));
    assert!(h.has_text("AS64999 SIM-DEST"), "the AS pill of the lab");
    let p = h.app.panel_mut::<LookupPanel>().unwrap();
    assert_eq!(p.command, "dig www.example.com A");
    let dig = p.dig_text();
    assert!(dig.contains(";; ->>HEADER<<- opcode: QUERY, status: NOERROR"), "{dig}");
    assert!(dig.contains("www.example.com.\t60\tIN\tA\t192.0.2.7"), "{dig}");
    assert!(dig.contains(";; STAGE: cache"), "{dig}");
}

#[test]
fn compare_shows_divergence_and_timeout() {
    let mut h = open(Session::virtual_lab());
    h.app.with_panel_as::<LookupPanel, _>(|p, app| {
        p.task = Some(1);
        p.arrived(app, "poll", 0, json!({"done": true, "state": "done",
            "events": [{"kind": "begin", "mode": "compare"}],
            "summary": {"mode": "compare", "servers": [
                {"kind": "compare", "server": "1.1.1.1", "rcode": "NOERROR", "ms": 9, "data": ["A 192.0.2.7"], "timeout": false, "diverge": false},
                {"kind": "compare", "server": "8.8.8.8", "rcode": "NOERROR", "ms": 14, "data": ["A 192.0.2.7"], "timeout": false, "diverge": false},
                {"kind": "compare", "server": "203.0.113.53", "rcode": "NOERROR", "ms": 31, "data": ["A 203.0.113.66"], "timeout": false, "diverge": true},
                {"kind": "compare", "server": "9.9.9.9", "rcode": null, "ms": null, "data": [], "error": "timeout (no answer in 3000 ms)", "timeout": true, "diverge": false}
            ]},
            "lines": ["SERVER STATUS TIME DATA"], "summary_lines": [";; 203.0.113.53 diverges from the other servers"]}));
        // The events of a compare (the summary replaces them once done).
        p.events.push(json!({"kind": "compare", "server": "1.1.1.1"}));
    });
    h.idle();
    h.idle();
    assert!(h.has_text("diverge"));
    assert!(h.has_text("timeout"));
    assert!(h.has_text("sem resposta"));
    assert!(h.has_text("A 203.0.113.66"));
    assert!(h.has_text("31 ms"));
    let dig = h.app.panel_mut::<LookupPanel>().unwrap().dig_text();
    assert!(dig.ends_with("diverges from the other servers\n"), "{dig}");
}

#[test]
fn trace_rows_say_signed_or_not() {
    let mut h = open(Session::virtual_lab());
    h.app.with_panel_as::<LookupPanel, _>(|p, app| {
        p.task = Some(1);
        p.arrived(app, "poll", 0, json!({"done": true, "state": "done", "events": [
            {"kind": "begin", "mode": "trace"},
            {"kind": "trace", "zone": ".", "asked": "k.root-servers.net.", "address": "193.0.14.129", "ms": 21, "answer": "referral: com. (13 NS)", "signed": true},
            {"kind": "trace", "zone": "com.", "asked": "a.gtld-servers.net.", "address": "192.5.6.30", "ms": null, "error": "timeout (no answer in 3000 ms)", "timeout": true},
            {"kind": "trace", "zone": "com.", "asked": "b.gtld-servers.net.", "address": "192.33.14.30", "ms": 18, "answer": "referral: example.com. (2 NS)", "signed": false},
            {"kind": "trace", "zone": "example.com.", "asked": "a.iana-servers.net.", "address": "199.43.135.53", "ms": 90, "answer": "A 93.184.216.34", "signed": true, "final": true}
        ]}));
    });
    h.idle();
    h.idle();
    assert!(h.has_text("Zone") && h.has_text("Asked"));
    assert!(h.has_text("assinada"));
    assert!(h.has_text("sem assinatura"));
    assert!(h.has_text("referral: com. (13 NS)"));
    assert!(h.has_text("timeout"));
    // Click a row: selected; again: cleared.
    for _ in 0..3 {
        h.idle();
    }
    h.click(h.text("a.iana-servers.net."));
    h.idle();
    assert_eq!(h.app.panel_mut::<LookupPanel>().unwrap().selected, Some(("trace", 3)));
    h.click(h.text("a.iana-servers.net."));
    h.idle();
    assert_eq!(h.app.panel_mut::<LookupPanel>().unwrap().selected, None);
}

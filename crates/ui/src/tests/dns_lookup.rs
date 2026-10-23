//! Tools › DNS Lookup (G6.6): `tool.dns.query` as a task, the answer with
//! its chips and AS pills, and the compare and trace tables; G6.8: the
//! window as wide as its tables, "Why this answer" and "Ask as".

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
            explain: Vec::new(),
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
    let before = h.win_rect(win_id(Win::Panel(WIN))).height();
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
    // Opened as tall as the form, the window grew with the answer.
    let after = h.win_rect(win_id(Win::Panel(WIN))).height();
    assert!(after > before + 40.0, "{before} → {after}");
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

/// Every text painted, as the screen has it.
fn painted(h: &Harness) -> Vec<String> {
    fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for s in &h.shapes {
        walk(&s.shape, &mut out);
    }
    out
}

/// An answer for `name` with `records` (type, data) and the AS of
/// 13.107.42.14, as the task's poll brings it.
fn answer(h: &mut Harness, records: &[(&str, &str)], more: Vec<Value>) {
    let rows: Vec<Value> = records
        .iter()
        .map(|(t, d)| json!({"name": "www.example.com.", "ttl": 60, "class": "IN", "type": t, "data": d}))
        .collect();
    let mut events = vec![
        json!({"kind": "answer", "server": "127.0.0.1#53(router)", "transport": "UDP", "ms": 3,
            "stage": "upstream", "rcode": "NOERROR", "flags": ["qr", "rd", "ra"], "answer": rows,
            "authority": [], "additional": [], "size": 120}),
        json!({"kind": "asn", "address": "13.107.42.14", "asn": 8075,
            "as_name": "MICROSOFT-CORP-MSN-AS-BLOCK, US", "prefix": "13.104.0.0/14"}),
    ];
    events.extend(more);
    h.app.with_panel_as::<LookupPanel, _>(|p, app| {
        p.task = Some(1);
        p.arrived(app, "poll", 0, json!({"done": true, "state": "done", "events": events}));
    });
    // The window follows its contents over a few frames.
    for _ in 0..6 {
        h.idle();
    }
}

/// The user's report: the AS pill in Data came out cut
/// ("AS8075 MICROSOFT-CORP-…"); the window now widens for it.
#[test]
fn the_window_widens_so_the_as_pill_is_whole() {
    let mut h = open(Session::virtual_lab());
    let before = h.win_rect(win_id(Win::Panel(WIN))).width();
    answer(&mut h, &[("A", "13.107.42.14")], Vec::new());
    assert!(h.has_text("AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"), "{:?}", painted(&h));
    assert!(!painted(&h).iter().any(|t| t.ends_with('…')), "nothing cut: {:?}", painted(&h));
    let r = h.win_rect(win_id(Win::Panel(WIN)));
    let pill = h.text("AS8075 MICROSOFT-CORP-MSN-AS-BLOCK");
    assert!(pill.x < r.right(), "the pill inside the window: {pill:?} in {r:?}");
    assert!(r.width() >= before, "{before} → {}", r.width());
}

/// A value longer than the screen: the window stops near the screen's
/// width, and only that value ends in "…" (the whole in its tooltip).
#[test]
fn a_value_wider_than_the_screen_is_cut() {
    let mut h = open(Session::virtual_lab());
    let long = format!("\"v=spf1 {}~all\"", "include:_spf.example.net ".repeat(20));
    answer(&mut h, &[("A", "13.107.42.14"), ("TXT", &long)], Vec::new());
    let r = h.win_rect(win_id(Win::Panel(WIN)));
    assert!(r.width() > 900.0, "it grew: {r:?}");
    assert!(r.right() <= h.screen.x + 1.0, "and stayed on the screen: {r:?}");
    let shown = painted(&h);
    assert!(!shown.contains(&long), "not whole");
    assert!(shown.iter().any(|t| t.starts_with("\"v=spf1 include") && t.ends_with('…')), "{shown:?}");
    assert!(h.has_text("AS8075 MICROSOFT-CORP-MSN-AS-BLOCK"), "the pill stays whole");
}

/// Why this answer: one row per stage, the texts in the explanations'
/// language (Portuguese by default), and "Open entry" opens IP › DNS ›
/// Static with the entry selected.
#[test]
fn why_this_answer_lists_the_stages_and_opens_the_rule() {
    let mut s = Session::virtual_lab();
    let id = s
        .execute("ip.dns.static.add", &json!({"name": "nas.lan", "address": "192.168.88.2"}))
        .unwrap();
    let id = id["id"].as_str().unwrap_or("*1").to_owned();
    let list = s.execute("ip.dns.adlist.add", &json!({"file": "ads.txt"})).unwrap();
    let list = list["id"].as_str().unwrap_or("*1").to_owned();
    let mut h = open(s);
    let why = |stage: &str, outcome: &str, id: &str, args: Value, text: &str, rule: Value| {
        json!({"kind": "why", "stage": stage, "outcome": outcome, "why": id, "args": args, "text": text, "rule": rule})
    };
    answer(&mut h, &[("A", "192.168.88.2")], vec![
        why("acl", "passed", "acl.allowed", json!({"client": "192.168.88.10", "net": "192.168.88.0/24"}),
            "192.168.88.10 is in allowed_from (192.168.88.0/24)", Value::Null),
        why("adlist", "passed", "adlist.allowed", json!({"list": list, "line": "2", "text": "0.0.0.0 nas.lan"}),
            "listed in adlist … but a static FWD entry lets it through", json!({"kind": "adlist", "id": list})),
        why("static", "answered", "static.answered", json!({"id": "*3", "match": "name=nas.lan", "type": "A"}),
            "static entry *3 (name=nas.lan) answers A", json!({"kind": "static", "id": id})),
        why("cache", "not-reached", "not-reached", json!({"stage": "static"}), "not reached: static answered first", Value::Null),
    ]);
    assert!(h.has_text("Why this answer"));
    assert!(h.has_text("192.168.88.10 está no allowed_from (192.168.88.0/24)"), "{:?}", painted(&h));
    assert!(h.has_text("a entrada static *3 (name=nas.lan) responde A"));
    assert!(h.has_text("não chegou: static respondeu antes"));
    assert!(h.has_text("answered") && h.has_text("not reached") && h.has_text("passed"));
    h.click(h.text("Open entry"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(crate::dns::WIN_STATIC)));
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.app.panel_mut::<crate::dns::DnsPanel>().unwrap().static_table.is_selected(&id), "{id}");
    // The adlist window was never open (no rows yet): the list is
    // selected once they arrive.
    h.click(h.text("Open list"));
    for _ in 0..4 {
        h.idle();
    }
    assert!(h.app.open.contains(&Win::Panel(crate::dns_adlist::WIN)));
    assert!(h.app.panel_mut::<crate::dns_adlist::AdlistPanel>().unwrap().table.is_selected(&list), "{list}");
    // In English when the explanations are.
    h.app.lang.help = crate::i18n::Lang::En;
    h.idle();
    h.idle();
    assert!(h.has_text("static entry *3 (name=nas.lan) answers A"));
}

/// "Ask as" shows with the router as the server and goes into the params.
#[test]
fn ask_as_is_a_router_field() {
    let mut h = open(Session::virtual_lab());
    assert!(h.has_text("Ask as"));
    h.app.panel_mut::<LookupPanel>().unwrap().ask = crate::dns_lookup::Ask::All;
    h.idle();
    h.idle();
    assert!(!h.has_text("Ask as"), "only for the router's chain");
}

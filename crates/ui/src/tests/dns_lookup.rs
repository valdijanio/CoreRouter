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
    assert!(h.has_text("13.107.42.14"), "the address whole: {:?}", painted(&h));
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

/// G6.8 Watch: Start runs `tool.dns.watch` on the router; the rows come in
/// as the task goes, and Esc stops it.
#[test]
fn watch_runs_until_esc() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.set_dns_backend(Arc::new(Cached));
    s.tick(1_000);
    let mut h = open(s);
    h.click(h.text("Watch"));
    h.idle();
    {
        let p = h.app.panel_mut::<LookupPanel>().unwrap();
        p.name = "www.example.com".into();
        p.interval = "100".into();
    }
    h.idle();
    h.click(h.text("Start"));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n = h.app.panel_mut::<LookupPanel>().unwrap().watch.events.iter().filter(|e| e["kind"] == "watch").count();
        if n >= 3 {
            break;
        }
        assert!(Instant::now() < deadline, "no rows: {:?}", h.app.log());
        thread::sleep(Duration::from_millis(50));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    h.idle();
    assert!(h.has_text("Latency") && h.has_text("Answer"), "{:?}", painted(&h));
    assert!(h.has_text("A 192.0.2.7"));
    assert!(h.has_text("Stop"));
    // Esc stops the watch (the window stays).
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    let deadline = Instant::now() + Duration::from_secs(5);
    while h.app.panel_mut::<LookupPanel>().unwrap().watch.running() {
        assert!(Instant::now() < deadline, "still running");
        thread::sleep(Duration::from_millis(50));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    assert!(h.app.open.contains(&Win::Panel(WIN)));
}

/// Watch rows: `changed` and `spike` chips, newest first.
#[test]
fn watch_rows_mark_changes_and_spikes() {
    let mut h = open(Session::virtual_lab());
    h.app.with_panel_as::<LookupPanel, _>(|p, app| {
        p.tab = crate::dns_lookup::Tab::Watch;
        p.watch.task = Some(1);
        p.arrived(app, "watch-poll", 0, json!({"done": false, "events": [
            {"kind": "begin", "seq": 0},
            {"kind": "watch", "seq": 1, "n": 1, "at": 3600.0, "t_ms": 0, "ms": 10, "rcode": "NOERROR", "stage": "cache", "ttl": 60, "data": ["A 192.0.2.7"], "changed": false, "spike": false, "timeout": false},
            {"kind": "watch", "seq": 2, "n": 2, "at": 3601.0, "t_ms": 1000, "ms": 250, "rcode": "NOERROR", "stage": "upstream", "ttl": 300, "data": ["A 192.0.2.8"], "changed": true, "spike": true, "timeout": false}
        ], "summary": {"mode": "watch", "sent": 2, "answered": 2, "loss_pct": 0.0, "p50_ms": 10.0, "p95_ms": 250.0, "max_ms": 250.0, "changes": 1, "spikes": 1}}));
    });
    for _ in 0..3 {
        h.idle();
    }
    assert_eq!(h.app.panel_mut::<LookupPanel>().unwrap().watch.last_seq, Some(2), "next poll asks after 2");
    assert!(h.has_text("changed") && h.has_text("spike"), "{:?}", painted(&h));
    assert!(h.has_text("01:00:01") && h.has_text("A 192.0.2.8"));
    assert!(h.has_text("1 × changed"));
    let rows = painted(&h);
    let first = rows.iter().position(|t| t == "01:00:01").unwrap();
    let second = rows.iter().position(|t| t == "01:00:00").unwrap();
    assert!(first < second, "newest first");
}

/// Upstreams: a row per server with its chips, then the advice in the
/// explanations' language.
#[test]
fn upstreams_rows_and_advice() {
    let mut h = open(Session::virtual_lab());
    h.app.with_panel_as::<LookupPanel, _>(|p, app| {
        p.tab = crate::dns_lookup::Tab::Upstreams;
        p.bench.task = Some(1);
        p.arrived(app, "bench-poll", 0, json!({"done": true, "state": "done", "events": [], "summary": {"mode": "upstreams",
            "servers": [
                {"server": "1.1.1.1", "groups": [], "transport": "UDP", "sent": 200, "answered": 200, "loss_pct": 0.0, "servfail_pct": 0.0, "p50_ms": 9.0, "p99_ms": 31.0, "tcp": true, "edns": true, "edns_udp": 1232, "nxdomain_hijack": false, "proxy": false, "forwarder": false, "down": false},
                {"server": "203.0.113.53", "groups": ["CORP"], "transport": "UDP", "sent": 200, "answered": 200, "loss_pct": 0.0, "servfail_pct": 0.0, "p50_ms": 7.0, "p99_ms": 20.0, "tcp": false, "edns": false, "nxdomain_hijack": true, "nx_data": ["A 203.0.113.66"], "proxy": true, "egress": ["198.51.100.77"], "egress_as": 64511, "server_as": 64500, "forwarder": false, "down": false}
            ],
            "recommend": [
                {"kind": "remove", "server": "203.0.113.53", "why": "hijack", "args": {"server": "203.0.113.53", "data": "A 203.0.113.66"}, "text": "203.0.113.53 answers names that do not exist (A 203.0.113.66) instead of NXDOMAIN: remove it"},
                {"kind": "use", "server": "1.1.1.1", "why": "use", "args": {"server": "1.1.1.1", "p50": "9", "p99": "31"}, "text": "use 1.1.1.1: p50 9 ms, p99 31 ms, no loss"}
            ]}}));
    });
    for _ in 0..4 {
        h.idle();
    }
    for t in ["1.1.1.1", "CORP", "9 ms", "NXDOMAIN hijacked", "proxy on the path", "EDNS 1232", "Recommendation"] {
        assert!(h.has_text(t), "{t}: {:?}", painted(&h));
    }
    assert!(h.has_text("203.0.113.53 responde nomes que não existem (A 203.0.113.66) em vez de NXDOMAIN: remova"));
    assert!(h.has_text("use 1.1.1.1: p50 de 9 ms, p99 de 31 ms, sem perda"));
}

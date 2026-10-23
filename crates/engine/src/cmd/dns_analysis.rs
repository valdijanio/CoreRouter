//! G6.8 DNS Lookup › Watch and Upstreams: `tool.dns.watch` (the same query
//! over and over, latency and answer changes) and `tool.dns.upstreams` (a
//! benchmark of every upstream, with hijack checks and advice). Tasks, as
//! `tool.dns.query`; the jobs are `crate::dns_watch` and
//! `crate::dns_upstreams`.

use std::net::IpAddr;
use std::time::Duration;

use corerouter_proto_dns::dig::{self, Ask};
use corerouter_proto_dns::message::parse_name;
use serde_json::{Value, json};

use super::CommandSpec;
use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::dns_lookup::{can_lookup, server, upstreams};
use crate::dns_lookup::{LookupServer, NEEDS_DAEMON, record_type};
use crate::dns_upstreams::{Bench, DEFAULT_COUNT, MAX_COUNT, Target};
use crate::dns_watch::Watch;
use crate::{EngineError, Result, Session};

/// Watch interval bounds (ms).
const MIN_INTERVAL_MS: u64 = 100;
const MAX_INTERVAL_MS: u64 = 60_000;
const DEFAULT_INTERVAL_MS: u64 = 1000;
/// A watch stops by itself after this many queries (`count` 0).
const MAX_WATCH: u64 = 100_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.dns.watch", "DNS Watch", ["Tools", "DNS Lookup"], None,
        "{name: string (a name, or an address for its PTR), type?: A | AAAA | ANY | CAA | CNAME | DNSKEY | DS | HTTPS | MX | NS | PTR | SOA | SRV | SSHFP | SVCB | TLSA | TXT (default A; PTR for an address), server?: string (empty or router = the router's own chain; an IP; https://… DoH or tls://… DoT), interval_ms?: u32 (100..60000, default 1000), count?: u32 (0 = until stopped, default), tcp?: bool} → {id, task_id, name, type, server, interval_ms}; events {kind: watch, n, at, t_ms, ms, rcode, stage, ttl, data, changed, spike, error?, timeout}",
        can_lookup, watch)
    .alias("dns-watch")
    .positional("name")
    .task(),
    cmd!(query "tool.dns.upstreams", "DNS Upstreams", ["Tools", "DNS Lookup"], None,
        "{count?: u32 (queries per server, 10..2000, default 200), hijack?: bool (check NXDOMAIN hijacking and a proxy on the way, default true)} → {id, task_id, servers, count}; events {kind: progress|bench, …}; summary {servers, recommend: [{kind: use|remove|note, server, why, args, text}]}",
        can_lookup, bench)
    .alias("dns-upstreams")
    .task(),
];

/// The name and type asked, as `tool.dns.query` reads them.
fn question(p: &Value) -> Result<(String, Ask, &'static str)> {
    let typed = req_str(p, "name")?.trim().to_owned();
    let shown: String = typed.chars().take(64).collect();
    let (name, default_type) = match typed.parse::<IpAddr>() {
        Ok(ip) => (corerouter_proto_dns::reverse::reverse_name(ip), "PTR"),
        Err(_) => (typed.clone(), "A"),
    };
    let qn = parse_name(&name).map_err(|e| EngineError::bad("name", format!("'{shown}': {e}")))?;
    let (rtype, rt) = match opt_str(p, "type")? {
        None | Some("") => record_type(default_type),
        Some(t) => record_type(t),
    }
    .ok_or_else(|| EngineError::bad("type", format!("must be one of {}", dig::TYPES.join(", "))))?;
    Ok((
        name,
        Ask {
            name: qn.name,
            rtype: rt,
            recursion: true,
            dnssec: false,
        },
        rtype,
    ))
}

fn watch(s: &mut Session, p: &Value) -> Result<Value> {
    let (name, ask, rtype) = question(p)?;
    let to = server(opt_str(p, "server")?.unwrap_or(""))?
        .ok_or_else(|| EngineError::bad("server", "watch asks one server: use Upstreams for all"))?;
    let interval_ms = opt_u32(p, "interval_ms")?.map(u64::from).unwrap_or(DEFAULT_INTERVAL_MS);
    if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&interval_ms) {
        return Err(EngineError::bad(
            "interval_ms",
            format!("must be {MIN_INTERVAL_MS}..{MAX_INTERVAL_MS}"),
        ));
    }
    let count = opt_u32(p, "count")?.map(u64::from).unwrap_or(0);
    if count > MAX_WATCH {
        return Err(EngineError::bad("count", format!("at most {MAX_WATCH} (0 = until stopped)")));
    }
    let w = Watch {
        ask,
        to: to.clone(),
        tcp: opt_bool(p, "tcp")?.unwrap_or(false),
        interval: Duration::from_millis(interval_ms),
        count: if count == 0 { MAX_WATCH } else { count },
        started_unix: s.now(),
    };
    let backend = s
        .dns_backend()
        .ok_or_else(|| EngineError::Hal(NEEDS_DAEMON.into()))?;
    let title = format!("dns watch {name} {rtype} @{}", to.label());
    let id = s.start_task("dns-watch", title, move |ctx| crate::dns_watch::run(ctx, &backend, &w))?;
    Ok(json!({"id": id, "task_id": id, "name": name, "type": rtype, "server": to.label(),
        "interval_ms": interval_ms}))
}

/// Every server the router may ask: `ip.dns` (servers, `use_doh_server`)
/// and each enabled forwarders group's, once each with the groups that
/// list it.
fn targets(s: &Session) -> Vec<Target> {
    let mut out: Vec<Target> = upstreams(s)
        .into_iter()
        .map(|to| Target { to, groups: Vec::new() })
        .collect();
    let cfg = s.store().running();
    for g in cfg.ip.dns_forwarders.entries.iter().filter(|g| !g.disabled) {
        let tos = g
            .dns_servers
            .iter()
            .map(|ip| LookupServer::Plain(*ip))
            .chain(g.doh_servers.iter().map(|u| LookupServer::Secure(u.clone())));
        for to in tos {
            match out.iter_mut().find(|t| t.to == to) {
                Some(t) => t.groups.push(g.name.clone()),
                None => out.push(Target {
                    to,
                    groups: vec![g.name.clone()],
                }),
            }
        }
    }
    out
}

fn bench(s: &mut Session, p: &Value) -> Result<Value> {
    let count = opt_u32(p, "count")?.map(u64::from).unwrap_or(DEFAULT_COUNT);
    if !(10..=MAX_COUNT).contains(&count) {
        return Err(EngineError::bad("count", format!("must be 10..{MAX_COUNT}")));
    }
    let list = targets(s);
    if list.is_empty() {
        return Err(EngineError::bad(
            "count",
            "no upstream to measure: set ip.dns.set servers=…, use_doh_server or a forwarders group",
        ));
    }
    let backend = s
        .dns_backend()
        .ok_or_else(|| EngineError::Hal(NEEDS_DAEMON.into()))?;
    let prober = s.tool_prober().ok();
    let servers: Vec<String> = list.iter().map(|t| t.to.label()).collect();
    let b = Bench {
        targets: list,
        count,
        hijack: opt_bool(p, "hijack")?.unwrap_or(true),
        seed: s.now().unwrap_or(0),
    };
    let title = format!("dns upstreams ({} servers × {count})", servers.len());
    let id = s.start_task("dns-upstreams", title, move |ctx| {
        crate::dns_upstreams::run(ctx, &backend, prober.as_ref(), &b)
    })?;
    Ok(json!({"id": id, "task_id": id, "servers": servers, "count": count}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsBackend;
    use crate::dns_lookup::Exchanged;
    use crate::tasks::test_runner;
    use corerouter_hal::probe::{AsInfo, Lookup};
    use corerouter_proto_dns::resolver::ResolveError;
    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, TXT};
    use hickory_proto::rr::{RData, Record, RecordType};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..1000 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256, "text": true}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    /// A lab of upstreams (192.0.2.0/24 is AS64500, 198.51.100.0/24 AS64511):
    /// - .1 and .2 answer fast and say they are themselves (whoami);
    /// - .3 answers, slowly;
    /// - .66 answers fast, and answers names that do not exist (a hijacker);
    /// - .5 is answered by a resolver of the client's own network (AS64511:
    ///   a proxy on the way);
    /// - .3's resolver leaves from another network (AS64512, not the
    ///   client's): told, not judged;
    /// - .9 never answers.
    ///
    /// The router (watch) answers 192.0.2.7, then 192.0.2.8 from the 4th
    /// query on, in 10 ms but 200 ms the 6th time.
    #[derive(Default)]
    struct Lab {
        asked: Mutex<Vec<(String, String, bool)>>,
        router: AtomicU64,
    }

    fn reply(q: &Message, rcode: ResponseCode, data: Option<RData>) -> Vec<u8> {
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.recursion_available = true;
        m.metadata.response_code = rcode;
        m.add_queries(q.queries.clone());
        if let Some(d) = data {
            m.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, d));
        }
        m.set_edns(hickory_proto::op::Edns::new());
        m.to_vec().unwrap()
    }

    impl DnsBackend for Lab {
        fn lookup(&self, _: &str) -> std::result::Result<Vec<IpAddr>, ResolveError> {
            Ok(Vec::new())
        }
        fn cache_rows(&self) -> Vec<corerouter_model::dns::CacheRow> {
            Vec::new()
        }
        fn cache_used_bytes(&self) -> usize {
            0
        }
        fn flush(&self) {}
        fn origin_as_nowait(&self, ip: IpAddr) -> Option<Lookup<Option<AsInfo>>> {
            let t = ip.to_string();
            let asn = if t.starts_with("192.0.2.") {
                Some(64500)
            } else if t.starts_with("198.51.100.") {
                Some(64511)
            } else if t.starts_with("203.0.113.") {
                Some(64512)
            } else {
                None
            };
            Some(Lookup::Done(asn.map(|asn| AsInfo { asn, name: None, prefix: None })))
        }
        fn exchange(&self, to: &LookupServer, q: &[u8], tcp: bool) -> std::result::Result<Exchanged, String> {
            let m = Message::from_vec(q).unwrap();
            let name = m.queries[0].name().to_ascii().trim_end_matches('.').to_owned();
            let qtype = m.queries[0].query_type();
            let server = to.label();
            self.asked.lock().unwrap().push((server.clone(), name.clone(), tcp));
            let ok = |bytes, ms| Ok(Exchanged { bytes, server: server.clone(), transport: "UDP".into(), ms, stage: None, source: None, explain: Vec::new() });
            let a = |x: [u8; 4]| Some(RData::A(A::new(x[0], x[1], x[2], x[3])));
            // Akamai's form, with the client's own address ("ip"): the lab
            // router is 198.51.100.1, in AS64511.
            let txt = |ip: &str| Some(RData::TXT(TXT::new(vec!["ns".into(), ip.into(), "ip".into(), "198.51.100.1".into()])));
            let popular = crate::dns_upstreams::POPULAR.contains(&name.as_str());
            let whoami = crate::dns_upstreams::WHOAMI.contains(&name.as_str());
            match server.as_str() {
                "router" => {
                    let n = self.router.fetch_add(1, Ordering::Relaxed) + 1;
                    let ip = if n >= 4 { [192, 0, 2, 8] } else { [192, 0, 2, 7] };
                    ok(reply(&m, ResponseCode::NoError, a(ip)), if n == 6 { 200 } else { 10 })
                }
                "192.0.2.9" => Err("timeout (no answer in 3000 ms)".into()),
                "192.0.2.5" if whoami => ok(reply(&m, ResponseCode::NoError, txt("198.51.100.77")), 9),
                "192.0.2.3" if whoami => ok(reply(&m, ResponseCode::NoError, txt("203.0.113.9")), 300),
                s if whoami => ok(reply(&m, ResponseCode::NoError, txt(s)), 9),
                "192.0.2.66" if qtype == RecordType::A => ok(reply(&m, ResponseCode::NoError, a([203, 0, 113, 66])), 5),
                s => {
                    let ms = match s { "192.0.2.3" => 300, "192.0.2.2" => 12, _ => 10 };
                    if popular {
                        ok(reply(&m, ResponseCode::NoError, a([192, 0, 2, 200])), ms)
                    } else {
                        ok(reply(&m, ResponseCode::NXDomain, None), ms)
                    }
                }
            }
        }
    }

    fn lab() -> (Session, Arc<Lab>) {
        let fake = Arc::new(Lab::default());
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        s.set_dns_backend(fake.clone());
        (s, fake)
    }

    #[test]
    fn watch_marks_the_change_and_the_spike() {
        let (mut s, _) = lab();
        let r = s
            .execute("tool.dns.watch", &json!({"name": "www.example", "interval_ms": 100, "count": 8}))
            .unwrap();
        assert_eq!(r["server"], "router");
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "done", "{done}");
        let ev: Vec<&Value> = done["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "watch").collect();
        assert_eq!(ev.len(), 8);
        let changed: Vec<u64> = ev.iter().filter(|e| e["changed"] == true).map(|e| e["n"].as_u64().unwrap()).collect();
        assert_eq!(changed, [4], "the answer changed once, at the 4th");
        let spikes: Vec<u64> = ev.iter().filter(|e| e["spike"] == true).map(|e| e["n"].as_u64().unwrap()).collect();
        assert_eq!(spikes, [6]);
        assert_eq!(ev[0]["data"], json!(["A 192.0.2.7"]));
        assert_eq!(done["summary"]["changes"], 1);
        assert_eq!(done["summary"]["spikes"], 1);
        let lines: Vec<&str> = done["lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(lines[0].contains("STATUS"), "{lines:?}");
        assert!(lines.iter().any(|l| l.ends_with("A 192.0.2.8 changed")), "{lines:?}");
    }

    #[test]
    fn watch_refuses_bad_params() {
        let (mut s, fake) = lab();
        for p in [
            json!({}),
            json!({"name": "a.example", "interval_ms": 10}),
            json!({"name": "a.example", "interval_ms": 600_000}),
            json!({"name": "a.example", "server": "all"}),
            json!({"name": "a.example", "count": 1_000_000}),
        ] {
            let err = s.execute("tool.dns.watch", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(fake.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn upstreams_rank_and_catch_the_hijacker_and_the_proxy() {
        let (mut s, fake) = lab();
        // Nothing configured: refused, with what to set.
        assert!(s.execute("tool.dns.upstreams", &json!({})).is_err());
        s.execute(
            "ip.dns.set",
            &json!({"servers": ["192.0.2.1", "192.0.2.3", "192.0.2.66", "192.0.2.5", "192.0.2.9"]}),
        )
        .unwrap();
        s.execute("ip.dns.forwarders.add", &json!({"name": "CORP", "dns_servers": ["192.0.2.2", "192.0.2.1"]}))
            .unwrap();
        let r = s.execute("tool.dns.upstreams", &json!({"count": 40})).unwrap();
        assert_eq!(r["servers"], json!(["192.0.2.1", "192.0.2.3", "192.0.2.66", "192.0.2.5", "192.0.2.9", "192.0.2.2"]));
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "done", "{done}");
        let rows = done["summary"]["servers"].as_array().unwrap();
        let row = |srv: &str| rows.iter().find(|r| r["server"] == srv).unwrap();
        assert_eq!(row("192.0.2.1")["groups"], json!(["CORP"]), "listed once, with its group");
        assert_eq!(row("192.0.2.1")["sent"], 40);
        assert_eq!(row("192.0.2.1")["loss_pct"], 0.0);
        assert_eq!(row("192.0.2.1")["p50_ms"], 10.0);
        assert_eq!(row("192.0.2.3")["p50_ms"], 300.0);
        assert_eq!(row("192.0.2.1")["tcp"], true);
        assert_eq!(row("192.0.2.1")["edns"], true);
        assert_eq!(row("192.0.2.1")["nxdomain_hijack"], false);
        assert_eq!(row("192.0.2.1")["proxy"], false, "says it is itself");
        assert_eq!(row("192.0.2.66")["nxdomain_hijack"], true);
        assert_eq!(row("192.0.2.5")["proxy"], true, "AS64511 answers for an AS64500 server");
        assert_eq!(row("192.0.2.5")["egress_as"], 64511);
        assert_eq!(row("192.0.2.3")["proxy"], false, "another network, not the client's");
        assert_eq!(row("192.0.2.3")["other_network"], true);
        assert_eq!(row("192.0.2.9")["down"], true);
        assert_eq!(row("192.0.2.9")["loss_pct"], 100.0);
        let dead = fake.asked.lock().unwrap().iter().filter(|a| a.0 == "192.0.2.9").count();
        assert!(dead < 20, "a dead server is not asked {dead} times");
        // Half the names are random, under the popular ones.
        let one: Vec<String> = fake.asked.lock().unwrap().iter().filter(|a| a.0 == "192.0.2.1" && !a.2).map(|a| a.1.clone()).collect();
        let random = one.iter().filter(|n| !crate::dns_upstreams::POPULAR.contains(&n.as_str())).count();
        assert!(random >= 20, "{random} random of {}", one.len());
        let advice: Vec<(String, String)> = done["summary"]["recommend"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| (a["kind"].as_str().unwrap().to_owned(), format!("{} {}", a["server"].as_str().unwrap(), a["why"].as_str().unwrap())))
            .collect();
        for want in [
            ("use", "192.0.2.1 use"),
            ("use", "192.0.2.2 use"),
            ("remove", "192.0.2.3 slow"),
            ("remove", "192.0.2.66 hijack"),
            ("remove", "192.0.2.5 proxy"),
            ("remove", "192.0.2.9 down"),
            ("note", "192.0.2.3 other-network"),
        ] {
            assert!(advice.contains(&(want.0.to_owned(), want.1.to_owned())), "{want:?} in {advice:?}");
        }
        let lines: Vec<&str> = done["summary_lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(lines.iter().any(|l| l.starts_with(";; remove: 192.0.2.66 answers names that do not exist")), "{lines:?}");
        assert!(s.execute("tool.dns.upstreams", &json!({"count": 5})).is_err(), "at least 10");
    }
}

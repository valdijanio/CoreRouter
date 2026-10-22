//! `tool.dns.query` (G6.6): Tools › DNS Lookup, `/tool dns-lookup`. A
//! `dig` as a task, never a wait under the session lock. The job is
//! `crate::dns_lookup`; the codec `corerouter_proto_dns::dig`.

use std::net::IpAddr;

use corerouter_proto_dns::dig::{self, Ask};
use corerouter_proto_dns::message::parse_name;
use serde_json::{Value, json};

use super::CommandSpec;
use super::args::{opt_bool, opt_str, req_str};
use crate::dns_lookup::{Job, LookupServer, Mode, NEEDS_DAEMON, command_line, record_type, run};
use crate::tasks::can_run;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "tool.dns.query", "DNS Lookup", ["Tools", "DNS Lookup"], None,
    "{name: string (a name, or an address for its PTR), type?: A | AAAA | ANY | CAA | CNAME | DNSKEY | DS | HTTPS | MX | NS | PTR | SOA | SRV | SSHFP | SVCB | TLSA | TXT (default A; PTR for an address), server?: string (empty or router = the router's own chain; an IP; https://… DoH or tls://… DoT; all = every upstream, as compare), recursion?: bool (RD, default true), dnssec?: bool (DO), tcp?: bool, trace?: bool (from the root down), compare?: bool (every upstream side by side)} → {id, task_id, mode, name, type, command}; events {kind: answer|asn|compare|trace|error, …}",
    can_lookup, query)
.alias("dns-lookup")
.positional("name")
.task()];

/// Tasks, and the daemon's resolver to carry the bytes.
fn can_lookup(s: &Session) -> std::result::Result<(), String> {
    can_run(s)?;
    if s.dns_backend().is_none() {
        return Err(NEEDS_DAEMON.into());
    }
    Ok(())
}

fn server(raw: &str) -> Result<Option<LookupServer>> {
    let t = raw.trim();
    let shown: String = t.chars().take(64).collect();
    if t.is_empty() || t.eq_ignore_ascii_case("router") {
        return Ok(Some(LookupServer::Router));
    }
    if t.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        if !corerouter_model::dns::usable_server(ip) {
            return Err(EngineError::bad("server", format!("{ip} cannot be a DNS server")));
        }
        return Ok(Some(LookupServer::Plain(ip)));
    }
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("tls://") {
        corerouter_proto_dns::check_secure(t)
            .map_err(|e| EngineError::bad("server", format!("'{shown}': {e}")))?;
        return Ok(Some(LookupServer::Secure(t.to_owned())));
    }
    Err(EngineError::bad(
        "server",
        format!("'{shown}': an IP, https://… (DoH), tls://… (DoT), router or all"),
    ))
}

/// Every upstream the router asks: the servers, then `use_doh_server`.
fn upstreams(s: &Session) -> Vec<LookupServer> {
    let settings = s.dns_settings();
    let mut out: Vec<LookupServer> = settings.servers.iter().map(|ip| LookupServer::Plain(*ip)).collect();
    out.extend(settings.secure.iter().map(|x| LookupServer::Secure(x.url())));
    out
}

fn query(s: &mut Session, p: &Value) -> Result<Value> {
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
    let to = server(opt_str(p, "server")?.unwrap_or(""))?;
    let trace = opt_bool(p, "trace")?.unwrap_or(false);
    let compare = opt_bool(p, "compare")?.unwrap_or(false) || to.is_none();
    let mode = match (trace, compare, to) {
        (true, true, _) => {
            return Err(EngineError::bad("trace", "trace and compare do not run together"));
        }
        (true, false, Some(LookupServer::Router)) => Mode::Trace,
        (true, false, _) => {
            return Err(EngineError::bad(
                "server",
                "trace starts at the root servers: leave server empty",
            ));
        }
        (false, true, Some(to)) if to != LookupServer::Router => {
            return Err(EngineError::bad(
                "server",
                "compare asks every upstream: leave server empty (or all)",
            ));
        }
        (false, true, _) => {
            let list = upstreams(s);
            if list.is_empty() {
                return Err(EngineError::bad(
                    "compare",
                    "no upstream server to compare: set ip.dns servers=… or use_doh_server",
                ));
            }
            Mode::Compare(list)
        }
        (false, false, Some(to)) => Mode::One(to),
        (false, false, None) => Mode::Compare(upstreams(s)),
    };
    let job = Job {
        typed,
        ask: Ask {
            name: qn.name,
            rtype: rt,
            recursion: opt_bool(p, "recursion")?.unwrap_or(true),
            dnssec: opt_bool(p, "dnssec")?.unwrap_or(false),
        },
        rtype,
        tcp: opt_bool(p, "tcp")?.unwrap_or(false),
        mode,
    };
    let backend = s
        .dns_backend()
        .ok_or_else(|| EngineError::Hal(NEEDS_DAEMON.into()))?;
    let prober = s.tool_prober().ok();
    let (mode, server_name) = match &job.mode {
        Mode::One(to) => ("query", to.dig_name()),
        Mode::Compare(_) => ("compare", None),
        Mode::Trace => ("trace", None),
    };
    let command = command_line(&job, server_name.as_deref());
    let title = format!("dig {}", command.chars().take(80).collect::<String>());
    let id = s.start_task("dns-lookup", title, move |ctx| {
        run(ctx, &backend, prober.as_ref(), &job)
    })?;
    Ok(json!({"id": id, "task_id": id, "mode": mode, "name": name, "type": rtype,
        "command": format!("dig {command}")}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsBackend, Resolution};
    use crate::dns_lookup::Exchanged;
    use crate::tasks::test_runner;
    use corerouter_proto_dns::resolver::ResolveError;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..500 {
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

    /// A reply to `q` with an A record per address of `answers`.
    fn reply(q: &[u8], rcode: u8, answers: &[[u8; 4]]) -> Vec<u8> {
        use hickory_proto::op::{Message, OpCode, ResponseCode};
        use hickory_proto::rr::{RData, Record, rdata::A};
        let q = Message::from_vec(q).unwrap();
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.recursion_desired = q.metadata.recursion_desired;
        m.metadata.recursion_available = true;
        m.metadata.response_code = ResponseCode::from(0, rcode);
        m.add_queries(q.queries.clone());
        for a in answers {
            m.add_answer(Record::from_rdata(q.queries[0].name().clone(), 300, RData::A(A::new(a[0], a[1], a[2], a[3]))));
        }
        m.to_vec().unwrap()
    }

    /// Upstreams: 192.0.2.1 and .2 agree, .5 hands out another server of
    /// the same AS (a CDN), .3 lies, .4 never answers.
    #[derive(Default)]
    struct Fake(Mutex<Vec<(LookupServer, bool)>>);

    impl DnsBackend for Fake {
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
        fn resolve_query(&self, _: &str, _: &str, _: Option<IpAddr>) -> std::result::Result<Resolution, String> {
            Err("unused".into())
        }
        /// 192.0.2.0/24 is AS64500; anything else has no known origin.
        fn origin_as_nowait(&self, ip: IpAddr) -> Option<corerouter_hal::probe::Lookup<Option<corerouter_hal::probe::AsInfo>>> {
            let known = ip.to_string().starts_with("192.0.2.");
            Some(corerouter_hal::probe::Lookup::Done(known.then(|| corerouter_hal::probe::AsInfo {
                asn: 64500,
                name: Some("EXAMPLE".into()),
                prefix: None,
            })))
        }
        fn exchange(&self, to: &LookupServer, q: &[u8], tcp: bool) -> std::result::Result<Exchanged, String> {
            self.0.lock().unwrap().push((to.clone(), tcp));
            let (bytes, stage) = match to {
                LookupServer::Router => (reply(q, 0, &[[192, 0, 2, 7]]), Some("cache".to_owned())),
                LookupServer::Plain(ip) if ip.to_string() == "192.0.2.3" => (reply(q, 0, &[[203, 0, 113, 66]]), None),
                LookupServer::Plain(ip) if ip.to_string() == "192.0.2.5" => (reply(q, 0, &[[192, 0, 2, 8]]), None),
                LookupServer::Plain(ip) if ip.to_string() == "192.0.2.4" => {
                    return Err("timeout (no answer in 3000 ms)".into());
                }
                _ => (reply(q, 0, &[[192, 0, 2, 7]]), None),
            };
            Ok(Exchanged {
                bytes,
                server: format!("{}#53", to.label()),
                transport: if tcp { "TCP" } else { "UDP" }.into(),
                ms: 4,
                stage,
                source: None,
            })
        }
    }

    fn lab(fake: &Arc<Fake>) -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        s.set_dns_backend(fake.clone());
        s
    }

    #[test]
    fn one_query_through_the_router() {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        // No daemon resolver: disabled, with why.
        let err = s.execute("tool.dns.query", &json!({"name": "www.example"})).unwrap_err();
        assert!(matches!(err, EngineError::Disabled { .. }), "{err}");
        let fake = Arc::new(Fake::default());
        let mut s = lab(&fake);
        let r = s
            .execute("tool.dns.query", &json!({"name": "www.example", "type": "a", "dnssec": true}))
            .unwrap();
        assert_eq!(r["mode"], "query");
        assert_eq!(r["command"], "dig www.example A +dnssec");
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "done", "{done}");
        let ev = &done["events"][0];
        assert_eq!(ev["kind"], "answer");
        assert_eq!(ev["rcode"], "NOERROR");
        assert_eq!(ev["stage"], "cache");
        assert_eq!(ev["answer"][0]["data"], "192.0.2.7");
        let dig = ev["dig"].as_str().unwrap();
        assert!(dig.contains(";; ->>HEADER<<- opcode: QUERY, status: NOERROR"), "{dig}");
        assert!(dig.contains(";; STAGE: cache"), "{dig}");
        // The terminal gets the dig text, line by line.
        let lines: Vec<&str> = done["lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(lines.iter().any(|l| l.starts_with(";; ANSWER SECTION:")), "{lines:?}");
        assert_eq!(fake.0.lock().unwrap()[0], (LookupServer::Router, false));
    }

    #[test]
    fn a_silent_server_fails_with_timeout() {
        let fake = Arc::new(Fake::default());
        let mut s = lab(&fake);
        let r = s
            .execute("tool.dns.query", &json!({"name": "www.example", "server": "192.0.2.4", "tcp": true}))
            .unwrap();
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "failed");
        assert_eq!(done["events"][0]["timeout"], true);
        assert!(done["reason"].as_str().unwrap().contains("timeout"));
        assert!(fake.0.lock().unwrap()[0].1, "tcp passed on");
    }

    #[test]
    fn compare_flags_the_upstream_that_diverges() {
        let fake = Arc::new(Fake::default());
        let mut s = lab(&fake);
        s.execute(
            "ip.dns.set",
            &json!({"servers": ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"]}),
        )
        .unwrap();
        let r = s.execute("tool.dns.query", &json!({"name": "www.example", "compare": true})).unwrap();
        assert_eq!(r["mode"], "compare");
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "done", "{done}");
        let rows = done["summary"]["servers"].as_array().unwrap();
        let flag = |i: usize| (rows[i]["diverge"] == true, rows[i]["timeout"] == true);
        assert_eq!(
            [flag(0), flag(1), flag(2), flag(3), flag(4)],
            [(false, false), (false, false), (true, false), (false, true), (false, false)],
            "the CDN's other server (same AS) agrees"
        );
        assert_eq!(rows[4]["data"], json!(["A 192.0.2.8"]));
        assert_eq!(rows[4]["match"], json!(["A AS64500"]));
        assert_eq!(done["summary"]["majority"], json!(["A 192.0.2.7"]));
        assert!(done["header"].is_null() || done["header"].is_string());
        let sum: Vec<&str> = done["summary_lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert_eq!(sum, [";; 192.0.2.3 diverges from the other servers"]);
        // "server": "all" is the same.
        let r = s.execute("tool.dns.query", &json!({"name": "www.example", "server": "all"})).unwrap();
        assert_eq!(r["mode"], "compare");
        until_done(&mut s, r["id"].as_u64().unwrap());
    }

    #[test]
    fn bad_requests_are_refused() {
        let fake = Arc::new(Fake::default());
        let mut s = lab(&fake);
        for p in [
            json!({}),
            json!({"name": "bad name!"}),
            json!({"name": "a.example", "type": "AXFR"}),
            json!({"name": "a.example", "server": "0.0.0.0"}),
            json!({"name": "a.example", "server": "ftp://x"}),
            json!({"name": "a.example", "server": "https://"}),
            json!({"name": "a.example", "trace": true, "compare": true}),
            json!({"name": "a.example", "trace": true, "server": "1.1.1.1"}),
            json!({"name": "a.example", "compare": true, "server": "1.1.1.1"}),
            // No upstream configured to compare.
            json!({"name": "a.example", "compare": true}),
            json!({"name": "a".repeat(300)}),
        ] {
            let err = s.execute("tool.dns.query", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(fake.0.lock().unwrap().is_empty(), "nothing was asked");
    }

    #[test]
    fn an_address_asks_its_ptr() {
        let fake = Arc::new(Fake::default());
        let mut s = lab(&fake);
        let r = s
            .execute("tool.dns.query", &json!({"name": "192.0.2.7", "server": "https://dns.example/dns-query"}))
            .unwrap();
        assert_eq!(r["type"], "PTR");
        assert_eq!(r["name"], "7.2.0.192.in-addr.arpa");
        assert_eq!(r["command"], "dig @https://dns.example/dns-query 192.0.2.7 PTR");
        until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(
            fake.0.lock().unwrap()[0].0,
            LookupServer::Secure("https://dns.example/dns-query".into())
        );
    }

    /// The hierarchy of a `+trace`: any root sends to com. (signed, glue),
    /// com. to example.com. (unsigned, no glue: the resolver finds it).
    struct Tree;

    impl DnsBackend for Tree {
        fn lookup(&self, name: &str) -> std::result::Result<Vec<IpAddr>, ResolveError> {
            assert_eq!(name, "ns1.example.com");
            Ok(vec!["2001:db8::53".parse().unwrap(), "192.0.2.53".parse().unwrap()])
        }
        fn cache_rows(&self) -> Vec<corerouter_model::dns::CacheRow> {
            Vec::new()
        }
        fn cache_used_bytes(&self) -> usize {
            0
        }
        fn flush(&self) {}
        fn exchange(&self, to: &LookupServer, q: &[u8], _: bool) -> std::result::Result<Exchanged, String> {
            use hickory_proto::op::{Message, OpCode};
            use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::{A, NS, NULL}};
            let LookupServer::Plain(ip) = to else { panic!("{to:?}") };
            let qm = Message::from_vec(q).unwrap();
            assert!(!qm.metadata.recursion_desired, "trace clears RD");
            let mut m = Message::response(qm.metadata.id, OpCode::Query);
            m.add_queries(qm.queries.clone());
            let n = |s: &str| Name::from_ascii(s).unwrap();
            match ip.to_string().as_str() {
                "192.0.2.30" => {
                    m.add_authority(Record::from_rdata(n("example.com."), 172800, RData::NS(NS(n("ns1.example.com.")))));
                }
                "192.0.2.53" => {
                    m.metadata.authoritative = true;
                    m.add_answer(Record::from_rdata(n("www.example.com."), 300, RData::A(A::new(192, 0, 2, 7))));
                }
                _ if dig::ROOT_SERVERS.iter().any(|(_, r)| IpAddr::V4(*r) == *ip) => {
                    m.add_authority(Record::from_rdata(n("com."), 172800, RData::NS(NS(n("a.gtld-servers.net.")))));
                    m.add_authority(Record::from_rdata(n("com."), 86400, RData::Unknown {
                        code: RecordType::DS,
                        // Key tag, algorithm 13, SHA-256 digest (RFC 4034 §5.1): a real DS
                        // also when hickory decodes DNSSEC types.
                        rdata: NULL::with([vec![0x4d, 0x06, 13, 2], vec![0xab; 32]].concat()),
                    }));
                    m.add_additional(Record::from_rdata(n("a.gtld-servers.net."), 172800, RData::A(A::new(192, 0, 2, 30))));
                }
                other => return Err(format!("unexpected server {other}")),
            }
            Ok(Exchanged { bytes: m.to_vec().unwrap(), server: ip.to_string(), transport: "UDP".into(), ms: 1, stage: None, source: None })
        }
    }

    #[test]
    fn trace_walks_from_the_root_down() {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        s.set_dns_backend(Arc::new(Tree));
        let r = s.execute("tool.dns.query", &json!({"name": "www.example.com", "trace": true})).unwrap();
        assert_eq!(r["mode"], "trace");
        assert_eq!(r["command"], "dig www.example.com A +trace");
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["state"], "done", "{done}");
        let steps: Vec<&Value> = done["events"].as_array().unwrap().iter().filter(|e| e["kind"] == "trace").collect();
        let zones: Vec<&str> = steps.iter().map(|e| e["zone"].as_str().unwrap()).collect();
        assert_eq!(zones, [".", "com.", "example.com."]);
        assert_eq!(steps[0]["answer"], "referral: com. (1 NS)");
        assert_eq!(steps[0]["signed"], true);
        assert_eq!(steps[1]["signed"], false);
        assert_eq!(steps[2]["address"], "192.0.2.53", "IPv4 first");
        assert_eq!(steps[2]["answer"], "A 192.0.2.7");
        assert_eq!(steps[2]["final"], true);
        let lines: Vec<&str> = done["lines"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(lines[0].starts_with("ZONE"), "{lines:?}");
    }

}

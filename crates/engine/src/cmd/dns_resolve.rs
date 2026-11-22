//! `ip.dns.resolve` (G4.1d), RouterOS `:resolve`: a name through the
//! router's resolver (cache, servers, DoH), or asked of one server. It
//! waits on the network, so it is a task (`tool.task.poll`), never a wait
//! under the session lock. One event per record type asked.

use std::net::IpAddr;

use corerouter_proto_dns::message::parse_name;
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, req_str};
use super::CommandSpec;
use crate::dns::Resolution;
use crate::tasks::can_run;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.dns.resolve", "Resolve", ["IP", "DNS"], None,
    "{name: string (a name, or an address for its PTR), type?: A | AAAA | CNAME | MX | NS | PTR | SOA | SRV | TXT | CAA | HTTPS | SVCB (default: A and AAAA; PTR for an address), server?: ip (ask this server only, without the cache)} → {id, task_id, types}; events {name, type, rcode, records, addresses, ttl, source, ms} or {name, type, error}",
    can_run, resolve)
.task()
.positional("name")];

const TYPES: [&str; 12] = [
    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA", "HTTPS", "SVCB",
];

fn resolve(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = req_str(p, "name")?.trim();
    let shown: String = raw.chars().take(64).collect();
    // An address: its PTR name (RFC 1035 §3.5, RFC 3596 §2.5), like dig -x.
    let (name, default_types) = match raw.parse::<IpAddr>() {
        Ok(ip) => (corerouter_proto_dns::reverse::reverse_name(ip), vec!["PTR"]),
        Err(_) => (raw.to_owned(), vec!["A", "AAAA"]),
    };
    parse_name(&name).map_err(|e| EngineError::bad("name", format!("'{shown}': {e}")))?;
    let types: Vec<&'static str> = match opt_str(p, "type")? {
        None | Some("") => default_types,
        Some(t) => {
            let up = t.trim().to_ascii_uppercase();
            let Some(known) = TYPES.iter().find(|k| **k == up) else {
                return Err(EngineError::bad("type", format!("must be one of {}", TYPES.join(", "))));
            };
            vec![*known]
        }
    };
    let server: Option<IpAddr> = opt_parse(p, "server")?;
    if let Some(ip) = server
        && !corerouter_model::dns::usable_server(ip)
    {
        return Err(EngineError::bad("server", format!("{ip} cannot be a DNS server")));
    }
    let backend = s.dns_backend();
    let prober = s.tool_prober().ok();
    let job_name = name.clone();
    let job_types = types.clone();
    let id = s.start_task("resolve", format!("resolve {shown}"), move |ctx| {
        let mut answered = 0usize;
        let mut last_error = String::new();
        let mut all: Vec<IpAddr> = Vec::new();
        for t in &job_types {
            if ctx.stopped() {
                break;
            }
            // The runner's clock: no `Instant` in the engine (wasm).
            let started = ctx.now();
            let got: std::result::Result<Resolution, String> = match (&backend, &prober) {
                (Some(b), _) => b.resolve_query(&job_name, t, server),
                // No daemon (the lab): the prober's own names, A/AAAA only.
                (None, Some(pr)) if matches!(*t, "A" | "AAAA") && server.is_none() => pr
                    .resolve(&job_name)
                    .map(|addrs| {
                        let addresses: Vec<IpAddr> = addrs
                            .into_iter()
                            .filter(|a| a.is_ipv4() == (*t == "A"))
                            .collect();
                        Resolution {
                            rcode: "NOERROR".into(),
                            records: addresses.iter().map(|a| format!("{t} {a}")).collect(),
                            addresses,
                            ttl: None,
                            source: "simulated".into(),
                        }
                    })
                    .map_err(|e| e.to_string()),
                _ => Err("ip.dns.resolve needs the router daemon's resolver".into()),
            };
            let ms = u64::try_from(ctx.now().saturating_sub(started).as_millis()).unwrap_or(u64::MAX);
            match got {
                Ok(r) => {
                    answered += 1;
                    for a in &r.addresses {
                        if !all.contains(a) {
                            all.push(*a);
                        }
                    }
                    let mut ev = serde_json::to_value(&r).unwrap_or(Value::Null);
                    if let Some(o) = ev.as_object_mut() {
                        o.insert("name".into(), json!(job_name));
                        o.insert("type".into(), json!(t));
                        o.insert("ms".into(), json!(ms));
                    }
                    ctx.emit(ev);
                }
                Err(e) => {
                    last_error = e.chars().take(300).collect();
                    ctx.emit(json!({"name": job_name, "type": t, "error": last_error, "ms": ms}));
                }
            }
        }
        ctx.summary(json!({"name": job_name, "answered": answered, "addresses": all}));
        if answered == 0 && !last_error.is_empty() {
            Err(last_error)
        } else {
            Ok(())
        }
    })?;
    Ok(json!({"id": id, "task_id": id, "types": types}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsBackend;
    use crate::tasks::test_runner;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..500 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    #[derive(Default)]
    struct Fake(Mutex<Vec<(String, String, Option<IpAddr>)>>);

    impl DnsBackend for Fake {
        fn lookup(&self, _: &str) -> std::result::Result<Vec<IpAddr>, corerouter_proto_dns::resolver::ResolveError> {
            Ok(Vec::new())
        }
        fn cache_rows(&self) -> Vec<corerouter_model::dns::CacheRow> {
            Vec::new()
        }
        fn cache_used_bytes(&self) -> usize {
            0
        }
        fn flush(&self) {}
        fn resolve_query(&self, name: &str, rtype: &str, server: Option<IpAddr>) -> std::result::Result<Resolution, String> {
            self.0.lock().unwrap().push((name.into(), rtype.into(), server));
            match rtype {
                "A" => Ok(Resolution {
                    rcode: "NOERROR".into(),
                    records: vec!["A 192.0.2.7".into()],
                    addresses: vec!["192.0.2.7".parse().unwrap()],
                    ttl: Some(300),
                    source: "198.51.100.53".into(),
                }),
                _ => Err("name 'x' could not be resolved: 198.51.100.53: SERVFAIL".into()),
            }
        }
    }

    #[test]
    fn resolve_runs_as_a_task() {
        let mut s = Session::virtual_lab();
        // No runner: disabled with the reason.
        let err = s.execute("ip.dns.resolve", &json!({"name": "www.example"})).unwrap_err();
        assert!(matches!(err, EngineError::Disabled { .. }), "{err}");
        s.set_runner(test_runner::sim());
        let fake = Arc::new(Fake::default());
        s.set_dns_backend(fake.clone());
        let r = s.execute("ip.dns.resolve", &json!({"name": "www.example"})).unwrap();
        assert_eq!(r["types"], json!(["A", "AAAA"]));
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        let ev = done["events"].as_array().unwrap();
        assert_eq!(ev[0]["addresses"], json!(["192.0.2.7"]));
        assert_eq!(ev[0]["source"], "198.51.100.53");
        assert!(ev[1]["error"].as_str().unwrap().contains("SERVFAIL"));
        assert_eq!(done["summary"]["answered"], 1);
        // An address asks PTR; a server is passed on.
        let r = s
            .execute("ip.dns.resolve", &json!({"name": "192.0.2.7", "server": "9.9.9.9"}))
            .unwrap();
        until_done(&mut s, r["id"].as_u64().unwrap());
        let calls = fake.0.lock().unwrap().clone();
        assert_eq!(
            calls.last().unwrap(),
            &("7.2.0.192.in-addr.arpa".to_owned(), "PTR".to_owned(), Some("9.9.9.9".parse().unwrap()))
        );
    }

    #[test]
    fn bad_requests_are_refused() {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::sim());
        for p in [
            json!({}),
            json!({"name": "bad name!"}),
            json!({"name": "a.example", "type": "BOGUS"}),
            json!({"name": "a.example", "server": "0.0.0.0"}),
            json!({"name": "a".repeat(300)}),
        ] {
            let err = s.execute("ip.dns.resolve", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
    }

    #[test]
    fn the_lab_resolves_its_own_names() {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::sim());
        let r = s.execute("ip.dns.resolve", &json!({"name": "localhost", "type": "A"})).unwrap();
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["events"][0]["source"], "simulated", "{done}");
    }
}

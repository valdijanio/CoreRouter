//! G6.6 DNS Lookup (`tool.dns.query`): carries the bytes of a `dig` for
//! the engine's job. The router itself is asked through the LAN
//! forwarder's chain in process (`dns_server::ask`: the stage that answered
//! comes back); a plain server over UDP (TCP when asked, or when the reply
//! is truncated, RFC 7766 §5) on the resolver's sockets; an encrypted one
//! over the DoH/DoT client of G4.1d. `compare` asks every upstream at once,
//! one thread each. Not a service: no `SERVICE` here.

use std::net::SocketAddr;
use std::thread;
use std::time::Instant;

use corerouter_engine::dns::DnsBackend;
use corerouter_engine::dns_lookup::{Exchanged, LookupServer, RouterAsk};
use corerouter_proto_dns::dig;
use corerouter_proto_dns::encrypted::{Proto, SecureServer};
use corerouter_proto_dns::resolver::{SECURE_TIMEOUT_MS, Transport, TransportError};

use super::dns::RouterDns;

/// How long a plain server gets (dig: 5 s with 3 tries; one try here,
/// the operator presses Start again).
const WAIT_MS: u64 = 3000;

fn err(e: TransportError, wait_ms: u64) -> String {
    match e {
        TransportError::Timeout => format!("timeout (no answer in {wait_ms} ms)"),
        TransportError::Io(s) => s.chars().take(200).collect(),
    }
}

pub(crate) fn exchange(
    dns: &RouterDns,
    to: &LookupServer,
    query: &[u8],
    tcp: bool,
) -> Result<Exchanged, String> {
    let started = Instant::now();
    let ms = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let transport = |tcp: bool| if tcp { "TCP" } else { "UDP" }.to_owned();
    match to {
        LookupServer::Router => {
            const DOWN: &str = "the router's DNS forwarder is not running (system.service print)";
            let mut got = super::dns_server::ask(query, tcp).ok_or(DOWN)?;
            let mut over_tcp = tcp;
            if !tcp && got.0.as_deref().is_some_and(dig::truncated) {
                got = super::dns_server::ask(query, true).ok_or(DOWN)?;
                over_tcp = true;
            }
            let (bytes, stage) = got;
            let bytes = bytes.ok_or_else(|| format!("the router dropped the query (stage {stage})"))?;
            Ok(Exchanged {
                bytes,
                server: "127.0.0.1#53(router)".into(),
                transport: transport(over_tcp),
                ms: ms(),
                stage: Some(stage.to_owned()),
                source: (stage == "cache").then(|| "cache".to_owned()),
                explain: Vec::new(),
            })
        }
        LookupServer::Plain(ip) => {
            // The resolver's port: 53 but in tests.
            let addr = SocketAddr::new(*ip, dns.resolver.settings().port);
            let id = match query {
                [a, b, ..] => u16::from_be_bytes([*a, *b]),
                _ => 0,
            };
            let mut accept = |m: &[u8]| dig::is_reply_to(id, m);
            let mut t = dns.transport();
            let mut over_tcp = tcp;
            let mut bytes = t
                .exchange(addr, query, tcp, WAIT_MS, &mut accept)
                .map_err(|e| err(e, WAIT_MS))?;
            if !tcp && dig::truncated(&bytes) {
                bytes = t
                    .exchange(addr, query, true, WAIT_MS, &mut accept)
                    .map_err(|e| err(e, WAIT_MS))?;
                over_tcp = true;
            }
            Ok(Exchanged {
                bytes,
                server: format!("{ip}#{}({ip})", addr.port()),
                transport: transport(over_tcp),
                ms: ms(),
                stage: None,
                source: None,
                explain: Vec::new(),
            })
        }
        LookupServer::Secure(url) => {
            // The configured server keeps its own verify_doh_cert.
            let via = match dns.resolver.settings().secure.iter().find(|s| s.url() == *url) {
                Some(s) => s.clone(),
                None => SecureServer::parse(url, true)?,
            };
            let ip = match via.ip() {
                Some(ip) => ip,
                None => {
                    let mut all = dns
                        .lookup(&via.host)
                        .map_err(|e| format!("cannot resolve {}: {e}", via.host))?;
                    all.sort_by_key(std::net::IpAddr::is_ipv6);
                    all.first()
                        .copied()
                        .ok_or_else(|| format!("{} has no address", via.host))?
                }
            };
            let addr = SocketAddr::new(ip, via.port);
            let bytes = dns
                .transport()
                .exchange_secure(addr, &via, query, SECURE_TIMEOUT_MS)
                .map_err(|e| err(e, SECURE_TIMEOUT_MS))?;
            Ok(Exchanged {
                bytes,
                server: format!("{}({ip})", via.url()),
                transport: match via.proto {
                    Proto::Https => "HTTPS",
                    Proto::Tls => "TLS",
                }
                .into(),
                ms: ms(),
                stage: None,
                source: None,
                explain: Vec::new(),
            })
        }
    }
}

/// The router's chain with `explain` or `as_client` (G6.8).
pub(crate) fn ask_router(query: &[u8], tcp: bool, how: RouterAsk) -> Result<Exchanged, String> {
    const DOWN: &str = "the router's DNS forwarder is not running (system.service print)";
    let started = Instant::now();
    let ask = |tcp| super::dns_server::ask_as(query, tcp, how.as_client, how.explain).ok_or(DOWN);
    let mut done = ask(tcp)?;
    let mut over_tcp = tcp;
    if !tcp && done.reply.as_deref().is_some_and(dig::truncated) {
        done = ask(true)?;
        over_tcp = true;
    }
    let stage = done.answered_by;
    let bytes = match done.reply {
        Some(b) => b,
        // The limit drops a flood over UDP: say so with what decided it.
        None => {
            let why = done
                .explain
                .iter()
                .find(|d| d.stage == stage)
                .map(|d| format!(": {}", d.text()))
                .unwrap_or_default();
            return Err(format!("the router dropped the query (stage {stage}){why}"));
        }
    };
    let server = match how.as_client {
        Some(ip) => format!("127.0.0.1#53(router, as {ip})"),
        None => "127.0.0.1#53(router)".into(),
    };
    Ok(Exchanged {
        bytes,
        server,
        transport: if over_tcp { "TCP" } else { "UDP" }.into(),
        ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stage: Some(stage.to_owned()),
        source: (stage == "cache").then(|| "cache".to_owned()),
        explain: done.explain,
    })
}

/// Every `(server, query)` at once, a thread each (a handful: the
/// configured upstreams), so the slowest sets the time, not the sum.
pub(crate) fn exchange_all(
    dns: &RouterDns,
    asks: &[(LookupServer, Vec<u8>)],
    tcp: bool,
) -> Vec<Result<Exchanged, String>> {
    thread::scope(|scope| {
        let handles: Vec<_> = asks
            .iter()
            .map(|(to, q)| {
                thread::Builder::new()
                    .name("dns-lookup-cmp".into())
                    .spawn_scoped(scope, move || exchange(dns, to, q, tcp))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| match h {
                Ok(h) => h
                    .join()
                    .unwrap_or_else(|_| Err("lookup thread failed".into())),
                Err(e) => Err(format!("cannot start a lookup thread: {e}")),
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use serde_json::json;
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    /// A fake upstream on `ip`:`port`: answers every query with an A record
    /// `answer`, or never (`None`).
    fn upstream(ip: &str, port: u16, answer: Option<[u8; 4]>) {
        use hickory_proto::op::{Message, OpCode};
        use hickory_proto::rr::{RData, Record, rdata::A};
        let sock = UdpSocket::bind((ip, port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let Some(a) = answer else { continue };
                let q = Message::from_vec(&buf[..n]).unwrap();
                let mut m = Message::response(q.metadata.id, OpCode::Query);
                m.metadata.recursion_available = true;
                m.metadata.recursion_desired = q.metadata.recursion_desired;
                m.add_queries(q.queries.clone());
                m.add_answer(Record::from_rdata(
                    q.queries[0].name().clone(),
                    60,
                    RData::A(A::new(a[0], a[1], a[2], a[3])),
                ));
                let _ = sock.send_to(&m.to_vec().unwrap(), from);
            }
        });
    }

    /// A port free on 127.0.0.1–4 alike (the upstreams share it: one
    /// `port` setting for every server).
    fn free_port() -> u16 {
        loop {
            let p = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            if (1..=4).all(|i| UdpSocket::bind((format!("127.0.0.{i}").as_str(), p)).is_ok()) {
                return p;
            }
        }
    }

    /// `compare` against real sockets, the whole task: two upstreams
    /// agree, one lies, one is silent (G6.6: divergent upstream in the lab).
    #[test]
    fn compare_finds_the_divergent_upstream_on_the_wire() {
        let port = free_port();
        upstream("127.0.0.1", port, Some([192, 0, 2, 7]));
        upstream("127.0.0.2", port, Some([192, 0, 2, 7]));
        upstream("127.0.0.3", port, Some([203, 0, 113, 66]));
        upstream("127.0.0.4", port, None);
        let session = shared(Session::virtual_lab());
        let dns = Arc::new(RouterDns::new());
        let id = {
            let mut s = corerouter_engine::lock(&session);
            s.set_runner(corerouter_control::thread_runner());
            s.execute(
                "ip.dns.set",
                &json!({"servers": ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"]}),
            )
            .unwrap();
            let mut settings = s.dns_settings();
            settings.port = port;
            dns.resolver.configure(settings, 0);
            s.set_dns_backend(dns.clone());
            let r = s
                .execute("tool.dns.query", &json!({"name": "www.example", "compare": true}))
                .unwrap();
            r["id"].as_u64().unwrap()
        };
        let started = Instant::now();
        let done = loop {
            let p = corerouter_engine::lock(&session)
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                break p;
            }
            assert!(started.elapsed() < Duration::from_secs(10), "{p}");
            thread::sleep(Duration::from_millis(20));
        };
        // In parallel: the silent one costs its timeout once, not the sum.
        assert!(started.elapsed() < Duration::from_millis(WAIT_MS * 2));
        assert_eq!(done["state"], "done", "{done}");
        let rows = done["summary"]["servers"].as_array().unwrap();
        let marks: Vec<(bool, bool)> = rows
            .iter()
            .map(|r| (r["diverge"] == true, r["timeout"] == true))
            .collect();
        assert_eq!(marks, [(false, false), (false, false), (true, false), (false, true)]);
        assert_eq!(rows[2]["data"], json!(["A 203.0.113.66"]));
        assert_eq!(done["summary"]["majority"], json!(["A 192.0.2.7"]));
    }

    /// An honest upstream on `ip`:`port` that answers after `delay`: the
    /// popular names exist, anything else is NXDOMAIN.
    fn honest(ip: &str, port: u16, delay: Duration) {
        use hickory_proto::op::{Message, OpCode, ResponseCode};
        use hickory_proto::rr::{RData, Record, rdata::A};
        let sock = UdpSocket::bind((ip, port)).unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let q = Message::from_vec(&buf[..n]).unwrap();
                let name = q.queries[0].name().to_ascii();
                let mut m = Message::response(q.metadata.id, OpCode::Query);
                m.metadata.recursion_available = true;
                m.add_queries(q.queries.clone());
                if corerouter_engine::dns_upstreams::POPULAR.contains(&name.trim_end_matches('.')) {
                    m.add_answer(Record::from_rdata(q.queries[0].name().clone(), 60, RData::A(A::new(192, 0, 2, 1))));
                } else {
                    m.metadata.response_code = ResponseCode::NXDomain;
                }
                thread::sleep(delay);
                let _ = sock.send_to(&m.to_vec().unwrap(), from);
            }
        });
    }

    /// G6.8: the upstream benchmark against real sockets: a slow server is
    /// ranked last, a hijacker (an address for any name) is caught.
    #[test]
    fn upstreams_benchmark_on_the_wire() {
        let port = free_port();
        honest("127.0.0.1", port, Duration::ZERO);
        honest("127.0.0.2", port, Duration::from_millis(150));
        upstream("127.0.0.3", port, Some([203, 0, 113, 66]));
        let session = shared(Session::virtual_lab());
        let dns = Arc::new(RouterDns::new());
        let id = {
            let mut s = corerouter_engine::lock(&session);
            s.set_runner(corerouter_control::thread_runner());
            s.execute("ip.dns.set", &json!({"servers": ["127.0.0.1", "127.0.0.2", "127.0.0.3"]}))
                .unwrap();
            let mut settings = s.dns_settings();
            settings.port = port;
            dns.resolver.configure(settings, 0);
            s.set_dns_backend(dns.clone());
            let r = s.execute("tool.dns.upstreams", &json!({"count": 20})).unwrap();
            r["id"].as_u64().unwrap()
        };
        let started = Instant::now();
        let done = loop {
            let p = corerouter_engine::lock(&session)
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                break p;
            }
            assert!(started.elapsed() < Duration::from_secs(60), "{p}");
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(done["state"], "done", "{done}");
        let rows = done["summary"]["servers"].as_array().unwrap();
        let row = |srv: &str| rows.iter().find(|r| r["server"] == srv).unwrap();
        assert_eq!(row("127.0.0.1")["answered"], 20);
        assert!(row("127.0.0.2")["p50_ms"].as_f64().unwrap() >= 140.0, "{}", row("127.0.0.2"));
        assert!(row("127.0.0.1")["p50_ms"].as_f64().unwrap() < 100.0);
        assert_eq!(row("127.0.0.1")["nxdomain_hijack"], false);
        assert_eq!(row("127.0.0.3")["nxdomain_hijack"], true);
        assert_eq!(row("127.0.0.1")["forwarder"], true, "a loopback server forwards");
        let advice = done["summary"]["recommend"].as_array().unwrap();
        let says = |kind: &str, srv: &str, why: &str| {
            advice.iter().any(|a| a["kind"] == kind && a["server"] == srv && a["why"] == why)
        };
        assert!(says("use", "127.0.0.1", "use"), "{advice:?}");
        assert!(says("remove", "127.0.0.2", "slow"), "{advice:?}");
        assert!(says("remove", "127.0.0.3", "hijack"), "{advice:?}");
    }
}

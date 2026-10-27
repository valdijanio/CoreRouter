//! G4.4j: the CGNAT's NAT log in IPFIX against a real kernel. Subscribers
//! in their own namespace send through this namespace's CGNAT in blocks
//! mode (`corerouter-daemon --backend linux`: the first packet waits in
//! the netfilter queue until the engine gives a port block); three
//! collectors written here decode and check what arrives:
//!
//! - IPFIX over **SCTP** (RFC 7011 §10.2): the port blocks (RFC 8158
//!   §4.6.10, natEvent 16 with the range and the pool), the exhausted pool
//!   (§4.6.5, natEvent 3, once however many are refused), the NAT44
//!   sessions;
//! - IPFIX over **TLS** (§11), both sides with certificates of a test CA
//!   (mutual authentication, §11.3): the same records;
//! - IPFIX over UDP with `nat_events_legacy` and `content=nat`: the NAT44
//!   sessions as natEvent 1/2.
//!
//! It ends with a storm (`COREROUTER_PBA_STORM` subscribers, 20 000 by
//! default) each sending its first packet, and prints what was measured.
//! No root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_nat_ipfix -- --nocapture
//! ```
//!
//! ```text
//!  [B: subscribers] sub0 ──veth── lan0 [here: CGNAT, collectors] wan0 ──veth── srv0 [C: server]
//!  100.64.0.0/16 (local)        100.64.0.254/16     192.0.2.1/24          192.0.2.2/24
//!                                pools: 198.51.100.9 (one address), 10.200.0.0/22 (storm)
//! ```
//!
//! Needs the `sctp` and `nfnetlink_queue` modules on the host (a user
//! namespace cannot load them); without them it says so and skips, unless
//! `COREROUTER_REQUIRE_SCTP=1` / `COREROUTER_REQUIRE_NFQUEUE=1` (the full
//! CI loads them: `ci/kernel-modules/`).
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use corerouter_proto_flow::decode::{Decoder, to_record};
use corerouter_proto_flow::{NatEventType, Record};
use serde_json::{Value, json};

const PORT: &str = "7996";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn sh(pid: Option<u32>, script: &str) {
    let out = in_ns(pid, "sh").args(["-c", script]).output().unwrap();
    assert!(
        out.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn within<T: Send + 'static>(pid: u32, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        f()
    })
    .join()
    .unwrap()
}

fn wait(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// What a collector decoded, and the raw natEvent values it saw.
#[derive(Default)]
struct Got {
    records: Vec<Record>,
    nat_codes: Vec<u64>,
    messages: u64,
    /// Sequence numbers that did not follow (RFC 7011 §3.1).
    gaps: u64,
}

type Shared = Arc<Mutex<Got>>;

fn take(got: &Shared, d: &mut Decoder, msg: &[u8], next: &mut Option<u32>) {
    let m = d.decode(msg).unwrap();
    let mut g = got.lock().unwrap();
    g.messages += 1;
    if next.is_some_and(|n| n != m.sequence) {
        g.gaps += 1;
    }
    *next = Some(m.sequence.wrapping_add(m.records.len() as u32));
    for r in &m.records {
        if let Some(c) = r.uint(230) {
            g.nat_codes.push(c);
        }
    }
    g.records.extend(m.records.iter().filter_map(|r| to_record(r, &m)));
}

/// Messages back to back on a byte stream, each framed by its own length
/// (RFC 7011 §10.4).
fn read_stream(got: &Shared, mut s: impl Read) {
    let mut d = Decoder::new();
    let mut next = None;
    let mut head = [0u8; 4];
    while s.read_exact(&mut head).is_ok() {
        let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let mut msg = head.to_vec();
        msg.resize(len.max(4), 0);
        if s.read_exact(&mut msg[4..]).is_err() {
            break;
        }
        take(got, &mut d, &msg, &mut next);
    }
}

/// IPFIX over SCTP: one message per SCTP message (RFC 7011 §10.2).
fn sctp_collector(port: u16) -> Shared {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let l = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(132))).unwrap();
    l.set_reuse_address(true).unwrap();
    l.bind(&SockAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], port)))).unwrap();
    l.listen(4).unwrap();
    let got: Shared = Arc::default();
    let g = got.clone();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            let mut d = Decoder::new();
            let mut next = None;
            let mut buf = vec![0u8; 65_536];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => take(&g, &mut d, &buf[..n], &mut next),
                }
            }
        }
    });
    got
}

struct Pki {
    ca: String,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

/// A CA, the collector's certificate for 127.0.0.1 and the router's.
fn pki() -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca, KeyPair::generate().unwrap()).unwrap();
    let leaf = |name: &str| {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&key, &ca)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    };
    let (server_cert, server_key) = leaf("127.0.0.1");
    let (client_cert, client_key) = leaf("router.example.net");
    Pki {
        ca: ca.pem(),
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

/// IPFIX over TLS that insists on the exporter's certificate (RFC 7011
/// §11.3). Counts the connections that showed one.
fn tls_collector(port: u16, pki: &Pki) -> (Shared, Arc<Mutex<u32>>) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.ca.as_bytes()).unwrap())
        .unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(pki.server_cert.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(pki.server_key.as_bytes()).unwrap(),
            )
            .unwrap(),
    );
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let got: Shared = Arc::default();
    let authenticated = Arc::new(Mutex::new(0u32));
    let (g, a) = (got.clone(), authenticated.clone());
    std::thread::spawn(move || {
        while let Ok((tcp, _)) = l.accept() {
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut first = [0u8; 4];
            if tls.read_exact(&mut first).is_err() {
                continue;
            }
            if tls.conn.peer_certificates().is_some_and(|c| !c.is_empty()) {
                *a.lock().unwrap() += 1;
            }
            let rest = std::io::Cursor::new(first.to_vec()).chain(tls);
            read_stream(&g, rest);
        }
    });
    (got, authenticated)
}

fn udp_collector(port: u16) -> Shared {
    let sock = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let got: Shared = Arc::default();
    let g = got.clone();
    std::thread::spawn(move || {
        let mut d = Decoder::new();
        let mut buf = vec![0u8; 65_536];
        while let Ok(n) = sock.recv(&mut buf) {
            take(&g, &mut d, &buf[..n], &mut None);
        }
    });
    got
}

fn module(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/module/{name}")).exists()
}

/// The daemon's CPU time so far (utime + stime, clock ticks of 10 ms).
fn cpu_ms(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after = stat.rsplit_once(')').unwrap().1;
    let f: Vec<&str> = after.split_whitespace().collect();
    (f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()) * 10
}

/// Not a test: `common::call` re-runs test binaries with it.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn cgnat_blocks_and_limits_reach_sctp_tls_and_legacy_collectors() {
    if !in_netns() {
        return;
    }
    // A module the host has not loaded stays absent: socket(SCTP) would
    // fail with "protocol not supported".
    for (m, var) in [("sctp", "COREROUTER_REQUIRE_SCTP"), ("nfnetlink_queue", "COREROUTER_REQUIRE_NFQUEUE")] {
        let required = std::env::var(var).is_ok_and(|v| v == "1");
        if !module(m) {
            assert!(!required, "the kernel module {m} is not loaded");
            eprintln!("skipped: the kernel module {m} is not loaded (modprobe {m} on the host)");
            return;
        }
    }
    if Command::new("nft").arg("--version").output().is_err() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let c = namespace_b();
    let (bp, cp) = (b.0.id(), c.0.id());
    ip(None, &["link", "add", "lan0", "type", "veth", "peer", "name", "sub0"]);
    ip(None, &["link", "add", "wan0", "type", "veth", "peer", "name", "srv0"]);
    ip(None, &["link", "set", "sub0", "netns", &bp.to_string()]);
    ip(None, &["link", "set", "srv0", "netns", &cp.to_string()]);
    // The subscribers: three addresses, and every address of
    // 100.64.128.0/17 local in B (a `local` route), so the storm binds to
    // thousands of sources.
    ip(Some(bp), &["link", "set", "lo", "up"]);
    for a in ["100.64.0.1/16", "100.64.0.2/16", "100.64.0.3/16"] {
        ip(Some(bp), &["addr", "add", a, "dev", "sub0"]);
    }
    ip(Some(bp), &["link", "set", "sub0", "up"]);
    ip(Some(bp), &["route", "add", "default", "via", "100.64.0.254"]);
    ip(Some(bp), &["route", "add", "local", "100.64.128.0/17", "dev", "lo"]);
    ip(Some(cp), &["link", "set", "lo", "up"]);
    ip(Some(cp), &["addr", "add", "192.0.2.2/24", "dev", "srv0"]);
    ip(Some(cp), &["link", "set", "srv0", "up"]);
    ip(Some(cp), &["route", "add", "default", "via", "192.0.2.1"]);
    for (a, i) in [("100.64.0.254/16", "lan0"), ("192.0.2.1/24", "wan0")] {
        ip(None, &["addr", "add", a, "dev", i]);
        ip(None, &["link", "set", i, "up"]);
    }
    sh(None, "echo 1 > /proc/sys/net/ipv4/ip_forward");
    sh(None, "echo 1 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout");

    let pki = pki();
    let sctp = sctp_collector(4739);
    let (tls, authenticated) = tls_collector(4740, &pki);
    let legacy = udp_collector(2055);

    let dir = std::env::temp_dir().join(format!("g44j-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g44j-netns.log")).unwrap();
    let mut cmd = Command::new(DAEMON);
    cmd.args(["--backend", "linux", "--no-discovery", "--control", PORT, "--config-dir"])
        .arg(&dir)
        .arg("--token-file")
        .arg(common::token_file(None, &dir))
        .env("RUST_LOG", std::env::var("COREROUTER_DAEMON_LOG").unwrap_or_else(|_| "info".into()))
        .stdout(Stdio::null())
        .stderr(log);
    let daemon = Kill(cmd.spawn().unwrap());
    let dpid = daemon.0.id();
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    // One public address, two blocks of 32 256 ports: the third subscriber
    // finds the pool exhausted.
    let pool = run(
        "ip.firewall.cgnat.pool.add",
        json!({"name": "pba", "mode": "blocks", "inside": "100.64.0.0/24", "outside": "198.51.100.9", "ports_per_subscriber": 32256, "max_blocks": 1}),
    )
    .unwrap();
    let pool_id = u32::from_str_radix(pool["id"].as_str().unwrap().trim_start_matches('*'), 16).unwrap();
    run(
        "ip.traffic-flow.target.add",
        json!({"dst_address": "127.0.0.1", "port": 4739, "transport": "sctp", "content": "nat"}),
    )
    .unwrap();
    run(
        "ip.traffic-flow.target.add",
        json!({"dst_address": "127.0.0.1", "port": 4740, "transport": "tls", "content": "nat",
               "certificate": pki.client_cert, "private_key": pki.client_key, "ca_certificate": pki.ca}),
    )
    .unwrap();
    run(
        "ip.traffic-flow.target.add",
        json!({"dst_address": "127.0.0.1", "port": 2055, "content": "nat", "nat_events_legacy": true}),
    )
    .unwrap();
    run(
        "ip.traffic-flow.set",
        json!({"enabled": true, "flows": false, "nat_events": true}),
    )
    .unwrap();
    wait("the exporter", 15, || {
        run("ip.traffic-flow.get", json!({})).unwrap()["state"] == "running"
    });
    wait("every collector connected", 20, || {
        run("ip.traffic-flow.target.list", json!({})).unwrap().as_array().unwrap().iter().all(|t| t["state"] == "sending")
    });

    // Three subscribers, one datagram each, again every half second as a
    // real client would (a first packet that came before the daemon served
    // the queue was dropped by the kernel).
    let send = move || {
        within(bp, || {
            for i in 1..=3u8 {
                let u = UdpSocket::bind((Ipv4Addr::new(100, 64, 0, i), 5000)).unwrap();
                u.send_to(&[1u8; 32], "192.0.2.2:53").unwrap();
            }
        });
    };
    let alloc = |r: &Record| {
        matches!(r, Record::PortBlock(b) if b.event == NatEventType::PortBlockAllocation
            && b.post_src == Ipv4Addr::new(198, 51, 100, 9) && b.ports == 32256
            && b.port_end - b.port_start + 1 == 32256 && b.step == 1 && b.pool == pool_id)
    };
    let exhausted = |r: &Record| {
        matches!(r, Record::NatLimit(l) if l.event == NatEventType::AddressesExhausted && l.pool == pool_id)
    };
    let session = |r: &Record| {
        matches!(r, Record::Nat(n) if n.event == NatEventType::Nat44SessionCreate
            && n.post_src == Ipv4Addr::new(198, 51, 100, 9) && n.protocol == 17
            && n.dst == Ipv4Addr::UNSPECIFIED)
    };
    let count = |g: &Shared, f: &dyn Fn(&Record) -> bool| g.lock().unwrap().records.iter().filter(|r| f(r)).count();
    let mut tries = 0;
    wait("the first blocks", 30, || {
        tries += 1;
        if tries % 5 == 1 {
            send();
        }
        count(&sctp, &alloc) == 2
    });
    for (name, g) in [("sctp", &sctp), ("tls", &tls)] {
        wait(&format!("{name}: two port blocks"), 30, || count(g, &alloc) == 2);
        wait(&format!("{name}: the exhausted pool"), 30, || count(g, &exhausted) >= 1);
        wait(&format!("{name}: the NAT44 sessions"), 30, || count(g, &session) >= 2);
        assert_eq!(g.lock().unwrap().gaps, 0, "{name}: sequence numbers follow (RFC 7011 §3.1)");
    }
    // A second refused packet a little later: rate-limited (RFC 8158 §5.2).
    within(bp, || {
        let u = UdpSocket::bind((Ipv4Addr::new(100, 64, 0, 3), 5001)).unwrap();
        u.send_to(&[1u8; 32], "192.0.2.2:53").unwrap();
    });
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(count(&sctp, &exhausted), 1, "one natEvent 3 per minute");
    assert!(*authenticated.lock().unwrap() >= 1, "the router showed its certificate (RFC 7011 §11.3)");
    // Legacy collector: the sessions as natEvent 1 (Historic), no blocks
    // renumbered.
    wait("legacy: natEvent 1", 30, || legacy.lock().unwrap().nat_codes.contains(&1));
    {
        let l = legacy.lock().unwrap();
        assert!(!l.nat_codes.contains(&4), "{:?}", l.nat_codes);
        assert!(l.nat_codes.contains(&16), "{:?}", l.nat_codes);
    }
    let st = run("ip.traffic-flow.stats", json!({})).unwrap();
    assert_eq!(st["nat_log_dropped"], 0, "{st}");

    // The storm: N subscribers of a big blocks-mode pool send their first
    // packet as fast as one thread can; each one waits in the queue for
    // its block, and each block is one IPFIX record.
    let n: u32 = std::env::var("COREROUTER_PBA_STORM").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000);
    run(
        "ip.firewall.cgnat.pool.add",
        json!({"name": "storm", "mode": "blocks", "inside": "100.64.128.0/17", "outside": "10.200.0.0/20", "ports_per_subscriber": 1000}),
    )
    .unwrap();
    ip(Some(cp), &["route", "add", "10.200.0.0/20", "via", "192.0.2.1"]);
    std::thread::sleep(Duration::from_secs(2));
    let storm = |r: &Record| matches!(r, Record::PortBlock(b) if b.src.octets()[2] >= 128 && b.event == NatEventType::PortBlockAllocation);
    let cpu0 = cpu_ms(dpid);
    let t0 = Instant::now();
    // Rounds, as clients do: whoever got no block sends again. The kernel
    // queue holds 4096 first packets (`nfqueue::MAXLEN`); one thread
    // sending as fast as it can outruns it.
    let mut rounds = 0;
    let mut sent = Duration::ZERO;
    while rounds < 20 {
        rounds += 1;
        let have: std::collections::HashSet<Ipv4Addr> = sctp
            .lock()
            .unwrap()
            .records
            .iter()
            .filter_map(|r| match r {
                Record::PortBlock(b) if storm(r) => Some(b.src),
                _ => None,
            })
            .collect();
        if have.len() >= n as usize {
            break;
        }
        let t = Instant::now();
        within(bp, move || {
            for i in 0..n {
                let a = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 128, 0)) + i);
                if have.contains(&a) {
                    continue;
                }
                if let Ok(u) = UdpSocket::bind((a, 6000)) {
                    let _ = u.send_to(&[0u8; 16], "192.0.2.2:9");
                }
            }
        });
        sent += t.elapsed();
        let (mut last, mut still) = (count(&sctp, &storm), Instant::now());
        while still.elapsed() < Duration::from_millis(500) {
            std::thread::sleep(Duration::from_millis(20));
            let now = count(&sctp, &storm);
            if now != last {
                (last, still) = (now, Instant::now());
            }
        }
    }
    let took = t0.elapsed().saturating_sub(Duration::from_millis(500));
    let cpu = cpu_ms(dpid) - cpu0;
    let (s_n, t_n) = (count(&sctp, &storm), count(&tls, &storm));
    std::thread::sleep(Duration::from_millis(1500));
    let st = run("ip.traffic-flow.stats", json!({})).unwrap();
    eprintln!(
        "MEASURED PBA storm: {n} subscribers, {rounds} rounds of first packets ({:.3} s sending); {s_n} block records over SCTP and {t_n} over TLS, the last {:.2} s after the first packet ({:.0} blocks/s); daemon CPU {cpu} ms ({:.1} us/block); nat_log +{} dropped {}",
        sent.as_secs_f64(),
        took.as_secs_f64(),
        s_n as f64 / took.as_secs_f64().max(0.001),
        cpu as f64 * 1000.0 / s_n.max(1) as f64,
        st["nat_log"],
        st["nat_log_dropped"],
    );
    assert_eq!(st["nat_log_dropped"], 0, "{st}");
    assert!(s_n >= n as usize * 99 / 100, "SCTP got {s_n} of {n} blocks: {st}");
    assert_eq!(s_n, t_n, "both collectors got every block");

    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}

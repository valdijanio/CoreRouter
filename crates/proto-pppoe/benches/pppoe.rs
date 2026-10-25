//! G4.3a — PPPoE/PPP hot paths: decoding Discovery and Session packets, the
//! server answering a PADI (AC-Cookie HMAC included) and an LCP Echo on an
//! established session, and a whole session setup (PADI to IPCP Opened, both
//! ends) in the in-memory lab. Under `cargo bench` it also prints the memory
//! a session costs (RSS growth over 50 000 sessions, Linux).
//!
//! G4.3e adds the IPv6 control path of a session: sorting a Router
//! Solicitation, building the session's RA (PIO, MTU, RDNSS, DNSSL) and the
//! stable IPv6CP identifier (RFC 8064).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-pppoe --bench pppoe`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;

use corerouter_proto_pppoe::discovery::{self, Code, DiscoveryWriter, tag};
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::lab::{Lab, LabConfig, ac_mac, client_mac};
use corerouter_proto_pppoe::lcp::{self, AuthProto};
use corerouter_proto_pppoe::ppp::{self, Link, SessionWriter, proto};
use corerouter_proto_pppoe::server::{Server, ServerConfig, ServerOutput};
use corerouter_proto_pppoe::wire::Mac;
use criterion::{Criterion, Throughput, criterion_group};

const HOST: Mac = Mac([0x02, 0x11, 0, 0, 0, 1]);

fn padi() -> Vec<u8> {
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(
        &mut b,
        Mac::BROADCAST,
        HOST,
        Vlans::single(100),
        Code::Padi,
        0,
    );
    w.tag(tag::SERVICE_NAME, b"");
    w.tag(tag::HOST_UNIQ, &[1, 2, 3, 4, 5, 6, 7, 8]);
    w.tag_bbf(Some(b"olt-1 pon 0/1/3:12"), Some(b"cust-0042"));
    w.finish().unwrap();
    b
}

fn lcp_request() -> Vec<u8> {
    let link = Link {
        dst: ac_mac(0),
        src: HOST,
        vlans: Vlans::single(100),
    };
    let mut b = Vec::new();
    let mut w = SessionWriter::control(
        &mut b,
        &link,
        7,
        proto::LCP,
        lcp::code::CONFIGURE_REQUEST,
        1,
    );
    for o in [
        lcp::LcpOpt::Mru(1492),
        lcp::LcpOpt::Magic(0x1234_5678),
        lcp::LcpOpt::Auth(AuthProto::MsChapV2),
    ] {
        o.put(w.buf()).unwrap();
    }
    w.finish(1492).unwrap();
    b
}

fn codecs(c: &mut Criterion) {
    let mut g = c.benchmark_group("pppoe");
    g.throughput(Throughput::Elements(1));
    let f = padi();
    g.bench_function("decode_padi", |b| {
        b.iter(|| discovery::parse(black_box(&f)).unwrap())
    });
    let f = lcp_request();
    g.bench_function("decode_lcp_request", |b| {
        b.iter(|| {
            let s = ppp::parse_session(black_box(&f)).unwrap();
            let c = ppp::parse_control(s.info).unwrap();
            let mut n = 0u32;
            for o in ppp::options(c.data) {
                black_box(lcp::LcpOpt::parse(o.unwrap()).unwrap());
                n += 1;
            }
            n
        })
    });
    g.finish();
}

fn ipv6(c: &mut Criterion) {
    use corerouter_proto_pppoe::nd;
    use std::net::Ipv6Addr;
    let mut g = c.benchmark_group("pppoe_ipv6");
    g.throughput(Throughput::Elements(1));
    let ours = nd::link_local([0x02, 0, 0, 0, 0, 0, 0, 1]);
    let peer: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
    let mut rs = Vec::new();
    nd::router_solicit(&mut rs, peer);
    g.bench_function("classify_rs", |b| b.iter(|| nd::classify(black_box(&rs))));
    let cfg = nd::RaConfig {
        other: true,
        mtu: Some(1492),
        prefixes: vec![nd::PrefixInfo {
            prefix: "2001:db8:0:7::".parse().unwrap(),
            len: 64,
            on_link: true,
            autonomous: true,
            valid: 86_400,
            preferred: 57_600,
        }],
        rdnss: vec![
            "2001:db8::53".parse().unwrap(),
            "2001:db8::54".parse().unwrap(),
        ],
        dnssl: vec!["isp.example".into()],
        ..nd::RaConfig::default()
    };
    let mut out = Vec::with_capacity(256);
    g.bench_function("build_ra", |b| {
        b.iter(|| {
            out.clear();
            nd::router_advert(&mut out, ours, peer, black_box(&cfg));
            out.len()
        })
    });
    g.bench_function("stable_iid", |b| {
        b.iter(|| nd::stable_iid(black_box(&[7; 32]), 3, Vlans::NONE, HOST, nd::IidRole::Peer))
    });
    g.finish();
}

/// One server and one session up, for the per-packet benchmarks.
fn established() -> (Lab, u16) {
    let mut l = Lab::new(LabConfig {
        clients: 1,
        start_spread_ms: 1,
        ..LabConfig::default()
    });
    l.start_all();
    l.run_until(5_000);
    assert_eq!(l.clients_up(), 1);
    let sid = l.up.keys().next().unwrap().1;
    (l, sid)
}

fn server(c: &mut Criterion) {
    let mut g = c.benchmark_group("pppoe");
    g.throughput(Throughput::Elements(1));
    // PADI → PADO: tag walk, AC-Cookie HMAC-SHA-256, PADO encode.
    let mut s = Server::new(ServerConfig::default(), [7; 32], 0);
    let mut out = ServerOutput::new();
    let f = padi();
    g.bench_function("server_padi_to_pado", |b| {
        b.iter(|| {
            out.clear();
            s.handle_frame(1000, 1, black_box(&f), &mut out);
            out.frames.len()
        })
    });
    // LCP Echo-Request → Echo-Reply on a live session (the steady state).
    let (mut l, sid) = established();
    let link = Link {
        dst: ac_mac(0),
        src: client_mac(0),
        vlans: Vlans::NONE,
    };
    let mut echo = Vec::new();
    let mut w = SessionWriter::control(
        &mut echo,
        &link,
        sid,
        proto::LCP,
        lcp::code::ECHO_REQUEST,
        9,
    );
    w.buf().extend_from_slice(&0x0bad_cafe_u32.to_be_bytes());
    w.finish(1492).unwrap();
    let srv = &mut l.servers[0];
    let mut out = ServerOutput::new();
    srv.handle_frame(6000, 1, &echo, &mut out);
    assert_eq!(out.frames.len(), 1, "echo answered");
    g.bench_function("server_lcp_echo", |b| {
        b.iter(|| {
            out.clear();
            srv.handle_frame(6000, 1, black_box(&echo), &mut out);
            out.frames.len()
        })
    });
    g.finish();
}

fn setup(c: &mut Criterion) {
    let mut g = c.benchmark_group("pppoe");
    // 1000 subscribers from PADI to IPCP Opened (both ends, CHAP-MD5, no
    // loss): server + client + the lab's network, per session.
    g.throughput(Throughput::Elements(1000));
    g.sample_size(10);
    g.bench_function("session_setup_1000_chap", |b| {
        b.iter(|| {
            let mut l = Lab::new(LabConfig {
                clients: 1000,
                start_spread_ms: 100,
                auth_cycle: vec![AuthProto::ChapMd5],
                ..LabConfig::default()
            });
            l.start_all();
            l.run_until(3_000);
            assert_eq!(l.clients_up(), 1000);
            l
        })
    });
    g.finish();
}

/// Resident set size in bytes (Linux; 0 elsewhere).
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096)
}

/// Bytes per established session on the server: RSS growth while a
/// server takes 50 000 sessions, minus the same lab without a server
/// session (clients only, never started) — printed, not a criterion row.
fn memory() {
    let n = 50_000;
    let base = rss();
    let clients_only = Lab::new(LabConfig {
        clients: n,
        ..LabConfig::default()
    });
    let with_clients = rss();
    drop(clients_only);
    let mut l = Lab::new(LabConfig {
        clients: n,
        start_spread_ms: 5_000,
        auth_cycle: vec![AuthProto::ChapMd5],
        ..LabConfig::default()
    });
    l.start_all();
    l.run_until(20_000);
    assert_eq!(l.clients_up(), n);
    let full = rss();
    let per = full.saturating_sub(base.max(with_clients)) / n as u64;
    println!(
        "memory: {n} sessions, RSS {} MiB → {} MiB; ≈ {per} B per session (server + client + lab), \
         Session struct {} B",
        base >> 20,
        full >> 20,
        Server::session_bytes()
    );
}

criterion_group!(benches, codecs, ipv6, server, setup);

fn main() {
    benches();
    if std::env::args().any(|a| a == "--bench") {
        memory();
    }
    Criterion::default().configure_from_args().final_summary();
}

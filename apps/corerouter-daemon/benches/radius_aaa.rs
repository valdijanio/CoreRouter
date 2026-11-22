//! G4.3j: authentications per second through the daemon's RADIUS AAA
//! service (the driver of `src/service/radius_aaa.rs`, included as it is),
//! against `proto-radius`'s test server on 127.0.0.1 in a thread. Measures
//! the whole path a PPP login takes: the queue, Access-Request encoding with
//! PAP and Message-Authenticator, UDP out and back, the reply checked and
//! decoded through the dictionary, the callback.
//!
//! `cargo bench -p corerouter-daemon --bench radius_aaa`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "../src/service/radius_aaa.rs"]
#[allow(dead_code)]
mod radius_aaa;

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::radius::AaaBackend;
use corerouter_model::ItemId;
use corerouter_model::radius::{AaaService, AuthOutcome, AuthRequest, RadiusServer};
use corerouter_proto_radius::packet::{AttrList, PushAttr};
use corerouter_proto_radius::testserver::TestServer;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// A server socket with room for a burst (net.core.rmem_max caps it).
fn big_socket() -> UdpSocket {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let _ = s.set_recv_buffer_size(4 << 20);
    s.bind(
        &"127.0.0.1:0"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    s.into()
}

const SECRET: &str = "bench-secret";

fn server(stop: Arc<AtomicBool>) -> std::net::SocketAddr {
    let sock = big_socket();
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || {
        let mut s = TestServer::new(SECRET.as_bytes(), 1);
        let mut reply = AttrList::new();
        reply.push_vsa(14988, 8, b"100M/200M").unwrap();
        s.add_user("bench", "pw", reply);
        let t0 = Instant::now();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            if let Some(r) = s.handle(from, &buf[..n], t0.elapsed().as_millis() as u64) {
                let _ = sock.send_to(&r.bytes, r.to);
            }
        }
    });
    addr
}

fn bench(c: &mut Criterion) {
    let stop = Arc::new(AtomicBool::new(false));
    let addr = server(stop.clone());
    let mut e = RadiusServer::new(ItemId(1), addr.ip());
    e.authentication_port = addr.port();
    e.accounting_port = 1;
    e.secret = SECRET.into();
    e.service = vec![AaaService::Ppp];
    e.timeout = 5000;
    let (aaa, h) = radius_aaa::spawn(radius_aaa::AaaConfig {
        servers: vec![e],
        nas_identifier: "bench".into(),
        ..radius_aaa::AaaConfig::default()
    })
    .unwrap();
    let mut g = c.benchmark_group("radius_aaa");
    g.sample_size(10);
    for n in [1u64, 1000] {
        g.throughput(Throughput::Elements(n));
        g.bench_function(format!("authenticate_{n}_concurrent"), |b| {
            b.iter_custom(|iters| {
                let t = Instant::now();
                for _ in 0..iters {
                    let (tx, rx) = mpsc::channel();
                    for _ in 0..n {
                        let tx = tx.clone();
                        aaa.authenticate(
                            AuthRequest::pap(AaaService::Ppp, "bench", "pw"),
                            Box::new(move |r| {
                                let _ = tx.send(r.outcome);
                            }),
                        );
                    }
                    for _ in 0..n {
                        let o = rx.recv_timeout(Duration::from_secs(30)).unwrap();
                        assert_eq!(o, AuthOutcome::Accept);
                    }
                }
                t.elapsed()
            });
        });
    }
    g.finish();
    aaa.stop();
    let _ = h.join();
    stop.store(true, Ordering::Relaxed);
}

criterion_group!(benches, bench);
criterion_main!(benches);

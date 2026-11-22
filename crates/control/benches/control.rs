//! G0.9 — the control channel: one request on a persistent loopback
//! connection, plain TCP (local token) and TLS (after login), for `ping`
//! (transport only) and `engine.execute interface.list` (transport + engine).
//! The guard against a Nagle-style regression is the latency test in
//! `tests/tcp.rs`; this measures the number behind it.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-control --bench control`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::TcpListener;
use std::time::Duration;

use corerouter_control::{Client, Endpoint, Gate, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, Shared, shared};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};

const PASSWORD: &str = "bench-password";
const TIMEOUT: Duration = Duration::from_secs(5);

fn lab() -> (Shared, Gate, String) {
    let mut s = Session::virtual_lab();
    s.execute(
        "user.add",
        &json!({"name": "admin", "group": "full", "password": PASSWORD}),
    )
    .unwrap();
    let gate = Gate::default();
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    (shared(s), gate, token)
}

fn tcp_client(session: &Shared, gate: &Gate, token: &str) -> Client {
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::loopback(listener),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    let mut c = Client::connect(&addr, TIMEOUT).unwrap();
    c.set_token(Some(token.to_owned()));
    c
}

fn tls_client(session: &Shared, gate: &Gate) -> Client {
    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::tls(listener, id.config.clone()),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    let mut c = Client::connect_tls(&addr, TIMEOUT, Some(&id.fingerprint)).unwrap();
    c.login("admin", PASSWORD).unwrap();
    c
}

fn control(c: &mut Criterion) {
    let (session, gate, token) = lab();
    let list = json!({"command": "interface.list", "params": {}});
    let mut g = c.benchmark_group("control");
    g.throughput(Throughput::Elements(1));
    for (transport, mut client) in [
        ("tcp", tcp_client(&session, &gate, &token)),
        ("tls", tls_client(&session, &gate)),
    ] {
        g.bench_function(format!("{transport}/ping"), |b| {
            b.iter(|| client.call("ping", black_box(Value::Null)).unwrap());
        });
        g.bench_function(format!("{transport}/interface.list"), |b| {
            b.iter(|| {
                client
                    .call("engine.execute", black_box(list.clone()))
                    .unwrap()
            });
        });
    }
    g.finish();
}

criterion_group!(benches, control);
criterion_main!(benches);

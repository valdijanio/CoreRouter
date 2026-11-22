//! G3.2a — the engine's side of BGP at scale, under the session lock:
//! adding 1 000 connections in one transaction (parse, seal nothing,
//! validate, commit), `routing.bgp.connection.list` and
//! `routing.bgp.session.list` with 1 000 of each. The FRR side (vty) is
//! measured on a real FRR by `scripts/frr-live.sh`.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench bgp`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_model::routing_state::{BgpSession, RoutingStatus};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

const N: u32 = 1000;

fn addr(i: u32) -> String {
    format!("10.{}.{}.{}", 100 + i / 65536, (i / 256) % 256, i % 256)
}

fn steps() -> Value {
    let mut steps = vec![json!({"command": "routing.bgp.template.add", "params": {
        "name": "peers", "hold_time": 90, "max_prefix_ipv4": 1000, "afi": "ip,ipv6"}})];
    steps.extend((0..N).map(|i| {
        json!({"command": "routing.bgp.connection.add", "params": {
            "name": format!("n{i}"), "remote_address": addr(i),
            "remote_as": 64512 + i, "templates": "peers"}})
    }));
    Value::Array(steps)
}

fn session() -> Session {
    let mut s = Session::new(Box::new(VirtualHal::default()));
    s.execute(
        "routing.bgp.instance.set",
        &json!({"asn": 65000, "router_id": "10.0.0.1"}),
    )
    .unwrap();
    s
}

fn loaded() -> Session {
    let mut s = session();
    s.batch(&steps(), true).unwrap();
    s.set_routing_status(RoutingStatus {
        backend: "frr 10.7.1".into(),
        updated: Some(1),
        error: None,
        bgp_sessions: (0..N)
            .map(|i| BgpSession {
                instance: "default".into(),
                vrf: "default".into(),
                remote_address: addr(i),
                remote_as: 64512 + i,
                local_as: 65000,
                state: "established".into(),
                established: true,
                uptime_secs: Some(1000),
                prefix_count: Some(800),
                prefix_sent: Some(10),
                connection: Some(format!("n{i}")),
                hold_time: Some(90),
                keepalive_time: Some(30),
                flaps: Some(0),
                afi: vec!["ipv4".into(), "ipv6".into()],
                ..BgpSession::default()
            })
            .collect(),
        ..RoutingStatus::default()
    });
    s
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("bgp");
    g.sample_size(10).measurement_time(Duration::from_secs(10));
    let batch = steps();
    g.bench_function("add_1000_connections_one_transaction", |b| {
        b.iter_batched(
            session,
            |mut s| s.batch(&batch, true).unwrap(),
            criterion::BatchSize::LargeInput,
        )
    });
    let mut s = loaded();
    g.bench_function("set_one_of_1000_connections", |b| {
        let mut h = 30;
        b.iter(|| {
            h = if h == 30 { 60 } else { 30 };
            s.execute(
                "routing.bgp.connection.set",
                &json!({"id": "n500", "hold_time": h}),
            )
            .unwrap()
        })
    });
    g.bench_function("connection_list_1000", |b| {
        b.iter(|| {
            s.execute("routing.bgp.connection.list", &json!({}))
                .unwrap()
        })
    });
    g.bench_function("session_list_1000", |b| {
        b.iter(|| s.execute("routing.bgp.session.list", &json!({})).unwrap())
    });
    let cfg = s.store().running().clone();
    g.bench_function("validate_1000", |b| {
        b.iter(|| corerouter_proto_bgp::validate(&cfg))
    });
    g.bench_function("render_1000", |b| {
        b.iter(|| corerouter_proto_bgp::render_all(&cfg.routing, &|_| None).unwrap())
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

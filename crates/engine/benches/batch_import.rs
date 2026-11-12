//! An atomic `engine.batch` the size of a big `/import` (audit-e2e): N
//! address-list entries in one transaction on a fresh lab. Each step used
//! to copy the whole candidate (its own rollback point) although the batch
//! already keeps one: quadratic in N.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench batch_import`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use corerouter_engine::Session;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

fn steps(n: usize) -> Value {
    let steps: Vec<Value> = (0..n)
        .map(|i| {
            json!({"command": "ip.firewall.address-list.add", "params": {
                "list": format!("l{}", i % 20),
                "address": format!("100.64.{}.{}", i / 256, i % 256),
            }})
        })
        .collect();
    Value::Array(steps)
}

/// G4.3g: a `/ppp secret` import (migrating subscribers from a RouterOS).
fn secrets(n: usize) -> Value {
    secrets_from(0, n)
}

fn secrets_from(base: usize, n: usize) -> Value {
    let steps: Vec<Value> = (base..base + n)
        .map(|i| {
            json!({"command": "ppp.secret.add", "params": {
                "name": format!("cliente{i}@isp"),
                "password": format!("senha{i}"),
            }})
        })
        .collect();
    Value::Array(steps)
}

/// G0.18: static DHCP leases, one per client, as a `/import` brings them.
fn leases(n: usize) -> Value {
    let steps: Vec<Value> = (0..n)
        .map(|i| {
            json!({"command": "ip.dhcp-server.lease.add", "params": {
                "address": format!("10.{}.{}.{}", 1 + i / 65_536, (i / 256) % 256, i % 256),
                "mac_address": format!("02:00:00:{:02x}:{:02x}:{:02x}", (i >> 16) & 255, (i >> 8) & 255, i & 255),
            }})
        })
        .collect();
    Value::Array(steps)
}

/// G3.4m: n 802.1Q sub-interfaces of ether1, an address each and one OSPF
/// template that matches them all, as the OSPF stress lab commits them
/// (docs/ospf-stress.md); and the batch that takes them out.
fn vlans_add(n: usize) -> Value {
    let mut steps: Vec<Value> = vec![
        json!({"command": "routing.ospf.instance.add", "params": {"name": "s", "router_id": "10.255.0.1"}}),
        json!({"command": "routing.ospf.area.add", "params": {"name": "bb", "instance": "s", "area_id": "0.0.0.0"}}),
    ];
    for i in 1..=n {
        let vid = 10 + i;
        steps.push(json!({"command": "interface.vlan.add", "params": {
            "name": format!("crs{vid}"), "parent": "ether1", "vlan_id": vid}}));
        steps.push(json!({"command": "ip.address.add", "params": {
            "address": format!("10.100.{}.{}/30", (i - 1) / 64, ((i - 1) % 64) * 4 + 1),
            "interface": format!("crs{vid}")}}));
    }
    steps.push(json!({"command": "routing.ospf.interface-template.add", "params": {
        "area": "bb", "networks": ["10.100.0.0/16"], "type": "ptp"}}));
    Value::Array(steps)
}

fn vlans_remove(s: &mut Session, n: usize) -> Value {
    let addrs = s.execute("ip.address.list", &json!({})).unwrap();
    let mut steps: Vec<Value> = addrs
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["interface"].as_str().unwrap_or("").starts_with("crs"))
        .map(|a| json!({"command": "ip.address.remove", "params": {"id": a["id"]}}))
        .collect();
    for i in 1..=n {
        steps.push(json!({"command": "interface.remove", "params": {"name": format!("crs{}", 10 + i)}}));
    }
    Value::Array(steps)
}

fn bench(c: &mut Criterion) {
    let mut line = String::new();
    for n in [500usize, 1000, 2000, 4000] {
        let mut s = Session::virtual_lab();
        let t = std::time::Instant::now();
        s.batch(&vlans_add(n), true).unwrap();
        let add = t.elapsed().as_secs_f64();
        let rm = vlans_remove(&mut s, n);
        let t = std::time::Instant::now();
        s.batch(&rm, true).unwrap();
        line.push_str(&format!(" {n}: add {add:.2} s, remove {:.2} s;", t.elapsed().as_secs_f64()));
    }
    eprintln!("batch_import: VLANs with an address and OSPF:{line}");
    // G4.3g: 100 000 secrets in batches of 10 000 (the batch limit) on one
    // session. The steps cost the same; the commit at the end of each batch
    // grows with the whole config.
    let mut s = Session::virtual_lab();
    let mut line = String::new();
    for k in 0..10 {
        let batch = secrets_from(k * 10_000, 10_000);
        let t = std::time::Instant::now();
        s.batch(&batch, true).unwrap();
        line.push_str(&format!(" {:.1}", t.elapsed().as_secs_f64() * 100.0));
    }
    eprintln!("batch_import: ppp.secret.add µs per secret by batch of 10 000 (0 → 100 000):{line}");
    let mut g = c.benchmark_group("batch_import");
    g.sample_size(10).measurement_time(Duration::from_secs(5));
    for n in [1000usize, 4000] {
        let batch = steps(n);
        g.bench_with_input(BenchmarkId::new("address_list", n), &batch, |b, batch| {
            b.iter_batched(
                Session::virtual_lab,
                |mut s| {
                    s.batch(batch, true).unwrap();
                    s
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    for n in [1000usize, 10_000] {
        let batch = secrets(n);
        g.bench_with_input(BenchmarkId::new("ppp_secret", n), &batch, |b, batch| {
            b.iter_batched(
                Session::virtual_lab,
                |mut s| {
                    s.batch(batch, true).unwrap();
                    s
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    for n in [1000usize, 10_000] {
        let batch = leases(n);
        g.bench_with_input(BenchmarkId::new("dhcp_lease", n), &batch, |b, batch| {
            b.iter_batched(
                Session::virtual_lab,
                |mut s| {
                    s.batch(batch, true).unwrap();
                    s
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

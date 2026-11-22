//! G1.31a: the WireGuard window's refresh on an interface with 20 000
//! peers (`MAX_PEERS`): `interface.wireguard.peers.list` and
//! `interface.wireguard.list`, as the GUI asks them every second while the
//! window is open. Each matches every configured peer to the data plane's
//! report; a walk of the report per peer made it O(peers²).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used)]

use std::hint::black_box;

use corerouter_engine::Session;
use corerouter_engine::wireguard::{encode, generate_private, public_of};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

const PEERS: u32 = 20_000;

fn session() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("interface.wireguard.add", &json!({"name": "wg0"}))
        .unwrap();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    for i in 0..PEERS {
        let k = encode(&public_of(&generate_private().unwrap()));
        let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i + 2);
        s.execute(
            "interface.wireguard.peers.add",
            &json!({"interface": "wg0", "public_key": k, "allowed_address": format!("{ip}/32"),
                    "endpoint_address": "198.51.100.7", "endpoint_port": 13231, "persistent_keepalive": 25}),
        )
        .unwrap();
    }
    s.execute("config.commit", &json!({})).unwrap();
    s
}

fn bench(c: &mut Criterion) {
    let mut s = session();
    let mut g = c.benchmark_group("wireguard_list");
    g.sample_size(10);
    g.bench_function("peers_list_20k", |b| {
        b.iter(|| {
            black_box(
                s.execute("interface.wireguard.peers.list", &json!({}))
                    .unwrap(),
            )
        });
    });
    g.bench_function("interfaces_list_20k", |b| {
        b.iter(|| black_box(s.execute("interface.wireguard.list", &json!({})).unwrap()));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

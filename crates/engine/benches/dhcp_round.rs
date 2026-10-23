//! One round of the DHCP server in the engine during a storm (audit of
//! G4.2): `Session::dhcp_server_poll` with 128 new clients a round (128
//! DISCOVERs and the 128 REQUESTs of the round before), lease history on,
//! a DNS zone and its reverse on the network and an address list on the
//! server. The whole round runs under the session's lock: its time is the
//! lock hold time. `mem`: the writes in memory (counted, printed once);
//! `fsync`: real files synced on this machine's disk, as `storage-fs` does.
//!
//! `cargo xtask bench dhcp_round`; alone:
//! `cargo bench -p corerouter-engine --bench dhcp_round`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../tests/support/dhcp_flood.rs"]
mod flood;

use std::hint::black_box;
use std::sync::{Arc, Mutex};

use corerouter_engine::{ConfigStorage, Session};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use serde_json::json;

const UNIX: u64 = 1_800_000_000;

fn session(storage: Box<dyn ConfigStorage>) -> (Session, flood::Shared) {
    let f: flood::Shared = Arc::new(Mutex::new(flood::Flood {
        per_tick: 128,
        ..flood::Flood::default()
    }));
    let mut s = Session::with_storage(Box::new(flood::FloodHal::new(f.clone())), storage);
    s.tick(UNIX);
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/12", "interface": "ether2"}),
        ),
        ("ip.dns.zone.add", json!({"name": "isp.example"})),
        ("ip.dns.zone.add", json!({"name": "10.in-addr.arpa"})),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.0.1.0-10.15.255.254"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "subs", "lease_time": "1h",
                   "conflict_detection": false, "client_rate_limit": 0, "address_lists": "subscribers"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/12", "gateway": "10.0.0.1", "dns_zone": "isp.example"}),
        ),
    ] {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    s.dhcp_server_driven(true);
    (s, f)
}

fn rounds(s: &mut Session, from: u64, n: u64) -> u64 {
    let mut ms = from;
    for _ in 0..n {
        ms += 5;
        black_box(s.dhcp_server_poll(ms, &|| 0));
    }
    ms
}

fn dhcp_round(c: &mut Criterion) {
    let mut g = c.benchmark_group("engine_dhcp_round");
    g.sample_size(10);
    // What one round writes, once.
    {
        let counting = flood::Counting::default();
        let (mut s, f) = session(Box::new(counting.clone()));
        let ms = rounds(&mut s, 0, 20);
        counting.take();
        rounds(&mut s, ms, 1);
        let w = counting.take();
        let acks = f.lock().unwrap().acks;
        eprintln!(
            "one storm round (128 binds, 128 offers): {} journal appends, {} journal rewrites, {} state saves ({acks} ACKs so far)",
            w.appends, w.rewrites, w.states
        );
    }
    g.bench_function("mem/10_rounds_of_128_binds", |b| {
        b.iter_batched(
            || {
                let (mut s, _) = session(Box::new(flood::Counting::default()));
                let ms = rounds(&mut s, 0, 20);
                (s, ms)
            },
            |(mut s, ms)| {
                rounds(&mut s, ms, 10);
                s
            },
            BatchSize::PerIteration,
        );
    });
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dhcp_round_fsync");
    let mut run = 0u32;
    g.bench_function("fsync/2_rounds_of_128_binds", |b| {
        b.iter_batched(
            || {
                run += 1;
                let d = dir.join(run.to_string());
                let _ = std::fs::remove_dir_all(&d);
                let (mut s, _) = session(Box::new(flood::Synced::new(d)));
                let ms = rounds(&mut s, 0, 5);
                (s, ms)
            },
            |(mut s, ms)| {
                rounds(&mut s, ms, 2);
                s
            },
            BatchSize::PerIteration,
        );
    });
    let _ = std::fs::remove_dir_all(&dir);
    g.finish();
}

criterion_group!(benches, dhcp_round);
criterion_main!(benches);

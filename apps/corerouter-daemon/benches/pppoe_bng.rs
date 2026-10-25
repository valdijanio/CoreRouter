//! G4.3d: PPPoE sessions per second through the daemon's BNG
//! (`src/service/pppoe_bng.rs`, included as it is) with real `proto-pppoe`
//! clients in memory: PADI to IPCP Opened, local `/ppp secret` with
//! MS-CHAPv2, an address from the pool, the XDP map entry made, the
//! history and the active table kept. And the memory a session costs
//! (RSS of 50 000 sessions, printed).
//!
//! `cargo bench -p corerouter-daemon --bench pppoe_bng`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "../src/service/pppoe_bng.rs"]
#[allow(dead_code)]
mod pppoe_bng;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use corerouter_model::ItemId;
use corerouter_model::ip_pool::{IpPool, IpPools, PoolRange};
use corerouter_model::ppp::{AddrOrPool, Ppp, PppProfile, PppSecret, PppoeServer};
use corerouter_model::ppp_secrets::Secrets;
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::wire::Mac;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use pppoe_bng::{Bng, PortInfo, Snapshot};

const IFINDEX: u32 = 3;

fn snapshot(users: usize) -> Snapshot {
    let mut ppp = Ppp::default();
    ppp.profiles.push(PppProfile {
        id: ItemId(1),
        name: "default".into(),
        remote_address: Some(AddrOrPool::Pool("p".into())),
        rate_limit: Some("10M/50M".into()),
        ..PppProfile::default()
    });
    ppp.secrets = Secrets::new(
        (0..users)
            .map(|i| PppSecret {
                id: ItemId(2 + i as u32),
                name: format!("u{i}"),
                password: format!("p{i}"),
                profile: "default".into(),
                ..PppSecret::default()
            })
            .collect(),
    );
    let srv: PppoeServer = serde_json::from_value(serde_json::json!({
        "id": "*1", "name": "s", "interface": "ether2", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0
    }))
    .unwrap();
    ppp.pppoe_servers.push(srv);
    let start = u32::from(Ipv4Addr::new(100, 64, 0, 1));
    let pools = IpPools {
        pools: vec![IpPool {
            id: ItemId(1),
            name: "p".into(),
            ranges: vec![
                PoolRange::new(Ipv4Addr::from(start), Ipv4Addr::from(start + 200_000)).unwrap(),
            ],
            next_pool: None,
            comment: String::new(),
        }],
        next_id: 1,
    };
    Snapshot {
        ppp,
        pools,
        aaa: None,
        unix_base: 0,
    }
}

/// Bring `n` subscribers up from scratch; returns the BNG (to keep it).
fn sessions(n: usize, snap: &Snapshot) -> Bng {
    let mut bng = Bng::new([1; 32]);
    bng.xdp = true;
    let ports = HashMap::from([(
        "s".to_owned(),
        PortInfo {
            ifindex: IFINDEX,
            mac: [2, 0xbb, 0, 0, 0, 1],
        },
    )]);
    bng.configure(0, snap.clone(), &ports);
    up(&mut bng, 0, n);
    bng
}

/// Bring subscribers `base..base + n` up on `bng`.
fn up(bng: &mut Bng, base: usize, n: usize) {
    let mut clients: Vec<Client> = (base..base + n)
        .map(|i| {
            let mac = [0x02, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 1];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: IFINDEX,
                username: format!("u{i}").into_bytes(),
                password: format!("p{i}"),
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            Client::new(cfg, [i as u8; 32])
        })
        .collect();
    let by_mac: HashMap<[u8; 6], usize> = clients
        .iter()
        .enumerate()
        .map(|(i, c)| (c.config().mac.0, i))
        .collect();
    let mut out = ClientOutput::new();
    let mut ups = 0;
    for c in &mut clients {
        c.start(0, &mut out);
    }
    let mut wire: Vec<Vec<u8>> = out.frames().map(|(_, f)| f.to_vec()).collect();
    out.clear();
    while !wire.is_empty() {
        for f in wire.drain(..) {
            bng.frame(0, IFINDEX, &f);
        }
        bng.effects.clear();
        for (_, f) in bng.frames.drain(..) {
            let mut dst = [0u8; 6];
            dst.copy_from_slice(&f[..6]);
            if let Some(&c) = by_mac.get(&dst) {
                clients[c].handle_frame(0, &f, &mut out);
                ups += out
                    .events
                    .iter()
                    .filter(|e| matches!(e, ClientEvent::Up { .. }))
                    .count();
                out.events.clear();
            }
        }
        wire.extend(out.frames().map(|(_, f)| f.to_vec()));
        out.clear();
    }
    assert_eq!(ups, n);
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmRSS:"))
                .map(str::to_owned)
        })
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

fn bench(c: &mut Criterion) {
    let snap = snapshot(50_000);
    // Memory: a second BNG with 50 000 sessions up, once the first one's
    // clients were freed (their memory is reused): the growth is the BNG's.
    let first = sessions(50_000, &snap);
    let before = rss_kib();
    let second = sessions(50_000, &snap);
    let after = rss_kib();
    eprintln!(
        "pppoe_bng: 50000 sessions up, RSS +{} KiB = {} B/session (BNG + proto-pppoe server, release)",
        after.saturating_sub(before),
        after.saturating_sub(before) * 1024 / 50_000
    );
    drop((first, second));
    // G4.3g: does a session cost more with many already up? 60 000 (one
    // server: 16-bit SESSION_ID) in batches of 10 000, each batch timed.
    let snap100 = snapshot(100_000);
    let mut bng = sessions(0, &snap100);
    let mut line = String::new();
    for k in 0..6 {
        let t = std::time::Instant::now();
        up(&mut bng, k * 10_000, 10_000);
        line.push_str(&format!(" {:.1}", t.elapsed().as_secs_f64() * 100.0));
    }
    eprintln!("pppoe_bng: µs per session by batch of 10 000 (0 → 60 000 up):{line}");
    drop(bng);
    let mut g = c.benchmark_group("pppoe_bng");
    g.sample_size(10);
    g.throughput(Throughput::Elements(1000));
    g.bench_function("setup_1000_sessions", |b| b.iter(|| sessions(1000, &snap)));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

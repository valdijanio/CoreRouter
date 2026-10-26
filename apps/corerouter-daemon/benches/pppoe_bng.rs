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
#[path = "../src/service/pppoe_bng6.rs"]
#[allow(dead_code)]
mod pppoe_bng6;
#[path = "../src/service/pppoe_slow6.rs"]
#[allow(dead_code)]
mod pppoe_slow6;

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
        ..Snapshot::default()
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
    let ids: Vec<usize> = (base..base + n).collect();
    up_ids(bng, &ids);
}

fn mac_of(i: usize) -> [u8; 6] {
    [0x02, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 1]
}

/// Bring subscribers `ids` up on `bng`.
fn up_ids(bng: &mut Bng, ids: &[usize]) {
    let n = ids.len();
    let mut clients: Vec<Client> = ids
        .iter()
        .map(|&i| {
            let mac = mac_of(i);
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
    // G4.3g: the workers, each on its own thread with the subscribers whose
    // MAC hashes to it (as the driver hands them out), sharing the active
    // table, the history and the pools: sessions a second, all together.
    let n = 40_000;
    let mut line = String::new();
    for lanes in [1u16, 2, 4, 8] {
        let first = Bng::first_of([1; 32], lanes);
        let mut bngs = vec![];
        for l in 1..lanes {
            bngs.push(first.sibling([1 + l as u8; 32], l, lanes));
        }
        bngs.insert(0, first);
        let ports = HashMap::from([(
            "s".to_owned(),
            PortInfo {
                ifindex: IFINDEX,
                mac: [2, 0xbb, 0, 0, 0, 1],
            },
        )]);
        for b in &mut bngs {
            b.xdp = true;
            b.configure(0, snap100.clone(), &ports);
        }
        let mut ids: Vec<Vec<usize>> = vec![Vec::new(); usize::from(lanes)];
        for i in 0..n {
            let mut f = [0u8; 12];
            f[6..12].copy_from_slice(&mac_of(i));
            ids[usize::from(Bng::lane_of(&f, lanes))].push(i);
        }
        let t = std::time::Instant::now();
        let handles: Vec<_> = bngs
            .into_iter()
            .zip(ids)
            .map(|(mut b, ids)| {
                std::thread::spawn(move || {
                    up_ids(&mut b, &ids);
                    b
                })
            })
            .collect();
        let done: Vec<Bng> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let secs = t.elapsed().as_secs_f64();
        line.push_str(&format!(" {lanes}: {:.0}/s", n as f64 / secs));
        drop(done);
    }
    eprintln!("pppoe_bng: {n} sessions by workers (sessions/s, release):{line}");
    let mut g = c.benchmark_group("pppoe_bng");
    g.sample_size(10);
    g.throughput(Throughput::Elements(1000));
    g.bench_function("setup_1000_sessions", |b| b.iter(|| sessions(1000, &snap)));
    g.finish();
    ha(c, &snap, &snap100);
    // G4.3l: the slow path's IPv6 lookup per packet down, with 100 000
    // sessions (a /64 and a delegated /56 each): one hash probe per prefix
    // length in use.
    let mut ix = pppoe_slow6::Net6Index::default();
    for i in 0..100_000u128 {
        let p64 = std::net::Ipv6Addr::from((0x2001_0db8_0100u128 << 80) | (i << 64));
        let pd = std::net::Ipv6Addr::from((0x2001_0db8_8000u128 << 80) | (i << 72));
        ix.insert(ipnet::Ipv6Net::new(p64, 64).unwrap(), (0usize, i as u16));
        ix.insert(ipnet::Ipv6Net::new(pd, 56).unwrap(), (0usize, i as u16));
    }
    let probes: Vec<std::net::Ipv6Addr> = (0..1024u128)
        .map(|k| {
            let i = (k * 7919) % 100_000;
            if k % 2 == 0 {
                std::net::Ipv6Addr::from((0x2001_0db8_0100u128 << 80) | (i << 64) | 0x77)
            } else {
                std::net::Ipv6Addr::from((0x2001_0db8_8000u128 << 80) | (i << 72) | (5 << 64) | 1)
            }
        })
        .collect();
    let mut g = c.benchmark_group("pppoe_slow6");
    g.throughput(Throughput::Elements(probes.len() as u64));
    g.bench_function("lookup_200k_prefixes", |b| {
        b.iter(|| probes.iter().filter(|a| ix.get(**a).is_some()).count())
    });
    g.finish();
}

/// G4.3h hot standby: what publishing the sessions to the standby costs
/// the BNG. Setup with and without it, the record of each new session
/// (`ha_take`), the counters sweep every 10 s, and the workers together
/// with every change into one shared publisher (the daemon's pair lock).
fn ha(c: &mut Criterion, snap: &Snapshot, snap100: &Snapshot) {
    use corerouter_proto_ha::sync::{Publisher, SyncConfig};
    use pppoe_bng::ha::HaChange;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    let hot = |s: &Snapshot| {
        let mut s = s.clone();
        s.ppp.redundancy.enabled = true;
        s.ppp.redundancy.mode = corerouter_model::ppp_redundancy::HaMode::HotStandby;
        s.ppp.redundancy.secret = "segredo-do-par-123".into();
        s
    };
    pppoe_bng::HA_ACTIVE.store(true, Ordering::Release);
    let hsnap = hot(snap);
    let publish = |p: &mut Publisher, v: Vec<HaChange>| {
        for ch in v {
            match ch {
                HaChange::Up(k, v) => p.upsert(0, k, v),
                HaChange::Gone(k) => p.remove(0, k),
                HaChange::Counters(k, c) => p.counters(0, k, c),
            }
        }
    };
    // The 1 s tick of one worker with 50 000 sessions (the worst case: one
    // lane), with and without the counters for the standby (every 10 s, in
    // the same pass).
    let mut bng = sessions(50_000, &hsnap);
    let _ = bng.ha_take(0);
    let t_tick = |bng: &mut Bng, at: u64| {
        let t = std::time::Instant::now();
        bng.tick(at, &[]);
        t.elapsed().as_secs_f64() * 1e3
    };
    let plain = t_tick(&mut bng, 1_000);
    let with = t_tick(&mut bng, pppoe_bng::ha::COUNTERS_MS + 2_000);
    let n = bng.ha_take(0).len();
    eprintln!(
        "pppoe_bng/ha: tick of 50000 sessions: {plain:.2} ms; with the {n} counters for the standby: {with:.2} ms (one worker)"
    );
    drop(bng);
    // The workers, 40 000 logins in rounds of 256 each, then the round's
    // publish into one shared publisher (the daemon's pair lock), while a
    // sync thread holds that lock 8 ms of every 10 (a snapshot being
    // encoded, the worst case). `wait`: the worker blocks on the lock;
    // else `try_lock`, and a busy lock leaves the changes for the next
    // round (`publish` in `ppp_ha.rs`). Sessions/s and the longest round.
    let n = 40_000;
    let hsnap100 = hot(snap100);
    let mut line = String::new();
    for (name, ha, wait) in [("off", false, false), ("hot+wait", true, true), ("hot+try", true, false)] {
        for lanes in [1u16, 8] {
            let publisher = Arc::new(Mutex::new(Publisher::new(1, SyncConfig::default())));
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let holder = {
                let (publisher, stop) = (publisher.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let g = publisher.lock().unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(8));
                        drop(g);
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                })
            };
            let first = Bng::first_of([1; 32], lanes);
            let mut bngs = vec![];
            for l in 1..lanes {
                bngs.push(first.sibling([1 + l as u8; 32], l, lanes));
            }
            bngs.insert(0, first);
            let ports = HashMap::from([(
                "s".to_owned(),
                PortInfo {
                    ifindex: IFINDEX,
                    mac: [2, 0xbb, 0, 0, 0, 1],
                },
            )]);
            for b in &mut bngs {
                b.xdp = true;
                b.configure(0, if ha { hsnap100.clone() } else { snap100.clone() }, &ports);
            }
            let mut ids: Vec<Vec<usize>> = vec![Vec::new(); usize::from(lanes)];
            for i in 0..n {
                let mut f = [0u8; 12];
                f[6..12].copy_from_slice(&mac_of(i));
                ids[usize::from(Bng::lane_of(&f, lanes))].push(i);
            }
            let t = std::time::Instant::now();
            let handles: Vec<_> = bngs
                .into_iter()
                .zip(ids)
                .map(|(mut b, ids)| {
                    let publisher = publisher.clone();
                    std::thread::spawn(move || {
                        let mut worst = 0f64;
                        let mut round = |b: &mut Bng, chunk: &[usize]| {
                            let t = std::time::Instant::now();
                            up_ids(b, chunk);
                            let v = b.ha_take(0);
                            if !v.is_empty() {
                                if wait {
                                    publish(&mut publisher.lock().unwrap(), v);
                                } else if let Ok(mut p) = publisher.try_lock() {
                                    publish(&mut p, v);
                                } else {
                                    b.ha_requeue(v);
                                }
                            }
                            worst = worst.max(t.elapsed().as_secs_f64() * 1e3);
                        };
                        for chunk in ids.chunks(256) {
                            round(&mut b, chunk);
                        }
                        // What is left goes once the lock frees.
                        let v = b.ha_take(0);
                        publish(&mut publisher.lock().unwrap(), v);
                        (b, worst)
                    })
                })
                .collect();
            let done: Vec<(Bng, f64)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let secs = t.elapsed().as_secs_f64();
            stop.store(true, Ordering::Relaxed);
            holder.join().unwrap();
            if ha {
                assert_eq!(publisher.lock().unwrap().len(), n);
            }
            let worst = done.iter().map(|d| d.1).fold(0f64, f64::max);
            line.push_str(&format!(
                "\n  {name} {lanes} workers: {:.0}/s, longest round {worst:.1} ms",
                n as f64 / secs
            ));
            drop(done);
        }
    }
    eprintln!("pppoe_bng/ha: {n} sessions by workers, rounds of 256, the lock held 8 of every 10 ms (release):{line}");
    let mut g = c.benchmark_group("pppoe_bng_ha");
    g.sample_size(10);
    g.throughput(Throughput::Elements(1000));
    g.bench_function("setup_1000_sessions_hot_standby", |b| {
        b.iter(|| {
            let mut bng = sessions(1000, &hsnap);
            let mut p = Publisher::new(1, SyncConfig::default());
            let v = bng.ha_take(0);
            publish(&mut p, v);
            (bng, p)
        })
    });
    g.finish();
    pppoe_bng::HA_ACTIVE.store(false, Ordering::Release);
}

criterion_group!(benches, bench);
criterion_main!(benches);

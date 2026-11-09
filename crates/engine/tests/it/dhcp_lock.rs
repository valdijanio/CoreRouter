//! G4.2h: the DHCP server reads, decodes and picks addresses outside the
//! session lock, so a storm of DISCOVERs does not hold the control channel
//! back, and giving an address away stays exclusive.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::support;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use corerouter_engine::dhcp_server::{JOURNAL, server_round};
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, Shared, lock, shared};
use corerouter_proto_dhcp::server::leases::State;
use serde_json::{Value, json};
use support::dhcp_flood::{self as flood, Flood, FloodHal, Synced};

const UNIX: u64 = 1_800_000_000;

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// A server on a big pool, with the lease history, a DNS zone and an address
/// list: everything a binding touches.
fn storm_session(storage: Box<dyn ConfigStorage>, f: flood::Shared) -> Shared {
    let mut s = Session::with_storage(Box::new(FloodHal::new(f)), storage);
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
        ok(&mut s, id, p);
    }
    s.dhcp_server_driven(true);
    shared(s)
}

/// What the control channel saw during a storm.
// Printed through `Debug`, which the dead-code lint does not count.
#[allow(dead_code)]
#[derive(Debug)]
struct Seen {
    p50: Duration,
    p99: Duration,
    max: Duration,
    samples: usize,
    /// `ip.dhcp-server.print`, which reads the leases: its own p99.
    leases_p99: Duration,
    messages: u64,
}

/// Two threads for `secs`: `round` runs the server as the daemon's service
/// does (1 ms apart in a storm, `service/dhcp_server.rs`), and a client runs
/// a read command under the session lock every 2 ms and times it from before
/// it asks for the lock, as the control channel would.
fn measure(
    s: &Shared,
    f: &flood::Shared,
    secs: u64,
    round: impl Fn(&Shared, u64, &dyn Fn() -> u64) + Send + Sync,
) -> Seen {
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let (mut lat, mut leases) = std::thread::scope(|sc| {
        let (stop, round) = (&stop, &round);
        sc.spawn(move || {
            let clock = move || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            while !stop.load(Ordering::Relaxed) {
                let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                round(s, ms, &clock);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let client = sc.spawn(move || {
            let (mut lat, mut leases) = (Vec::new(), Vec::new());
            let mut i = 0u32;
            while start.elapsed() < Duration::from_secs(secs) {
                let reads_leases = i.is_multiple_of(10);
                let id = if reads_leases {
                    "ip.dhcp-server.print"
                } else {
                    "interface.list"
                };
                let t = Instant::now();
                ok(&mut lock(s), id, json!({}));
                if reads_leases { &mut leases } else { &mut lat }.push(t.elapsed());
                i += 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            stop.store(true, Ordering::Relaxed);
            (lat, leases)
        });
        client.join().unwrap()
    });
    lat.sort();
    leases.sort();
    let at = |p: usize| lat[(lat.len() - 1) * p / 100];
    Seen {
        p50: at(50),
        p99: at(99),
        max: lat[lat.len() - 1],
        samples: lat.len(),
        leases_p99: leases[(leases.len() - 1) * 99 / 100],
        messages: f.lock().unwrap().recv_calls,
    }
}

fn discover_storm() -> flood::Shared {
    Arc::new(Mutex::new(Flood {
        endless: true,
        discover_only: true,
        ..Flood::default()
    }))
}

fn binding_storm() -> flood::Shared {
    Arc::new(Mutex::new(Flood {
        per_tick: 128,
        ..Flood::default()
    }))
}

/// Slow layer (G4.2h): real fsyncs and 5 s of each storm, before and after,
/// ~20 s. `G42H_SECS=30` for the numbers in `docs/dhcp.md`.
#[test]
fn slow_the_control_channel_stays_quick_in_a_discover_storm() {
    let dir = std::env::temp_dir().join(format!("cr-dhcp-lock-{}", std::process::id()));
    let secs: u64 = std::env::var("G42H_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    for (name, f) in [("discover", discover_storm()), ("binding", binding_storm())] {
        if std::env::var("G42H_ONLY").is_ok_and(|o| o != name) {
            continue;
        }
        let s = storm_session(Box::new(Synced::new(dir.join(name))), f.clone());
        let before = measure(&s, &f, secs, |s, ms, clock| {
            lock(s).dhcp_server_poll(ms, clock);
        });
        eprintln!("G4.2h {name} under the lock: {before:?}");
        let f = if name == "discover" {
            discover_storm()
        } else {
            binding_storm()
        };
        let s = storm_session(
            Box::new(Synced::new(dir.join(format!("{name}-after")))),
            f.clone(),
        );
        let after = measure(&s, &f, secs, |s, ms, clock| {
            server_round(s, ms, clock);
        });
        eprintln!("G4.2h {name} outside the lock: {after:?}");
        // The gap's target. Bindings: their DNS names still take long under
        // the lock (`dns_dynamic::apply` walks the records per lease).
        if name == "discover" {
            assert!(after.p99 < Duration::from_millis(50), "{after:?}");
            assert!(after.leases_p99 < Duration::from_millis(50), "{after:?}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A small pool, more clients than addresses, the server's rounds on one
/// thread and an operator on others, all at once: releasing, forgetting,
/// making static and committing config while addresses are being picked.
///
/// No address ever goes to two clients: an ACK to another MAC comes only
/// after the operator or the server took it from the first (`freed`). And
/// the journal, written in the order the leases changed, replays to the
/// table the server holds.
#[test]
fn an_address_never_goes_to_two_clients_with_commands_in_between() {
    let storage = MemoryStorage::default();
    let f: flood::Shared = Arc::new(Mutex::new(Flood {
        per_tick: 8,
        record_acks: true,
        ..Flood::default()
    }));
    let mut session = Session::with_storage(
        Box::new(FloodHal::new(f.clone())),
        Box::new(storage.clone()),
    );
    session.tick(UNIX);
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "ether2"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.0.0.10-10.0.0.73"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "subs", "lease_time": "1h",
                   "conflict_detection": false, "client_rate_limit": 0}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/24", "gateway": "10.0.0.1"}),
        ),
    ] {
        ok(&mut session, id, p);
    }
    session.dhcp_server_driven(true);
    let s = shared(session);
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let clock = move || u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    let freed = std::thread::scope(|sc| {
        let (stop, s) = (&stop, &s);
        // The operator: takes addresses back and changes the config.
        let operator = sc.spawn(move || {
            // How many times each address was taken from its client.
            let mut freed: HashMap<Ipv4Addr, u32> = HashMap::new();
            let mut i = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let ip = Ipv4Addr::new(10, 0, 0, 10 + (i % 64) as u8);
                let text = ip.to_string();
                let mut g = lock(s);
                let took = match i % 4 {
                    0 => g
                        .execute("ip.dhcp-server.lease.release", &json!({"address": text}))
                        .is_ok(),
                    1 => g
                        .execute("ip.dhcp-server.lease.remove", &json!({"id": text}))
                        .is_ok(),
                    2 => {
                        // A plan change while addresses are being picked.
                        ok(
                            &mut g,
                            "ip.dhcp-server.network.set",
                            json!({"id": "10.0.0.0/24", "comment": format!("r{i}")}),
                        );
                        false
                    }
                    _ => {
                        ok(&mut g, "ip.dhcp-server.lease.print", json!({}));
                        false
                    }
                };
                drop(g);
                if took {
                    *freed.entry(ip).or_default() += 1;
                }
                i += 1;
                std::thread::sleep(Duration::from_micros(200));
            }
            freed
        });
        for n in 0u64..4000 {
            server_round(s, n * 5, &clock);
        }
        stop.store(true, Ordering::Relaxed);
        operator.join().unwrap()
    });
    // Each change of owner of an address needs one taking of it.
    let acked = std::mem::take(&mut f.lock().unwrap().acked);
    assert!(acked.len() > 200, "a real contest: {} grants", acked.len());
    assert!(
        freed.values().sum::<u32>() > 50,
        "a real contest: {freed:?}"
    );
    let mut owner: HashMap<Ipv4Addr, [u8; 6]> = HashMap::new();
    let mut changes: HashMap<Ipv4Addr, u32> = HashMap::new();
    for (ip, mac) in acked {
        if owner.insert(ip, mac).is_some_and(|old| old != mac) {
            *changes.entry(ip).or_default() += 1;
        }
    }
    for (ip, n) in &changes {
        let took = freed.get(ip).copied().unwrap_or(0);
        assert!(
            *n <= took,
            "{ip} changed owner {n} times, taken back {took}"
        );
    }

    // One more round applies what the last one left; then the journal
    // replays to what the server holds.
    server_round(&s, 4001 * 5, &clock);
    let g = lock(&s);
    let holds: HashMap<Ipv4Addr, [u8; 6]> = g
        .dhcp_server()
        .unwrap()
        .leases()
        .iter()
        .filter(|l| l.state == State::Bound)
        .map(|l| (l.address, l.mac))
        .collect();
    assert!(!holds.is_empty());
    let plan = g.dhcp_server().unwrap().plan().clone();
    drop(g);
    let text = storage.clone().load_journal(JOURNAL).unwrap().unwrap();
    let mut replayed = corerouter_proto_dhcp::server::Server::new(plan, UNIX);
    assert_eq!(replayed.replay(text.lines()), 0);
    let back: HashMap<Ipv4Addr, [u8; 6]> = replayed
        .leases()
        .iter()
        .filter(|l| l.state == State::Bound)
        .map(|l| (l.address, l.mac))
        .collect();
    assert_eq!(
        back, holds,
        "the journal is in the order the leases changed"
    );
}

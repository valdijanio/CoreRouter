//! G0.13: deadlines across a step of the wall clock. NTP steps it ahead (a
//! router without a battery-backed clock boots in 1970) or back (a wrong
//! server, an operator); only the monotonic clock says how much time
//! passed. Each deadline is checked with a step each way.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use corerouter_engine::Session;
use serde_json::{Value, json};
use support::dhcp_flood::{self as flood, Counting, Flood, FloodHal};

const UNIX: u64 = 1_800_000_000;
/// The steps: 56 years ahead, back to 1970, and small ones.
const STEPS: [i64; 4] = [1_700_000_000, -1_799_000_000, 40, -40];

struct Clocks {
    wall: Arc<AtomicU64>,
    mono: Arc<AtomicU64>,
}

impl Clocks {
    /// The wall clock jumps by `step`, and one second really passes.
    fn step(&self, step: i64) -> u64 {
        let w = self.wall.load(Ordering::SeqCst).saturating_add_signed(step);
        self.wall.store(w + 1, Ordering::SeqCst);
        self.mono.fetch_add(1, Ordering::SeqCst);
        w + 1
    }

    /// `secs` really pass.
    fn pass(&self, secs: u64) -> u64 {
        self.mono.fetch_add(secs, Ordering::SeqCst);
        self.wall.fetch_add(secs, Ordering::SeqCst) + secs
    }
}

fn lab(per_tick: u32) -> (Session, flood::Shared, Clocks, Counting) {
    let f: flood::Shared = Arc::new(Mutex::new(Flood {
        per_tick,
        ..Flood::default()
    }));
    let clocks = Clocks {
        wall: Arc::new(AtomicU64::new(UNIX)),
        mono: Arc::new(AtomicU64::new(100)),
    };
    let mut hal = FloodHal::new(f.clone());
    hal.clocks = Some((clocks.wall.clone(), clocks.mono.clone()));
    let counting = Counting::default();
    let mut s = Session::with_storage(Box::new(hal), Box::new(counting.clone()));
    s.tick(UNIX);
    (s, f, clocks, counting)
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn in_list(s: &mut Session, list: &str) -> Vec<Value> {
    ok(s, "ip.firewall.address-list.list", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["list"] == list)
        .cloned()
        .collect()
}

#[test]
fn dynamic_address_list_entries_follow_the_monotonic_clock() {
    for step in STEPS {
        let (mut s, _, clocks, _) = lab(0);
        ok(
            &mut s,
            "ip.firewall.address-list.add",
            json!({"list": "blocked", "address": "192.0.2.7", "timeout": 600}),
        );
        let w = clocks.step(step);
        s.tick(w);
        let e = in_list(&mut s, "blocked");
        assert_eq!(e.len(), 1, "step {step}: gone at once");
        assert_eq!(e[0]["timeout"], 599, "step {step}");
        // It ends when its 600 s are over, not a step earlier or later.
        let w = clocks.pass(598);
        s.tick(w);
        assert_eq!(in_list(&mut s, "blocked").len(), 1, "step {step}: early");
        let w = clocks.pass(1);
        s.tick(w);
        assert!(in_list(&mut s, "blocked").is_empty(), "step {step}: late");
    }
}

fn lan(s: &mut Session) {
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/16", "interface": "ether2"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.0.1.0-10.0.255.254"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "subs", "lease_time": "2m",
                   "conflict_detection": false, "client_rate_limit": 0,
                   "address_lists": "subscribers"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/16", "gateway": "10.0.0.1"}),
        ),
    ] {
        ok(s, id, p);
    }
    s.dhcp_server_driven(true);
}

fn rounds(s: &mut Session, ms: &mut u64, n: u64) {
    for _ in 0..n {
        *ms += 5;
        s.dhcp_server_poll(*ms, &|| 0);
    }
}

fn bound(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.dhcp-server.lease.print", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["status"] == "bound")
        .cloned()
        .collect()
}

/// The leases (and the address-list entries they put clients in) keep the
/// time they had left; the journal is rewritten with the moved times, so
/// a restart after the step does not end them either.
#[test]
fn dhcp_leases_keep_their_time_across_a_step() {
    for step in STEPS {
        let (mut s, f, clocks, counting) = lab(4);
        lan(&mut s);
        let mut ms = 0;
        rounds(&mut s, &mut ms, 3);
        f.lock().unwrap().per_tick = 0;
        rounds(&mut s, &mut ms, 2);
        let before = bound(&mut s);
        assert!(!before.is_empty(), "nothing bound");
        let left = before[0]["expires_after_secs"].as_u64().unwrap();
        assert!(left >= 115, "{left}");
        counting.take();

        let w = clocks.step(step);
        s.tick(w);
        rounds(&mut s, &mut ms, 2);
        let after = bound(&mut s);
        assert_eq!(after.len(), before.len(), "step {step}: leases ended");
        assert_eq!(
            after[0]["expires_after_secs"].as_u64().unwrap(),
            left - 1,
            "step {step}"
        );
        assert_eq!(
            in_list(&mut s, "subscribers").len(),
            before.len(),
            "step {step}"
        );
        if step.abs() >= 1000 {
            assert!(
                counting.take().rewrites >= 1,
                "step {step}: journal not rewritten"
            );
        }
        let log = ok(&mut s, "log.print", json!({})).to_string();
        assert!(
            log.contains("deu um passo de"),
            "step {step}: not in the log"
        );
        // And they end on time.
        let w = clocks.pass(left - 2);
        s.tick(w);
        rounds(&mut s, &mut ms, 2);
        assert_eq!(bound(&mut s).len(), before.len(), "step {step}: early");
        let w = clocks.pass(2);
        s.tick(w);
        rounds(&mut s, &mut ms, 2);
        assert!(bound(&mut s).is_empty(), "step {step}: late");
    }
}

//! Audit of G4.2 — the DHCP server in the engine under a storm and across
//! a restart: one write of each kind per round (group commit, as the
//! module promises), a round bounded in time (the session lock is shared
//! with the control channel), bindings that get their names and address
//! lists back after a restart, a failing disk that is not rewritten every
//! round, and a relay that only takes replies from its servers.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod support;

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use corerouter_engine::{ConfigStorage, Session};
use corerouter_hal::dhcp_server::Heard;
use serde_json::{Value, json};
use support::dhcp_flood::{self as flood, Counting, Flood, FloodHal};

const UNIX: u64 = 1_800_000_000;

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn session(storage: Box<dyn ConfigStorage>, per_tick: u32) -> (Session, flood::Shared) {
    let f: flood::Shared = Arc::new(Mutex::new(Flood {
        per_tick,
        ..Flood::default()
    }));
    let mut s = Session::with_storage(Box::new(FloodHal::new(f.clone())), storage);
    s.tick(UNIX);
    (s, f)
}

fn lan(s: &mut Session) {
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/16", "interface": "ether2"}),
        ),
        ("ip.dns.zone.add", json!({"name": "isp.example"})),
        ("ip.dns.zone.add", json!({"name": "10.in-addr.arpa"})),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.0.1.0-10.0.255.254"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "subs", "lease_time": "2m",
                   "conflict_detection": false, "client_rate_limit": 0, "address_lists": "subscribers"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/16", "gateway": "10.0.0.1", "dns_zone": "isp.example"}),
        ),
    ] {
        ok(s, id, p);
    }
    s.dhcp_server_driven(true);
}

fn rounds(s: &mut Session, from: u64, n: u64) -> u64 {
    let mut ms = from;
    for _ in 0..n {
        ms += 5;
        s.dhcp_server_poll(ms, &|| 0);
    }
    ms
}

/// One storm round (128 new bindings with history, a DNS zone and its
/// reverse, an address list): one append to each journal and one save of
/// the dynamic DNS records, not one (or two) per binding.
#[test]
fn a_storm_round_writes_once_per_journal() {
    let counting = Counting::default();
    let (mut s, f) = session(Box::new(counting.clone()), 128);
    lan(&mut s);
    let ms = rounds(&mut s, 0, 3);
    let before = f.lock().unwrap().acks;
    counting.take();
    rounds(&mut s, ms, 1);
    let w = counting.take();
    let acks = f.lock().unwrap().acks - before;
    assert_eq!(acks, 128, "the round bound 128 clients");
    assert!(w.appends <= 2, "{w:?}: leases + history, once each");
    assert!(w.states <= 1, "{w:?}: the DNS records, once");
    // And they are all there.
    let (_, dynamic) = s.dns_dynamic();
    assert_eq!(
        dynamic.records.len(),
        2 * 3 * 128,
        "A + PTR of each binding"
    );
    let list = ok(&mut s, "ip.firewall.address-list.list", json!({}));
    let n = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["list"] == "subscribers")
        .count();
    assert_eq!(n, 3 * 128);
    let hist = ok(&mut s, "ip.dhcp-server.history.print", json!({}));
    assert_eq!(hist["total"], 3 * 128);
}

/// An endless storm: one round stops reading after its time budget (the
/// clock here moves 1 ms per message), whatever the packet budget says.
#[test]
fn a_storm_round_is_bounded_in_time() {
    let (mut s, f) = session(Box::new(Counting::default()), 0);
    lan(&mut s);
    f.lock().unwrap().endless = true;
    let t = Cell::new(0u64);
    let clock = || {
        t.set(t.get() + 1_000);
        t.get()
    };
    s.dhcp_server_poll(5, &clock);
    let calls = f.lock().unwrap().recv_calls;
    assert!(calls <= 30, "{calls} messages in one round");
    assert!(calls >= 5, "{calls}");
}

/// A restart: bound leases come back from the journal with their address
/// list entries (not stored: rebuilt) and their DNS names, which leave the
/// zone when the lease ends.
#[test]
fn bindings_get_their_names_and_lists_back_after_a_restart() {
    let counting = Counting::default();
    let (mut s, _) = session(Box::new(counting.clone()), 1);
    lan(&mut s);
    let ms = rounds(&mut s, 0, 3);
    let bound: Vec<Ipv4Addr> = s
        .dhcp_server()
        .unwrap()
        .leases()
        .iter()
        .filter(|l| l.state == corerouter_proto_dhcp::server::leases::State::Bound)
        .map(|l| l.address)
        .collect();
    assert!(!bound.is_empty());
    let ip = bound[0];
    assert!(s.dhcp_server_dns(ip).is_some());
    drop(s);
    let _ = ms;

    let (mut s, _) = session(Box::new(counting.clone()), 0);
    s.dhcp_server_driven(true);
    rounds(&mut s, 0, 1);
    assert_eq!(
        s.dhcp_server_lists(ip),
        Some(vec!["subscribers".to_owned()])
    );
    let list = ok(&mut s, "ip.firewall.address-list.list", json!({}));
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|e| e["list"] == "subscribers" && e["address"] == ip.to_string()),
        "{list:#}"
    );
    assert!(s.dhcp_server_dns(ip).is_some());
    // The lease runs out (2 minutes): its names go.
    s.tick(UNIX + 600);
    rounds(&mut s, 10, 2);
    let (_, dynamic) = s.dns_dynamic();
    assert!(
        !dynamic
            .records
            .iter()
            .any(|r| r.record.address == Some(IpAddr::V4(ip))),
        "{:#?}",
        dynamic.records
    );
}

/// A disk that refuses every journal write: the leases journal is not
/// rewritten every round (each attempt serializes the whole table); it is
/// tried again after a pause. ACKs still go out (availability first, the
/// error is on the service's row).
#[test]
fn a_failing_disk_is_not_rewritten_every_round() {
    let counting = Counting {
        fail_journal: true,
        ..Counting::default()
    };
    let (mut s, f) = session(Box::new(counting.clone()), 8);
    lan(&mut s);
    let ms = rounds(&mut s, 0, 2);
    // The 8 clients renew in a loop: lines, no new records, until a
    // compaction is due (2 × records + 1024 lines).
    {
        let mut g = f.lock().unwrap();
        g.per_tick = 0;
        g.echo_acks = true;
    }
    let ms = rounds(&mut s, ms, 200);
    assert!(f.lock().unwrap().acks > 1100);
    assert!(s.dhcp_server_journal_error().is_some());
    counting.take();
    rounds(&mut s, ms, 100);
    let w = counting.take();
    assert!(w.rewrites <= 2, "{w:?}");
}

fn reply_from_server(giaddr: Ipv4Addr) -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = 2;
    m[1] = 1;
    m[2] = 6;
    m[16..20].copy_from_slice(&[10, 20, 0, 50]);
    m[24..28].copy_from_slice(&giaddr.octets());
    m[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]);
    m.extend_from_slice(&[53, 1, 2, 54, 4, 10, 99, 0, 2, 255]);
    m
}

/// The relay's uplink listens on port 67: a reply from an address that is
/// not one of the relay's servers is not put on the client's LAN.
#[test]
fn the_relay_only_takes_replies_from_its_servers() {
    let (mut s, f) = session(Box::new(Counting::default()), 0);
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.20.0.1/24", "interface": "ether3"}),
    );
    ok(
        &mut s,
        "ip.dhcp-relay.add",
        json!({"interface": "ether3", "dhcp_server": "10.99.0.2"}),
    );
    s.dhcp_server_driven(true);
    rounds(&mut s, 0, 1);
    let giaddr = Ipv4Addr::new(10, 20, 0, 1);
    let heard = |src| Heard {
        payload: reply_from_server(giaddr),
        src,
        dst: giaddr,
        src_mac: [0; 6],
        to_server: true,
    };
    f.lock()
        .unwrap()
        .uplink
        .push_back(heard(Ipv4Addr::new(10, 66, 6, 6)));
    rounds(&mut s, 10, 1);
    assert_eq!(f.lock().unwrap().sent, 0, "a stranger's reply went down");
    f.lock()
        .unwrap()
        .uplink
        .push_back(heard(Ipv4Addr::new(10, 99, 0, 2)));
    rounds(&mut s, 20, 1);
    assert_eq!(f.lock().unwrap().sent, 1, "the server's reply goes down");
}

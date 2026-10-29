//! audit-net — regressions found by the audit of interfaces, addresses,
//! routes, interface lists and firewall: each test failed before its fix.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use corerouter_engine::{Caller, EngineError, Link, MemoryStorage, Principal, Session, Slot};
use corerouter_hal::sff::SfpModule;
use corerouter_hal::{
    DynamicChange, Features, Hal, HalError, LinkInfo, LinkState, SharedProber, VirtualHal,
};
use corerouter_model::{Config, ConfigStore, IfName, persist};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// The command fails on `field`, with `needle` in the message, and leaves
/// the candidate as it was.
fn bad(s: &mut Session, id: &str, p: Value, field: &str, needle: &str) {
    let before = s.store().candidate().clone();
    match s.execute(id, &p) {
        Err(EngineError::BadParam {
            param: key,
            reason: msg,
        }) => {
            assert_eq!(key, field, "{id} {p}: {msg}");
            assert!(msg.contains(needle), "{id} {p}: '{msg}' lacks '{needle}'");
        }
        other => panic!("{id} {p}: expected bad {field}, got {other:?}"),
    }
    assert_eq!(s.store().candidate(), &before, "{id} left changes behind");
}

fn remote(peer: &str, local: &str) -> Caller {
    Caller::new(9, format!("tls {peer}"))
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: peer.parse().unwrap(),
            local: local.parse().unwrap(),
        })
}

fn lockout(s: &mut Session, who: &Caller, id: &str, p: Value) -> String {
    match s.execute_as(who, id, &p) {
        Err(e @ EngineError::Lockout(_)) => e.to_string(),
        other => panic!("{id} {p}: expected a lockout, got {other:?}"),
    }
}

// --- lockout: where the management connection really comes in ---------

/// ISP style: management on a loopback /32, reached through the WAN port.
/// The probe packet used to come in on `lo0` (the interface holding the
/// address), so a drop on the WAN list never matched it.
#[test]
fn lockout_sees_the_wan_ingress_of_a_loopback_management_address() {
    let mut s = Session::virtual_lab();
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.255.0.1/32", "interface": "lo0"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.0.2.2/30", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.1"}),
    );
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "WAN", "interface": "ether1"}),
    );
    let op = remote("198.51.100.7:50123", "10.255.0.1:8729");
    let msg = lockout(
        &mut s,
        &op,
        "ip.firewall.filter.add",
        json!({"chain": "input", "in_interface_list": "WAN", "action": "drop"}),
    );
    assert!(msg.contains("on ether1"), "{msg}");
    // A drop on another port does not concern this connection.
    s.execute_as(
        &op,
        "ip.firewall.filter.add",
        &json!({"chain": "input", "in_interface": "ether5", "action": "drop"}),
    )
    .unwrap();
}

/// A connected peer comes in on the port of its network, whatever port
/// holds the address it connected to.
#[test]
fn lockout_uses_the_port_facing_a_connected_peer() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.9.1/24", "interface": "ether3"}),
    );
    // From the LAN (ether2) to the address of ether3.
    let op = remote("192.168.88.10:50123", "10.9.9.1:8729");
    let msg = lockout(
        &mut s,
        &op,
        "ip.firewall.filter.add",
        json!({"chain": "input", "in_interface": "ether2", "action": "drop"}),
    );
    assert!(msg.contains("on ether2"), "{msg}");
}

/// A HAL that counts what the engine asks of it.
#[derive(Default, Clone)]
struct Counts {
    dynamic_calls: Arc<AtomicUsize>,
    dynamic_entries: Arc<AtomicUsize>,
    sfp_reads: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

struct Counting {
    inner: VirtualHal,
    counts: Counts,
}

impl Hal for Counting {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.inner.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn features(&self) -> Features {
        self.inner.features()
    }
    fn prober(&self) -> Result<SharedProber, String> {
        self.inner.prober()
    }
    fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
        self.counts.dynamic_calls.fetch_add(1, Ordering::Relaxed);
        let n = match change {
            DynamicChange::Add(_) | DynamicChange::Remove(_) => 1,
            DynamicChange::Expired(all) => all.len(),
        };
        self.counts.dynamic_entries.fetch_add(n, Ordering::Relaxed);
        self.inner.address_list_dynamic(change)
    }
    fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        self.counts.sfp_reads.fetch_add(1, Ordering::Relaxed);
        self.counts.seen.lock().unwrap().push(name.to_string());
        Err(HalError::Unsupported(format!("'{name}' has no cage")))
    }
}

fn counting() -> (Session, Counts) {
    let counts = Counts::default();
    let hal = Counting {
        inner: VirtualHal::default(),
        counts: counts.clone(),
    };
    (Session::new(Box::new(hal)), counts)
}

/// Entries that expire together go to the data plane as one change (the
/// Linux backend ran one `nft` per entry, under the session lock).
#[test]
fn dynamic_entries_expiring_together_are_one_data_plane_change() {
    let (mut s, counts) = counting();
    s.tick(1_000);
    for i in 0..300 {
        ok(
            &mut s,
            "ip.firewall.address-list.add",
            json!({"list": "blk", "address": format!("10.1.{}.{}", i / 250, i % 250), "timeout": 60}),
        );
    }
    counts.dynamic_calls.store(0, Ordering::Relaxed);
    counts.dynamic_entries.store(0, Ordering::Relaxed);
    s.tick(1_061);
    assert_eq!(counts.dynamic_calls.load(Ordering::Relaxed), 1);
    assert_eq!(counts.dynamic_entries.load(Ordering::Relaxed), 300);
    let rows = ok(&mut s, "ip.firewall.address-list.list", Value::Null);
    assert!(rows.as_array().unwrap().is_empty(), "{rows}");
}

/// A port without a cage is asked once, not on every scan.
#[test]
fn ports_without_a_cage_are_not_probed_on_every_scan() {
    let (mut s, counts) = counting();
    for t in [1_000, 1_031, 1_062, 1_093] {
        s.tick(t);
    }
    let ports = s
        .store()
        .running()
        .interfaces
        .values()
        .filter(|i| i.kind == corerouter_model::InterfaceKind::Ethernet)
        .count();
    assert!(ports > 0);
    assert_eq!(
        counts.sfp_reads.load(Ordering::Relaxed),
        ports,
        "{:?}",
        counts.seen.lock().unwrap()
    );
}

// --- address lists -----------------------------------------------------

#[test]
fn address_list_set_refuses_an_address_a_dynamic_entry_has() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "blk", "address": "10.0.0.5", "timeout": "1h"}),
    );
    let id = ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "blk", "address": "10.0.0.6"}),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bad(
        &mut s,
        "ip.firewall.address-list.set",
        json!({"id": id, "address": "10.0.0.5"}),
        "address",
        "already in list blk",
    );
}

// --- addresses -----------------------------------------------------------

/// Linux keys an IPv6 address by address and interface only: a second
/// prefix length was refused by the kernel (EEXIST) and silently adopted.
#[test]
fn an_ipv6_address_cannot_be_on_one_interface_twice_with_two_prefixes() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "2001:db8::1/64", "interface": "ether1"}),
    );
    bad(
        &mut s,
        "ip.address.add",
        json!({"address": "2001:db8::1/48", "interface": "ether1"}),
        "address",
        "already on ether1 as 2001:db8::1/64",
    );
    // Another interface, or IPv4 with another mask, is fine (Linux too).
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "2001:db8::1/48", "interface": "ether2"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/16", "interface": "ether1"}),
    );
}

/// The commit check catches the same thing in a hand-edited config.
#[test]
fn validation_refuses_an_ipv6_address_twice_on_one_interface() {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for (i, a) in ["2001:db8::1/64", "2001:db8::1/56"].into_iter().enumerate() {
        cfg.ip.addresses.push(corerouter_model::AddressEntry {
            id: corerouter_model::ItemId(u32::try_from(i + 1).unwrap()),
            address: a.parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert!(
        issues
            .iter()
            .any(|i| i.to_string().contains("2001:db8::1 is already on ether1")),
        "{issues:?}"
    );
}

/// `ip.address.add` has a bound like every other list.
#[test]
fn addresses_are_bounded() {
    let max = corerouter_engine::validate::MAX_ADDRESSES;
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..max {
        let [a, b, c, d] = u32::try_from(i).unwrap().to_be_bytes();
        let _ = a;
        cfg.ip.addresses.push(corerouter_model::AddressEntry {
            id: corerouter_model::ItemId(u32::try_from(i + 1).unwrap()),
            address: format!("10.{b}.{c}.{d}/32").parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let storage = MemoryStorage::default();
    storage.put(
        Slot::Current,
        Some(persist::encode(&ConfigStore::new(cfg.clone())).unwrap()),
    );
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage));
    assert_eq!(s.store().running().ip.addresses.len(), max);
    bad(
        &mut s,
        "ip.address.add",
        json!({"address": "192.0.2.1/24", "interface": "ether2"}),
        "address",
        "at most",
    );
    cfg.ip.addresses.push(corerouter_model::AddressEntry {
        id: corerouter_model::ItemId(u32::try_from(max + 1).unwrap()),
        address: "192.0.2.1/24".parse().unwrap(),
        interface: "ether2".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert!(
        issues.iter().any(|i| i.to_string().contains("at most")),
        "{issues:?}"
    );
}

// --- interface lists ---------------------------------------------------

/// Renaming a list carries the settings that name it (as RouterOS does):
/// before, RA acceptance silently turned off and DNS refused the LAN.
#[test]
fn renaming_an_interface_list_renames_its_references() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "WAN", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ipv6.settings.set",
        json!({"accept_router_advertisements_on": "WAN"}),
    );
    ok(
        &mut s,
        "interface.list.set",
        json!({"name": "WAN", "new_name": "uplink"}),
    );
    let set = ok(&mut s, "ipv6.settings.get", Value::Null);
    assert_eq!(set["accept_router_advertisements_on"], "uplink", "{set}");

    // DNS allowed_from defaults to LAN.
    ok(
        &mut s,
        "interface.list.set",
        json!({"name": "LAN", "new_name": "inside"}),
    );
    let dns = ok(&mut s, "ip.dns.get", Value::Null);
    assert_eq!(dns["allowed_from"], json!(["inside"]), "{dns}");
    // And the commit after it still validates.
    ok(
        &mut s,
        "interface.set",
        json!({"name": "ether3", "comment": "x"}),
    );
}

/// Removing a list DNS still uses is refused up front, with the reason.
#[test]
fn removing_an_interface_list_dns_uses_is_refused() {
    let mut s = Session::virtual_lab();
    bad(
        &mut s,
        "interface.list.remove",
        json!({"name": "LAN"}),
        "name",
        "allowed_from",
    );
}

// --- routes ------------------------------------------------------------

/// Duplicates are still found when other routes sit between them.
#[test]
fn duplicate_routes_are_found_across_the_list() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.0.2.2/24", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.1.0.0/16", "gateway": "192.0.2.1"}),
    );
    for i in 0..5 {
        ok(
            &mut s,
            "ip.route.add",
            json!({"dst_address": format!("10.2.{i}.0/24"), "gateway": "192.0.2.1"}),
        );
    }
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    let mut cfg = s.store().candidate().clone();
    let mut dup = cfg.ip.routes.get(0).unwrap().clone();
    dup.id = corerouter_model::ItemId(999);
    cfg.ip.routes.push(dup);
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert!(
        issues
            .iter()
            .any(|i| i.to_string().contains("already goes to 10.1.0.0/16")),
        "{issues:?}"
    );
}

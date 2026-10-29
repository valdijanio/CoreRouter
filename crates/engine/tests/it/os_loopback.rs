//! G3.4i — the loopback named `lo` is the OS loopback (`os_loopback`): the
//! platform lists the kernel's `lo` as unmanaged until the config claims it,
//! yet `interface.loopback.add name=lo` and its addresses go through (also
//! in a transaction, before the commit that claims it); 127.0.0.0/8 and ::1
//! never land on it, only a loopback takes the name, and it joins no VRF.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use corerouter_engine::Session;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, IfName};
use serde_json::{Value, json};

/// The virtual lab, plus the kernel's `lo` as the Linux backend reports it
/// before the config claims it.
struct Host {
    lab: VirtualHal,
}

impl Hal for Host {
    fn describe(&self) -> String {
        "lab with the kernel lo".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.lab.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.lab.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.lab.poll()
    }
    fn unmanaged(&mut self) -> Vec<(IfName, String)> {
        vec![(
            "lo".parse().unwrap(),
            "the kernel loopback, kept by the OS".into(),
        )]
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

fn session() -> Session {
    Session::new(Box::new(Host {
        lab: VirtualHal::new(2),
    }))
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value, want: &str) {
    let e = s.execute(id, &p).expect_err(id).to_string();
    assert!(e.contains(want), "{id}: {e:?} lacks {want:?}");
}

fn addresses_on_lo(s: &Session) -> Vec<String> {
    s.store()
        .running()
        .ip
        .addresses
        .iter()
        .filter(|a| a.interface.as_str() == "lo")
        .map(|a| a.address.to_string())
        .collect()
}

#[test]
fn lo_takes_the_node_addresses() {
    let mut s = session();
    ok(&mut s, "interface.loopback.add", json!({"name": "lo"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.255.0.1/32", "interface": "lo"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "2001:db8::1/128", "interface": "lo"}),
    );
    assert_eq!(addresses_on_lo(&s), ["10.255.0.1/32", "2001:db8::1/128"]);
    // Another unmanaged name is still refused.
    let mut t = session();
    fails(
        &mut t,
        "ip.address.add",
        json!({"address": "10.255.0.1/32", "interface": "lo"}),
        "not managed",
    );
}

#[test]
fn lo_in_a_transaction_before_its_commit() {
    let mut s = session();
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(&mut s, "interface.loopback.add", json!({"name": "lo"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.255.0.2/32", "interface": "lo"}),
    );
    ok(&mut s, "config.commit", json!({}));
    assert_eq!(addresses_on_lo(&s), ["10.255.0.2/32"]);
}

#[test]
fn the_os_addresses_and_odd_uses_of_lo_are_refused() {
    let mut s = session();
    ok(&mut s, "interface.loopback.add", json!({"name": "lo"}));
    for a in ["127.0.0.1/8", "127.0.0.2/32", "::1/128"] {
        fails(
            &mut s,
            "ip.address.add",
            json!({"address": a, "interface": "lo"}),
            "OS's own",
        );
    }
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "vrf1", "interfaces": "lo"}),
        "OS loopback",
    );
    // Only a loopback takes the name (here the platform has no `lo`).
    let mut v = Session::virtual_lab();
    fails(
        &mut v,
        "interface.bridge.add",
        json!({"name": "lo"}),
        "OS loopback",
    );
    // A loopback with another name may hold 127.0.0.2 (it is not the OS's).
    ok(&mut v, "interface.loopback.add", json!({"name": "lo0"}));
    ok(
        &mut v,
        "ip.address.add",
        json!({"address": "127.0.0.2/32", "interface": "lo0"}),
    );
}

#[test]
fn rollback_takes_the_addresses_off_lo() {
    let mut s = session();
    let rev = s.store().current_revision();
    ok(&mut s, "interface.loopback.add", json!({"name": "lo"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.255.0.3/32", "interface": "lo"}),
    );
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert!(addresses_on_lo(&s).is_empty());
    assert!(
        !s.store()
            .running()
            .interfaces
            .contains_key(&"lo".parse::<IfName>().unwrap())
    );
}

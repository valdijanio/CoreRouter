//! G1.18 — links the platform does not let CoreRouter manage (another
//! program's bridge, the host `lo`) are listed with the reason, never land
//! in the config, and every command that would change them is refused. The
//! seed copies the kernel's admin state, so the boot apply changes nothing.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{ConfigStorage, MemoryStorage, Session};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, ConfigStore, IfName, Interface, InterfaceKind, persist};
use serde_json::{Value, json};

const WHY: &str = "a bridge created outside CoreRouter";

/// The virtual lab plus a foreign `docker0` bridge; `ether2` is down in
/// the "kernel".
struct Host {
    lab: VirtualHal,
    applies: Vec<(Config, Config)>,
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

impl Hal for Host {
    fn describe(&self) -> String {
        "lab with a foreign bridge".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        let mut links = self.lab.discover_links()?;
        for l in &mut links {
            l.up = l.name.as_str() != "ether2";
        }
        Ok(links)
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.applies.push((from.clone(), to.clone()));
        self.lab.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        // The lab "applies" whatever the config says; the kernel has one
        // docker0, the foreign bridge.
        let mut out = self.lab.poll();
        out.retain(|l| l.name.as_str() != "docker0");
        out.push(LinkState {
            name: n("docker0"),
            running: true,
            rx_bytes: 7,
            tx_bytes: 8,
            rx_packets: 1,
            tx_packets: 1,
            kind: "bridge".into(),
            mtu: 1400,
            mac: None,
            bus: None,
            unmanaged: Some(WHY.into()),
            errors: None,
        });
        out
    }
    fn unmanaged(&mut self) -> Vec<(IfName, String)> {
        vec![(n("docker0"), WHY.into())]
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

fn session() -> Session {
    Session::new(Box::new(Host {
        lab: VirtualHal::new(2),
        applies: Vec::new(),
    }))
}

fn row<'a>(rows: &'a Value, name: &str) -> &'a Value {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {rows}"))
}

#[test]
fn foreign_links_are_listed_but_not_managed() {
    let mut s = session();
    let rows = s.execute("interface.list", &json!({})).unwrap();
    let names: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ether1", "ether2", "docker0"]);
    let e1 = row(&rows, "ether1");
    assert_eq!(e1["managed"], true);
    assert_eq!(e1["unmanaged_reason"], Value::Null);
    let d = row(&rows, "docker0");
    assert_eq!(d["managed"], false);
    assert_eq!(d["type"], "bridge");
    assert_eq!(d["kind"], "bridge");
    assert_eq!(d["mtu"], 1400);
    assert_eq!(d["unmanaged_reason"], WHY);
    assert!(!s.store().candidate().interfaces.contains_key(&n("docker0")));
    // The type filter sees it too.
    let bridges = s
        .execute("interface.list", &json!({"type": "bridge"}))
        .unwrap();
    assert_eq!(bridges.as_array().unwrap().len(), 1);
}

#[test]
fn the_seed_copies_the_kernel_admin_state() {
    let s = session();
    let cfg = s.store().running();
    assert!(!cfg.interfaces[&n("ether1")].disabled);
    assert!(
        cfg.interfaces[&n("ether2")].disabled,
        "a port that is down stays down"
    );
}

#[test]
fn commands_on_foreign_links_are_refused_with_the_reason() {
    let mut s = session();
    let before = s.store().candidate().clone();
    let refused = [
        ("interface.set", json!({"name": "docker0", "mtu": 1500})),
        ("interface.bridge.add", json!({"name": "docker0"})),
        ("interface.loopback.add", json!({"name": "docker0"})),
        (
            "interface.vlan.add",
            json!({"name": "v5", "parent": "docker0", "vlan_id": 5}),
        ),
        (
            "interface.bridge.port.add",
            json!({"bridge": "docker0", "interface": "ether1"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "docker0"}),
        ),
        (
            "ip.vrf.add",
            json!({"name": "blue", "interfaces": "ether1,docker0"}),
        ),
    ];
    for (id, p) in refused {
        let err = s.execute(id, &p).unwrap_err().to_string();
        assert!(
            err.contains("'docker0' is not managed by CoreRouter") && err.contains(WHY),
            "{id}: {err}"
        );
    }
    assert_eq!(s.store().candidate(), &before);
    // Managed ports still work.
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
}

#[test]
fn a_stale_port_entry_for_a_foreign_link_can_be_removed() {
    // What a pre-G1.18 seed saved: the host's bridge taken as a port.
    let mut cfg = Config::default();
    for name in ["ether1", "docker0"] {
        cfg.interfaces
            .insert(n(name), Interface::new(n(name), InterfaceKind::Ethernet));
    }
    let mut storage = MemoryStorage::default();
    storage
        .save(&persist::encode(&ConfigStore::new(cfg)).unwrap())
        .unwrap();
    let host = Host {
        lab: VirtualHal::new(2),
        applies: Vec::new(),
    };
    let mut s = Session::with_storage(Box::new(host), Box::new(storage));
    let rows = s.execute("interface.list", &json!({})).unwrap();
    assert_eq!(row(&rows, "docker0")["managed"], false);
    assert_eq!(row(&rows, "docker0")["type"], "ether");
    let err = s
        .execute(
            "interface.set",
            &json!({"name": "docker0", "disabled": true}),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("not managed"), "{err}");
    s.execute("interface.remove", &json!({"name": "docker0"}))
        .unwrap();
    assert!(!s.store().running().interfaces.contains_key(&n("docker0")));
    // A real port still cannot go.
    let err = s
        .execute("interface.remove", &json!({"name": "ether1"}))
        .unwrap_err()
        .to_string();
    assert!(err.contains("physical port"), "{err}");
}

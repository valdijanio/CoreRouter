//! G1.3 — drift: `config.drift.list` sees what changed in the data plane
//! behind CoreRouter's back, `config.drift.reconcile` puts the running
//! config back without changing it. The virtual lab's kernel is changed
//! through its handle, like an operator with a root shell would.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, CommitMode, EngineError, Link, Principal, Session};
use corerouter_hal::VirtualHal;
use corerouter_hal::drift::KernelRoute;
use corerouter_hal::virt::LabKernel;
use corerouter_model::IfName;
use serde_json::{Value, json};

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// Lab: ether1 = 10.0.0.2/24 with a default route, ether2 =
/// 192.168.88.1/24, VLAN `v10` on ether2 with 10.10.0.1/24.
fn lab() -> (Session, LabKernel) {
    let hal = VirtualHal::new(8);
    let kernel = hal.kernel();
    let mut s = Session::new(Box::new(hal));
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v10", "parent": "ether2", "vlan_id": 10}),
    );
    for (a, i) in [
        ("10.0.0.2/24", "ether1"),
        ("192.168.88.1/24", "ether2"),
        ("10.10.0.1/24", "v10"),
    ] {
        ok(
            &mut s,
            "ip.address.add",
            json!({"address": a, "interface": i}),
        );
    }
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    (s, kernel)
}

fn drift(s: &mut Session) -> Vec<Value> {
    let r = ok(s, "config.drift.list", json!({}));
    assert_eq!(r["in_sync"], r["drift"].as_array().unwrap().is_empty());
    r["drift"].as_array().unwrap().clone()
}

fn kinds(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|d| {
            format!(
                "{} {}",
                d["kind"].as_str().unwrap(),
                d["item"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn an_applied_config_is_in_sync() {
    let (mut s, _) = lab();
    assert_eq!(drift(&mut s), Vec::<Value>::new());
    let r = ok(&mut s, "config.drift.reconcile", json!({}));
    assert_eq!(r, json!({"fixed": 0, "remaining": []}));
}

#[test]
fn every_kind_of_drift_is_listed_and_reconciled() {
    let (mut s, kernel) = lab();
    let rev = s.store().current_revision();
    let running = s.store().running().clone();
    {
        let mut k = kernel.lock().unwrap();
        k.addresses
            .remove(&(n("ether2"), "192.168.88.1/24".parse().unwrap()));
        k.addresses
            .insert((n("ether2"), "192.0.2.50/24".parse().unwrap()));
        // The kernel's own link-local is not drift.
        k.addresses
            .insert((n("ether2"), "fe80::1/64".parse().unwrap()));
        // Another program's link is not drift either.
        k.addresses
            .insert((n("docker0"), "172.17.0.1/16".parse().unwrap()));
        k.routes.clear();
        k.routes.insert(KernelRoute {
            table: 254,
            dst: "198.51.100.0/24".parse().unwrap(),
            metric: 1,
            link: n("ether1"),
            gateway: Some("10.0.0.9".parse().unwrap()),
        });
        let e3 = k.links.get_mut(&n("ether3")).unwrap();
        e3.up = false;
        e3.mtu = 9000;
        k.links.remove(&n("v10"));
        k.addresses
            .remove(&(n("v10"), "10.10.0.1/24".parse().unwrap()));
    }
    let rows = drift(&mut s);
    assert_eq!(
        kinds(&rows),
        [
            "link-missing v10",
            "admin-state ether3",
            "mtu ether3",
            "address-missing 192.168.88.1/24",
            "address-extra 192.0.2.50/24",
            "route-missing route 0.0.0.0/0 via 10.0.0.1 dev 'ether1' metric 1",
            "route-extra route 198.51.100.0/24 via 10.0.0.9 dev 'ether1' metric 1",
        ]
    );
    let mtu = rows.iter().find(|d| d["kind"] == "mtu").unwrap();
    assert_eq!(
        (&mtu["expected"], &mtu["actual"]),
        (&json!("1500"), &json!("9000"))
    );
    assert!(rows.iter().all(|d| d["fixable"] == true));

    let r = ok(&mut s, "config.drift.reconcile", json!({}));
    assert_eq!(r, json!({"fixed": 7, "remaining": []}));
    assert_eq!(drift(&mut s), Vec::<Value>::new());
    // The kernel's own address and the foreign link stay.
    let k = kernel.lock().unwrap();
    assert!(
        k.addresses
            .contains(&(n("ether2"), "fe80::1/64".parse().unwrap()))
    );
    assert!(
        k.addresses
            .contains(&(n("docker0"), "172.17.0.1/16".parse().unwrap()))
    );
    drop(k);
    // The config did not change; the journal has the reconcile.
    assert_eq!(s.store().current_revision(), rev);
    assert_eq!(s.store().running(), &running);
    assert_eq!(
        s.journal().last().unwrap().command,
        "config.drift.reconcile"
    );
}

#[test]
fn a_gone_port_is_reported_but_not_fixable() {
    let (mut s, kernel) = lab();
    {
        let mut k = kernel.lock().unwrap();
        k.links.remove(&n("ether1"));
        k.addresses
            .remove(&(n("ether1"), "10.0.0.2/24".parse().unwrap()));
        k.routes.clear();
        k.addresses
            .remove(&(n("ether2"), "192.168.88.1/24".parse().unwrap()));
    }
    let rows = drift(&mut s);
    assert_eq!(
        kinds(&rows),
        ["link-missing ether1", "address-missing 192.168.88.1/24"]
    );
    assert_eq!(rows[0]["fixable"], false);
    let r = ok(&mut s, "config.drift.reconcile", json!({}));
    assert_eq!(r["fixed"], 1);
    assert_eq!(
        kinds(r["remaining"].as_array().unwrap()),
        ["link-missing ether1"]
    );
}

#[test]
fn only_the_running_config_counts() {
    let (mut s, _) = lab();
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "172.16.0.1/24", "interface": "ether4"}),
    );
    assert_eq!(s.mode(), CommitMode::Transactional);
    assert_eq!(drift(&mut s), Vec::<Value>::new());
}

#[test]
fn reconcile_does_not_cut_the_callers_connection() {
    let (mut s, kernel) = lab();
    // Added by hand (outside the config) to reach the router.
    kernel
        .lock()
        .unwrap()
        .addresses
        .insert((n("ether3"), "203.0.113.1/24".parse().unwrap()));
    let who = Caller::new(9, "tls 198.51.100.7")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "198.51.100.7:50123".parse().unwrap(),
            local: "203.0.113.1:8729".parse().unwrap(),
        });
    let err = s
        .execute_as(&who, "config.drift.reconcile", &json!({}))
        .unwrap_err();
    assert!(matches!(err, EngineError::BadParam { .. }), "{err:?}");
    assert!(err.to_string().contains("ip.address.add"), "{err}");
    assert_eq!(drift(&mut s).len(), 1, "nothing was removed");

    let r = s
        .execute_as(&who, "config.drift.reconcile", &json!({"force": true}))
        .unwrap();
    assert_eq!(r["fixed"], 1);
}

#[test]
fn bad_params_are_refused() {
    let (mut s, _) = lab();
    let err = s
        .execute("config.drift.reconcile", &json!({"force": "yes"}))
        .unwrap_err();
    assert!(err.to_string().contains("force"), "{err}");
    let err = s
        .execute("config.drift.list", &json!({"interface": "ether1"}))
        .unwrap_err();
    assert!(err.to_string().contains("interface"), "{err}");
}

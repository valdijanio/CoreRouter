//! G1.14 — commands that need a backend feature are disabled, with the
//! reason, when the backend lacks it (here: a kernel without VRF).
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
use corerouter_hal::{Features, Hal, HalError, LinkInfo, LinkState, NO_VRF, VirtualHal};
use corerouter_model::Config;
use serde_json::{Value, json};

/// The virtual lab on a "kernel" without CONFIG_NET_VRF.
struct NoVrf(VirtualHal);

impl Hal for NoVrf {
    fn describe(&self) -> String {
        "virtual lab without vrf".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn features(&self) -> Features {
        Features {
            vrf: false,
            mpls: false,
        }
    }
}

/// `list_commands` entry of `id`.
fn entry(s: &Session, id: &str) -> Value {
    s.list()
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} not registered"))
}

#[test]
fn vrf_add_is_disabled_without_kernel_vrf() {
    let mut s = Session::new(Box::new(NoVrf(VirtualHal::new(2))));
    let before = s.store().candidate().clone();
    let rev = s.store().current_revision();

    let err = s
        .execute(
            "ip.vrf.add",
            &json!({"name": "blue", "interfaces": "ether2"}),
        )
        .unwrap_err();
    match &err {
        EngineError::Disabled { id, reason } => {
            assert_eq!(id, "ip.vrf.add");
            assert_eq!(reason, NO_VRF);
        }
        other => panic!("expected Disabled, got {other:?}"),
    }
    assert!(err.to_string().contains("CONFIG_NET_VRF"), "{err}");
    assert_eq!(s.store().candidate(), &before, "nothing may change");
    assert_eq!(s.store().current_revision(), rev);

    // Menus and agents see it greyed out, with the reason.
    let e = entry(&s, "ip.vrf.add");
    assert_eq!(e["enabled"], false);
    assert_eq!(e["disabledReason"], NO_VRF);

    // The rest still works: listing VRFs, routes in main, other interfaces.
    assert_eq!(s.execute("ip.vrf.list", &json!({})).unwrap(), json!([]));
    s.execute(
        "interface.vlan.add",
        &json!({"name": "v10", "parent": "ether1", "vlan_id": 10}),
    )
    .unwrap();
}

#[test]
fn vrf_add_is_enabled_where_the_backend_has_vrf() {
    let mut s = Session::virtual_lab();
    let e = entry(&s, "ip.vrf.add");
    assert_eq!(e["enabled"], true);
    assert!(e["disabledReason"].is_null());
    let out = s.execute("ip.vrf.add", &json!({"name": "blue"})).unwrap();
    assert_eq!(out["name"], "blue");
}

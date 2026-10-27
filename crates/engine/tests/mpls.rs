//! G3.5 — /mpls: settings, interfaces, static LSPs, LDP (instance,
//! interfaces, neighbors) and the forwarding table: success, validation
//! errors, rollback, and the commands greyed out without kernel MPLS.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::net::Ipv4Addr;

use corerouter_engine::{EngineError, Session};
use corerouter_hal::mpls::NO_MPLS;
use corerouter_hal::{Features, Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use corerouter_model::mpls_state::{
    IgpSyncState, LdpBinding, LdpInterfaceState, LdpNeighborState, LdpState, RemoteLabel,
};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, gave {v}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn static_lsps_need_labels_outside_the_dynamic_range() {
    let mut s = Session::virtual_lab();
    let e = err(&mut s, "mpls.static.add", json!({"label": 1000, "nexthop": "10.0.0.2"}));
    assert!(e.contains("inside the dynamic range 16-1048575"), "{e}");
    ok(&mut s, "mpls.settings.set", json!({"dynamic_label_range": "16-99999", "propagate_ttl": false}));
    let st = ok(&mut s, "mpls.settings.get", json!({}));
    assert_eq!(st["dynamic_label_range"], "16-99999");
    assert_eq!(st["platform_labels"], 100_000);
    assert_eq!(st["available"], true);
    ok(&mut s, "mpls.static.add", json!({"label": 100_000, "nexthop": "10.0.0.2", "interface": "ether1", "out_labels": "200 300"}));
    ok(&mut s, "mpls.static.add", json!({"label": 100_001, "nexthop": "10.0.0.3", "out_labels": "implicit-null"}));
    // RFC 3032 §2.1: 3 never goes on the wire; a reserved incoming label.
    assert!(err(&mut s, "mpls.static.add", json!({"label": 100_002, "nexthop": "10.0.0.2", "out_labels": [3]})).contains("implicit NULL"));
    assert!(err(&mut s, "mpls.static.add", json!({"label": 7, "nexthop": "10.0.0.2"})).contains("reserved"));
    assert!(err(&mut s, "mpls.static.add", json!({"label": 100_000, "nexthop": "10.0.0.2"})).contains("already"));
    assert!(err(&mut s, "mpls.static.add", json!({"label": 100_003, "nexthop": "10.0.0.2", "interface": "nope9"})).contains("no interface"));
    let l = ok(&mut s, "mpls.static.list", json!({}));
    assert_eq!(l[0]["out_label"], "200 300");
    assert_eq!(l[1]["out_label"], "implicit-null (pop)");
    // The lab's kernel holds them: the forwarding table lists them.
    let page = ok(&mut s, "mpls.forwarding-table.page", json!({}));
    assert_eq!(page["total"], 2, "{page}");
    assert_eq!(page["rows"][0]["in_label"], 100_000);
    assert_eq!(page["rows"][0]["origin"], "static");
    assert_eq!(page["rows"][0]["interface"], "ether1");
    assert_eq!(page["summary"]["labels"], 2);
    assert_eq!(page["ldp"]["running"], false);
    let found = ok(&mut s, "mpls.forwarding-table.page", json!({"find": "10.0.0.3"}));
    assert_eq!(found["total"], 1);
    ok(&mut s, "mpls.static.set", json!({"id": "100001", "disabled": true}));
    assert_eq!(ok(&mut s, "mpls.forwarding-table.page", json!({}))["total"], 1);
    ok(&mut s, "mpls.static.remove", json!({"id": 100_000}));
    assert!(err(&mut s, "mpls.static.remove", json!({"id": 100_000})).contains("no static entry"));
}

#[test]
fn a_failed_batch_leaves_nothing() {
    let mut s = Session::virtual_lab();
    let before = s.store().running().clone();
    let e = s
        .batch(
            &json!([
                {"command": "mpls.ldp.add", "params": {"lsr_id": "10.255.0.1"}},
                {"command": "mpls.ldp.interface.add", "params": {"interface": "ether1"}},
                {"command": "mpls.ldp.interface.add", "params": {"interface": "ether2", "hello_interval": 20, "hold_time": 15}},
            ]),
            true,
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("RFC 5036"), "{e}");
    assert_eq!(s.store().running(), &before);
    assert_eq!(ok(&mut s, "mpls.ldp.list", json!({})), json!([]));
}

#[test]
fn ldp_instance_interfaces_and_neighbors() {
    let mut s = Session::virtual_lab();
    ok(&mut s, "mpls.ldp.add", json!({"lsr_id": "10.255.0.1"}));
    assert!(err(&mut s, "mpls.ldp.add", json!({"lsr_id": "10.255.0.1"})).contains("already"));
    // IPv6 needs a global transport address (RFC 7552 §6.1): the commit
    // refuses, the instance stays IPv4.
    assert!(err(&mut s, "mpls.ldp.set", json!({"afi": "ip,ipv6"})).contains("RFC 7552"));
    ok(&mut s, "mpls.ldp.set", json!({"afi": ["ip", "ipv6"], "transport_addresses": "2001:db8::1", "igp_sync_holddown": 60}));
    let l = ok(&mut s, "mpls.ldp.list", json!({}));
    assert_eq!(l[0]["afi"], json!(["ip", "ipv6"]));
    assert_eq!(l[0]["transport_ipv4"], "10.255.0.1");
    assert_eq!(l[0]["igp_sync"], true);
    assert_eq!(l[0]["gtsm"], true);
    assert_eq!(l[0]["state"], "no daemon");
    ok(&mut s, "mpls.ldp.interface.add", json!({"interface": "ether1"}));
    assert!(err(&mut s, "mpls.ldp.interface.add", json!({"interface": "ether1"})).contains("already"));
    let i = ok(&mut s, "mpls.ldp.interface.list", json!({}));
    assert_eq!(i[0]["hello_interval"], 5);
    assert_eq!(i[0]["hold_time"], 15);
    // The lab's ports are 1500: one label does not fit a 1500-byte packet.
    assert_eq!(i[0]["mtu_warning"], "MTU 1500 < 1504: a 1500-byte IP packet with 1 label does not fit; raise the link MTU to 1504");
    ok(&mut s, "mpls.ldp.neighbor.add", json!({"lsr_id": "10.255.0.9", "targeted": "10.255.0.9", "password": "s3cret"}));
    // The password is sealed: never in the config in clear.
    let cfg = serde_json::to_string(s.store().running()).unwrap();
    assert!(!cfg.contains("s3cret"));
    let n = ok(&mut s, "mpls.ldp.neighbor.list", json!({}));
    assert_eq!(n[0]["password"], true);
    assert_eq!(n[0]["state"], "no daemon");
    assert!(err(&mut s, "mpls.ldp.neighbor.set", json!({"id": "10.0.0.77"})).contains("not configured"));
    ok(&mut s, "mpls.ldp.neighbor.set", json!({"id": "10.255.0.9", "password": ""}));
    assert_eq!(ok(&mut s, "mpls.ldp.neighbor.list", json!({}))[0]["password"], false);
    ok(&mut s, "mpls.ldp.remove", json!({}));
    assert_eq!(ok(&mut s, "mpls.ldp.list", json!({})), json!([]));
}

fn status() -> LdpState {
    let n = |id: [u8; 4]| LdpNeighborState {
        lsr_id: Ipv4Addr::from(id),
        afi: "ipv4".into(),
        state: "OPERATIONAL".into(),
        transport: None,
        uptime: Some("00:10:00".into()),
    };
    LdpState {
        neighbors: vec![n([10, 255, 0, 2])],
        interfaces: vec![LdpInterfaceState { name: "ether1".into(), afi: "ipv4".into(), state: "ACTIVE".into(), adjacencies: 1 }],
        bindings: vec![
            LdpBinding {
                prefix: "10.255.0.2/32".parse().unwrap(),
                local_label: Some(16),
                remote: vec![RemoteLabel { neighbor: Ipv4Addr::new(10, 255, 0, 2), label: 3, in_use: true }],
            },
            LdpBinding { prefix: "10.9.0.0/24".parse().unwrap(), local_label: Some(17), remote: vec![] },
        ],
        igp_sync: vec![IgpSyncState { interface: "ether1".into(), igp: "ospf".into(), achieved: false, holddown_left: Some(30) }],
    }
}

#[test]
fn the_lists_join_what_the_routing_daemon_reports() {
    let mut s = Session::virtual_lab();
    ok(&mut s, "mpls.ldp.add", json!({"lsr_id": "10.255.0.1"}));
    ok(&mut s, "mpls.ldp.interface.add", json!({"interface": "ether1"}));
    corerouter_engine::mpls::set_ldp(&mut s, Ok(Some(status())));
    let n = ok(&mut s, "mpls.ldp.neighbor.list", json!({}));
    assert_eq!(n[0]["dynamic"], true);
    assert_eq!(n[0]["operational"], true);
    assert_eq!(n[0]["labels"], 1);
    let i = ok(&mut s, "mpls.ldp.interface.list", json!({}));
    assert_eq!(i[0]["state"], "active");
    assert_eq!(i[0]["igp_sync"], "waiting");
    let page = ok(&mut s, "mpls.forwarding-table.page", json!({}));
    assert_eq!(page["summary"]["fecs"], 2, "{page}");
    assert_eq!(page["summary"]["unlabeled"], 1);
    let un = ok(&mut s, "mpls.forwarding-table.page", json!({"unlabeled": true}));
    assert_eq!(un["total"], 1);
    assert!(un["rows"][0]["reason"].as_str().unwrap().contains("no neighbor advertised"));
    assert_eq!(ok(&mut s, "mpls.ldp.list", json!({}))[0]["operational"], 1);
    assert!(err(&mut s, "mpls.forwarding-table.page", json!({"limit": 0})).contains("1..="));
}

/// The virtual lab on a kernel without `mpls_router`.
struct NoMpls(VirtualHal);

impl Hal for NoMpls {
    fn describe(&self) -> String {
        "virtual lab without mpls".into()
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
        Features { mpls: false, ..Features::default() }
    }
}

#[test]
fn without_kernel_mpls_the_adds_say_why() {
    let mut s = Session::new(Box::new(NoMpls(VirtualHal::new(2))));
    for (id, p) in [
        ("mpls.ldp.add", json!({"lsr_id": "10.255.0.1"})),
        ("mpls.static.add", json!({"label": 100, "nexthop": "10.0.0.2"})),
        ("mpls.interface.add", json!({"interface": "all"})),
    ] {
        match s.execute(id, &p).unwrap_err() {
            EngineError::Disabled { reason, .. } => assert_eq!(reason, NO_MPLS),
            other => panic!("{id}: expected Disabled, got {other:?}"),
        }
    }
    let page = ok(&mut s, "mpls.forwarding-table.page", json!({}));
    assert_eq!(page["available"], false);
    assert!(page["why"].as_str().unwrap().contains("mpls_router"));
}

#[test]
fn ip_routes_show_their_ldp_labels() {
    let mut s = Session::virtual_lab();
    ok(&mut s, "ip.address.add", json!({"address": "10.0.12.1/24", "interface": "ether1"}));
    ok(&mut s, "ip.route.add", json!({"dst_address": "10.255.0.3/32", "gateway": "10.0.12.2"}));
    let mut st = status();
    st.bindings.push(LdpBinding {
        prefix: "10.255.0.3/32".parse().unwrap(),
        local_label: Some(18),
        remote: vec![RemoteLabel { neighbor: Ipv4Addr::new(10, 255, 0, 2), label: 20, in_use: true }],
    });
    corerouter_engine::mpls::set_ldp(&mut s, Ok(Some(st)));
    for (id, rows) in [("ip.route.list", ok(&mut s, "ip.route.list", json!({}))), ("ip.route.page", ok(&mut s, "ip.route.page", json!({}))["rows"].clone())] {
        let r = rows.as_array().unwrap().iter().find(|r| r["dst_address"] == "10.255.0.3/32").unwrap_or_else(|| panic!("{id}: {rows}"));
        assert_eq!(r["mpls_out"], "20", "{id}");
        assert_eq!(r["mpls_in"], 18, "{id}");
    }
}

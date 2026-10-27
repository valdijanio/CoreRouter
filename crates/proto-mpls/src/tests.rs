//! Validation, the `ldpd` render and the forwarding-table view.
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::mpls::{MplsNexthop, MplsRoute, Origin};
use corerouter_model::mpls::{LdpInstance, LdpInterface, LdpNeighbor, StaticLsp};
use corerouter_model::mpls_state::{
    IgpSyncState, LdpBinding, LdpNeighborState, LdpState, RemoteLabel,
};
use corerouter_model::{Config, IfName, Interface, InterfaceKind};

use super::*;

fn name(s: &str) -> IfName {
    s.parse().unwrap()
}

fn base() -> Config {
    let mut c = Config::default();
    for n in ["ether1", "ether2", "lo"] {
        c.interfaces
            .insert(name(n), Interface::new(name(n), InterfaceKind::Ethernet));
    }
    let mpls = &mut c.routing.mpls;
    mpls.ldp = Some(LdpInstance::new(Ipv4Addr::new(10, 255, 0, 1)));
    mpls.ldp_interfaces.insert(name("ether1"), LdpInterface::default());
    c
}

fn paths(c: &Config) -> Vec<String> {
    validate(c).into_iter().map(|i| format!("{}: {}", i.path, i.message)).collect()
}

#[test]
fn a_plain_ldp_config_is_valid_and_renders_for_ldpd() {
    let c = base();
    assert!(paths(&c).is_empty(), "{:?}", paths(&c));
    let text = render_frr(&c.routing.mpls, &|_| None).unwrap();
    assert_eq!(
        text,
        "mpls ldp\n router-id 10.255.0.1\n address-family ipv4\n  discovery transport-address 10.255.0.1\n  interface ether1\n exit-address-family\n"
    );
    // RFC 5443 on by default: the IGP gets the sync lines.
    assert_eq!(igp_sync_lines(&c.routing.mpls), vec!["mpls ldp-sync".to_owned()]);
}

#[test]
fn ipv6_gtsm_password_and_targeted_neighbors() {
    let mut c = base();
    let l = c.routing.mpls.ldp.as_mut().unwrap();
    l.afi = vec![Afi::Ip, Afi::Ipv6];
    // RFC 7552 §6.1: IPv6 needs a global transport address.
    assert!(paths(&c).iter().any(|p| p.contains("RFC 7552")));
    let l = c.routing.mpls.ldp.as_mut().unwrap();
    l.transport_addresses = vec!["fe80::1".parse().unwrap()];
    assert!(paths(&c).iter().any(|p| p.contains("global unicast")));
    let l = c.routing.mpls.ldp.as_mut().unwrap();
    l.transport_addresses = vec!["2001:db8::1".parse().unwrap()];
    l.preferred_afi = Some(Afi::Ip);
    l.gtsm = false;
    l.igp_sync_holddown = Some(30);
    c.routing.mpls.ldp_neighbors.insert(
        Ipv4Addr::new(10, 255, 0, 9),
        LdpNeighbor {
            targeted: Some(IpAddr::from([10, 255, 0, 9])),
            password: Some("s3cret".into()),
            keepalive_hold: Some(90),
            disabled: false,
            comment: String::new(),
        },
    );
    assert!(paths(&c).is_empty(), "{:?}", paths(&c));
    let text = render_frr(&c.routing.mpls, &|k| Some(k.stored().to_owned())).unwrap();
    for line in [
        " dual-stack transport-connection prefer ipv4\n",
        " neighbor 10.255.0.9 password s3cret\n",
        " neighbor 10.255.0.9 session holdtime 90\n",
        "  ttl-security disable\n",
        "  neighbor 10.255.0.9 targeted\n",
        " address-family ipv6\n  discovery transport-address 2001:db8::1\n  interface ether1\n",
    ] {
        assert!(text.contains(line), "{line:?} not in\n{text}");
    }
    // GTSM is mandatory for IPv6 (RFC 7552 §9): never turned off there.
    assert_eq!(text.matches("ttl-security disable").count(), 1);
    assert_eq!(igp_sync_lines(&c.routing.mpls).len(), 2);
    // A key that does not open is a render error, not an empty password.
    assert!(render_frr(&c.routing.mpls, &|_| None).is_err());
}

#[test]
fn bad_values_are_refused_with_the_rule() {
    let mut c = base();
    c.routing.mpls.ldp_interfaces.insert(
        name("ether2"),
        LdpInterface {
            hello_interval: 15,
            hold_time: 15,
            ..LdpInterface::default()
        },
    );
    c.routing.mpls.ldp_interfaces.insert(name("nope"), LdpInterface::default());
    c.routing.mpls.statics.insert(
        5000,
        StaticLsp {
            nexthop: IpAddr::from([10, 0, 0, 2]),
            interface: None,
            out_labels: vec![3],
            disabled: false,
            comment: String::new(),
        },
    );
    let p = paths(&c);
    assert!(p.iter().any(|x| x.contains("RFC 5036 §3.5.2.1")), "{p:?}");
    assert!(p.iter().any(|x| x.contains("no interface 'nope'")), "{p:?}");
    // In the dynamic range, and 3 out: both said.
    assert!(p.iter().any(|x| x.contains("inside the dynamic range")), "{p:?}");
    assert!(p.iter().any(|x| x.contains("outgoing label 3")), "{p:?}");
    c.routing.mpls.settings.dynamic_label_range = (16, 4999);
    let p = paths(&c);
    assert!(!p.iter().any(|x| x.contains("inside the dynamic range")), "{p:?}");
    // The range then reaches zebra, so LDP never takes a static label.
    assert!(render_frr(&c.routing.mpls, &|_| None).unwrap().starts_with("mpls label dynamic-block 16 4999\n"));
    c.routing.mpls.settings.dynamic_label_range = (3, 10);
    assert!(paths(&c).iter().any(|x| x.contains("reserved")));
}

#[test]
fn a_disabled_instance_renders_nothing() {
    let mut c = base();
    c.routing.mpls.ldp.as_mut().unwrap().disabled = true;
    assert_eq!(render_frr(&c.routing.mpls, &|_| None).unwrap(), "");
    assert!(igp_sync_lines(&c.routing.mpls).is_empty());
}

fn nbr(id: [u8; 4], up: bool) -> LdpNeighborState {
    LdpNeighborState {
        lsr_id: Ipv4Addr::from(id),
        afi: "ipv4".into(),
        state: if up { "OPERATIONAL" } else { "OPENSENT" }.into(),
        transport: None,
        uptime: None,
    }
}

fn binding(p: &str, local: Option<u32>, remote: &[([u8; 4], u32, bool)]) -> LdpBinding {
    LdpBinding {
        prefix: p.parse().unwrap(),
        local_label: local,
        remote: remote
            .iter()
            .map(|(n, l, u)| RemoteLabel {
                neighbor: Ipv4Addr::from(*n),
                label: *l,
                in_use: *u,
            })
            .collect(),
    }
}

#[test]
fn every_fec_without_a_label_says_why() {
    let st = LdpState {
        neighbors: vec![nbr([10, 255, 0, 2], true)],
        interfaces: vec![],
        bindings: vec![
            binding("10.255.0.2/32", Some(16), &[([10, 255, 0, 2], 3, true)]),
            binding("10.255.0.3/32", Some(17), &[([10, 255, 0, 2], 20, true)]),
            binding("10.255.0.1/32", Some(3), &[]),
            binding("10.9.0.0/24", Some(18), &[]),
            binding("10.8.0.0/24", Some(19), &[([10, 255, 0, 2], 21, false)]),
        ],
        igp_sync: vec![IgpSyncState {
            interface: "ether1".into(),
            igp: "ospf".into(),
            achieved: true,
            holddown_left: None,
        }],
    };
    let route = |label, out: &[u32]| MplsRoute {
        label,
        origin: Origin::Ldp,
        nexthops: vec![MplsNexthop {
            via: Some(IpAddr::from([10, 0, 12, 2])),
            interface: Some(name("ether1")),
            out_labels: out.to_vec(),
        }],
    };
    let kernel = vec![route(16, &[]), route(17, &[20]), route(9000, &[30])];
    let c = base();
    let rows = forwarding_rows(&c.routing.mpls, Some(&st), &kernel, &|_| Some(1500));
    let row = |fec: &str| rows.iter().find(|r| r.fec.as_deref() == Some(fec)).unwrap();
    // PHP: the neighbor advertised implicit NULL, we pop.
    assert_eq!(row("10.255.0.2/32").out_label, "implicit-null (pop)");
    assert_eq!(row("10.255.0.2/32").reason, None);
    assert_eq!(row("10.255.0.2/32").igp_sync.as_deref(), Some("achieved"));
    assert_eq!(row("10.255.0.2/32").mtu, None, "popped: plain IP leaves");
    assert_eq!(row("10.255.0.3/32").out_label, "20");
    // MTU 1500 < 1504 for a 1500-byte packet with one label (the mockup).
    assert_eq!(
        row("10.255.0.3/32").mtu.as_deref(),
        Some("MTU 1500 < 1504: a 1500-byte IP packet with 1 label does not fit; raise the link MTU to 1504")
    );
    assert!(row("10.255.0.1/32").reason.as_deref().unwrap().starts_with("egress"));
    assert!(row("10.9.0.0/24").reason.as_deref().unwrap().contains("no neighbor advertised"));
    assert!(row("10.8.0.0/24").reason.as_deref().unwrap().contains("none is the IGP next hop"));
    // The kernel entry no FEC explains is listed too.
    let other: Vec<_> = rows.iter().filter(|r| r.fec.is_none()).collect();
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].in_label, Some(9000));
    // Every neighbor down: said so.
    let down = LdpState {
        neighbors: vec![nbr([10, 255, 0, 2], false)],
        ..st.clone()
    };
    let rows = forwarding_rows(&c.routing.mpls, Some(&down), &[], &|_| Some(9000));
    assert!(rows.iter().find(|r| r.fec.as_deref() == Some("10.9.0.0/24")).unwrap().reason.as_deref().unwrap().contains("no LDP neighbor is operational"));
}

#[test]
fn mtu_warning_counts_four_bytes_per_label() {
    assert_eq!(mtu_warning(1500, 0, 1504), None);
    assert_eq!(mtu_warning(1500, 2, 1508), None);
    assert!(mtu_warning(1500, 2, 1507).unwrap().starts_with("MTU 1507 < 1508"));
}

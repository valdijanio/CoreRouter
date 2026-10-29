//! G3.9ha — the Router Advertisement plan at scale: what the `router-advertisement`
//! thread costs under the session lock once a second
//! ([`corerouter_engine::ipv6_nd::plan`]). 100 and 1000 VLAN interfaces,
//! each with a global /64 and an IPv6 default route out of the WAN, under
//! `interface=all` (every interface is looked at, the WAN skipped).
//!
//! `cargo bench -p corerouter-engine --bench ipv6_nd`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_engine::ipv6_nd::plan;
use corerouter_model::config::AddressEntry;
use corerouter_model::ipv6_nd::NdInterface;
use corerouter_model::{Config, Gateway, Interface, InterfaceKind, RouteEntry, RoutingTable};
use criterion::{Criterion, criterion_group, criterion_main};

fn config(n: u16) -> Config {
    let mut cfg = Config::default();
    let port = |name: String, kind| Interface {
        name: name.parse().unwrap(),
        kind,
        mtu: 1500,
        disabled: false,
        mac: None,
        comment: String::new(),
        bridge: None,
        vrf: None,
        bond: None,
        ethernet: Default::default(),
    };
    cfg.interfaces.insert(
        "ether1".parse().unwrap(),
        port("ether1".into(), InterfaceKind::Ethernet),
    );
    cfg.interfaces.insert(
        "ether2".parse().unwrap(),
        port("ether2".into(), InterfaceKind::Ethernet),
    );
    let wan = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id: wan,
        address: "2001:db8:ffff::2/64".parse().unwrap(),
        interface: "ether1".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    let rid = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id: rid,
        dst_address: "::/0".parse().unwrap(),
        gateway: "2001:db8:ffff::1".parse::<Gateway>().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
    for v in 1..=n {
        let name = format!("vlan{v}");
        cfg.interfaces.insert(
            name.parse().unwrap(),
            port(
                name.clone(),
                InterfaceKind::Vlan {
                    parent: "ether2".parse().unwrap(),
                    vlan_id: corerouter_model::VlanId::new(v).unwrap(),
                    service_tag: false,
                },
            ),
        );
        let id = cfg.ip.next_address_id();
        cfg.ip.addresses.push(AddressEntry {
            id,
            address: format!("2001:db8:{v:x}::1/64").parse().unwrap(),
            interface: name.parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let id = cfg.ipv6.nd.next_id();
    cfg.ipv6
        .nd
        .interfaces
        .push(NdInterface::new(id, "all".parse().unwrap()));
    cfg
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("ipv6_nd");
    for n in [100u16, 1000] {
        let cfg = config(n);
        assert_eq!(plan(&cfg).adverts.len(), usize::from(n));
        g.bench_function(format!("plan_all_{n}"), |b| {
            b.iter(|| plan(black_box(&cfg)))
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

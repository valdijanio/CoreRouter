//! Hooks for the benchmarks (`benches/`): sessions over configs no command
//! path would build in reasonable time — a full BGP-sized table of a
//! million routes (G1.27c) does not fit the saved config (32 MB budget)
//! and belongs to a routing protocol's table, not to static routes. Not
//! part of the API.

#![doc(hidden)]

use corerouter_model::{
    AddressEntry, Config, ConfigStore, Gateway, ItemId, RouteEntry, RoutingTable,
};
use ipnet::IpNet;

use crate::Session;

/// The virtual lab with `cfg` as its running (and candidate) config, put
/// in place without validating, saving or applying it.
pub fn with_running(cfg: Config) -> Session {
    let mut s = Session::virtual_lab();
    *s.store_mut() = ConfigStore::new(cfg);
    s
}

fn address(cfg: &mut Config, a: &str) {
    let id = cfg.ip.next_address_id();
    if let (Ok(address), Ok(interface)) = (a.parse(), "ether1".parse()) {
        cfg.ip.addresses.push(AddressEntry {
            id,
            address,
            interface,
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
}

/// The lab with a BGP-sized table of `n` routes through 192.0.2.254 /
/// 2001:db8::1 on ether1: IPv4 /24s from 11.0.0.0 up, a /16 every 256
/// routes, an IPv6 /48 every 20.
pub fn full_table(n: usize) -> Config {
    let mut cfg = Session::virtual_lab().store().running().clone();
    address(&mut cfg, "192.0.2.1/24");
    address(&mut cfg, "2001:db8::2/64");
    let v4 = Gateway::ip(std::net::IpAddr::from([192, 0, 2, 254]));
    let v6 = Gateway::ip(std::net::IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1u16]));
    let mut routes = Vec::with_capacity(n);
    for i in 0..n {
        let k = u32::try_from(i).unwrap_or(u32::MAX);
        let (dst, gateway) = if i % 20 == 0 {
            let a = std::net::Ipv6Addr::new(0x2a00, (k >> 16) as u16, (k & 0xffff) as u16, 0, 0, 0, 0, 0);
            (IpNet::new(a.into(), 48), v6.clone())
        } else if i % 256 == 1 {
            let a = std::net::Ipv4Addr::new(11u8.wrapping_add((k >> 16) as u8), (k >> 8) as u8, 0, 0);
            (IpNet::new(a.into(), 16), v4.clone())
        } else {
            let a = std::net::Ipv4Addr::from(0x0B00_0000u32.wrapping_add(k.wrapping_mul(256)));
            (IpNet::new(a.into(), 24), v4.clone())
        };
        let Ok(dst_address) = dst else { continue };
        routes.push(RouteEntry {
            id: ItemId(k.wrapping_add(1)),
            dst_address,
            gateway,
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
    }
    cfg.ip.routes = routes.into();
    cfg.ip.next_route_id = u32::try_from(n).unwrap_or(u32::MAX).wrapping_add(1);
    cfg
}

/// G3.4n: a session as the daemon's FRR poll leaves it on a large OSPF
/// network: `ifaces` VLANs with addresses in one area (templates by name,
/// `ifaces / 40` of them), a routing backend that only says yes, the last
/// poll holding `nbrs` neighbors and `ifaces` OSPF interfaces, and instance
/// `v2`'s LSDB read: `routers` router LSAs (4 point-to-point links and a
/// stub each), `routers / 4` network LSAs, externals up to `lsas` in all,
/// and `routes` OSPF routes (two next hops each).
pub fn ospf_scale(ifaces: u32, nbrs: u32, routers: u32, lsas: u32, routes: u32) -> Session {
    use corerouter_model::ospf::{AreaId, AreaType, NssaTranslate, OspfArea, OspfInstance, OspfTemplate};
    use corerouter_model::ospf_state::{Link, Lsa, Lsdb, OspfIfState, OspfNeighbor, OspfRoute};
    use corerouter_model::routing_state::RoutingStatus;

    let mut cfg = Session::virtual_lab().store().running().clone();
    let mut names = Vec::new();
    for i in 0..ifaces {
        let name = format!("vlan{i}");
        let Ok(iface) = serde_json::from_value::<corerouter_model::config::Interface>(
            serde_json::json!({"name": name, "kind": {"type": "ethernet"}}),
        ) else {
            continue;
        };
        let Ok(key) = name.parse() else { continue };
        cfg.interfaces.insert(key, iface);
        address(&mut cfg, &format!("10.{}.{}.{}/30", 128 + i / 16_384, (i / 64) % 256, (i % 64) * 4 + 1));
        if let Some(a) = cfg.ip.addresses.last_mut()
            && let Ok(n) = name.parse()
        {
            a.interface = n;
        }
        names.push(name);
    }
    let o = &mut cfg.routing.ospf;
    o.instances.insert(
        "v2".into(),
        OspfInstance {
            name: "v2".into(),
            version: Default::default(),
            vrf: "main".into(),
            router_id: Some([10, 1, 0, 0].into()),
            redistribute: Vec::new(),
            out_filter_chain: None,
            originate_default: Default::default(),
            subscriber_pools: false,
            stub_router: false,
            stub_router_on_startup: None,
            max_lsa: None,
            disabled: false,
            comment: String::new(),
        },
    );
    o.areas.insert(
        "bb".into(),
        OspfArea {
            name: "bb".into(),
            instance: "v2".into(),
            area_id: AreaId(0),
            kind: AreaType::Default,
            no_summaries: false,
            default_cost: None,
            nssa_translate: NssaTranslate::Candidate,
            disabled: false,
            comment: String::new(),
        },
    );
    for chunk in names.chunks(40) {
        let id = o.next_id();
        let interfaces = chunk.to_vec();
        o.templates.push(OspfTemplate { id, area: "bb".into(), cost: Some(10), interfaces, ..OspfTemplate::default() });
    }
    let mut s = with_running(cfg);
    let _ = s.attach_routing(Box::new(YesDaemon));
    let rid = |i: u32| 0x0A01_0000u32.wrapping_add(i);
    let ip = |i: u32| std::net::Ipv4Addr::from(i).to_string();
    let neighbors = (0..nbrs)
        .map(|i| OspfNeighbor {
            instance: "v2".into(),
            version: 2,
            router_id: ip(rid(i + 1)),
            address: ip(0x0A80_0002 + i * 4),
            interface: format!("vlan{i}"),
            area: Some("0.0.0.0".into()),
            state: "Full".into(),
            role: "DR".into(),
            priority: Some(1),
            state_secs: Some(93_784),
            dead_secs: Some(35),
            ..OspfNeighbor::default()
        })
        .collect();
    let interfaces = (0..ifaces)
        .map(|i| OspfIfState {
            instance: "v2".into(),
            version: 2,
            interface: format!("vlan{i}"),
            area: Some("0.0.0.0".into()),
            network_type: Some("BROADCAST".into()),
            state: Some("DROther".into()),
            address: Some(format!("{}/30", ip(0x0A80_0001 + i * 4))),
            cost: Some(10),
            mtu: Some(1500),
            mtu_mismatch_detection: Some(true),
            hello: Some(10),
            dead: Some(40),
            dr: Some(ip(rid(i + 1))),
            bdr: Some("10.1.0.0".into()),
            passive: false,
            neighbors: 1,
            adjacent: 1,
        })
        .collect();
    s.set_routing_status(RoutingStatus { ospf_neighbors: neighbors, ospf_interfaces: interfaces, ..RoutingStatus::default() });
    let mut db = Lsdb { version: 2, router_id: Some(rid(0)), ..Lsdb::default() };
    for r in 0..routers {
        let start = u32::try_from(db.links.len()).unwrap_or(u32::MAX);
        for k in 0..4 {
            db.links.push(Link { kind: 1, id: rid((r + k + 1) % routers.max(1)), data: 0x0A80_0001 + r * 4, metric: 10 + (k as u16) });
        }
        db.links.push(Link { kind: 3, id: 0x0AC0_0000 + r * 4, data: 0xFFFF_FFFC, metric: 10 });
        db.lsas.push(Lsa { kind: 1, area: 0, id: rid(r), adv: rid(r), age: 100, seq: 0x8000_0003, link_start: start, link_count: 5, flags: u8::from(r % 50 == 0) * 3, ..Lsa::default() });
    }
    for n in 0..routers / 4 {
        let start = u32::try_from(db.attached.len()).unwrap_or(u32::MAX);
        db.attached.extend([rid(n), rid(n + 1)]);
        db.lsas.push(Lsa { kind: 2, area: 0, id: 0x0AE0_0001 + n * 256, adv: rid(n), age: 5, seq: 0x8000_0002, link_start: start, link_count: 2, flags: 24, plen: 24, ..Lsa::default() });
    }
    let mut e = 0u32;
    while u32::try_from(db.lsas.len()).unwrap_or(u32::MAX) < lsas {
        db.lsas.push(Lsa { kind: 5, area: u32::MAX, id: 0x1400_0000 + e * 256, adv: rid(e % routers.max(1)), age: 1, seq: 0x8000_0001, metric: 20 | 1 << 31, plen: 24, ..Lsa::default() });
        e += 1;
    }
    let routes = (0..routes)
        .map(|i| OspfRoute {
            instance: "v2".into(),
            prefix: format!("{}/24", ip(0x1400_0000 + i * 256)),
            kind: if i % 3 == 2 { "ext-2" } else { "intra-area" }.into(),
            cost: 20,
            type2_cost: (i % 3 == 2).then_some(1),
            area: (i % 3 != 2).then(|| "0.0.0.0".into()),
            nexthops: vec![
                (Some(ip(0x0A80_0002 + (i % 500) * 4)), format!("vlan{}", i % 500)),
                (Some(ip(0x0A80_0006 + (i % 500) * 4)), format!("vlan{}", (i + 1) % 500)),
            ],
            fast_reroute: None,
        })
        .collect();
    s.set_ospf_db("v2".into(), Ok((db, routes)));
    s
}

/// A routing backend that takes every commit and reads nothing.
struct YesDaemon;

impl corerouter_hal::routing::RoutingDaemon for YesDaemon {
    fn describe(&self) -> String {
        "bench".into()
    }
    fn apply(&mut self, _: &Config, _: &Config) -> std::result::Result<(), corerouter_hal::HalError> {
        Ok(())
    }
    fn reader(&self) -> Box<dyn corerouter_hal::routing::RoutingReader> {
        Box::new(YesDaemon)
    }
}

impl corerouter_hal::routing::RoutingReader for YesDaemon {
    fn bgp_sessions(
        &mut self,
        _: &Config,
    ) -> std::result::Result<Vec<corerouter_model::routing_state::BgpSession>, corerouter_hal::HalError> {
        Ok(Vec::new())
    }
    fn version(&mut self) -> std::result::Result<String, corerouter_hal::HalError> {
        Ok("bench".into())
    }
}

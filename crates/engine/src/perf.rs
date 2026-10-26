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
        });
    }
    cfg.ip.routes = routes.into();
    cfg.ip.next_route_id = u32::try_from(n).unwrap_or(u32::MAX).wrapping_add(1);
    cfg
}

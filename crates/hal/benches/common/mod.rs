//! Configs with N addresses, routes or filter rules for the apply benchmarks.
//! Shared by `hal/benches/apply.rs` (VirtualHal) and
//! `hal-linux/benches/netns_apply.rs` (netlink + nftables), which includes this
//! file by `#[path]`, so both measure the very same change.

use std::net::Ipv4Addr;

use corerouter_firewall::sample;
use corerouter_model::firewall::Action;
use corerouter_model::{
    AddressEntry, Config, Gateway, IfName, Interface, InterfaceKind, RouteEntry, RoutingTable,
};

/// The N of every "apply N items" benchmark.
pub const SIZES: [usize; 2] = [100, 1000];

/// Address of the port the routes go through (their gateway is `.254`).
pub const PORT_NET: &str = "192.0.2.1/24";

pub fn name(s: &str) -> IfName {
    s.parse().unwrap()
}

/// A config with one managed Ethernet port `port` holding [`PORT_NET`].
pub fn base(port: &str) -> Config {
    let mut cfg = Config::default();
    cfg.interfaces.insert(
        name(port),
        Interface::new(name(port), InterfaceKind::Ethernet),
    );
    push_address(&mut cfg, port, PORT_NET);
    cfg
}

fn push_address(cfg: &mut Config, port: &str, a: &str) {
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: a.parse().unwrap(),
        interface: name(port),
        disabled: false,
        comment: String::new(),
    });
}

/// The i-th of up to 65 536 distinct addresses inside 10.1.0.0/16.
fn host(i: usize) -> Ipv4Addr {
    let i = u16::try_from(i).unwrap();
    let [hi, lo] = i.to_be_bytes();
    Ipv4Addr::new(10, 1, hi, lo)
}

/// `base` plus `n` /32 addresses on `port`.
pub fn addresses(base: &Config, port: &str, n: usize) -> Config {
    let mut cfg = base.clone();
    for i in 0..n {
        push_address(&mut cfg, port, &format!("{}/32", host(i)));
    }
    cfg
}

/// `base` plus `n` static /24 routes (inside 172.16.0.0/12) via 192.0.2.254.
pub fn routes(base: &Config, n: usize) -> Config {
    let mut cfg = base.clone();
    for i in 0..n {
        let i = u16::try_from(i).unwrap();
        let [hi, lo] = i.to_be_bytes();
        let id = cfg.ip.next_route_id();
        cfg.ip.routes.push(RouteEntry {
            id,
            dst_address: format!("172.{}.{lo}.0/24", 16 + hi).parse().unwrap(),
            gateway: Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        });
    }
    cfg
}

/// `base` plus `n` forward rules (drop one source address each), the shape of
/// a long hand-written block list.
pub fn filter_rules(base: &Config, n: usize) -> Config {
    let mut cfg = base.clone();
    for i in 0..n {
        let src = host(i).to_string();
        let id = u32::try_from(i + 1).unwrap();
        let rule = sample::rule(
            id,
            "forward",
            sample::m(&[("src_address", src.as_str()), ("protocol", "tcp")]).unwrap(),
            Action::Drop,
        )
        .unwrap();
        cfg.ip.firewall.filter.push(rule);
    }
    cfg
}

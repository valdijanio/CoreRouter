//! G0.31e — the data plane's side of a commit that adds one static route
//! to 60 000: the plan (`plan::plan`) and the routes that are CoreRouter's
//! (`plan::owned_routes`, what the executor may merge into an ECMP group).
//! No kernel: what the commit computes before it talks to netlink.
//!
//! ```sh
//! cargo bench -p corerouter-hal-linux --bench route_plan
//! ```

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_hal_linux::plan;
use corerouter_model::{AddressEntry, Config, Interface, InterfaceKind, RouteEntry, RoutingTable};
use criterion::{Criterion, criterion_group, criterion_main};

/// Static routes in place (the G0.31 audit's table).
const N: usize = 60_000;

fn route(cfg: &mut Config, i: usize) {
    let id = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id,
        dst_address: format!("{}.{}.{}.0/24", 10 + i / 65_536, (i / 256) % 256, i % 256)
            .parse()
            .unwrap(),
        gateway: "192.168.88.254".parse().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
}

fn table() -> Config {
    let mut c = Config::default();
    let ether1 = "ether1".parse().unwrap();
    c.interfaces.insert(
        "ether1".parse().unwrap(),
        Interface::new(ether1, InterfaceKind::Ethernet),
    );
    let id = c.ip.next_address_id();
    c.ip.addresses.push(AddressEntry {
        id,
        address: "192.168.88.1/24".parse().unwrap(),
        interface: "ether1".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    for i in 0..N {
        route(&mut c, i);
    }
    c
}

fn bench(c: &mut Criterion) {
    let from = table();
    let mut to = from.clone();
    route(&mut to, N);
    let ops = plan::plan(&from, &to).unwrap();
    assert_eq!(ops.len(), 1, "one route to add: {ops:?}");
    let mut g = c.benchmark_group("route_plan");
    g.bench_function("plan/one_more", |b| {
        b.iter(|| plan::plan(black_box(&from), black_box(&to)).unwrap());
    });
    g.bench_function("owned/one_more", |b| {
        b.iter(|| plan::owned_routes(black_box(&from), black_box(&to), black_box(&ops)));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

//! G1.27f — check-gateway at scale, the engine's side: what the
//! `route-check` thread costs while it holds the session lock and between
//! locks. 1 000 and 10 000 gateways (one /24 behind each, plus 4 routes
//! per gateway for the grouping):
//!
//! - `targets`: taking the targets (routes → targets, under the lock),
//!   when the config changed; `sync-unchanged`: the sync once a second
//!   when it did not;
//! - `report`: a tick's results handed to the engine (under the lock):
//!   every gateway answering, and every gateway down at once (one apply
//!   of the whole change);
//! - `schedule`: one interval of `Schedule::due` + `echo` at 20 ms ticks
//!   (the thread's own work, no lock).
//!
//! `cargo bench -p corerouter-engine --bench gateway_check`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use corerouter_engine::Session;
use corerouter_engine::gateway_check::{ProbeTarget, Schedule, Target};
use corerouter_model::dhcp_client::CheckGateway;
use corerouter_model::{AddressEntry, Gateway, RouteEntry, RoutingTable};
use criterion::{Criterion, criterion_group, criterion_main};
use ipnet::IpNet;

/// A lab with `n` gateways in 10.64.0.0/10 on ether1, each with 4 routes
/// (half ping, half arp), put in place directly (validating 40 000
/// `ip.route.add` one by one is another benchmark).
fn lab(n: u32) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: "10.64.0.1/10".parse().unwrap(),
        interface: "ether1".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    for i in 0..n {
        let gw = Gateway::ip(IpAddr::V4(Ipv4Addr::from(0x0a40_0100 + i)));
        for k in 0..4u32 {
            let dst = Ipv4Addr::from(0xac00_0000 + (i * 4 + k) * 256);
            let id = cfg.ip.next_route_id();
            cfg.ip.routes.push(RouteEntry {
                id,
                dst_address: IpNet::new(IpAddr::V4(dst), 24).unwrap(),
                gateway: gw.clone(),
                distance: 1,
                routing_table: RoutingTable::Main,
                disabled: false,
                comment: String::new(),
                check_gateway: if i % 2 == 0 {
                    CheckGateway::Ping
                } else {
                    CheckGateway::Arp
                },
                bfd_profile: String::new(),
            });
        }
    }
    corerouter_engine::perf::with_running(cfg)
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("gateway_check");
    g.sample_size(10).measurement_time(Duration::from_secs(5));
    for n in [1_000u32, 10_000] {
        let mut s = lab(n);
        let targets: Vec<ProbeTarget> = s.route_check_targets(Some(0));
        assert_eq!(targets.len(), n as usize);
        g.bench_function(format!("targets/{n}"), |b| {
            b.iter(|| black_box(s.route_check_targets(Some(0)).len()))
        });
        // The thread's sync once a second with the config unchanged.
        g.bench_function(format!("sync-unchanged/{n}"), |b| {
            b.iter(|| black_box(s.route_check_sync(Some(1)).is_none()))
        });
        let up: Vec<(Target, bool)> = targets.iter().map(|t| (t.target.clone(), true)).collect();
        let down: Vec<(Target, bool)> = targets.iter().map(|t| (t.target.clone(), false)).collect();
        let mut now = 1_000;
        g.bench_function(format!("report-all-up/{n}"), |b| {
            b.iter(|| {
                now += 1;
                s.route_check_report(&up, Some(now));
            })
        });
        // Every gateway down at once (the uplink switch died), then back:
        // the whole change in one apply each way.
        g.bench_function(format!("report-all-down-and-up/{n}"), |b| {
            b.iter(|| {
                now += 1_000_000;
                s.route_check_report(&down, Some(now));
                s.route_check_report(&down, Some(now + 1));
                s.route_check_report(&up, Some(now + 2));
            })
        });
        g.bench_function(format!("schedule-interval/{n}"), |b| {
            b.iter(|| {
                let mut sched = Schedule::default();
                sched.sync(targets.clone(), 0);
                let mut t = 0;
                let mut sent = 0usize;
                while t < 10_000 {
                    for d in sched.due(t) {
                        sched.echo(d.target.gateway, d.seq);
                        sent += 1;
                    }
                    t += 20;
                }
                black_box(sent)
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

//! G3.1: the CPU side of an FRR commit, without FRR: parsing a running
//! config, diffing it against the render, rendering it back. The I/O side
//! (vty against frr-reload.py) is measured on a real FRR by
//! `scripts/frr-compare.sh` (docs/architecture.md).

use std::fmt::Write as _;
use std::hint::black_box;

use corerouter_hal_frr::conf::{Conf, diff};
use criterion::{Criterion, criterion_group, criterion_main};

/// BGP with `peers` neighbors and `entries` prefix-list lines, as FRR
/// prints it.
fn config(peers: u32, entries: u32, router_id: &str) -> String {
    let mut s = String::from("frr version 10.7.1\nfrr defaults traditional\n!\n");
    for i in 0..entries {
        let _ = writeln!(
            s,
            "ip prefix-list BIG seq {} permit 10.{}.{}.0/24",
            (i + 1) * 5,
            i / 256,
            i % 256
        );
    }
    let _ = writeln!(
        s,
        "!\nrouter bgp 65000\n bgp router-id {router_id}\n no bgp default ipv4-unicast"
    );
    for i in 0..peers {
        let _ = writeln!(
            s,
            " neighbor 127.1.{}.{} remote-as {}",
            i / 200,
            i % 200 + 1,
            65001 + i
        );
    }
    s.push_str(" !\n address-family ipv4 unicast\n");
    for i in 0..peers {
        let _ = writeln!(s, "  neighbor 127.1.{}.{} activate", i / 200, i % 200 + 1);
    }
    s.push_str(" exit-address-family\nexit\n!\nend\n");
    s
}

fn bench(c: &mut Criterion) {
    let big = config(100, 10_000, "10.0.0.1");
    let big_changed = config(100, 10_000, "10.0.0.2");
    let half = config(100, 5_000, "10.0.0.1");
    let a = Conf::parse(&big).unwrap_or_default();
    let b = Conf::parse(&big_changed).unwrap_or_default();
    let h = Conf::parse(&half).unwrap_or_default();
    c.bench_function("frr_parse_10k_entries_100_peers", |x| {
        x.iter(|| Conf::parse(black_box(&big)))
    });
    c.bench_function("frr_diff_small_change_10k", |x| {
        x.iter(|| diff(black_box(&a), black_box(&b)))
    });
    c.bench_function("frr_diff_remove_5k_of_10k", |x| {
        x.iter(|| diff(black_box(&a), black_box(&h)))
    });
    c.bench_function("frr_diff_add_10k_from_empty", |x| {
        let empty = Conf::default();
        x.iter(|| diff(black_box(&empty), black_box(&a)))
    });
    c.bench_function("frr_render_10k", |x| x.iter(|| black_box(&a).render()));

    // G3.2a: 1 000 connections (5 000 lines), rendered by proto-bgp, parsed
    // and diffed against the same with one neighbor changed.
    let cfg = connections(1000, 500);
    let changed = connections(1000, 501);
    let text = corerouter_proto_bgp::render_all(&cfg.routing, &|_| None).unwrap_or_default();
    let one = corerouter_proto_bgp::render_all(&changed.routing, &|_| None).unwrap_or_default();
    let ca = Conf::parse(&text).unwrap_or_default();
    let cb = Conf::parse(&one).unwrap_or_default();
    c.bench_function("bgp_render_1000_connections", |x| {
        x.iter(|| corerouter_proto_bgp::render_all(black_box(&cfg.routing), &|_| None))
    });
    c.bench_function("bgp_parse_1000_connections", |x| {
        x.iter(|| Conf::parse(black_box(&text)))
    });
    c.bench_function("bgp_diff_one_of_1000_connections", |x| {
        x.iter(|| diff(black_box(&ca), black_box(&cb)))
    });
    c.bench_function("bgp_diff_add_1000_connections", |x| {
        let empty = Conf::default();
        x.iter(|| diff(black_box(&empty), black_box(&ca)))
    });
}

/// `n` connections over a template; connection `short` has a 30 s hold.
fn connections(n: u32, short: u32) -> corerouter_model::Config {
    use corerouter_model::bgp::{BgpConnection, BgpParams, BgpTemplate};
    use corerouter_model::{Asn, BgpInstance, Config};
    let mut cfg = Config::default();
    cfg.routing.bgp.insert(
        "default".into(),
        BgpInstance {
            name: "default".into(),
            asn: Asn(65000),
            router_id: [10, 0, 0, 1].into(),
            disabled: false,
            comment: String::new(),
            graceful_restart_time: None,
            graceful_stale_time: None,
            graceful_defer_time: None,
            graceful_notification: None,
            hard_admin_reset: None,
        },
    );
    cfg.routing.bgp_templates.insert(
        "peers".into(),
        BgpTemplate {
            name: "peers".into(),
            templates: Vec::new(),
            params: BgpParams {
                hold_time: Some(90),
                max_prefix_ipv4: Some(1000),
                ..Default::default()
            },
            comment: String::new(),
        },
    );
    for i in 0..n {
        let name = format!("n{i}");
        cfg.routing.bgp_connections.insert(
            name.clone(),
            BgpConnection {
                name,
                instance: "default".into(),
                remote_address: std::net::IpAddr::from([
                    10,
                    100 + (i / 65536) as u8,
                    (i / 256 % 256) as u8,
                    (i % 256) as u8,
                ]),
                templates: vec!["peers".into()],
                params: BgpParams {
                    remote_as: Some(Asn(64512 + i)),
                    hold_time: (i == short).then_some(30),
                    ..Default::default()
                },
                disabled: false,
                comment: String::new(),
            },
        );
    }
    cfg
}

criterion_group!(benches, bench);
criterion_main!(benches);

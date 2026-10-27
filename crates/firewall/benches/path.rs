//! G2.1c — the packet tester (`ip.firewall.test`) over a large firewall:
//! 10 000 filter forward rules that do not match the packet and one that
//! accepts it at the end, plus raw, NAT and mangle rules on the way, so the
//! walk reads every rule of every chain it crosses.
//!
//! ```sh
//! cargo bench -p corerouter-firewall --bench path
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use corerouter_firewall::eval::Packet;
use corerouter_firewall::path::{Route, path};
use corerouter_firewall::sample::{m, rule};
use corerouter_model::Config;
use corerouter_model::firewall::{Action, ConnState, Protocol};
use criterion::{Criterion, criterion_group, criterion_main};

fn config(n: u32) -> Config {
    let mut c = Config::default();
    let mut filter = Vec::with_capacity(n as usize + 1);
    for i in 0..n {
        let src = format!(
            "10.{}.{}.{}/32",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        );
        filter.push(
            rule(
                i + 1,
                "forward",
                m(&[
                    ("src_address", &src),
                    ("protocol", "tcp"),
                    ("dst_port", "443"),
                ])
                .unwrap(),
                Action::Drop,
            )
            .unwrap(),
        );
    }
    filter.push(rule(n + 1, "forward", m(&[]).unwrap(), Action::Accept).unwrap());
    c.ip.firewall.filter = filter.into();
    c.ip.firewall.raw = vec![
        rule(
            n + 2,
            "prerouting",
            m(&[("src_address", "198.18.0.0/15")]).unwrap(),
            Action::Drop,
        )
        .unwrap(),
    ]
    .into();
    c.ip.firewall.mangle = vec![
        rule(
            n + 3,
            "forward",
            m(&[("protocol", "udp")]).unwrap(),
            Action::Passthrough,
        )
        .unwrap(),
    ]
    .into();
    c
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("firewall_test");
    let packet = Packet {
        src: "203.0.113.9".parse().unwrap(),
        dst: "192.0.2.80".parse().unwrap(),
        protocol: Protocol::TCP,
        src_port: Some(40_000),
        dst_port: Some(443),
        icmp: None,
        in_interface: Some("ether1".into()),
        out_interface: None,
        state: ConnState::New,
        nat: None,
    };
    let router = |_: std::net::IpAddr, _: Option<&str>| Route::Out("ether2".into());
    for n in [1_000u32, 10_000] {
        let cfg = config(n);
        g.bench_function(format!("path/{n} rules"), |b| {
            b.iter(|| {
                let p = path(&cfg, &[], &packet, &router);
                assert_eq!(p.decided_by.map(|(_, id)| id.0), Some(n + 1));
                p
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

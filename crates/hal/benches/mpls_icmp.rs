//! G3.9d — the CPU one ICMP time exceeded costs the LSR: reading the
//! expired frame ([`expired::parse`]) and building the error with its
//! RFC 4950 object and the way back ([`expired::answer`]), against an
//! in-memory view of 100 000 labels. Only expired packets pay it (bounded
//! by `icmp_rate`); the per-packet cost on the data path is the kernel's
//! filter (`benches/netns_mpls_ttl.rs` in hal-linux).
//!
//! ```sh
//! cargo bench -p corerouter-hal --bench mpls_icmp
//! ```

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::IpAddr;

use corerouter_hal::lsp::expired;
use corerouter_hal::lsp::respond::LsrView;
use corerouter_hal::lsp::wire;
use corerouter_hal::mpls::{MplsNexthop, MplsRoute, Origin};
use corerouter_hal::probe::MplsLabel;
use corerouter_model::IfName;
use criterion::{Criterion, criterion_group, criterion_main};
use ipnet::IpNet;

/// A transit LSR with 100 000 labels; `routed`: it has an IP route back.
struct View {
    labels: BTreeMap<u32, MplsRoute>,
    routed: bool,
}

impl LsrView for View {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }
    fn fec_route(&self, _: IpNet) -> Option<Vec<MplsNexthop>> {
        self.routed.then(|| {
            vec![MplsNexthop {
                via: Some("10.0.12.1".parse().unwrap()),
                interface: Some("ether1".parse().unwrap()),
                out_labels: vec![],
            }]
        })
    }
    fn is_local(&self, _: IpNet) -> bool {
        false
    }
    fn interface_addrs(&self, _: &IfName) -> Vec<IpAddr> {
        vec!["10.0.12.2".parse().unwrap()]
    }
    fn mtu(&self, _: &IfName) -> Option<u16> {
        Some(1500)
    }
}

fn view(routed: bool) -> View {
    let labels = (16..100_016u32)
        .map(|l| {
            let r = MplsRoute {
                label: l,
                origin: Origin::Ldp,
                nexthops: vec![MplsNexthop {
                    via: Some("10.0.23.3".parse().unwrap()),
                    interface: Some("ether2".parse().unwrap()),
                    out_labels: vec![l + 200_000],
                }],
            };
            (l, r)
        })
        .collect();
    View { labels, routed }
}

/// A 1400-byte traceroute probe under `stack` (Ethernet header stripped).
fn frame(stack: &[MplsLabel]) -> Vec<u8> {
    let mut f: Vec<u8> = stack
        .iter()
        .flat_map(|l| wire::label_word(l).to_be_bytes())
        .collect();
    let total: u16 = 1400;
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0, 0, 1, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 9]);
    ip.extend_from_slice(&[0x80, 0, 0x82, 0x9b, 0x05, 0x64, 0, 0]);
    ip.resize(usize::from(total), 0xab);
    f.extend_from_slice(&ip);
    f
}

fn bench(c: &mut Criterion) {
    let ifc: IfName = "ether1".parse().unwrap();
    let one = frame(&[MplsLabel {
        label: 50_000,
        tc: 0,
        bottom: true,
        ttl: 1,
    }]);
    let vpn = frame(&[
        MplsLabel {
            label: 50_000,
            tc: 0,
            bottom: false,
            ttl: 1,
        },
        MplsLabel {
            label: 16,
            tc: 0,
            bottom: true,
            ttl: 63,
        },
    ]);
    let routed = view(true);
    let core = view(false);
    let mut g = c.benchmark_group("mpls_icmp");
    g.bench_function("parse", |b| {
        b.iter(|| expired::parse(&ifc, black_box(&one)).unwrap())
    });
    let e = expired::parse(&ifc, &one).unwrap();
    g.bench_function("answer/1 label, by the IP table", |b| {
        b.iter(|| expired::answer(black_box(&e), &routed).unwrap())
    });
    g.bench_function("answer/1 label, along the LSP (100k labels)", |b| {
        b.iter(|| expired::answer(black_box(&e), &core).unwrap())
    });
    let e = expired::parse(&ifc, &vpn).unwrap();
    g.bench_function("answer/2 labels (VPN), along the LSP", |b| {
        b.iter(|| expired::answer(black_box(&e), &routed).unwrap())
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

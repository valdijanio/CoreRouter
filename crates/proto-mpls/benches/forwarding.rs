//! G3.5: the forwarding-table view at LSR size.
//!
//! - `forwarding/rows_100k`: 100 000 kernel labels joined with 10 000 LDP
//!   FECs, each with its reason and MTU check (what every
//!   `mpls.forwarding-table.page` does before it cuts the page).
//!
//! Synthetic: FEC i has local label 16 + i, the kernel holds it with one
//! out label; one FEC in ten has no label (no neighbor sent one); the other
//! 90 000 kernel labels belong to no FEC (static or another program).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::mpls::{MplsNexthop, MplsRoute, Origin};
use corerouter_model::IfName;
use corerouter_model::mpls::Mpls;
use corerouter_model::mpls_state::{LdpBinding, LdpNeighborState, LdpState, RemoteLabel};
use criterion::{Criterion, criterion_group, criterion_main};

fn fixture(fecs: u32, labels: u32) -> (LdpState, Vec<MplsRoute>) {
    let nbr = Ipv4Addr::new(10, 255, 0, 2);
    let bindings = (0..fecs)
        .map(|i| LdpBinding {
            prefix: ipnet::IpNet::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (i << 8))), 24)
                .unwrap(),
            local_label: Some(16 + i),
            remote: if i % 10 == 0 {
                vec![]
            } else {
                vec![RemoteLabel {
                    neighbor: nbr,
                    label: 100_000 + i,
                    in_use: true,
                }]
            },
        })
        .collect();
    let e1: IfName = "ether1".parse().unwrap();
    let kernel = (0..labels)
        .map(|i| MplsRoute {
            label: 16 + i,
            origin: if i < fecs {
                Origin::Ldp
            } else {
                Origin::Static
            },
            nexthops: vec![MplsNexthop {
                via: Some(IpAddr::from([10, 0, 12, 2])),
                interface: Some(e1.clone()),
                out_labels: vec![100_000 + i],
            }],
        })
        .collect();
    let st = LdpState {
        neighbors: vec![LdpNeighborState {
            lsr_id: nbr,
            afi: "ipv4".into(),
            state: "OPERATIONAL".into(),
            transport: None,
            uptime: None,
        }],
        bindings,
        ..LdpState::default()
    };
    (st, kernel)
}

fn bench(c: &mut Criterion) {
    let (st, kernel) = fixture(10_000, 100_000);
    let mpls = Mpls::default();
    let mtu = |_: &str| Some(1500u32);
    c.bench_function("forwarding/rows_100k", |b| {
        b.iter(|| {
            black_box(corerouter_proto_mpls::forwarding_rows(
                &mpls,
                Some(&st),
                &kernel,
                &mtu,
            ))
            .len()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

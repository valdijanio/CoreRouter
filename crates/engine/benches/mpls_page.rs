//! G3.5: `mpls.forwarding-table.page` on a 100 000-label LSR (10 000 LDP
//! FECs), as the daemon runs it (the `mpls` service builds the lines off
//! the lock): a page, a search, and the build itself (`service/build`).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_engine::Session;
use corerouter_engine::mpls::KernelLabels;
use corerouter_hal::mpls::{MplsNexthop, MplsRoute, Origin};
use corerouter_model::mpls_state::{LdpBinding, LdpNeighborState, LdpState, RemoteLabel};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

fn session() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("mpls.ldp.add", &json!({"lsr_id": "10.255.0.1"}))
        .unwrap();
    let nbr = Ipv4Addr::new(10, 255, 0, 2);
    let st = LdpState {
        neighbors: vec![LdpNeighborState {
            lsr_id: nbr,
            afi: "ipv4".into(),
            state: "OPERATIONAL".into(),
            transport: None,
            uptime: None,
        }],
        bindings: (0..10_000u32)
            .map(|i| LdpBinding {
                prefix: ipnet::IpNet::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + (i << 8))), 24)
                    .unwrap(),
                local_label: Some(16 + i),
                remote: vec![RemoteLabel {
                    neighbor: nbr,
                    label: 100_000 + i,
                    in_use: i % 10 != 0,
                }],
            })
            .collect(),
        ..LdpState::default()
    };
    corerouter_engine::mpls::set_ldp(&mut s, Ok(Some(st)));
    if let Some(k) = s.ext_mut::<KernelLabels>() {
        k.service = true;
    }
    fill(&mut s);
    s
}

/// A new read of the table (what the service stores every 2 s).
fn fill(s: &mut Session) {
    let e1: corerouter_model::IfName = "ether1".parse().unwrap();
    let table: Vec<MplsRoute> = (0..100_000u32)
        .map(|i| MplsRoute {
            label: 16 + i,
            origin: if i < 10_000 {
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
    // As the service does: the lines built off the lock with the read.
    let inputs = corerouter_engine::mpls::line_inputs(s);
    let lines = corerouter_engine::mpls::build_lines(&inputs, &table);
    corerouter_engine::mpls::set_kernel_lines(s, table, lines);
}

fn bench(c: &mut Criterion) {
    let mut s = session();
    let page = json!({"limit": 500});
    c.bench_function("mpls_page/cached", |b| {
        b.iter(|| black_box(s.execute("mpls.forwarding-table.page", &page).unwrap()))
    });
    let find = json!({"limit": 500, "find": "10.0.3"});
    c.bench_function("mpls_page/find_cached", |b| {
        b.iter(|| black_box(s.execute("mpls.forwarding-table.page", &find).unwrap()))
    });
    let table: Vec<MplsRoute> = s
        .ext::<KernelLabels>()
        .map(|k| k.routes.as_ref().clone())
        .unwrap();
    let inputs = corerouter_engine::mpls::line_inputs(&s);
    c.bench_function("mpls_page/service_build", |b| {
        b.iter(|| {
            black_box(corerouter_engine::mpls::build_lines(&inputs, &table))
                .rows
                .len()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

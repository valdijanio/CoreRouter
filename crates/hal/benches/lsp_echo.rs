//! G3.5b — the CPU an MPLS echo request costs: encode (the sender, per
//! request), parse, and the responder's whole answer (parse, label and
//! FEC lookups in an in-memory view, encode the reply). The I/O around it
//! is the kernel's (`tests/netns_lsp.rs` in hal-linux, the VM run in
//! `docs/mpls.md`).
//!
//! ```sh
//! cargo bench -p corerouter-hal --bench lsp_echo
//! ```

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::IpAddr;

use corerouter_hal::lsp::respond::{Heard, LsrView, ddmap_of, respond};
use corerouter_hal::lsp::wire::{self, Echo, Fec};
use corerouter_hal::mpls::{MplsNexthop, MplsRoute, Origin};
use corerouter_hal::probe::MplsLabel;
use corerouter_model::IfName;
use criterion::{Criterion, criterion_group, criterion_main};
use ipnet::IpNet;

/// A transit LSR with 100 000 labels and as many FECs.
struct View {
    labels: BTreeMap<u32, MplsRoute>,
    fecs: BTreeMap<IpNet, Vec<MplsNexthop>>,
}

impl LsrView for View {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }
    fn fec_route(&self, p: IpNet) -> Option<Vec<MplsNexthop>> {
        self.fecs.get(&p).cloned()
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

fn view() -> View {
    let mut labels = BTreeMap::new();
    let mut fecs = BTreeMap::new();
    for i in 0..100_000u32 {
        let nh = MplsNexthop {
            via: Some("10.0.23.3".parse().unwrap()),
            interface: Some("ether2".parse().unwrap()),
            out_labels: vec![200_000 + i],
        };
        labels.insert(
            16 + i,
            MplsRoute {
                label: 16 + i,
                origin: Origin::Ldp,
                nexthops: vec![nh.clone()],
            },
        );
        let [a, b, c, d] = (0x0a00_0000 + i).to_be_bytes();
        fecs.insert(format!("{a}.{b}.{c}.{d}/32").parse().unwrap(), vec![nh]);
    }
    View { labels, fecs }
}

fn bench(c: &mut Criterion) {
    let v = view();
    let fec: IpNet = "10.0.195.80/32".parse().unwrap(); // 0x0a00c350 = i 50 000
    let mut e = Echo::request(1, 1, vec![Fec::Ldp(fec)]);
    e.ddmaps.push(ddmap_of(
        &MplsNexthop {
            via: Some("10.0.12.2".parse().unwrap()),
            interface: None,
            out_labels: vec![16 + 50_000],
        },
        Origin::Ldp,
        Some(1500),
        false,
    ));
    let payload = wire::encode(&e);
    let heard = Heard {
        interface: "ether1".parse().unwrap(),
        stack: vec![MplsLabel {
            label: 16 + 50_000,
            tc: 0,
            bottom: true,
            ttl: 1,
        }],
        src: "10.0.12.1".parse().unwrap(),
        dst: "127.0.0.1".parse().unwrap(),
        src_port: 50_000,
        dst_port: wire::PORT,
        payload: payload.clone(),
    };
    let mut g = c.benchmark_group("lsp_echo");
    g.bench_function("encode_request_with_ddmap", |b| b.iter(|| wire::encode(black_box(&e))));
    g.bench_function("parse_request_with_ddmap", |b| b.iter(|| wire::parse(black_box(&payload))));
    g.bench_function("respond_transit_100k_labels", |b| {
        b.iter(|| respond(black_box(&heard), &v, (0, 0)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

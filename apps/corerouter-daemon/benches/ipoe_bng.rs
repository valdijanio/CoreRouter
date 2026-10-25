//! G4.3f: the cost of one IPoE subscriber in the daemon's core
//! (`src/service/ipoe_bng.rs`, included as it is): the local decision
//! (`/ppp secret service=ipoe` through the engine's index) and the session
//! made from the bound lease (active row, history, XDP map change), with
//! 10 000 and 100 000 subscribers already up and as many secrets. The cost
//! per lease must not grow with the total.
//!
//! `cargo bench -p corerouter-daemon --bench ipoe_bng`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

#[path = "../src/service/ipoe_bng.rs"]
#[allow(dead_code)]
mod ipoe_bng;

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_engine::ipoe::{IpoeBackend, IpoeIndex, IpoeView};
use corerouter_model::cow::CowArc;
use corerouter_model::dhcp_server::DhcpServer;
use corerouter_model::ppp::{PppProfile, PppSecret, PppService};
use corerouter_model::{Config, ItemId, MacAddr};
use corerouter_proto_dhcp::server::Binding;
use corerouter_proto_dhcp::server::authorize::AuthAsk;
use corerouter_proto_dhcp::server::leases::{Lease, State};
use corerouter_proto_dhcp::server::request::Kind;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use ipoe_bng::{Backend, Core};

fn mac(i: usize) -> [u8; 6] {
    let [_, a, b, c] = u32::try_from(i).unwrap().to_be_bytes();
    [0x02, 0x30, 0, a, b, c]
}

fn config(n: usize) -> Config {
    let mut c = Config::default();
    let mut s = DhcpServer::new(ItemId(1), "dhcp1".into(), "ether2".parse().unwrap());
    s.ipoe = true;
    c.ip.dhcp_server.servers.push(s);
    c.ppp.profiles.push(PppProfile {
        id: ItemId(1),
        name: "p".into(),
        rate_limit: Some("10M/50M".into()),
        ..PppProfile::default()
    });
    c.ppp.secrets = CowArc::new(
        (0..n)
            .map(|i| PppSecret {
                id: ItemId(u32::try_from(i).unwrap() + 10),
                name: MacAddr(mac(i)).to_string(),
                service: PppService::Ipoe,
                profile: "p".into(),
                ..PppSecret::default()
            })
            .collect(),
    );
    c
}

fn ask(i: usize) -> AuthAsk {
    let m = mac(i);
    AuthAsk {
        server: "dhcp1".into(),
        interface: "ether2".parse().unwrap(),
        client_key: [&[1u8][..], &m].concat(),
        mac: m,
        client_id: None,
        circuit_id: None,
        remote_id: None,
        giaddr: Ipv4Addr::UNSPECIFIED,
        host_name: String::new(),
        vendor_class: String::new(),
        kind: Kind::Discover,
    }
}

fn binding(i: usize) -> Binding {
    Binding {
        lease: Lease {
            address: Ipv4Addr::from(0x0a40_0000 + u32::try_from(i).unwrap()),
            server: "dhcp1".into(),
            state: State::Bound,
            mac: mac(i),
            client_id: None,
            host_name: String::new(),
            vendor_class: String::new(),
            expires: 1_800_003_600,
            lease_time: 3600,
            last_seen: 1_800_000_000,
            reason: String::new(),
            relay_info: None,
            hw: None,
        },
        new: true,
        dns: None,
        ttl: 1200,
        address_lists: Vec::new(),
    }
}

/// `n` subscribers up, then the next 1000 authorized and bound.
fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("ipoe_bng");
    g.sample_size(10);
    for n in [10_000usize, 100_000] {
        let cfg = config(n + 1000);
        let index = IpoeIndex::of(&cfg);
        let view = IpoeView::new(&cfg, &index);
        let core = Core::new();
        core.configure(&cfg, None);
        core.set_xdp(true);
        let b = Backend(core.clone());
        for i in 0..n {
            b.authorize(&ask(i), &view);
            b.bound(&binding(i), &view);
        }
        let _ = core.take_ops();
        g.throughput(Throughput::Elements(1000));
        g.bench_function(format!("authorize_bind_1000/after_{n}"), |bn| {
            bn.iter_batched(
                || (),
                |()| {
                    for i in n..n + 1000 {
                        black_box(b.authorize(&ask(i), &view));
                        b.bound(&binding(i), &view);
                    }
                    // The same 1000 end: the next round makes them again.
                    for i in n..n + 1000 {
                        b.gone(&binding(i).lease, "released");
                    }
                    let _ = core.take_ops();
                },
                BatchSize::PerIteration,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

//! The DHCP servers under hostile load (audit of G4.2): what one message
//! costs when the pool is full, when the config has thousands of static
//! leases, when someone answers every ARP probe, when the lease history is
//! at its cap, and when DHCPv6 SOLICITs come from random DUIDs.
//!
//! `cargo xtask bench attack`; alone:
//! `cargo bench -p corerouter-proto-dhcp --bench server_attack`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::net::{Ipv4Addr, Ipv6Addr};

use corerouter_hal::dhcp_server::Heard;
use corerouter_model::dhcp_server::{DhcpNetwork, DhcpServer, StaticLease};
use corerouter_model::dhcp6_server::{Dhcp6Server, Ipv6Pool};
use corerouter_model::ip_pool::IpPool;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind, ItemId, MacAddr};
use corerouter_proto_dhcp::server::history::History;
use corerouter_proto_dhcp::server::leases::{Lease, State};
use corerouter_proto_dhcp::server::plan::Plan;
use corerouter_proto_dhcp::server::{Effect, Now, PROBE_WAIT_MS, Server};
use corerouter_proto_dhcp::server6::{Plan6, Server6};
use corerouter_proto_dhcp::v4::Outgoing;
use corerouter_proto_dhcp::v6::{self, IaReq};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use dhcproto::v4::MessageType;

const NOW: Now = Now {
    ms: 10_000,
    unix: 1_800_000_000,
};

fn iface() -> IfName {
    "ether2".parse().unwrap()
}

/// A /16 LAN on ether2 with a pool of `pool` addresses from 10.0.1.0.
fn v4_cfg(pool: u32, probe: bool, statics: u32) -> Config {
    let mut c = Config::default();
    c.interfaces
        .insert(iface(), Interface::new(iface(), InterfaceKind::Ethernet));
    c.ip.addresses.push(AddressEntry {
        id: ItemId(1),
        address: "10.0.0.1/16".parse().unwrap(),
        interface: iface(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    let first = u32::from(Ipv4Addr::new(10, 0, 1, 0));
    let last = Ipv4Addr::from(first + pool - 1);
    c.ip.pools.pools.push(IpPool {
        id: ItemId(1),
        name: "p".into(),
        ranges: vec![format!("10.0.1.0-{last}").parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    let mut s = DhcpServer::new(ItemId(1), "dhcp1".into(), iface());
    s.address_pool = Some("p".into());
    s.conflict_detection = probe;
    s.client_rate_limit = 0;
    c.ip.dhcp_server.servers.push(s);
    let mut net = DhcpNetwork::new(ItemId(2), "10.0.0.0/16".parse().unwrap());
    net.gateway = vec![Ipv4Addr::new(10, 0, 0, 1)];
    c.ip.dhcp_server.networks.push(net);
    // Static leases outside the pool, for other MACs (never the clients').
    for i in 0..statics {
        let mut st = StaticLease::new(
            ItemId(i + 10),
            Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 1, 0, 0)) + i),
        );
        let [_, a, b, d] = i.to_be_bytes();
        st.mac_address = Some(MacAddr([0x0a, 0x5a, 0, a, b, d]));
        c.ip.dhcp_server.leases.push(st);
    }
    c
}

fn mac_of(n: u32) -> [u8; 6] {
    let [a, b, c, d] = n.to_be_bytes();
    [0x02, a, b, c, d, 0x01]
}

fn v4_msg(kind: MessageType, n: u32, requested: Option<Ipv4Addr>) -> Heard {
    let payload = Outgoing {
        kind,
        xid: n,
        secs: 0,
        mac: mac_of(n),
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: false,
        requested,
        server_id: requested.map(|_| Ipv4Addr::new(10, 0, 0, 1)),
        client_id: &[],
        host_name: None,
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .unwrap();
    Heard {
        payload,
        src: Ipv4Addr::UNSPECIFIED,
        dst: Ipv4Addr::BROADCAST,
        src_mac: mac_of(n),
        to_server: true,
    }
}

fn offered(fx: &[Effect]) -> Option<Ipv4Addr> {
    fx.iter().find_map(|e| match e {
        Effect::Send { payload, .. } => corerouter_proto_dhcp::v4::decode(payload)
            .ok()
            .map(|m| m.yiaddr),
        _ => None,
    })
}

/// A pool full of offers, then DISCOVERs from MACs never seen: each one is
/// refused (RFC 2131: no address), and that must stay cheap.
fn exhausted(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp_attack");
    g.sample_size(10);
    let pool = 16_384u32;
    let cfg = v4_cfg(pool, false, 0);
    let mut full = Server::new(Plan::from_config(&cfg), NOW.unix);
    for n in 0..pool {
        full.handle(NOW, &iface(), &v4_msg(MessageType::Discover, n, None));
    }
    let flood: Vec<Heard> = (0..1_000)
        .map(|i| v4_msg(MessageType::Discover, 1_000_000 + i, None))
        .collect();
    g.throughput(Throughput::Elements(flood.len() as u64));
    g.bench_function("exhausted_pool_random_mac/16k", |b| {
        b.iter_batched(
            || full.clone(),
            |mut srv| {
                for h in &flood {
                    black_box(srv.handle(NOW, &iface(), h));
                }
            },
            BatchSize::LargeInput,
        );
    });
    g.finish();
}

/// DORA of 200 clients with 0, 10k and 65,536 static leases in the config.
fn statics(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp_attack");
    g.sample_size(10);
    let n = 200u32;
    for st in [0u32, 10_000, 65_536] {
        let plan = Plan::from_config(&v4_cfg(4096, false, st));
        g.throughput(Throughput::Elements(u64::from(n)));
        g.bench_function(format!("statics_dora/{st}"), |b| {
            b.iter_batched(
                || Server::new(plan.clone(), NOW.unix),
                |mut srv| {
                    for i in 0..n {
                        let fx = srv.handle(NOW, &iface(), &v4_msg(MessageType::Discover, i, None));
                        let ip = offered(&fx).unwrap();
                        black_box(srv.handle(
                            NOW,
                            &iface(),
                            &v4_msg(MessageType::Request, i, Some(ip)),
                        ));
                    }
                },
                BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

/// An attacker answers every ARP probe on a pool of 4096 with 4000 bound:
/// each answer sends the server looking for another address.
fn arp_spoof(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp_attack");
    g.sample_size(10);
    let cfg = v4_cfg(4096, true, 0);
    let mut base = Server::new(Plan::from_config(&cfg), NOW.unix);
    let mut now = NOW;
    for i in 0..4_000u32 {
        base.handle(now, &iface(), &v4_msg(MessageType::Discover, i, None));
        now.ms += PROBE_WAIT_MS;
        let fx = base.tick_ms(now);
        let ip = offered(&fx).unwrap();
        base.handle(now, &iface(), &v4_msg(MessageType::Request, i, Some(ip)));
    }
    let squatter = [0x0e, 0, 0, 0, 0, 0x99];
    g.throughput(Throughput::Elements(200));
    g.bench_function("arp_spoof_probe_replies/4096", |b| {
        b.iter_batched(
            || base.clone(),
            |mut srv| {
                for i in 0..200u32 {
                    let mut fx = srv.handle(
                        now,
                        &iface(),
                        &v4_msg(MessageType::Discover, 10_000 + i, None),
                    );
                    for _ in 0..3 {
                        let Some(ip) = fx.iter().find_map(|e| match e {
                            Effect::Probe { ip, .. } => Some(*ip),
                            _ => None,
                        }) else {
                            break;
                        };
                        fx = srv.probe_reply(now, &iface(), ip, squatter);
                    }
                    black_box(fx);
                }
            },
            BatchSize::LargeInput,
        );
    });
    g.finish();
}

fn lease(n: u32) -> Lease {
    Lease {
        address: Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 0, 0)) + (n % 65_536)),
        server: "dhcp1".into(),
        state: State::Bound,
        mac: mac_of(n),
        client_id: None,
        host_name: "cpe".into(),
        vendor_class: String::new(),
        expires: NOW.unix + 600,
        lease_time: 600,
        last_seen: NOW.unix,
        reason: String::new(),
        relay_info: None,
        hw: None,
    }
}

/// 100 new bindings on a history at its cap (500k entries).
fn history_at_cap(c: &mut Criterion) {
    use corerouter_proto_dhcp::server::history::MAX_ENTRIES;
    let mut g = c.benchmark_group("dhcp_attack");
    g.sample_size(10);
    let mut full = History::default();
    let cap = u32::try_from(MAX_ENTRIES).unwrap();
    for n in 0..cap {
        full.open(&lease(n), NOW.unix);
    }
    g.throughput(Throughput::Elements(100));
    g.bench_function("history_open_at_cap/500k", |b| {
        b.iter_batched(
            || full.clone(),
            |mut h| {
                for n in 0..100 {
                    black_box(h.open(&lease(cap + n), NOW.unix));
                }
            },
            BatchSize::LargeInput,
        );
    });
    g.finish();
}

fn v6_cfg(pd: bool) -> Config {
    let mut c = Config::default();
    c.interfaces
        .insert(iface(), Interface::new(iface(), InterfaceKind::Ethernet));
    let d = &mut c.ipv6.dhcp_server;
    d.pools.push(Ipv6Pool {
        id: ItemId(1),
        name: "addrs".into(),
        prefix: "2001:db8:1::/64".parse().unwrap(),
        prefix_length: 128,
        comment: String::new(),
    });
    d.pools.push(Ipv6Pool {
        id: ItemId(2),
        name: "cpe".into(),
        prefix: "2001:db8::/48".parse().unwrap(),
        prefix_length: 64,
        comment: String::new(),
    });
    let mut s = Dhcp6Server::new(ItemId(3), "v6".into(), iface());
    if pd {
        s.prefix_pool = Some("cpe".into());
    } else {
        s.address_pool = Some("addrs".into());
    }
    s.rapid_commit = true;
    d.servers.push(s);
    c
}

fn solicit(n: u32, rapid: bool, pd: bool) -> Vec<u8> {
    let [a, b, c, d] = n.to_be_bytes();
    let duid = v6::duid_ll([2, 0x66, a, b, c, d]);
    let ia = Some(IaReq {
        iaid: 1,
        addrs: vec![],
        prefixes: vec![],
    });
    v6::Outgoing {
        kind: v6::msg::SOLICIT,
        xid: n,
        client_id: &duid,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: rapid,
        ia_na: if pd { None } else { ia.clone() },
        ia_pd: if pd { ia } else { None },
        oro: &[],
    }
    .encode()
}

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn src(n: u32) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, (n >> 16) as u16, n as u16)
}

/// 100k SOLICITs from random DUIDs on an IA_NA /64, then the second's tick.
fn v6_flood(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp6_attack");
    g.sample_size(10);
    let plan = Plan6::from_config(&v6_cfg(false));
    let n = 100_000u32;
    let msgs: Vec<Vec<u8>> = (0..n).map(|i| solicit(i, false, false)).collect();
    g.throughput(Throughput::Elements(u64::from(n)));
    g.bench_function("solicit_flood_ia_na/100k", |b| {
        b.iter_batched(
            || Server6::new(plan.clone()),
            |mut srv| {
                for (i, m) in msgs.iter().enumerate() {
                    black_box(srv.handle(NOW, &iface(), MAC, src(i as u32), m));
                }
                let mut later = NOW;
                later.unix += 1;
                black_box(srv.tick(later));
                if !SHOWN.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    eprintln!("bindings held after the flood: {}", srv.leases().len());
                }
                srv
            },
            BatchSize::LargeInput,
        );
    });
    // A PD pool of 2^16 /64s, all delegated: SOLICITs from new DUIDs.
    let plan = Plan6::from_config(&v6_cfg(true));
    let mut full = Server6::new(plan);
    for i in 0..65_536u32 {
        full.handle(NOW, &iface(), MAC, src(i), &solicit(i, true, true));
    }
    let late: Vec<Vec<u8>> = (0..100u32)
        .map(|i| solicit(1_000_000 + i, false, true))
        .collect();
    g.throughput(Throughput::Elements(100));
    g.bench_function("solicit_pd_exhausted/65536", |b| {
        b.iter(|| {
            for (i, m) in late.iter().enumerate() {
                black_box(full.handle(NOW, &iface(), MAC, src(i as u32), m));
            }
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    exhausted,
    statics,
    arp_spoof,
    history_at_cap,
    v6_flood
);
criterion_main!(benches);

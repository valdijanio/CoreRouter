//! G3.2c: the costs of RPKI and of the BGP route lists at full-table size.
//!
//! - `rpki/build`: the VRP trie from 550 k VRPs (a 2026 global set,
//!   **estimado**), built on each End of Data.
//! - `rpki/validate_1m`: RFC 6811 for 1 M routes, one thread, and split
//!   over 2/4/8 threads (does splitting pay?).
//! - `rib/index_1m`: sort and validate one neighbor's full table.
//! - `rib/search_*`: one page of 500 out of 1 M, by prefix, AS path,
//!   community and RPKI state.
//! - `decision/explain_10`: "Why this route?" with 10 paths.
//!
//! Synthetic but shaped like the real table: /24s are ~60 % of IPv4
//! routes, ~45 % of routes have a covering VRP (fixed LCG, no rand crate).

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::bgp_rib::{
    AsSegment, BgpAttrs, BgpPath, BgpPrefix, BgpRib, BgpRoute, PeerKind, SegmentKind,
};
use corerouter_model::rpki::RpkiState;
use corerouter_proto_bgp::decision::{Options, explain};
use corerouter_proto_bgp::rib::{AsPathPattern, Indexed, Match, Query};
use corerouter_proto_bgp::rpki::{Vrp, VrpTable, origin_as};
use criterion::{Criterion, criterion_group, criterion_main};
use ipnet::IpNet;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
}

fn v4_len(r: u64) -> u8 {
    match r % 100 {
        0..=59 => 24,
        60..=74 => 22,
        75..=84 => 23,
        85..=94 => 20,
        _ => 16,
    }
}

/// `n` routes (90 % IPv4) with origin ASes from a pool of 75 k.
fn table(n: usize, rng: &mut Lcg) -> Vec<(IpNet, u32)> {
    (0..n)
        .map(|_| {
            let r = rng.next();
            let asn = 1 + u32::try_from(r % 75_000).unwrap_or(0);
            let net = if r.is_multiple_of(10) {
                let a = (0x2001_0000u128 | u128::from((r >> 8) & 0xffff)) << 96
                    | u128::from((r >> 24) & 0xffff) << 80;
                IpNet::new(IpAddr::V6(Ipv6Addr::from(a)), 32 + 16).unwrap_or_default()
            } else {
                let len = v4_len(r >> 4);
                let a = u32::try_from((r >> 20) & 0xffff_ff00).unwrap_or(0) | 0x0100_0000;
                IpNet::new(IpAddr::V4(Ipv4Addr::from(a)), len)
                    .map(|n| n.trunc())
                    .unwrap_or_default()
            };
            (net, asn)
        })
        .collect()
}

/// VRPs for ~45 % of `routes` (most with the right origin) plus extra.
fn vrps(routes: &[(IpNet, u32)], extra: usize, rng: &mut Lcg) -> Vec<Vrp> {
    let mut out: Vec<Vrp> = routes
        .iter()
        .filter_map(|(n, asn)| {
            if rng.next() % 100 >= 45 {
                return None;
            }
            let wrong = rng.next().is_multiple_of(100);
            Vrp::new(
                n.network(),
                n.prefix_len(),
                n.prefix_len(),
                if wrong { asn + 1 } else { *asn },
            )
        })
        .collect();
    out.extend(
        table(extra, rng)
            .iter()
            .filter_map(|(n, a)| Vrp::new(n.network(), n.prefix_len(), n.prefix_len(), *a)),
    );
    out
}

fn rib(routes: &[(IpNet, u32)]) -> BgpRib {
    // ~150 k distinct AS paths over the table (**estimado** from public
    // RIB dumps: a few per origin).
    let mut attrs = Vec::new();
    let mut out = Vec::with_capacity(routes.len());
    for (i, (net, asn)) in routes.iter().enumerate() {
        let a = i % 150_000;
        if a == attrs.len() {
            attrs.push(BgpAttrs {
                as_path: format!("64500 {} {asn}", 3_356 + (a % 7)),
                communities: if a % 3 == 0 {
                    vec!["64500:100".into()]
                } else {
                    vec![]
                },
                ..BgpAttrs::default()
            });
        }
        out.push(BgpRoute {
            prefix: *net,
            attrs: u32::try_from(a).unwrap_or(0),
            flags: BgpRoute::BEST,
        });
    }
    BgpRib {
        routes: out,
        attrs,
        pre_policy: true,
        warnings: vec![],
    }
}

fn validate_all(t: &VrpTable, routes: &[(IpNet, u32)]) -> [u64; 4] {
    let mut n = [0u64; 4];
    for (net, asn) in routes {
        let s = t.validate(net.network(), net.prefix_len(), Some(*asn));
        let i = match s {
            RpkiState::Valid => 0,
            RpkiState::Invalid => 1,
            RpkiState::Unknown => 2,
            RpkiState::Unverified => 3,
        };
        if let Some(c) = n.get_mut(i) {
            *c += 1;
        }
    }
    n
}

fn bench(c: &mut Criterion) {
    let mut rng = Lcg(0x5eed);
    let routes = table(1_000_000, &mut rng);
    let set = vrps(&routes, 100_000, &mut rng);
    let mut g = c.benchmark_group("rpki");
    g.sample_size(10);
    g.bench_function("build_550k", |b| {
        b.iter(|| black_box(VrpTable::build(&set)))
    });
    let t = VrpTable::build(&set);
    eprintln!(
        "VRPs: {} IPv4 + {} IPv6; states of 1 M routes: {:?}",
        t.len_v4(),
        t.len_v6(),
        validate_all(&t, &routes)
    );
    g.bench_function("validate_1m_1thread", |b| {
        b.iter(|| black_box(validate_all(&t, &routes)))
    });
    for threads in [2usize, 4, 8] {
        g.bench_function(format!("validate_1m_{threads}threads"), |b| {
            b.iter(|| {
                let chunk = routes.len().div_ceil(threads);
                std::thread::scope(|s| {
                    let hs: Vec<_> = routes
                        .chunks(chunk)
                        .map(|part| s.spawn(|| validate_all(&t, part)))
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap_or_default()).fold(
                        [0u64; 4],
                        |mut a, x| {
                            for (a, x) in a.iter_mut().zip(x) {
                                *a += x;
                            }
                            a
                        },
                    )
                })
            })
        });
    }
    g.finish();

    let full = rib(&routes);
    let mut g = c.benchmark_group("rib");
    g.sample_size(10);
    g.bench_function("index_1m", |b| {
        b.iter(|| black_box(Indexed::new(full.clone(), Some(&t), Some(65000))))
    });
    let ix = Indexed::new(full, Some(&t), Some(65000));
    let page = |q: &Query| black_box(ix.search(q, 0, 500));
    let by_prefix = Query {
        prefix: Some(("16.0.0.0/8".parse().unwrap_or_default(), Match::OrLonger)),
        ..Query::default()
    };
    g.bench_function("search_prefix_page", |b| b.iter(|| page(&by_prefix)));
    let deep = Query::default();
    g.bench_function("page_at_offset_900k", |b| {
        b.iter(|| black_box(ix.search(&deep, 900_000, 500)))
    });
    let by_path = Query {
        as_path: AsPathPattern::parse("^64500 3357").ok(),
        ..Query::default()
    };
    g.bench_function("search_as_path_count_all", |b| b.iter(|| page(&by_path)));
    let by_comm = Query {
        community: Some("64500:100".into()),
        rpki: Some(RpkiState::Invalid),
        ..Query::default()
    };
    g.bench_function("search_community_invalid_count_all", |b| {
        b.iter(|| page(&by_comm))
    });
    g.finish();

    let mut g = c.benchmark_group("decision");
    let paths: Vec<BgpPath> = (1..=10u32)
        .map(|i| BgpPath {
            peer: format!("198.51.100.{i}"),
            peer_router_id: Some(Ipv4Addr::new(198, 51, 100, u8::try_from(i).unwrap_or(0))),
            peer_kind: if i % 2 == 0 {
                PeerKind::External
            } else {
                PeerKind::Internal
            },
            segments: vec![AsSegment {
                kind: SegmentKind::Sequence,
                asns: (0..(2 + i % 3)).map(|k| 64_500 + k).collect(),
            }],
            local_pref: Some(100 + i % 2),
            med: Some(i % 4),
            valid: true,
            best: i == 3,
            ..BgpPath::default()
        })
        .collect();
    let p = BgpPrefix {
        prefix: "10.0.0.0/8".into(),
        paths,
        ..BgpPrefix::default()
    };
    g.bench_function("explain_10_paths", |b| {
        b.iter(|| black_box(explain(&p, &Options::default())))
    });
    g.bench_function("origin_as", |b| {
        b.iter(|| black_box(origin_as("64500 3356 1299 13335", None)))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

//! G3.2b: the CPU side of `/routing filter`.
//! - the preview of a transit input policy over a full table (1 M routes),
//!   on 1..16 threads (each a range of the routes; the policy is shared);
//! - compiling 10 000 rules (what validation does on every commit) and
//!   rendering them for FRR (`hal-frr/benches/filter_diff.rs` diffs them).

use std::collections::BTreeSet;
use std::hint::black_box;
use std::time::Duration;

use corerouter_model::routing_filter::{CommunityList, FilterRule, PrefixList, RoutingFilter};
use corerouter_proto_bgp::filter::eval::{Policy, Side, preview};
use corerouter_proto_bgp::filter::{frr, sample};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

/// A transit input policy as an ISP writes it: bogons, too long, private
/// ASes in the path, blackhole community, preference by neighbor, a tag.
pub fn transit() -> RoutingFilter {
    let mut f = RoutingFilter::default();
    let bogons = [
        "0.0.0.0/8 le 32", "10.0.0.0/8 le 32", "100.64.0.0/10 le 32", "127.0.0.0/8 le 32",
        "169.254.0.0/16 le 32", "172.16.0.0/12 le 32", "192.0.2.0/24 le 32", "192.168.0.0/16 le 32",
        "198.18.0.0/15 le 32", "198.51.100.0/24 le 32", "203.0.113.0/24 le 32", "224.0.0.0/4 le 32",
        "240.0.0.0/4 le 32", "0.0.0.0/0", "::/8 le 128", "2001:db8::/32 le 128", "fc00::/7 le 128",
        "fe80::/10 le 128", "ff00::/8 le 128", "::/0",
    ];
    f.prefix_lists.insert(
        "bogons".into(),
        PrefixList { name: "bogons".into(), entries: bogons.iter().filter_map(|e| e.parse().ok()).collect(), comment: String::new() },
    );
    f.community_lists.insert(
        "blackhole".into(),
        CommunityList { name: "blackhole".into(), communities: vec!["blackhole".into(), "64500:666".into()], comment: String::new() },
    );
    for (chain, rule) in [
        ("transit-in", "if (dst in bogons) { reject }"),
        ("transit-in", "if (afi ipv4 && dst-len > 24 || afi ipv6 && dst-len > 48) { reject }"),
        ("transit-in", "if (bgp-as-path \"_(6451[2-9]|645[2-9][0-9]|65[0-4][0-9][0-9]|655[0-2][0-9]|6553[0-4])_\") { reject }"),
        ("transit-in", "if (bgp-communities any-list blackhole) { reject }"),
        ("transit-in", "if (bgp-as-path \"^64500_[0-9]+$\") { set bgp-local-pref 200 }"),
        ("transit-in", "append bgp-communities 65000:100; accept"),
    ] {
        let id = f.next_id();
        f.rules.push(FilterRule { id, chain: chain.into(), rule: rule.into(), disabled: false, comment: String::new() });
    }
    f
}

/// 10 000 rules in 100 chains, each matching its own prefix.
pub fn ten_thousand() -> RoutingFilter {
    let mut f = transit();
    for i in 0..10_000u32 {
        let chain = format!("c{}", i / 100);
        let rule = match i % 4 {
            0 => format!("if (dst in 10.{}.{}.0/24) {{ set bgp-local-pref {}; accept }}", i / 256 % 256, i % 256, i % 300),
            1 => format!("if (bgp-communities includes 65000:{}) {{ reject }}", i % 65_000),
            2 => format!("if (bgp-as-path \"_{}$\" && dst-len in 16-24) {{ set bgp-path-prepend 2 }}", 1 + i % 60_000),
            _ => format!("if (dst in bogons || not afi ipv4) {{ reject }} append bgp-communities 65000:{}", i % 65_000),
        };
        let id = f.next_id();
        f.rules.push(FilterRule { id, chain, rule, disabled: false, comment: String::new() });
    }
    f
}

fn bench(c: &mut Criterion) {
    let routes = sample::routes(1_000_000, 1, 64500);
    let f = transit();
    let (policy, problems) = Policy::build(&f);
    assert!(problems.is_empty(), "{problems:?}");
    let side = Side { policy: &policy, chain: policy.chain("transit-in"), accept_without: false, asn: 65000 };
    let mut g = c.benchmark_group("filter_preview_1m_routes");
    g.sample_size(10).measurement_time(Duration::from_secs(10));
    for threads in [1usize, 2, 4, 8, 16] {
        g.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &t| {
            b.iter(|| preview(black_box(&side), None, black_box(&routes), 50, t))
        });
    }
    g.finish();
    // Against the policy in force (each route run twice).
    let mut g = c.benchmark_group("filter_preview_1m_routes_compared");
    g.sample_size(10).measurement_time(Duration::from_secs(10));
    for threads in [1usize, 8] {
        g.bench_with_input(BenchmarkId::from_parameter(threads), &threads, |b, &t| {
            b.iter(|| preview(black_box(&side), Some(&side), black_box(&routes), 50, t))
        });
    }
    g.finish();

    let big = ten_thousand();
    let mut g = c.benchmark_group("filter_10k_rules");
    g.sample_size(10);
    g.bench_function("build", |b| b.iter(|| Policy::build(black_box(&big))));
    g.bench_function("render", |b| b.iter(|| frr::render(black_box(&big), &BTreeSet::new(), &|_| Some(65000))));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

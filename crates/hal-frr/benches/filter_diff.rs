//! G3.2b: the FRR side of a `/routing filter` commit with 10 000 rules in
//! 100 chains: parsing the render (what `show running-config` gives back
//! when nothing changed) and diffing it after one rule changed, which is
//! what a commit types.

use std::collections::BTreeSet;
use std::hint::black_box;

use corerouter_hal_frr::conf::{Conf, diff};
use corerouter_model::routing_filter::{FilterRule, RoutingFilter};
use corerouter_proto_bgp::filter::frr;
use criterion::{Criterion, criterion_group, criterion_main};

fn rules(changed: Option<u32>) -> RoutingFilter {
    let mut f = RoutingFilter::default();
    for i in 0..10_000u32 {
        let pref = if Some(i) == changed { 999 } else { i % 300 };
        let rule = match i % 3 {
            0 => format!("if (dst in 10.{}.{}.0/24) {{ set bgp-local-pref {pref}; accept }}", i / 256 % 256, i % 256),
            1 => format!("if (bgp-communities includes 65000:{}) {{ reject }}", i % 65_000),
            _ => format!("if (bgp-as-path \"_{}$\" && dst-len in 16-24) {{ set bgp-local-pref {pref} }}", 1 + i % 60_000),
        };
        let id = f.next_id();
        f.rules.push(FilterRule { id, chain: format!("c{}", i / 100), rule, disabled: false, comment: String::new() });
    }
    f
}

fn bench(c: &mut Criterion) {
    let (text, _) = frr::render(&rules(None), &BTreeSet::new(), &|_| Some(65000));
    let (text2, _) = frr::render(&rules(Some(5_000)), &BTreeSet::new(), &|_| Some(65000));
    let a = Conf::parse(&text).unwrap_or_default();
    let b = Conf::parse(&text2).unwrap_or_default();
    let script = diff(&a, &b);
    assert!(!script.is_empty() && script.len() < 20, "{script:?}");
    let mut g = c.benchmark_group("filter_10k_rules_frr");
    g.sample_size(20);
    g.bench_function("parse", |x| x.iter(|| Conf::parse(black_box(&text))));
    g.bench_function("diff_one_rule", |x| x.iter(|| diff(black_box(&a), black_box(&b))));
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

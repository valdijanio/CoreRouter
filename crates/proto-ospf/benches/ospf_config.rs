//! G3.4: the CPU side of an OSPF commit on a large box: which interfaces
//! each template takes, the FRR render and the commit impact, with 4 000
//! interfaces (VLANs of an aggregation router), 4 000 addresses and 1 000
//! templates (most by name, some by network).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_model::Config;
use corerouter_model::config::{AddressEntry, Interface};
use corerouter_model::ospf::{
    AreaId, AreaType, AuthType, NssaTranslate, OspfArea, OspfInstance, OspfTemplate,
};
use corerouter_model::types::ItemId;
use criterion::{Criterion, criterion_group, criterion_main};

fn config(ifaces: u32, templates: u32) -> Config {
    let mut cfg = Config::default();
    for i in 0..ifaces {
        let name = format!("vlan{i}");
        let iface: Interface =
            serde_json::from_value(serde_json::json!({"name": name, "kind": {"type": "ethernet"}}))
                .unwrap();
        cfg.interfaces.insert(name.parse().unwrap(), iface);
        cfg.ip.addresses.push(AddressEntry {
            id: ItemId(i + 1),
            address: format!("10.{}.{}.1/30", i / 64, (i % 64) * 4)
                .parse()
                .unwrap(),
            interface: name.parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let o = &mut cfg.routing.ospf;
    o.instances.insert(
        "v2".into(),
        OspfInstance {
            name: "v2".into(),
            version: Default::default(),
            vrf: "main".into(),
            router_id: Some([10, 255, 0, 1].into()),
            redistribute: Vec::new(),
            out_filter_chain: None,
            originate_default: Default::default(),
            subscriber_pools: false,
            disabled: false,
            comment: String::new(),
        },
    );
    o.areas.insert(
        "bb".into(),
        OspfArea {
            name: "bb".into(),
            instance: "v2".into(),
            area_id: AreaId(0),
            kind: AreaType::Default,
            no_summaries: false,
            default_cost: None,
            nssa_translate: NssaTranslate::Candidate,
            disabled: false,
            comment: String::new(),
        },
    );
    let per = ifaces / templates.max(1);
    for t in 0..templates {
        let id = o.next_id();
        let mut tpl = OspfTemplate {
            id,
            area: "bb".into(),
            cost: Some(10 + (t % 50) as u16),
            auth: Some(AuthType::Sha256),
            auth_key: "k3y".into(),
            ..OspfTemplate::default()
        };
        if t % 10 == 9 {
            tpl.networks = vec![format!("10.{}.0.0/16", t % 64).parse().unwrap()];
        } else {
            tpl.interfaces = (0..per).map(|k| format!("vlan{}", t * per + k)).collect();
        }
        o.templates.push(tpl);
    }
    cfg
}

fn bench(c: &mut Criterion) {
    let cfg = config(4_000, 1_000);
    let mut after = cfg.clone();
    if let Some(t) = after.routing.ospf.templates.get_mut(3) {
        t.cost = Some(999);
    }
    c.bench_function("ospf bindings 4000 ifaces x 1000 templates", |b| {
        b.iter(|| black_box(corerouter_proto_ospf::bind::bindings(black_box(&cfg)).len()))
    });
    c.bench_function("ospf render 4000 ifaces", |b| {
        b.iter(|| {
            black_box(
                corerouter_proto_ospf::frr::render(black_box(&cfg), &|s| {
                    Some(s.stored().to_owned())
                })
                .map(|t| t.len()),
            )
        })
    });
    c.bench_function("ospf validate 1000 templates", |b| {
        b.iter(|| black_box(corerouter_proto_ospf::validate(black_box(&cfg)).len()))
    });
    c.bench_function("ospf impact one cost changed", |b| {
        b.iter(|| {
            black_box(
                corerouter_proto_ospf::impact::changes(black_box(&cfg), black_box(&after)).len(),
            )
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

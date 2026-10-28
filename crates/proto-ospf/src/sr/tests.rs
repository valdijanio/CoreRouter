use corerouter_model::config::{AddressEntry, Interface};
use corerouter_model::mpls::StaticLsp;
use corerouter_model::ospf::OspfTemplate;
use corerouter_model::ospf_sr::{SegmentRouting, SrNode, SrPrefix};
use corerouter_model::types::ItemId;

use super::*;
use crate::tests::sample;

fn lo(cfg: &mut Config, name: &str, addr: &str) {
    let i: Interface =
        serde_json::from_value(serde_json::json!({"name": name, "kind": {"type": "loopback"}}))
            .unwrap();
    cfg.interfaces.insert(name.parse().unwrap(), i);
    let id = ItemId(100 + u32::try_from(cfg.ip.addresses.len()).unwrap());
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: addr.parse().unwrap(),
        interface: name.parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
}

/// The OSPF sample with a loopback in the backbone, SR on, one SID.
pub(crate) fn sr_sample() -> Config {
    let mut cfg = sample();
    lo(&mut cfg, "lo0", "10.255.0.1/32");
    let o = &mut cfg.routing.ospf;
    let id = o.next_id();
    o.templates.push(OspfTemplate {
        id,
        area: "backbone".into(),
        interfaces: vec!["lo0".into()],
        passive: true,
        ..OspfTemplate::default()
    });
    o.segment_routing = Some(SegmentRouting::new("v2"));
    let id = o.next_id();
    o.prefix_sids.push(PrefixSid {
        id,
        prefix: "10.255.0.1/32".parse().unwrap(),
        index: 1,
        behavior: SidBehavior::Php,
        disabled: false,
        comment: String::new(),
    });
    cfg
}

fn issues(cfg: &Config) -> Vec<String> {
    crate::validate(cfg)
        .into_iter()
        .map(|i| i.message)
        .collect()
}

#[test]
fn the_sr_sample_is_valid_and_renders_for_ospfd() {
    let cfg = sr_sample();
    assert_eq!(issues(&cfg), Vec::<String>::new());
    let text = crate::frr::render(&cfg, &|s| Some(s.stored().to_owned())).unwrap();
    let want = " capability opaque\n router-info area\n segment-routing on\n segment-routing prefix 10.255.0.1/32 index 1\n";
    assert!(text.contains(want), "{text}");
    // Default blocks: FRR prints no global-block line.
    assert!(!text.contains("global-block"), "{text}");
}

#[test]
fn blocks_and_flags_render_as_ospfd_prints_them() {
    let mut cfg = sr_sample();
    let o = &mut cfg.routing.ospf;
    if let Some(sr) = o.segment_routing.as_mut() {
        sr.srlb = LabelBlock {
            start: 5000,
            end: 5999,
        };
        sr.node_msd = Some(8);
    }
    o.prefix_sids[0].behavior = SidBehavior::ExplicitNull;
    let inst = cfg.routing.ospf.instances["v2"].clone();
    let l = router_lines(&cfg, &inst);
    // Only the SRLB differs: FRR prints the default SRGB with it.
    assert!(
        l.contains(&"segment-routing global-block 16000 23999 local-block 5000 5999".to_owned()),
        "{l:?}"
    );
    assert!(l.contains(&"segment-routing node-msd 8".to_owned()));
    assert!(l.contains(&"segment-routing prefix 10.255.0.1/32 index 1 explicit-null".to_owned()));
    // The blocks are typed before SR starts, the prefixes after.
    let pos = |s: &str| l.iter().position(|x| x.starts_with(s)).unwrap();
    assert!(pos("segment-routing global-block") < pos("segment-routing on"));
    assert!(pos("segment-routing on") < pos("segment-routing prefix"));
    cfg.routing.ospf.prefix_sids[0].behavior = SidBehavior::NoPhp;
    assert!(
        router_lines(&cfg, &inst)
            .contains(&"segment-routing prefix 10.255.0.1/32 index 1 no-php-flag".to_owned())
    );
}

#[test]
fn disabled_or_absent_sr_renders_nothing() {
    let mut cfg = sr_sample();
    if let Some(sr) = cfg.routing.ospf.segment_routing.as_mut() {
        sr.disabled = true;
    }
    let inst = cfg.routing.ospf.instances["v2"].clone();
    assert!(router_lines(&cfg, &inst).is_empty());
    cfg.routing.ospf.segment_routing = None;
    assert!(
        issues(&cfg)
            .iter()
            .any(|m| m.contains("need Segment Routing"))
    );
}

#[test]
fn blocks_are_checked_against_each_other_ldp_and_static_lsps() {
    let mut cfg = sr_sample();
    if let Some(sr) = cfg.routing.ospf.segment_routing.as_mut() {
        sr.srgb = LabelBlock { start: 10, end: 20 };
        sr.srlb = LabelBlock { start: 15, end: 30 };
    }
    let v = issues(&cfg);
    assert!(v.iter().any(|m| m.contains("RFC 3032 §2.1")), "{v:?}");
    assert!(v.iter().any(|m| m.contains("overlaps the SRGB")), "{v:?}");

    let mut cfg = sr_sample();
    cfg.routing.mpls.settings.dynamic_label_range = (16, 20_000);
    cfg.routing.mpls.statics.insert(
        16_005,
        StaticLsp {
            nexthop: "10.0.1.2".parse().unwrap(),
            interface: None,
            out_labels: vec![],
            disabled: false,
            comment: String::new(),
        },
    );
    let v = issues(&cfg);
    assert!(
        v.iter().any(|m| m.contains("overlaps the LDP labels")),
        "{v:?}"
    );
    assert!(v.iter().any(|m| m.contains("kernel label table")), "{v:?}");
    assert!(
        v.iter().any(|m| m.contains("static LSP label 16005")),
        "{v:?}"
    );
}

#[test]
fn ldp_gets_the_labels_above_the_sr_blocks() {
    let cfg = sr_sample();
    assert_eq!(
        dynamic_block(&cfg),
        Some(LabelBlock {
            start: 24_000,
            end: MAX_LABEL
        })
    );
    // High blocks: the larger stretch is below them.
    let mut cfg = sr_sample();
    if let Some(sr) = cfg.routing.ospf.segment_routing.as_mut() {
        sr.srgb = LabelBlock {
            start: 900_000,
            end: 907_999,
        };
        sr.srlb = LabelBlock {
            start: 908_000,
            end: 908_999,
        };
    }
    assert_eq!(
        dynamic_block(&cfg),
        Some(LabelBlock {
            start: 16,
            end: 899_999
        })
    );
    // A range the operator set is theirs (checked, not moved).
    cfg.routing.mpls.settings.dynamic_label_range = (16, 50_000);
    assert_eq!(dynamic_block(&cfg), None);
    cfg.routing.ospf.segment_routing = None;
    cfg.routing.mpls.settings = Default::default();
    assert_eq!(dynamic_block(&cfg), None);
}

#[test]
fn sids_live_on_announced_loopbacks_inside_the_srgb_once() {
    let mut cfg = sr_sample();
    let o = &mut cfg.routing.ospf;
    let mut dup = o.prefix_sids[0].clone();
    dup.id = ItemId(90);
    o.prefix_sids.push(dup.clone());
    dup.id = ItemId(91);
    dup.prefix = "10.0.1.1/32".parse().unwrap(); // ether1's network, not a loopback
    dup.index = 9000;
    o.prefix_sids.push(dup);
    let v = issues(&cfg);
    assert!(v.iter().any(|m| m.contains("already the SID of")), "{v:?}");
    assert!(v.iter().any(|m| m.contains("already has a SID")), "{v:?}");
    assert!(
        v.iter().any(|m| m.contains("not an address of a loopback")),
        "{v:?}"
    );
    assert!(
        v.iter().any(|m| m.contains("below the SRGB size 8000")),
        "{v:?}"
    );

    // A loopback no template takes is not announced.
    let mut cfg = sr_sample();
    lo(&mut cfg, "lo1", "10.255.9.9/32");
    cfg.routing.ospf.prefix_sids[0].prefix = "10.255.9.9/32".parse().unwrap();
    assert!(
        issues(&cfg)
            .iter()
            .any(|m| m.contains("OSPF does not announce it"))
    );
}

#[test]
fn sr_needs_the_v2_instance_in_main() {
    let mut cfg = sr_sample();
    if let Some(i) = cfg.routing.ospf.instances.get_mut("v2") {
        i.version = Version::V3;
    }
    assert!(
        issues(&cfg)
            .iter()
            .any(|m| m.contains("ospf6d has no SR-MPLS"))
    );
    let mut cfg = sr_sample();
    if let Some(sr) = cfg.routing.ospf.segment_routing.as_mut() {
        sr.instance = "nope".into();
        sr.node_msd = Some(0);
    }
    let v = issues(&cfg);
    assert!(
        v.iter().any(|m| m.contains("no OSPF instance nope")),
        "{v:?}"
    );
    assert!(v.iter().any(|m| m.contains("1..=16 labels")), "{v:?}");
}

fn node(rid: [u8; 4], prefixes: &[(&str, u32)]) -> SrNode {
    SrNode {
        router_id: u32::from(Ipv4Addr::from(rid)),
        srgb_start: 16_000,
        srgb_size: 8000,
        srlb_start: 15_000,
        srlb_size: 1000,
        msd: None,
        prefixes: prefixes
            .iter()
            .map(|(p, sid)| {
                let n: Ipv4Net = p.parse().unwrap();
                SrPrefix {
                    prefix: u32::from(n.addr()),
                    plen: n.prefix_len(),
                    sid: *sid,
                    in_label: 16_000 + sid,
                    out: vec![],
                }
            })
            .collect(),
        adjacencies: 1,
    }
}

#[test]
fn conflicts_name_both_sides() {
    let cfg = sr_sample();
    let db = SrDb {
        router_id: Some(u32::from(Ipv4Addr::new(10, 255, 0, 1))),
        nodes: vec![
            node([10, 255, 0, 1], &[("10.255.0.1/32", 1)]),
            node([10, 255, 0, 2], &[("10.255.0.2/32", 1)]),
            node(
                [10, 255, 0, 3],
                &[("10.255.0.3/32", 3), ("10.255.0.33/32", 3)],
            ),
            node([10, 255, 0, 4], &[("10.255.0.3/32", 4)]),
        ],
    };
    let c = conflicts(&db, &cfg.routing.ospf.prefix_sids);
    assert!(
        c.iter().any(|c| c.kind == "index"
            && c.index == 1
            && c.router == "10.255.0.2"
            && c.prefix == "10.255.0.1/32"),
        "{c:?}"
    );
    assert!(c.iter().any(|c| c.kind == "index" && c.index == 3), "{c:?}");
    assert!(
        c.iter()
            .any(|c| c.kind == "prefix" && c.prefix == "10.255.0.3/32"),
        "{c:?}"
    );
    assert!(conflicts(&SrDb::default(), &cfg.routing.ospf.prefix_sids).is_empty());
}

#[test]
fn the_proposed_index_is_the_last_octet_when_free() {
    let srgb = corerouter_model::ospf_sr::DEFAULT_SRGB;
    let p: Ipv4Net = "10.255.0.7/32".parse().unwrap();
    assert_eq!(propose_index(p, srgb, &[], &SrDb::default()), Some(7));
    let db = SrDb {
        router_id: None,
        nodes: vec![node([10, 255, 0, 9], &[("10.255.0.9/32", 7)])],
    };
    assert_eq!(propose_index(p, srgb, &[], &db), Some(1));
    // Anycast: another router has the prefix; its index is taken.
    let db = SrDb {
        router_id: None,
        nodes: vec![node([10, 255, 0, 9], &[("10.255.0.7/32", 42)])],
    };
    assert_eq!(propose_index(p, srgb, &[], &db), Some(42));
    let tiny = LabelBlock {
        start: 16_000,
        end: 16_015,
    };
    let p: Ipv4Net = "10.255.0.200/32".parse().unwrap();
    assert_eq!(propose_index(p, tiny, &[], &SrDb::default()), Some(1));
}

#[test]
fn the_preview_lists_labels_mtu_and_input() {
    let running = sample();
    let mut cfg = sr_sample();
    if let Some(i) = cfg.interfaces.get_mut(&"ether1".parse().unwrap()) {
        i.mtu = 1500;
    }
    let routes = vec![
        OspfRoute {
            prefix: "10.255.0.2/32".into(),
            ..OspfRoute::default()
        },
        OspfRoute {
            prefix: "10.255.0.5/32".into(),
            ..OspfRoute::default()
        },
        OspfRoute {
            prefix: "172.16.0.0/24".into(),
            ..OspfRoute::default()
        },
    ];
    let db = SrDb {
        router_id: None,
        nodes: vec![node([10, 255, 0, 2], &[("10.255.0.2/32", 2)])],
    };
    let p = preview(&cfg, &running, Some(&db), &routes, 1);
    assert_eq!(p.switches, Some("on"));
    assert_eq!(p.by_label, vec!["10.255.0.2/32".to_owned()]);
    assert!(p.maybe.is_empty());
    assert_eq!(p.own, vec![("10.255.0.1/32".to_owned(), 1, 16_001)]);
    assert_eq!(p.mtu.len(), 1, "{p:?}");
    assert_eq!(p.mtu[0].needed, 1504);
    assert_eq!(p.no_mpls_input, vec!["ether1".to_owned()]);
    assert_eq!(p.ldp_block.as_deref(), Some("24000-1048575"));
    // Not read yet: every /32 is a "maybe".
    let p = preview(&cfg, &running, None, &routes, 1);
    assert_eq!(p.maybe.len(), 2);
    assert_eq!(
        preview(&running, &cfg, None, &routes, 1).switches,
        Some("off")
    );
}

#[test]
fn the_kernel_loopback_gets_no_network_type() {
    // FRR takes a prefix SID only on an IFF_LOOPBACK interface (Linux lo),
    // and refuses a network type there (lab VM, FRR 10.7.1).
    let mut cfg = sr_sample();
    lo(&mut cfg, "lo", "10.255.0.5/32");
    if let Some(t) = cfg.routing.ospf.templates.last_mut() {
        t.interfaces = vec!["lo0".into(), "lo".into()];
    }
    let text = crate::frr::render(&cfg, &|s| Some(s.stored().to_owned())).unwrap();
    assert!(
        text.contains("interface lo\n ip ospf area 0.0.0.0\n ip ospf passive\nexit\n"),
        "{text}"
    );
    assert!(
        text.contains("interface lo0\n ip ospf network broadcast\n"),
        "{text}"
    );
}

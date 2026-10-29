//! Convergence on known topologies, failures, determinism and the decision
//! process checked against `proto_bgp::decision`.

use std::cmp::Ordering;
use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::bgp_rib::{AsSegment, BgpPath, Origin, PeerKind, SegmentKind};
use corerouter_proto_bgp::decision;
use ipnet::Ipv4Net;
use proptest::prelude::*;

use crate::preset::{self, BgpMode};
use crate::{Fault, LinkId, LinkState, NodeId, Proto, RecordKind, SEC, Simulation};

fn net(s: &str) -> Ipv4Net {
    s.parse().unwrap()
}

fn has(sim: &Simulation, node: u32, prefix: &str) -> Option<crate::FibRoute> {
    sim.routes(NodeId(node))
        .into_iter()
        .find(|r| r.prefix == net(prefix))
}

fn link_between(sim: &Simulation, a: u32, b: u32) -> LinkId {
    sim.links()
        .into_iter()
        .find(|l| (l.a, l.b) == (NodeId(a), NodeId(b)) || (l.a, l.b) == (NodeId(b), NodeId(a)))
        .unwrap()
        .id
}

fn converged(scn: &preset::Scenario, secs: u64) -> Simulation {
    let mut sim = scn.build(7).unwrap();
    assert!(sim.advance(secs * SEC, u64::MAX));
    sim
}

#[test]
fn bgp_multipath_like_frr() {
    // FRR installs every path equal to the best down to the IGP cost
    // (maximum-paths 64 by default; our render leaves it): the lab VM's
    // FRR showed both of these (tests/frr_fidelity.rs).
    let sim = converged(&preset::square(), 60);
    // R2: the upstream's /24 through R1 and R3 (iBGP, next-hop-self, both
    // loopbacks 10 away).
    let r = has(&sim, 1, "198.51.100.0/24").unwrap();
    let mut want = vec![link_between(&sim, 0, 1), link_between(&sim, 1, 2)];
    want.sort_unstable();
    assert_eq!(r.links, want, "{r:?}");
    // R4: the customer /16 from R1 and R3 (eBGP, the same AS path).
    let r = has(&sim, 3, "100.64.0.0/16").unwrap();
    let mut want = vec![link_between(&sim, 3, 0), link_between(&sim, 3, 2)];
    want.sort_unstable();
    assert_eq!(r.links, want, "{r:?}");
    // A longer AS path is no member: on a 5-ring with eBGP, R1 reaches R3's
    // /24 through R2 only (2 ASes against 3 the other way).
    let ring = converged(&preset::ring(5, preset::BgpMode::Ebgp), 60);
    let r = has(&ring, 0, &preset::customer(2).to_string()).unwrap();
    assert_eq!(r.links, vec![link_between(&ring, 0, 1)], "{r:?}");
}

#[test]
fn every_seed_converges() {
    // The handshake must survive a lost first answer (a route back not
    // there yet), whatever the timing a seed gives.
    for seed in 0..20 {
        let mut sim = preset::square().build(seed).unwrap();
        sim.advance(60 * SEC, u64::MAX);
        for n in sim.nodes() {
            assert_eq!(
                n.bgp_established,
                n.bgp_peers,
                "seed {seed} {}: {:?}",
                n.name,
                sim.bgp_peers(n.id)
            );
        }
    }
}

#[test]
fn square_converges() {
    let sim = converged(&preset::square(), 60);
    for n in sim.nodes() {
        assert_eq!(
            n.bgp_established,
            n.bgp_peers,
            "{}: {:?}",
            n.name,
            sim.bgp_peers(n.id)
        );
    }
    // R2 learns the upstream's prefixes over iBGP; R4 the customer /16.
    let r = has(&sim, 1, "198.51.100.0/24").unwrap();
    assert_eq!(r.proto, Proto::Ibgp);
    assert_eq!(has(&sim, 3, "100.64.0.0/16").unwrap().proto, Proto::Ebgp);
    // OSPF carries the loopbacks inside AS 65000, not to R4.
    assert_eq!(has(&sim, 0, "10.255.0.2/32").unwrap().proto, Proto::Ospf);
    assert!(has(&sim, 3, "10.255.0.2/32").is_none());
    // Packets follow the tables end to end.
    let (path, arrived) = sim.trace(NodeId(3), "10.255.0.2".parse().unwrap());
    assert!(!arrived, "R4 has no route to R2's loopback: {path:?}");
    let (path, arrived) = sim.trace(NodeId(0), "10.255.0.2".parse().unwrap());
    assert!(arrived);
    assert_eq!(path, vec![NodeId(0), NodeId(1)]);
}

/// Every router reaches every other router's loopback and customer /24.
fn full_reachability(sim: &Simulation, n: usize) {
    for me in 0..n {
        for other in (0..n).filter(|o| *o != me) {
            let lo = format!("{}/32", preset::loopback(other));
            let cust = preset::customer(other).to_string();
            let me32 = u32::try_from(me).unwrap();
            assert!(has(sim, me32, &lo).is_some(), "R{} → {lo}", me + 1);
            assert!(has(sim, me32, &cust).is_some(), "R{} → {cust}", me + 1);
        }
    }
}

#[test]
fn ring_mesh_star_converge() {
    for scn in [
        preset::ring(8, BgpMode::Ebgp),
        preset::mesh(6, BgpMode::Ebgp),
        preset::star(7, BgpMode::Ebgp),
        preset::grid(9, BgpMode::Ebgp),
        preset::ring(5, BgpMode::Ibgp),
    ] {
        let n = scn.nodes.len();
        let sim = converged(&scn, 60);
        full_reachability(&sim, n);
        for v in sim.nodes() {
            assert_eq!(v.bgp_established, v.bgp_peers, "{} {}", scn.name, v.name);
        }
    }
}

#[test]
fn ospf_takes_the_cheapest_path_and_balances_equal_ones() {
    let mut sim = converged(&preset::ring(4, BgpMode::None), 60);
    // R1 → R3 (opposite corner): two paths of cost 20, both used.
    let r = has(&sim, 0, "10.255.0.3/32").unwrap();
    assert_eq!((r.metric, r.links.len()), (20, 2));
    // Make one dearer: only the other one is left.
    let l = link_between(&sim, 0, 1);
    sim.set_link(l, Some(100), Some(100), None).unwrap();
    let t = sim.now();
    sim.advance(t + 5 * SEC, u64::MAX);
    let r = has(&sim, 0, "10.255.0.3/32").unwrap();
    assert_eq!((r.metric, r.links.len()), (20, 1));
    assert_ne!(r.links, vec![l]);
}

#[test]
fn a_cut_link_reconverges_with_bfd() {
    let mut sim = converged(&preset::square(), 60);
    let l = link_between(&sim, 0, 1);
    let before = has(&sim, 0, "10.255.0.2/32").unwrap();
    assert_eq!(before.links, vec![l]);
    let t = sim.now();
    sim.schedule(t, Fault::LinkCut { link: l }).unwrap();
    sim.advance(t + 5 * SEC, u64::MAX);
    // BFD (300 ms × 3) saw it, OSPF went around through R3.
    let c = sim.convergence().unwrap();
    let detected = c.detected_after.unwrap();
    assert!((600_000..=900_000).contains(&detected), "{c:?}");
    assert!(c.igp_after.unwrap() < 2 * SEC, "{c:?}");
    let after = has(&sim, 0, "10.255.0.2/32").unwrap();
    assert_eq!(after.metric, 20);
    assert_ne!(after.links, vec![l]);
    // iBGP between loopbacks survives: nothing lost.
    assert_eq!(c.bgp_prefixes_now, c.bgp_prefixes_before);
    for n in sim.nodes() {
        assert_eq!(n.bgp_established, n.bgp_peers, "{}", n.name);
    }
    // Repaired: the direct path comes back.
    let t = sim.now();
    sim.schedule(t, Fault::LinkRestore { link: l }).unwrap();
    sim.advance(t + 30 * SEC, u64::MAX);
    assert_eq!(has(&sim, 0, "10.255.0.2/32").unwrap().links, vec![l]);
}

#[test]
fn without_bfd_the_dead_interval_decides() {
    let mut scn = preset::ring(4, BgpMode::None);
    for l in &mut scn.links {
        l.bfd = false;
    }
    let mut sim = converged(&scn, 60);
    let l = link_between(&sim, 0, 1);
    let t = sim.now();
    sim.schedule(t, Fault::LinkCut { link: l }).unwrap();
    sim.advance(t + 60 * SEC, u64::MAX);
    let c = sim.convergence().unwrap();
    let d = c.detected_after.unwrap();
    // RouterDeadInterval 40 s after the last hello (sent up to 10 s before).
    assert!((30 * SEC..=40 * SEC).contains(&d), "{c:?}");
}

#[test]
fn carrier_loss_is_immediate() {
    let mut sim = converged(&preset::square(), 60);
    let l = link_between(&sim, 0, 1);
    let t = sim.now();
    sim.schedule(t, Fault::LinkDown { link: l }).unwrap();
    sim.advance(t + SEC, u64::MAX);
    let c = sim.convergence().unwrap();
    assert_eq!(c.detected_after, Some(0));
    assert_eq!(sim.link(l).unwrap().state, LinkState::Down);
}

#[test]
fn an_upstream_link_failure_moves_to_the_other_exit() {
    let mut sim = converged(&preset::square(), 60);
    let up = link_between(&sim, 3, 0);
    assert_eq!(has(&sim, 0, "198.51.100.0/24").unwrap().proto, Proto::Ebgp);
    let t = sim.now();
    sim.schedule(t, Fault::LinkCut { link: up }).unwrap();
    sim.advance(t + 5 * SEC, u64::MAX);
    // eBGP with BFD dropped in under a second; R1 now goes through R3.
    let down = sim
        .records()
        .find(|r| matches!(&r.kind, RecordKind::BgpDown { reason, .. } if reason == "BFD down"))
        .unwrap();
    assert!(down.at - t <= 900_000);
    let r = has(&sim, 0, "198.51.100.0/24").unwrap();
    assert_eq!(r.proto, Proto::Ibgp);
    let c = sim.convergence().unwrap();
    // R1 lost its own eBGP copies but every router still has every prefix
    // (the sum counts best paths per router: unchanged).
    assert_eq!(c.bgp_prefixes_now, c.bgp_prefixes_before, "{c:?}");
}

#[test]
fn a_router_failure_and_its_return() {
    let mut sim = converged(&preset::square(), 60);
    let t = sim.now();
    sim.schedule(t, Fault::NodeDown { node: NodeId(1) })
        .unwrap();
    sim.advance(t + 5 * SEC, u64::MAX);
    // R2's /16 is gone from R4 once its iBGP neighbors noticed… which over
    // loopbacks without BFD is the next-hop check: R2's loopback left OSPF.
    assert!(has(&sim, 0, "10.255.0.2/32").is_none());
    assert!(has(&sim, 0, "100.64.0.0/16").is_none());
    assert!(sim.bgp_prefixes() < sim.convergence().unwrap().bgp_prefixes_before);
    let t = sim.now();
    sim.schedule(t, Fault::NodeUp { node: NodeId(1) }).unwrap();
    sim.advance(t + 60 * SEC, u64::MAX);
    assert!(has(&sim, 3, "100.64.0.0/16").is_some());
}

#[test]
fn ebgp_without_a_policy_exchanges_nothing() {
    // RFC 8212, as FRR's `bgp ebgp-requires-policy`.
    let scn = preset::ring(3, BgpMode::Ebgp);
    let plan = scn.plan().unwrap();
    let mut sim = Simulation::new(1);
    for n in &plan.nodes {
        let mut cfg = crate::NodeConfig::new(n.name.clone(), n.router_id);
        cfg.addresses.clone_from(&n.addresses);
        let mut neighbors = n.neighbors.clone();
        for nb in &mut neighbors {
            nb.input = None;
            nb.output = None;
        }
        cfg.bgp = Some(crate::BgpConfig {
            asn: n.asn,
            networks: n.networks.clone(),
            neighbors,
            policy: Arc::default(),
        });
        sim.add_node(cfg).unwrap();
    }
    for l in plan.links {
        sim.add_link(l).unwrap();
    }
    sim.advance(60 * SEC, u64::MAX);
    for n in sim.nodes() {
        assert_eq!(n.bgp_established, 2, "{}", n.name);
        assert_eq!(n.bgp_prefixes, 1, "{}: only its own", n.name);
    }
}

#[test]
fn a_wrong_remote_as_is_reported_once() {
    let scn = preset::ring(2, BgpMode::Ebgp);
    let plan = scn.plan().unwrap();
    let policy =
        Arc::new(corerouter_proto_bgp::filter::eval::Policy::build(&preset::accept_filter()).0);
    let mut sim = Simulation::new(1);
    for (i, n) in plan.nodes.iter().enumerate() {
        let mut cfg = crate::NodeConfig::new(n.name.clone(), n.router_id);
        cfg.addresses.clone_from(&n.addresses);
        let mut neighbors = n.neighbors.clone();
        if i == 0 {
            neighbors[0].remote_as = Some(1);
        }
        cfg.bgp = Some(crate::BgpConfig {
            asn: n.asn,
            networks: n.networks.clone(),
            neighbors,
            policy: policy.clone(),
        });
        sim.add_node(cfg).unwrap();
    }
    for l in plan.links {
        sim.add_link(l).unwrap();
    }
    sim.advance(120 * SEC, u64::MAX);
    let errors: Vec<_> = sim
        .records()
        .filter(|r| matches!(r.kind, RecordKind::BgpError { .. }))
        .collect();
    assert!(!errors.is_empty() && errors.len() <= 2, "{errors:?}");
    assert_eq!(sim.nodes()[0].bgp_established, 0);
    let peer = &sim.bgp_peers(NodeId(0))[0];
    assert!(
        peer.last_error.as_deref().unwrap().contains("expected 1"),
        "{peer:?}"
    );
}

fn run_with_faults(threads: usize, seed: u64) -> (u64, usize) {
    let scn = preset::grid(64, BgpMode::Ebgp);
    let mut sim = scn.build(seed).unwrap();
    sim.set_threads(threads);
    sim.advance(60 * SEC, u64::MAX);
    let t = sim.now();
    sim.schedule(t + SEC, Fault::LinkCut { link: LinkId(5) })
        .unwrap();
    sim.schedule(t + 2 * SEC, Fault::NodeDown { node: NodeId(20) })
        .unwrap();
    sim.schedule(
        t + 3 * SEC,
        Fault::Loss {
            link: LinkId(30),
            loss_pct: 50,
        },
    )
    .unwrap();
    sim.schedule(t + 20 * SEC, Fault::NodeUp { node: NodeId(20) })
        .unwrap();
    sim.advance(t + 120 * SEC, u64::MAX);
    (sim.fingerprint(), sim.records().len())
}

#[test]
fn same_seed_same_run_on_any_number_of_threads() {
    let one = run_with_faults(1, 42);
    assert_eq!(one, run_with_faults(1, 42));
    assert_eq!(one, run_with_faults(4, 42));
    assert_eq!(one, run_with_faults(8, 42));
}

#[test]
fn a_budget_stops_and_resumes_the_same_run() {
    let scn = preset::grid(25, BgpMode::Ebgp);
    let mut whole = scn.build(3).unwrap();
    whole.advance(30 * SEC, u64::MAX);
    let mut pieces = scn.build(3).unwrap();
    let mut calls = 0;
    while !pieces.advance(30 * SEC, 500) {
        calls += 1;
    }
    assert!(calls > 3);
    assert_eq!(whole.fingerprint(), pieces.fingerprint());
}

#[test]
fn step_moves_to_the_next_event() {
    let mut sim = preset::square().build(1).unwrap();
    let a = sim.step();
    let b = sim.step();
    assert!(b > a, "{a} {b}");
}

fn path_of(s: &crate::bgp::check::Side) -> BgpPath {
    BgpPath {
        peer: if s.local {
            "0.0.0.0".into()
        } else {
            s.addr.to_string()
        },
        peer_router_id: (!s.local).then_some(s.rid),
        peer_kind: if s.local {
            PeerKind::Local
        } else if s.ebgp {
            PeerKind::External
        } else {
            PeerKind::Internal
        },
        segments: if s.attrs.as_path.is_empty() {
            Vec::new()
        } else {
            vec![AsSegment {
                kind: SegmentKind::Sequence,
                asns: s.attrs.as_path.clone(),
            }]
        },
        as_path: String::new(),
        origin: match s.attrs.origin {
            0 => Origin::Igp,
            1 => Origin::Egp,
            _ => Origin::Incomplete,
        },
        med: s.attrs.med,
        local_pref: s.attrs.local_pref,
        weight: 0,
        next_hop: None,
        igp_metric: Some(s.igp),
        next_hop_reachable: true,
        valid: true,
        best: s.best,
        multipath: false,
        selection_reason: None,
        originator_id: None,
        cluster_list_len: 0,
        communities: Vec::new(),
        large_communities: Vec::new(),
        last_update: None,
        rpki: None,
        stale: false,
    }
}

fn side() -> impl Strategy<Value = crate::bgp::check::Side> {
    (
        any::<bool>(),
        any::<bool>(),
        proptest::collection::vec(64_600u32..64_603, 0..3),
        proptest::option::of(99u32..102),
        proptest::option::of(0u32..3),
        0u8..3,
        0u32..3,
        1u8..4,
        1u8..4,
    )
        .prop_map(|(local, ebgp, as_path, lp, med, origin, igp, rid, addr)| {
            crate::bgp::check::Side {
                local,
                ebgp: ebgp && !local,
                attrs: crate::bgp::Attrs {
                    as_path: if local { Vec::new() } else { as_path },
                    next_hop: Ipv4Addr::UNSPECIFIED,
                    local_pref: lp,
                    med,
                    origin,
                    communities: Vec::new(),
                },
                igp: if local { 0 } else { igp },
                rid: Ipv4Addr::new(10, 0, 0, rid),
                addr: Ipv4Addr::new(192, 0, 2, addr),
                best: false,
            }
        })
}

proptest! {
    /// The simulator decides as `proto_bgp::decision` (FRR's order) does.
    #[test]
    fn decision_matches_proto_bgp(
        // At most one locally originated side, filtered in the strategy:
        // a `prop_assume!` here rejects ~1 case in 4, and at the nightly's
        // 4096 cases that passes proptest's 1024 global rejects.
        (mut a, mut b) in (side(), side()).prop_filter("one local side at most", |(a, b)| !(a.local && b.local)),
        best in 0u8..3,
    ) {
        a.best = best == 1;
        b.best = best == 2;
        let ours = crate::bgp::check::compare(&a, &b);
        let theirs = decision::compare(&path_of(&a), &path_of(&b), a.best, b.best, &decision::Options::default());
        // Two different neighbors with the same address cannot exist.
        prop_assume!(a.local || b.local || a.addr != b.addr || ours != Ordering::Equal);
        prop_assert_eq!(ours, theirs.order, "step {:?}", theirs.step);
    }
}

#[test]
fn the_routers_own_ospf_config_decides() {
    use crate::OspfIface;
    let mut sim = converged(&preset::ring(4, BgpMode::None), 60);
    let iface = |name: &str, cost: Option<u32>, passive: bool| OspfIface {
        iface: name.into(),
        cost,
        hello: None,
        dead: None,
        passive,
        bfd: false,
    };
    // R1: ether1 (to R2) costs 100, ether2 (to R4) is passive, the
    // loopback is in no template.
    let mut cfg = sim.config(NodeId(0)).unwrap().clone();
    cfg.ospf_ifaces = Some(vec![
        iface("ether1", Some(100), false),
        iface("ether2", None, true),
    ]);
    sim.set_config(NodeId(0), cfg).unwrap();
    let t = sim.now();
    sim.advance(t + 60 * SEC, u64::MAX);
    let n = sim.ospf_neighbors(NodeId(0));
    assert_eq!(
        n.iter().find(|x| x.iface == "ether1").unwrap().state,
        "full"
    );
    assert_ne!(
        n.iter().find(|x| x.iface == "ether2").unwrap().state,
        "full",
        "{n:?}"
    );
    assert!(
        has(&sim, 1, "10.255.0.1/32").is_none(),
        "R1's loopback is not in OSPF"
    );
    // R1 → R3 only through R2 now: 100 + 10.
    assert_eq!(has(&sim, 0, "10.255.0.3/32").unwrap().metric, 110);
    // The passive interface's subnet is still advertised (a stub).
    let r3 = has(&sim, 2, "10.0.0.12/30").unwrap();
    assert_eq!(r3.proto, Proto::Ospf);
}

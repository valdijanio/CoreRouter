//! The virtual lab's OSPF (G3.4b): without FRR there is no daemon to read,
//! so the neighbors, the LSDB and the routes are made up from the config —
//! one neighbor per active interface the templates take, each the door to
//! a small ring of routers and a transit LAN, and one ASBR announcing a
//! default. Deterministic (the same config gives the same network), and
//! every answer built from it says `source: "virtual lab sample"`.
//! Interface 2 (when there is one) is left in ExStart, so the Diagnose has
//! something to explain.

use std::net::Ipv4Addr;

use corerouter_model::Config;
use corerouter_model::ospf::Version;
use corerouter_model::ospf_state::{Link, Lsa, Lsdb, OspfIfState, OspfNeighbor, OspfRoute};

use crate::bind::bindings;
use crate::topology::{Node, graphs, path};

/// Routers behind each neighbor.
const RING: u8 = 3;

fn rid(a: u8, b: u8) -> u32 {
    u32::from(Ipv4Addr::new(10, 250, a, b))
}

/// What the lab shows for instance `instance` of `cfg`.
pub fn lab(
    cfg: &Config,
    instance: &str,
) -> (Vec<OspfNeighbor>, Vec<OspfIfState>, Lsdb, Vec<OspfRoute>) {
    let Some(inst) = cfg.routing.ospf.instances.get(instance) else {
        return Default::default();
    };
    let me = inst.router_id.map_or(rid(255, 1), u32::from);
    let binds: Vec<_> = bindings(cfg)
        .into_iter()
        .filter(|b| b.instance.name == instance)
        .collect();
    let mut db = Lsdb {
        version: inst.version.number(),
        router_id: Some(me),
        ..Lsdb::default()
    };
    let mut nbrs = Vec::new();
    let mut ifs = Vec::new();
    // Our router LSA of each area: the links of that area's interfaces.
    let mut my_links: std::collections::BTreeMap<u32, Vec<Link>> =
        std::collections::BTreeMap::new();
    let addrs = crate::bind::addresses(cfg, inst.version == Version::V3);
    for (i, b) in binds.iter().enumerate() {
        let i = u8::try_from(i.min(200)).unwrap_or(200);
        let area = b.area.area_id.0;
        let cost = b.template.cost.unwrap_or(10);
        let state = if b.template.passive {
            "DR"
        } else if b.template.kind == corerouter_model::ospf::NetworkType::Ptp {
            "Point-To-Point"
        } else {
            "DR"
        };
        ifs.push(OspfIfState {
            instance: instance.to_owned(),
            version: inst.version.number(),
            interface: b.interface.to_string(),
            area: Some(b.area.area_id.to_string()),
            network_type: Some(b.template.kind.name().to_owned()),
            state: Some(state.to_owned()),
            address: addrs
                .get(&b.interface)
                .and_then(|v| v.first())
                .map(ToString::to_string),
            cost: Some(u32::from(cost)),
            mtu: Some(1500),
            mtu_mismatch_detection: Some(!b.template.mtu_ignore),
            hello: Some(u32::from(b.template.hello_interval.unwrap_or(10))),
            dead: Some(u32::from(b.template.dead_interval.unwrap_or(40))),
            dr: None,
            bdr: None,
            passive: b.template.passive,
            neighbors: u32::from(!b.template.passive),
            adjacent: u32::from(!b.template.passive && i != 1),
        });
        for a in addrs.get(&b.interface).map_or(&[][..], Vec::as_slice) {
            if let ipnet::IpNet::V4(n) = a {
                my_links.entry(area).or_default().push(Link {
                    kind: 3,
                    id: u32::from(n.network()),
                    data: u32::from(n.netmask()),
                    metric: cost,
                });
            }
        }
        if b.template.passive {
            continue;
        }
        let nb = rid(i, 1);
        let full = i != 1;
        nbrs.push(OspfNeighbor {
            instance: instance.to_owned(),
            version: inst.version.number(),
            router_id: Ipv4Addr::from(nb).to_string(),
            address: format!("10.254.{i}.2"),
            interface: b.interface.to_string(),
            area: Some(b.area.area_id.to_string()),
            state: if full { "Full" } else { "ExStart" }.to_owned(),
            role: if b.template.kind == corerouter_model::ospf::NetworkType::Ptp {
                "ptp"
            } else {
                "DR"
            }
            .to_owned(),
            priority: Some(1),
            state_secs: Some(if full { 3_600 * u64::from(i + 1) } else { 420 }),
            dead_secs: Some(34),
            bfd: b.template.bfd.as_ref().map(|_| "up".to_owned()),
            retransmit: 0,
            request: 0,
            summary: if full { 0 } else { 12 },
        });
        if !full {
            continue;
        }
        my_links.entry(area).or_default().push(Link {
            kind: 1,
            id: nb,
            data: 0,
            metric: cost,
        });
        // The neighbor and its ring.
        let ring: Vec<u32> = (0..RING).map(|k| rid(i, k + 2)).collect();
        let push = |db: &mut Lsdb, adv: u32, links: Vec<Link>, flags: u8| {
            let start = u32::try_from(db.links.len()).unwrap_or(u32::MAX);
            let count = u16::try_from(links.len()).unwrap_or(0);
            db.links.extend(links);
            db.lsas.push(Lsa {
                kind: 1,
                area,
                id: adv,
                adv,
                age: 120,
                seq: 0x8000_0002,
                link_start: start,
                link_count: count,
                flags,
                ..Lsa::default()
            });
        };
        let first = ring.first().copied().unwrap_or(nb);
        let last = ring.last().copied().unwrap_or(nb);
        push(
            &mut db,
            nb,
            vec![
                Link {
                    kind: 1,
                    id: me,
                    data: 0,
                    metric: cost,
                },
                Link {
                    kind: 1,
                    id: first,
                    data: 0,
                    metric: 10,
                },
                Link {
                    kind: 1,
                    id: last,
                    data: 0,
                    metric: 30,
                },
            ],
            0,
        );
        let lan = u32::from(Ipv4Addr::new(10, 253, i, 1));
        for (k, r) in ring.iter().enumerate() {
            let prev = if k == 0 {
                nb
            } else {
                ring.get(k - 1).copied().unwrap_or(nb)
            };
            let next = ring.get(k + 1).copied().unwrap_or(nb);
            let mut links = vec![
                Link {
                    kind: 1,
                    id: prev,
                    data: 0,
                    metric: if k == 0 { 10 } else { 20 },
                },
                Link {
                    kind: 1,
                    id: next,
                    data: 0,
                    metric: if k + 1 == ring.len() { 30 } else { 20 },
                },
                Link {
                    kind: 3,
                    id: u32::from(Ipv4Addr::new(172, 16, i, 0))
                        + u32::try_from(k).unwrap_or(0) * 256,
                    data: u32::from(Ipv4Addr::new(255, 255, 255, 0)),
                    metric: 1,
                },
            ];
            if k >= 1 {
                links.push(Link {
                    kind: 2,
                    id: lan,
                    data: 0,
                    metric: 5,
                });
            }
            push(&mut db, *r, links, if k + 1 == ring.len() { 2 } else { 0 });
        }
        // The transit LAN of the last two ring routers.
        let att: Vec<u32> = ring.iter().skip(1).copied().collect();
        let start = u32::try_from(db.attached.len()).unwrap_or(u32::MAX);
        db.attached.extend(&att);
        db.lsas.push(Lsa {
            kind: 2,
            area,
            id: lan,
            adv: att.first().copied().unwrap_or(nb),
            age: 300,
            seq: 0x8000_0001,
            link_start: start,
            link_count: u16::try_from(att.len()).unwrap_or(0),
            flags: 24,
            plen: 24,
            ..Lsa::default()
        });
        if i == 0 {
            db.lsas.push(Lsa {
                kind: 5,
                area: u32::MAX,
                id: 0,
                adv: last,
                age: 60,
                seq: 0x8000_0001,
                metric: 1 | 1 << 31,
                ..Lsa::default()
            });
        }
    }
    for (i, (area, links)) in my_links.into_iter().enumerate() {
        let start = u32::try_from(db.links.len()).unwrap_or(u32::MAX);
        let count = u16::try_from(links.len()).unwrap_or(0);
        db.links.extend(links);
        db.lsas.insert(
            i,
            Lsa {
                kind: 1,
                area,
                id: me,
                adv: me,
                age: 30,
                seq: 0x8000_0005,
                link_start: start,
                link_count: count,
                ..Lsa::default()
            },
        );
    }
    let routes = routes(&db, instance, me, &nbrs);
    (nbrs, ifs, db, routes)
}

/// The routes the lab's network gives (the SPF over the sample).
fn routes(db: &Lsdb, instance: &str, me: u32, nbrs: &[OspfNeighbor]) -> Vec<OspfRoute> {
    let mut out = Vec::new();
    for (area, g) in graphs(db) {
        for (p, _, _) in &g.prefixes {
            let Some(hops) = path(&g, me, p.addr()) else {
                continue;
            };
            let total = hops.last().map_or(0, |h| h.total);
            let via = hops.get(1).and_then(|h| match h.node {
                Node::Router(r) => nbrs
                    .iter()
                    .find(|n| n.router_id == Ipv4Addr::from(r).to_string()),
                Node::Network(_) => None,
            });
            out.push(OspfRoute {
                instance: instance.to_owned(),
                prefix: p.to_string(),
                kind: "intra-area".into(),
                cost: total,
                type2_cost: None,
                area: Some(Ipv4Addr::from(area).to_string()),
                nexthops: vec![match via {
                    Some(n) => (Some(n.address.clone()), n.interface.clone()),
                    None => (
                        None,
                        hops.first().map(|_| "local".to_owned()).unwrap_or_default(),
                    ),
                }],
            });
        }
    }
    out.sort_by(|a, b| a.prefix.cmp(&b.prefix));
    out.dedup_by(|a, b| a.prefix == b.prefix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample;

    #[test]
    fn the_lab_has_a_network_around_the_config() {
        let mut cfg = sample();
        cfg.routing.ospf.templates[1].passive = false;
        let (n, i, db, r) = lab(&cfg, "v2");
        assert_eq!(n.len(), 2);
        assert_eq!(n[1].state, "ExStart");
        assert_eq!(i.len(), 2);
        let g = graphs(&db);
        assert!(g[&0].nodes.len() >= 5, "{:?}", g[&0].nodes);
        assert!(r.iter().any(|r| r.prefix.starts_with("172.16.0.")), "{r:?}");
        assert_eq!(lab(&cfg, "v2").2, db, "deterministic");
    }
}

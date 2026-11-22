//! The lab's connection table (G2.2): a deterministic set of connections
//! made from the applied config, so `IP › Firewall › Connections` has
//! something real-looking to show without a kernel: CGNAT subscribers
//! going out through their slot (some fast-tracked in software or
//! hardware, to show the Via column), and a few of the router's own.
//! Killed connections stay away until the config changes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::cgnat::{Mode, Slot};
use corerouter_model::{Config, ItemId};

use crate::conntrack::{Conn, Stats, Tuple, status};

/// Subscribers of each pool that get connections in the lab.
const SUBSCRIBERS: u64 = 300;
/// The lab's `nf_conntrack_max`.
pub const LAB_MAX: u64 = 262_144;

/// A small LCG: the same table every time.
fn mix(x: u64) -> u64 {
    x.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
        >> 17
}

/// Subscribers of each blocks-mode pool the lab pretends are online.
pub const ONLINE: u64 = 40;

/// The lab's online subscribers of blocks-mode pools without a block.
pub fn waiting(
    cfg: &Config,
    blocks: &BTreeMap<(ItemId, Ipv4Addr), Slot>,
) -> Vec<crate::cgnat::Waiting> {
    let mut out = Vec::new();
    for p in cfg
        .ip
        .cgnat
        .pools
        .iter()
        .filter(|p| !p.disabled && p.mode == Mode::Blocks)
    {
        let Ok(l) = p.layout() else { continue };
        for i in 0..l.subscribers().min(ONLINE) {
            if let Some(sub) = l.subscriber(i)
                && !blocks.contains_key(&(p.id, sub))
                && cfg.ip.cgnat.exception_of(sub).is_none()
            {
                out.push(crate::cgnat::Waiting {
                    pool: p.id,
                    subscriber: sub,
                });
            }
        }
    }
    out
}

/// The ports of the lab's flowtable (every one exists in the lab).
pub fn fastpath_ports(cfg: &Config) -> Vec<String> {
    corerouter_firewall::fastpath::devices(&cfg.ip.fastpath, cfg, |n| {
        cfg.interfaces.keys().any(|k| k.as_str() == n)
    })
}

pub fn table(
    cfg: &Config,
    killed: &BTreeSet<u32>,
    blocks: &BTreeMap<(ItemId, Ipv4Addr), Slot>,
) -> Vec<Conn> {
    let mut out = Vec::new();
    let servers = [
        Ipv4Addr::new(142, 250, 79, 46),
        Ipv4Addr::new(157, 240, 12, 35),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(200, 160, 2, 3),
    ];
    let fast = cfg.ip.fastpath.enabled;
    let hw = fast
        && cfg.ip.fastpath.hw_offload != corerouter_model::fastpath::HwOffload::No
        && crate::virt::LAB_SWITCHDEV
            .iter()
            .any(|p| fastpath_ports(cfg).iter().any(|d| d == p));
    let mut push = |c: Conn| {
        if !killed.contains(&c.id) {
            out.push(c);
        }
    };
    for p in cfg.ip.cgnat.pools.iter().filter(|p| !p.disabled) {
        let Ok(l) = p.layout() else { continue };
        for i in 0..l.subscribers().min(SUBSCRIBERS) {
            let Some(sub) = l.subscriber(i) else { continue };
            // Blocks mode: only subscribers with a block talk.
            let slot = match p.mode {
                Mode::Deterministic => l.slot(i),
                Mode::Blocks => blocks.get(&(p.id, sub)).copied(),
            };
            let Some(slot) = slot else { continue };
            if cfg.ip.cgnat.exception_of(sub).is_some() {
                continue;
            }
            // A few heavy users, most light: like a real access network.
            // Every 17th subscriber (from the 4th) is a heavy one.
            let heavy = i % 17 == 3;
            let n = match mix(i) % 17 {
                _ if heavy => u64::from(slot.ports()).min(1000) * 19 / 20,
                1 | 2 => 60 + mix(i + 1) % 120,
                _ => 2 + mix(i + 2) % 25,
            };
            for k in 0..n {
                let h = mix(i.wrapping_mul(1009).wrapping_add(k));
                // Heavy users fill their TCP ports (a P2P client, a
                // crawler): what runs a slot out first.
                let protocol = match h % 10 {
                    _ if heavy => 6,
                    0..=5 => 6,
                    6..=8 => 17,
                    _ => 1,
                };
                let pick = |list: &[u16], at: u64| {
                    list.get(usize::try_from(at % list.len() as u64).unwrap_or(0))
                        .copied()
                        .unwrap_or(0)
                };
                let server = servers
                    .get(usize::try_from(h % servers.len() as u64).unwrap_or(0))
                    .copied()
                    .unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
                let dport = match protocol {
                    6 => pick(&[443, 443, 80, 993, 5222], h >> 8),
                    17 => pick(&[53, 443, 123, 3478, 27015], h >> 8),
                    _ => 0,
                };
                let span = u64::from(slot.ports());
                let public_port = slot.first_port + u16::try_from(k % span).unwrap_or(0);
                let sport = 32_768 + u16::try_from(h % 28_000).unwrap_or(0);
                let mut st = status::CONFIRMED | status::SRC_NAT | status::SEEN_REPLY;
                if protocol == 6 && !h.is_multiple_of(4) {
                    st |= status::ASSURED;
                }
                // With the fast path on (G2.4) some established TCP and UDP
                // connections are in the flowtable, and with hardware offload
                // a few of those in the card (the lab's switchdev port).
                match h % 23 {
                    0..=5 if fast && protocol != 1 => st |= status::OFFLOAD,
                    6 if fast && protocol != 1 => {
                        st |= status::OFFLOAD;
                        if hw {
                            st |= status::HW_OFFLOAD;
                        }
                    }
                    _ => {}
                }
                let id = u32::try_from((u64::from(u32::from(sub)) ^ (k << 20) ^ h) & 0xffff_ffff)
                    .unwrap_or(0);
                let (s, d) = (IpAddr::V4(sub), IpAddr::V4(server));
                let icmp_id = u16::try_from(h % 65_536).unwrap_or(1);
                push(Conn {
                    id,
                    protocol,
                    orig: Tuple {
                        src: s,
                        dst: d,
                        src_port: if protocol == 1 { icmp_id } else { sport },
                        // ICMP: type and code, an echo request.
                        dst_port: if protocol == 1 { 8 << 8 } else { dport },
                    },
                    // ICMP: the query id is the translated "port", carried
                    // in both tuples' id (here `src_port`).
                    reply: Tuple {
                        src: d,
                        dst: IpAddr::V4(slot.public),
                        src_port: if protocol == 1 { public_port } else { dport },
                        dst_port: if protocol == 1 { 0 } else { public_port },
                    },
                    status: st,
                    timeout: match protocol {
                        6 => 30 + u32::try_from(h % 432_000).unwrap_or(0),
                        17 => 5 + u32::try_from(h % 180).unwrap_or(0),
                        _ => 1 + u32::try_from(h % 30).unwrap_or(0),
                    },
                    tcp_state: (protocol == 6).then_some(if h.is_multiple_of(9) { 7 } else { 3 }),
                    mark: 0,
                    orig_packets: if protocol == 1 {
                        1 + h % 5
                    } else {
                        3 + h % 4000
                    },
                    orig_bytes: if protocol == 1 {
                        84 * (1 + h % 5)
                    } else {
                        200 + (h % 4000) * 120
                    },
                    reply_packets: if protocol == 1 {
                        1 + h % 5
                    } else {
                        2 + h % 6000
                    },
                    reply_bytes: if protocol == 1 {
                        84 * (1 + h % 5)
                    } else {
                        400 + (h % 6000) * 1100
                    },
                });
            }
        }
    }
    // The router's own: its DNS upstream and the management session.
    for (k, (dst, dport, protocol)) in [
        (Ipv4Addr::new(1, 1, 1, 1), 53u16, 17u8),
        (Ipv4Addr::new(200, 160, 7, 186), 123, 17),
        (Ipv4Addr::new(192, 168, 88, 254), 8291, 6),
    ]
    .into_iter()
    .enumerate()
    {
        let k = u32::try_from(k).unwrap_or(0);
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 88, 1));
        push(Conn {
            id: 0x00c0_ff00 + k,
            protocol,
            orig: Tuple {
                src,
                dst: IpAddr::V4(dst),
                src_port: 40_000 + u16::try_from(k).unwrap_or(0),
                dst_port: dport,
            },
            reply: Tuple {
                src: IpAddr::V4(dst),
                dst: src,
                src_port: dport,
                dst_port: 40_000 + u16::try_from(k).unwrap_or(0),
            },
            status: status::CONFIRMED | status::SEEN_REPLY | status::ASSURED,
            timeout: 120 + k * 60,
            tcp_state: (protocol == 6).then_some(3),
            mark: 0,
            orig_packets: 12,
            orig_bytes: 1440,
            reply_packets: 12,
            reply_bytes: 2880,
        });
    }
    out
}

pub fn stats(conns: usize) -> Stats {
    Stats {
        count: conns as u64,
        max: LAB_MAX,
        insert_failed: 0,
        drop: 0,
        early_drop: 0,
    }
}

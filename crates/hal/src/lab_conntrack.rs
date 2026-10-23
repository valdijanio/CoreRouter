//! The lab's connection table (G2.2): a deterministic set of connections
//! made from the applied config, so `IP › Firewall › Connections` has
//! something real-looking to show without a kernel: CGNAT subscribers
//! going out through their slot (some fast-tracked in software or
//! hardware, to show the Via column), and a few of the router's own.
//! Killed connections stay away until the config changes.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::Config;
use corerouter_model::cgnat::Mode;

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

pub fn table(cfg: &Config, killed: &BTreeSet<u32>) -> Vec<Conn> {
    let mut out = Vec::new();
    let servers = [
        Ipv4Addr::new(142, 250, 79, 46),
        Ipv4Addr::new(157, 240, 12, 35),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(200, 160, 2, 3),
    ];
    let mut push = |c: Conn| {
        if !killed.contains(&c.id) {
            out.push(c);
        }
    };
    for p in cfg
        .ip
        .cgnat
        .pools
        .iter()
        .filter(|p| !p.disabled && p.mode == Mode::Deterministic)
    {
        let Ok(l) = p.layout() else { continue };
        for i in 0..l.subscribers().min(SUBSCRIBERS) {
            let (Some(sub), Some(slot)) = (l.subscriber(i), l.slot(i)) else {
                continue;
            };
            if cfg.ip.cgnat.exception_of(sub).is_some() {
                continue;
            }
            // A few heavy users, most light: like a real access network.
            let n = match mix(i) % 17 {
                0 => u64::from(slot.ports()).min(1000) * 19 / 20,
                1 | 2 => 60 + mix(i + 1) % 120,
                _ => 2 + mix(i + 2) % 25,
            };
            for k in 0..n {
                let h = mix(i.wrapping_mul(1009).wrapping_add(k));
                let protocol = match h % 10 {
                    0..=5 => 6,
                    6..=8 => 17,
                    _ => 1,
                };
                let server = servers[(h % servers.len() as u64) as usize];
                let dport = match protocol {
                    6 => [443u16, 443, 80, 993, 5222][(h >> 8) as usize % 5],
                    17 => [53u16, 443, 123, 3478, 27015][(h >> 8) as usize % 5],
                    _ => 0,
                };
                let span = u64::from(slot.ports());
                let public_port = slot.first_port + u16::try_from(k % span).unwrap_or(0);
                let sport = 32_768 + u16::try_from(h % 28_000).unwrap_or(0);
                let mut st = status::CONFIRMED | status::SRC_NAT | status::SEEN_REPLY;
                if protocol == 6 && h % 4 != 0 {
                    st |= status::ASSURED;
                }
                match h % 23 {
                    0..=5 => st |= status::OFFLOAD,
                    6 => st |= status::OFFLOAD | status::HW_OFFLOAD,
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
                        dst_port: dport,
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
                    tcp_state: (protocol == 6).then_some(if h % 9 == 0 { 7 } else { 3 }),
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

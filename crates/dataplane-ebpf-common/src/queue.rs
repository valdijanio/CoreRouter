// SPDX-License-Identifier: GPL-2.0-or-later
//! Queues in the data plane (G4.9b): what the tc programs share with the
//! loader for the targets that are not subscriber sessions (fixed queues,
//! DHCP leases, PCQ), and the parse both shapers use.
//!
//! - Download (to the target) is shaped on the egress of the port the
//!   packet leaves by (`shape_egress`, [`crate::shaper`]); upload (from the
//!   target) is policed on the ingress of the port it comes in by
//!   (`shape_ingress`, [`crate::policer`]).
//! - A PPPoE/IPoE session's download lives in the session maps (its
//!   `down` rate, [`SUB_SHAPE`] and its state); its upload stays the XDP
//!   policer of G4.3c. A session wins over a queue on its own address
//!   (looked up first).
//! - Targets: an LPM trie per family gives the queue of an address
//!   ([`crate::maps`] `Q_V4`/`Q_V6`), then the port (`Q_IFACE`, interface
//!   targets). The engine resolved RouterOS's first match into prefixes
//!   that a longest-prefix lookup answers the same way.
//! - PCQ: a queue whose type is `pcq` splits into sub-streams by the
//!   masked address (`Q_PCQ`, LRU): each has its own clock at `pcq-rate`
//!   and the queue's own clock at `max-limit` caps them together.

use crate::packet::Packet;
use crate::parse::{Addr, ETH_HLEN, ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6};
use crate::policer::{RATE_WORDS, Rate};
use crate::pppoe::{ETH_P_PPP_SES, PPP_IPV4, PPP_IPV6, PPPOE_OVERHEAD};
use crate::shaper::{QUEUE_WORDS, Queue};

/// Queues the maps hold (fixed queues and DHCP leases; sessions have their
/// own). Arrays are preallocated: ~280 B (config) + 2 × 176 B (state) + 2
/// × 32 B (counters) per queue, ~45 MiB at this size, **estimated**; the
/// loader sizes them to 1 entry while no queue exists.
pub const Q_MAX: u32 = 1 << 16;
/// Prefixes in each trie (a queue may have several targets).
pub const Q_PREFIXES: u32 = 1 << 17;
/// Ports with an interface target.
pub const Q_IFACES: u32 = 256;
/// PCQ sub-streams remembered (LRU: the least recently seen address
/// starts over with an empty clock). ~80 B each with the kernel's
/// overhead, **estimated** ~20 MiB; sized to 1 without PCQ queues.
pub const PCQ_MAX: u32 = 1 << 18;

/// `SETTINGS` slot of the shaper switches: bit 0 queues exist (the trie
/// lookups run), bit 1 subscriber sessions may be shaped.
pub const SETTINGS_SLOT: u32 = 4;
pub const ON_QUEUES: u64 = 1;
pub const ON_SESSIONS: u64 = 1 << 1;

/// One direction of a PCQ queue's sub-streams. Always whole (`on` says
/// whether it applies): an `Option` would leave its bytes undefined when
/// `None`, and the verifier refuses a spill of an undefined register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pcq {
    pub on: bool,
    /// Each sub-stream's rate and bucket (only `rate` and `depth` are
    /// used: PCQ's own burst is not shaped here).
    pub rate: Rate,
    pub queue: Queue,
    /// Classified by the source address (upload) instead of the
    /// destination (download).
    pub by_src: bool,
    pub mask4: u8,
    pub mask6: u8,
}

/// One direction of a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dir {
    /// The queue's own limit (`max-limit`, burst): 0 = none.
    pub rate: Rate,
    pub queue: Queue,
    pub pcq: Pcq,
}

pub const DIR_WORDS: usize = RATE_WORDS + QUEUE_WORDS + 3 + QUEUE_WORDS;
pub const CONF_WORDS: usize = 1 + 2 * DIR_WORDS;
pub type ConfWords = [u64; CONF_WORDS];

/// The queue is in use (cleared before its index is reused).
pub const F_ACTIVE: u64 = 1;
const PCQ_ON: u64 = 1;
const PCQ_SRC: u64 = 1 << 1;

impl Dir {
    fn put(&self, w: &mut ConfWords, base: usize) {
        let pcq = self.pcq;
        let head = if pcq.on { PCQ_ON } else { 0 }
            | if pcq.by_src { PCQ_SRC } else { 0 }
            | u64::from(pcq.mask4) << 8
            | u64::from(pcq.mask6) << 16;
        let words = self
            .rate
            .to_words()
            .into_iter()
            .chain(self.queue.to_words())
            .chain([head, pcq.rate.rate, pcq.rate.depth])
            .chain(pcq.queue.to_words());
        for (i, v) in words.enumerate() {
            if let Some(slot) = w.get_mut(base + i) {
                *slot = v;
            }
        }
    }

    /// Direction `dir` (0 upload, 1 download) of a queue's words.
    #[inline(always)]
    pub fn of(w: &ConfWords, dir: usize) -> Dir {
        let base = 1 + (dir & 1) * DIR_WORDS;
        let g = |i: usize| w.get(base + i).copied().unwrap_or(0);
        let mut r = [0u64; RATE_WORDS];
        for (i, slot) in r.iter_mut().enumerate() {
            *slot = g(i);
        }
        let q = |at: usize| Queue::from_words([g(at), g(at + 1), g(at + 2), g(at + 3)]);
        let head = g(RATE_WORDS + QUEUE_WORDS);
        let pcq = Pcq {
            on: head & PCQ_ON != 0,
            rate: Rate {
                rate: g(RATE_WORDS + QUEUE_WORDS + 1),
                depth: g(RATE_WORDS + QUEUE_WORDS + 2),
                ..Rate::default()
            },
            queue: q(RATE_WORDS + QUEUE_WORDS + 3),
            by_src: head & PCQ_SRC != 0,
            mask4: (head >> 8) as u8,
            mask6: (head >> 16) as u8,
        };
        Dir {
            rate: Rate::from_words(r),
            queue: q(RATE_WORDS),
            pcq,
        }
    }
}

/// A queue as the maps hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Conf {
    pub up: Dir,
    pub down: Dir,
}

impl Conf {
    pub fn to_words(&self) -> ConfWords {
        let mut w = [0u64; CONF_WORDS];
        if let Some(h) = w.get_mut(0) {
            *h = F_ACTIVE;
        }
        self.up.put(&mut w, 1);
        self.down.put(&mut w, 1 + DIR_WORDS);
        w
    }

    pub fn from_words(w: &ConfWords) -> Conf {
        Conf {
            up: Dir::of(w, 0),
            down: Dir::of(w, 1),
        }
    }
}

#[inline(always)]
pub fn active(w: &ConfWords) -> bool {
    w.first().is_some_and(|h| h & F_ACTIVE != 0)
}

/// Where a frame's IP packet is: through up to two VLAN tags and, on an
/// access port, a PPPoE session header (RFC 2516; the shaper on the
/// egress sees what `bng0` encapsulated). Addresses are plain 16-byte
/// arrays (IPv4 in the first four, the rest zero), not [`Addr`]: an
/// enum's IPv4 variant leaves bytes undefined, and the verifier refuses a
/// copy that spills them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3 {
    pub off: usize,
    pub v6: bool,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    /// IP total length (IPv6: header + payload).
    pub ip_len: u16,
}

impl L3 {
    /// The IPv4 address in the first four bytes of `a`.
    #[inline(always)]
    pub fn v4(a: &[u8; 16]) -> [u8; 4] {
        let [w, x, y, z, ..] = *a;
        [w, x, y, z]
    }

    pub fn src_addr(&self) -> Addr {
        if self.v6 { Addr::V6(self.src) } else { Addr::V4(Self::v4(&self.src)) }
    }

    pub fn dst_addr(&self) -> Addr {
        if self.v6 { Addr::V6(self.dst) } else { Addr::V4(Self::v4(&self.dst)) }
    }
}

#[inline(always)]
fn wide([a, b, c, d]: [u8; 4]) -> [u8; 16] {
    [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

#[inline(always)]
pub fn l3<P: Packet + ?Sized>(p: &P) -> Option<L3> {
    let mut off = ETH_HLEN;
    let mut proto = p.be16(12)?;
    let mut tags = 0;
    while tags < 2 {
        if proto != ETH_P_8021Q && proto != ETH_P_8021AD {
            break;
        }
        proto = p.be16(off + 2)?;
        off += 4;
        tags += 1;
    }
    let v6 = match proto {
        ETH_P_IP => false,
        ETH_P_IPV6 => true,
        ETH_P_PPP_SES => {
            // VER/TYPE 1/1, CODE 0 (session data), then the PPP protocol.
            if p.u8_at(off)? != 0x11 || p.u8_at(off + 1)? != 0 {
                return None;
            }
            let ppp = p.be16(off + 6)?;
            off += PPPOE_OVERHEAD;
            match ppp {
                PPP_IPV4 => false,
                PPP_IPV6 => true,
                _ => return None,
            }
        }
        _ => return None,
    };
    if v6 {
        if p.u8_at(off)? >> 4 != 6 {
            return None;
        }
        let payload = p.be16(off + 4)?;
        Some(L3 {
            off,
            v6,
            src: p.bytes::<16>(off + 8)?,
            dst: p.bytes::<16>(off + 24)?,
            ip_len: payload.saturating_add(40),
        })
    } else {
        if p.u8_at(off)? >> 4 != 4 {
            return None;
        }
        Some(L3 {
            off,
            v6,
            src: wide(p.bytes::<4>(off + 12)?),
            dst: wide(p.bytes::<4>(off + 16)?),
            ip_len: p.be16(off + 2)?,
        })
    }
}

/// The ECN field of the packet at `l3` (RFC 3168 §5: the low two bits of
/// the TOS / Traffic Class): 0 = not ECN-capable, 3 = CE.
#[inline(always)]
pub fn ecn<P: Packet + ?Sized>(p: &P, l3: &L3) -> Option<u8> {
    if l3.v6 {
        Some(p.u8_at(l3.off + 1)? >> 4 & 3)
    } else {
        Some(p.u8_at(l3.off + 1)? & 3)
    }
}

/// Address `a` (IPv4 in the first four bytes unless `v6`) with the bits
/// past the family's mask cleared.
#[inline(always)]
pub fn masked(v6: bool, a: &[u8; 16], mask4: u8, mask6: u8) -> [u8; 16] {
    let (mut b, len) = if v6 {
        (*a, mask6.min(128))
    } else {
        (wide(L3::v4(a)), mask4.min(32))
    };
    let mut i = 0;
    while i < 16 {
        let bit = i * 8;
        if let Some(byte) = b.get_mut(i) {
            let keep = u32::from(len).saturating_sub(bit as u32).min(8);
            *byte &= if keep == 0 { 0 } else { 0xffu8 << (8 - keep) };
        }
        i += 1;
    }
    b
}

pub const PCQ_KEY_LEN: usize = 24;

/// The sub-stream of queue `idx`, direction `dir`, for address `a`:
/// `[idx (LE) | dir | family | 0 0 | masked address]`.
#[inline(always)]
pub fn pcq_key(idx: u32, dir: u8, v6: bool, a: &[u8; 16], mask4: u8, mask6: u8) -> [u8; PCQ_KEY_LEN] {
    let [i0, i1, i2, i3] = idx.to_le_bytes();
    let fam = if v6 { 6 } else { 4 };
    let [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15] = masked(v6, a, mask4, mask6);
    [
        i0, i1, i2, i3, dir, fam, 0, 0, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15,
    ]
}

/// Per-queue counters, per direction: `[packets, bytes, dropped, marked]`
/// (IP bytes; added atomically).
pub const COUNT_WORDS: usize = 4;
pub type Counts = [u64; COUNT_WORDS];
pub const C_PACKETS: usize = 0;
pub const C_BYTES: usize = 1;
pub const C_DROPPED: usize = 2;
pub const C_MARKED: usize = 3;

/// Why a packet went the way it did in the tc programs (per-CPU array
/// `SHAPE_STATS`, summed by the loader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Stat {
    /// Not a target of anything (passed untouched).
    NoTarget = 0,
    /// Sent now (the target was under its rate).
    Sent = 1,
    /// Held for a later departure (`skb->tstamp` in the future).
    Held = 2,
    /// Dropped by the shaper (queue limit or CoDel).
    Dropped = 3,
    /// Marked CE instead of dropped.
    Marked = 4,
    /// Upload over the policer: dropped.
    Policed = 5,
    /// Not IP, or IP the parse refused: passed untouched.
    NotIp = 6,
    /// `bng0`: encapsulated for a PPPoE session and sent to its port.
    BngEncap = 7,
    /// `bng0`: no session for the destination (dropped).
    BngNoSession = 8,
    /// `bng0`: the encapsulation failed (no headroom): dropped.
    BngFailed = 9,
    /// A session's download shaped.
    SessionShaped = 10,
}

impl Stat {
    pub const SLOTS: u32 = 11;
    pub const ALL: [Stat; 11] = [
        Stat::NoTarget,
        Stat::Sent,
        Stat::Held,
        Stat::Dropped,
        Stat::Marked,
        Stat::Policed,
        Stat::NotIp,
        Stat::BngEncap,
        Stat::BngNoSession,
        Stat::BngFailed,
        Stat::SessionShaped,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Stat::NoTarget => "no-target",
            Stat::Sent => "sent",
            Stat::Held => "held",
            Stat::Dropped => "dropped",
            Stat::Marked => "marked",
            Stat::Policed => "policed",
            Stat::NotIp => "not-ip",
            Stat::BngEncap => "bng-encap",
            Stat::BngNoSession => "bng-no-session",
            Stat::BngFailed => "bng-failed",
            Stat::SessionShaped => "session-shaped",
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::policer::Rate;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn conf_round_trips() {
        let c = Conf {
            up: Dir {
                rate: Rate::mikrotik(10_000_000, 20_000_000, 0, 8_000_000_000),
                queue: Queue::codel(1_250_000),
                pcq: Pcq {
                    on: true,
                    rate: Rate::mikrotik(1_000_000, 0, 0, 0),
                    queue: Queue::default(),
                    by_src: true,
                    mask4: 32,
                    mask6: 64,
                },
            },
            down: Dir {
                rate: Rate::mikrotik(50_000_000, 0, 0, 0),
                ..Dir::default()
            },
        };
        let w = c.to_words();
        assert!(active(&w));
        let back = Conf::from_words(&w);
        assert_eq!(back.down, c.down);
        assert_eq!(back.up.queue, c.up.queue);
        assert_eq!(back.up.rate, c.up.rate);
        let p = back.up.pcq;
        assert_eq!((p.on, p.by_src, p.mask4, p.mask6, p.rate.rate, p.rate.depth), (true, true, 32, 64, 125_000, c.up.pcq.rate.depth));
        assert!(!back.down.pcq.on);
    }

    #[test]
    fn masks() {
        let a = [0x20, 1, 0xd, 0xb8, 0, 1, 0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(masked(true, &a, 32, 64), [0x20, 1, 0xd, 0xb8, 0, 1, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(masked(true, &a, 32, 60)[7], 0x30);
        let v4 = wide([10, 1, 2, 3]);
        assert_eq!(&masked(false, &v4, 24, 128)[..4], &[10, 1, 2, 0]);
        assert_eq!(&masked(false, &v4, 0, 128)[..4], &[0, 0, 0, 0]);
        assert_ne!(pcq_key(1, 1, false, &v4, 32, 128), pcq_key(1, 0, false, &v4, 32, 128));
        assert_ne!(pcq_key(1, 1, false, &v4, 32, 128), pcq_key(1, 1, true, &v4, 32, 128));
    }

    #[test]
    fn l3_through_vlan_and_pppoe() {
        use crate::packet::Packet;
        struct F(Vec<u8>);
        impl Packet for F {
            fn len(&self) -> usize {
                self.0.len()
            }
            fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
                self.0.get(off..off + N)?.try_into().ok()
            }
        }
        let ip = [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 100, 64, 0, 9];
        let mut f = vec![0u8; 12];
        f.extend([0x81, 0, 0, 7, 0x88, 0x64, 0x11, 0, 0, 5, 0, 42, 0, 0x21]);
        f.extend(ip);
        f.extend([0u8; 20]);
        let l = l3(&F(f.clone())).unwrap();
        assert_eq!((l.off, l.v6, l.ip_len), (26, false, 40));
        assert_eq!(l.dst_addr(), Addr::V4([100, 64, 0, 9]));
        assert_eq!(l.src_addr(), Addr::V4([10, 0, 0, 1]));
        // A PPPoE control frame (LCP) is not IP.
        f[24] = 0xc0;
        f[25] = 0x21;
        assert!(l3(&F(f)).is_none());
    }
}

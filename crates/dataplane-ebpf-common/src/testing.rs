// SPDX-License-Identifier: GPL-2.0-or-later
//! Frames and a reference model for the tests (feature `testing`): the
//! host proptests here and the kernel differential test of `hal-linux`
//! (`tests/xdp_root.rs`) build the same frames and expect the same
//! decisions.

extern crate std;

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use crate::bucket::Bucket;
use crate::filter::Lookups;
use crate::parse::{self, Addr, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

/// A frame to build.
#[derive(Debug, Clone)]
pub struct Spec {
    pub vlans: Vec<u16>,
    pub src: Addr,
    pub dst: Addr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub payload: usize,
}

/// The frame `s` describes (no FCS).
pub fn build(s: &Spec) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    for (i, tci) in s.vlans.iter().enumerate() {
        let tpid: u16 = if i == 0 && s.vlans.len() == 2 {
            0x88a8
        } else {
            0x8100
        };
        f.extend(tpid.to_be_bytes());
        f.extend(tci.to_be_bytes());
    }
    let l4 = l4(s);
    match (s.src, s.dst) {
        (Addr::V4(src), Addr::V4(dst)) => {
            f.extend(0x0800u16.to_be_bytes());
            let total = 20 + l4.len();
            f.extend([0x45, 0]);
            f.extend((total as u16).to_be_bytes());
            f.extend([0, 0, 0x40, 0, 64, s.proto, 0, 0]);
            f.extend(src);
            f.extend(dst);
        }
        (Addr::V6(src), Addr::V6(dst)) => {
            f.extend(0x86ddu16.to_be_bytes());
            f.extend([0x60, 0, 0, 0]);
            f.extend((l4.len() as u16).to_be_bytes());
            f.extend([s.proto, 64]);
            f.extend(src);
            f.extend(dst);
        }
        // Mixed families: nothing to build.
        _ => return Vec::new(),
    }
    f.extend(l4);
    f
}

fn l4(s: &Spec) -> Vec<u8> {
    let mut h = Vec::new();
    match s.proto {
        IPPROTO_TCP => {
            h.extend(s.sport.to_be_bytes());
            h.extend(s.dport.to_be_bytes());
            h.extend([0; 8]);
            h.extend([0x50, s.flags, 0xff, 0xff, 0, 0, 0, 0]);
        }
        IPPROTO_UDP => {
            h.extend(s.sport.to_be_bytes());
            h.extend(s.dport.to_be_bytes());
            h.extend(((8 + s.payload) as u16).to_be_bytes());
            h.extend([0, 0]);
        }
        _ => h.extend([8, 0, 0, 0]),
    }
    h.extend(std::iter::repeat_n(0xab, s.payload));
    h
}

/// Two addresses of one family.
pub fn addr_pair() -> impl Strategy<Value = (Addr, Addr)> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<[u8; 4]>()).prop_map(|(a, b)| (Addr::V4(a), Addr::V4(b))),
        (any::<[u8; 16]>(), any::<[u8; 16]>()).prop_map(|(a, b)| (Addr::V6(a), Addr::V6(b))),
    ]
}

/// Any frame the builder makes.
pub fn spec() -> impl Strategy<Value = Spec> {
    (
        prop::collection::vec(0u16..4096, 0..=2),
        addr_pair(),
        prop::sample::select(vec![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP]),
        any::<u16>(),
        any::<u16>(),
        any::<u8>(),
        0usize..64,
    )
        .prop_map(|(vlans, (src, dst), proto, sport, dport, flags, payload)| {
            // ICMPv6 for IPv6 sources.
            let proto = match (proto, src) {
                (IPPROTO_ICMP, Addr::V6(_)) => parse::IPPROTO_ICMPV6,
                (p, _) => p,
            };
            Spec {
                vlans,
                src,
                dst,
                proto,
                sport,
                dport,
                flags,
                payload,
            }
        })
}

/// Lists and buckets in plain collections; longest-prefix match the
/// slow, obvious way.
#[derive(Default, Clone)]
pub struct Model {
    /// `(network, prefix length, list index)`.
    pub block: Vec<(Addr, u32, u32)>,
    pub allow: Vec<(Addr, u32)>,
    pub buckets: BTreeMap<[u8; 16], Bucket>,
}

/// Whether `net/len` holds `a`.
pub fn covers(net: &Addr, len: u32, a: &Addr) -> bool {
    let bits = |x: &[u8]| -> u128 {
        x.iter().fold(0u128, |acc, b| (acc << 8) | u128::from(*b)) << (128 - x.len() * 8)
    };
    let (n, x) = match (net, a) {
        (Addr::V4(n), Addr::V4(x)) => (bits(n), bits(x)),
        (Addr::V6(n), Addr::V6(x)) => (bits(n), bits(x)),
        _ => return false,
    };
    len == 0 || (n ^ x) >> (128 - len) == 0
}

impl Lookups for Model {
    fn blocked(&self, src: &Addr) -> Option<u32> {
        self.block
            .iter()
            .filter(|(n, l, _)| covers(n, *l, src))
            .max_by_key(|(_, l, _)| *l)
            .map(|(_, _, i)| *i)
    }
    fn allowed(&self, src: &Addr) -> bool {
        self.allow.iter().any(|(n, l)| covers(n, *l, src))
    }
    fn bucket(&mut self, src: &Addr) -> Option<&mut Bucket> {
        self.buckets.get_mut(&src.mapped())
    }
    fn new_bucket(&mut self, src: &Addr, b: Bucket) {
        self.buckets.insert(src.mapped(), b);
    }
}

/// One's-complement sum of `bytes` as 16-bit big-endian words (an odd
/// last byte padded with zero), plus `seed`.
pub fn ones_sum(bytes: &[u8], seed: u32) -> u32 {
    bytes.chunks(2).fold(seed, |acc, w| {
        let word = match *w {
            [a, b] => u16::from_be_bytes([a, b]),
            [a] => u16::from_be_bytes([a, 0]),
            _ => 0,
        };
        acc + u32::from(word)
    })
}

/// Fill in the IPv4 header checksum and the TCP/UDP checksum of an
/// untagged IPv4 frame from [`build`] (computed in full, the reference the
/// incremental rewrite is checked against). Other frames are left alone.
pub fn with_checksums(mut f: Vec<u8>) -> Vec<u8> {
    let Some(&[0x08, 0x00]) = f.get(12..14) else {
        return f;
    };
    let ihl = usize::from(f.get(14).copied().unwrap_or(0) & 0x0f) * 4;
    let l4 = 14 + ihl;
    let proto = f.get(23).copied().unwrap_or(0);
    if let Some(h) = f.get_mut(24..26) {
        h.copy_from_slice(&[0, 0]);
    }
    let ip = !crate::nat::fold(ones_sum(f.get(14..l4).unwrap_or(&[]), 0));
    if let Some(h) = f.get_mut(24..26) {
        h.copy_from_slice(&ip.to_be_bytes());
    }
    let csum_at = match proto {
        IPPROTO_TCP => l4 + 16,
        IPPROTO_UDP => l4 + 6,
        _ => return f,
    };
    let seg_len = f.len() - l4;
    if let Some(h) = f.get_mut(csum_at..csum_at + 2) {
        h.copy_from_slice(&[0, 0]);
    }
    let pseudo = ones_sum(
        f.get(26..34).unwrap_or(&[]),
        u32::from(proto) + seg_len as u32,
    );
    let mut c = !crate::nat::fold(ones_sum(f.get(l4..).unwrap_or(&[]), pseudo));
    if proto == IPPROTO_UDP && c == 0 {
        c = 0xffff;
    }
    if let Some(h) = f.get_mut(csum_at..csum_at + 2) {
        h.copy_from_slice(&c.to_be_bytes());
    }
    f
}

/// Whether the IPv4 header and TCP/UDP checksums of `f` verify (a full
/// sum over each comes to 0xFFFF; a UDP checksum of 0 means none).
pub fn checksums_ok(f: &[u8]) -> bool {
    let ihl = usize::from(f.get(14).copied().unwrap_or(0) & 0x0f) * 4;
    let l4 = 14 + ihl;
    let proto = f.get(23).copied().unwrap_or(0);
    let ip_ok = crate::nat::fold(ones_sum(f.get(14..l4).unwrap_or(&[]), 0)) == 0xffff;
    let udp_none = proto == IPPROTO_UDP && f.get(l4 + 6..l4 + 8) == Some(&[0, 0]);
    if udp_none || !matches!(proto, IPPROTO_TCP | IPPROTO_UDP) {
        return ip_ok;
    }
    let seg_len = f.len() - l4;
    let pseudo = ones_sum(
        f.get(26..34).unwrap_or(&[]),
        u32::from(proto) + seg_len as u32,
    );
    ip_ok && crate::nat::fold(ones_sum(f.get(l4..).unwrap_or(&[]), pseudo)) == 0xffff
}

// --- PPPoE (G4.3c) ----------------------------------------------------------

use crate::filter::{self, Settings};
use crate::nat::PacketMut;
use crate::packet::Packet;
use crate::policer;
use crate::pppoe::{self, Down, PacketHead, Session, SessionWords, Sessions, Stat, Up};

/// Room in front of the frame, as XDP gives (`XDP_PACKET_HEADROOM`).
pub const HEADROOM: usize = 256;

/// A frame with headroom: what `bpf_xdp_adjust_head` moves through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
}

impl Buf {
    pub fn new(frame: &[u8]) -> Self {
        let mut data = vec![0; HEADROOM];
        data.extend_from_slice(frame);
        Buf {
            data,
            start: HEADROOM,
        }
    }

    pub fn frame(&self) -> &[u8] {
        self.data.get(self.start..).unwrap_or(&[])
    }
}

impl Packet for Buf {
    fn len(&self) -> usize {
        self.frame().len()
    }
    fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        self.frame().bytes(off)
    }
}

impl PacketMut for Buf {
    fn store<const N: usize>(&mut self, off: usize, bytes: [u8; N]) -> Option<()> {
        let start = self.start;
        self.data.get_mut(start..)?.store(off, bytes)
    }
}

impl PacketHead for Buf {
    fn adjust_head(&mut self, delta: i32) -> Option<()> {
        // The kernel keeps at least an Ethernet header (ETH_HLEN) of frame.
        let new = self.start.checked_add_signed(delta as isize)?;
        if new + 14 > self.data.len() {
            return None;
        }
        self.start = new;
        Some(())
    }
}

/// The session maps in plain collections.
#[derive(Debug, Clone, Default)]
pub struct Subs {
    pub keys: BTreeMap<[u8; pppoe::KEY_LEN], u32>,
    pub sessions: BTreeMap<u32, SessionWords>,
    pub v4: BTreeMap<[u8; 4], u32>,
    /// `(prefix (16 bytes), length, index)`.
    pub v6: Vec<([u8; 16], u32, u32)>,
    pub policers: BTreeMap<(u32, u32), policer::State>,
    /// `IPOE_PORTS` (G4.3f).
    pub ipoe_ports: std::collections::BTreeSet<u32>,
    /// `PPPOE_RT4` / `PPPOE_RT6` (G4.3cd): `(prefix, length, index)`.
    pub routes4: Vec<([u8; 4], u32, u32)>,
    pub routes6: Vec<([u8; 16], u32, u32)>,
}

impl Subs {
    /// Put `s` at `idx` as the loader does (full buckets at `now`).
    pub fn insert(&mut self, idx: u32, s: &Session, now: u64) {
        self.sessions.insert(idx, s.to_words());
        self.policers.insert((idx, 0), policer::fresh(&s.up, now));
        self.policers.insert((idx, 1), policer::fresh(&s.down, now));
        self.keys.insert(s.key().to_bytes(), idx);
        if s.flags & pppoe::F_IPV4 != 0 {
            self.v4.insert(s.ipv4, idx);
        }
        let full = |p: [u8; 8]| {
            let mut a = [0u8; 16];
            a[..8].copy_from_slice(&p);
            a
        };
        if s.flags & pppoe::F_IPV6 != 0 {
            self.v6.push((full(s.ipv6_prefix), 64, idx));
        }
        if s.flags & pppoe::F_PD != 0 {
            self.v6.push((full(s.pd_prefix), u32::from(s.pd_len), idx));
        }
    }
}

impl Sessions for Subs {
    fn by_key(&self, key: &[u8; pppoe::KEY_LEN]) -> Option<u32> {
        self.keys.get(key).copied()
    }
    fn session(&self, idx: u32) -> Option<&SessionWords> {
        self.sessions.get(&idx)
    }
    fn by_v4(&self, dst: [u8; 4]) -> Option<u32> {
        self.v4.get(&dst).copied()
    }
    fn by_v6(&self, dst: [u8; 16]) -> Option<u32> {
        let d = Addr::V6(dst);
        self.v6
            .iter()
            .filter(|(p, l, _)| covers(&Addr::V6(*p), *l, &d))
            .max_by_key(|(_, l, _)| *l)
            .map(|(_, _, i)| *i)
    }
    type Policer<'a> = Option<&'a mut policer::State>;

    fn policer(&mut self, idx: u32, dir: u32) -> Option<&mut policer::State> {
        self.policers.get_mut(&(idx, dir))
    }
    fn ipoe_port(&self, ifindex: u32) -> bool {
        self.ipoe_ports.contains(&ifindex)
    }
    fn by_route_v4(&self, dst: [u8; 4]) -> Option<u32> {
        let d = Addr::V4(dst);
        self.routes4
            .iter()
            .filter(|(p, l, _)| covers(&Addr::V4(*p), *l, &d))
            .max_by_key(|(_, l, _)| *l)
            .map(|(_, _, i)| *i)
    }
    fn by_route_v6(&self, dst: [u8; 16]) -> Option<u32> {
        let d = Addr::V6(dst);
        self.routes6
            .iter()
            .filter(|(p, l, _)| covers(&Addr::V6(*p), *l, &d))
            .max_by_key(|(_, l, _)| *l)
            .map(|(_, _, i)| *i)
    }
}

/// A PPPoE session frame from the client of `s` carrying the IP packet of
/// the untagged frame `ip_frame` (its bytes from 14 on), protocol `proto`.
pub fn pppoe_frame(s: &Session, ip_frame: &[u8], proto: u16) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(s.server_mac);
    f.extend(s.client_mac);
    let tag = |f: &mut Vec<u8>, tpid: u16, v: u16| {
        f.extend(tpid.to_be_bytes());
        f.extend((v & 0x0fff).to_be_bytes());
    };
    let view = pppoe::View::of(&s.to_words());
    match view.tags() {
        1 => tag(&mut f, 0x8100, s.vlan),
        2 => {
            let tpid = if s.outer_tpid == 0 {
                0x88a8
            } else {
                s.outer_tpid
            };
            tag(&mut f, tpid, s.vlan);
            tag(&mut f, 0x8100, s.inner_vlan);
        }
        _ => {}
    }
    let payload = ip_frame.get(14..).unwrap_or(&[]);
    f.extend(pppoe::ETH_P_PPP_SES.to_be_bytes());
    f.extend([pppoe::VER_TYPE, 0]);
    f.extend(s.sid.to_be_bytes());
    f.extend(((payload.len() + 2) as u16).to_be_bytes());
    f.extend(proto.to_be_bytes());
    f.extend(payload);
    f
}

/// XDP actions.
pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;
pub const XDP_REDIRECT: u32 = 4;

/// The action, the frame after it, the redirect target, the statistic.
pub type Outcome = (u32, Vec<u8>, Option<u32>, Option<Stat>);

/// What the XDP program does with `frame` arriving on `ifindex`, with the
/// filter set to `s`, no CGNAT fast path and no FIB (every session without
/// `F_FAST_UP`, as the kernel differential test sets them up): the action,
/// the frame after it, the redirect target and the statistic counted.
pub fn program_model(
    frame: &[u8],
    ifindex: u32,
    s: &Settings,
    subs: &mut Subs,
    filter_state: &mut Model,
    now: u64,
) -> Outcome {
    let mut buf = Buf::new(frame);
    let mut from = None;
    let mut up = pppoe::upstream(&buf, ifindex, subs, now);
    if up == Up::NotPppoe {
        up = crate::ipoe::upstream(&buf, ifindex, subs, now);
    }
    match up {
        Up::NotPppoe => {}
        Up::User(st) => return (XDP_PASS, frame.to_vec(), None, Some(st)),
        Up::Drop(st, _) => return (XDP_DROP, frame.to_vec(), None, Some(st)),
        Up::Session(u) => {
            if !u.ipoe && pppoe::decap(&mut buf, u.tags, u.v6).is_none() {
                return (XDP_DROP, frame.to_vec(), None, Some(Stat::Malformed));
            }
            from = Some(u);
        }
    }
    let v = filter::decide(&buf, s, filter_state, now);
    if v.drop {
        return (XDP_DROP, buf.frame().to_vec(), None, None);
    }
    if v.ip.is_some()
        && let Some(r) = to_subscriber_model(&mut buf, subs, now)
    {
        return r;
    }
    let st = from.map(|u| if u.fast { Stat::UpFib } else { Stat::UpKernel });
    (XDP_PASS, buf.frame().to_vec(), None, st)
}

fn to_subscriber_model(buf: &mut Buf, subs: &mut Subs, now: u64) -> Option<Outcome> {
    let d = pppoe::to_subscriber(buf, subs, now)?;
    match d.verdict.down() {
        Down::NotSub => None,
        Down::Kernel(st, _) | Down::Counted(st, _, _) => {
            Some((XDP_PASS, buf.frame().to_vec(), None, Some(st)))
        }
        Down::Drop(st, _) => Some((XDP_DROP, buf.frame().to_vec(), None, Some(st))),
        Down::Encap(e) => Some((
            XDP_REDIRECT,
            buf.frame().to_vec(),
            Some(e.ifindex),
            Some(Stat::DownFast),
        )),
    }
}

/// A session for tests: `idx`-derived SID, MACs and addresses, on
/// `ifindex` with `tags` VLAN tags, flags `flags`, no limits.
pub fn test_session(idx: u32, ifindex: u32, tags: u8, flags: u16) -> Session {
    let [_, b, c, d] = idx.to_be_bytes();
    Session {
        flags: pppoe::F_ACTIVE | flags,
        ifindex,
        sid: (idx as u16).wrapping_add(1).max(1),
        vlan: if tags >= 1 {
            pppoe::TAGGED | (idx as u16 & 0x0fff)
        } else {
            0
        },
        inner_vlan: if tags >= 2 { pppoe::TAGGED | 7 } else { 0 },
        outer_tpid: 0,
        mtu: 0,
        client_mac: [0x02, 0xcc, 0, b, c, d],
        server_mac: [0x02, 0xbb, 0, 0, 0, 1],
        ipv4: [100, 64 | (b & 0x3f), c, d],
        ipv6_prefix: [0x20, 0x01, 0x0d, 0xb8, b, c, d, 0],
        pd_prefix: [0x20, 0x01, 0x0d, 0xb9, b, c, d, 0],
        pd_len: 56,
        up: policer::Rate::default(),
        down: policer::Rate::default(),
    }
}

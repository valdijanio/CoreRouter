// SPDX-License-Identifier: GPL-2.0-or-later
//! PPPoE subscriber data plane (G4.3c): a BNG without one kernel netdev per
//! session. The access port's XDP program checks each session frame
//! against the session map, polices it, strips the PPPoE header and hands
//! the inner IPv4/IPv6 packet on (the filter, the CGNAT fast path, the FIB,
//! or the kernel). A packet to a subscriber gets the PPPoE and Ethernet
//! header pushed and goes out of the access port. The control plane
//! (discovery, LCP, authentication, IPCP/IPV6CP, link-local IPv6) stays in
//! userspace: those frames pass untouched to the daemon's AF_PACKET socket.
//!
//! Frame formats: RFC 2516 §4 (Ethernet type 0x8863 discovery, 0x8864
//! session; VER = 1, TYPE = 1, CODE = 0 in session frames; LENGTH counts
//! the PPP payload, protocol field included) and RFC 1661 §2 (protocol
//! field: 0x0*** – 0x3*** network layer, 0x4*** – 0x7*** low-volume
//! traffic with no NCP, 0x8*** – 0xb*** NCPs, 0xc*** – 0xf*** link
//! control). The MTU toward each subscriber is the MRU it negotiated:
//! 1492 by default, up to 1500 with RFC 4638 (PPP-Max-Payload).
//!
//! The daemon (G4.3d) fills the maps from the session descriptor of
//! `proto-pppoe` (G4.3a): [`Session`] and [`SessionKey`] are plain
//! `#[repr(C)]` types with an explicit word/byte encoding, so neither side
//! needs `unsafe` to share them.

use crate::nat::{self, PacketMut};
use crate::packet::Packet;
use crate::parse::{Addr, ETH_HLEN, ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6};
use crate::policer::{self, RATE_WORDS, Rate};

pub const ETH_P_PPP_DISC: u16 = 0x8863;
pub const ETH_P_PPP_SES: u16 = 0x8864;
/// PPPoE header (6) + PPP protocol field (2).
pub const PPPOE_OVERHEAD: usize = 8;
/// RFC 2516 §4: VER = 1, TYPE = 1.
pub const VER_TYPE: u8 = 0x11;
pub const PPP_IPV4: u16 = 0x0021;
pub const PPP_IPV6: u16 = 0x0057;
/// MRU of a PPPoE link without RFC 4638 (1500 − 8).
pub const DEFAULT_MTU: u16 = 1492;

/// A frame whose head can move (`bpf_xdp_adjust_head`): positive `delta`
/// drops bytes from the front, negative grows it (the new bytes are
/// garbage until written).
pub trait PacketHead: PacketMut {
    fn adjust_head(&mut self, delta: i32) -> Option<()>;
}

// --- Session map layout ---------------------------------------------------

/// The session is in use (the daemon clears it before reusing the slot).
pub const F_ACTIVE: u16 = 1;
/// `ipv4` is the subscriber's address (IPCP done).
pub const F_IPV4: u16 = 1 << 1;
/// `ipv6_prefix` is the subscriber's /64 (IPV6CP + RA done).
pub const F_IPV6: u16 = 1 << 2;
/// `pd_prefix`/`pd_len` is a delegated prefix (DHCPv6-PD).
pub const F_PD: u16 = 1 << 3;
/// Upstream packets may be forwarded in XDP (FIB) without the kernel:
/// nothing in the forward path (firewall, queues) needs to see them.
pub const F_FAST_UP: u16 = 1 << 4;
/// Downstream packets may be encapsulated in XDP without the kernel.
/// Flows conntrack already accepted (the CGNAT fast path) always may.
pub const F_FAST_DOWN: u16 = 1 << 5;

/// `SETTINGS` slot of the PPPoE switch (bit 0: on). Off, the program
/// never looks at PPPoE frames (they pass as before).
pub const SETTINGS_SLOT: u32 = 3;

/// How many sessions the maps hold (at most) when PPPoE is on. Arrays are
/// preallocated: ~150 B (session) + 2 × 104 B (policers) + 64 B
/// (counters) + ~64 B (key hash) per session, ~64 MiB at this size,
/// **estimated**; the loader sizes them to 1 while PPPoE is off.
pub const SESSIONS_MAX: u32 = 1 << 17;
/// IPv6 prefixes (a /64 and a delegated prefix per session).
pub const PREFIXES_V6: u32 = SESSIONS_MAX * 2;

/// A VLAN field of [`SessionKey`]/[`Session`]: 0 = no tag, else
/// `TAGGED | VID`.
pub const TAGGED: u16 = 0x1000;

/// What identifies a session frame on the access side: the port, the VLAN
/// tags, the PPPoE session id and the client's MAC (RFC 2516 §4: a session
/// is the pair of MACs plus the SESSION_ID; the port and tags make it
/// unique across access networks).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SessionKey {
    pub ifindex: u32,
    /// Outer (or only) tag: 0 or `TAGGED | VID`.
    pub vlan: u16,
    /// Inner (QinQ customer) tag: 0 or `TAGGED | VID`.
    pub inner_vlan: u16,
    pub sid: u16,
    pub client_mac: [u8; 6],
}

pub const KEY_LEN: usize = 16;

impl SessionKey {
    /// The map key: ifindex little-endian, then network order.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        let [i0, i1, i2, i3] = self.ifindex.to_le_bytes();
        let [v0, v1] = self.vlan.to_be_bytes();
        let [n0, n1] = self.inner_vlan.to_be_bytes();
        let [s0, s1] = self.sid.to_be_bytes();
        let [m0, m1, m2, m3, m4, m5] = self.client_mac;
        [
            i0, i1, i2, i3, v0, v1, n0, n1, s0, s1, m0, m1, m2, m3, m4, m5,
        ]
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        let [
            i0,
            i1,
            i2,
            i3,
            v0,
            v1,
            n0,
            n1,
            s0,
            s1,
            m0,
            m1,
            m2,
            m3,
            m4,
            m5,
        ] = b;
        SessionKey {
            ifindex: u32::from_le_bytes([i0, i1, i2, i3]),
            vlan: u16::from_be_bytes([v0, v1]),
            inner_vlan: u16::from_be_bytes([n0, n1]),
            sid: u16::from_be_bytes([s0, s1]),
            client_mac: [m0, m1, m2, m3, m4, m5],
        }
    }
}

/// One subscriber session, as the daemon fills it (mirrors the G4.3a
/// session descriptor: MAC, SID, port, VLAN, IPv4, IPv6, rate limits).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Session {
    /// `F_*` bits.
    pub flags: u16,
    /// Access port.
    pub ifindex: u32,
    pub sid: u16,
    pub vlan: u16,
    pub inner_vlan: u16,
    /// TPID of the outer tag when there are two (0x88a8, or 0x8100 for
    /// "Q-in-Q" with 802.1Q twice); 0 = 0x88a8.
    pub outer_tpid: u16,
    /// Largest IP packet toward the subscriber (its MRU, RFC 1661 §6.1 /
    /// RFC 4638); 0 = [`DEFAULT_MTU`].
    pub mtu: u16,
    pub client_mac: [u8; 6],
    /// The BNG's MAC on the access port (the PADO/PADS source).
    pub server_mac: [u8; 6],
    pub ipv4: [u8; 4],
    /// The subscriber's /64 (first 8 bytes).
    pub ipv6_prefix: [u8; 8],
    /// Delegated prefix (first 8 bytes) and its length (1..=64).
    pub pd_prefix: [u8; 8],
    pub pd_len: u8,
    /// Subscriber → network (RouterOS "rx" of the PPP interface).
    pub up: Rate,
    /// Network → subscriber ("tx").
    pub down: Rate,
}

/// Header words of [`Session::to_words`], then the two rates.
pub const SESSION_HEAD_WORDS: usize = 7;
pub const SESSION_WORDS: usize = SESSION_HEAD_WORDS + 2 * RATE_WORDS;
pub type SessionWords = [u64; SESSION_WORDS];

fn mac_word(m: [u8; 6]) -> u64 {
    let [a, b, c, d, e, f] = m;
    u64::from_be_bytes([0, 0, a, b, c, d, e, f])
}

fn word_mac(w: u64) -> [u8; 6] {
    let [_, _, a, b, c, d, e, f] = w.to_be_bytes();
    [a, b, c, d, e, f]
}

impl Session {
    /// The map value: `[ifindex | sid << 32 | flags << 48, vlan |
    /// inner_vlan << 16 | outer_tpid << 32 | mtu << 48, client MAC |
    /// pd_len << 48, server MAC, IPv4 (big endian), IPv6 /64, delegated
    /// prefix, up rate, down rate]`.
    pub fn to_words(&self) -> SessionWords {
        let mut w = [0u64; SESSION_WORDS];
        let head = [
            u64::from(self.ifindex) | u64::from(self.sid) << 32 | u64::from(self.flags) << 48,
            u64::from(self.vlan)
                | u64::from(self.inner_vlan) << 16
                | u64::from(self.outer_tpid) << 32
                | u64::from(self.mtu) << 48,
            mac_word(self.client_mac) | u64::from(self.pd_len) << 48,
            mac_word(self.server_mac),
            u64::from(u32::from_be_bytes(self.ipv4)),
            u64::from_be_bytes(self.ipv6_prefix),
            u64::from_be_bytes(self.pd_prefix),
        ];
        for (slot, v) in w.iter_mut().zip(
            head.into_iter()
                .chain(self.up.to_words())
                .chain(self.down.to_words()),
        ) {
            *slot = v;
        }
        w
    }

    pub fn from_words(w: &SessionWords) -> Session {
        let v = View::of(w);
        Session {
            flags: v.flags,
            ifindex: v.ifindex,
            sid: v.sid,
            vlan: v.vlan,
            inner_vlan: v.inner_vlan,
            outer_tpid: v.outer_tpid,
            mtu: v.mtu,
            client_mac: v.client_mac,
            server_mac: v.server_mac,
            ipv4: v.ipv4,
            ipv6_prefix: v.ipv6_prefix.to_be_bytes(),
            pd_prefix: v.pd_prefix.to_be_bytes(),
            pd_len: v.pd_len,
            up: rate_of(w, 0),
            down: rate_of(w, 1),
        }
    }

    /// Its key in the upstream map.
    pub fn key(&self) -> SessionKey {
        SessionKey {
            ifindex: self.ifindex,
            vlan: self.vlan,
            inner_vlan: self.inner_vlan,
            sid: self.sid,
            client_mac: self.client_mac,
        }
    }
}

/// Direction `dir` (0 up, 1 down) of a session's words.
#[inline(always)]
pub fn rate_of(w: &SessionWords, dir: usize) -> Rate {
    let base = SESSION_HEAD_WORDS + dir * RATE_WORDS;
    let mut r = [0u64; RATE_WORDS];
    for (i, slot) in r.iter_mut().enumerate() {
        *slot = w.get(base + i).copied().unwrap_or(0);
    }
    Rate::from_words(r)
}

/// The fields the data path reads, decoded from [`SessionWords`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub flags: u16,
    pub ifindex: u32,
    pub sid: u16,
    pub vlan: u16,
    pub inner_vlan: u16,
    pub outer_tpid: u16,
    pub mtu: u16,
    pub client_mac: [u8; 6],
    pub server_mac: [u8; 6],
    pub ipv4: [u8; 4],
    pub ipv6_prefix: u64,
    pub pd_prefix: u64,
    pub pd_len: u8,
}

impl View {
    #[inline(always)]
    pub fn of(w: &SessionWords) -> View {
        let [w0, w1, w2, w3, w4, w5, w6, ..] = *w;
        View {
            flags: (w0 >> 48) as u16,
            ifindex: w0 as u32,
            sid: (w0 >> 32) as u16,
            vlan: w1 as u16,
            inner_vlan: (w1 >> 16) as u16,
            outer_tpid: (w1 >> 32) as u16,
            mtu: (w1 >> 48) as u16,
            client_mac: word_mac(w2),
            server_mac: word_mac(w3),
            ipv4: (w4 as u32).to_be_bytes(),
            ipv6_prefix: w5,
            pd_prefix: w6,
            pd_len: (w2 >> 48) as u8,
        }
    }

    #[inline(always)]
    pub fn has(&self, f: u16) -> bool {
        self.flags & f != 0
    }

    #[inline(always)]
    pub fn mtu(&self) -> u16 {
        if self.mtu == 0 { DEFAULT_MTU } else { self.mtu }
    }

    /// VLAN tags on the access side (0, 1 or 2).
    #[inline(always)]
    pub fn tags(&self) -> u8 {
        match (self.vlan & TAGGED != 0, self.inner_vlan & TAGGED != 0) {
            (false, _) => 0,
            (true, false) => 1,
            (true, true) => 2,
        }
    }

    /// Whether IPv6 `src` belongs to the subscriber: its /64 or its
    /// delegated prefix.
    #[inline(always)]
    pub fn owns_v6(&self, src: &[u8; 16]) -> bool {
        let [a, b, c, d, e, f, g, h, ..] = *src;
        let net = u64::from_be_bytes([a, b, c, d, e, f, g, h]);
        if self.has(F_IPV6) && net == self.ipv6_prefix {
            return true;
        }
        if self.has(F_PD) && (1..=64).contains(&self.pd_len) {
            let mask = u64::MAX << (64 - u32::from(self.pd_len));
            return net & mask == self.pd_prefix & mask;
        }
        false
    }
}

// --- Counters -------------------------------------------------------------

/// Per-session counters: `[up packets, up bytes, down packets, down bytes,
/// up policed, down policed, spoofed, to the kernel]` (bytes are IP
/// bytes, as the PPP interface counts them).
pub const COUNTER_WORDS: usize = 8;
pub type Counters = [u64; COUNTER_WORDS];
pub const C_UP_PACKETS: usize = 0;
pub const C_UP_BYTES: usize = 1;
pub const C_DOWN_PACKETS: usize = 2;
pub const C_DOWN_BYTES: usize = 3;
pub const C_UP_POLICED: usize = 4;
pub const C_DOWN_POLICED: usize = 5;
pub const C_SPOOFED: usize = 6;
pub const C_KERNEL: usize = 7;

/// What happened to a frame, for the global per-CPU `PPPOE_STATS` (the
/// order is the map layout; new ones at the end).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Stat {
    /// Upstream, forwarded in XDP (FIB or CGNAT fast path).
    UpFast = 0,
    /// Upstream, decapsulated and handed to the kernel.
    UpKernel = 1,
    /// Discovery (0x8863): to userspace.
    Discovery = 2,
    /// LCP, authentication, NCPs: to userspace.
    Control = 3,
    /// A data protocol other than IPv4/IPv6: to userspace (it answers with
    /// LCP Protocol-Reject).
    OtherProtocol = 4,
    /// IPv6 from link-local or to multicast (RS, ND): to userspace.
    Ipv6Control = 5,
    /// A session frame to another MAC: not ours, to the kernel untouched.
    NotOurs = 6,
    /// Broken PPPoE or inner IP header: dropped.
    Malformed = 7,
    /// IP in a session the map does not have (spoofed or stale SID):
    /// dropped.
    UnknownSession = 8,
    /// Source address not the subscriber's: dropped.
    Spoofed = 9,
    /// Over the upload rate: dropped.
    UpPoliced = 10,
    /// Downstream, encapsulated in XDP.
    DownFast = 11,
    /// Downstream, TTL/hop limit ≤ 1: the kernel sends time exceeded.
    DownTtl = 12,
    /// Downstream, larger than the subscriber's MTU: the kernel fragments
    /// or sends "fragmentation needed"/"packet too big" (RFC 1191, 8201).
    DownMtu = 13,
    /// Downstream, the session is not marked fast: the kernel path.
    DownKernel = 14,
    /// Over the download rate: dropped.
    DownPoliced = 15,
    /// Upstream, the FIB did not resolve (no route, no neighbor, MTU):
    /// to the kernel.
    UpFib = 16,
    /// Downstream on a tagged uplink (not handled in XDP yet): to the
    /// kernel.
    DownTagged = 17,
}

impl Stat {
    pub const ALL: [Stat; 18] = [
        Stat::UpFast,
        Stat::UpKernel,
        Stat::Discovery,
        Stat::Control,
        Stat::OtherProtocol,
        Stat::Ipv6Control,
        Stat::NotOurs,
        Stat::Malformed,
        Stat::UnknownSession,
        Stat::Spoofed,
        Stat::UpPoliced,
        Stat::DownFast,
        Stat::DownTtl,
        Stat::DownMtu,
        Stat::DownKernel,
        Stat::DownPoliced,
        Stat::UpFib,
        Stat::DownTagged,
    ];
    pub const SLOTS: u32 = 18;

    pub fn name(self) -> &'static str {
        match self {
            Stat::UpFast => "up-fast",
            Stat::UpKernel => "up-kernel",
            Stat::Discovery => "discovery",
            Stat::Control => "control",
            Stat::OtherProtocol => "other-protocol",
            Stat::Ipv6Control => "ipv6-control",
            Stat::NotOurs => "not-ours",
            Stat::Malformed => "malformed",
            Stat::UnknownSession => "unknown-session",
            Stat::Spoofed => "spoofed",
            Stat::UpPoliced => "up-policed",
            Stat::DownFast => "down-fast",
            Stat::DownTtl => "down-ttl",
            Stat::DownMtu => "down-mtu",
            Stat::DownKernel => "down-kernel",
            Stat::DownPoliced => "down-policed",
            Stat::UpFib => "up-fib",
            Stat::DownTagged => "down-tagged",
        }
    }
}

// --- Lookups --------------------------------------------------------------

/// The session maps: hash and arrays in the kernel, collections in tests.
pub trait Sessions {
    /// Session index of an upstream key.
    fn by_key(&self, key: &[u8; KEY_LEN]) -> Option<u32>;
    /// The session at `idx`.
    fn session(&self, idx: u32) -> Option<&SessionWords>;
    /// Session index owning IPv4 `dst` (exact /32).
    fn by_v4(&self, dst: [u8; 4]) -> Option<u32>;
    /// Session index whose /64 or delegated prefix holds IPv6 `dst`
    /// (longest prefix).
    fn by_v6(&self, dst: [u8; 16]) -> Option<u32>;
    /// Policer state of session `idx`, direction `dir` (0 up, 1 down).
    fn policer(&mut self, idx: u32, dir: u32) -> Option<&mut policer::State>;
}

/// Police `bytes` of session `idx` in direction `dir`. A missing state
/// (should not happen: the daemon creates it with the session) passes.
#[inline(always)]
fn police<L: Sessions>(l: &mut L, idx: u32, dir: u32, now: u64, bytes: u64) -> bool {
    let Some(r) = l.session(idx).map(|w| rate_of(w, dir as usize)) else {
        return true;
    };
    if r.rate == 0 {
        return true;
    }
    match l.policer(idx, dir) {
        Some(st) => policer::admit(st, &r, now, bytes),
        None => true,
    }
}

// --- Upstream -------------------------------------------------------------

/// A session frame's L2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessHeader {
    /// VLAN tags before the PPPoE type (0..=2).
    pub tags: u8,
    pub vlan: u16,
    pub inner_vlan: u16,
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub sid: u16,
    /// PPP protocol field.
    pub proto: u16,
    /// LENGTH minus the protocol field: the PPP payload.
    pub payload: u16,
}

impl AccessHeader {
    /// Offset of the PPP payload (the inner IP header).
    #[inline(always)]
    pub fn payload_off(&self) -> usize {
        ETH_HLEN + 4 * usize::from(self.tags) + PPPOE_OVERHEAD
    }
}

/// What an access-side frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    NotPppoe,
    Discovery,
    Malformed,
    Session(AccessHeader),
}

/// Parse the L2 of an access-side frame (up to two VLAN tags).
#[inline(always)]
pub fn access<P: Packet + ?Sized>(p: &P) -> Access {
    let Some(t0) = p.be16(12) else {
        return Access::NotPppoe;
    };
    let (tags, vlan, inner, ethertype) = if t0 == ETH_P_8021Q || t0 == ETH_P_8021AD {
        let (Some(tci), Some(t1)) = (p.be16(14), p.be16(16)) else {
            return Access::NotPppoe;
        };
        let outer = TAGGED | (tci & 0x0fff);
        if t1 == ETH_P_8021Q || t1 == ETH_P_8021AD {
            let (Some(tci2), Some(t2)) = (p.be16(18), p.be16(20)) else {
                return Access::NotPppoe;
            };
            (2u8, outer, TAGGED | (tci2 & 0x0fff), t2)
        } else {
            (1, outer, 0, t1)
        }
    } else {
        (0, 0, 0, t0)
    };
    match ethertype {
        ETH_P_PPP_DISC => return Access::Discovery,
        ETH_P_PPP_SES => {}
        _ => return Access::NotPppoe,
    }
    let off = ETH_HLEN + 4 * usize::from(tags);
    let (Some(h), Some(macs)) = (p.bytes::<8>(off), p.bytes::<12>(0)) else {
        return Access::Malformed;
    };
    let [vt, code, s0, s1, l0, l1, p0, p1] = h;
    let len = u16::from_be_bytes([l0, l1]);
    // RFC 2516 §4: VER/TYPE 1/1, CODE 0 in the session stage; LENGTH
    // holds at least the protocol field and fits in the frame (Ethernet
    // may pad past it).
    if vt != VER_TYPE || code != 0 || len < 2 || off + 6 + usize::from(len) > p.len() {
        return Access::Malformed;
    }
    let [d0, d1, d2, d3, d4, d5, m0, m1, m2, m3, m4, m5] = macs;
    Access::Session(AccessHeader {
        tags,
        vlan,
        inner_vlan: inner,
        dst: [d0, d1, d2, d3, d4, d5],
        src: [m0, m1, m2, m3, m4, m5],
        sid: u16::from_be_bytes([s0, s1]),
        proto: u16::from_be_bytes([p0, p1]),
        payload: len - 2,
    })
}

/// A session frame that goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpSession {
    pub idx: u32,
    pub tags: u8,
    pub v6: bool,
    /// The inner IP packet's length.
    pub ip_len: u16,
    /// [`F_FAST_UP`]: may be forwarded without the kernel.
    pub fast: bool,
}

/// The upstream verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Up {
    /// Not a PPPoE frame: the rest of the program decides.
    NotPppoe,
    /// To userspace untouched (`XDP_PASS`).
    User(Stat),
    /// Dropped; the session, when known.
    Drop(Stat, Option<u32>),
    /// Decapsulate and forward.
    Session(UpSession),
}

/// Classify and police an access-side frame that arrived on `ifindex`.
#[inline(always)]
pub fn upstream<P: Packet + ?Sized, L: Sessions>(p: &P, ifindex: u32, l: &mut L, now: u64) -> Up {
    let h = match access(p) {
        Access::NotPppoe => return Up::NotPppoe,
        Access::Discovery => return Up::User(Stat::Discovery),
        Access::Malformed => return Up::Drop(Stat::Malformed, None),
        Access::Session(h) => h,
    };
    let v6 = match h.proto {
        PPP_IPV4 => false,
        PPP_IPV6 => true,
        p if p >= 0x4000 => return Up::User(Stat::Control),
        _ => return Up::User(Stat::OtherProtocol),
    };
    let key = SessionKey {
        ifindex,
        vlan: h.vlan,
        inner_vlan: h.inner_vlan,
        sid: h.sid,
        client_mac: h.src,
    };
    let Some(idx) = l.by_key(&key.to_bytes()) else {
        return Up::Drop(Stat::UnknownSession, None);
    };
    let Some(s) = l.session(idx).map(View::of) else {
        return Up::Drop(Stat::UnknownSession, None);
    };
    // A stale index (slot reused) or a cleared session.
    if !s.has(F_ACTIVE)
        || s.ifindex != ifindex
        || s.sid != h.sid
        || s.client_mac != h.src
        || s.vlan != h.vlan
        || s.inner_vlan != h.inner_vlan
    {
        return Up::Drop(Stat::UnknownSession, None);
    }
    if h.dst != s.server_mac {
        return Up::User(Stat::NotOurs);
    }
    let off = h.payload_off();
    let ip_len = if v6 {
        let Some(ip) = p.bytes::<40>(off) else {
            return Up::Drop(Stat::Malformed, Some(idx));
        };
        let [ver, _, _, _, l0, l1, _, _, rest @ ..] = ip;
        let len = 40 + usize::from(u16::from_be_bytes([l0, l1]));
        if ver >> 4 != 6 || len > usize::from(h.payload) {
            return Up::Drop(Stat::Malformed, Some(idx));
        }
        let (src, dst) = crate::parse::split16(rest);
        // fe80::/10 source or multicast destination: RS, NS, DAD, MLD…
        // The link belongs to userspace.
        let [s0, s1, ..] = src;
        let [d0, ..] = dst;
        if (s0 == 0xfe && s1 & 0xc0 == 0x80) || d0 == 0xff || src == [0; 16] {
            return Up::User(Stat::Ipv6Control);
        }
        if !s.owns_v6(&src) {
            return Up::Drop(Stat::Spoofed, Some(idx));
        }
        len
    } else {
        let Some([vi, _, l0, l1, _, _, _, _, _, _, _, _, a, b, c, d]) = p.bytes::<16>(off) else {
            return Up::Drop(Stat::Malformed, Some(idx));
        };
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        if vi >> 4 != 4 || vi & 0x0f < 5 || len < 20 || len > usize::from(h.payload) {
            return Up::Drop(Stat::Malformed, Some(idx));
        }
        if !s.has(F_IPV4) || [a, b, c, d] != s.ipv4 {
            return Up::Drop(Stat::Spoofed, Some(idx));
        }
        len
    };
    if !police(l, idx, 0, now, ip_len as u64) {
        return Up::Drop(Stat::UpPoliced, Some(idx));
    }
    Up::Session(UpSession {
        idx,
        tags: h.tags,
        v6,
        ip_len: ip_len as u16,
        fast: s.has(F_FAST_UP),
    })
}

/// Strip the VLAN tags and the PPPoE header: the frame becomes an
/// untagged Ethernet frame of the inner protocol, same MACs (the
/// destination is the BNG, so the kernel takes it as its own). Constant
/// offsets per tag count (the verifier wants them after a head move).
#[inline(always)]
pub fn decap<P: PacketHead + ?Sized>(p: &mut P, tags: u8, v6: bool) -> Option<()> {
    match tags {
        0 => decap_n::<P, 8>(p, v6),
        1 => decap_n::<P, 12>(p, v6),
        2 => decap_n::<P, 16>(p, v6),
        _ => None,
    }
}

#[inline(always)]
fn decap_n<P: PacketHead + ?Sized, const SHIFT: usize>(p: &mut P, v6: bool) -> Option<()> {
    let macs = p.bytes::<12>(0)?;
    let ethertype = if v6 { ETH_P_IPV6 } else { ETH_P_IP };
    // The ethertype lands on the PPP protocol field: both end the header.
    p.store(SHIFT + 12, ethertype.to_be_bytes())?;
    p.store(SHIFT, macs)?;
    p.adjust_head(SHIFT as i32)
}

// --- Downstream -----------------------------------------------------------

/// Length and TTL/hop limit of the IP packet of an untagged frame (IP at
/// 14, constant offsets).
#[inline(always)]
pub fn ip_meta<P: Packet + ?Sized>(p: &P, v6: bool) -> Option<(u16, u8)> {
    if v6 {
        let [_, _, _, _, l0, l1, _, hop] = p.bytes::<8>(ETH_HLEN)?;
        Some((u16::from_be_bytes([l0, l1]).checked_add(40)?, hop))
    } else {
        let [_, _, l0, l1, _, _, _, _, ttl] = p.bytes::<9>(ETH_HLEN)?;
        Some((u16::from_be_bytes([l0, l1]), ttl))
    }
}

/// Take one from the TTL (IPv4, checksum updated per RFC 1624) or the hop
/// limit (IPv6) of an untagged frame. Call only with TTL > 1.
#[inline(always)]
pub fn ttl_dec<P: PacketMut + ?Sized>(p: &mut P, v6: bool) -> Option<()> {
    if v6 {
        let [hop] = p.bytes::<1>(ETH_HLEN + 7)?;
        return p.store(ETH_HLEN + 7, [hop.checked_sub(1)?]);
    }
    let word = p.be16(ETH_HLEN + 8)?;
    let new = word.checked_sub(0x0100)?;
    let csum = p.be16(ETH_HLEN + 10)?;
    p.store(ETH_HLEN + 8, new.to_be_bytes())?;
    p.store(ETH_HLEN + 10, nat::update16(csum, word, new).to_be_bytes())
}

/// Where a downstream packet goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownSession {
    pub idx: u32,
    pub ifindex: u32,
    pub tags: u8,
    pub outer_tpid: u16,
    pub vlan: u16,
    pub inner_vlan: u16,
    pub sid: u16,
    pub client_mac: [u8; 6],
    pub server_mac: [u8; 6],
    pub ip_len: u16,
    pub v6: bool,
}

/// The downstream verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Down {
    /// Not to a subscriber.
    NotSub,
    /// To a subscriber, but the kernel must handle it.
    Kernel(Stat, u32),
    Drop(Stat, u32),
    Encap(DownSession),
}

/// The session owning `dst`.
#[inline(always)]
pub fn owner<L: Sessions>(l: &L, dst: &Addr) -> Option<u32> {
    match *dst {
        Addr::V4(a) => l.by_v4(a),
        Addr::V6(a) => l.by_v6(a),
    }
}

/// Decide a packet of `ip_len` bytes with `ttl` to session `idx`.
/// `accepted`: conntrack already accepted the flow (the CGNAT fast path),
/// so [`F_FAST_DOWN`] is not needed.
#[inline(always)]
pub fn downstream<L: Sessions>(
    l: &mut L,
    idx: u32,
    v6: bool,
    ip_len: u16,
    ttl: u8,
    now: u64,
    accepted: bool,
) -> Down {
    let Some(s) = l.session(idx).map(View::of) else {
        return Down::NotSub;
    };
    if !s.has(F_ACTIVE) {
        return Down::NotSub;
    }
    if !accepted && !s.has(F_FAST_DOWN) {
        return Down::Kernel(Stat::DownKernel, idx);
    }
    if ttl <= 1 {
        return Down::Kernel(Stat::DownTtl, idx);
    }
    if ip_len > s.mtu() {
        return Down::Kernel(Stat::DownMtu, idx);
    }
    if !police(l, idx, 1, now, u64::from(ip_len)) {
        return Down::Drop(Stat::DownPoliced, idx);
    }
    Down::Encap(DownSession {
        idx,
        ifindex: s.ifindex,
        tags: s.tags(),
        outer_tpid: if s.outer_tpid == 0 {
            ETH_P_8021AD
        } else {
            s.outer_tpid
        },
        vlan: s.vlan,
        inner_vlan: s.inner_vlan,
        sid: s.sid,
        client_mac: s.client_mac,
        server_mac: s.server_mac,
        ip_len,
        v6,
    })
}

/// Push the access-side header on an untagged frame whose IP packet `d`
/// describes (the TTL already decremented): MACs, tags, PPPoE, PPP
/// protocol. Ethernet padding past the IP packet stays (PPPoE LENGTH says
/// where the payload ends).
#[inline(always)]
pub fn encap<P: PacketHead + ?Sized>(p: &mut P, d: &DownSession) -> Option<()> {
    let [s0, s1] = d.sid.to_be_bytes();
    let [l0, l1] = d.ip_len.checked_add(2)?.to_be_bytes();
    let [p0, p1] = if d.v6 { PPP_IPV6 } else { PPP_IPV4 }.to_be_bytes();
    let pppoe = [0x88, 0x64, VER_TYPE, 0, s0, s1, l0, l1, p0, p1];
    let [c0, c1, c2, c3, c4, c5] = d.client_mac;
    let [m0, m1, m2, m3, m4, m5] = d.server_mac;
    let macs = [c0, c1, c2, c3, c4, c5, m0, m1, m2, m3, m4, m5];
    let tag = |tpid: u16, v: u16| {
        let [t0, t1] = tpid.to_be_bytes();
        let [v0, v1] = (v & 0x0fff).to_be_bytes();
        [t0, t1, v0, v1]
    };
    match d.tags {
        0 => {
            p.adjust_head(-(PPPOE_OVERHEAD as i32))?;
            p.store(0, macs)?;
            p.store(12, pppoe)
        }
        1 => {
            p.adjust_head(-(PPPOE_OVERHEAD as i32 + 4))?;
            p.store(0, macs)?;
            p.store(12, tag(ETH_P_8021Q, d.vlan))?;
            p.store(16, pppoe)
        }
        2 => {
            p.adjust_head(-(PPPOE_OVERHEAD as i32 + 8))?;
            p.store(0, macs)?;
            p.store(12, tag(d.outer_tpid, d.vlan))?;
            p.store(16, tag(ETH_P_8021Q, d.inner_vlan))?;
            p.store(20, pppoe)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_round_trip() {
        let s = Session {
            flags: F_ACTIVE | F_IPV4 | F_PD,
            ifindex: 0xdead_beef,
            sid: 0x1234,
            vlan: TAGGED | 100,
            inner_vlan: TAGGED | 4095,
            outer_tpid: 0x8100,
            mtu: 1500,
            client_mac: [2, 3, 4, 5, 6, 7],
            server_mac: [0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa],
            ipv4: [100, 64, 1, 2],
            ipv6_prefix: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 1],
            pd_prefix: [0x20, 1, 0xd, 0xb8, 0xff, 0, 0, 0],
            pd_len: 56,
            up: Rate::mikrotik(10_000_000, 20_000_000, 0, 0),
            down: Rate::mikrotik(100_000_000, 0, 0, 0),
        };
        assert_eq!(Session::from_words(&s.to_words()), s);
        let k = s.key();
        assert_eq!(SessionKey::from_bytes(k.to_bytes()), k);
        let v = View::of(&s.to_words());
        assert_eq!(v.tags(), 2);
        assert!(v.owns_v6(&[0x20, 1, 0xd, 0xb8, 0xff, 0, 0, 0x7f, 1, 0, 0, 0, 0, 0, 0, 1]));
        assert!(!v.owns_v6(&[0x20, 1, 0xd, 0xb8, 0xff, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        // The /64 only counts with F_IPV6.
        assert!(!v.owns_v6(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn stats_have_stable_codes() {
        for (i, s) in Stat::ALL.iter().enumerate() {
            assert_eq!(*s as usize, i);
        }
        assert_eq!(Stat::ALL.len() as u32, Stat::SLOTS);
    }
}

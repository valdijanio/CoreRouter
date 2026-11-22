//! LSP ping and traceroute on Linux (G3.5b, RFC 8029 with RFC 9570),
//! without `unsafe`:
//!
//! - **Sending:** the request leaves as traffic of the FEC would: the
//!   route of the FEC (`RTM_GETROUTE` with `RTM_F_FIB_MATCH`) gives the next
//!   hop, the interface and the labels (`RTA_ENCAP`, `MPLS_IPTUNNEL_DST`);
//!   the whole Ethernet frame (labels, IP to 127.0.0.1 with TTL 1, UDP to
//!   3503) goes out on an `AF_PACKET` socket of that interface to the next
//!   hop's MAC. The kernel cannot send it itself: a packet to 127/8 never
//!   leaves the host. Replies come back as plain UDP to the source port of
//!   a socket of this process.
//! - **Answering:** three `AF_PACKET` sockets for the host, one per
//!   protocol (MPLS, IPv4, IPv6), not bound to an interface (bound, every
//!   packet of the port was cloned: G3.9d, `Taps` in `host.rs`); the frame's
//!   interface is checked against the MPLS ones. A classic BPF filter, so
//!   the kernel copies only candidates: an MPLS frame whose top label TTL
//!   expired (the kernel drops it without an ICMP) or that carries explicit
//!   null, and IP to 127/8 (::1, ::ffff:127/104) UDP port 3503 (the
//!   kernel drops it as martian; the tap sees it first). Protocol sockets
//!   are not called for frames the host sends, unlike `ETH_P_ALL` ones.
//!   Replies leave from a UDP socket on port 3503, IP TTL 255 (§4.5).
//! - **ICMP for expired labeled packets** (G3.9d): an expired frame that
//!   is not an echo request becomes an [`expired::Expired`] ([`classify`]);
//!   its time exceeded leaves by the IP table from an `IPPROTO_RAW` socket,
//!   or along the LSP as a whole frame on the packet socket of the label's
//!   way out, to the next hop's MAC ([`icmp_frame`]).
//! - **ICMP for labeled packets too big for their way out** (G3.9da): with
//!   `icmp-too-big` on, the MPLS filter also keeps frames longer than the
//!   smallest way out of the label table ([`mpls_filter`]; on a network of
//!   equal MTUs no frame is, so no copy), cut to what the error quotes;
//!   [`classify`] makes them a [`too_big::TooBig`].
//! - **What the LSR knows** ([`LsrView`]): the label table (one dump,
//!   kept a second), the addresses and MTUs of the links (kept a second),
//!   the route of each FEC asked (kept a second, 1024 at most).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_hal::lsp::{Frame, Heard, expired, too_big};
use corerouter_hal::probe::MplsLabel;
use corerouter_model::IfName;
use socket2::SockFilter;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_HEADER: usize = 14;
/// Labels walked in a received frame.
const MAX_STACK: usize = 16;
const IPPROTO_UDP: u8 = 17;
const UDP_HEADER: usize = 8;
/// Largest frame read or built (a jumbo frame).
pub const MAX_FRAME: usize = 9216;

// --- frames -----------------------------------------------------------------

use crate::dhcp::sum16;

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// What a request frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameSpec<'a> {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    /// Labels, top first; empty: the IP packet goes out unlabeled.
    pub labels: &'a [u32],
    pub ttl: u8,
    pub tos: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub id: u16,
    pub payload: &'a [u8],
}

/// The whole Ethernet frame of a request (RFC 8029 §4.3: IP TTL 1, UDP to
/// 3503, no Router Alert since RFC 9570 §4). `None`: families differ or
/// it would not fit an IP packet.
pub fn build_frame(f: &FrameSpec<'_>) -> Option<Vec<u8>> {
    let udp_len = UDP_HEADER.checked_add(f.payload.len())?;
    let ethertype = match (f.labels.is_empty(), f.dst) {
        (false, _) => ETH_P_MPLS_UC,
        (true, IpAddr::V4(_)) => ETH_P_IP,
        (true, IpAddr::V6(_)) => ETH_P_IPV6,
    };
    let mut out = Vec::with_capacity(ETH_HEADER + 4 * f.labels.len() + 48 + udp_len);
    out.extend_from_slice(&f.dst_mac);
    out.extend_from_slice(&f.src_mac);
    out.extend_from_slice(&ethertype.to_be_bytes());
    let tc = f.tos >> 5;
    for (i, l) in f.labels.iter().enumerate() {
        let entry = MplsLabel {
            label: *l,
            tc,
            bottom: i + 1 == f.labels.len(),
            ttl: f.ttl,
        };
        out.extend_from_slice(&corerouter_hal::lsp::wire::label_word(&entry).to_be_bytes());
    }
    let len16 = |n: usize| u16::try_from(n).ok();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&f.src_port.to_be_bytes());
    udp.extend_from_slice(&corerouter_hal::lsp::wire::PORT.to_be_bytes());
    udp.extend_from_slice(&len16(udp_len)?.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(f.payload);
    match (f.src, f.dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = len16(20 + udp_len)?;
            let mut ip = vec![0x45, f.tos];
            ip.extend_from_slice(&total.to_be_bytes());
            ip.extend_from_slice(&f.id.to_be_bytes());
            ip.extend_from_slice(&[0, 0, 1, IPPROTO_UDP, 0, 0]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let c = fold(sum16(&ip, 0)).to_be_bytes();
            ip.splice(10..12, c);
            // UDP checksum over the pseudo-header (RFC 768).
            let mut acc = sum16(&s.octets(), 0);
            acc = sum16(&d.octets(), acc);
            acc = acc
                .wrapping_add(u32::from(IPPROTO_UDP))
                .wrapping_add(udp_len as u32);
            let c = match fold(sum16(&udp, acc)) {
                0 => 0xffff,
                c => c,
            };
            udp.splice(6..8, c.to_be_bytes());
            out.extend_from_slice(&ip);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut ip = vec![0x60 | (f.tos >> 4), (f.tos & 0x0f) << 4, 0, 0];
            ip.extend_from_slice(&len16(udp_len)?.to_be_bytes());
            ip.extend_from_slice(&[IPPROTO_UDP, 1]);
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            // IPv6 needs the UDP checksum (RFC 8200 §8.1).
            let mut acc = sum16(&s.octets(), 0);
            acc = sum16(&d.octets(), acc);
            acc = acc
                .wrapping_add(udp_len as u32)
                .wrapping_add(u32::from(IPPROTO_UDP));
            let c = match fold(sum16(&udp, acc)) {
                0 => 0xffff,
                c => c,
            };
            udp.splice(6..8, c.to_be_bytes());
            out.extend_from_slice(&ip);
        }
        _ => return None,
    }
    out.extend_from_slice(&udp);
    Some(out)
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn v6_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let s: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(s))
}

/// A frame heard on `interface`, read as a request candidate: its label
/// stack, IP addresses and UDP ports and payload. `None`: not UDP over
/// IPv4/IPv6 (fragments included), or malformed.
pub fn parse_frame(frame: &[u8], interface: &IfName) -> Option<Heard> {
    let mut ethertype = u16_at(frame, 12)?;
    let mut at = ETH_HEADER;
    let mut stack = Vec::new();
    if ethertype == ETH_P_MPLS_UC {
        loop {
            let w = frame.get(at..at + 4)?;
            let w = u32::from_be_bytes(w.try_into().ok()?);
            let l = MplsLabel {
                label: w >> 12,
                tc: ((w >> 9) & 7) as u8,
                bottom: w & 0x100 != 0,
                ttl: (w & 0xff) as u8,
            };
            stack.push(l);
            at += 4;
            if l.bottom {
                break;
            }
            if stack.len() >= MAX_STACK {
                return None;
            }
        }
        // What is under the stack: the IP version nibble (RFC 3032 §2.2,
        // as the kernel does for explicit null).
        ethertype = match frame.get(at)? >> 4 {
            4 => ETH_P_IP,
            6 => ETH_P_IPV6,
            _ => return None,
        };
    }
    let (src, dst, udp_at) = match ethertype {
        ETH_P_IP => {
            let vihl = *frame.get(at)?;
            let ihl = usize::from(vihl & 0x0f) * 4;
            if vihl >> 4 != 4 || ihl < 20 || *frame.get(at + 9)? != IPPROTO_UDP {
                return None;
            }
            // Fragments are not requests.
            if u16_at(frame, at + 6)? & 0x3fff != 0 {
                return None;
            }
            let s: [u8; 4] = frame.get(at + 12..at + 16)?.try_into().ok()?;
            let d: [u8; 4] = frame.get(at + 16..at + 20)?.try_into().ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(s)),
                IpAddr::V4(Ipv4Addr::from(d)),
                at + ihl,
            )
        }
        ETH_P_IPV6 => {
            if frame.get(at)? >> 4 != 6 || *frame.get(at + 6)? != IPPROTO_UDP {
                return None;
            }
            (
                IpAddr::V6(v6_at(frame, at + 8)?),
                IpAddr::V6(v6_at(frame, at + 24)?),
                at + 40,
            )
        }
        _ => return None,
    };
    let src_port = u16_at(frame, udp_at)?;
    let dst_port = u16_at(frame, udp_at + 2)?;
    let len = usize::from(u16_at(frame, udp_at + 4)?);
    if len < UDP_HEADER {
        return None;
    }
    // Ethernet pads short frames: the UDP length says where it ends.
    let payload = frame.get(udp_at + UDP_HEADER..udp_at + len)?.to_vec();
    Some(Heard {
        interface: interface.clone(),
        stack,
        src,
        dst,
        src_port,
        dst_port,
        payload,
    })
}

/// Whether `h` is an MPLS echo request candidate: UDP 3503 to 127/8, ::1
/// or ::ffff:127/104 (RFC 8029 §4.3, RFC 9570 §4).
fn is_echo(h: &Heard) -> bool {
    h.dst_port == corerouter_hal::lsp::wire::PORT
        && match h.dst {
            IpAddr::V4(a) => a.is_loopback(),
            IpAddr::V6(a) => a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v| v.is_loopback()),
        }
}

/// What a frame heard on `interface` is for: an echo request candidate
/// for the responder, a labeled packet whose TTL expired here (G3.9d: the
/// kernel drops it without the ICMP error), or, when `big` is given, one
/// whose frame payload (labels and IP packet) is longer than `big` and so
/// may not fit its way out (G3.9da). `None`: none of these.
pub fn classify(frame: &[u8], interface: &IfName, big: Option<usize>) -> Option<Frame> {
    let heard = parse_frame(frame, interface);
    if u16_at(frame, 12)? == ETH_P_MPLS_UC && !heard.as_ref().is_some_and(is_echo) {
        let mpls = frame.get(ETH_HEADER..)?;
        if let Some(e) = expired::parse(interface, mpls) {
            return Some(Frame::Expired(e));
        }
        if let Some(big) = big
            && let Some(t) = too_big::parse(interface, mpls)
            && 4 * t.stack.len() + t.len > big
        {
            return Some(Frame::TooBig(t));
        }
    }
    heard.map(Frame::Echo)
}

/// The Ethernet frame of an ICMP error sent along an LSP: `stack` (empty:
/// unlabeled) over the IP `packet`.
pub fn icmp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    stack: &[MplsLabel],
    packet: &[u8],
) -> Vec<u8> {
    let ethertype = match (stack.is_empty(), packet.first().map(|b| b >> 4)) {
        (false, _) => ETH_P_MPLS_UC,
        (true, Some(6)) => ETH_P_IPV6,
        (true, _) => ETH_P_IP,
    };
    let mut out = Vec::with_capacity(ETH_HEADER + 4 * stack.len() + packet.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&ethertype.to_be_bytes());
    for l in stack {
        out.extend_from_slice(&corerouter_hal::lsp::wire::label_word(l).to_be_bytes());
    }
    out.extend_from_slice(packet);
    out
}

// --- kernel filters (classic BPF, linux/filter.h) ---------------------------

const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_W_LEN: u16 = 0x80;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JSET_K: u16 = 0x45;
const AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;
const KEEP: u32 = 0xffff;

/// One instruction: code, jump if true, jump if false, constant.
pub type Insn = (u16, u8, u8, u32);

/// `SKF_AD_OFF + SKF_AD_HATYPE` (linux/filter.h): the device type.
const AD_HATYPE: u32 = 0xffff_f000 + 28;
const ARPHRD_ETHER: u32 = 1;

/// `prog` behind a check that the frame came from an Ethernet device: the
/// taps listen on every device (see `Taps` in `host.rs`), and the offsets
/// of the filters assume an Ethernet header (a PPP or tun device hands the
/// IP packet bare).
pub fn ether_only(prog: &[Insn]) -> Vec<Insn> {
    let mut p = vec![
        (LD_W_ABS, 0, 0, AD_HATYPE),
        (JEQ_K, 1, 0, ARPHRD_ETHER),
        (RET_K, 0, 0, 0),
    ];
    p.extend_from_slice(prog);
    p
}

/// The kernel's form of a program.
pub fn sock_filter(prog: &[Insn]) -> Vec<SockFilter> {
    prog.iter()
        .map(|(code, jt, jf, k)| SockFilter::new(*code, *jt, *jf, *k))
        .collect()
}

/// MPLS frames: the top label's TTL is 1 or 0 (it expires here), or the
/// label is explicit null (IPv4 0, IPv6 2: it ends here).
pub const MPLS_FILTER: &[Insn] = &[
    /* 0 */ (LD_B_ABS, 0, 0, 17), // top label TTL
    /* 1 */ (JGT_K, 0, 4, 1), // ≤ 1 → keep
    /* 2 */ (LD_W_ABS, 0, 0, 14),
    /* 3 */ (AND_K, 0, 0, 0xffff_d000), // the label, bit 1 cleared: 0 and 2 → 0
    /* 4 */ (JEQ_K, 1, 0, 0),
    /* 5 */ (RET_K, 0, 0, 0),
    /* 6 */ (RET_K, 0, 0, KEEP),
];

/// [`MPLS_FILTER`], also keeping frames longer than `frame_len` octets
/// (Ethernet header included: `skb->len` once `packet_rcv` pushed it),
/// cut to the Ethernet header plus [`too_big::SNAP`] (G3.9da: the error
/// quotes no more, and a jumbo frame is not copied whole). `None`: as
/// [`MPLS_FILTER`].
pub fn mpls_filter(frame_len: Option<u32>) -> Vec<Insn> {
    let Some(len) = frame_len else {
        return MPLS_FILTER.to_vec();
    };
    vec![
        /* 0 */ (LD_B_ABS, 0, 0, 17), // top label TTL
        /* 1 */ (JGT_K, 0, 6, 1), // ≤ 1 → keep
        /* 2 */ (LD_W_ABS, 0, 0, 14),
        /* 3 */ (AND_K, 0, 0, 0xffff_d000), // explicit null → keep
        /* 4 */ (JEQ_K, 3, 0, 0),
        /* 5 */ (LD_W_LEN, 0, 0, 0),
        /* 6 */ (JGT_K, 2, 0, len), // longer → keep the start
        /* 7 */ (RET_K, 0, 0, 0),
        /* 8 */ (RET_K, 0, 0, KEEP),
        /* 9 */ (RET_K, 0, 0, (ETH_HEADER + too_big::SNAP) as u32),
    ]
}

/// IPv4: UDP to 3503 and 127/8, not a fragment.
pub const IP4_FILTER: &[Insn] = &[
    /* 0 */ (LD_B_ABS, 0, 0, 23), // protocol
    /* 1 */ (JEQ_K, 0, 7, IPPROTO_UDP as u32),
    /* 2 */ (LD_B_ABS, 0, 0, 30), // first octet of the destination
    /* 3 */ (JEQ_K, 0, 5, 127),
    /* 4 */ (LD_H_ABS, 0, 0, 20), // flags + fragment offset
    /* 5 */ (JSET_K, 3, 0, 0x3fff),
    /* 6 */ (LDX_B_MSH, 0, 0, 14), // X = IP header length
    /* 7 */ (LD_H_IND, 0, 0, 16), // UDP destination port
    /* 8 */ (JEQ_K, 1, 0, corerouter_hal::lsp::wire::PORT as u32),
    /* 9 */ (RET_K, 0, 0, 0),
    /* 10 */ (RET_K, 0, 0, KEEP),
];

/// IPv6: UDP (no extension header) to 3503, destination ::1 or
/// ::ffff:127.0.0.0/104 (RFC 9570 §4).
pub const IP6_FILTER: &[Insn] = &[
    /* 0 */ (LD_B_ABS, 0, 0, 20), // next header
    /* 1 */ (JEQ_K, 0, 13, IPPROTO_UDP as u32),
    /* 2 */ (LD_H_ABS, 0, 0, 56), // UDP destination port
    /* 3 */ (JEQ_K, 0, 11, corerouter_hal::lsp::wire::PORT as u32),
    /* 4 */ (LD_W_ABS, 0, 0, 38), // destination, word by word
    /* 5 */ (JEQ_K, 0, 9, 0),
    /* 6 */ (LD_W_ABS, 0, 0, 42),
    /* 7 */ (JEQ_K, 0, 7, 0),
    /* 8 */ (LD_W_ABS, 0, 0, 46),
    /* 9 */ (JEQ_K, 3, 0, 0), // ::x → is x 1?
    /* 10 */ (JEQ_K, 0, 4, 0xffff), // ::ffff:x → is x in 127/8?
    /* 11 */ (LD_B_ABS, 0, 0, 50),
    /* 12 */ (JEQ_K, 3, 2, 127),
    /* 13 */ (LD_W_ABS, 0, 0, 50),
    /* 14 */ (JEQ_K, 1, 0, 1),
    /* 15 */ (RET_K, 0, 0, 0),
    /* 16 */ (RET_K, 0, 0, KEEP),
];

// --- the route of a FEC (rtnetlink, built and read in place) ----------------

const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 0x1;
const RTM_F_FIB_MATCH: u32 = 0x2000;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_VIA: u16 = 18;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const LWTUNNEL_ENCAP_MPLS: u16 = 1;
const MPLS_IPTUNNEL_DST: u16 = 1;
const RTN_UNICAST: u8 = 1;
const RTPROT_STATIC: u8 = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
/// Ways out of one route kept.
const MAX_NEXTHOPS: usize = 16;

/// `ip route get <dst> fibmatch`.
pub fn route_request(dst: IpAddr, seq: u32) -> Vec<u8> {
    let (family, addr): (u8, Vec<u8>) = match dst {
        IpAddr::V4(a) => (2, a.octets().to_vec()),
        IpAddr::V6(a) => (10, a.octets().to_vec()),
    };
    let mut b = Vec::with_capacity(48);
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
    b.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    // rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type.
    b.extend_from_slice(&[family, (addr.len() * 8) as u8, 0, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&RTM_F_FIB_MATCH.to_ne_bytes());
    let rta_len = 4 + addr.len() as u16;
    b.extend_from_slice(&rta_len.to_ne_bytes());
    b.extend_from_slice(&RTA_DST.to_ne_bytes());
    b.extend_from_slice(&addr);
    let len = (b.len() as u32).to_ne_bytes();
    b.splice(0..4, len);
    b
}

/// One way out of a FEC's route.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawFtn {
    pub ifindex: Option<u32>,
    pub gateway: Option<IpAddr>,
    pub labels: Vec<u32>,
}

/// A FEC's route as the kernel answered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawFecRoute {
    pub unicast: bool,
    pub static_route: bool,
    pub prefsrc: Option<IpAddr>,
    pub nexthops: Vec<RawFtn>,
}

fn rtattrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16::from_ne_bytes([*b.first()?, *b.get(1)?]));
        let kind = u16::from_ne_bytes([*b.get(2)?, *b.get(3)?]) & NLA_TYPE_MASK;
        if len < 4 {
            return None;
        }
        let data = b.get(4..len)?;
        b = b.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        Some((kind, data))
    })
}

fn ip_of(data: &[u8]) -> Option<IpAddr> {
    match data.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
        _ => None,
    }
}

/// `RTA_VIA`: family (2 octets) then the address.
fn via_of(data: &[u8]) -> Option<IpAddr> {
    ip_of(data.get(2..)?)
}

fn encap_labels(data: &[u8]) -> Vec<u32> {
    rtattrs(data)
        .find(|(k, _)| *k == MPLS_IPTUNNEL_DST)
        .and_then(|(_, d)| crate::mpls::decode_stack(d))
        .unwrap_or_default()
}

fn nexthop_attrs(attrs: &[u8], nh: &mut RawFtn) {
    let mut mpls = false;
    let mut encap: &[u8] = &[];
    for (kind, data) in rtattrs(attrs) {
        match kind {
            RTA_OIF => nh.ifindex = data.try_into().ok().map(u32::from_ne_bytes),
            RTA_GATEWAY => nh.gateway = ip_of(data),
            RTA_VIA => nh.gateway = via_of(data),
            RTA_ENCAP_TYPE => {
                mpls = data
                    .get(..2)
                    .and_then(|d| d.try_into().ok())
                    .map(u16::from_ne_bytes)
                    == Some(LWTUNNEL_ENCAP_MPLS);
            }
            RTA_ENCAP => encap = data,
            _ => {}
        }
    }
    if mpls {
        nh.labels = encap_labels(encap);
    }
}

/// Read the answer to [`route_request`] (the message body, after the
/// netlink header). Hostile input: bounded, `None` when malformed.
pub fn parse_route(body: &[u8]) -> Option<RawFecRoute> {
    let hdr = body.get(..12)?;
    let mut r = RawFecRoute {
        unicast: *hdr.get(7)? == RTN_UNICAST,
        static_route: *hdr.get(5)? == RTPROT_STATIC,
        ..RawFecRoute::default()
    };
    let attrs = body.get(12..)?;
    let mut single = RawFtn::default();
    nexthop_attrs(attrs, &mut single);
    for (kind, data) in rtattrs(attrs) {
        match kind {
            RTA_PREFSRC => r.prefsrc = ip_of(data),
            RTA_MULTIPATH => {
                // struct rtnexthop { len u16, flags u8, hops u8, ifindex
                // i32 } followed by its attributes.
                let mut rest = data;
                while r.nexthops.len() < MAX_NEXTHOPS {
                    let Some(len) = rest
                        .get(..2)
                        .and_then(|b| b.try_into().ok())
                        .map(u16::from_ne_bytes)
                    else {
                        break;
                    };
                    let len = usize::from(len);
                    if len < 8 {
                        break;
                    }
                    let Some(one) = rest.get(..len) else { break };
                    let mut nh = RawFtn {
                        ifindex: one
                            .get(4..8)
                            .and_then(|b| b.try_into().ok())
                            .map(u32::from_ne_bytes),
                        ..RawFtn::default()
                    };
                    nexthop_attrs(one.get(8..).unwrap_or(&[]), &mut nh);
                    r.nexthops.push(nh);
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                }
            }
            _ => {}
        }
    }
    if r.nexthops.is_empty() && single.ifindex.is_some() {
        r.nexthops.push(single);
    }
    Some(r)
}

mod ebpf;
mod host;
pub use host::*;

#[cfg(test)]
mod tests;

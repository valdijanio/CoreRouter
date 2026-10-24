// SPDX-License-Identifier: GPL-2.0-or-later
//! Header parse: Ethernet (up to two VLAN tags, 802.1Q or 802.1ad), IPv4,
//! IPv6 (a few extension headers), and the first bytes of TCP, UDP and
//! ICMP. Only what the filter needs: the source, the protocol, the TCP
//! flags, and whether the headers are malformed.

use crate::packet::Packet;

pub const ETH_HLEN: usize = 14;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88A8;
/// QinQ: a service tag and a customer tag (ISP access networks).
pub const MAX_VLAN_TAGS: usize = 2;
/// IPv6 extension headers walked before giving up on the upper layer.
pub const MAX_IPV6_EXT: usize = 3;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_DEST_OPTS: u8 = 60;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;
pub const TCP_ECE: u8 = 0x40;
pub const TCP_CWR: u8 = 0x80;

/// An IP address as the maps key it: network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Addr {
    /// One key for both families: IPv4 as IPv4-mapped IPv6
    /// (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2), as the top-sources map keys it.
    pub fn mapped(&self) -> [u8; 16] {
        match *self {
            Addr::V6(a) => a,
            Addr::V4([a, b, c, d]) => [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d],
        }
    }

    /// Back from [`Addr::mapped`].
    pub fn from_mapped(k: [u8; 16]) -> Self {
        match k {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => Addr::V4([a, b, c, d]),
            other => Addr::V6(other),
        }
    }
}

/// What is wrong with a frame's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The frame ends inside the Ethernet, VLAN or IP header.
    Truncated,
    /// IP version does not match the EtherType.
    BadVersion,
    /// IPv4 header length (IHL) under 20 bytes.
    BadHeaderLength,
    /// IP total/payload length shorter than the header or longer than the
    /// frame.
    BadLength,
    /// First fragment too short to hold the transport header, or a TCP
    /// fragment at offset 8 bytes (RFC 1858 §3: both rewrite the header a
    /// filter already checked).
    TinyFragment,
    /// The transport header is cut short or its length field is impossible.
    BadTransport,
    /// A TCP flag combination no connection uses (the table of
    /// `nf_conntrack`'s `tcp_valid_flags`): SYN+FIN, SYN+RST, no flags…
    BadTcpFlags,
}

/// Which fragment of a datagram this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fragment {
    /// A whole datagram.
    No,
    /// Offset 0, more to come: the transport header is here.
    First,
    /// Offset above 0: no transport header.
    Later,
}

/// An IP packet's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpInfo {
    /// Offset of the IP header in the frame (14 when untagged).
    pub ip_off: usize,
    pub src: Addr,
    pub dst: Addr,
    /// Upper-layer protocol (after IPv6 extension headers, when walked).
    pub proto: u8,
    pub fragment: Fragment,
    /// Offset of the transport header in the frame.
    pub l4_off: usize,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP flags byte (0 for other protocols).
    pub tcp_flags: u8,
    /// Set when the IP header was fine but something after it is not: the
    /// source is known, so the block lists still apply when malformed
    /// packets are let through.
    pub malformed: Option<Malformed>,
}

/// The outcome of [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// ARP, LLDP, MPLS, PPPoE…: not the filter's business.
    NotIp,
    Ip(IpInfo),
    /// Broken before the source address could be trusted.
    Bad(Malformed),
}

/// Parse `p`'s headers. Never reads past the frame.
pub fn parse<P: Packet + ?Sized>(p: &P) -> Parsed {
    let Some(mut proto) = p.be16(12) else {
        return Parsed::Bad(Malformed::Truncated);
    };
    let mut off = ETH_HLEN;
    for _ in 0..MAX_VLAN_TAGS {
        if proto != ETH_P_8021Q && proto != ETH_P_8021AD {
            break;
        }
        // Tag: TCI (2 bytes), then the inner EtherType.
        let Some(inner) = p.be16(off + 2) else {
            return Parsed::Bad(Malformed::Truncated);
        };
        proto = inner;
        off += 4;
    }
    match proto {
        ETH_P_IP => ipv4(p, off),
        ETH_P_IPV6 => ipv6(p, off),
        _ => Parsed::NotIp,
    }
}

fn ipv4<P: Packet + ?Sized>(p: &P, off: usize) -> Parsed {
    let Some([ver_ihl, _tos, len_hi, len_lo]) = p.bytes::<4>(off) else {
        return Parsed::Bad(Malformed::Truncated);
    };
    if ver_ihl >> 4 != 4 {
        return Parsed::Bad(Malformed::BadVersion);
    }
    let ihl = usize::from(ver_ihl & 0x0f) * 4;
    if ihl < 20 {
        return Parsed::Bad(Malformed::BadHeaderLength);
    }
    let Some(
        [
            _,
            _,
            _,
            _,
            _,
            _,
            f_hi,
            f_lo,
            _ttl,
            proto,
            _,
            _,
            s0,
            s1,
            s2,
            s3,
            d0,
            d1,
            d2,
            d3,
        ],
    ) = p.bytes::<20>(off)
    else {
        return Parsed::Bad(Malformed::Truncated);
    };
    // Options, if any, must be in the frame too.
    if p.u8_at(off + ihl - 1).is_none() {
        return Parsed::Bad(Malformed::Truncated);
    }
    let total = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    // Ethernet pads short frames: the frame may be longer than the
    // datagram, never shorter.
    if total < ihl || off + total > p.len() {
        return Parsed::Bad(Malformed::BadLength);
    }
    let frag = u16::from_be_bytes([f_hi, f_lo]);
    let more = frag & 0x2000 != 0;
    let frag_off = frag & 0x1fff;
    let fragment = match (frag_off, more) {
        (0, false) => Fragment::No,
        (0, true) => Fragment::First,
        _ => Fragment::Later,
    };
    let info = IpInfo {
        ip_off: off,
        src: Addr::V4([s0, s1, s2, s3]),
        dst: Addr::V4([d0, d1, d2, d3]),
        proto,
        fragment,
        l4_off: off + ihl,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        malformed: None,
    };
    // RFC 1858 §3.2: a TCP fragment at offset 1 (8 bytes) overwrites the
    // flags of the first one.
    if proto == IPPROTO_TCP && frag_off == 1 {
        return Parsed::Ip(IpInfo {
            malformed: Some(Malformed::TinyFragment),
            ..info
        });
    }
    Parsed::Ip(transport(p, info, off + total))
}

fn ipv6<P: Packet + ?Sized>(p: &P, off: usize) -> Parsed {
    let Some(h) = p.bytes::<40>(off) else {
        return Parsed::Bad(Malformed::Truncated);
    };
    let [v, _, _, _, l_hi, l_lo, next, _hop, rest @ ..] = h;
    if v >> 4 != 6 {
        return Parsed::Bad(Malformed::BadVersion);
    }
    let payload = usize::from(u16::from_be_bytes([l_hi, l_lo]));
    let end = off + 40 + payload;
    if end > p.len() {
        return Parsed::Bad(Malformed::BadLength);
    }
    let (src, dst) = split16(rest);
    let mut info = IpInfo {
        ip_off: off,
        src: Addr::V6(src),
        dst: Addr::V6(dst),
        proto: next,
        fragment: Fragment::No,
        l4_off: off + 40,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        malformed: None,
    };
    for _ in 0..MAX_IPV6_EXT {
        match info.proto {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DEST_OPTS => {
                let Some([nh, len]) = p.bytes::<2>(info.l4_off) else {
                    return Parsed::Ip(IpInfo {
                        malformed: Some(Malformed::BadTransport),
                        ..info
                    });
                };
                info.proto = nh;
                info.l4_off += (usize::from(len) + 1) * 8;
            }
            IPV6_FRAGMENT => {
                let Some([nh, _, o_hi, o_lo]) = p.bytes::<4>(info.l4_off) else {
                    return Parsed::Ip(IpInfo {
                        malformed: Some(Malformed::BadTransport),
                        ..info
                    });
                };
                let field = u16::from_be_bytes([o_hi, o_lo]);
                info.fragment = match (field >> 3, field & 1 != 0) {
                    (0, false) => Fragment::No,
                    (0, true) => Fragment::First,
                    _ => Fragment::Later,
                };
                info.proto = nh;
                info.l4_off += 8;
            }
            _ => break,
        }
    }
    if info.l4_off > end {
        return Parsed::Ip(IpInfo {
            malformed: Some(Malformed::BadTransport),
            ..info
        });
    }
    Parsed::Ip(transport(p, info, end))
}

/// Source and destination out of the last 32 bytes of the IPv6 header.
fn split16(rest: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let [
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
        s8,
        s9,
        s10,
        s11,
        s12,
        s13,
        s14,
        s15,
        d0,
        d1,
        d2,
        d3,
        d4,
        d5,
        d6,
        d7,
        d8,
        d9,
        d10,
        d11,
        d12,
        d13,
        d14,
        d15,
    ] = rest;
    (
        [
            s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15,
        ],
        [
            d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15,
        ],
    )
}

/// The transport header of `info` (datagram ends at `end`).
fn transport<P: Packet + ?Sized>(p: &P, mut info: IpInfo, end: usize) -> IpInfo {
    if info.fragment == Fragment::Later {
        return info;
    }
    let short = if info.fragment == Fragment::First {
        Malformed::TinyFragment
    } else {
        Malformed::BadTransport
    };
    let l4 = info.l4_off;
    match info.proto {
        IPPROTO_TCP => {
            let Some([sp0, sp1, dp0, dp1, _, _, _, _, _, _, _, _, doff, flags, ..]) =
                p.bytes::<20>(l4).filter(|_| l4 + 20 <= end)
            else {
                info.malformed = Some(short);
                return info;
            };
            info.src_port = u16::from_be_bytes([sp0, sp1]);
            info.dst_port = u16::from_be_bytes([dp0, dp1]);
            info.tcp_flags = flags;
            let hlen = usize::from(doff >> 4) * 4;
            if hlen < 20 || (info.fragment == Fragment::No && l4 + hlen > end) {
                info.malformed = Some(Malformed::BadTransport);
            } else if !tcp_flags_valid(flags) {
                info.malformed = Some(Malformed::BadTcpFlags);
            }
        }
        IPPROTO_UDP => {
            let Some([sp0, sp1, dp0, dp1, l0, l1, _, _]) =
                p.bytes::<8>(l4).filter(|_| l4 + 8 <= end)
            else {
                info.malformed = Some(short);
                return info;
            };
            info.src_port = u16::from_be_bytes([sp0, sp1]);
            info.dst_port = u16::from_be_bytes([dp0, dp1]);
            let len = usize::from(u16::from_be_bytes([l0, l1]));
            // A first fragment carries only part of the datagram the UDP
            // length counts.
            if len < 8 || (info.fragment == Fragment::No && l4 + len > end) {
                info.malformed = Some(Malformed::BadTransport);
            }
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 if p.bytes::<4>(l4).filter(|_| l4 + 4 <= end).is_none() => {
            info.malformed = Some(short);
        }
        _ => {}
    }
    info
}

/// Whether a connection could carry these TCP flags: the combinations
/// `nf_conntrack` accepts (`tcp_valid_flags` in
/// `net/netfilter/nf_conntrack_proto_tcp.c`), ignoring PSH, ECE and CWR.
/// Everything else (SYN+FIN, SYN+RST, FIN without ACK, no flags at all,
/// "Xmas") is a scan or an attack.
pub fn tcp_flags_valid(flags: u8) -> bool {
    const SA: u8 = TCP_SYN | TCP_ACK;
    const SU: u8 = TCP_SYN | TCP_URG;
    const RA: u8 = TCP_RST | TCP_ACK;
    const FA: u8 = TCP_FIN | TCP_ACK;
    const FAU: u8 = TCP_FIN | TCP_ACK | TCP_URG;
    const AU: u8 = TCP_ACK | TCP_URG;
    matches!(
        flags & !(TCP_PSH | TCP_ECE | TCP_CWR),
        TCP_SYN | SU | SA | TCP_RST | RA | FA | FAU | TCP_ACK | AU
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tcp_flags_are_the_conntrack_table() {
        for ok in [
            TCP_SYN,
            TCP_SYN | TCP_ACK,
            TCP_ACK,
            TCP_ACK | TCP_PSH,
            TCP_FIN | TCP_ACK,
            TCP_RST,
            TCP_RST | TCP_ACK,
            TCP_SYN | TCP_ECE | TCP_CWR,
        ] {
            assert!(tcp_flags_valid(ok), "{ok:#x}");
        }
        for bad in [
            0,
            TCP_SYN | TCP_FIN,
            TCP_SYN | TCP_RST,
            TCP_FIN,
            TCP_FIN | TCP_PSH | TCP_URG,
            TCP_FIN | TCP_RST | TCP_ACK,
            TCP_PSH,
        ] {
            assert!(!tcp_flags_valid(bad), "{bad:#x}");
        }
    }

    #[test]
    fn mapped_round_trips() {
        for a in [
            Addr::V4([192, 0, 2, 1]),
            Addr::V6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            assert_eq!(Addr::from_mapped(a.mapped()), a);
        }
    }
}

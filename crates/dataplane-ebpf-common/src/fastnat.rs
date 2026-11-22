// SPDX-License-Identifier: GPL-2.0-or-later
//! The CGNAT fast path (G2.5b): flows the kernel already NATed, translated
//! and forwarded in XDP. The kernel decides everything first — the first
//! packets of a flow go through nftables (G2.3), which picks the port in
//! the subscriber's deterministic range — and the daemon copies each
//! established NAT connection from conntrack into `NAT_FLOWS`, one entry
//! per direction. A packet whose 5-tuple is there is rewritten (address,
//! port, checksums, TTL) and redirected out of the interface the FIB names;
//! anything else, and anything this cannot finish, goes to the kernel
//! untouched.
//!
//! Stays in the kernel: IPv6, ICMP, fragments, VLAN-tagged frames, TCP
//! SYN/FIN/RST (conntrack must see a connection open and close), TTL ≤ 1
//! (the kernel sends the ICMP time exceeded), and whatever the FIB lookup
//! does not resolve (no neighbor yet, MTU, local delivery).

use crate::nat::{self, Endpoint, PacketMut};
use crate::parse::{
    Addr, ETH_HLEN, Fragment, IPPROTO_TCP, IPPROTO_UDP, IpInfo, TCP_FIN, TCP_RST, TCP_SYN,
};

/// Where the transport header starts in a frame the fast path takes.
pub const L4_OFF: usize = ETH_HLEN + 20;

/// Key of `NAT_FLOWS`: a direction's 5-tuple as it arrives,
/// `[proto, 0, 0, 0, src (4), dst (4), sport (2), dport (2)]`, network
/// order.
pub type FlowKey = [u8; 16];

/// Value of `NAT_FLOWS`: `[new source, new destination, last packet (ns,
/// CLOCK_MONOTONIC), packets]`; an endpoint word is the address (big
/// endian) in the low 32 bits and the port in the next 16.
pub type FlowValue = [u64; 4];

/// The key of a 5-tuple.
pub fn key(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> FlowKey {
    let [s0, s1, s2, s3] = src;
    let [d0, d1, d2, d3] = dst;
    let [sp0, sp1] = sport.to_be_bytes();
    let [dp0, dp1] = dport.to_be_bytes();
    [
        proto, 0, 0, 0, s0, s1, s2, s3, d0, d1, d2, d3, sp0, sp1, dp0, dp1,
    ]
}

/// The key of a parsed packet, when the fast path could take it at all
/// (IPv4 TCP/UDP, whole datagram).
pub fn key_of(info: &IpInfo) -> Option<FlowKey> {
    let (Addr::V4(src), Addr::V4(dst)) = (info.src, info.dst) else {
        return None;
    };
    if info.fragment != Fragment::No || !matches!(info.proto, IPPROTO_TCP | IPPROTO_UDP) {
        return None;
    }
    Some(key(info.proto, src, dst, info.src_port, info.dst_port))
}

pub fn encode(e: Endpoint) -> u64 {
    u64::from(u32::from_be_bytes(e.addr)) | (u64::from(e.port) << 32)
}

pub fn decode(word: u64) -> Endpoint {
    Endpoint {
        addr: ((word & 0xffff_ffff) as u32).to_be_bytes(),
        port: ((word >> 32) & 0xffff) as u16,
    }
}

/// A fresh `NAT_FLOWS` value.
pub fn value(src: Endpoint, dst: Endpoint) -> FlowValue {
    [encode(src), encode(dst), 0, 0]
}

/// Why a packet of a known flow still goes to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel {
    /// A VLAN tag: the egress may need another one.
    Tagged,
    /// IP options: rare, and they would make every offset variable (the
    /// eBPF verifier wants constant ones here).
    Options,
    /// SYN, FIN or RST: conntrack follows the connection's life.
    Control,
    /// TTL 1 or 0: the kernel answers with time exceeded.
    Ttl,
    /// The frame ends before a field to rewrite.
    Short,
}

impl Kernel {
    /// Its slot in `NAT_MISS` (after the FIB lookup's return codes).
    pub fn slot(self) -> u32 {
        MISS_FIB
            + 9
            + match self {
                Kernel::Tagged => 0,
                Kernel::Options => 1,
                Kernel::Control => 2,
                Kernel::Ttl => 3,
                Kernel::Short => 4,
            }
    }
}

/// `NAT_MISS` slots: why a packet of a known flow went to the kernel.
/// `MISS_FIB + rc` for a FIB lookup that returned `rc` (1..=8: blackhole,
/// unreachable, prohibit, not forwarded, forwarding disabled, unsupported
/// lwt, no neighbor, fragmentation needed), then [`Kernel::slot`].
pub const MISS_FIB: u32 = 0;
pub const MISS_SLOTS: u32 = MISS_FIB + 9 + 5;
/// Names of the slots, in order (`""` for the unused FIB code 0).
pub const MISS_NAMES: [&str; MISS_SLOTS as usize] = [
    "",
    "fib-blackhole",
    "fib-unreachable",
    "fib-prohibit",
    "fib-not-forwarded",
    "fib-forwarding-disabled",
    "fib-unsupported-lwt",
    "fib-no-neighbor",
    "fib-frag-needed",
    "tagged",
    "ip-options",
    "tcp-control",
    "ttl",
    "short",
];

/// Whether the fast path may take this packet of a known flow (before the
/// FIB lookup).
#[inline(always)]
pub fn admit<P: crate::packet::Packet + ?Sized>(p: &P, info: &IpInfo) -> Result<(), Kernel> {
    if info.ip_off != ETH_HLEN {
        return Err(Kernel::Tagged);
    }
    if info.l4_off != L4_OFF {
        return Err(Kernel::Options);
    }
    if info.proto == IPPROTO_TCP && info.tcp_flags & (TCP_SYN | TCP_FIN | TCP_RST) != 0 {
        return Err(Kernel::Control);
    }
    match p.u8_at(ETH_HLEN + 8) {
        Some(ttl) if ttl > 1 => Ok(()),
        Some(_) => Err(Kernel::Ttl),
        None => Err(Kernel::Short),
    }
}

/// Rewrite the packet for flow value `v`: new endpoints, checksums, TTL
/// minus one (its checksum too). Call after [`admit`] and a successful
/// FIB lookup; the MACs are the caller's (they come from the lookup).
#[inline(always)]
pub fn translate<P: PacketMut + ?Sized>(
    p: &mut P,
    info: &IpInfo,
    v: &FlowValue,
) -> Result<(), Kernel> {
    let [src, dst, ..] = *v;
    // Constant offsets (an untagged frame without IP options, as `admit`
    // checked): the verifier sees every access's bound.
    let info = IpInfo {
        ip_off: ETH_HLEN,
        l4_off: L4_OFF,
        ..*info
    };
    nat::rewrite(p, &info, Some(decode(src)), Some(decode(dst))).map_err(|_| Kernel::Short)?;
    let ip_off = ETH_HLEN;
    let ttl_off = ip_off + 8;
    let word = p.be16(ttl_off).ok_or(Kernel::Short)?;
    let new = word.checked_sub(0x0100).ok_or(Kernel::Ttl)?;
    let csum = p.be16(ip_off + 10).ok_or(Kernel::Short)?;
    p.store(ttl_off, new.to_be_bytes()).ok_or(Kernel::Short)?;
    p.store(ip_off + 10, nat::update16(csum, word, new).to_be_bytes())
        .ok_or(Kernel::Short)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_round_trip() {
        for e in [
            Endpoint {
                addr: [100, 64, 0, 1],
                port: 5000,
            },
            Endpoint {
                addr: [255, 255, 255, 255],
                port: 65535,
            },
            Endpoint {
                addr: [0, 0, 0, 0],
                port: 0,
            },
        ] {
            assert_eq!(decode(encode(e)), e);
        }
        assert_eq!(
            key(17, [1, 2, 3, 4], [5, 6, 7, 8], 0x1234, 0x5678),
            [17, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x12, 0x34, 0x56, 0x78]
        );
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
//! NAT rewrite for the CGNAT fast path (G2.5b): new IPv4 source and/or
//! destination address and port, with the IP header checksum and the
//! TCP/UDP checksum updated incrementally (RFC 1624), never recomputed
//! over the payload. The XDP program runs it over the packet; the tests
//! check it against a full recompute.

use crate::packet::Packet;
use crate::parse::{Fragment, IPPROTO_TCP, IPPROTO_UDP, IpInfo};

/// A frame that can be written in place.
pub trait PacketMut: Packet {
    /// Write `bytes` at `off`; `None` (nothing written) if they do not
    /// all fit in the frame.
    fn store<const N: usize>(&mut self, off: usize, bytes: [u8; N]) -> Option<()>;
}

impl PacketMut for [u8] {
    fn store<const N: usize>(&mut self, off: usize, bytes: [u8; N]) -> Option<()> {
        let end = off.checked_add(N)?;
        self.get_mut(off..end)?.copy_from_slice(&bytes);
        Some(())
    }
}

/// Fold a one's-complement sum to 16 bits (end-around carry, RFC 1071).
pub fn fold(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum as u16
}

/// RFC 1624 Eqn 3: the checksum `hc` of data where the 16-bit word `old`
/// became `new`: HC' = ~(~HC + ~m + m'). A word that did not change
/// leaves the checksum alone (errata 4782: with HC = 0 the equation would
/// give 0xFFFF).
pub fn update16(hc: u16, old: u16, new: u16) -> u16 {
    if old == new {
        return hc;
    }
    !fold(u32::from(!hc) + u32::from(!old) + u32::from(new))
}

/// [`update16`] for a 32-bit field (an IPv4 address): its two words.
pub fn update32(hc: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let [o0, o1, o2, o3] = old;
    let [n0, n1, n2, n3] = new;
    let hc = update16(
        hc,
        u16::from_be_bytes([o0, o1]),
        u16::from_be_bytes([n0, n1]),
    );
    update16(
        hc,
        u16::from_be_bytes([o2, o3]),
        u16::from_be_bytes([n2, n3]),
    )
}

/// One side of a translation: the address and port it becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: [u8; 4],
    pub port: u16,
}

/// Why a packet stays on the kernel's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotHere {
    /// Not IPv4 TCP/UDP.
    Protocol,
    /// A fragment (the kernel reassembles).
    Fragment,
    /// The frame ends before a field to rewrite.
    Short,
}

/// Rewrite the IPv4 TCP/UDP packet `info` describes: source to `src`,
/// destination to `dst` (each optional), IP and transport checksums
/// updated. Nothing is written unless everything fits (all reads first).
/// A UDP checksum of 0 (none, RFC 768) stays 0; a computed 0 is sent as
/// 0xFFFF.
pub fn rewrite<P: PacketMut + ?Sized>(
    p: &mut P,
    info: &IpInfo,
    src: Option<Endpoint>,
    dst: Option<Endpoint>,
) -> Result<(), NotHere> {
    if info.fragment != Fragment::No {
        return Err(NotHere::Fragment);
    }
    let (ip_off, l4_off) = info.v4_offsets();
    let csum_off = match info.proto {
        IPPROTO_TCP => l4_off + 16,
        IPPROTO_UDP => l4_off + 6,
        _ => return Err(NotHere::Protocol),
    };
    let (crate::parse::Addr::V4(old_src), crate::parse::Addr::V4(old_dst)) = (info.src, info.dst)
    else {
        return Err(NotHere::Protocol);
    };
    let ip_csum = p.be16(ip_off + 10).ok_or(NotHere::Short)?;
    let l4_csum = p.be16(csum_off).ok_or(NotHere::Short)?;
    // Ports are read from the frame, not trusted from `info`.
    let old_sport = p.be16(l4_off).ok_or(NotHere::Short)?;
    let old_dport = p.be16(l4_off + 2).ok_or(NotHere::Short)?;
    let src = src.unwrap_or(Endpoint {
        addr: old_src,
        port: old_sport,
    });
    let dst = dst.unwrap_or(Endpoint {
        addr: old_dst,
        port: old_dport,
    });
    let mut ip = ip_csum;
    ip = update32(ip, old_src, src.addr);
    ip = update32(ip, old_dst, dst.addr);
    // The pseudo-header carries the addresses: the transport checksum
    // follows them and the ports.
    let udp_none = info.proto == IPPROTO_UDP && l4_csum == 0;
    let mut l4 = l4_csum;
    if !udp_none {
        l4 = update32(l4, old_src, src.addr);
        l4 = update32(l4, old_dst, dst.addr);
        l4 = update16(l4, old_sport, src.port);
        l4 = update16(l4, old_dport, dst.port);
        if info.proto == IPPROTO_UDP && l4 == 0 {
            l4 = 0xffff;
        }
    }
    // Every write fits: offsets were all read above (checksum field last
    // byte is the farthest).
    let w = |p: &mut P, off: usize, b: [u8; 2]| p.store(off, b).ok_or(NotHere::Short);
    p.store(ip_off + 12, src.addr).ok_or(NotHere::Short)?;
    p.store(ip_off + 16, dst.addr).ok_or(NotHere::Short)?;
    w(p, ip_off + 10, ip.to_be_bytes())?;
    w(p, l4_off, src.port.to_be_bytes())?;
    w(p, l4_off + 2, dst.port.to_be_bytes())?;
    w(p, csum_off, l4.to_be_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1624 §4: a header checksum 0xDD2F with a word 0x5555 becoming
    /// 0x3285 gives 0x0000.
    #[test]
    fn rfc_1624_example() {
        assert_eq!(update16(0xdd2f, 0x5555, 0x3285), 0x0000);
        // Errata 4782: an unchanged word leaves even 0 alone.
        assert_eq!(update16(0x0000, 0x1234, 0x1234), 0x0000);
    }
}

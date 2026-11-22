// SPDX-License-Identifier: GPL-2.0-or-later
//! The LSP responder's tap in tc (G3.9db): which frames of an MPLS
//! interface the `lsp_tap` ingress program hands to the `lsp-ping` service
//! — the decision the classic BPF filters of the `AF_PACKET` taps made in
//! `hal-linux` (G3.5b, G3.9d, G3.9da), now without a packet socket in the
//! receive path (each one cost every frame of the host a `packet_rcv`):
//!
//! - **MPLS:** the top label's TTL is 0 or 1 (it expires here: the kernel
//!   drops it without an ICMP), or the label is explicit null (IPv4 0,
//!   IPv6 2: it ends here); or, with [`Settings::big`], the frame is longer
//!   than the smallest way out of the label table and is not a GSO packet
//!   (the kernel checks the segments then, `mpls_pkt_too_big`).
//! - **IPv4:** UDP to port 3503 and 127/8, not a fragment (an echo request
//!   popped by the penultimate hop; the kernel drops it as martian).
//! - **IPv6:** UDP (no extension header) to 3503, destination `::1` or
//!   `::ffff:127.0.0.0/104` (RFC 9570 §4).
//!
//! A kept frame is copied to the ring buffer and passes on too: the kernel
//! goes on as before (drops it, or forwards it).

use crate::packet::Packet;

/// What to copy of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// Nothing: not a candidate.
    No,
    /// The whole frame, up to [`FRAME`] octets.
    Whole,
    /// Its start, [`SNAP`] octets: a frame that may be too big (the error
    /// quotes no more).
    Head,
}

/// Octets kept of a frame that may be too big: Ethernet, the deepest stack
/// read (16 labels), an IPv6 header and the longest ICMPv6 quote (1232,
/// RFC 4443 §3.2). As `hal-linux`'s classic filter.
pub const SNAP: usize = 14 + 4 * 16 + 40 + 1232;
/// Longest frame copied (a jumbo frame; echo requests may be padded up to
/// the LSP MTU, RFC 8029 §3.5).
pub const FRAME: usize = 9216;
/// Copies up to this long take a small ring buffer slot.
pub const SMALL: usize = 256;
/// Octets before the frame in a ring buffer record: ifindex, `skb->len`,
/// octets copied (little-endian `u32`s), and a reserved word.
pub const HEADER: usize = 16;

/// The tap's settings: one word in `LSP_TAP_SET`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Settings {
    /// Keep MPLS frames longer than this (Ethernet header included); 0:
    /// do not look at the length.
    pub big: u32,
}

impl Settings {
    pub fn to_word(self) -> u64 {
        u64::from(self.big)
    }

    pub fn from_word(w: u64) -> Self {
        Self {
            big: (w & 0xffff_ffff) as u32,
        }
    }
}

/// Counters, slots of the per-CPU `LSP_TAP_STATS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Stat {
    /// Copied to the ring buffer.
    Kept = 0,
    /// A candidate the ring buffer had no room for (the service is
    /// behind): the same loss as a full socket buffer.
    Full = 1,
}

impl Stat {
    pub const SLOTS: u32 = 2;
}

/// A record the program wrote: `(ifindex, skb->len, the frame copied)`.
/// `None`: shorter than the header says.
pub fn record(b: &[u8]) -> Option<(u32, u32, &[u8])> {
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
    };
    let copied = usize::try_from(word(8)?).ok()?;
    Some((
        word(0)?,
        word(4)?,
        b.get(HEADER..HEADER.checked_add(copied)?)?,
    ))
}

/// How many octets of a `len`-octet frame `k` copies.
pub fn copied(k: Keep, len: u32) -> usize {
    let len = len as usize;
    match k {
        Keep::No => 0,
        Keep::Whole => len.min(FRAME),
        Keep::Head => len.min(SNAP),
    }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_MPLS_UC: u16 = 0x8847;
const UDP: u8 = 17;
const PORT: u16 = 3503;

#[inline(always)]
fn mpls<P: Packet + ?Sized>(p: &P, len: u32, gso: bool, s: Settings) -> Option<Keep> {
    let w = u32::from_be_bytes(p.bytes::<4>(14)?);
    if w & 0xff <= 1 {
        return Some(Keep::Whole);
    }
    // The label with bit 1 cleared: 0 and 2 become 0.
    if w & 0xffff_d000 == 0 {
        return Some(Keep::Whole);
    }
    Some(if s.big != 0 && len > s.big && !gso {
        Keep::Head
    } else {
        Keep::No
    })
}

#[inline(always)]
fn ipv4<P: Packet + ?Sized>(p: &P) -> Option<Keep> {
    if p.u8_at(23)? != UDP || p.u8_at(30)? != 127 || p.be16(20)? & 0x3fff != 0 {
        return Some(Keep::No);
    }
    let ihl = usize::from(p.u8_at(14)? & 0x0f) * 4;
    Some(if p.be16(14 + ihl + 2)? == PORT {
        Keep::Whole
    } else {
        Keep::No
    })
}

#[inline(always)]
fn ipv6<P: Packet + ?Sized>(p: &P) -> Option<Keep> {
    if p.u8_at(20)? != UDP || p.be16(56)? != PORT {
        return Some(Keep::No);
    }
    let w = |off| p.bytes::<4>(off).map(u32::from_be_bytes);
    if w(38)? != 0 || w(42)? != 0 {
        return Some(Keep::No);
    }
    let ok = match w(46)? {
        0 => w(50)? == 1,
        0xffff => p.u8_at(50)? == 127,
        _ => false,
    };
    Some(if ok { Keep::Whole } else { Keep::No })
}

/// What to copy of the Ethernet frame `p`, `len` octets long in all
/// (`skb->len`; `p` may hold only its linear start), `gso` when the kernel
/// will segment it. A frame too short to say is not kept.
#[inline(always)]
pub fn keep<P: Packet + ?Sized>(p: &P, len: u32, gso: bool, s: Settings) -> Keep {
    let found = match p.be16(12) {
        Some(ETH_P_MPLS_UC) => mpls(p, len, gso, s),
        Some(ETH_P_IP) => ipv4(p),
        Some(ETH_P_IPV6) => ipv6(p),
        _ => None,
    };
    found.unwrap_or(Keep::No)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mpls_frame(label: u32, ttl: u8) -> [u8; 64] {
        let mut f = [0u8; 64];
        f[12..14].copy_from_slice(&ETH_P_MPLS_UC.to_be_bytes());
        f[14..18].copy_from_slice(&((label << 12) | 0x100 | u32::from(ttl)).to_be_bytes());
        f[18] = 0x45;
        f
    }

    #[test]
    fn mpls_frames_are_kept_when_expired_explicit_null_or_long() {
        let s = Settings { big: 1518 };
        for (label, ttl) in [(100, 1), (100, 0), (0, 64), (2, 64)] {
            assert_eq!(keep(&mpls_frame(label, ttl)[..], 64, false, s), Keep::Whole);
        }
        assert_eq!(keep(&mpls_frame(3, 64)[..], 64, false, s), Keep::No);
        let alive = mpls_frame(100, 64);
        assert_eq!(keep(&alive[..], 64, false, s), Keep::No);
        assert_eq!(keep(&alive[..], 1518, false, s), Keep::No);
        assert_eq!(keep(&alive[..], 1519, false, s), Keep::Head);
        // GSO: the kernel checks the segments, not the whole.
        assert_eq!(keep(&alive[..], 9000, true, s), Keep::No);
        assert_eq!(keep(&alive[..], 9000, false, Settings::default()), Keep::No);
    }

    #[test]
    fn short_and_other_frames_are_not_kept() {
        assert_eq!(
            keep(&[0u8; 10][..], 10, false, Settings::default()),
            Keep::No
        );
        let mut arp = [0u8; 64];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(keep(&arp[..], 64, false, Settings::default()), Keep::No);
    }

    #[test]
    fn records_and_copies() {
        let mut r = [0u8; HEADER + 4];
        r[0..4].copy_from_slice(&7u32.to_le_bytes());
        r[4..8].copy_from_slice(&1500u32.to_le_bytes());
        r[8..12].copy_from_slice(&4u32.to_le_bytes());
        r[HEADER..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(record(&r), Some((7, 1500, &[1u8, 2, 3, 4][..])));
        assert_eq!(record(&r[..HEADER + 3]), None);
        assert_eq!(copied(Keep::Head, 9000), SNAP);
        assert_eq!(copied(Keep::Whole, 64), 64);
        assert_eq!(copied(Keep::Whole, 100_000), FRAME);
        let s = Settings { big: 1504 };
        assert_eq!(Settings::from_word(s.to_word()), s);
    }
}

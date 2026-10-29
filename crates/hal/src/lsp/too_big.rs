//! ICMP "fragmentation needed" / ICMPv6 "packet too big" for labeled
//! packets larger than the way out of their label (G3.9da), without I/O.
//!
//! The Linux MPLS forwarder drops a labeled packet that does not fit the
//! outgoing link and sends nothing (`mpls_forward`: `if
//! (mpls_pkt_too_big(skb, mtu - new_header_size)) goto tx_err`, which only
//! counts `tx_errors`), so Path MTU Discovery through the LSP black-holes:
//! the TCP handshake works, the first full-size segment never arrives. The
//! IP layer is right where the packet is first labeled (the MPLS
//! lightweight tunnel declares its headroom, `ip_forward` sends the error),
//! so only a transit or penultimate LSR needs this. The responder's MPLS
//! tap also copies frames longer than the smallest way out of the label
//! table (`hal-linux`), and this module turns one into the error:
//!
//! - **When it is too big** (RFC 3032 §3.3, as the kernel decides): the
//!   packet under the top label, plus the labels the label table pushes,
//!   does not fit the MTU of the outgoing link. With ECMP the kernel picks
//!   a way by a hash this module does not see; the smallest way counts.
//! - **IPv4** (RFC 3032 §3.4): with DF set, Destination Unreachable code 4
//!   with the Next-Hop MTU (RFC 1191 §4) = link MTU minus the label stack
//!   that would leave, quoting 128 octets and the RFC 4950 label stack
//!   object as it arrived (RFC 4884 §4.1: type 3 carries extensions).
//!   Without DF the LSR "MAY silently discard" it, which the kernel
//!   already did; fragmenting here is left out (see `docs/mpls.md`).
//! - **IPv6** (RFC 3032 §3.5): Packet Too Big with that MTU, quoting as
//!   much of the packet as fits the minimum IPv6 MTU (RFC 4443 §3.2; no
//!   RFC 4884 extension exists for type 2). A packet of at most 1280
//!   octets with a fragment header is to be fragmented instead (§3.5 step
//!   4): dropped and counted.
//! - **Not sent**, **how it goes back**: as for time exceeded
//!   ([`super::expired`]); Packet Too Big may be about a multicast
//!   destination (RFC 4443 §2.4(e.2)).

use std::net::IpAddr;

use corerouter_model::IfName;

use super::LsrView;
use super::expired::{self, Icmp, QUOTE};
use crate::probe::MplsLabel;

/// Octets of the original packet an ICMPv6 Packet Too Big quotes at most:
/// the error must fit the minimum IPv6 MTU (1280 − 40 − 8, RFC 4443 §3.2).
pub const QUOTE6: usize = 1232;
/// Frame payload the tap copies of a frame that may be too big: the
/// deepest stack read and the longest quote.
pub const SNAP: usize = 4 * expired::MAX_STACK + 40 + QUOTE6;

const ICMP_UNREACHABLE: u8 = 3;
const FRAG_NEEDED: u8 = 4;
const ICMP6_TOO_BIG: u8 = 2;
const IPV6_MIN_MTU: usize = 1280;

/// A labeled packet that may not fit its way out, as the data plane copied
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooBig {
    /// Where it came in.
    pub interface: IfName,
    /// The labels it came with, top first (at least one).
    pub stack: Vec<MplsLabel>,
    /// The start of the IP packet under the stack, at most [`QUOTE6`]
    /// octets (the tap copies no more).
    pub packet: Vec<u8>,
    /// The IP packet's length, from its header (the copy is cut).
    pub len: usize,
}

/// The labeled packet at the start of `mpls` (an MPLS frame's payload,
/// after the Ethernet header) whose top TTL is alive. `None`: expired (a
/// time exceeded instead), a reserved top label (explicit null ends here),
/// malformed, or not IP under the stack.
pub fn parse(interface: &IfName, mpls: &[u8]) -> Option<TooBig> {
    let (stack, at) = expired::read_stack(mpls)?;
    let top = stack.first()?;
    if top.ttl <= 1 || top.label < 16 {
        return None;
    }
    let ip = mpls.get(at..)?;
    let len = expired::ip_len(ip)?;
    let keep = ip.len().min(len).min(QUOTE6);
    Some(TooBig {
        interface: interface.clone(),
        stack,
        packet: ip.get(..keep)?.to_vec(),
        len,
    })
}

/// The largest IP packet the top label's way out takes now: its link MTU
/// minus the labels that would leave (pushed ones and the rest of the
/// stack; RFC 3032 §3.4 "N"). The smallest over ECMP ways.
pub fn limit(stack: &[MplsLabel], view: &dyn LsrView) -> Result<usize, &'static str> {
    let top = stack.first().ok_or("no label")?;
    let entry = view.label_entry(top.label).ok_or("label has no entry")?;
    let below = 4 * stack.len().saturating_sub(1);
    entry
        .nexthops
        .iter()
        .filter_map(|nh| {
            let mtu = usize::from(view.mtu(nh.interface.as_ref()?)?);
            Some(mtu.saturating_sub(4 * nh.out_labels.len() + below))
        })
        .min()
        .ok_or("MTU of the way out unknown")
}

/// Whether an IPv6 packet carries a fragment header (walking the
/// extension headers that may come before it, RFC 8200 §4.1).
fn has_fragment_header(p: &[u8]) -> bool {
    let mut next = p.get(6).copied();
    let mut at = 40;
    for _ in 0..8 {
        match next {
            Some(44) => return true,
            // Hop-by-hop, routing, destination options: length in 8-octet
            // units, not counting the first 8.
            Some(0 | 43 | 60) => {
                let (Some(n), Some(l)) = (p.get(at).copied(), p.get(at + 1).copied()) else {
                    return false;
                };
                next = Some(n);
                at += 8 + 8 * usize::from(l);
            }
            _ => return false,
        }
    }
    false
}

/// The error for `t`, or why none is sent (for the counters).
pub fn answer(t: &TooBig, view: &dyn LsrView) -> Result<Icmp, &'static str> {
    let mtu = limit(&t.stack, view)?;
    if t.len <= mtu {
        // A GSO packet the kernel segments, or a table that changed.
        return Err("fits the way out");
    }
    let v6 = match t.packet.first().map(|b| b >> 4) {
        Some(4) => false,
        Some(6) => true,
        _ => return Err("not IP under the stack"),
    };
    if v6 {
        if t.len <= IPV6_MIN_MTU && has_fragment_header(&t.packet) {
            return Err("IPv6 to fragment (RFC 3032 §3.5)");
        }
    } else {
        let df = t.packet.get(6).is_some_and(|b| b & 0x40 != 0);
        if !df {
            return Err("DF not set (RFC 3032 §3.4: dropped)");
        }
    }
    let to = expired::original(&t.packet, v6)?.src;
    let src = expired::source(&t.interface, to, view).ok_or("no address to send from")?;
    let (head, body, ext) = if v6 {
        let m = u32::try_from(mtu).unwrap_or(u32::MAX).to_be_bytes();
        let body = t.packet.get(..QUOTE6).unwrap_or(&t.packet).to_vec();
        ([ICMP6_TOO_BIG, 0, 0, 0, m[0], m[1], m[2], m[3]], body, None)
    } else {
        // RFC 1191 §4: Next-Hop MTU in octets 6–7; RFC 4884 §4.1: the
        // quote's length in 32-bit words at octet 5.
        let m = u16::try_from(mtu).unwrap_or(u16::MAX).to_be_bytes();
        let mut body = t.packet.get(..QUOTE).unwrap_or(&t.packet).to_vec();
        body.resize(QUOTE, 0);
        (
            [
                ICMP_UNREACHABLE,
                FRAG_NEEDED,
                0,
                0,
                0,
                (QUOTE / 4) as u8,
                m[0],
                m[1],
            ],
            body,
            Some(t.stack.as_slice()),
        )
    };
    let message = expired::message(head, &body, ext, src, to);
    let packet = expired::ip_packet(src, to, &message).ok_or("address families differ")?;
    let delivery = expired::delivery(&t.stack, to, view)?;
    Ok(Icmp {
        packet,
        to,
        delivery,
    })
}

/// Where an error about `t` would go (the per-source rate limit's key).
pub fn origin(t: &TooBig) -> Option<IpAddr> {
    expired::origin(&t.packet)
}

#[cfg(test)]
mod tests;

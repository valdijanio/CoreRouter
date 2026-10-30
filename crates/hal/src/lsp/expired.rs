//! ICMP "time exceeded" for labeled packets whose TTL expires here (G3.9d),
//! without I/O.
//!
//! The Linux MPLS forwarder drops a packet whose top label TTL is 0 or 1
//! (`mpls_forward`: `if (dec.ttl <= 1) goto err`) and sends nothing, so a
//! traceroute through the LSP shows `*` at this LSR. The responder's packet
//! socket already copies those frames (its classic BPF filter keeps top TTL
//! ≤ 1); this module turns one into the ICMP error the kernel does not
//! send:
//!
//! - **What is sent** (RFC 3032 §2.3.1; RFC 792 / RFC 4443 §3.3): ICMP type
//!   11 / ICMPv6 type 3, code 0, quoting the first 128 octets of the IP
//!   packet under the stack, zero-padded, followed by the RFC 4884
//!   extension structure with the RFC 4950 object holding the stack as it
//!   arrived (what `mtr -e` and RouterOS traceroute show as `MPLS:L=…`).
//!   From an address of the interface it came in on, IP TTL 255.
//! - **Not sent** (RFC 1812 §4.3.2.7, RFC 4443 §2.4(e)): about an ICMP
//!   error, a fragment other than the first, a multicast or broadcast
//!   destination, or a source that is not a unicast host.
//! - **How it goes back** (RFC 3032 §2.3.2, as Cisco does by default): a
//!   packet with one label goes by the IP table when this router has a
//!   route to the source; a deeper stack (a VPN: the source may be an
//!   address this router does not know, or one it knows in another table)
//!   is label switched along the original LSP, the stack copied with its
//!   top label swapped as the label table says and every TTL set to 255,
//!   so the egress routes it back to the source. Without a route, a single
//!   label also goes along the LSP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::IfName;
use ipnet::IpNet;

use super::LsrView;
use crate::icmp_ext;
use crate::probe::MplsLabel;

/// Octets of the original packet quoted (RFC 4884 §4: at least 128 when
/// extensions follow; Cisco and Junos quote exactly 128).
pub const QUOTE: usize = icmp_ext::MIN_ORIGINAL;
/// IP TTL of the error and of the labels it carries (RFC 3032 §2.3.2:
/// "long enough to allow the circuitous route").
pub const TTL: u8 = 255;
/// Labels walked in a received stack.
pub const MAX_STACK: usize = 16;

const PROTO_ICMP: u8 = 1;
const PROTO_ICMP6: u8 = 58;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP6_TIME_EXCEEDED: u8 = 3;
/// DSCP CS6 (internetwork control), what Linux puts on its ICMP errors.
const TOS: u8 = 0xc0;

/// A labeled packet whose top TTL expired here, as the data plane copied
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    /// Where it came in.
    pub interface: IfName,
    /// The labels it came with, top first (at least one).
    pub stack: Vec<MplsLabel>,
    /// The start of the IP packet under the stack: at most [`QUOTE`]
    /// octets, cut at the packet's own length (Ethernet pads short frames).
    pub packet: Vec<u8>,
}

/// How the error leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// By the IP table, to the source.
    Ip,
    /// Label switched out of `interface` to `nexthop` with `stack` (empty:
    /// the top label popped to an unlabeled next hop).
    Lsp {
        interface: IfName,
        nexthop: Option<IpAddr>,
        stack: Vec<MplsLabel>,
    },
}

/// The error to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    /// The whole IP packet (header, ICMP, quote, extensions).
    pub packet: Vec<u8>,
    /// Its destination: the expired packet's source.
    pub to: IpAddr,
    pub delivery: Delivery,
}

/// The stack and the start of the IP packet of an MPLS frame's payload
/// (after the Ethernet header), if its top TTL expired. `None`: not
/// expired, malformed, or not IP under the stack.
pub fn parse(interface: &IfName, mpls: &[u8]) -> Option<Expired> {
    let mut stack = Vec::new();
    let mut at = 0;
    loop {
        let w = u32::from_be_bytes(mpls.get(at..at + 4)?.try_into().ok()?);
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
    if stack.first()?.ttl > 1 {
        return None;
    }
    let ip = mpls.get(at..)?;
    let len = match ip.first()? >> 4 {
        4 => usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?])),
        6 => 40 + usize::from(u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?])),
        _ => return None,
    };
    let keep = len.min(ip.len()).min(QUOTE);
    Some(Expired {
        interface: interface.clone(),
        stack,
        packet: ip.get(..keep)?.to_vec(),
    })
}

/// What the expired packet was, read from its header.
struct Original {
    src: IpAddr,
}

fn v4_unicast(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_loopback())
}

/// RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e): whether an error may be sent
/// about `p`, and to whom.
fn original(p: &[u8]) -> Result<Original, &'static str> {
    match p.first().map(|b| b >> 4) {
        Some(4) => {
            let ihl = usize::from(p.first().copied().unwrap_or(0) & 0x0f) * 4;
            let h: [u8; 20] = p
                .get(..20)
                .and_then(|h| h.try_into().ok())
                .ok_or("truncated IPv4 header")?;
            if ihl < 20 {
                return Err("bad IPv4 header");
            }
            let frag = u16::from_be_bytes([h[6], h[7]]) & 0x1fff;
            if frag != 0 {
                return Err("not the first fragment");
            }
            let src = Ipv4Addr::new(h[12], h[13], h[14], h[15]);
            let dst = Ipv4Addr::new(h[16], h[17], h[18], h[19]);
            if !v4_unicast(src) {
                return Err("source is not a unicast host");
            }
            if dst.is_multicast() || dst.is_broadcast() {
                return Err("multicast or broadcast destination");
            }
            if h[9] == PROTO_ICMP {
                // Only queries (echo, timestamp…) may be answered with an
                // error; RFC 792 error types are 3, 4, 5, 11, 12.
                let ty = p.get(ihl).copied().ok_or("truncated ICMP")?;
                if matches!(ty, 3 | 4 | 5 | 11 | 12) {
                    return Err("about an ICMP error");
                }
            }
            Ok(Original {
                src: IpAddr::V4(src),
            })
        }
        Some(6) => {
            let h: [u8; 40] = p
                .get(..40)
                .and_then(|h| h.try_into().ok())
                .ok_or("truncated IPv6 header")?;
            let addr = |at: usize| -> Option<Ipv6Addr> {
                let b: [u8; 16] = h.get(at..at + 16)?.try_into().ok()?;
                Some(Ipv6Addr::from(b))
            };
            let src = addr(8).ok_or("truncated IPv6 header")?;
            let dst = addr(24).ok_or("truncated IPv6 header")?;
            if src.is_unspecified() || src.is_multicast() || src.is_loopback() {
                return Err("source is not a unicast host");
            }
            if dst.is_multicast() {
                return Err("multicast destination");
            }
            // ICMPv6 errors have types below 128 (RFC 4443 §2.1).
            if h[6] == PROTO_ICMP6 && p.get(40).is_some_and(|t| *t < 128) {
                return Err("about an ICMP error");
            }
            Ok(Original {
                src: IpAddr::V6(src),
            })
        }
        _ => Err("not IP under the stack"),
    }
}

fn link_local(a: &IpAddr) -> bool {
    match a {
        IpAddr::V6(x) => x.segments().first().is_some_and(|s| s & 0xffc0 == 0xfe80),
        IpAddr::V4(x) => x.is_link_local(),
    }
}

/// The address the error comes from: one of the incoming interface (a
/// routable one first, as traceroute users expect the hop's link
/// address), else what the view picks.
fn source(e: &Expired, to: IpAddr, view: &dyn LsrView) -> Option<IpAddr> {
    let addrs: Vec<IpAddr> = view
        .interface_addrs(&e.interface)
        .into_iter()
        .filter(|a| a.is_ipv6() == to.is_ipv6())
        .collect();
    addrs
        .iter()
        .find(|a| !link_local(a))
        .or(addrs.first())
        .copied()
        .or_else(|| view.source_for(to))
}

/// The ICMP message (header, quote, extensions) with its checksum;
/// ICMPv6's covers the pseudo-header (RFC 4443 §2.3).
fn icmp_message(e: &Expired, src: IpAddr, to: IpAddr) -> Vec<u8> {
    let v6 = to.is_ipv6();
    let ext = icmp_ext::encode_extension(&[icmp_ext::mpls_object(&e.stack)]);
    let mut m = Vec::with_capacity(8 + QUOTE + ext.len());
    if v6 {
        // Length in 64-bit words at octet 4 (RFC 4884 §4.5).
        m.extend_from_slice(&[ICMP6_TIME_EXCEEDED, 0, 0, 0, (QUOTE / 8) as u8, 0, 0, 0]);
    } else {
        // Length in 32-bit words at octet 5 (RFC 4884 §4.1).
        m.extend_from_slice(&[ICMP_TIME_EXCEEDED, 0, 0, 0, 0, (QUOTE / 4) as u8, 0, 0]);
    }
    let quote = e.packet.get(..QUOTE).unwrap_or(&e.packet);
    m.extend_from_slice(quote);
    m.resize(8 + QUOTE, 0);
    m.extend_from_slice(&ext);
    let sum = match (src, to) {
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut pseudo = Vec::with_capacity(40 + m.len());
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&(m.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, PROTO_ICMP6]);
            pseudo.extend_from_slice(&m);
            icmp_ext::checksum(&pseudo)
        }
        _ => icmp_ext::checksum(&m),
    };
    if let Some(c) = m.get_mut(2..4) {
        c.copy_from_slice(&sum.to_be_bytes());
    }
    m
}

/// The whole IP packet of the error.
fn ip_packet(src: IpAddr, to: IpAddr, icmp: &[u8]) -> Option<Vec<u8>> {
    match (src, to) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(20 + icmp.len()).ok()?;
            let mut p = vec![0x45, TOS];
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, TTL, PROTO_ICMP, 0, 0]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            let c = icmp_ext::checksum(&p).to_be_bytes();
            p.get_mut(10..12)?.copy_from_slice(&c);
            p.extend_from_slice(icmp);
            Some(p)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = u16::try_from(icmp.len()).ok()?;
            let mut p = vec![0x60 | (TOS >> 4), (TOS & 0x0f) << 4, 0, 0];
            p.extend_from_slice(&len.to_be_bytes());
            p.extend_from_slice(&[PROTO_ICMP6, TTL]);
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(icmp);
            Some(p)
        }
        _ => None,
    }
}

/// The original stack with its top label swapped as the label table says
/// (RFC 3032 §2.3.2), every TTL 255. `None`: the label has no entry.
fn along_the_lsp(e: &Expired, view: &dyn LsrView) -> Option<Delivery> {
    let (top, rest) = e.stack.split_first()?;
    let entry = view.label_entry(top.label)?;
    // ECMP: any way out does for an error.
    let nh = entry.nexthops.into_iter().find(|n| n.interface.is_some())?;
    let mut stack: Vec<MplsLabel> = nh
        .out_labels
        .iter()
        .map(|l| MplsLabel {
            label: *l,
            tc: top.tc,
            bottom: false,
            ttl: TTL,
        })
        .chain(rest.iter().map(|l| MplsLabel {
            bottom: false,
            ttl: TTL,
            ..*l
        }))
        .collect();
    if let Some(last) = stack.last_mut() {
        last.bottom = true;
    }
    Some(Delivery::Lsp {
        interface: nh.interface?,
        nexthop: nh.via,
        stack,
    })
}

/// The error for `e`, or why none is sent (for the counters).
pub fn answer(e: &Expired, view: &dyn LsrView) -> Result<Icmp, &'static str> {
    if e.stack.first().is_none_or(|l| l.ttl > 1) {
        return Err("TTL not expired");
    }
    let o = original(&e.packet)?;
    let to = o.src;
    let src = source(e, to, view).ok_or("no address to send from")?;
    let message = icmp_message(e, src, to);
    let packet = ip_packet(src, to, &message).ok_or("address families differ")?;
    let routed = || {
        view.fec_route(IpNet::from(to))
            .is_some_and(|nhs| !nhs.is_empty())
    };
    let delivery = if e.stack.len() == 1 && routed() {
        Delivery::Ip
    } else if let Some(d) = along_the_lsp(e, view) {
        d
    } else if routed() {
        Delivery::Ip
    } else {
        return Err("no way back to the source");
    };
    Ok(Icmp {
        packet,
        to,
        delivery,
    })
}

#[cfg(test)]
mod tests;

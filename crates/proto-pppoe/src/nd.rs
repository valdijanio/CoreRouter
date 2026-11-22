//! IPv6 on a PPP link, the BNG's side (G4.3e): what the concentrator
//! answers once IPv6CP is up, before any prefix reaches the data plane.
//!
//! - Link-local addresses come from the IPv6CP interface identifiers
//!   (RFC 5072 §5: `fe80::/64` + the 64-bit identifier; no link-layer
//!   address options on PPP).
//! - [`stable_iid`]: identifiers that are stable for one subscriber line and
//!   opaque (RFC 8064 §3 recommends the RFC 7217 scheme over identifiers
//!   built from a MAC address): a keyed hash of the port, the VLANs and the
//!   client MAC, retried past the reserved identifiers of RFC 5453.
//! - [`classify`] reads an IPv6 packet from the subscriber: Router
//!   Solicitation, Neighbor Solicitation, Echo Request (RFC 4861 §4.1,
//!   §4.3, RFC 4443 §4.1, each with the validity checks of RFC 4861 §6.1.1
//!   and §7.1.1) or DHCPv6 toward the server port (RFC 8415 §7.2).
//! - [`router_advert`] builds the RA of one session: the /64 in a Prefix
//!   Information option (RFC 4861 §4.6.2), the MTU (§4.6.4) and the DNS
//!   options RDNSS and DNSSL (RFC 8106 §5.1, §5.2). [`RaTimer`] spaces them
//!   (RFC 4861 §6.2.4, §6.2.6).
//!
//! [`router_advert_icmp`] is the same RA as a bare ICMPv6 message, for
//! the Ethernet sender of `/ipv6 nd` (G3.9ha), whose raw socket gets the
//! IPv6 header and the checksum from the kernel (RFC 3542 §3.1); there the
//! RA also carries the Source Link-Layer Address and the Default Router
//! Preference (RFC 4191 §2.2). [`parse_rs_icmp`] and [`parse_ra_icmp`] read
//! what that socket receives.
//!
//! Everything else returns whole IPv6 packets (the PPP payload of protocol
//! 0x0057) with the ICMPv6/UDP checksum over the pseudo-header (RFC 8200
//! §8.1). Readers never panic and never read past the payload length.

use crate::eth::Vlans;
use crate::timer::Millis;
use crate::wire::{Mac, WireError};
use sha2::{Digest, Sha256};
use std::net::Ipv6Addr;

/// IPv6 next-header values used here.
pub mod next {
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// ICMPv6 types (RFC 4443 §2.1, RFC 4861 §4).
pub mod icmp {
    pub const ECHO_REQUEST: u8 = 128;
    pub const ECHO_REPLY: u8 = 129;
    pub const ROUTER_SOLICIT: u8 = 133;
    pub const ROUTER_ADVERT: u8 = 134;
    pub const NEIGHBOR_SOLICIT: u8 = 135;
    pub const NEIGHBOR_ADVERT: u8 = 136;
}

/// Neighbor Discovery option types.
pub mod ndopt {
    /// RFC 4861 §4.6.1.
    pub const SOURCE_LL: u8 = 1;
    /// RFC 4861 §4.6.2.
    pub const PREFIX_INFO: u8 = 3;
    /// RFC 4861 §4.6.4.
    pub const MTU: u8 = 5;
    /// RFC 8106 §5.1.
    pub const RDNSS: u8 = 25;
    /// RFC 8106 §5.2.
    pub const DNSSL: u8 = 31;
}

/// UDP ports of DHCPv6 (RFC 8415 §7.2).
pub const DHCP6_CLIENT_PORT: u16 = 546;
pub const DHCP6_SERVER_PORT: u16 = 547;
/// `ff02::1:2`, All_DHCP_Relay_Agents_and_Servers (RFC 8415 §7.1).
pub const ALL_DHCP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
/// `ff02::1`, all nodes: the destination of unsolicited RAs.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// `ff02::2`, all routers: where a Router Solicitation goes.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// IPv6 fixed header (RFC 8200 §3).
pub const IPV6_HLEN: usize = 40;
/// Largest packet built here: within the IPv6 minimum MTU (RFC 8200 §5),
/// so an RA always fits the link.
pub const MAX_BUILT: usize = 1280;
/// DNS servers and search domains one RA carries at most (an RDNSS of 8
/// addresses is 136 bytes; more is a config error, not a reason to grow).
pub const MAX_DNS: usize = 8;
pub const MAX_DOMAINS: usize = 8;

/// RFC 4861 §10 router constants.
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL_MS: u64 = 16_000;
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;
pub const MIN_DELAY_BETWEEN_RAS_MS: u64 = 3_000;

/// `fe80::<iid>` (RFC 5072 §5).
pub fn link_local(iid: [u8; 8]) -> Ipv6Addr {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    for (d, s) in a.iter_mut().skip(8).zip(iid) {
        *d = s;
    }
    Ipv6Addr::from(a)
}

/// The interface identifier of `a` (its low 64 bits).
pub fn iid_of(a: Ipv6Addr) -> [u8; 8] {
    (a.to_bits() as u64).to_be_bytes()
}

/// `prefix` (its high 64 bits) + `iid`.
pub fn with_iid(prefix: Ipv6Addr, iid: [u8; 8]) -> Ipv6Addr {
    let hi = prefix.to_bits() & !u128::from(u64::MAX);
    Ipv6Addr::from_bits(hi | u128::from(u64::from_be_bytes(iid)))
}

/// RFC 5453 §3 reserved identifiers (plus all zeros, the Subnet-Router
/// anycast of RFC 4291 §2.6.1): never proposed.
pub fn is_reserved_iid(iid: [u8; 8]) -> bool {
    let v = u64::from_be_bytes(iid);
    v == 0
        // Proxy Mobile IPv6, 0200:5EFF:FE00:0000–0200:5EFF:FE00:5212.
        || (0x0200_5eff_fe00_0000..=0x0200_5eff_fe00_5212).contains(&v)
        // Subnet anycast (RFC 2526), FDFF:FFFF:FFFF:FF80–FDFF:FFFF:FFFF:FFFF.
        || (0xfdff_ffff_ffff_ff80..=0xfdff_ffff_ffff_ffff).contains(&v)
}

/// Who an identifier is for: the BNG's own end of the link or the one it
/// suggests to a subscriber that proposed zero or a collision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IidRole {
    Local,
    Peer,
}

/// A stable, opaque interface identifier (RFC 8064 §3, built as RFC 7217
/// §5): `F(prefix, port, network id, counter, secret)` with SHA-256, the
/// network id being the subscriber line (VLANs + client MAC) and the prefix
/// `fe80::/64`. The same line gets the same link-local after every
/// reconnect (logs and ACLs stay readable), nobody learns the MAC from it,
/// and another BNG with another secret gives other values. The counter
/// steps past reserved identifiers (RFC 7217 §6 does the same for DAD).
pub fn stable_iid(
    secret: &[u8; 32],
    ifindex: u32,
    vlans: Vlans,
    mac: Mac,
    role: IidRole,
) -> [u8; 8] {
    for counter in 0u8..=u8::MAX {
        let mut h = Sha256::new();
        h.update([0xfe, 0x80, 0, 0, 0, 0, 0, 0]);
        h.update(ifindex.to_be_bytes());
        h.update(vlans.outer.to_be_bytes());
        h.update(vlans.inner.to_be_bytes());
        h.update(vlans.outer_tpid.to_be_bytes());
        h.update(mac.0);
        h.update([role as u8, counter]);
        h.update(secret);
        let d = h.finalize();
        let mut iid = [0u8; 8];
        for (o, b) in iid.iter_mut().zip(d.iter()) {
            *o = *b;
        }
        if !is_reserved_iid(iid) {
            return iid;
        }
    }
    // 256 reserved hashes in a row do not happen; a fixed non-reserved value
    // keeps the function total.
    [0x02, 0, 0, 0, 0, 0, 0, 1]
}

/// The fixed header of a received packet and its payload (bounded by the
/// Payload Length field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Head<'a> {
    pub next: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub payload: &'a [u8],
}

fn addr_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let s: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(s))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Reads the IPv6 fixed header. Extension headers are not walked: ND and
/// DHCPv6 on a PPP link come without them, and anything else is not ours
/// to answer.
pub fn parse_ipv6(p: &[u8]) -> Result<Ipv6Head<'_>, WireError> {
    let have = p.len();
    if have < IPV6_HLEN {
        return Err(WireError::Truncated {
            need: IPV6_HLEN,
            have,
        });
    }
    let first = p.first().copied().unwrap_or(0);
    if first >> 4 != 6 {
        return Err(WireError::Malformed("not IPv6"));
    }
    let len = usize::from(u16_at(p, 4).unwrap_or(0));
    let payload = p
        .get(IPV6_HLEN..IPV6_HLEN + len)
        .ok_or(WireError::BadLength {
            field: len,
            have: have - IPV6_HLEN,
        })?;
    Ok(Ipv6Head {
        next: p.get(6).copied().unwrap_or(0),
        hop_limit: p.get(7).copied().unwrap_or(0),
        src: addr_at(p, 8).unwrap_or(Ipv6Addr::UNSPECIFIED),
        dst: addr_at(p, 24).unwrap_or(Ipv6Addr::UNSPECIFIED),
        payload,
    })
}

/// RFC 8200 §8.1 upper-layer checksum: pseudo-header (source, destination,
/// upper-layer length, next header) and the data, one's complement.
pub fn checksum(src: Ipv6Addr, dst: Ipv6Addr, next: u8, data: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut add = |b: &[u8]| {
        let (pairs, rest) = b.as_chunks::<2>();
        for c in pairs {
            sum += u64::from(u16::from_be_bytes(*c));
        }
        if let Some(l) = rest.first() {
            sum += u64::from(*l) << 8;
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(data.len() as u32).to_be_bytes());
    add(&[0, 0, 0, next]);
    add(data);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// What the BNG does with an IPv6 packet from a subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound<'a> {
    /// RFC 4861 §4.1, valid by §6.1.1.
    RouterSolicit { src: Ipv6Addr },
    /// RFC 4861 §4.3, valid by §7.1.1.
    NeighborSolicit { src: Ipv6Addr, target: Ipv6Addr },
    /// RFC 4443 §4.1 toward one of our addresses.
    EchoRequest {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        body: &'a [u8],
    },
    /// UDP to port 547 (RFC 8415 §7.2).
    Dhcp6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        payload: &'a [u8],
    },
    /// Any other packet (forwarded traffic, or ND we do not act on).
    Other,
    /// ND that fails its validity checks: silently discarded (RFC 4861
    /// §6.1.1, §7.1.1), counted by the caller.
    Invalid(&'static str),
}

/// Sorts one packet. `checksum` failures and the ND rules (hop limit 255,
/// code 0, length, no unspecified source with an option) make `Invalid`.
pub fn classify(p: &[u8]) -> Inbound<'_> {
    let Ok(h) = parse_ipv6(p) else {
        return Inbound::Invalid("bad IPv6 header");
    };
    match h.next {
        next::ICMPV6 => classify_icmp(&h),
        next::UDP => classify_udp(&h),
        _ => Inbound::Other,
    }
}

fn classify_icmp<'a>(h: &Ipv6Head<'a>) -> Inbound<'a> {
    let b = h.payload;
    let (Some(kind), Some(code)) = (b.first().copied(), b.get(1).copied()) else {
        return Inbound::Invalid("ICMPv6 shorter than 4 bytes");
    };
    if !matches!(
        kind,
        icmp::ROUTER_SOLICIT | icmp::NEIGHBOR_SOLICIT | icmp::ECHO_REQUEST
    ) {
        return Inbound::Other;
    }
    if checksum(h.src, h.dst, next::ICMPV6, b) != 0 {
        return Inbound::Invalid("bad ICMPv6 checksum");
    }
    if kind == icmp::ECHO_REQUEST {
        if code != 0 || b.len() < 8 {
            return Inbound::Invalid("bad Echo Request");
        }
        return Inbound::EchoRequest {
            src: h.src,
            dst: h.dst,
            body: b.get(4..).unwrap_or(&[]),
        };
    }
    // RFC 4861 §6.1.1 / §7.1.1: hop limit 255 (the packet was not routed),
    // code 0, and the options all have a non-zero length.
    if h.hop_limit != 255 {
        return Inbound::Invalid("ND hop limit is not 255");
    }
    if code != 0 {
        return Inbound::Invalid("ND code is not 0");
    }
    let fixed = if kind == icmp::ROUTER_SOLICIT { 8 } else { 24 };
    if b.len() < fixed {
        return Inbound::Invalid("ND message too short");
    }
    let opts = b.get(fixed..).unwrap_or(&[]);
    let mut at = 0usize;
    let mut has_sllao = false;
    while at < opts.len() {
        let (Some(t), Some(l)) = (opts.get(at).copied(), opts.get(at + 1).copied()) else {
            return Inbound::Invalid("ND option truncated");
        };
        if l == 0 {
            return Inbound::Invalid("ND option of length 0");
        }
        has_sllao |= t == 1;
        at += usize::from(l) * 8;
        if at > opts.len() {
            return Inbound::Invalid("ND option past the end");
        }
    }
    if kind == icmp::ROUTER_SOLICIT {
        // §6.1.1: unspecified source → no source link-layer option.
        if h.src.is_unspecified() && has_sllao {
            return Inbound::Invalid("RS from :: with a link-layer option");
        }
        return Inbound::RouterSolicit { src: h.src };
    }
    let Some(target) = addr_at(b, 8) else {
        return Inbound::Invalid("NS too short");
    };
    // §7.1.1: target not multicast; from :: only to a solicited-node group,
    // without a source link-layer option (that is DAD, answered to ff02::1).
    if target.is_multicast() {
        return Inbound::Invalid("NS target is multicast");
    }
    if h.src.is_unspecified() && (has_sllao || h.dst.segments()[0] != 0xff02) {
        return Inbound::Invalid("DAD NS not to a solicited-node group");
    }
    Inbound::NeighborSolicit { src: h.src, target }
}

fn classify_udp<'a>(h: &Ipv6Head<'a>) -> Inbound<'a> {
    let b = h.payload;
    let (Some(sp), Some(dp), Some(len)) = (u16_at(b, 0), u16_at(b, 2), u16_at(b, 4)) else {
        return Inbound::Other;
    };
    if dp != DHCP6_SERVER_PORT {
        return Inbound::Other;
    }
    let len = usize::from(len);
    let Some(dgram) = b.get(..len).filter(|_| len >= 8) else {
        return Inbound::Invalid("UDP length past the payload");
    };
    // RFC 8200 §8.1: a zero UDP checksum is invalid over IPv6.
    if u16_at(b, 6) == Some(0) || checksum(h.src, h.dst, next::UDP, dgram) != 0 {
        return Inbound::Invalid("bad UDP checksum");
    }
    Inbound::Dhcp6 {
        src: h.src,
        dst: h.dst,
        src_port: sp,
        payload: dgram.get(8..).unwrap_or(&[]),
    }
}

fn ipv6_header(out: &mut Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop: u8, len: usize) {
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    out.push(next);
    out.push(hop);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
}

/// Appends an ICMPv6 packet: header, then `body` after type/code/checksum.
fn icmp6(out: &mut Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr, kind: u8, body: &[u8]) {
    let mut m = Vec::with_capacity(4 + body.len());
    m.extend_from_slice(&[kind, 0, 0, 0]);
    m.extend_from_slice(body);
    let c = checksum(src, dst, next::ICMPV6, &m);
    if let Some(s) = m.get_mut(2..4) {
        s.copy_from_slice(&c.to_be_bytes());
    }
    ipv6_header(out, src, dst, next::ICMPV6, 255, m.len());
    out.extend_from_slice(&m);
}

/// One Prefix Information option (RFC 4861 §4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub len: u8,
    /// L: the prefix is on-link.
    pub on_link: bool,
    /// A: usable for SLAAC (RFC 4862 §5.5.3, only with a /64).
    pub autonomous: bool,
    pub valid: u32,
    pub preferred: u32,
}

/// The Router Advertisement of one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaConfig {
    /// Cur Hop Limit for the subscriber (0 = unspecified).
    pub hop_limit: u8,
    /// M: addresses by DHCPv6 (IA_NA offered).
    pub managed: bool,
    /// O: other configuration by DHCPv6 (DNS, the delegated prefix).
    pub other: bool,
    /// Router Lifetime, seconds (0 = not a default router; ≤ 9000,
    /// RFC 8319 §4 allows up to 65535).
    pub router_lifetime: u16,
    pub reachable_ms: u32,
    pub retrans_ms: u32,
    /// The link MTU (the subscriber's negotiated MRU), if advertised.
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
    pub rdnss: Vec<Ipv6Addr>,
    pub dnssl: Vec<String>,
    /// RDNSS/DNSSL lifetime, seconds (RFC 8106 §5.1: by default at least
    /// 3 × MaxRtrAdvInterval).
    pub dns_lifetime: u32,
    /// Source Link-Layer Address option (RFC 4861 §4.6.1; none on PPP).
    pub sllao: Option<[u8; 6]>,
    /// Default Router Preference, the two Prf bits (RFC 4191 §2.2: 01
    /// high, 00 medium, 11 low; 10 is reserved and sent as medium).
    pub preference: u8,
}

impl Default for RaConfig {
    fn default() -> Self {
        RaConfig {
            hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: 1800,
            reachable_ms: 0,
            retrans_ms: 0,
            mtu: None,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl: Vec::new(),
            dns_lifetime: 1800,
            sllao: None,
            preference: 0,
        }
    }
}

fn dns_name(name: &str, out: &mut Vec<u8>) -> bool {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        let Ok(l) = u8::try_from(label.len()) else {
            return false;
        };
        if l == 0 || l > 63 {
            return false;
        }
        out.push(l);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    true
}

/// Appends the RA of `cfg` from `src` (our link-local) to `dst`
/// (`ff02::1`, or the soliciting subscriber). Options past [`MAX_DNS`] /
/// [`MAX_DOMAINS`] and names that are not valid DNS names are left out;
/// the packet never exceeds [`MAX_BUILT`].
pub fn router_advert(out: &mut Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr, cfg: &RaConfig) {
    let b = ra_body(cfg);
    icmp6(out, src, dst, icmp::ROUTER_ADVERT, &b);
}

/// The RA of `cfg` as an ICMPv6 message with a zero checksum, for a raw
/// ICMPv6 socket (the kernel fills the checksum, RFC 3542 §3.1). Within
/// [`MAX_BUILT`] with the IPv6 header, like [`router_advert`].
pub fn router_advert_icmp(cfg: &RaConfig) -> Vec<u8> {
    let b = ra_body(cfg);
    let mut m = Vec::with_capacity(4 + b.len());
    m.extend_from_slice(&[icmp::ROUTER_ADVERT, 0, 0, 0]);
    m.extend_from_slice(&b);
    m
}

/// The RA after type, code and checksum (RFC 4861 §4.2).
fn ra_body(cfg: &RaConfig) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    // RFC 4191 §2.2: Prf in bits 3-4 of the flags; 10 (reserved) MUST
    // NOT be sent, it goes out as medium.
    let prf = match cfg.preference & 0b11 {
        0b10 => 0,
        p => p,
    };
    let flags = (u8::from(cfg.managed) << 7) | (u8::from(cfg.other) << 6) | (prf << 3);
    b.extend_from_slice(&[cfg.hop_limit, flags]);
    b.extend_from_slice(&cfg.router_lifetime.to_be_bytes());
    b.extend_from_slice(&cfg.reachable_ms.to_be_bytes());
    b.extend_from_slice(&cfg.retrans_ms.to_be_bytes());
    if let Some(mac) = cfg.sllao {
        b.extend_from_slice(&[ndopt::SOURCE_LL, 1]);
        b.extend_from_slice(&mac);
    }
    if let Some(m) = cfg.mtu {
        b.extend_from_slice(&[ndopt::MTU, 1, 0, 0]);
        b.extend_from_slice(&m.to_be_bytes());
    }
    for p in cfg.prefixes.iter().take(MAX_DNS) {
        let len = p.len.min(128);
        let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
        let net = Ipv6Addr::from_bits(p.prefix.to_bits() & mask);
        // §4.6.2: preferred never above valid.
        let preferred = p.preferred.min(p.valid);
        let f = (u8::from(p.on_link) << 7) | (u8::from(p.autonomous) << 6);
        b.extend_from_slice(&[ndopt::PREFIX_INFO, 4, len, f]);
        b.extend_from_slice(&p.valid.to_be_bytes());
        b.extend_from_slice(&preferred.to_be_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&net.octets());
    }
    let dns: Vec<Ipv6Addr> = cfg.rdnss.iter().take(MAX_DNS).copied().collect();
    if !dns.is_empty() {
        // §5.1: Length = 1 + 2 × addresses, in units of 8 octets.
        b.extend_from_slice(&[ndopt::RDNSS, 1 + 2 * dns.len() as u8, 0, 0]);
        b.extend_from_slice(&cfg.dns_lifetime.to_be_bytes());
        for a in dns {
            b.extend_from_slice(&a.octets());
        }
    }
    let mut names = Vec::new();
    for d in cfg.dnssl.iter().take(MAX_DOMAINS) {
        let mark = names.len();
        if !dns_name(d, &mut names) {
            names.truncate(mark);
        }
    }
    if !names.is_empty() {
        // §5.2: padded with zeros to a multiple of 8 octets.
        let body = 8 + names.len();
        let total = body.div_ceil(8) * 8;
        if b.len() + 4 + total <= MAX_BUILT - IPV6_HLEN {
            b.extend_from_slice(&[ndopt::DNSSL, (total / 8) as u8, 0, 0]);
            b.extend_from_slice(&cfg.dns_lifetime.to_be_bytes());
            b.extend_from_slice(&names);
            b.resize(b.len() + total - body, 0);
        }
    }
    b
}

/// Appends a Neighbor Advertisement for `target` (RFC 4861 §4.4; R set,
/// we are a router; S when it answers a unicast solicitation; O clear, no
/// link-layer address on PPP).
pub fn neighbor_advert(
    out: &mut Vec<u8>,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    target: Ipv6Addr,
    solicited: bool,
) {
    let mut b = vec![0x80 | (u8::from(solicited) << 6), 0, 0, 0];
    b.extend_from_slice(&target.octets());
    icmp6(out, src, dst, icmp::NEIGHBOR_ADVERT, &b);
}

/// Appends the Echo Reply to `body` (identifier, sequence, data; RFC 4443
/// §4.2), cut so the packet stays within [`MAX_BUILT`].
pub fn echo_reply(out: &mut Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) {
    let keep = body.len().min(MAX_BUILT - IPV6_HLEN - 4);
    icmp6(
        out,
        src,
        dst,
        icmp::ECHO_REPLY,
        body.get(..keep).unwrap_or(&[]),
    );
}

/// Appends a UDP datagram (DHCPv6 replies: 547 → 546).
pub fn udp6(out: &mut Vec<u8>, src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, data: &[u8]) {
    let len = 8 + data.len();
    let mut u = Vec::with_capacity(len);
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let mut c = checksum(src, dst, next::UDP, &u);
    if c == 0 {
        c = 0xffff;
    }
    if let Some(s) = u.get_mut(6..8) {
        s.copy_from_slice(&c.to_be_bytes());
    }
    ipv6_header(out, src, dst, next::UDP, 255, u.len());
    out.extend_from_slice(&u);
}

/// Appends a Router Solicitation from `src` (the subscriber side: lab and
/// tests).
pub fn router_solicit(out: &mut Vec<u8>, src: Ipv6Addr) {
    icmp6(out, src, ALL_ROUTERS, icmp::ROUTER_SOLICIT, &[0; 4]);
}

/// A Router Solicitation as a raw ICMPv6 socket hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRs {
    pub src: Ipv6Addr,
    /// The host's link-layer address, if it sent one.
    pub sllao: Option<[u8; 6]>,
}

/// Reads a Router Solicitation (RFC 4861 §6.1.1): code 0, at least 8
/// octets, every option of non-zero length, and no Source Link-Layer
/// Address option from the unspecified address. `hop_limit` is the IPv6
/// header's (from `IPV6_RECVHOPLIMIT`): it MUST be 255.
pub fn parse_rs_icmp(src: Ipv6Addr, hop_limit: u8, b: &[u8]) -> Result<ParsedRs, WireError> {
    if b.first() != Some(&icmp::ROUTER_SOLICIT) {
        return Err(WireError::Malformed("not a Router Solicitation"));
    }
    if hop_limit != 255 || b.get(1) != Some(&0) || b.len() < 8 {
        return Err(WireError::Malformed("RS fails RFC 4861 §6.1.1"));
    }
    let mut rs = ParsedRs { src, sllao: None };
    let opts = b.get(8..).unwrap_or(&[]);
    let mut at = 0usize;
    while at < opts.len() {
        let (Some(t), Some(l)) = (opts.get(at).copied(), opts.get(at + 1).copied()) else {
            return Err(WireError::Malformed("RS option truncated"));
        };
        let size = usize::from(l) * 8;
        let o = opts
            .get(at..at + size)
            .filter(|_| l != 0)
            .ok_or(WireError::BadOption { kind: t, len: size })?;
        if t == ndopt::SOURCE_LL && l == 1 {
            if src.is_unspecified() {
                return Err(WireError::Malformed("RS from :: with a link-layer address"));
            }
            rs.sllao = o.get(2..8).and_then(|m| <[u8; 6]>::try_from(m).ok());
        }
        at += size;
    }
    Ok(rs)
}

/// An RA as a subscriber reads it (lab, tests and the fuzz round trip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRa {
    pub src: Ipv6Addr,
    pub hop_limit: u8,
    pub managed: bool,
    pub other: bool,
    pub router_lifetime: u16,
    pub mtu: Option<u32>,
    pub prefixes: Vec<PrefixInfo>,
    pub rdnss: Vec<Ipv6Addr>,
    pub dnssl_raw: Vec<u8>,
    pub dns_lifetime: Option<u32>,
    pub reachable_ms: u32,
    pub retrans_ms: u32,
    /// The Prf bits (RFC 4191 §2.2).
    pub preference: u8,
    pub sllao: Option<[u8; 6]>,
}

impl Default for ParsedRa {
    fn default() -> Self {
        ParsedRa {
            src: Ipv6Addr::UNSPECIFIED,
            hop_limit: 0,
            managed: false,
            other: false,
            router_lifetime: 0,
            mtu: None,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl_raw: Vec::new(),
            dns_lifetime: None,
            reachable_ms: 0,
            retrans_ms: 0,
            preference: 0,
            sllao: None,
        }
    }
}

impl Default for PrefixInfo {
    fn default() -> Self {
        PrefixInfo {
            prefix: Ipv6Addr::UNSPECIFIED,
            len: 0,
            on_link: false,
            autonomous: false,
            valid: 0,
            preferred: 0,
        }
    }
}

/// Reads a Router Advertisement (RFC 4861 §6.1.2 checks: source
/// link-local, hop limit 255, code 0, checksum, options of non-zero
/// length).
pub fn parse_ra(p: &[u8]) -> Result<ParsedRa, WireError> {
    let h = parse_ipv6(p)?;
    let b = h.payload;
    if h.next != next::ICMPV6 || b.first() != Some(&icmp::ROUTER_ADVERT) {
        return Err(WireError::Malformed("not a Router Advertisement"));
    }
    if h.hop_limit != 255 || b.get(1) != Some(&0) || b.len() < 16 {
        return Err(WireError::Malformed("RA fails RFC 4861 §6.1.2"));
    }
    if h.src.segments()[0] != 0xfe80 {
        return Err(WireError::Malformed("RA source is not link-local"));
    }
    if checksum(h.src, h.dst, next::ICMPV6, b) != 0 {
        return Err(WireError::Malformed("bad ICMPv6 checksum"));
    }
    parse_ra_icmp(h.src, b)
}

/// Reads an RA as a raw ICMPv6 socket hands it over: the message from
/// type on, sent from `src`. The caller has checked what the IPv6 header
/// says (RFC 4861 §6.1.2: hop limit 255, link-local source); the kernel
/// checked the checksum.
pub fn parse_ra_icmp(src: Ipv6Addr, b: &[u8]) -> Result<ParsedRa, WireError> {
    if b.first() != Some(&icmp::ROUTER_ADVERT) {
        return Err(WireError::Malformed("not a Router Advertisement"));
    }
    if b.get(1) != Some(&0) || b.len() < 16 {
        return Err(WireError::Malformed("RA fails RFC 4861 §6.1.2"));
    }
    let flags = b.get(5).copied().unwrap_or(0);
    let mut ra = ParsedRa {
        src,
        hop_limit: b.get(4).copied().unwrap_or(0),
        managed: flags & 0x80 != 0,
        other: flags & 0x40 != 0,
        preference: (flags >> 3) & 0b11,
        router_lifetime: u16_at(b, 6).unwrap_or(0),
        reachable_ms: u32_at(b, 8).unwrap_or(0),
        retrans_ms: u32_at(b, 12).unwrap_or(0),
        ..ParsedRa::default()
    };
    let opts = b.get(16..).unwrap_or(&[]);
    let mut at = 0usize;
    while at < opts.len() {
        let (Some(t), Some(l)) = (opts.get(at).copied(), opts.get(at + 1).copied()) else {
            return Err(WireError::Malformed("RA option truncated"));
        };
        let size = usize::from(l) * 8;
        let o = opts
            .get(at..at + size)
            .filter(|_| l != 0)
            .ok_or(WireError::BadOption { kind: t, len: size })?;
        match t {
            ndopt::SOURCE_LL if l == 1 => {
                ra.sllao = o.get(2..8).and_then(|m| <[u8; 6]>::try_from(m).ok());
            }
            ndopt::MTU => ra.mtu = u32_at(o, 4),
            ndopt::PREFIX_INFO if l == 4 => {
                let f = o.get(3).copied().unwrap_or(0);
                if ra.prefixes.len() < MAX_DNS {
                    ra.prefixes.push(PrefixInfo {
                        len: o.get(2).copied().unwrap_or(0),
                        on_link: f & 0x80 != 0,
                        autonomous: f & 0x40 != 0,
                        valid: u32_at(o, 4).unwrap_or(0),
                        preferred: u32_at(o, 8).unwrap_or(0),
                        prefix: addr_at(o, 16).unwrap_or(Ipv6Addr::UNSPECIFIED),
                    });
                }
            }
            ndopt::RDNSS if l >= 3 => {
                ra.dns_lifetime = u32_at(o, 4);
                let mut i = 8;
                while let Some(a) = addr_at(o, i) {
                    if ra.rdnss.len() < MAX_DNS {
                        ra.rdnss.push(a);
                    }
                    i += 16;
                }
            }
            ndopt::DNSSL if l >= 2 => {
                ra.dnssl_raw = o.get(8..).unwrap_or(&[]).to_vec();
            }
            _ => {}
        }
        at += size;
    }
    Ok(ra)
}

/// RA timing of one session (RFC 4861 §6.2.4, §6.2.6), as deadlines on the
/// caller's clock.
///
/// - Right after IPv6CP comes up: up to [`MAX_INITIAL_RTR_ADVERTISEMENTS`],
///   at most [`MAX_INITIAL_RTR_ADVERT_INTERVAL_MS`] apart (the first one at
///   once: the link just came up and nobody else may have sent one).
/// - Then one every `MinRtrAdvInterval`..`MaxRtrAdvInterval`, uniformly
///   spread (§6.2.4) so 100 000 sessions do not tick together.
/// - A solicitation answers at once on a point-to-point link (§6.2.6 allows
///   a unicast answer), but not twice within [`MIN_DELAY_BETWEEN_RAS_MS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaTimer {
    pub initial_left: u8,
    pub last_sent: Option<Millis>,
    pub next_at: Millis,
}

impl RaTimer {
    pub fn new(now: Millis) -> RaTimer {
        RaTimer {
            initial_left: MAX_INITIAL_RTR_ADVERTISEMENTS,
            last_sent: None,
            next_at: now,
        }
    }

    /// An RA was sent at `now`; `rand` is any 32-bit random value,
    /// `min_ms..=max_ms` the interval (RFC 4861 §6.2.1: Min ≥ 3 s,
    /// Min ≤ 0.75 × Max).
    pub fn sent(&mut self, now: Millis, rand: u32, min_ms: u64, max_ms: u64) {
        self.last_sent = Some(now);
        let span = max_ms.saturating_sub(min_ms).max(1);
        let mut gap = min_ms + u64::from(rand) % span;
        if self.initial_left > 0 {
            self.initial_left -= 1;
            if self.initial_left > 0 {
                gap = gap.min(MAX_INITIAL_RTR_ADVERT_INTERVAL_MS);
            }
        }
        self.next_at = now.saturating_add(gap);
    }

    /// When a solicited RA may go out: now, or once the minimum gap since
    /// the last one has passed.
    pub fn solicited_at(&self, now: Millis) -> Millis {
        match self.last_sent {
            Some(t) => now.max(t + MIN_DELAY_BETWEEN_RAS_MS),
            None => now,
        }
    }
}

#[cfg(test)]
mod tests;

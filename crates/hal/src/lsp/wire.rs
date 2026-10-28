//! MPLS echo request / reply on the wire (RFC 8029 §3, with the updates of
//! RFC 9570 and the errata 7639 and 8788).
//!
//! ```text
//! | version (1)       | global flags (R T V)  |
//! | msg type | reply mode | return code | subcode |
//! | sender's handle                              |
//! | sequence number                              |
//! | timestamp sent (NTP, 64 bits)                |
//! | timestamp received (NTP, 64 bits)            |
//! | TLVs: type (2) length (2) value, zero padded to 4 octets
//! ```
//!
//! Pure code over bytes: every input is hostile. Lengths are checked
//! before use, a TLV that does not fit is an error ([`WireError`]), and
//! the number of TLVs, FECs and labels read is bounded.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::probe::MplsLabel;

/// RFC 8029 §6.1: the UDP port of MPLS echo requests.
pub const PORT: u16 = 3503;
/// RFC 8029 §3: "The Version Number is currently 1."
pub const VERSION: u16 = 1;
/// The fixed part, before the TLVs.
pub const HEADER_LEN: usize = 32;
/// TLVs read from one message (a real one has 1–4).
const MAX_TLVS: usize = 64;
/// FECs read from one Target FEC Stack.
const MAX_FECS: usize = 16;
/// Labels read from one Label Stack sub-TLV or Interface and Label Stack.
pub const MAX_LABELS: usize = 16;

/// RFC 8029 §3 message types.
pub const MSG_REQUEST: u8 = 1;
pub const MSG_REPLY: u8 = 2;

/// RFC 8029 §3 reply modes. Mode 3 (with Router Alert) is deprecated by
/// RFC 9570 §2.2: never sent, answered like mode 2.
pub const REPLY_NONE: u8 = 1;
pub const REPLY_UDP: u8 = 2;
pub const REPLY_UDP_ROUTER_ALERT: u8 = 3;
pub const REPLY_CONTROL_CHANNEL: u8 = 4;

/// RFC 8029 §3 global flags.
pub const FLAG_VALIDATE: u16 = 0x0001;
pub const FLAG_TTL_EXPIRED_ONLY: u16 = 0x0002;
pub const FLAG_REVERSE_PATH: u16 = 0x0004;

/// RFC 8029 §3 TLV types.
pub const TLV_FEC_STACK: u16 = 1;
pub const TLV_PAD: u16 = 3;
pub const TLV_VENDOR: u16 = 5;
pub const TLV_IF_LABEL_STACK: u16 = 7;
pub const TLV_ERRORED: u16 = 9;
pub const TLV_REPLY_TOS: u16 = 10;
pub const TLV_DDMAP: u16 = 20;

/// RFC 8029 §3.2 Target FEC Stack sub-types this codec understands.
pub const FEC_LDP_V4: u16 = 1;
pub const FEC_LDP_V6: u16 = 2;
pub const FEC_GENERIC_V4: u16 = 14;
pub const FEC_GENERIC_V6: u16 = 15;
pub const FEC_NIL: u16 = 16;

/// RFC 8029 §3.4.1 DDMAP sub-TLVs.
pub const DDMAP_SUB_LABEL_STACK: u16 = 2;

/// RFC 8029 §3.4 DS flags.
pub const DS_FLAG_IF_LABEL_STACK: u8 = 0x02;
pub const DS_FLAG_NON_IP: u8 = 0x01;

/// RFC 8029 §3.4.1.2 label distribution protocols.
pub const PROTO_UNKNOWN: u8 = 0;
pub const PROTO_STATIC: u8 = 1;
pub const PROTO_BGP: u8 = 2;
pub const PROTO_LDP: u8 = 3;

/// RFC 3032 §2.1 reserved labels.
pub const LABEL_EXPLICIT_NULL_V4: u32 = 0;
pub const LABEL_ROUTER_ALERT: u32 = 1;
pub const LABEL_EXPLICIT_NULL_V6: u32 = 2;
pub const LABEL_IMPLICIT_NULL: u32 = 3;

/// RFC 8029 §3.1 return codes.
pub mod code {
    pub const NONE: u8 = 0;
    pub const MALFORMED: u8 = 1;
    pub const TLV_NOT_UNDERSTOOD: u8 = 2;
    pub const EGRESS: u8 = 3;
    pub const NO_MAPPING: u8 = 4;
    pub const DS_MISMATCH: u8 = 5;
    pub const UPSTREAM_IF_UNKNOWN: u8 = 6;
    pub const LABEL_SWITCHED: u8 = 8;
    pub const SWITCHED_NO_MPLS: u8 = 9;
    pub const WRONG_LABEL: u8 = 10;
    pub const NO_LABEL_ENTRY: u8 = 11;
    pub const PROTOCOL_NOT_ON_IF: u8 = 12;
    pub const PREMATURE: u8 = 13;
    pub const SEE_DDMAP: u8 = 14;
    pub const FEC_CHANGE: u8 = 15;
}

/// Why a message could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("shorter than the 32-octet header")]
    Short,
    #[error("version {0} (only 1 is known)")]
    Version(u16),
    #[error("TLV {0} does not fit in the message")]
    Truncated(u16),
    #[error("TLV {0} is malformed")]
    Malformed(u16),
    #[error("more than {MAX_TLVS} TLVs")]
    TooMany,
}

/// One FEC of a Target FEC Stack (RFC 8029 §3.2), top of the stack first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fec {
    /// LDP IPv4 / IPv6 prefix (§3.2.1, §3.2.2).
    Ldp(IpNet),
    /// Generic IPv4 / IPv6 prefix (§3.2.15, §3.2.16): the protocol is not
    /// known (a static LSP).
    Generic(IpNet),
    /// Nil FEC (§3.2.17): a reserved label, for FEC hiding.
    Nil { label: u32 },
    /// Any other sub-type (RSVP, VPN, pseudowire…), kept as is.
    Other { kind: u16, value: Vec<u8> },
}

impl Fec {
    /// The prefix of an LDP or generic FEC.
    pub fn prefix(&self) -> Option<IpNet> {
        match self {
            Self::Ldp(p) | Self::Generic(p) => Some(*p),
            _ => None,
        }
    }
}

/// Downstream (DDMAP) and interface (Interface and Label Stack) address,
/// RFC 8029 §3.4 and §3.7 with errata 8788: an unnumbered IPv6 interface
/// is an index of 4 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsAddress {
    /// Type 1: the router (or its interface) and its interface address.
    V4 { addr: Ipv4Addr, iface: Ipv4Addr },
    /// Type 2: router id and the upstream's interface index. 127.0.0.1 /
    /// index 0: "do not check the interface"; 224.0.0.2: "check nothing".
    V4Unnumbered { addr: Ipv4Addr, index: u32 },
    /// Type 3.
    V6 { addr: Ipv6Addr, iface: Ipv6Addr },
    /// Type 4.
    V6Unnumbered { addr: Ipv6Addr, index: u32 },
    /// Type 5 (RFC 6426 §3.3): no address (DDMAP only).
    NonIp,
}

impl DsAddress {
    pub fn kind(&self) -> u8 {
        match self {
            Self::V4 { .. } => 1,
            Self::V4Unnumbered { .. } => 2,
            Self::V6 { .. } => 3,
            Self::V6Unnumbered { .. } => 4,
            Self::NonIp => 5,
        }
    }

    /// The router address.
    pub fn addr(&self) -> Option<IpAddr> {
        match *self {
            Self::V4 { addr, .. } | Self::V4Unnumbered { addr, .. } => Some(IpAddr::V4(addr)),
            Self::V6 { addr, .. } | Self::V6Unnumbered { addr, .. } => Some(IpAddr::V6(addr)),
            Self::NonIp => None,
        }
    }

    /// The interface address of a numbered link.
    pub fn iface(&self) -> Option<IpAddr> {
        match *self {
            Self::V4 { iface, .. } => Some(IpAddr::V4(iface)),
            Self::V6 { iface, .. } => Some(IpAddr::V6(iface)),
            _ => None,
        }
    }

    /// A numbered address pair for `ip` (router and interface the same).
    pub fn numbered(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => Self::V4 { addr: a, iface: a },
            IpAddr::V6(a) => Self::V6 { addr: a, iface: a },
        }
    }

    /// RFC 8029 §3.4: "does not know the IP address of its neighbor":
    /// 127.0.0.1 / 0::1, index 0 (skip the interface check).
    pub fn unknown(v6: bool) -> Self {
        if v6 {
            Self::V6Unnumbered {
                addr: Ipv6Addr::LOCALHOST,
                index: 0,
            }
        } else {
            Self::V4Unnumbered {
                addr: Ipv4Addr::LOCALHOST,
                index: 0,
            }
        }
    }

    /// RFC 8029 §3.4: the all-routers address: "bypass both interface and
    /// label stack validation".
    pub fn all_routers(v6: bool) -> Self {
        if v6 {
            Self::V6Unnumbered {
                addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
                index: 0,
            }
        } else {
            Self::V4Unnumbered {
                addr: Ipv4Addr::new(224, 0, 0, 2),
                index: 0,
            }
        }
    }

    pub fn is_unknown(&self) -> bool {
        self.addr().is_some_and(|a| a.is_loopback())
    }

    pub fn is_all_routers(&self) -> bool {
        match self.addr() {
            Some(IpAddr::V4(a)) => a == Ipv4Addr::new(224, 0, 0, 2),
            Some(IpAddr::V6(a)) => a == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
            None => false,
        }
    }
}

/// One entry of a DDMAP Label Stack sub-TLV (§3.4.1.2): a label without
/// its TTL, and who distributed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DsLabel {
    pub label: u32,
    pub tc: u8,
    pub bottom: bool,
    pub protocol: u8,
}

/// Downstream Detailed Mapping TLV (§3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ddmap {
    pub mtu: u16,
    pub address: DsAddress,
    pub flags: u8,
    pub return_code: u8,
    pub return_subcode: u8,
    /// The Label Stack sub-TLV, top first (implicit null included).
    pub labels: Vec<DsLabel>,
    /// Other sub-TLVs (multipath, FEC stack change), kept as they came.
    pub other: Vec<(u16, Vec<u8>)>,
}

/// Interface and Label Stack TLV (§3.7): where the request came in, and
/// with which labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfLabelStack {
    pub address: DsAddress,
    pub stack: Vec<MplsLabel>,
}

/// A whole echo request or reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Echo {
    pub flags: u16,
    pub msg_type: u8,
    pub reply_mode: u8,
    pub return_code: u8,
    pub return_subcode: u8,
    pub handle: u32,
    pub seq: u32,
    /// NTP timestamps (seconds, fraction).
    pub sent: (u32, u32),
    pub received: (u32, u32),
    /// `None`: no Target FEC Stack TLV (a request must have one).
    pub fec_stack: Option<Vec<Fec>>,
    pub ddmaps: Vec<Ddmap>,
    pub if_label_stack: Option<IfLabelStack>,
    /// The Pad TLV's value (first octet: 1 drop from reply, 2 copy).
    pub pad: Option<Vec<u8>>,
    pub reply_tos: Option<u8>,
    pub vendor: Option<u32>,
    /// Errored TLVs TLV (§3.8): the TLVs the replier did not understand,
    /// whole.
    pub errored: Option<Vec<u8>>,
    /// Mandatory TLVs (type < 32768) this codec does not know, whole
    /// (header included): a responder answers code 2 with them.
    pub unknown: Vec<u8>,
}

impl Echo {
    pub fn request(handle: u32, seq: u32, fecs: Vec<Fec>) -> Self {
        Self {
            msg_type: MSG_REQUEST,
            reply_mode: REPLY_UDP,
            handle,
            seq,
            fec_stack: Some(fecs),
            ..Self::default()
        }
    }
}

// --- reading ---------------------------------------------------------------

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Some(u32::from_be_bytes(a))
}

fn v4_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    u32_at(b, at).map(Ipv4Addr::from)
}

fn v6_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let s = b.get(at..at.checked_add(16)?)?;
    let mut a = [0u8; 16];
    a.copy_from_slice(s);
    Some(Ipv6Addr::from(a))
}

/// `n` rounded up to 4.
fn padded(n: usize) -> usize {
    n.div_ceil(4).saturating_mul(4)
}

/// TLVs of `b`: (type, value, whole TLV with header and padding). A TLV
/// whose value runs past the end is an error; missing padding after the
/// last one is tolerated (some senders omit it).
/// One TLV: type, value, and the whole TLV (header and padding).
type Tlv<'a> = (u16, &'a [u8], &'a [u8]);

fn tlvs(b: &[u8]) -> Result<Vec<Tlv<'_>>, WireError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < b.len() {
        if out.len() >= MAX_TLVS {
            return Err(WireError::TooMany);
        }
        let (Some(kind), Some(len)) = (u16_at(b, at), u16_at(b, at + 2)) else {
            return Err(WireError::Truncated(u16_at(b, at).unwrap_or(0)));
        };
        let start = at + 4;
        let end = start + usize::from(len);
        let value = b.get(start..end).ok_or(WireError::Truncated(kind))?;
        let next = (start + padded(usize::from(len))).min(b.len());
        out.push((kind, value, b.get(at..next).unwrap_or(&[])));
        at = next;
    }
    Ok(out)
}

fn prefix(kind: u16, v: &[u8]) -> Result<IpNet, WireError> {
    let bad = WireError::Malformed(TLV_FEC_STACK);
    let v6 = matches!(kind, FEC_LDP_V6 | FEC_GENERIC_V6);
    let (want, addr_len) = if v6 { (17, 16) } else { (5, 4) };
    if v.len() < want {
        return Err(bad);
    }
    let len = *v.get(addr_len).ok_or(bad)?;
    let net = if v6 {
        let a = v6_at(v, 0).ok_or(bad)?;
        IpNet::V6(Ipv6Net::new(a, len).map_err(|_| bad)?)
    } else {
        let a = v4_at(v, 0).ok_or(bad)?;
        IpNet::V4(Ipv4Net::new(a, len).map_err(|_| bad)?)
    };
    // RFC 8029 §3.2.1: "trailing bits SHOULD be set to zero": read leniently.
    Ok(net.trunc())
}

fn fec_stack(v: &[u8]) -> Result<Vec<Fec>, WireError> {
    let mut out = Vec::new();
    for (kind, value, _) in tlvs(v).map_err(|_| WireError::Malformed(TLV_FEC_STACK))? {
        if out.len() >= MAX_FECS {
            return Err(WireError::Malformed(TLV_FEC_STACK));
        }
        out.push(match kind {
            FEC_LDP_V4 | FEC_LDP_V6 => Fec::Ldp(prefix(kind, value)?),
            FEC_GENERIC_V4 | FEC_GENERIC_V6 => Fec::Generic(prefix(kind, value)?),
            FEC_NIL => {
                let w = u32_at(value, 0).ok_or(WireError::Malformed(TLV_FEC_STACK))?;
                Fec::Nil { label: w >> 12 }
            }
            _ => Fec::Other {
                kind,
                value: value.to_vec(),
            },
        });
    }
    Ok(out)
}

/// Address fields of a DDMAP or Interface and Label Stack: the address and
/// the octets it took.
fn ds_address(kind: u8, v: &[u8], at: usize, tlv: u16) -> Result<(DsAddress, usize), WireError> {
    let bad = WireError::Malformed(tlv);
    Ok(match kind {
        1 => (
            DsAddress::V4 {
                addr: v4_at(v, at).ok_or(bad)?,
                iface: v4_at(v, at + 4).ok_or(bad)?,
            },
            8,
        ),
        2 => (
            DsAddress::V4Unnumbered {
                addr: v4_at(v, at).ok_or(bad)?,
                index: u32_at(v, at + 4).ok_or(bad)?,
            },
            8,
        ),
        3 => (
            DsAddress::V6 {
                addr: v6_at(v, at).ok_or(bad)?,
                iface: v6_at(v, at + 16).ok_or(bad)?,
            },
            32,
        ),
        // Errata 8788: the interface of an unnumbered IPv6 link is an
        // index (4 octets), not 16.
        4 => (
            DsAddress::V6Unnumbered {
                addr: v6_at(v, at).ok_or(bad)?,
                index: u32_at(v, at + 16).ok_or(bad)?,
            },
            20,
        ),
        5 if tlv == TLV_DDMAP => (DsAddress::NonIp, 0),
        _ => return Err(bad),
    })
}

fn label_entry(w: u32) -> MplsLabel {
    MplsLabel {
        label: w >> 12,
        tc: ((w >> 9) & 0x7) as u8,
        bottom: w & 0x100 != 0,
        ttl: (w & 0xff) as u8,
    }
}

fn ddmap(v: &[u8]) -> Result<Ddmap, WireError> {
    let bad = WireError::Malformed(TLV_DDMAP);
    let mtu = u16_at(v, 0).ok_or(bad)?;
    let kind = *v.get(2).ok_or(bad)?;
    let flags = *v.get(3).ok_or(bad)?;
    let (address, used) = ds_address(kind, v, 4, TLV_DDMAP)?;
    let at = 4 + used;
    let return_code = *v.get(at).ok_or(bad)?;
    let return_subcode = *v.get(at + 1).ok_or(bad)?;
    let sub_len = usize::from(u16_at(v, at + 2).ok_or(bad)?);
    let subs = v.get(at + 4..at + 4 + sub_len).ok_or(bad)?;
    let mut labels = Vec::new();
    let mut other = Vec::new();
    for (kind, value, _) in tlvs(subs).map_err(|_| bad)? {
        if kind == DDMAP_SUB_LABEL_STACK {
            if value.len() % 4 != 0 || value.len() / 4 > MAX_LABELS {
                return Err(bad);
            }
            labels = value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_be_bytes(*c))
                .map(|w| DsLabel {
                    label: w >> 12,
                    tc: ((w >> 9) & 0x7) as u8,
                    bottom: w & 0x100 != 0,
                    protocol: (w & 0xff) as u8,
                })
                .collect();
        } else if other.len() < MAX_TLVS {
            other.push((kind, value.to_vec()));
        }
    }
    Ok(Ddmap {
        mtu,
        address,
        flags,
        return_code,
        return_subcode,
        labels,
        other,
    })
}

fn if_label_stack(v: &[u8]) -> Result<IfLabelStack, WireError> {
    let bad = WireError::Malformed(TLV_IF_LABEL_STACK);
    let kind = *v.first().ok_or(bad)?;
    let (address, used) = ds_address(kind, v, 4, TLV_IF_LABEL_STACK)?;
    let rest = v.get(4 + used..).ok_or(bad)?;
    if rest.len() % 4 != 0 || rest.len() / 4 > MAX_LABELS {
        return Err(bad);
    }
    let stack = rest
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| label_entry(u32::from_be_bytes(*c)))
        .collect();
    Ok(IfLabelStack { address, stack })
}

/// The handle and sequence number of a message, without reading the rest
/// (to match a reply that fails to parse with its request).
pub fn ids(b: &[u8]) -> Option<(u32, u32)> {
    Some((u32_at(b, 8)?, u32_at(b, 12)?))
}

/// Read a message.
pub fn parse(b: &[u8]) -> Result<Echo, WireError> {
    if b.len() < HEADER_LEN {
        return Err(WireError::Short);
    }
    let version = u16_at(b, 0).ok_or(WireError::Short)?;
    if version != VERSION {
        return Err(WireError::Version(version));
    }
    let byte = |i: usize| b.get(i).copied().unwrap_or(0);
    let word = |i: usize| u32_at(b, i).unwrap_or(0);
    let mut e = Echo {
        flags: u16_at(b, 2).unwrap_or(0),
        msg_type: byte(4),
        reply_mode: byte(5),
        return_code: byte(6),
        return_subcode: byte(7),
        handle: word(8),
        seq: word(12),
        sent: (word(16), word(20)),
        received: (word(24), word(28)),
        ..Echo::default()
    };
    for (kind, value, whole) in tlvs(b.get(HEADER_LEN..).unwrap_or(&[]))? {
        match kind {
            TLV_FEC_STACK => e.fec_stack = Some(fec_stack(value)?),
            TLV_DDMAP => {
                if e.ddmaps.len() < MAX_FECS {
                    e.ddmaps.push(ddmap(value)?);
                }
            }
            TLV_IF_LABEL_STACK => e.if_label_stack = Some(if_label_stack(value)?),
            TLV_PAD => {
                if value.is_empty() {
                    return Err(WireError::Malformed(TLV_PAD));
                }
                e.pad = Some(value.to_vec());
            }
            TLV_REPLY_TOS => {
                e.reply_tos = Some(*value.first().ok_or(WireError::Malformed(kind))?);
            }
            TLV_VENDOR => e.vendor = Some(u32_at(value, 0).ok_or(WireError::Malformed(kind))?),
            TLV_ERRORED => e.errored = Some(value.to_vec()),
            // RFC 8029 §3: types >= 32768 "SHOULD be ignored" when unknown.
            k if k >= 0x8000 => {}
            _ => e.unknown.extend_from_slice(whole),
        }
    }
    Ok(e)
}

// --- writing ---------------------------------------------------------------

/// Append a TLV with `value`, padded to 4 octets. A value longer than
/// 65 535 octets is cut (never sent: callers bound their sizes).
fn put_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.get(..usize::from(len)).unwrap_or(value));
    out.resize(padded(out.len()), 0);
}

fn put_prefix(out: &mut Vec<u8>, p: &IpNet) {
    match p {
        IpNet::V4(n) => out.extend_from_slice(&n.network().octets()),
        IpNet::V6(n) => out.extend_from_slice(&n.network().octets()),
    }
    out.push(p.prefix_len());
}

fn fec_value(fecs: &[Fec]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fecs {
        let mut v = Vec::new();
        let kind = match f {
            Fec::Ldp(p) => {
                put_prefix(&mut v, p);
                if p.addr().is_ipv4() { FEC_LDP_V4 } else { FEC_LDP_V6 }
            }
            Fec::Generic(p) => {
                put_prefix(&mut v, p);
                if p.addr().is_ipv4() {
                    FEC_GENERIC_V4
                } else {
                    FEC_GENERIC_V6
                }
            }
            Fec::Nil { label } => {
                v.extend_from_slice(&((label & 0xf_ffff) << 12).to_be_bytes());
                FEC_NIL
            }
            Fec::Other { kind, value } => {
                v.extend_from_slice(value);
                *kind
            }
        };
        put_tlv(&mut out, kind, &v);
    }
    out
}

fn put_address(out: &mut Vec<u8>, a: &DsAddress) {
    match a {
        DsAddress::V4 { addr, iface } => {
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&iface.octets());
        }
        DsAddress::V4Unnumbered { addr, index } => {
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&index.to_be_bytes());
        }
        DsAddress::V6 { addr, iface } => {
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&iface.octets());
        }
        DsAddress::V6Unnumbered { addr, index } => {
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&index.to_be_bytes());
        }
        DsAddress::NonIp => {}
    }
}

fn ddmap_value(d: &Ddmap) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&d.mtu.to_be_bytes());
    v.push(d.address.kind());
    v.push(d.flags);
    put_address(&mut v, &d.address);
    v.push(d.return_code);
    v.push(d.return_subcode);
    let mut subs = Vec::new();
    if !d.labels.is_empty() {
        let mut ls = Vec::new();
        for l in d.labels.iter().take(MAX_LABELS) {
            let w = ((l.label & 0xf_ffff) << 12)
                | (u32::from(l.tc & 0x7) << 9)
                | (u32::from(l.bottom) << 8)
                | u32::from(l.protocol);
            ls.extend_from_slice(&w.to_be_bytes());
        }
        put_tlv(&mut subs, DDMAP_SUB_LABEL_STACK, &ls);
    }
    for (kind, value) in &d.other {
        put_tlv(&mut subs, *kind, value);
    }
    let len = u16::try_from(subs.len()).unwrap_or(u16::MAX);
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&subs);
    v
}

/// One label stack entry (RFC 3032 §2.1).
pub fn label_word(l: &MplsLabel) -> u32 {
    ((l.label & 0xf_ffff) << 12)
        | (u32::from(l.tc & 0x7) << 9)
        | (u32::from(l.bottom) << 8)
        | u32::from(l.ttl)
}

/// Write a message.
pub fn encode(e: &Echo) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&e.flags.to_be_bytes());
    out.extend_from_slice(&[e.msg_type, e.reply_mode, e.return_code, e.return_subcode]);
    for w in [
        e.handle, e.seq, e.sent.0, e.sent.1, e.received.0, e.received.1,
    ] {
        out.extend_from_slice(&w.to_be_bytes());
    }
    if let Some(fecs) = &e.fec_stack {
        put_tlv(&mut out, TLV_FEC_STACK, &fec_value(fecs));
    }
    for d in &e.ddmaps {
        put_tlv(&mut out, TLV_DDMAP, &ddmap_value(d));
    }
    if let Some(i) = &e.if_label_stack {
        let mut v = vec![i.address.kind(), 0, 0, 0];
        put_address(&mut v, &i.address);
        for l in i.stack.iter().take(MAX_LABELS) {
            v.extend_from_slice(&label_word(l).to_be_bytes());
        }
        put_tlv(&mut out, TLV_IF_LABEL_STACK, &v);
    }
    if let Some(t) = e.reply_tos {
        put_tlv(&mut out, TLV_REPLY_TOS, &[t, 0, 0, 0]);
    }
    if let Some(v) = e.vendor {
        put_tlv(&mut out, TLV_VENDOR, &v.to_be_bytes());
    }
    if let Some(errored) = &e.errored {
        put_tlv(&mut out, TLV_ERRORED, errored);
    }
    if let Some(pad) = &e.pad {
        put_tlv(&mut out, TLV_PAD, pad);
    }
    out
}

/// What a return code means (RFC 8029 §3.1), with the stack depth.
pub fn describe(code: u8, subcode: u8) -> String {
    let depth = |s: &str| format!("{s} at stack-depth {subcode}");
    match code {
        code::NONE => "no return code".into(),
        code::MALFORMED => "malformed echo request received".into(),
        code::TLV_NOT_UNDERSTOOD => "one or more of the TLVs was not understood".into(),
        code::EGRESS => depth("replying router is an egress for the FEC"),
        code::NO_MAPPING => depth("replying router has no mapping for the FEC"),
        code::DS_MISMATCH => "downstream mapping mismatch (interface or label)".into(),
        code::UPSTREAM_IF_UNKNOWN => "upstream interface index unknown".into(),
        code::LABEL_SWITCHED => depth("label switched"),
        code::SWITCHED_NO_MPLS => depth("label switched but no MPLS forwarding"),
        code::WRONG_LABEL => depth("mapping for this FEC is not the given label"),
        code::NO_LABEL_ENTRY => depth("no label entry"),
        code::PROTOCOL_NOT_ON_IF => depth("protocol not associated with interface"),
        code::PREMATURE => "premature termination: label stack shrank to a single label".into(),
        code::SEE_DDMAP => "see the downstream mappings for the return codes".into(),
        code::FEC_CHANGE => "label switched with FEC change".into(),
        c => format!("unknown return code {c}"),
    }
}

/// The one-letter code Cisco and Junos print per reply (`!` egress, `L`
/// labeled switch, `.` timeout…), so operators read it at a glance.
pub fn letter(code: u8) -> char {
    match code {
        code::EGRESS => '!',
        code::NO_MAPPING => 'F',
        code::DS_MISMATCH => 'D',
        code::UPSTREAM_IF_UNKNOWN => 'I',
        code::LABEL_SWITCHED => 'L',
        code::SWITCHED_NO_MPLS => 'B',
        code::WRONG_LABEL => 'f',
        code::NO_LABEL_ENTRY => 'N',
        code::PROTOCOL_NOT_ON_IF => 'P',
        code::PREMATURE => 'p',
        code::MALFORMED => 'M',
        code::TLV_NOT_UNDERSTOOD => 'm',
        code::SEE_DDMAP => 'R',
        code::FEC_CHANGE => 'l',
        _ => 'X',
    }
}

/// Seconds between 1900 (NTP) and 1970 (Unix).
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// A Unix time (seconds, nanoseconds) as an NTP timestamp.
pub fn ntp(unix_secs: u64, nanos: u32) -> (u32, u32) {
    let secs = unix_secs.saturating_add(NTP_UNIX_OFFSET) as u32;
    let frac = ((u64::from(nanos) << 32) / 1_000_000_000) as u32;
    (secs, frac)
}

#[cfg(test)]
mod tests;

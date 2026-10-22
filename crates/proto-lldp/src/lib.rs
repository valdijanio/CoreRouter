//! L2 — LLDP (IEEE 802.1AB) LLDPDU codec. Pure: no sockets, no clock.
//!
//! Written from IEEE Std 802.1AB-2016 ("Station and Media Access Control
//! Connectivity Discovery"), clause 8 (LLDPDU and TLV formats) and 9.2.7.7
//! (receive validation). The Ethernet framing (EtherType [`ETHERTYPE`] to
//! [`MULTICAST_NEAREST_BRIDGE`]) and the sockets live in `hal-linux`; the
//! daemon glues the two (layers: this crate is L2, `hal-linux` L1).
//!
//! An LLDPDU is a sequence of TLVs, each with a 16-bit header (7-bit type,
//! 9-bit length) and the value. Mandatory, in this order: Chassis ID, Port
//! ID, Time To Live; then optional TLVs; then End Of LLDPDU (optional since
//! 802.1AB-2009, so a PDU that just stops at a TLV boundary is accepted).
//!
//! Decoding is hostile-input safe: lengths are checked before every read,
//! the input is capped at [`MAX_LLDPDU_LEN`], text is decoded lossily and
//! cut at the standard's limits, and unknown or organizationally specific
//! TLVs are kept as raw bytes (never an error). Decoding a decoded PDU's
//! encoding gives the same PDU back (tested with proptest).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// EtherType of LLDP frames.
pub const ETHERTYPE: u16 = 0x88CC;
/// Nearest-bridge group address: frames to it are never forwarded by
/// 802.1D bridges, so LLDP only ever reaches the directly attached station.
pub const MULTICAST_NEAREST_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];
/// msgTxInterval default (802.1AB 9.2.5.7): one LLDPDU every 30 s.
pub const TX_INTERVAL_SECS: u16 = 30;
/// msgTxHold default (9.2.5.6): TTL = interval × 4 = 120 s.
pub const TTL_SECS: u16 = TX_INTERVAL_SECS * 4;
/// Largest LLDPDU we encode: it must fit an untagged 1500-byte payload.
pub const MAX_ENCODED_LEN: usize = 1500;
/// Largest input we decode (jumbo frame); anything bigger is refused unread.
pub const MAX_LLDPDU_LEN: usize = 9216;
/// Max length of every text TLV (Port/System Description, System Name).
pub const MAX_TEXT_LEN: usize = 255;
/// Max length of a Chassis ID / Port ID value (after the subtype octet).
pub const MAX_ID_LEN: usize = 255;
/// Max length of a Management Address OID.
pub const MAX_OID_LEN: usize = 128;
/// Max length of a management address (after the family octet).
pub const MAX_MGMT_ADDR_LEN: usize = 31;
/// Max length of an organizationally specific information string.
pub const MAX_ORG_INFO_LEN: usize = 507;
/// Max value length of any TLV (9-bit length field).
const MAX_TLV_LEN: usize = 511;

const T_END: u8 = 0;
const T_CHASSIS: u8 = 1;
const T_PORT: u8 = 2;
const T_TTL: u8 = 3;
const T_PORT_DESC: u8 = 4;
const T_SYS_NAME: u8 = 5;
const T_SYS_DESC: u8 = 6;
const T_CAPS: u8 = 7;
const T_MGMT: u8 = 8;
const T_ORG: u8 = 127;

/// IANA address family numbers used by the ID and management address TLVs.
const AF_IPV4: u8 = 1;
const AF_IPV6: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("LLDPDU of {0} bytes exceeds the {MAX_LLDPDU_LEN}-byte limit")]
    TooLong(usize),
    #[error("TLV header at offset {0} is truncated")]
    TruncatedHeader(usize),
    #[error("TLV type {tlv_type} at offset {offset} claims {len} bytes, only {left} left")]
    TruncatedValue {
        tlv_type: u8,
        offset: usize,
        len: usize,
        left: usize,
    },
    #[error("expected {expected} TLV at offset {offset}, found type {found}")]
    OutOfOrder {
        expected: &'static str,
        offset: usize,
        found: u8,
    },
    #[error("missing mandatory {0} TLV")]
    Missing(&'static str),
    #[error("duplicate {0} TLV")]
    Duplicate(&'static str),
    #[error("malformed {tlv}: {why}")]
    Malformed {
        tlv: &'static str,
        why: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("{field} is {len} bytes, the limit is {max}")]
    TooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("the LLDPDU would be {0} bytes, more than {MAX_ENCODED_LEN}")]
    PduTooLong(usize),
    #[error("TLV type {0} is reserved for a typed field; use that field")]
    ReservedType(u8),
}

/// Chassis ID (TLV 1). Known subtypes with a well-formed value get a typed
/// variant; everything else stays `Other`, byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChassisId {
    /// Subtype 4.
    Mac([u8; 6]),
    /// Subtype 5 (IPv4 or IPv6).
    NetworkAddress(IpAddr),
    /// Subtype 6.
    InterfaceName(String),
    /// Subtype 7.
    Local(String),
    Other {
        subtype: u8,
        value: Vec<u8>,
    },
}

/// Port ID (TLV 2), same idea as [`ChassisId`] (subtype numbers differ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortId {
    /// Subtype 1.
    InterfaceAlias(String),
    /// Subtype 3.
    Mac([u8; 6]),
    /// Subtype 4.
    NetworkAddress(IpAddr),
    /// Subtype 5.
    InterfaceName(String),
    /// Subtype 7.
    Local(String),
    Other {
        subtype: u8,
        value: Vec<u8>,
    },
}

/// System Capabilities (TLV 7): what the system can do and what is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    pub system: u16,
    pub enabled: u16,
}

impl Capabilities {
    pub const OTHER: u16 = 1 << 0;
    pub const REPEATER: u16 = 1 << 1;
    pub const BRIDGE: u16 = 1 << 2;
    pub const WLAN_AP: u16 = 1 << 3;
    pub const ROUTER: u16 = 1 << 4;
    pub const TELEPHONE: u16 = 1 << 5;
    pub const DOCSIS: u16 = 1 << 6;
    pub const STATION: u16 = 1 << 7;
    pub const C_VLAN: u16 = 1 << 8;
    pub const S_VLAN: u16 = 1 << 9;
    pub const TPMR: u16 = 1 << 10;

    const NAMES: [(u16, &'static str); 11] = [
        (Self::OTHER, "other"),
        (Self::REPEATER, "repeater"),
        (Self::BRIDGE, "bridge"),
        (Self::WLAN_AP, "wlan-ap"),
        (Self::ROUTER, "router"),
        (Self::TELEPHONE, "telephone"),
        (Self::DOCSIS, "docsis"),
        (Self::STATION, "station"),
        (Self::C_VLAN, "c-vlan"),
        (Self::S_VLAN, "s-vlan"),
        (Self::TPMR, "tpmr"),
    ];

    /// Names of the bits set in `bits`, in bit order (unknown bits skipped).
    pub fn names(bits: u16) -> Vec<&'static str> {
        Self::NAMES
            .iter()
            .filter(|(b, _)| bits & b != 0)
            .map(|(_, n)| *n)
            .collect()
    }
}

/// Address in a Management Address TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MgmtAddr {
    Ip(IpAddr),
    /// Any other IANA family (e.g. 6 = 802 MAC), 1..=31 bytes.
    Other {
        family: u8,
        value: Vec<u8>,
    },
}

/// Management Address (TLV 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementAddress {
    pub address: MgmtAddr,
    /// 1 = unknown, 2 = ifIndex, 3 = system port number.
    pub if_subtype: u8,
    pub if_number: u32,
    /// ASN.1 BER OID of the hardware component, up to 128 bytes; usually empty.
    pub oid: Vec<u8>,
}

impl ManagementAddress {
    /// An IP management address with an ifIndex, no OID.
    pub fn ip(ip: IpAddr, if_index: u32) -> Self {
        Self {
            address: MgmtAddr::Ip(ip),
            if_subtype: 2,
            if_number: if_index,
            oid: Vec::new(),
        }
    }
}

/// Organizationally Specific TLV (127): kept raw, never interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgTlv {
    pub oui: [u8; 3],
    pub subtype: u8,
    pub info: Vec<u8>,
}

/// A TLV of a type this codec does not know (9..=126), kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTlv {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

/// One LLDPDU, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldpdu {
    pub chassis_id: ChassisId,
    pub port_id: PortId,
    /// Seconds the receiver keeps this information; 0 = "forget me now"
    /// (shutdown LLDPDU).
    pub ttl_secs: u16,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub capabilities: Option<Capabilities>,
    pub management_addresses: Vec<ManagementAddress>,
    pub org_specific: Vec<OrgTlv>,
    pub unknown: Vec<UnknownTlv>,
}

impl Lldpdu {
    /// A PDU with only the mandatory TLVs.
    pub fn new(chassis_id: ChassisId, port_id: PortId, ttl_secs: u16) -> Self {
        Self {
            chassis_id,
            port_id,
            ttl_secs,
            port_description: None,
            system_name: None,
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            org_specific: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// True for a shutdown LLDPDU (TTL 0): drop this neighbor now.
    pub fn is_shutdown(&self) -> bool {
        self.ttl_secs == 0
    }
}

// ---------------------------------------------------------------- display

/// `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(m: &[u8; 6]) -> String {
    let [a, b, c, d, e, f] = *m;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// Printable text as is; anything else as hex.
fn fmt_raw(f: &mut fmt::Formatter<'_>, v: &[u8]) -> fmt::Result {
    match std::str::from_utf8(v) {
        Ok(s) if !s.is_empty() && !s.chars().any(char::is_control) => f.write_str(s),
        _ => v.iter().try_for_each(|b| write!(f, "{b:02x}")),
    }
}

impl fmt::Display for ChassisId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mac(m) => f.write_str(&format_mac(m)),
            Self::NetworkAddress(ip) => write!(f, "{ip}"),
            Self::InterfaceName(s) | Self::Local(s) => f.write_str(s),
            Self::Other { value, .. } => fmt_raw(f, value),
        }
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mac(m) => f.write_str(&format_mac(m)),
            Self::NetworkAddress(ip) => write!(f, "{ip}"),
            Self::InterfaceAlias(s) | Self::InterfaceName(s) | Self::Local(s) => f.write_str(s),
            Self::Other { value, .. } => fmt_raw(f, value),
        }
    }
}

// ---------------------------------------------------------------- decode

/// Bytes consumed front to back; every read is bounds-checked.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }
    fn u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }
}

/// Lossy UTF-8, cut to `max` bytes on a char boundary (so re-encoding the
/// decoded text always fits).
fn text(v: &[u8], max: usize) -> String {
    let mut s = String::from_utf8_lossy(v).into_owned();
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        s.truncate(end);
    }
    s
}

/// Strict UTF-8 (for ID subtypes, so a non-UTF-8 value stays `Other`).
fn utf8(v: &[u8]) -> Option<String> {
    std::str::from_utf8(v).ok().map(str::to_owned)
}

/// Network address value: IANA family octet + address.
fn net_addr(v: &[u8]) -> Option<IpAddr> {
    let (&family, addr) = v.split_first()?;
    match family {
        AF_IPV4 => <[u8; 4]>::try_from(addr)
            .ok()
            .map(|a| Ipv4Addr::from(a).into()),
        AF_IPV6 => <[u8; 16]>::try_from(addr)
            .ok()
            .map(|a| Ipv6Addr::from(a).into()),
        _ => None,
    }
}

fn id_parts(tlv: &'static str, v: &[u8]) -> Result<(u8, Vec<u8>), DecodeError> {
    let (&subtype, value) = v.split_first().ok_or(DecodeError::Malformed {
        tlv,
        why: "empty (no subtype)",
    })?;
    if value.is_empty() {
        return Err(DecodeError::Malformed {
            tlv,
            why: "empty ID value",
        });
    }
    if value.len() > MAX_ID_LEN {
        return Err(DecodeError::Malformed {
            tlv,
            why: "ID value longer than 255 bytes",
        });
    }
    Ok((subtype, value.to_vec()))
}

fn chassis_id(v: &[u8]) -> Result<ChassisId, DecodeError> {
    let (subtype, value) = id_parts("Chassis ID", v)?;
    let typed = match subtype {
        4 => <[u8; 6]>::try_from(value.as_slice())
            .ok()
            .map(ChassisId::Mac),
        5 => net_addr(&value).map(ChassisId::NetworkAddress),
        6 => utf8(&value).map(ChassisId::InterfaceName),
        7 => utf8(&value).map(ChassisId::Local),
        _ => None,
    };
    Ok(typed.unwrap_or(ChassisId::Other { subtype, value }))
}

fn port_id(v: &[u8]) -> Result<PortId, DecodeError> {
    let (subtype, value) = id_parts("Port ID", v)?;
    let typed = match subtype {
        1 => utf8(&value).map(PortId::InterfaceAlias),
        3 => <[u8; 6]>::try_from(value.as_slice()).ok().map(PortId::Mac),
        4 => net_addr(&value).map(PortId::NetworkAddress),
        5 => utf8(&value).map(PortId::InterfaceName),
        7 => utf8(&value).map(PortId::Local),
        _ => None,
    };
    Ok(typed.unwrap_or(PortId::Other { subtype, value }))
}

fn mgmt(v: &[u8]) -> Result<ManagementAddress, DecodeError> {
    let bad = |why| DecodeError::Malformed {
        tlv: "Management Address",
        why,
    };
    let mut r = Reader(v);
    let str_len = usize::from(r.u8().ok_or(bad("truncated"))?);
    if !(2..=MAX_MGMT_ADDR_LEN + 1).contains(&str_len) {
        return Err(bad("address string length out of 2..=32"));
    }
    let addr = r.take(str_len).ok_or(bad("truncated address"))?;
    let (&family, value) = addr.split_first().ok_or(bad("truncated address"))?;
    let address = net_addr(addr).map(MgmtAddr::Ip).unwrap_or(MgmtAddr::Other {
        family,
        value: value.to_vec(),
    });
    let if_subtype = r.u8().ok_or(bad("truncated interface subtype"))?;
    let if_number = r.u32().ok_or(bad("truncated interface number"))?;
    let oid_len = usize::from(r.u8().ok_or(bad("truncated OID length"))?);
    if oid_len > MAX_OID_LEN {
        return Err(bad("OID longer than 128 bytes"));
    }
    let oid = r.take(oid_len).ok_or(bad("truncated OID"))?.to_vec();
    Ok(ManagementAddress {
        address,
        if_subtype,
        if_number,
        oid,
    })
}

/// Decode one LLDPDU (the Ethernet payload, without the 14-byte header).
pub fn decode(buf: &[u8]) -> Result<Lldpdu, DecodeError> {
    if buf.len() > MAX_LLDPDU_LEN {
        return Err(DecodeError::TooLong(buf.len()));
    }
    let mut r = Reader(buf);
    let mut chassis = None;
    let mut port = None;
    let mut ttl = None;
    let mut du_opt = Optional::default();
    let mut index = 0usize;
    loop {
        let offset = buf.len().saturating_sub(r.0.len());
        if r.0.is_empty() {
            break; // no End TLV: allowed since 802.1AB-2009
        }
        let header = r.u16().ok_or(DecodeError::TruncatedHeader(offset))?;
        let tlv_type = u8::try_from(header >> 9).unwrap_or(u8::MAX);
        let len = usize::from(header & 0x01FF);
        let left = r.0.len();
        let value = r.take(len).ok_or(DecodeError::TruncatedValue {
            tlv_type,
            offset,
            len,
            left,
        })?;
        // The first three TLVs are fixed (9.2.7.7.1).
        let expected = match index {
            0 => Some((T_CHASSIS, "Chassis ID")),
            1 => Some((T_PORT, "Port ID")),
            2 => Some((T_TTL, "Time To Live")),
            _ => None,
        };
        index = index.saturating_add(1);
        if let Some((want, name)) = expected
            && tlv_type != want
        {
            return Err(DecodeError::OutOfOrder {
                expected: name,
                offset,
                found: tlv_type,
            });
        }
        match tlv_type {
            T_END => {
                if len != 0 {
                    return Err(DecodeError::Malformed {
                        tlv: "End Of LLDPDU",
                        why: "non-zero length",
                    });
                }
                break; // anything after End is padding
            }
            T_CHASSIS if chassis.is_none() => chassis = Some(chassis_id(value)?),
            T_PORT if port.is_none() => port = Some(port_id(value)?),
            T_TTL if ttl.is_none() => {
                // Longer than 2 is tolerated: only the first two octets count.
                let mut v = Reader(value);
                ttl = Some(v.u16().ok_or(DecodeError::Malformed {
                    tlv: "Time To Live",
                    why: "shorter than 2 bytes",
                })?);
            }
            T_CHASSIS => return Err(DecodeError::Duplicate("Chassis ID")),
            T_PORT => return Err(DecodeError::Duplicate("Port ID")),
            T_TTL => return Err(DecodeError::Duplicate("Time To Live")),
            _ => du_opt.add(tlv_type, value)?,
        }
    }
    Ok(Lldpdu {
        chassis_id: chassis.ok_or(DecodeError::Missing("Chassis ID"))?,
        port_id: port.ok_or(DecodeError::Missing("Port ID"))?,
        ttl_secs: ttl.ok_or(DecodeError::Missing("Time To Live"))?,
        port_description: du_opt.port_description,
        system_name: du_opt.system_name,
        system_description: du_opt.system_description,
        capabilities: du_opt.capabilities,
        management_addresses: du_opt.management_addresses,
        org_specific: du_opt.org_specific,
        unknown: du_opt.unknown,
    })
}

/// The optional part, filled while decoding. A repeated single-instance TLV
/// (descriptions, name, capabilities) keeps the first one (9.2.7.7.4).
#[derive(Default)]
struct Optional {
    port_description: Option<String>,
    system_name: Option<String>,
    system_description: Option<String>,
    capabilities: Option<Capabilities>,
    management_addresses: Vec<ManagementAddress>,
    org_specific: Vec<OrgTlv>,
    unknown: Vec<UnknownTlv>,
}

impl Optional {
    fn add(&mut self, tlv_type: u8, value: &[u8]) -> Result<(), DecodeError> {
        let first_text = |slot: &mut Option<String>| {
            slot.get_or_insert_with(|| text(value, MAX_TEXT_LEN));
        };
        match tlv_type {
            T_PORT_DESC => first_text(&mut self.port_description),
            T_SYS_NAME => first_text(&mut self.system_name),
            T_SYS_DESC => first_text(&mut self.system_description),
            T_CAPS => {
                let mut r = Reader(value);
                let caps = r
                    .u16()
                    .zip(r.u16())
                    .filter(|_| r.0.is_empty())
                    .map(|(system, enabled)| Capabilities { system, enabled })
                    .ok_or(DecodeError::Malformed {
                        tlv: "System Capabilities",
                        why: "length is not 4",
                    })?;
                self.capabilities.get_or_insert(caps);
            }
            T_MGMT => self.management_addresses.push(mgmt(value)?),
            T_ORG => {
                let mut r = Reader(value);
                let oui: [u8; 3] =
                    r.take(3)
                        .and_then(|o| o.try_into().ok())
                        .ok_or(DecodeError::Malformed {
                            tlv: "Organizationally Specific",
                            why: "shorter than 4 bytes",
                        })?;
                let subtype = r.u8().ok_or(DecodeError::Malformed {
                    tlv: "Organizationally Specific",
                    why: "shorter than 4 bytes",
                })?;
                self.org_specific.push(OrgTlv {
                    oui,
                    subtype,
                    info: r.0.to_vec(),
                });
            }
            _ => self.unknown.push(UnknownTlv {
                tlv_type,
                value: value.to_vec(),
            }),
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- encode

struct Writer(Vec<u8>);

impl Writer {
    fn tlv(&mut self, tlv_type: u8, value: &[u8]) -> Result<(), EncodeError> {
        if value.len() > MAX_TLV_LEN {
            return Err(EncodeError::TooLong {
                field: "TLV value",
                len: value.len(),
                max: MAX_TLV_LEN,
            });
        }
        // len ≤ 511 (checked above) and type ≤ 127: both fit their bits.
        let len = u16::try_from(value.len()).unwrap_or(0) & 0x01FF;
        let header = (u16::from(tlv_type & 0x7F) << 9) | len;
        self.0.extend_from_slice(&header.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }
}

fn check_len(field: &'static str, len: usize, max: usize) -> Result<(), EncodeError> {
    if len > max {
        Err(EncodeError::TooLong { field, len, max })
    } else {
        Ok(())
    }
}

fn net_addr_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => [&[AF_IPV4][..], &a.octets()].concat(),
        IpAddr::V6(a) => [&[AF_IPV6][..], &a.octets()].concat(),
    }
}

fn id_bytes(field: &'static str, subtype: u8, value: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if value.is_empty() {
        return Err(EncodeError::Empty { field });
    }
    check_len(field, value.len(), MAX_ID_LEN)?;
    Ok([&[subtype][..], value].concat())
}

fn chassis_bytes(c: &ChassisId) -> Result<Vec<u8>, EncodeError> {
    const F: &str = "Chassis ID";
    match c {
        ChassisId::Mac(m) => id_bytes(F, 4, m),
        ChassisId::NetworkAddress(ip) => id_bytes(F, 5, &net_addr_bytes(ip)),
        ChassisId::InterfaceName(s) => id_bytes(F, 6, s.as_bytes()),
        ChassisId::Local(s) => id_bytes(F, 7, s.as_bytes()),
        ChassisId::Other { subtype, value } => id_bytes(F, *subtype, value),
    }
}

fn port_bytes(p: &PortId) -> Result<Vec<u8>, EncodeError> {
    const F: &str = "Port ID";
    match p {
        PortId::InterfaceAlias(s) => id_bytes(F, 1, s.as_bytes()),
        PortId::Mac(m) => id_bytes(F, 3, m),
        PortId::NetworkAddress(ip) => id_bytes(F, 4, &net_addr_bytes(ip)),
        PortId::InterfaceName(s) => id_bytes(F, 5, s.as_bytes()),
        PortId::Local(s) => id_bytes(F, 7, s.as_bytes()),
        PortId::Other { subtype, value } => id_bytes(F, *subtype, value),
    }
}

fn mgmt_bytes(m: &ManagementAddress) -> Result<Vec<u8>, EncodeError> {
    let addr = match &m.address {
        MgmtAddr::Ip(ip) => net_addr_bytes(ip),
        MgmtAddr::Other { family, value } => {
            if value.is_empty() {
                return Err(EncodeError::Empty {
                    field: "management address",
                });
            }
            check_len("management address", value.len(), MAX_MGMT_ADDR_LEN)?;
            [&[*family][..], value].concat()
        }
    };
    check_len("management OID", m.oid.len(), MAX_OID_LEN)?;
    let mut v = Vec::with_capacity(addr.len().saturating_add(m.oid.len()).saturating_add(7));
    // Both lengths were bounded above (≤ 32 and ≤ 128).
    v.push(u8::try_from(addr.len()).unwrap_or(u8::MAX));
    v.extend_from_slice(&addr);
    v.push(m.if_subtype);
    v.extend_from_slice(&m.if_number.to_be_bytes());
    v.push(u8::try_from(m.oid.len()).unwrap_or(u8::MAX));
    v.extend_from_slice(&m.oid);
    Ok(v)
}

/// Encode an LLDPDU (Ethernet payload), mandatory TLVs first, End last.
pub fn encode(du: &Lldpdu) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer(Vec::with_capacity(128));
    w.tlv(T_CHASSIS, &chassis_bytes(&du.chassis_id)?)?;
    w.tlv(T_PORT, &port_bytes(&du.port_id)?)?;
    w.tlv(T_TTL, &du.ttl_secs.to_be_bytes())?;
    for (t, field, text) in [
        (T_PORT_DESC, "Port Description", &du.port_description),
        (T_SYS_NAME, "System Name", &du.system_name),
        (T_SYS_DESC, "System Description", &du.system_description),
    ] {
        if let Some(s) = text {
            check_len(field, s.len(), MAX_TEXT_LEN)?;
            w.tlv(t, s.as_bytes())?;
        }
    }
    if let Some(c) = du.capabilities {
        w.tlv(
            T_CAPS,
            &[c.system.to_be_bytes(), c.enabled.to_be_bytes()].concat(),
        )?;
    }
    for m in &du.management_addresses {
        w.tlv(T_MGMT, &mgmt_bytes(m)?)?;
    }
    for u in &du.unknown {
        if u.tlv_type <= T_MGMT || u.tlv_type >= T_ORG {
            return Err(EncodeError::ReservedType(u.tlv_type));
        }
        w.tlv(u.tlv_type, &u.value)?;
    }
    for o in &du.org_specific {
        check_len(
            "organizationally specific info",
            o.info.len(),
            MAX_ORG_INFO_LEN,
        )?;
        let v = [&o.oui[..], &[o.subtype], &o.info].concat();
        w.tlv(T_ORG, &v)?;
    }
    w.tlv(T_END, &[])?;
    if w.0.len() > MAX_ENCODED_LEN {
        return Err(EncodeError::PduTooLong(w.0.len()));
    }
    Ok(w.0)
}

#[cfg(test)]
mod tests;

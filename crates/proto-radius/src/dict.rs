//! Typed attribute dictionary.
//!
//! [`Dictionary::builtin`] ships the attributes a BNG meets: RFC 2865,
//! 2866, 2868, 2869, 3162, 4372, 4675, 4818, 5176, 5580, 6911 and 6929;
//! Microsoft (311, RFC 2548); DSL Forum (3561, RFC 4679); MikroTik (14988);
//! Juniper/ERX (4874, service activation, parse only); Ascend (529) and
//! Redback (2352) rate and circuit attributes that MikroTik also reads.
//! More can be loaded at run time from FreeRADIUS-format text
//! ([`Dictionary::load`]), the format every RADIUS server ships.
//!
//! Data types follow RFC 8044. A value that does not fit its type is an
//! "invalid attribute" (RFC 6929 §2.8) and decodes as [`Value::Invalid`].

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// Vendor ids (IANA "SMI Network Management Private Enterprise Codes").
pub mod vendor {
    pub const ASCEND: u32 = 529;
    pub const MICROSOFT: u32 = 311;
    pub const REDBACK: u32 = 2352;
    pub const DSL_FORUM: u32 = 3561;
    pub const ERX: u32 = 4874;
    pub const MIKROTIK: u32 = 14988;
}

/// MikroTik vendor types (MikroTik's "RADIUS" manual, numeric table).
pub mod mikrotik {
    pub const RECV_LIMIT: u8 = 1;
    pub const XMIT_LIMIT: u8 = 2;
    pub const GROUP: u8 = 3;
    pub const RATE_LIMIT: u8 = 8;
    pub const REALM: u8 = 9;
    pub const HOST_IP: u8 = 10;
    pub const MARK_ID: u8 = 11;
    pub const RECV_LIMIT_GIGAWORDS: u8 = 14;
    pub const XMIT_LIMIT_GIGAWORDS: u8 = 15;
    pub const TOTAL_LIMIT: u8 = 17;
    pub const TOTAL_LIMIT_GIGAWORDS: u8 = 18;
    pub const ADDRESS_LIST: u8 = 19;
    pub const DELEGATED_IPV6_POOL: u8 = 22;
}

/// RFC 4679 §3 (DSL Forum, vendor 3561) vendor types.
pub mod dsl_forum {
    pub const AGENT_CIRCUIT_ID: u8 = 1;
    pub const AGENT_REMOTE_ID: u8 = 2;
    pub const ACTUAL_DATA_RATE_UPSTREAM: u8 = 129;
    pub const ACTUAL_DATA_RATE_DOWNSTREAM: u8 = 130;
    pub const ACCESS_LOOP_ENCAPSULATION: u8 = 144;
    pub const IWF_SESSION: u8 = 254;
}

/// Where an attribute's key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AttrId {
    /// Top-level type 1–255.
    Std(u8),
    /// Vendor-Specific sub-attribute (RFC 2865 §5.26).
    Vendor(u32, u8),
    /// RFC 6929 extended (241–246) with its Extended-Type.
    Ext(u8, u8),
}

/// RFC 8044 data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Text,
    String,
    Integer,
    Integer64,
    Ipv4Addr,
    Ipv6Addr,
    Ipv6Prefix,
    Ipv4Prefix,
    Ifid,
    Time,
    /// Containers decoded by the packet layer (26, 241–246) or TLV bags.
    Opaque,
}

/// How the value is hidden on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    /// RFC 2865 §5.2.
    UserPassword,
    /// RFC 2868 §3.5 / RFC 2548 §2.4.2 (salt).
    Salted,
}

/// RFC 5176 §3: the role of an attribute in CoA and Disconnect-Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynAuthRole {
    /// NAS identification (§3): NAS-IP-Address, NAS-Identifier,
    /// NAS-IPv6-Address.
    Nas,
    /// Session identification (§3).
    Session,
    /// Authorization change (Notes 3 and 5, CoA only).
    Authorization,
    /// Protocol bookkeeping (Proxy-State, State, Event-Timestamp,
    /// Message-Authenticator, Reply-Message, Error-Cause, Service-Type…).
    Control,
    /// Not meaningful in CoA/DM.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrDef {
    pub name: Cow<'static, str>,
    pub id: AttrId,
    pub data: DataType,
    /// RFC 2868 §3.1: the first octet may be a tag (0x01–0x1F).
    pub tagged: bool,
    pub encrypt: Encryption,
    pub dynauth: DynAuthRole,
}

/// A decoded value, borrowing the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    Text(&'a str),
    Octets(&'a [u8]),
    Integer(u32),
    Integer64(u64),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6Prefix(Ipv6Addr, u8),
    Ipv4Prefix(Ipv4Addr, u8),
    Ifid([u8; 8]),
    /// Seconds since 1970 (RFC 8044 §3.2).
    Time(u32),
    /// RFC 6929 §2.8: the value does not fit the type.
    Invalid(&'a [u8]),
}

/// One attribute decoded through the dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<'a, 'd> {
    pub id: AttrId,
    pub def: Option<&'d AttrDef>,
    /// RFC 2868 §3.1 tag, when the attribute is tagged and has one.
    pub tag: Option<u8>,
    pub value: Value<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DictError {
    #[error("line {line}: {why}")]
    Syntax { line: usize, why: String },
    #[error("attribute {0} is already defined differently")]
    Conflict(String),
    #[error("dictionary text larger than 1 MiB")]
    TooLarge,
}

#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    defs: Vec<AttrDef>,
    by_id: HashMap<AttrId, usize>,
    by_name: HashMap<String, usize>,
    vendors: HashMap<u32, Cow<'static, str>>,
}

use DataType as D;
use DynAuthRole as R;
use Encryption as E;

/// (name, type, data, encryption, tagged, dynauth role)
type Row = (&'static str, u8, DataType, Encryption, bool, DynAuthRole);

const STANDARD: &[Row] = &[
    // RFC 2865 §5
    ("User-Name", 1, D::Text, E::None, false, R::Session),
    (
        "User-Password",
        2,
        D::String,
        E::UserPassword,
        false,
        R::None,
    ),
    ("CHAP-Password", 3, D::String, E::None, false, R::None),
    ("NAS-IP-Address", 4, D::Ipv4Addr, E::None, false, R::Nas),
    ("NAS-Port", 5, D::Integer, E::None, false, R::Session),
    ("Service-Type", 6, D::Integer, E::None, false, R::Control),
    (
        "Framed-Protocol",
        7,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-IP-Address",
        8,
        D::Ipv4Addr,
        E::None,
        false,
        R::Session,
    ),
    (
        "Framed-IP-Netmask",
        9,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-Routing",
        10,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    ("Filter-Id", 11, D::Text, E::None, false, R::Authorization),
    (
        "Framed-MTU",
        12,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-Compression",
        13,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-IP-Host",
        14,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-Service",
        15,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-TCP-Port",
        16,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    ("Reply-Message", 18, D::Text, E::None, false, R::Control),
    (
        "Callback-Number",
        19,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    ("Callback-Id", 20, D::Text, E::None, false, R::Authorization),
    (
        "Framed-Route",
        22,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-IPX-Network",
        23,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    ("State", 24, D::String, E::None, false, R::Control),
    ("Class", 25, D::String, E::None, false, R::Authorization),
    (
        "Vendor-Specific",
        26,
        D::Opaque,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Session-Timeout",
        27,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Idle-Timeout",
        28,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Termination-Action",
        29,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    ("Called-Station-Id", 30, D::Text, E::None, false, R::Session),
    (
        "Calling-Station-Id",
        31,
        D::Text,
        E::None,
        false,
        R::Session,
    ),
    ("NAS-Identifier", 32, D::Text, E::None, false, R::Nas),
    ("Proxy-State", 33, D::String, E::None, false, R::Control),
    (
        "Login-LAT-Service",
        34,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-LAT-Node",
        35,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-LAT-Group",
        36,
        D::String,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-AppleTalk-Link",
        37,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-AppleTalk-Network",
        38,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-AppleTalk-Zone",
        39,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 2866 §5
    ("Acct-Status-Type", 40, D::Integer, E::None, false, R::None),
    ("Acct-Delay-Time", 41, D::Integer, E::None, false, R::None),
    ("Acct-Input-Octets", 42, D::Integer, E::None, false, R::None),
    (
        "Acct-Output-Octets",
        43,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    ("Acct-Session-Id", 44, D::Text, E::None, false, R::Session),
    ("Acct-Authentic", 45, D::Integer, E::None, false, R::None),
    ("Acct-Session-Time", 46, D::Integer, E::None, false, R::None),
    (
        "Acct-Input-Packets",
        47,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        "Acct-Output-Packets",
        48,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        "Acct-Terminate-Cause",
        49,
        D::Integer,
        E::None,
        false,
        R::Control,
    ),
    (
        "Acct-Multi-Session-Id",
        50,
        D::Text,
        E::None,
        false,
        R::Session,
    ),
    ("Acct-Link-Count", 51, D::Integer, E::None, false, R::None),
    // RFC 2869 §5
    (
        "Acct-Input-Gigawords",
        52,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        "Acct-Output-Gigawords",
        53,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    ("Event-Timestamp", 55, D::Time, E::None, false, R::Control),
    // RFC 4675
    (
        "Egress-VLANID",
        56,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Ingress-Filters",
        57,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Egress-VLAN-Name",
        58,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "User-Priority-Table",
        59,
        D::String,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 2865 §5
    ("CHAP-Challenge", 60, D::String, E::None, false, R::None),
    ("NAS-Port-Type", 61, D::Integer, E::None, false, R::None),
    (
        "Port-Limit",
        62,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Login-LAT-Port",
        63,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 2868 §3
    (
        "Tunnel-Type",
        64,
        D::Integer,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Medium-Type",
        65,
        D::Integer,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Client-Endpoint",
        66,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Server-Endpoint",
        67,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Acct-Tunnel-Connection",
        68,
        D::Text,
        E::None,
        false,
        R::None,
    ),
    (
        "Tunnel-Password",
        69,
        D::String,
        E::Salted,
        true,
        R::Authorization,
    ),
    // RFC 2869 §5
    ("ARAP-Password", 70, D::String, E::None, false, R::None),
    (
        "ARAP-Features",
        71,
        D::String,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "ARAP-Zone-Access",
        72,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    ("ARAP-Security", 73, D::Integer, E::None, false, R::None),
    ("ARAP-Security-Data", 74, D::Text, E::None, false, R::None),
    ("Password-Retry", 75, D::Integer, E::None, false, R::None),
    ("Prompt", 76, D::Integer, E::None, false, R::None),
    ("Connect-Info", 77, D::Text, E::None, false, R::None),
    (
        "Configuration-Token",
        78,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    ("EAP-Message", 79, D::String, E::None, false, R::Control),
    (
        "Message-Authenticator",
        80,
        D::String,
        E::None,
        false,
        R::Control,
    ),
    (
        "Tunnel-Private-Group-ID",
        81,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Assignment-ID",
        82,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Preference",
        83,
        D::Integer,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "ARAP-Challenge-Response",
        84,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        "Acct-Interim-Interval",
        85,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Acct-Tunnel-Packets-Lost",
        86,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    ("NAS-Port-Id", 87, D::Text, E::None, false, R::Session),
    ("Framed-Pool", 88, D::Text, E::None, false, R::Authorization),
    // RFC 4372
    (
        "Chargeable-User-Identity",
        89,
        D::String,
        E::None,
        false,
        R::Session,
    ),
    // RFC 2868 §3
    (
        "Tunnel-Client-Auth-ID",
        90,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        "Tunnel-Server-Auth-ID",
        91,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    // RFC 4849
    (
        "NAS-Filter-Rule",
        92,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 7155
    (
        "Originating-Line-Info",
        94,
        D::String,
        E::None,
        false,
        R::None,
    ),
    // RFC 3162 §2
    ("NAS-IPv6-Address", 95, D::Ipv6Addr, E::None, false, R::Nas),
    (
        "Framed-Interface-Id",
        96,
        D::Ifid,
        E::None,
        false,
        R::Session,
    ),
    (
        "Framed-IPv6-Prefix",
        97,
        D::Ipv6Prefix,
        E::None,
        false,
        R::Session,
    ),
    (
        "Login-IPv6-Host",
        98,
        D::Ipv6Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-IPv6-Route",
        99,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Framed-IPv6-Pool",
        100,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 5176 §3.5
    ("Error-Cause", 101, D::Integer, E::None, false, R::Control),
    // RFC 4818
    (
        "Delegated-IPv6-Prefix",
        123,
        D::Ipv6Prefix,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 6911 §3
    (
        "Framed-IPv6-Address",
        168,
        D::Ipv6Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "DNS-Server-IPv6-Address",
        169,
        D::Ipv6Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Route-IPv6-Information",
        170,
        D::Ipv6Prefix,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Delegated-IPv6-Prefix-Pool",
        171,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        "Stateful-IPv6-Address-Pool",
        172,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 6929 §2 containers
    ("Extended-Type-1", 241, D::Opaque, E::None, false, R::None),
    ("Extended-Type-2", 242, D::Opaque, E::None, false, R::None),
    ("Extended-Type-3", 243, D::Opaque, E::None, false, R::None),
    ("Extended-Type-4", 244, D::Opaque, E::None, false, R::None),
    (
        "Long-Extended-Type-1",
        245,
        D::Opaque,
        E::None,
        false,
        R::None,
    ),
    (
        "Long-Extended-Type-2",
        246,
        D::Opaque,
        E::None,
        false,
        R::None,
    ),
];

/// (vendor, name, type, data, encryption, tagged, dynauth role)
type VRow = (
    u32,
    &'static str,
    u8,
    DataType,
    Encryption,
    bool,
    DynAuthRole,
);

const VENDORS: &[VRow] = &[
    // RFC 2548 §2 (Microsoft)
    (
        311,
        "MS-CHAP-Response",
        1,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (311, "MS-CHAP-Error", 2, D::String, E::None, false, R::None),
    (311, "MS-CHAP-CPW-1", 3, D::String, E::None, false, R::None),
    (311, "MS-CHAP-CPW-2", 4, D::String, E::None, false, R::None),
    (
        311,
        "MS-CHAP-LM-Enc-PW",
        5,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-CHAP-NT-Enc-PW",
        6,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-MPPE-Encryption-Policy",
        7,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        311,
        "MS-MPPE-Encryption-Types",
        8,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (311, "MS-RAS-Vendor", 9, D::Integer, E::None, false, R::None),
    (311, "MS-CHAP-Domain", 10, D::Text, E::None, false, R::None),
    (
        311,
        "MS-CHAP-Challenge",
        11,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-CHAP-MPPE-Keys",
        12,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (311, "MS-BAP-Usage", 13, D::Integer, E::None, false, R::None),
    (
        311,
        "MS-Link-Utilization-Threshold",
        14,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-Link-Drop-Time-Limit",
        15,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-MPPE-Send-Key",
        16,
        D::String,
        E::Salted,
        false,
        R::None,
    ),
    (
        311,
        "MS-MPPE-Recv-Key",
        17,
        D::String,
        E::Salted,
        false,
        R::None,
    ),
    (311, "MS-RAS-Version", 18, D::Text, E::None, false, R::None),
    (
        311,
        "MS-Old-ARAP-Password",
        19,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-New-ARAP-Password",
        20,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-ARAP-PW-Change-Reason",
        21,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-Filter",
        22,
        D::String,
        E::None,
        false,
        R::Authorization,
    ),
    (
        311,
        "MS-Acct-Auth-Type",
        23,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-Acct-EAP-Type",
        24,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-CHAP2-Response",
        25,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (
        311,
        "MS-CHAP2-Success",
        26,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (311, "MS-CHAP2-CPW", 27, D::String, E::None, false, R::None),
    (
        311,
        "MS-Primary-DNS-Server",
        28,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        311,
        "MS-Secondary-DNS-Server",
        29,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        311,
        "MS-Primary-NBNS-Server",
        30,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        311,
        "MS-Secondary-NBNS-Server",
        31,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    // RFC 4679 §3 (DSL Forum)
    (
        3561,
        "ADSL-Agent-Circuit-Id",
        1,
        D::Text,
        E::None,
        false,
        R::Session,
    ),
    (
        3561,
        "ADSL-Agent-Remote-Id",
        2,
        D::Text,
        E::None,
        false,
        R::Session,
    ),
    (
        3561,
        "Actual-Data-Rate-Upstream",
        129,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Actual-Data-Rate-Downstream",
        130,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Minimum-Data-Rate-Upstream",
        131,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Minimum-Data-Rate-Downstream",
        132,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Attainable-Data-Rate-Upstream",
        133,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Attainable-Data-Rate-Downstream",
        134,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Maximum-Data-Rate-Upstream",
        135,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Maximum-Data-Rate-Downstream",
        136,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Minimum-Data-Rate-Upstream-Low-Power",
        137,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Minimum-Data-Rate-Downstream-Low-Power",
        138,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Maximum-Interleaving-Delay-Upstream",
        139,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Actual-Interleaving-Delay-Upstream",
        140,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Maximum-Interleaving-Delay-Downstream",
        141,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Actual-Interleaving-Delay-Downstream",
        142,
        D::Integer,
        E::None,
        false,
        R::None,
    ),
    (
        3561,
        "Access-Loop-Encapsulation",
        144,
        D::String,
        E::None,
        false,
        R::None,
    ),
    (3561, "IWF-Session", 254, D::String, E::None, false, R::None),
    // MikroTik (RADIUS manual, numeric table; wireless types omitted)
    (
        14988,
        "Mikrotik-Recv-Limit",
        1,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Xmit-Limit",
        2,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Group",
        3,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Rate-Limit",
        8,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (14988, "Mikrotik-Realm", 9, D::Text, E::None, false, R::None),
    (
        14988,
        "Mikrotik-Host-IP",
        10,
        D::Ipv4Addr,
        E::None,
        false,
        R::None,
    ),
    (
        14988,
        "Mikrotik-Mark-Id",
        11,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Advertise-URL",
        12,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Advertise-Interval",
        13,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Recv-Limit-Gigawords",
        14,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Xmit-Limit-Gigawords",
        15,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Total-Limit",
        17,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Total-Limit-Gigawords",
        18,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Address-List",
        19,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Delegated-IPv6-Pool",
        22,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-DHCP-Option-Set",
        23,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-DHCP-Option-Param-STR1",
        24,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-DHCP-Option-Param-STR2",
        25,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        14988,
        "Mikrotik-Switching-Filter",
        30,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    // Juniper/ERX (FreeRADIUS dictionary.erx): service activation, parse only
    (
        4874,
        "ERX-Virtual-Router-Name",
        1,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        4874,
        "ERX-Ingress-Policy-Name",
        10,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        4874,
        "ERX-Egress-Policy-Name",
        11,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        4874,
        "ERX-Service-Activate",
        65,
        D::Text,
        E::None,
        true,
        R::Authorization,
    ),
    (
        4874,
        "ERX-Service-Deactivate",
        66,
        D::Text,
        E::None,
        false,
        R::Authorization,
    ),
    (
        4874,
        "ERX-Service-Statistics",
        69,
        D::Integer,
        E::None,
        true,
        R::Authorization,
    ),
    // Ascend (read by RouterOS when Mikrotik-Rate-Limit is absent)
    (
        529,
        "Ascend-Client-Gateway",
        132,
        D::Ipv4Addr,
        E::None,
        false,
        R::Authorization,
    ),
    (
        529,
        "Ascend-Data-Rate",
        197,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    (
        529,
        "Ascend-Xmit-Rate",
        255,
        D::Integer,
        E::None,
        false,
        R::Authorization,
    ),
    // Redback (sent by RouterOS for PPPoE intermediate agents)
    (
        2352,
        "Agent-Remote-Id",
        96,
        D::String,
        E::None,
        false,
        R::Session,
    ),
    (
        2352,
        "Agent-Circuit-Id",
        97,
        D::String,
        E::None,
        false,
        R::Session,
    ),
];

const VENDOR_NAMES: &[(u32, &str)] = &[
    (vendor::ASCEND, "Ascend"),
    (vendor::MICROSOFT, "Microsoft"),
    (vendor::REDBACK, "Redback"),
    (vendor::DSL_FORUM, "ADSL-Forum"),
    (vendor::ERX, "ERX"),
    (vendor::MIKROTIK, "Mikrotik"),
];

/// Cap on dictionary text (hostile files).
const MAX_DICT_TEXT: usize = 1 << 20;

impl Dictionary {
    /// The shipped attributes.
    pub fn builtin() -> Self {
        let mut d = Self::default();
        for &(id, name) in VENDOR_NAMES {
            d.vendors.insert(id, Cow::Borrowed(name));
        }
        for &(name, typ, data, encrypt, tagged, dynauth) in STANDARD {
            d.insert_unchecked(AttrDef {
                name: Cow::Borrowed(name),
                id: AttrId::Std(typ),
                data,
                tagged,
                encrypt,
                dynauth,
            });
        }
        for &(v, name, typ, data, encrypt, tagged, dynauth) in VENDORS {
            d.insert_unchecked(AttrDef {
                name: Cow::Borrowed(name),
                id: AttrId::Vendor(v, typ),
                data,
                tagged,
                encrypt,
                dynauth,
            });
        }
        d
    }

    fn insert_unchecked(&mut self, def: AttrDef) {
        let i = self.defs.len();
        self.by_id.insert(def.id, i);
        self.by_name.insert(def.name.to_ascii_lowercase(), i);
        self.defs.push(def);
    }

    /// Add a definition. The same id and name again is fine (FreeRADIUS
    /// dictionaries repeat the standard ones); a different meaning for an
    /// existing id or name is an error.
    pub fn add(&mut self, def: AttrDef) -> Result<(), DictError> {
        let by_id = self.by_id.get(&def.id).and_then(|&i| self.defs.get(i));
        let by_name = self
            .by_name
            .get(&def.name.to_ascii_lowercase())
            .and_then(|&i| self.defs.get(i));
        match (by_id, by_name) {
            (None, None) => {
                self.insert_unchecked(def);
                Ok(())
            }
            (Some(a), Some(b)) if a.id == b.id && a.id == def.id && same_kind(a.data, def.data) => {
                Ok(())
            }
            _ => Err(DictError::Conflict(def.name.into_owned())),
        }
    }

    pub fn get(&self, id: AttrId) -> Option<&AttrDef> {
        self.by_id.get(&id).and_then(|&i| self.defs.get(i))
    }

    /// Case-insensitive.
    pub fn by_name(&self, name: &str) -> Option<&AttrDef> {
        self.by_name
            .get(&name.to_ascii_lowercase())
            .and_then(|&i| self.defs.get(i))
    }

    pub fn vendor_name(&self, id: u32) -> Option<&str> {
        self.vendors.get(&id).map(|s| s.as_ref())
    }

    pub fn len(&self) -> usize {
        self.defs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AttrDef> {
        self.defs.iter()
    }

    /// Decode one value. Encrypted values come back as octets (the caller
    /// has the secret and the request authenticator).
    pub fn decode<'a>(&self, id: AttrId, raw: &'a [u8]) -> Decoded<'a, '_> {
        let def = self.get(id);
        let (tag, body) = match (def, raw.split_first()) {
            // RFC 2868 §3.1: a tag is 0x01–0x1F; anything else is data.
            (Some(d), Some((&t, rest))) if d.tagged && (1..=0x1f).contains(&t) => (
                Some(t),
                if d.data == DataType::Integer {
                    raw
                } else {
                    rest
                },
            ),
            _ => (None, raw),
        };
        let data = def.map_or(DataType::String, |d| {
            if d.encrypt == Encryption::None {
                d.data
            } else {
                DataType::String
            }
        });
        let value = if tag.is_some() && data == DataType::Integer {
            // RFC 2868 §3.1: tagged integers keep the tag in the high octet
            // of the 4-octet value.
            match body {
                [_, a, b, c] => Value::Integer(u32::from_be_bytes([0, *a, *b, *c])),
                _ => Value::Invalid(raw),
            }
        } else {
            decode_value(data, body)
        };
        Decoded {
            id,
            def,
            tag,
            value,
        }
    }

    /// Every attribute of a packet, flattened (VSA sub-attributes and
    /// extended attributes get their own [`AttrId`]).
    pub fn decode_packet<'a, 'd>(&'d self, p: &crate::Packet<'a>) -> Vec<Decoded<'a, 'd>> {
        let mut out = Vec::new();
        for a in p.attributes() {
            match a.typ {
                crate::packet::attr::VENDOR_SPECIFIC => {
                    match crate::packet::VendorSpecific::parse(a.value) {
                        Some(vs) if vs.is_well_formed() => {
                            for v in vs {
                                out.push(self.decode(AttrId::Vendor(v.vendor, v.typ), v.value));
                            }
                        }
                        _ => out.push(self.decode(AttrId::Std(a.typ), a.value)),
                    }
                }
                241..=246 => match crate::packet::Extended::parse(a) {
                    Some(e) => out.push(self.decode(AttrId::Ext(e.typ, e.ext), e.value)),
                    None => out.push(Decoded {
                        id: AttrId::Std(a.typ),
                        def: self.get(AttrId::Std(a.typ)),
                        tag: None,
                        value: Value::Invalid(a.value),
                    }),
                },
                t => out.push(self.decode(AttrId::Std(t), a.value)),
            }
        }
        out
    }

    /// Load FreeRADIUS-format dictionary text: `VENDOR name id`,
    /// `BEGIN-VENDOR name` / `END-VENDOR name`, `ATTRIBUTE name number type
    /// [flags]` (flags `has_tag`, `encrypt=1|2`). `VALUE`, `$INCLUDE` and
    /// other keywords are ignored. Returns how many attributes were added.
    pub fn load(&mut self, text: &str) -> Result<usize, DictError> {
        if text.len() > MAX_DICT_TEXT {
            return Err(DictError::TooLarge);
        }
        let mut vendor: Option<u32> = None;
        let mut added = 0;
        for (n, raw) in text.lines().enumerate() {
            let line = n + 1;
            let err = |why: &str| DictError::Syntax {
                line,
                why: why.to_owned(),
            };
            let words: Vec<&str> = raw
                .split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            match words.as_slice() {
                [] => {}
                ["VENDOR", name, id, ..] => {
                    let id: u32 = id.parse().map_err(|_| err("bad vendor id"))?;
                    if id > 0x00FF_FFFF {
                        return Err(err("vendor id above 2^24"));
                    }
                    self.vendors.insert(id, Cow::Owned((*name).to_owned()));
                }
                ["BEGIN-VENDOR", name, ..] => {
                    let id = self
                        .vendors
                        .iter()
                        .find(|(_, n)| n.eq_ignore_ascii_case(name))
                        .map(|(id, _)| *id)
                        .ok_or_else(|| err("unknown vendor"))?;
                    vendor = Some(id);
                }
                ["END-VENDOR", ..] => vendor = None,
                ["ATTRIBUTE", name, number, typ, rest @ ..] => {
                    let data = parse_type(typ).ok_or_else(|| err("unknown data type"))?;
                    let flags = rest.first().copied().unwrap_or("");
                    let tagged = flags.split(',').any(|f| f == "has_tag");
                    let encrypt = if flags.split(',').any(|f| f == "encrypt=1") {
                        Encryption::UserPassword
                    } else if flags.split(',').any(|f| f == "encrypt=2") {
                        Encryption::Salted
                    } else {
                        Encryption::None
                    };
                    let id =
                        parse_number(number, vendor).ok_or_else(|| err("bad attribute number"))?;
                    if name.is_empty() || name.len() > 128 {
                        return Err(err("bad attribute name"));
                    }
                    let before = self.len();
                    self.add(AttrDef {
                        name: Cow::Owned((*name).to_owned()),
                        id,
                        data,
                        tagged,
                        encrypt,
                        dynauth: DynAuthRole::Authorization,
                    })?;
                    added += self.len() - before;
                }
                ["ATTRIBUTE", ..] => return Err(err("ATTRIBUTE needs name, number and type")),
                _ => {}
            }
        }
        Ok(added)
    }
}

/// FreeRADIUS calls RFC 8044 `text` attributes `string`.
fn same_kind(a: DataType, b: DataType) -> bool {
    let norm = |d| {
        if d == DataType::Text {
            DataType::String
        } else {
            d
        }
    };
    norm(a) == norm(b)
}

fn parse_type(t: &str) -> Option<DataType> {
    Some(match t {
        "string" | "octets" | "abinary" | "ether" => DataType::String,
        "text" => DataType::Text,
        "integer" | "byte" | "short" | "signed" => DataType::Integer,
        "integer64" => DataType::Integer64,
        "ipaddr" => DataType::Ipv4Addr,
        "ipv6addr" => DataType::Ipv6Addr,
        "ipv6prefix" => DataType::Ipv6Prefix,
        "ipv4prefix" => DataType::Ipv4Prefix,
        "ifid" => DataType::Ifid,
        "date" => DataType::Time,
        "tlv" | "vsa" | "extended" | "long-extended" | "evs" | "combo-ip" => DataType::Opaque,
        _ => return None,
    })
}

/// `12` (inside BEGIN-VENDOR: a vendor type), or `241.3` (extended).
fn parse_number(s: &str, vendor: Option<u32>) -> Option<AttrId> {
    if let Some((a, b)) = s.split_once('.') {
        let (a, b): (u8, u8) = (a.parse().ok()?, b.parse().ok()?);
        return (241..=246).contains(&a).then_some(AttrId::Ext(a, b));
    }
    let n: u8 = s.parse().ok()?;
    Some(match vendor {
        Some(v) => AttrId::Vendor(v, n),
        None => AttrId::Std(n),
    })
}

/// RFC 8044 §3 decoding of one data type.
pub fn decode_value(data: DataType, v: &[u8]) -> Value<'_> {
    match data {
        DataType::Text => std::str::from_utf8(v).map_or(Value::Invalid(v), Value::Text),
        DataType::String | DataType::Opaque => Value::Octets(v),
        DataType::Integer => crate::packet::be_u32(v).map_or(Value::Invalid(v), Value::Integer),
        DataType::Time => crate::packet::be_u32(v).map_or(Value::Invalid(v), Value::Time),
        DataType::Integer64 => <[u8; 8]>::try_from(v).map_or(Value::Invalid(v), |b| {
            Value::Integer64(u64::from_be_bytes(b))
        }),
        DataType::Ipv4Addr => {
            <[u8; 4]>::try_from(v).map_or(Value::Invalid(v), |b| Value::Ipv4(b.into()))
        }
        DataType::Ipv6Addr => {
            <[u8; 16]>::try_from(v).map_or(Value::Invalid(v), |b| Value::Ipv6(b.into()))
        }
        DataType::Ifid => <[u8; 8]>::try_from(v).map_or(Value::Invalid(v), Value::Ifid),
        DataType::Ipv6Prefix => {
            decode_ipv6_prefix(v).map_or(Value::Invalid(v), |(a, l)| Value::Ipv6Prefix(a, l))
        }
        DataType::Ipv4Prefix => match v {
            // RFC 8044 §3.11: reserved, prefix length (6 bits), 4 octets.
            [0, len, a, b, c, d] if *len <= 32 => {
                Value::Ipv4Prefix(Ipv4Addr::new(*a, *b, *c, *d), *len)
            }
            _ => Value::Invalid(v),
        },
    }
}

/// RFC 8044 §3.10 / RFC 3162 §2.3: reserved octet, length 0–128, then
/// 0–16 octets (at least enough for the length); bits past the length
/// MUST be zero.
pub fn decode_ipv6_prefix(v: &[u8]) -> Option<(Ipv6Addr, u8)> {
    let ([_reserved, len], rest) = v.split_first_chunk::<2>().map(|(h, r)| (*h, r))?;
    if len > 128 || rest.len() > 16 || rest.len() * 8 < usize::from(len) {
        return None;
    }
    let mut o = [0u8; 16];
    o.get_mut(..rest.len())?.copy_from_slice(rest);
    let bits = u128::from_be_bytes(o);
    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
    (bits & !mask == 0).then_some((Ipv6Addr::from(bits), len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Builder, Code, PushAttr};

    #[test]
    fn builtin_has_the_bng_attributes() {
        let d = Dictionary::builtin();
        let rl = d.by_name("mikrotik-rate-limit").unwrap();
        assert_eq!(rl.id, AttrId::Vendor(14988, 8));
        assert_eq!(
            d.by_name("Mikrotik-Address-List").unwrap().id,
            AttrId::Vendor(14988, 19)
        );
        assert_eq!(
            d.by_name("ADSL-Agent-Circuit-Id").unwrap().id,
            AttrId::Vendor(3561, 1)
        );
        assert_eq!(
            d.by_name("MS-MPPE-Send-Key").unwrap().encrypt,
            Encryption::Salted
        );
        assert_eq!(
            d.get(AttrId::Std(2)).unwrap().encrypt,
            Encryption::UserPassword
        );
        assert!(d.by_name("ERX-Service-Activate").unwrap().tagged);
        assert_eq!(d.vendor_name(14988), Some("Mikrotik"));
        // No duplicate names or ids in the shipped tables.
        assert_eq!(d.len(), STANDARD.len() + VENDORS.len());
    }

    #[test]
    fn values_decode_by_type_and_bad_ones_are_invalid() {
        let d = Dictionary::builtin();
        let mut b = Builder::new(Code::AccessAccept, 0);
        b.push_ipv4(8, [10, 0, 0, 9].into()).unwrap();
        b.push(27, &[0, 0, 1]).unwrap(); // 3-byte integer: invalid
        b.push_vsa(14988, 8, b"10M/20M").unwrap();
        b.push_ipv6_prefix(123, "2001:db8:1::".parse().unwrap(), 48)
            .unwrap();
        b.push(64, &[1, 0, 0, 3]).unwrap(); // tagged Tunnel-Type = 3 (L2TP)
        b.push_extended(241, 9, b"z").unwrap();
        let bytes = b.into_unsigned();
        let p = crate::Packet::parse(&bytes).unwrap();
        let all = d.decode_packet(&p);
        assert_eq!(all[0].value, Value::Ipv4([10, 0, 0, 9].into()));
        assert_eq!(all[1].value, Value::Invalid(&[0, 0, 1]));
        assert_eq!(all[2].id, AttrId::Vendor(14988, 8));
        assert_eq!(all[2].value, Value::Text("10M/20M"));
        assert_eq!(
            all[3].value,
            Value::Ipv6Prefix("2001:db8:1::".parse().unwrap(), 48)
        );
        assert_eq!((all[4].tag, &all[4].value), (Some(1), &Value::Integer(3)));
        assert_eq!(all[5].id, AttrId::Ext(241, 9));
    }

    #[test]
    fn ipv6_prefix_rejects_bits_past_the_length() {
        assert!(decode_ipv6_prefix(&[0, 8, 0xff]).is_some());
        assert!(decode_ipv6_prefix(&[0, 4, 0xff]).is_none());
        assert!(decode_ipv6_prefix(&[0, 129]).is_none());
        assert!(decode_ipv6_prefix(&[0, 64, 1]).is_none());
        assert_eq!(
            decode_ipv6_prefix(&[0, 0]),
            Some((Ipv6Addr::UNSPECIFIED, 0))
        );
    }

    #[test]
    fn freeradius_text_extends_the_dictionary() {
        let mut d = Dictionary::builtin();
        let text = "
            # comment
            VENDOR      Acme    99999
            BEGIN-VENDOR Acme
            ATTRIBUTE   Acme-Plan   1   string
            ATTRIBUTE   Acme-Key    2   octets  encrypt=2,has_tag
            VALUE       Acme-Plan   Gold    1
            END-VENDOR  Acme
            ATTRIBUTE   Frag-Thing  245.4  octets
            ATTRIBUTE   User-Name   1   string
        ";
        assert_eq!(d.load(text).unwrap(), 3);
        let k = d.by_name("Acme-Key").unwrap();
        assert_eq!(
            (k.id, k.encrypt, k.tagged),
            (AttrId::Vendor(99999, 2), Encryption::Salted, true)
        );
        assert_eq!(d.by_name("Frag-Thing").unwrap().id, AttrId::Ext(245, 4));
        assert!(matches!(
            d.load("ATTRIBUTE User-Name 1 integer"),
            Err(DictError::Conflict(_))
        ));
        assert!(matches!(
            d.load("BEGIN-VENDOR Nope"),
            Err(DictError::Syntax { line: 1, .. })
        ));
        assert!(matches!(
            d.load("ATTRIBUTE X 300 string"),
            Err(DictError::Syntax { .. })
        ));
    }
}

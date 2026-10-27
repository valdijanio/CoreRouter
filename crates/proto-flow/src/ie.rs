//! Information Elements: the field numbers of IPFIX (IANA "IPFIX
//! Information Elements" registry, RFC 7012) and NetFlow v9 (RFC 3954 §8,
//! the same numbers for the fields both have).
//!
//! Only the elements CoreRouter exports (and the collector side reads back)
//! are named here; a decoder keeps any other element as raw bytes.

/// RFC 7012 §2 / IANA: name, number and abstract type in the comment.
pub mod id {
    /// unsigned64, octets of the flow in this report.
    pub const OCTET_DELTA_COUNT: u16 = 1;
    /// unsigned64.
    pub const PACKET_DELTA_COUNT: u16 = 2;
    /// unsigned8, IP protocol number.
    pub const PROTOCOL_IDENTIFIER: u16 = 4;
    /// unsigned16.
    pub const SOURCE_TRANSPORT_PORT: u16 = 7;
    /// ipv4Address.
    pub const SOURCE_IPV4_ADDRESS: u16 = 8;
    /// unsigned32, the ifIndex the packets came in on.
    pub const INGRESS_INTERFACE: u16 = 10;
    /// unsigned16.
    pub const DESTINATION_TRANSPORT_PORT: u16 = 11;
    /// unsigned16, the VLAN of the ingress interface (RFC 8158 §4.6
    /// "vlanID").
    pub const VLAN_ID: u16 = 58;
    /// ipv4Address.
    pub const DESTINATION_IPV4_ADDRESS: u16 = 12;
    /// unsigned32.
    pub const EGRESS_INTERFACE: u16 = 14;
    /// unsigned32, sysUpTime in ms of the last packet (NetFlow v9
    /// `LAST_SWITCHED`).
    pub const FLOW_END_SYS_UP_TIME: u16 = 21;
    /// unsigned32, sysUpTime in ms of the first packet (v9 `FIRST_SWITCHED`).
    pub const FLOW_START_SYS_UP_TIME: u16 = 22;
    /// ipv6Address.
    pub const SOURCE_IPV6_ADDRESS: u16 = 27;
    /// ipv6Address.
    pub const DESTINATION_IPV6_ADDRESS: u16 = 28;
    /// unsigned32, 1 in N (v9 `SAMPLING_INTERVAL`; deprecated in IPFIX for
    /// `samplingPacketInterval`, still what most collectors read).
    pub const SAMPLING_INTERVAL: u16 = 34;
    /// unsigned8, 1 deterministic, 2 random (v9 `SAMPLING_ALGORITHM`).
    pub const SAMPLING_ALGORITHM: u16 = 35;
    /// string, the interface's short name.
    pub const INTERFACE_NAME: u16 = 82;
    /// unsigned8, why the flow was reported ([`super::EndReason`]).
    pub const FLOW_END_REASON: u16 = 136;
    /// unsigned32.
    pub const OBSERVATION_DOMAIN_ID: u16 = 149;
    /// dateTimeMilliseconds.
    pub const FLOW_START_MILLISECONDS: u16 = 152;
    /// dateTimeMilliseconds.
    pub const FLOW_END_MILLISECONDS: u16 = 153;
    /// ipv4Address, the source after NAT (RFC 8158 §4).
    pub const POST_NAT_SOURCE_IPV4_ADDRESS: u16 = 225;
    /// ipv4Address.
    pub const POST_NAT_DESTINATION_IPV4_ADDRESS: u16 = 226;
    /// unsigned16.
    pub const POST_NAPT_SOURCE_TRANSPORT_PORT: u16 = 227;
    /// unsigned16.
    pub const POST_NAPT_DESTINATION_TRANSPORT_PORT: u16 = 228;
    /// unsigned8, [`super::NatEventType`].
    pub const NAT_EVENT: u16 = 230;
    /// unsigned8, RFC 5103: 1 initiator, 2 reverse initiator.
    pub const BIFLOW_DIRECTION: u16 = 239;
    /// unsigned32, a locally unique id of the NAT pool.
    pub const NAT_POOL_ID: u16 = 283;
    /// ipv6Address (NPTv6, NAT66).
    pub const POST_NAT_SOURCE_IPV6_ADDRESS: u16 = 281;
    /// ipv6Address.
    pub const POST_NAT_DESTINATION_IPV6_ADDRESS: u16 = 282;
    /// dateTimeMilliseconds, when the event happened (RFC 8158 §4: the
    /// timestamp of every NAT event).
    pub const OBSERVATION_TIME_MILLISECONDS: u16 = 323;
    /// unsigned16, RFC 8158 port block allocation.
    pub const PORT_RANGE_START: u16 = 361;
    pub const PORT_RANGE_END: u16 = 362;
    pub const PORT_RANGE_STEP_SIZE: u16 = 363;
    pub const PORT_RANGE_NUM_PORTS: u16 = 364;
    /// string, the user name of the flow (a PPPoE login).
    pub const USER_NAME: u16 = 371;
    /// unsigned32, RFC 8158 §4.4 Table 3.
    pub const NAT_QUOTA_EXCEEDED_EVENT: u16 = 466;
    /// unsigned32, RFC 8158 §4.5 Table 4.
    pub const NAT_THRESHOLD_EVENT: u16 = 467;
    /// unsigned32 (RFC 8158 §4.6.7.3).
    pub const MAX_ENTRIES_PER_USER: u16 = 473;
    /// unsigned32. RFC 8158 Table 18 names `addressPortMappingHighThreshold`
    /// (478) for the per-user event too; its §6 registered this one for the
    /// per-user threshold, which says what the value is.
    pub const ADDRESS_PORT_MAPPING_PER_USER_HIGH_THRESHOLD: u16 = 480;
}

/// A field specifier of a template: element number and length in octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Field {
    pub id: u16,
    pub len: u16,
    /// IPFIX enterprise number (RFC 7011 §3.2); `None` for IANA elements.
    pub enterprise: Option<u32>,
}

impl Field {
    pub const fn new(id: u16, len: u16) -> Self {
        Self {
            id,
            len,
            enterprise: None,
        }
    }
}

/// RFC 7011 §7: a field of this length is variable-length.
pub const VARIABLE: u16 = 65535;

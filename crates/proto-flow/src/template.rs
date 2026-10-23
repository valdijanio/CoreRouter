//! The templates CoreRouter exports and how a record fills them.
//!
//! Every field has a fixed length, so a record's size is known before it
//! is written (a message never overflows) and NetFlow v9, which has no
//! variable-length fields, uses the same layout. The two versions differ
//! only in the flow timestamps (IPFIX absolute milliseconds, v9 sysUpTime)
//! and in the scope of the options templates (IPFIX elements, v9 scope
//! types, RFC 3954 §6.1).

use std::net::IpAddr;

use crate::ie::{Field, id};
use crate::record::{Flow, NatEvent, PortBlock};

/// IPFIX (RFC 7011 §3.1 version 10) or NetFlow v9 (RFC 3954 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    V9,
    Ipfix,
}

impl Version {
    pub fn number(self) -> u16 {
        match self {
            Self::V9 => 9,
            Self::Ipfix => 10,
        }
    }
}

/// Template ids (data sets use them; 256 is the first allowed, RFC 7011
/// §3.4.1 and RFC 3954 §5.2).
pub const FLOW_V4: u16 = 256;
pub const FLOW_V6: u16 = 257;
pub const NAT44: u16 = 258;
pub const PORT_BLOCK: u16 = 259;
pub const OPT_SAMPLING: u16 = 260;
pub const OPT_INTERFACE: u16 = 261;

/// Fixed length of `interfaceName` (v9 has no variable length; Linux names
/// are at most 15 bytes, our `IfName` a little more).
pub const IFNAME_LEN: u16 = 32;

/// RFC 3954 §6.1 scope field types of an options template.
const V9_SCOPE_SYSTEM: u16 = 1;
const V9_SCOPE_INTERFACE: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub id: u16,
    /// Number of leading scope fields; 0 for a data template.
    pub scope: u16,
    pub fields: Vec<Field>,
}

impl Template {
    /// Bytes of one record.
    pub fn record_len(&self) -> usize {
        self.fields.iter().map(|f| usize::from(f.len)).sum()
    }
}

const fn f(id: u16, len: u16) -> Field {
    Field::new(id, len)
}

fn times(v: Version) -> [Field; 2] {
    match v {
        Version::Ipfix => [
            f(id::FLOW_START_MILLISECONDS, 8),
            f(id::FLOW_END_MILLISECONDS, 8),
        ],
        Version::V9 => [
            f(id::FLOW_START_SYS_UP_TIME, 4),
            f(id::FLOW_END_SYS_UP_TIME, 4),
        ],
    }
}

fn flow(v: Version, tid: u16, addr: u16, ids: [u16; 4]) -> Template {
    let [src, dst, post_src, post_dst] = ids;
    let mut fields = times(v).to_vec();
    fields.extend([
        f(id::OCTET_DELTA_COUNT, 8),
        f(id::PACKET_DELTA_COUNT, 8),
        f(id::INGRESS_INTERFACE, 4),
        f(id::EGRESS_INTERFACE, 4),
        f(src, addr),
        f(dst, addr),
        f(post_src, addr),
        f(post_dst, addr),
        f(id::SOURCE_TRANSPORT_PORT, 2),
        f(id::DESTINATION_TRANSPORT_PORT, 2),
        f(id::POST_NAPT_SOURCE_TRANSPORT_PORT, 2),
        f(id::POST_NAPT_DESTINATION_TRANSPORT_PORT, 2),
        f(id::PROTOCOL_IDENTIFIER, 1),
        f(id::FLOW_END_REASON, 1),
        f(id::BIFLOW_DIRECTION, 1),
    ]);
    Template {
        id: tid,
        scope: 0,
        fields,
    }
}

/// The templates of version `v`, data templates first.
pub fn all(v: Version) -> Vec<Template> {
    let (sys, iface) = match v {
        Version::Ipfix => (id::OBSERVATION_DOMAIN_ID, id::INGRESS_INTERFACE),
        Version::V9 => (V9_SCOPE_SYSTEM, V9_SCOPE_INTERFACE),
    };
    vec![
        flow(
            v,
            FLOW_V4,
            4,
            [
                id::SOURCE_IPV4_ADDRESS,
                id::DESTINATION_IPV4_ADDRESS,
                id::POST_NAT_SOURCE_IPV4_ADDRESS,
                id::POST_NAT_DESTINATION_IPV4_ADDRESS,
            ],
        ),
        flow(
            v,
            FLOW_V6,
            16,
            [
                id::SOURCE_IPV6_ADDRESS,
                id::DESTINATION_IPV6_ADDRESS,
                id::POST_NAT_SOURCE_IPV6_ADDRESS,
                id::POST_NAT_DESTINATION_IPV6_ADDRESS,
            ],
        ),
        // RFC 8158 §4.2.1/§4.2.2 (NAT44 session create/delete): the
        // timestamp, the event, the protocol and both tuples before and
        // after translation.
        Template {
            id: NAT44,
            scope: 0,
            fields: vec![
                f(id::OBSERVATION_TIME_MILLISECONDS, 8),
                f(id::NAT_EVENT, 1),
                f(id::PROTOCOL_IDENTIFIER, 1),
                f(id::SOURCE_IPV4_ADDRESS, 4),
                f(id::POST_NAT_SOURCE_IPV4_ADDRESS, 4),
                f(id::DESTINATION_IPV4_ADDRESS, 4),
                f(id::POST_NAT_DESTINATION_IPV4_ADDRESS, 4),
                f(id::SOURCE_TRANSPORT_PORT, 2),
                f(id::POST_NAPT_SOURCE_TRANSPORT_PORT, 2),
                f(id::DESTINATION_TRANSPORT_PORT, 2),
                f(id::POST_NAPT_DESTINATION_TRANSPORT_PORT, 2),
            ],
        },
        // RFC 8158 §4.2.10/§4.2.11 (port block allocation/de-allocation).
        Template {
            id: PORT_BLOCK,
            scope: 0,
            fields: vec![
                f(id::OBSERVATION_TIME_MILLISECONDS, 8),
                f(id::NAT_EVENT, 1),
                f(id::SOURCE_IPV4_ADDRESS, 4),
                f(id::POST_NAT_SOURCE_IPV4_ADDRESS, 4),
                f(id::PORT_RANGE_START, 2),
                f(id::PORT_RANGE_END, 2),
                f(id::PORT_RANGE_STEP_SIZE, 2),
                f(id::PORT_RANGE_NUM_PORTS, 2),
            ],
        },
        Template {
            id: OPT_SAMPLING,
            scope: 1,
            fields: vec![
                f(sys, 4),
                f(id::SAMPLING_INTERVAL, 4),
                f(id::SAMPLING_ALGORITHM, 1),
            ],
        },
        Template {
            id: OPT_INTERFACE,
            scope: 1,
            fields: vec![f(iface, 4), f(id::INTERFACE_NAME, IFNAME_LEN)],
        },
    ]
}

/// What one data record is filled from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Row<'a> {
    Flow(&'a Flow),
    Nat(&'a NatEvent),
    Block(&'a PortBlock),
    Sampling { domain: u32, interval: u32 },
    Interface { index: u32, name: &'a str },
}

impl Row<'_> {
    pub(crate) fn template(&self) -> u16 {
        match self {
            Row::Flow(fl) if fl.src.is_ipv4() => FLOW_V4,
            Row::Flow(_) => FLOW_V6,
            Row::Nat(_) => NAT44,
            Row::Block(_) => PORT_BLOCK,
            Row::Sampling { .. } => OPT_SAMPLING,
            Row::Interface { .. } => OPT_INTERFACE,
        }
    }
}

/// `v` big-endian in `len` bytes (the low ones: RFC 7011 §6.2 reduced-size
/// encoding).
fn put_uint(out: &mut Vec<u8>, v: u64, len: u16) {
    let bytes = v.to_be_bytes();
    let len = usize::from(len);
    if len >= 8 {
        out.resize(out.len() + len - 8, 0);
        out.extend_from_slice(&bytes);
    } else {
        out.extend_from_slice(bytes.get(8 - len..).unwrap_or(&[]));
    }
}

fn put_addr(out: &mut Vec<u8>, a: IpAddr, len: u16) {
    match (a, len) {
        (IpAddr::V4(a), 4) => out.extend_from_slice(&a.octets()),
        (IpAddr::V6(a), 16) => out.extend_from_slice(&a.octets()),
        (IpAddr::V4(a), 16) => out.extend_from_slice(&a.to_ipv6_mapped().octets()),
        _ => out.resize(out.len() + usize::from(len), 0),
    }
}

/// Milliseconds since the exporter's boot, for v9 (RFC 3954 §8
/// `FIRST_SWITCHED`): 0 for a time before it, wrapping like sysUpTime.
fn uptime(t: u64, boot_ms: u64) -> u64 {
    t.saturating_sub(boot_ms) & 0xffff_ffff
}

/// Write one field of `row`; an element the row does not have is zeros.
pub(crate) fn put(out: &mut Vec<u8>, field: Field, row: Row<'_>, boot_ms: u64) {
    let len = field.len;
    let uint = |out: &mut Vec<u8>, v: u64| put_uint(out, v, len);
    match row {
        Row::Flow(fl) => match field.id {
            id::FLOW_START_MILLISECONDS => uint(out, fl.start_ms),
            id::FLOW_END_MILLISECONDS => uint(out, fl.end_ms),
            id::FLOW_START_SYS_UP_TIME => uint(out, uptime(fl.start_ms, boot_ms)),
            id::FLOW_END_SYS_UP_TIME => uint(out, uptime(fl.end_ms, boot_ms)),
            id::OCTET_DELTA_COUNT => uint(out, fl.octets),
            id::PACKET_DELTA_COUNT => uint(out, fl.packets),
            id::INGRESS_INTERFACE => uint(out, u64::from(fl.ingress)),
            id::EGRESS_INTERFACE => uint(out, u64::from(fl.egress)),
            id::SOURCE_IPV4_ADDRESS | id::SOURCE_IPV6_ADDRESS => put_addr(out, fl.src, len),
            id::DESTINATION_IPV4_ADDRESS | id::DESTINATION_IPV6_ADDRESS => {
                put_addr(out, fl.dst, len);
            }
            id::POST_NAT_SOURCE_IPV4_ADDRESS | id::POST_NAT_SOURCE_IPV6_ADDRESS => {
                put_addr(out, fl.post_src, len);
            }
            id::POST_NAT_DESTINATION_IPV4_ADDRESS | id::POST_NAT_DESTINATION_IPV6_ADDRESS => {
                put_addr(out, fl.post_dst, len);
            }
            id::SOURCE_TRANSPORT_PORT => uint(out, u64::from(fl.src_port)),
            id::DESTINATION_TRANSPORT_PORT => uint(out, u64::from(fl.dst_port)),
            id::POST_NAPT_SOURCE_TRANSPORT_PORT => uint(out, u64::from(fl.post_src_port)),
            id::POST_NAPT_DESTINATION_TRANSPORT_PORT => uint(out, u64::from(fl.post_dst_port)),
            id::PROTOCOL_IDENTIFIER => uint(out, u64::from(fl.protocol)),
            id::FLOW_END_REASON => uint(out, u64::from(fl.end_reason.code())),
            id::BIFLOW_DIRECTION => uint(out, u64::from(fl.direction.code())),
            _ => uint(out, 0),
        },
        Row::Nat(n) => match field.id {
            id::OBSERVATION_TIME_MILLISECONDS => uint(out, n.time_ms),
            id::NAT_EVENT => uint(out, u64::from(n.event.code())),
            id::PROTOCOL_IDENTIFIER => uint(out, u64::from(n.protocol)),
            id::SOURCE_IPV4_ADDRESS => put_addr(out, n.src.into(), len),
            id::POST_NAT_SOURCE_IPV4_ADDRESS => put_addr(out, n.post_src.into(), len),
            id::DESTINATION_IPV4_ADDRESS => put_addr(out, n.dst.into(), len),
            id::POST_NAT_DESTINATION_IPV4_ADDRESS => put_addr(out, n.post_dst.into(), len),
            id::SOURCE_TRANSPORT_PORT => uint(out, u64::from(n.src_port)),
            id::POST_NAPT_SOURCE_TRANSPORT_PORT => uint(out, u64::from(n.post_src_port)),
            id::DESTINATION_TRANSPORT_PORT => uint(out, u64::from(n.dst_port)),
            id::POST_NAPT_DESTINATION_TRANSPORT_PORT => uint(out, u64::from(n.post_dst_port)),
            _ => uint(out, 0),
        },
        Row::Block(b) => match field.id {
            id::OBSERVATION_TIME_MILLISECONDS => uint(out, b.time_ms),
            id::NAT_EVENT => uint(out, u64::from(b.event.code())),
            id::SOURCE_IPV4_ADDRESS => put_addr(out, b.src.into(), len),
            id::POST_NAT_SOURCE_IPV4_ADDRESS => put_addr(out, b.post_src.into(), len),
            id::PORT_RANGE_START => uint(out, u64::from(b.port_start)),
            id::PORT_RANGE_END => uint(out, u64::from(b.port_end)),
            id::PORT_RANGE_STEP_SIZE => uint(out, u64::from(b.step)),
            id::PORT_RANGE_NUM_PORTS => uint(out, u64::from(b.ports)),
            _ => uint(out, 0),
        },
        Row::Sampling { domain, interval } => match field.id {
            id::SAMPLING_INTERVAL => uint(out, u64::from(interval)),
            // 1: deterministic (one connection in N, by a hash of its tuple).
            id::SAMPLING_ALGORITHM => uint(out, 1),
            _ => uint(out, u64::from(domain)),
        },
        Row::Interface { index, name } => match field.id {
            id::INTERFACE_NAME => {
                let bytes = name.as_bytes();
                let n = bytes.len().min(usize::from(len));
                out.extend_from_slice(bytes.get(..n).unwrap_or(&[]));
                out.resize(out.len() + usize::from(len) - n, 0);
            }
            _ => uint(out, u64::from(index)),
        },
    }
}

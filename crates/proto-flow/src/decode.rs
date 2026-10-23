//! The collecting side: IPFIX and NetFlow v9 messages back into records.
//! It serves the tests (RFC examples, round trips) and the test collector
//! of the namespace tests; the router itself never collects.
//!
//! The input is hostile: every length is checked against what is left,
//! a set or template that does not add up ends the message's parsing
//! with an error instead of a guess, templates are bounded
//! ([`MAX_TEMPLATES`]), and a template whose records would take no bytes
//! is refused (it would loop forever).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ie::{Field, VARIABLE, id};
use crate::record::{Direction, EndReason, Flow, NatEvent, NatEventType, PortBlock, Record};

/// Templates one decoder remembers (all domains).
pub const MAX_TEMPLATES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Short,
    Version(u16),
    Length,
    Set(u16),
    Template(u16),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => write!(f, "message shorter than its header"),
            Self::Version(v) => write!(f, "version {v} is neither 9 nor 10"),
            Self::Length => write!(f, "message length does not match"),
            Self::Set(id) => write!(f, "set {id} is malformed"),
            Self::Template(id) => write!(f, "template {id} is malformed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tpl {
    scope: u16,
    fields: Vec<Field>,
}

/// One data record: each field's specifier and raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRecord {
    pub template: u16,
    /// Leading scope fields (options records).
    pub scope: u16,
    pub fields: Vec<(Field, Vec<u8>)>,
}

impl DataRecord {
    pub fn get(&self, ie: u16) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(f, _)| f.id == ie && f.enterprise.is_none())
            .map(|(_, v)| v.as_slice())
    }

    /// An unsigned value of 1–8 bytes.
    pub fn uint(&self, ie: u16) -> Option<u64> {
        let v = self.get(ie)?;
        if v.is_empty() || v.len() > 8 {
            return None;
        }
        Some(v.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    pub fn ip(&self, ie: u16) -> Option<IpAddr> {
        let v = self.get(ie)?;
        match v.len() {
            4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(v).ok()?))),
            16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(v).ok()?))),
            _ => None,
        }
    }

    pub fn string(&self, ie: u16) -> Option<String> {
        let v = self.get(ie)?;
        let end = v.iter().position(|b| *b == 0).unwrap_or(v.len());
        Some(String::from_utf8_lossy(v.get(..end).unwrap_or(&[])).into_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub version: u16,
    pub export_secs: u32,
    /// v9 only.
    pub sys_uptime_ms: Option<u32>,
    pub sequence: u32,
    /// Observation domain (IPFIX) or source id (v9).
    pub domain: u32,
    /// v9 header count.
    pub count: u16,
    /// Template and options template records seen.
    pub templates: usize,
    pub records: Vec<DataRecord>,
    /// Data sets whose template is not known yet (dropped).
    pub unknown_sets: usize,
}

#[derive(Debug, Default)]
pub struct Decoder {
    templates: HashMap<(u16, u32, u16), Tpl>,
}

struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn templates(&self) -> usize {
        self.templates.len()
    }

    fn learn(&mut self, key: (u16, u32, u16), t: Tpl) {
        if self.templates.len() < MAX_TEMPLATES || self.templates.contains_key(&key) {
            self.templates.insert(key, t);
        }
    }

    pub fn decode(&mut self, bytes: &[u8]) -> Result<Message, Error> {
        let mut r = Rd::new(bytes);
        let version = r.u16().ok_or(Error::Short)?;
        let mut m = Message {
            version,
            ..Message::default()
        };
        match version {
            10 => {
                let len = usize::from(r.u16().ok_or(Error::Short)?);
                m.export_secs = r.u32().ok_or(Error::Short)?;
                m.sequence = r.u32().ok_or(Error::Short)?;
                m.domain = r.u32().ok_or(Error::Short)?;
                if len < 16 || len > bytes.len() {
                    return Err(Error::Length);
                }
                let body = bytes.get(16..len).ok_or(Error::Length)?;
                self.sets(body, &mut m)?;
            }
            9 => {
                m.count = r.u16().ok_or(Error::Short)?;
                m.sys_uptime_ms = Some(r.u32().ok_or(Error::Short)?);
                m.export_secs = r.u32().ok_or(Error::Short)?;
                m.sequence = r.u32().ok_or(Error::Short)?;
                m.domain = r.u32().ok_or(Error::Short)?;
                let body = bytes.get(20..).ok_or(Error::Short)?;
                self.sets(body, &mut m)?;
            }
            v => return Err(Error::Version(v)),
        }
        Ok(m)
    }

    fn sets(&mut self, body: &[u8], m: &mut Message) -> Result<(), Error> {
        let mut r = Rd::new(body);
        // v9 may pad the packet's end; IPFIX has no trailing bytes.
        while r.left() >= 4 {
            let id = r.u16().ok_or(Error::Short)?;
            let len = usize::from(r.u16().ok_or(Error::Short)?);
            if len < 4 {
                return Err(Error::Set(id));
            }
            let set = r.take(len - 4).ok_or(Error::Set(id))?;
            match (m.version, id) {
                (10, 2) | (9, 0) => self.templates_set(set, m, false)?,
                (10, 3) | (9, 1) => self.templates_set(set, m, true)?,
                (_, 256..) => self.data_set(id, set, m),
                _ => {}
            }
        }
        Ok(())
    }

    fn field(r: &mut Rd<'_>, ipfix: bool, tid: u16) -> Result<Field, Error> {
        let raw = r.u16().ok_or(Error::Template(tid))?;
        let len = r.u16().ok_or(Error::Template(tid))?;
        if ipfix && raw & 0x8000 != 0 {
            let pen = r.u32().ok_or(Error::Template(tid))?;
            return Ok(Field {
                id: raw & 0x7fff,
                len,
                enterprise: Some(pen),
            });
        }
        Ok(Field::new(raw, len))
    }

    fn templates_set(&mut self, set: &[u8], m: &mut Message, options: bool) -> Result<(), Error> {
        let ipfix = m.version == 10;
        let mut r = Rd::new(set);
        // Records until only padding is left (shorter than a header).
        while r.left() >= if options { 6 } else { 4 } {
            let tid = r.u16().ok_or(Error::Short)?;
            if tid == 0 && !ipfix {
                break; // v9 padding
            }
            let key = (m.version, m.domain, tid);
            let (count, scope) = if !options {
                (usize::from(r.u16().ok_or(Error::Template(tid))?), 0u16)
            } else if ipfix {
                let n = r.u16().ok_or(Error::Template(tid))?;
                let s = r.u16().ok_or(Error::Template(tid))?;
                (usize::from(n), s)
            } else {
                let sl = r.u16().ok_or(Error::Template(tid))?;
                let ol = r.u16().ok_or(Error::Template(tid))?;
                if sl % 4 != 0 || ol % 4 != 0 {
                    return Err(Error::Template(tid));
                }
                (usize::from(sl / 4) + usize::from(ol / 4), sl / 4)
            };
            if tid < 256 {
                return Err(Error::Template(tid));
            }
            if count == 0 {
                // RFC 7011 §8.1: a withdrawal.
                self.templates.remove(&key);
                continue;
            }
            if usize::from(scope) > count || (options && scope == 0) {
                return Err(Error::Template(tid));
            }
            let mut fields = Vec::with_capacity(count.min(256));
            for _ in 0..count {
                fields.push(Self::field(&mut r, ipfix, tid)?);
            }
            if fields.iter().all(|f| f.len == 0) {
                return Err(Error::Template(tid));
            }
            if !ipfix && fields.iter().any(|f| f.len == VARIABLE) {
                return Err(Error::Template(tid));
            }
            m.templates += 1;
            self.learn(key, Tpl { scope, fields });
        }
        Ok(())
    }

    fn data_set(&mut self, tid: u16, set: &[u8], m: &mut Message) {
        let Some(t) = self.templates.get(&(m.version, m.domain, tid)) else {
            m.unknown_sets += 1;
            return;
        };
        let min: usize = t
            .fields
            .iter()
            .map(|f| {
                if f.len == VARIABLE {
                    1
                } else {
                    usize::from(f.len)
                }
            })
            .sum();
        let mut r = Rd::new(set);
        while min > 0 && r.left() >= min {
            let mut fields = Vec::with_capacity(t.fields.len());
            for f in &t.fields {
                let len = if f.len == VARIABLE {
                    // RFC 7011 §7: one byte, or 255 and two more.
                    match r.u8() {
                        Some(255) => r.u16().map(usize::from),
                        other => other.map(usize::from),
                    }
                } else {
                    Some(usize::from(f.len))
                };
                let Some(v) = len.and_then(|n| r.take(n)) else {
                    return;
                };
                fields.push((*f, v.to_vec()));
            }
            m.records.push(DataRecord {
                template: tid,
                scope: t.scope,
                fields,
            });
        }
    }
}

/// A decoded data record as one of ours (`None` for options records and
/// records of other exporters' templates that carry none of our shapes).
pub fn to_record(d: &DataRecord, m: &Message) -> Option<Record> {
    let u16v = |ie| d.uint(ie).and_then(|v| u16::try_from(v).ok()).unwrap_or(0);
    let v4 = |ie| match d.ip(ie) {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    };
    if d.scope > 0 {
        return None;
    }
    if let Some(ev) = d.uint(id::NAT_EVENT) {
        let event = NatEventType::from_code(u8::try_from(ev).ok()?)?;
        let time_ms = d.uint(id::OBSERVATION_TIME_MILLISECONDS)?;
        if d.get(id::PORT_RANGE_START).is_some() {
            return Some(Record::PortBlock(PortBlock {
                time_ms,
                event,
                src: v4(id::SOURCE_IPV4_ADDRESS)?,
                post_src: v4(id::POST_NAT_SOURCE_IPV4_ADDRESS)?,
                port_start: u16v(id::PORT_RANGE_START),
                port_end: u16v(id::PORT_RANGE_END),
                step: u16v(id::PORT_RANGE_STEP_SIZE),
                ports: u16v(id::PORT_RANGE_NUM_PORTS),
            }));
        }
        return Some(Record::Nat(NatEvent {
            time_ms,
            start_ms: d.uint(id::FLOW_START_MILLISECONDS).unwrap_or(0),
            event,
            protocol: u8::try_from(d.uint(id::PROTOCOL_IDENTIFIER)?).ok()?,
            src: v4(id::SOURCE_IPV4_ADDRESS)?,
            dst: v4(id::DESTINATION_IPV4_ADDRESS).unwrap_or(Ipv4Addr::UNSPECIFIED),
            src_port: u16v(id::SOURCE_TRANSPORT_PORT),
            dst_port: u16v(id::DESTINATION_TRANSPORT_PORT),
            post_src: v4(id::POST_NAT_SOURCE_IPV4_ADDRESS)?,
            post_dst: v4(id::POST_NAT_DESTINATION_IPV4_ADDRESS).unwrap_or(Ipv4Addr::UNSPECIFIED),
            post_src_port: u16v(id::POST_NAPT_SOURCE_TRANSPORT_PORT),
            post_dst_port: u16v(id::POST_NAPT_DESTINATION_TRANSPORT_PORT),
        }));
    }
    let octets = d.uint(id::OCTET_DELTA_COUNT)?;
    // v9 sysUpTime → Unix ms (RFC 3954 §5.1: the header's uptime and
    // seconds were taken together).
    let time = |abs: u16, rel: u16| -> Option<u64> {
        if let Some(t) = d.uint(abs) {
            return Some(t);
        }
        let rel = d.uint(rel)?;
        let up = u64::from(m.sys_uptime_ms?);
        Some((u64::from(m.export_secs) * 1000).saturating_sub(up.saturating_sub(rel)))
    };
    let (src, dst, psrc, pdst) = if d.get(id::SOURCE_IPV4_ADDRESS).is_some() {
        (
            id::SOURCE_IPV4_ADDRESS,
            id::DESTINATION_IPV4_ADDRESS,
            id::POST_NAT_SOURCE_IPV4_ADDRESS,
            id::POST_NAT_DESTINATION_IPV4_ADDRESS,
        )
    } else {
        (
            id::SOURCE_IPV6_ADDRESS,
            id::DESTINATION_IPV6_ADDRESS,
            id::POST_NAT_SOURCE_IPV6_ADDRESS,
            id::POST_NAT_DESTINATION_IPV6_ADDRESS,
        )
    };
    let src_ip = d.ip(src)?;
    let dst_ip = d.ip(dst)?;
    Some(Record::Flow(Flow {
        start_ms: time(id::FLOW_START_MILLISECONDS, id::FLOW_START_SYS_UP_TIME)?,
        end_ms: time(id::FLOW_END_MILLISECONDS, id::FLOW_END_SYS_UP_TIME)?,
        protocol: u8::try_from(d.uint(id::PROTOCOL_IDENTIFIER)?).ok()?,
        src: src_ip,
        dst: dst_ip,
        src_port: u16v(id::SOURCE_TRANSPORT_PORT),
        dst_port: u16v(id::DESTINATION_TRANSPORT_PORT),
        post_src: d.ip(psrc).unwrap_or(src_ip),
        post_dst: d.ip(pdst).unwrap_or(dst_ip),
        post_src_port: d
            .uint(id::POST_NAPT_SOURCE_TRANSPORT_PORT)
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(u16v(id::SOURCE_TRANSPORT_PORT)),
        post_dst_port: d
            .uint(id::POST_NAPT_DESTINATION_TRANSPORT_PORT)
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(u16v(id::DESTINATION_TRANSPORT_PORT)),
        octets,
        packets: d.uint(id::PACKET_DELTA_COUNT).unwrap_or(0),
        ingress: d
            .uint(id::INGRESS_INTERFACE)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
        egress: d
            .uint(id::EGRESS_INTERFACE)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0),
        end_reason: d
            .uint(id::FLOW_END_REASON)
            .and_then(|v| EndReason::from_code(u8::try_from(v).ok()?))
            .unwrap_or(EndReason::Idle),
        direction: match d.uint(id::BIFLOW_DIRECTION) {
            Some(2) => Direction::Reverse,
            _ => Direction::Initiator,
        },
    }))
}

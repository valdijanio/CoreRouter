//! Zone transfers and NOTIFY, as messages (the daemon has the sockets).
//!
//! Server side, [`intercept`]: before the chain sees a message, AXFR and
//! IXFR queries (RFC 5936, RFC 1995), NOTIFY (RFC 1996) and UPDATE (RFC
//! 2136, handed to the daemon's updater: `zone::update`) are answered
//! here, with their own ACLs (`allow_transfer`, a secondary's
//! `primaries`), not `allowed_from`: a secondary somewhere else may
//! transfer, a LAN client may not.
//!
//! Client side, for secondaries: the SOA check ([`soa_query`],
//! [`soa_serial`]), the transfer ([`xfr_query`], [`Transfer`]) and the
//! NOTIFY we send ([`notify_message`], [`notify_ack`]).

use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_model::dns_zone::{ZoneType, serial_gt};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;

use super::{Changed, Diff, MAX_ZONE_RECORDS, ZoneData};
use crate::message::key_of;
use crate::server::Forwarder;

/// Bytes of records per transfer message (BIND packs up to 64 KiB; smaller
/// messages cost a little more framing and nothing else).
const MESSAGE_BYTES: usize = 16_000;
/// RFC 1035 §4.2.1, for IXFR over UDP without EDNS.
const UDP_BYTES: usize = 512;
/// Messages one transfer may take (a zone at the record limit fits in far
/// fewer).
const MAX_MESSAGES: usize = 100_000;
/// RFC 5936 §2.2.1 (and RFC 2136 §2.2): RCODE 9.
const NOTAUTH: ResponseCode = ResponseCode::NotAuth;

/// The opcode and, for a one-question query, the QTYPE of `packet`,
/// without decoding it (most queries are not transfers: they go to the
/// chain untouched).
fn peek(packet: &[u8]) -> Option<(u8, Option<u16>)> {
    let flags = *packet.get(2)?;
    if flags & 0x80 != 0 {
        return None;
    }
    let opcode = (flags >> 3) & 0x0f;
    let qdcount = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
    if qdcount != 1 {
        return Some((opcode, None));
    }
    let mut i = 12usize;
    for _ in 0..128 {
        let len = *packet.get(i)?;
        if len == 0 {
            let t = u16::from_be_bytes([*packet.get(i + 1)?, *packet.get(i + 2)?]);
            return Some((opcode, Some(t)));
        }
        if len & 0xc0 != 0 {
            return Some((opcode, None));
        }
        i += usize::from(len) + 1;
    }
    Some((opcode, None))
}

/// Answers a transfer or NOTIFY from `client`; `None`: an ordinary query
/// (or junk), for the chain.
pub fn intercept(f: &Forwarder, packet: &[u8], client: IpAddr, tcp: bool) -> Option<Vec<Vec<u8>>> {
    let (opcode, qtype) = peek(packet)?;
    // RFC 2136 UPDATE (G4.1c-3): the daemon's zone service answers it.
    if opcode == 5 {
        if let Some(u) = super::updater(f) {
            return Some(u(packet, client).into_iter().collect());
        }
        let m = Message::from_vec(packet).ok()?;
        return Some(error(&m, ResponseCode::NotImp).into_iter().collect());
    }
    let notify = opcode == 4;
    let transfer = opcode == 0
        && qtype
            .is_some_and(|t| t == u16::from(RecordType::AXFR) || t == u16::from(RecordType::IXFR));
    if !notify && !transfer {
        return None;
    }
    let m = Message::from_vec(packet).ok()?;
    let out = if notify {
        vec![notify_in(f, &m, client)]
    } else {
        serve(f, &m, client, tcp)
    };
    Some(out.into_iter().flatten().collect())
}

/// A bare reply to `m` with `rcode` (its question echoed).
fn error(m: &Message, rcode: ResponseCode) -> Option<Vec<u8>> {
    let mut r = Message::error_msg(m.metadata.id, m.metadata.op_code, rcode);
    r.add_queries(m.queries.clone());
    r.to_vec().ok()
}

fn soa_serial_of(r: &Record) -> Option<u32> {
    match &r.data {
        RData::SOA(s) => Some(s.serial),
        _ => None,
    }
}

/// RFC 1996 §3.10–§3.11, §4.7: a NOTIFY for one of our secondaries from
/// one of its primaries starts a refresh; the reply echoes it with AA.
fn notify_in(f: &Forwarder, m: &Message, client: IpAddr) -> Option<Vec<u8>> {
    let q = m.queries.first()?;
    if m.queries.len() != 1 || q.query_type() != RecordType::SOA {
        return error(m, ResponseCode::FormErr);
    }
    let key = key_of(q.name());
    let cfg = f.config();
    let zones = super::zones(f, &cfg);
    let Some(conf) = zones.conf.get(&key) else {
        return error(m, NOTAUTH);
    };
    let from = client.to_canonical();
    if conf.ztype != ZoneType::Secondary || !conf.primaries.contains(&from) {
        // §3.10: not from a master of ours; BIND answers REFUSED too.
        return error(m, ResponseCode::Refused);
    }
    super::mark_notified(f, &key);
    let mut r = Message::response(m.metadata.id, OpCode::Notify);
    r.metadata.authoritative = true;
    r.add_queries(m.queries.clone());
    r.to_vec().ok()
}

/// RFC 5936 / RFC 1995: the whole zone (AXFR), or what changed (IXFR).
fn serve(f: &Forwarder, m: &Message, client: IpAddr, tcp: bool) -> Vec<Option<Vec<u8>>> {
    let Some(q) = m.queries.first() else {
        return vec![error(m, ResponseCode::FormErr)];
    };
    if q.query_class() != DNSClass::IN {
        return vec![error(m, ResponseCode::Refused)];
    }
    let key = key_of(q.name());
    let cfg = f.config();
    let zones = super::zones(f, &cfg);
    // RFC 5936 §2.2.1: not authoritative for that zone → NotAuth.
    let Some(conf) = zones.conf.get(&key) else {
        return vec![error(m, NOTAUTH)];
    };
    // RFC 5936 §5: only the networks in allow_transfer (none by default).
    if !conf.may_transfer(client) {
        return vec![error(m, ResponseCode::Refused)];
    }
    let Some(Ok(zone)) = super::find(f, &cfg, &key) else {
        return vec![error(m, ResponseCode::ServFail)];
    };
    if q.query_type() == RecordType::AXFR {
        // RFC 5936 §4.2: AXFR over UDP is not defined.
        if !tcp {
            return vec![error(m, ResponseCode::Refused)];
        }
        return messages(m, &axfr_records(&zone));
    }
    // RFC 1995 §3: the client's SOA is in the authority section.
    let Some(theirs) = m.authorities.iter().find_map(soa_serial_of) else {
        return vec![error(m, ResponseCode::FormErr)];
    };
    let records = if !serial_gt(zone.serial, theirs) {
        // RFC 1995 §4: up to date (or ahead of us): one SOA.
        vec![zone.soa.clone()]
    } else if let Some(diffs) = super::changes_since(f, &zone, theirs) {
        ixfr_records(&zone, &diffs)
    } else {
        // §4: no history from that serial: the whole zone, AXFR style.
        axfr_records(&zone)
    };
    let out = messages(m, &records);
    if !tcp
        && (out.len() != 1
            || out
                .first()
                .and_then(Option::as_ref)
                .is_none_or(|b| b.len() > udp_limit(m)))
    {
        // RFC 1995 §2: too big for UDP: the current SOA tells the client
        // to come back over TCP.
        return messages(m, std::slice::from_ref(&zone.soa));
    }
    out
}

fn udp_limit(m: &Message) -> usize {
    m.edns
        .as_ref()
        .map_or(UDP_BYTES, |e| usize::from(e.max_payload()).max(UDP_BYTES))
}

/// RFC 5936 §2.2: the SOA, every record, the SOA again.
pub fn axfr_records(z: &ZoneData) -> Vec<Record> {
    let mut out = Vec::with_capacity(z.len() + 2);
    out.push(z.soa.clone());
    out.extend(z.records().into_iter().cloned());
    out.push(z.soa.clone());
    out
}

/// RFC 1995 §4: the new SOA, then per change the old SOA, what went, the
/// new SOA, what came; the new SOA closes.
pub fn ixfr_records(z: &ZoneData, diffs: &[Diff]) -> Vec<Record> {
    let mut out = vec![z.soa.clone()];
    for d in diffs {
        out.push(d.from.clone());
        out.extend(d.removed.iter().cloned());
        out.push(d.to.clone());
        out.extend(d.added.iter().cloned());
    }
    out.push(z.soa.clone());
    out
}

/// The records in as many messages as they need: the question in the
/// first only, AA set (RFC 5936 §2.2, §2.2.1).
fn messages(m: &Message, records: &[Record]) -> Vec<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut cur: Vec<Record> = Vec::new();
    let mut bytes = 0usize;
    let flush = |cur: &mut Vec<Record>, first: bool| {
        let mut r = Message::response(m.metadata.id, OpCode::Query);
        r.metadata.authoritative = true;
        if first {
            r.add_queries(m.queries.clone());
        }
        r.add_answers(std::mem::take(cur));
        r.to_vec().ok()
    };
    for rec in records {
        let size = rec.to_bytes().map_or(0, |b| b.len());
        if !cur.is_empty() && bytes + size > MESSAGE_BYTES {
            out.push(flush(&mut cur, out.is_empty()));
            bytes = 0;
        }
        bytes += size;
        cur.push(rec.clone());
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(flush(&mut cur, out.is_empty()));
    }
    out
}

// ---- client side (secondaries) ----

fn zone_name(zone: &str) -> Result<Name, String> {
    super::fqdn(zone).ok_or_else(|| format!("'{zone}' is not a zone name"))
}

/// An SOA query for `zone`, without recursion (we ask a primary).
pub fn soa_query(zone: &str) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    m.add_query(Query::query(zone_name(zone)?, RecordType::SOA));
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// Checks a reply is ours: our id, a response, the opcode asked.
fn ours(m: &Message, id: u16, op: OpCode) -> Result<(), String> {
    if m.metadata.id != id || m.metadata.message_type != MessageType::Response {
        return Err("a reply that is not ours".into());
    }
    if m.metadata.op_code != op {
        return Err("a reply with another opcode".into());
    }
    if m.metadata.response_code != ResponseCode::NoError {
        return Err(format!("the server said {}", m.metadata.response_code));
    }
    Ok(())
}

/// The serial a primary has for `zone`. An answer without AA is not from
/// an authority of the zone (RFC 1996 §3.11 asks the SOA of the primary).
/// `Ok(None)`: truncated, ask again over TCP.
pub fn soa_serial(reply: &[u8], id: u16, zone: &str) -> Result<Option<u32>, String> {
    let m = Message::from_vec(reply).map_err(|e| format!("bad reply: {e}"))?;
    ours(&m, id, OpCode::Query)?;
    if m.metadata.truncation {
        return Ok(None);
    }
    if !m.metadata.authoritative {
        return Err(format!("the server is not authoritative for {zone}"));
    }
    m.answers
        .iter()
        .find(|r| key_of(&r.name) == zone)
        .and_then(soa_serial_of)
        .map(Some)
        .ok_or_else(|| format!("no SOA for {zone} in the reply"))
}

/// What to ask: IXFR from the serial we have (RFC 1995 §3), or AXFR.
pub fn xfr_query(zone: &str, have: Option<&ZoneData>) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    let name = zone_name(zone)?;
    match have {
        Some(z) => {
            m.add_query(Query::query(name, RecordType::IXFR));
            m.add_authority(z.soa.clone());
        }
        None => {
            m.add_query(Query::query(name, RecordType::AXFR));
        }
    }
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// A transfer coming in, one message at a time.
#[derive(Debug)]
pub struct Transfer {
    id: u16,
    zone: String,
    ixfr: bool,
    records: Vec<Record>,
    messages: usize,
    /// The new serial (the first SOA).
    serial: Option<u32>,
    /// IXFR: the new serial of the change being read, in its "added" part.
    adding: Option<u32>,
    done: bool,
}

impl Transfer {
    pub fn new(id: u16, zone: &str, ixfr: bool) -> Self {
        Self {
            id,
            zone: zone.to_owned(),
            ixfr,
            records: Vec::new(),
            messages: 0,
            serial: None,
            adding: None,
            done: false,
        }
    }

    /// One message; `Ok(true)` when the transfer is complete.
    pub fn push(&mut self, msg: &[u8]) -> Result<bool, String> {
        if self.done {
            return Ok(true);
        }
        let m = Message::from_vec(msg).map_err(|e| format!("bad transfer message: {e}"))?;
        ours(&m, self.id, OpCode::Query)?;
        if m.metadata.truncation {
            return Err("a truncated transfer message".into());
        }
        self.messages += 1;
        if self.messages > MAX_MESSAGES {
            return Err(format!("more than {MAX_MESSAGES} messages"));
        }
        let first_message = self.records.is_empty();
        let count = m.answers.len();
        for r in m.answers {
            self.take(r)?;
            if self.done {
                return Ok(true);
            }
        }
        // RFC 1995 §4: an IXFR answered with the SOA alone: up to date.
        if self.ixfr && first_message && count == 1 {
            self.done = true;
        }
        Ok(self.done)
    }

    fn take(&mut self, r: Record) -> Result<(), String> {
        if self.records.len() > 2 * MAX_ZONE_RECORDS {
            return Err(format!("more than {MAX_ZONE_RECORDS} records"));
        }
        let soa = soa_serial_of(&r);
        let Some(n) = self.serial else {
            // RFC 5936 §2.2: the first record is the zone's SOA.
            let s = soa.ok_or("the transfer does not start with the SOA")?;
            if key_of(&r.name) != self.zone {
                return Err("the transfer is of another zone".into());
            }
            self.serial = Some(s);
            self.records.push(r);
            return Ok(());
        };
        let second = self.records.len() == 1;
        self.records.push(r);
        if second && soa.is_some_and(|s| s != n) {
            // RFC 1995 §4: an old SOA second: incremental.
            self.adding = None;
            return Ok(());
        }
        let Some(s) = soa else {
            return Ok(());
        };
        if !self.is_incremental() {
            // AXFR style: the second SOA closes.
            if s == n {
                self.done = true;
            }
            return Ok(());
        }
        // Incremental: SOAs alternate old (deletions follow), new
        // (additions follow); the new serial again after the last
        // additions closes.
        match self.adding {
            Some(cur) if cur == n && s == n => self.done = true,
            Some(_) => self.adding = None,
            None => self.adding = Some(s),
        }
        Ok(())
    }

    fn is_incremental(&self) -> bool {
        match (self.records.get(1).and_then(soa_serial_of), self.serial) {
            (Some(s), Some(n)) => s != n,
            _ => false,
        }
    }

    /// The zone after the transfer; `Ok(None)`: we were up to date.
    pub fn finish(self, have: Option<&ZoneData>) -> Result<Option<ZoneData>, String> {
        if !self.done {
            return Err("the transfer ended early".into());
        }
        let n = self.serial.ok_or("an empty transfer")?;
        if self.records.len() == 1 {
            return if have.is_some_and(|h| !serial_gt(n, h.serial)) {
                Ok(None)
            } else {
                Err("the server sent only its SOA (try again over TCP)".into())
            };
        }
        if !self.is_incremental() {
            let mut recs = self.records;
            recs.pop();
            return ZoneData::from_records(recs).map(Some);
        }
        let have = have.ok_or("an incremental transfer, and no copy to apply it to")?;
        apply(have, &self.records).map(Some)
    }
}

/// Identity of a record for deletion (RFC 2136 §1.1.1: name without case,
/// class, type and data; the TTL aside).
fn identity(r: &Record) -> Vec<u8> {
    let mut c = r.clone();
    c.name = c.name.to_lowercase();
    c.ttl = 0;
    c.to_bytes().unwrap_or_default()
}

/// Applies an incremental transfer's changes to `have` (RFC 1995 §4).
fn apply(have: &ZoneData, recs: &[Record]) -> Result<ZoneData, String> {
    let mut set: HashMap<Vec<u8>, Record> = have
        .records()
        .into_iter()
        .map(|r| (identity(r), r.clone()))
        .collect();
    // recs: SOA(new) [SOA(old) del… SOA(new) add…]… SOA(new).
    let body = recs
        .get(1..recs.len().saturating_sub(1))
        .ok_or("a short incremental transfer")?;
    #[derive(PartialEq)]
    enum Phase {
        Start,
        Deleting,
        Adding,
    }
    let mut serial = have.serial;
    let mut phase = Phase::Start;
    for r in body {
        match (soa_serial_of(r), &phase) {
            // An old SOA: the change must start where the copy is.
            (Some(s), Phase::Start | Phase::Adding) => {
                if s != serial {
                    return Err(format!(
                        "the changes do not follow on: from {s}, the copy is at {serial}"
                    ));
                }
                phase = Phase::Deleting;
            }
            (Some(s), Phase::Deleting) => {
                serial = s;
                phase = Phase::Adding;
            }
            (None, Phase::Start) => return Err("a malformed incremental transfer".into()),
            (None, Phase::Deleting) => {
                set.remove(&identity(r));
            }
            (None, Phase::Adding) => {
                set.insert(identity(r), r.clone());
            }
        }
    }
    if phase != Phase::Adding {
        return Err("a malformed incremental transfer".into());
    }
    let soa = recs.first().cloned().ok_or("an empty transfer")?;
    if soa_serial_of(&soa) != Some(serial) {
        return Err("the changes do not end at the new serial".into());
    }
    ZoneData::new(soa, set.into_values().collect())
}

/// A NOTIFY for a changed zone (RFC 1996 §3.7: AA, the zone's SOA as the
/// question; the SOA itself in the answer as a hint).
pub fn notify_message(c: &Changed) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    m.metadata.op_code = OpCode::Notify;
    m.metadata.authoritative = true;
    m.add_query(Query::query(zone_name(&c.zone)?, RecordType::SOA));
    m.add_answer(c.soa.clone());
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// What a secondary said to our NOTIFY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ack {
    /// Taken (§4.7).
    Yes,
    /// Not ours (another id): keep waiting.
    Other,
    /// §3.12: NOTIMP or another error ends the exchange.
    No(String),
}

pub fn notify_ack(reply: &[u8], id: u16) -> Ack {
    let Ok(m) = Message::from_vec(reply) else {
        return Ack::Other;
    };
    if m.metadata.id != id
        || m.metadata.message_type != MessageType::Response
        || m.metadata.op_code != OpCode::Notify
    {
        return Ack::Other;
    }
    match m.metadata.response_code {
        ResponseCode::NoError => Ack::Yes,
        other => Ack::No(other.to_string()),
    }
}

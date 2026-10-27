//! The RPKI-to-Router protocol (RTR): RFC 8210 (version 1) and RFC 6810
//! (version 0), sans-IO. [`Client`] is the router side the daemon's
//! `rpki` service drives over TCP; [`Server`] answers queries from a fixed
//! set of VRPs (the lab's validator and the tests). The codec reads bytes
//! from the network: every length is checked before it is used, a PDU is
//! at most [`MAX_PDU`] bytes, and a bad one is an error, never a panic.
//!
//! No RFC errata exist for 8210 or 6810 (rfc-editor.org, 2026-10-27);
//! draft-ietf-sidrops-8210bis (version 2, ASPA) is not an RFC yet, so a
//! cache that offers it is answered with version 1 (§7).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::rpki::Vrp;

/// The newest version spoken (RFC 8210).
pub const VERSION: u8 = 1;
/// Largest PDU accepted. A prefix PDU is 32 bytes; only Router Key and
/// Error Report carry variable data (8210bis caps every PDU at 64 KiB).
pub const MAX_PDU: usize = 64 * 1024;

const SERIAL_NOTIFY: u8 = 0;
const SERIAL_QUERY: u8 = 1;
const RESET_QUERY: u8 = 2;
const CACHE_RESPONSE: u8 = 3;
const IPV4_PREFIX: u8 = 4;
const IPV6_PREFIX: u8 = 6;
const END_OF_DATA: u8 = 7;
const CACHE_RESET: u8 = 8;
const ROUTER_KEY: u8 = 9;
const ERROR_REPORT: u8 = 10;

/// RFC 8210 §12 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    CorruptData,
    InternalError,
    NoDataAvailable,
    InvalidRequest,
    UnsupportedVersion,
    UnsupportedPduType,
    WithdrawalOfUnknown,
    DuplicateAnnouncement,
    UnexpectedVersion,
    Other(u16),
}

impl ErrorCode {
    pub fn code(self) -> u16 {
        match self {
            ErrorCode::CorruptData => 0,
            ErrorCode::InternalError => 1,
            ErrorCode::NoDataAvailable => 2,
            ErrorCode::InvalidRequest => 3,
            ErrorCode::UnsupportedVersion => 4,
            ErrorCode::UnsupportedPduType => 5,
            ErrorCode::WithdrawalOfUnknown => 6,
            ErrorCode::DuplicateAnnouncement => 7,
            ErrorCode::UnexpectedVersion => 8,
            ErrorCode::Other(c) => c,
        }
    }

    pub fn from_code(c: u16) -> Self {
        match c {
            0 => ErrorCode::CorruptData,
            1 => ErrorCode::InternalError,
            2 => ErrorCode::NoDataAvailable,
            3 => ErrorCode::InvalidRequest,
            4 => ErrorCode::UnsupportedVersion,
            5 => ErrorCode::UnsupportedPduType,
            6 => ErrorCode::WithdrawalOfUnknown,
            7 => ErrorCode::DuplicateAnnouncement,
            8 => ErrorCode::UnexpectedVersion,
            c => ErrorCode::Other(c),
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            ErrorCode::CorruptData => "corrupt data",
            ErrorCode::InternalError => "internal error",
            ErrorCode::NoDataAvailable => "no data available",
            ErrorCode::InvalidRequest => "invalid request",
            ErrorCode::UnsupportedVersion => "unsupported protocol version",
            ErrorCode::UnsupportedPduType => "unsupported PDU type",
            ErrorCode::WithdrawalOfUnknown => "withdrawal of unknown record",
            ErrorCode::DuplicateAnnouncement => "duplicate announcement received",
            ErrorCode::UnexpectedVersion => "unexpected protocol version",
            ErrorCode::Other(_) => "unknown error",
        }
    }
}

/// One PDU (RFC 8210 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pdu {
    SerialNotify { session: u16, serial: u32 },
    SerialQuery { session: u16, serial: u32 },
    ResetQuery,
    CacheResponse { session: u16 },
    /// IPv4 and IPv6 Prefix; `announce` is flag bit 0 (§5.6).
    Prefix { announce: bool, vrp: Vrp },
    /// Version 1 carries the timers; version 0 only the serial.
    EndOfData { session: u16, serial: u32, timers: Option<Timers> },
    CacheReset,
    /// BGPsec router key (§5.10): counted, not used.
    RouterKey { announce: bool, asn: u32 },
    ErrorReport { code: ErrorCode, pdu: Vec<u8>, text: String },
}

/// The intervals of End of Data, seconds (RFC 8210 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timers {
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

impl Default for Timers {
    fn default() -> Self {
        use corerouter_model::rpki::{DEFAULT_EXPIRE, DEFAULT_REFRESH, DEFAULT_RETRY};
        Timers {
            refresh: DEFAULT_REFRESH,
            retry: DEFAULT_RETRY,
            expire: DEFAULT_EXPIRE,
        }
    }
}

impl Timers {
    /// Clamp to the §6 ranges: a cache cannot make the router poll every
    /// millisecond or keep data for a year.
    pub fn clamped(self) -> Self {
        use corerouter_model::rpki::{EXPIRE_RANGE, REFRESH_RANGE, RETRY_RANGE};
        let c = |v: u32, (lo, hi): (u32, u32)| v.clamp(lo, hi);
        Timers {
            refresh: c(self.refresh, REFRESH_RANGE),
            retry: c(self.retry, RETRY_RANGE),
            expire: c(self.expire, EXPIRE_RANGE),
        }
    }
}

/// Why bytes are not a PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub code: ErrorCode,
    pub reason: String,
}

fn bad(code: ErrorCode, reason: impl Into<String>) -> DecodeError {
    DecodeError {
        code,
        reason: reason.into(),
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The length of the PDU at the start of `buf`, once its header is there.
/// `Err` when the length cannot be right (shorter than a header, longer
/// than [`MAX_PDU`]): the stream cannot be resynchronized after that.
pub fn pdu_len(buf: &[u8]) -> Result<Option<usize>, DecodeError> {
    let Some(len) = be32(buf, 4) else {
        return Ok(None);
    };
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if !(8..=MAX_PDU).contains(&len) {
        return Err(bad(ErrorCode::CorruptData, format!("PDU length {len}")));
    }
    Ok(Some(len))
}

/// Decode one whole PDU (`b` is exactly its length). Returns the version
/// it was sent with.
pub fn decode(b: &[u8]) -> Result<(u8, Pdu), DecodeError> {
    let (Some(&version), Some(&kind), Some(field)) = (b.first(), b.get(1), be16(b, 2)) else {
        return Err(bad(ErrorCode::CorruptData, "short PDU"));
    };
    if version > VERSION {
        return Err(bad(ErrorCode::UnsupportedVersion, format!("version {version}")));
    }
    let need = |n: usize| {
        if b.len() == n {
            Ok(())
        } else {
            Err(bad(
                ErrorCode::CorruptData,
                format!("PDU type {kind} is {} bytes, not {n}", b.len()),
            ))
        }
    };
    let short = || bad(ErrorCode::CorruptData, "short PDU");
    let pdu = match kind {
        SERIAL_NOTIFY | SERIAL_QUERY => {
            need(12)?;
            let serial = be32(b, 8).ok_or_else(short)?;
            if kind == SERIAL_NOTIFY {
                Pdu::SerialNotify { session: field, serial }
            } else {
                Pdu::SerialQuery { session: field, serial }
            }
        }
        RESET_QUERY => {
            need(8)?;
            Pdu::ResetQuery
        }
        CACHE_RESPONSE => {
            need(8)?;
            Pdu::CacheResponse { session: field }
        }
        IPV4_PREFIX | IPV6_PREFIX => {
            let v6 = kind == IPV6_PREFIX;
            need(if v6 { 32 } else { 20 })?;
            let (Some(&flags), Some(&len), Some(&max)) = (b.get(8), b.get(9), b.get(10)) else {
                return Err(short());
            };
            let (addr, asn) = if v6 {
                let raw: [u8; 16] = b.get(12..28).and_then(|s| s.try_into().ok()).ok_or_else(short)?;
                (IpAddr::V6(Ipv6Addr::from(raw)), be32(b, 28).ok_or_else(short)?)
            } else {
                let raw: [u8; 4] = b.get(12..16).and_then(|s| s.try_into().ok()).ok_or_else(short)?;
                (IpAddr::V4(Ipv4Addr::from(raw)), be32(b, 16).ok_or_else(short)?)
            };
            // §5.6/§5.7: prefix length ≤ max length ≤ the family's bits.
            let vrp = Vrp::new(addr, len, max, asn).ok_or_else(|| {
                bad(
                    ErrorCode::CorruptData,
                    format!("bad prefix {addr}/{len} max {max} AS{asn}"),
                )
            })?;
            Pdu::Prefix {
                announce: flags & 1 == 1,
                vrp,
            }
        }
        END_OF_DATA => {
            let serial = be32(b, 8).ok_or_else(short)?;
            if version == 0 {
                need(12)?;
                Pdu::EndOfData {
                    session: field,
                    serial,
                    timers: None,
                }
            } else {
                need(24)?;
                Pdu::EndOfData {
                    session: field,
                    serial,
                    timers: Some(Timers {
                        refresh: be32(b, 12).ok_or_else(short)?,
                        retry: be32(b, 16).ok_or_else(short)?,
                        expire: be32(b, 20).ok_or_else(short)?,
                    }),
                }
            }
        }
        CACHE_RESET => {
            need(8)?;
            Pdu::CacheReset
        }
        ROUTER_KEY if version >= 1 => {
            // Header, 20-byte SKI, AS, and a key of at least one byte.
            if b.len() < 8 + 20 + 4 + 1 {
                return Err(short());
            }
            let flags = b.get(2).copied().unwrap_or(0);
            Pdu::RouterKey {
                announce: flags & 1 == 1,
                asn: be32(b, 28).ok_or_else(short)?,
            }
        }
        ERROR_REPORT => {
            let plen = usize::try_from(be32(b, 8).ok_or_else(short)?).unwrap_or(usize::MAX);
            let pdu_end = 12usize.checked_add(plen).filter(|e| *e + 4 <= b.len()).ok_or_else(short)?;
            let pdu = b.get(12..pdu_end).ok_or_else(short)?.to_vec();
            let tlen = usize::try_from(be32(b, pdu_end).ok_or_else(short)?).unwrap_or(usize::MAX);
            let text_at = pdu_end + 4;
            if text_at.checked_add(tlen) != Some(b.len()) {
                return Err(bad(ErrorCode::CorruptData, "error report lengths do not add up"));
            }
            let text = b.get(text_at..).map(String::from_utf8_lossy).unwrap_or_default();
            Pdu::ErrorReport {
                code: ErrorCode::from_code(field),
                pdu,
                text: text.chars().take(200).collect(),
            }
        }
        other => {
            return Err(bad(
                ErrorCode::UnsupportedPduType,
                format!("PDU type {other} (version {version})"),
            ));
        }
    };
    Ok((version, pdu))
}

fn header(out: &mut Vec<u8>, version: u8, kind: u8, field: u16, len: u32) {
    out.push(version);
    out.push(kind);
    out.extend_from_slice(&field.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
}

/// Encode `pdu` for `version` (0 or 1).
pub fn encode(version: u8, pdu: &Pdu, out: &mut Vec<u8>) {
    match pdu {
        Pdu::SerialNotify { session, serial } | Pdu::SerialQuery { session, serial } => {
            let kind = if matches!(pdu, Pdu::SerialNotify { .. }) {
                SERIAL_NOTIFY
            } else {
                SERIAL_QUERY
            };
            header(out, version, kind, *session, 12);
            out.extend_from_slice(&serial.to_be_bytes());
        }
        Pdu::ResetQuery => header(out, version, RESET_QUERY, 0, 8),
        Pdu::CacheResponse { session } => header(out, version, CACHE_RESPONSE, *session, 8),
        Pdu::Prefix { announce, vrp } => {
            let v6 = vrp.is_v6();
            header(
                out,
                version,
                if v6 { IPV6_PREFIX } else { IPV4_PREFIX },
                0,
                if v6 { 32 } else { 20 },
            );
            out.extend_from_slice(&[u8::from(*announce), vrp.prefix_len(), vrp.max_len, 0]);
            match vrp.addr() {
                IpAddr::V4(a) => out.extend_from_slice(&a.octets()),
                IpAddr::V6(a) => out.extend_from_slice(&a.octets()),
            }
            out.extend_from_slice(&vrp.asn.to_be_bytes());
        }
        Pdu::EndOfData {
            session,
            serial,
            timers,
        } => match (version, timers.unwrap_or_default()) {
            // Version 1 always carries the timers (§5.8).
            (1.., t) => {
                header(out, version, END_OF_DATA, *session, 24);
                for v in [*serial, t.refresh, t.retry, t.expire] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            _ => {
                header(out, version, END_OF_DATA, *session, 12);
                out.extend_from_slice(&serial.to_be_bytes());
            }
        },
        Pdu::CacheReset => header(out, version, CACHE_RESET, 0, 8),
        Pdu::RouterKey { .. } => {}
        Pdu::ErrorReport { code, pdu, text } => {
            let pdu = pdu.get(..pdu.len().min(MAX_PDU / 2)).unwrap_or_default();
            let text = text.get(..text.len().min(1024)).unwrap_or_default();
            let len = 16 + pdu.len() + text.len();
            header(out, version, ERROR_REPORT, code.code(), u32::try_from(len).unwrap_or(u32::MAX));
            out.extend_from_slice(&u32::try_from(pdu.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(pdu);
            out.extend_from_slice(&u32::try_from(text.len()).unwrap_or(0).to_be_bytes());
            out.extend_from_slice(text.as_bytes());
        }
    }
}

/// Where a [`Client`] is (RouterOS `/routing rpki session` state names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not connected.
    Idle,
    /// A query is out, no Cache Response yet.
    Connecting,
    /// Receiving the data of a response.
    Loading,
    /// The last response ended with End of Data.
    Sync,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Connecting => "connecting",
            State::Loading => "loading",
            State::Sync => "sync",
        }
    }
}

/// What the client asks of its driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Write these bytes to the cache.
    Send(Vec<u8>),
    /// New data is in force (End of Data); the counts of the change.
    Synced { serial: u32, announced: usize, withdrawn: usize },
    /// The cache has news (Serial Notify): poll now.
    Notified,
    /// The cache has no data yet (Error Report "No Data Available", §8):
    /// try again after the retry interval, keeping what is held.
    NoData,
    /// The session must be closed (after sending the bytes before it):
    /// a fatal error (§8, §12). The data held stays until it expires.
    Close(String),
}

/// The router side of one RTR session. The driver connects, sends
/// [`Client::query`], then feeds every byte read to [`Client::feed`] and
/// carries out the events. The VRPs change only at End of Data, all at
/// once (§5.8: a router never sees half an update).
#[derive(Debug, Clone)]
pub struct Client {
    version: u8,
    session: Option<u16>,
    serial: Option<u32>,
    vrps: HashSet<Vrp>,
    keys: u64,
    pending: Option<Pending>,
    timers: Timers,
    state: State,
    buf: Vec<u8>,
    /// The version was lowered once in this session (§7).
    downgraded: bool,
}

#[derive(Debug, Clone, Default)]
struct Pending {
    /// Answer to a Reset Query: a whole new set.
    reset: bool,
    announce: Vec<Vrp>,
    withdraw: Vec<Vrp>,
    keys: i64,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Client {
            version: VERSION,
            session: None,
            serial: None,
            vrps: HashSet::new(),
            keys: 0,
            pending: None,
            timers: Timers::default(),
            state: State::Idle,
            buf: Vec::new(),
            downgraded: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn session(&self) -> Option<u16> {
        self.session
    }

    pub fn serial(&self) -> Option<u32> {
        self.serial
    }

    pub fn timers(&self) -> Timers {
        self.timers
    }

    pub fn router_keys(&self) -> u64 {
        self.keys
    }

    pub fn vrps(&self) -> &HashSet<Vrp> {
        &self.vrps
    }

    /// The connection is gone: what was half received is dropped, the
    /// data held stays (until the driver lets it expire).
    pub fn disconnected(&mut self) {
        self.state = State::Idle;
        self.pending = None;
        self.buf.clear();
    }

    /// Drop the data (it expired, RFC 8210 §6): the next query is a
    /// Reset Query.
    pub fn expire(&mut self) {
        self.vrps.clear();
        self.keys = 0;
        self.session = None;
        self.serial = None;
    }

    /// The query to send now: Serial Query when the session and serial
    /// are known (§8.2), Reset Query otherwise (§8.1).
    pub fn query(&mut self) -> Vec<u8> {
        let pdu = match (self.session, self.serial) {
            (Some(session), Some(serial)) => Pdu::SerialQuery { session, serial },
            _ => Pdu::ResetQuery,
        };
        self.state = State::Connecting;
        let mut out = Vec::new();
        encode(self.version, &pdu, &mut out);
        out
    }

    fn fatal(&mut self, code: ErrorCode, offending: &[u8], why: &str, events: &mut Vec<Event>) {
        let mut out = Vec::new();
        encode(
            self.version,
            &Pdu::ErrorReport {
                code,
                pdu: offending.to_vec(),
                text: why.to_owned(),
            },
            &mut out,
        );
        events.push(Event::Send(out));
        events.push(Event::Close(format!("{}: {why}", code.text())));
        self.disconnected();
    }

    /// Feed bytes read from the cache.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        self.buf.extend_from_slice(bytes);
        loop {
            let len = match pdu_len(&self.buf) {
                Ok(Some(len)) => len,
                Ok(None) => break,
                Err(e) => {
                    let head = self.buf.get(..8).unwrap_or_default().to_vec();
                    self.fatal(e.code, &head, &e.reason, &mut events);
                    break;
                }
            };
            if self.buf.len() < len {
                break;
            }
            let raw: Vec<u8> = self.buf.drain(..len).collect();
            self.handle(&raw, &mut events);
            if matches!(events.last(), Some(Event::Close(_))) {
                break;
            }
        }
        events
    }

    fn handle(&mut self, raw: &[u8], events: &mut Vec<Event>) {
        let (version, pdu) = match decode(raw) {
            Ok(v) => v,
            Err(e) => return self.fatal(e.code, raw, &e.reason, events),
        };
        // §7: the cache answers our first query with our version or with
        // an Unsupported Version error carrying its own.
        if version != self.version {
            if let Pdu::ErrorReport {
                code: ErrorCode::UnsupportedVersion,
                ..
            } = pdu
                && version < self.version
                && !self.downgraded
                && self.session.is_none()
            {
                self.version = version;
                self.downgraded = true;
                events.push(Event::Close(format!(
                    "the cache speaks RTR version {version}; reconnecting with it"
                )));
                self.disconnected();
                return;
            }
            return self.fatal(
                ErrorCode::UnexpectedVersion,
                raw,
                &format!("version {version} in a version {} session", self.version),
                events,
            );
        }
        match pdu {
            Pdu::SerialNotify { .. } => {
                if self.state == State::Sync || self.state == State::Idle {
                    events.push(Event::Notified);
                }
            }
            Pdu::CacheResponse { session } => {
                let reset = self.session != Some(session) || self.serial.is_none();
                if self.session.is_some() && self.session != Some(session) && self.state == State::Connecting {
                    // §5.1: a new Session ID means the cache restarted; what
                    // we hold is from another session. Ask for all of it.
                    self.session = None;
                    self.serial = None;
                    events.push(Event::Send(self.query()));
                    return;
                }
                self.session = Some(session);
                self.pending = Some(Pending {
                    reset,
                    ..Pending::default()
                });
                self.state = State::Loading;
            }
            Pdu::Prefix { announce, vrp } => {
                let Some(p) = self.pending.as_mut() else {
                    return self.fatal(ErrorCode::InvalidRequest, raw, "prefix outside a response", events);
                };
                if announce {
                    p.announce.push(vrp);
                } else {
                    p.withdraw.push(vrp);
                }
            }
            Pdu::RouterKey { announce, .. } => {
                if let Some(p) = self.pending.as_mut() {
                    p.keys += if announce { 1 } else { -1 };
                }
            }
            Pdu::EndOfData {
                session,
                serial,
                timers,
            } => {
                let Some(p) = self.pending.take() else {
                    return self.fatal(ErrorCode::InvalidRequest, raw, "End of Data outside a response", events);
                };
                if Some(session) != self.session {
                    return self.fatal(ErrorCode::CorruptData, raw, "End of Data of another session", events);
                }
                match self.apply(p) {
                    Ok((announced, withdrawn)) => {
                        self.serial = Some(serial);
                        if let Some(t) = timers {
                            self.timers = t.clamped();
                        }
                        self.state = State::Sync;
                        events.push(Event::Synced {
                            serial,
                            announced,
                            withdrawn,
                        });
                    }
                    Err((code, why)) => self.fatal(code, raw, &why, events),
                }
            }
            Pdu::CacheReset => {
                // §5.9: the cache cannot serve that serial; start over.
                self.serial = None;
                self.session = None;
                self.pending = None;
                events.push(Event::Send(self.query()));
            }
            Pdu::ErrorReport { code, text, .. } => {
                self.pending = None;
                if code == ErrorCode::NoDataAvailable {
                    self.state = State::Idle;
                    events.push(Event::NoData);
                } else {
                    events.push(Event::Close(format!("the cache reported {}: {text}", code.text())));
                    self.disconnected();
                }
            }
            Pdu::SerialQuery { .. } | Pdu::ResetQuery => {
                self.fatal(ErrorCode::InvalidRequest, raw, "a query sent to the router", events)
            }
        }
    }

    /// Apply a whole response. §5.6: an announcement of a VRP already held
    /// or a withdrawal of one not held is an error (and the data held
    /// stays as it was).
    fn apply(&mut self, p: Pending) -> Result<(usize, usize), (ErrorCode, String)> {
        if p.reset {
            let mut next = HashSet::with_capacity(p.announce.len());
            for v in &p.announce {
                if !next.insert(*v) {
                    return Err((ErrorCode::DuplicateAnnouncement, format!("{v} announced twice")));
                }
            }
            let n = next.len();
            self.vrps = next;
            self.keys = u64::try_from(p.keys.max(0)).unwrap_or(0);
            return Ok((n, 0));
        }
        for v in &p.withdraw {
            if !self.vrps.contains(v) {
                return Err((ErrorCode::WithdrawalOfUnknown, format!("{v} withdrawn but not held")));
            }
        }
        for v in &p.announce {
            if self.vrps.contains(v) && !p.withdraw.contains(v) {
                return Err((ErrorCode::DuplicateAnnouncement, format!("{v} announced but already held")));
            }
        }
        for v in &p.withdraw {
            self.vrps.remove(v);
        }
        for v in &p.announce {
            self.vrps.insert(*v);
        }
        self.keys = u64::try_from((i64::try_from(self.keys).unwrap_or(0) + p.keys).max(0)).unwrap_or(0);
        Ok((p.announce.len(), p.withdraw.len()))
    }
}

/// The cache side, for a fixed set of VRPs that may be replaced: answers
/// Reset and Serial Queries (a serial it does not know gets Cache Reset).
#[derive(Debug, Clone)]
pub struct Server {
    pub session: u16,
    pub serial: u32,
    pub timers: Timers,
    vrps: Vec<Vrp>,
    /// The set before the last change, with its serial: a router one
    /// serial behind gets the difference (§8.2).
    previous: Option<(u32, Vec<Vrp>)>,
}

impl Server {
    pub fn new(session: u16, vrps: Vec<Vrp>) -> Self {
        Server {
            session,
            serial: 1,
            timers: Timers::default(),
            vrps,
            previous: None,
        }
    }

    pub fn vrps(&self) -> &[Vrp] {
        &self.vrps
    }

    /// Replace the data: the serial goes up and the Serial Notify to send
    /// to every connected router is returned (§8.4).
    pub fn replace(&mut self, vrps: Vec<Vrp>, version: u8) -> Vec<u8> {
        let old = std::mem::replace(&mut self.vrps, vrps);
        self.previous = Some((self.serial, old));
        self.serial = self.serial.wrapping_add(1);
        let mut out = Vec::new();
        encode(
            version,
            &Pdu::SerialNotify {
                session: self.session,
                serial: self.serial,
            },
            &mut out,
        );
        out
    }

    /// The answer to one query PDU (whole). `Err` closes the session.
    pub fn answer(&self, raw: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
        let version = raw.first().copied().unwrap_or(VERSION).min(VERSION);
        let refuse = |code: ErrorCode, why: &str| {
            let mut out = Vec::new();
            encode(
                version,
                &Pdu::ErrorReport {
                    code,
                    pdu: raw.to_vec(),
                    text: why.to_owned(),
                },
                &mut out,
            );
            out
        };
        let (version, pdu) = decode(raw).map_err(|e| refuse(e.code, &e.reason))?;
        let mut out = Vec::new();
        let send = |set: &[Vrp], announce: bool, out: &mut Vec<u8>| {
            for v in set {
                encode(version, &Pdu::Prefix { announce, vrp: *v }, out);
            }
        };
        match pdu {
            Pdu::ResetQuery => {
                encode(version, &Pdu::CacheResponse { session: self.session }, &mut out);
                send(&self.vrps, true, &mut out);
            }
            Pdu::SerialQuery { session, serial } if session == self.session && serial == self.serial => {
                encode(version, &Pdu::CacheResponse { session: self.session }, &mut out);
            }
            Pdu::SerialQuery { session, serial }
                if session == self.session && self.previous.as_ref().is_some_and(|(s, _)| *s == serial) =>
            {
                encode(version, &Pdu::CacheResponse { session: self.session }, &mut out);
                if let Some((_, old)) = &self.previous {
                    let now: HashSet<&Vrp> = self.vrps.iter().collect();
                    let before: HashSet<&Vrp> = old.iter().collect();
                    let gone: Vec<Vrp> = old.iter().filter(|v| !now.contains(v)).copied().collect();
                    let new: Vec<Vrp> = self.vrps.iter().filter(|v| !before.contains(v)).copied().collect();
                    send(&gone, false, &mut out);
                    send(&new, true, &mut out);
                }
            }
            Pdu::SerialQuery { .. } => {
                encode(version, &Pdu::CacheReset, &mut out);
                return Ok(out);
            }
            _ => return Err(refuse(ErrorCode::InvalidRequest, "not a query")),
        }
        encode(
            version,
            &Pdu::EndOfData {
                session: self.session,
                serial: self.serial,
                timers: Some(self.timers),
            },
            &mut out,
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vrp(s: &str, max: u8, asn: u32) -> Vrp {
        let (a, l) = s.split_once('/').unwrap();
        Vrp::new(a.parse().unwrap(), l.parse().unwrap(), max, asn).unwrap()
    }

    #[test]
    fn pdus_round_trip() {
        let all = [
            Pdu::SerialNotify { session: 7, serial: 9 },
            Pdu::SerialQuery { session: 7, serial: 9 },
            Pdu::ResetQuery,
            Pdu::CacheResponse { session: 7 },
            Pdu::Prefix { announce: true, vrp: vrp("192.0.2.0/24", 24, 64500) },
            Pdu::Prefix { announce: false, vrp: vrp("2001:db8::/32", 48, 64501) },
            Pdu::EndOfData { session: 7, serial: 9, timers: Some(Timers { refresh: 60, retry: 30, expire: 600 }) },
            Pdu::CacheReset,
            Pdu::ErrorReport { code: ErrorCode::NoDataAvailable, pdu: vec![1, 2], text: "warming up".into() },
        ];
        for p in &all {
            let mut b = Vec::new();
            encode(1, p, &mut b);
            assert_eq!(pdu_len(&b).unwrap(), Some(b.len()), "{p:?}");
            assert_eq!(decode(&b).unwrap(), (1, p.clone()));
        }
        // Version 0 End of Data: 12 bytes, no timers (RFC 6810 §5.8).
        let mut b = Vec::new();
        encode(0, &Pdu::EndOfData { session: 1, serial: 2, timers: Some(Timers::default()) }, &mut b);
        assert_eq!(b.len(), 12);
        assert_eq!(decode(&b).unwrap(), (0, Pdu::EndOfData { session: 1, serial: 2, timers: None }));
    }

    #[test]
    fn rfc8210_wire_examples() {
        // §5.6 IPv4 Prefix: version 1, type 4, zero, length 20, flags 1,
        // 24, 24, zero, 192.0.2.0, AS 64496.
        let b = [1, 4, 0, 0, 0, 0, 0, 20, 1, 24, 24, 0, 192, 0, 2, 0, 0, 0, 0xfb, 0xf0];
        assert_eq!(
            decode(&b).unwrap().1,
            Pdu::Prefix { announce: true, vrp: vrp("192.0.2.0/24", 24, 64496) }
        );
        // §5.4 Reset Query is the 8-byte header alone.
        let mut q = Vec::new();
        encode(1, &Pdu::ResetQuery, &mut q);
        assert_eq!(q, [1, 2, 0, 0, 0, 0, 0, 8]);
    }

    #[test]
    fn hostile_pdus_are_errors() {
        // Max length below the prefix length (§5.6).
        let b = [1, 4, 0, 0, 0, 0, 0, 20, 1, 24, 16, 0, 192, 0, 2, 0, 0, 0, 0, 1];
        assert_eq!(decode(&b).unwrap_err().code, ErrorCode::CorruptData);
        // /33 in IPv4.
        let b = [1, 4, 0, 0, 0, 0, 0, 20, 1, 33, 33, 0, 192, 0, 2, 0, 0, 0, 0, 1];
        assert!(decode(&b).is_err());
        // Wrong length for the type, absurd length, unknown type, version 2.
        assert!(decode(&[1, 2, 0, 0, 0, 0, 0, 9, 0]).is_err());
        assert!(pdu_len(&[1, 2, 0, 0, 0xff, 0, 0, 0]).is_err());
        assert!(pdu_len(&[1, 2, 0, 0, 0, 0, 0, 3]).is_err());
        assert_eq!(decode(&[1, 99, 0, 0, 0, 0, 0, 8]).unwrap_err().code, ErrorCode::UnsupportedPduType);
        assert_eq!(decode(&[2, 2, 0, 0, 0, 0, 0, 8]).unwrap_err().code, ErrorCode::UnsupportedVersion);
        // Error report whose inner lengths lie.
        let b = [1, 10, 0, 0, 0, 0, 0, 16, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        assert!(decode(&b).is_err());
    }

    #[test]
    fn client_and_server_sync_reset_then_serial() {
        let mut server = Server::new(42, vec![vrp("192.0.2.0/24", 24, 64500), vrp("2001:db8::/32", 48, 64501)]);
        let mut c = Client::new();
        let q = c.query();
        assert_eq!(decode(&q).unwrap().1, Pdu::ResetQuery);
        // Fed one byte at a time: PDUs straddle reads.
        let a = server.answer(&q).unwrap();
        let mut ev = Vec::new();
        for byte in a {
            ev.extend(c.feed(&[byte]));
        }
        assert_eq!(ev, [Event::Synced { serial: 1, announced: 2, withdrawn: 0 }]);
        assert_eq!((c.state(), c.session(), c.serial(), c.vrps().len()), (State::Sync, Some(42), Some(1), 2));
        // The cache changes: Serial Notify, Serial Query, the difference.
        let notify = server.replace(vec![vrp("192.0.2.0/24", 24, 64500), vrp("198.51.100.0/22", 24, 64502)], 1);
        assert_eq!(c.feed(&notify), [Event::Notified]);
        let q = c.query();
        assert_eq!(decode(&q).unwrap().1, Pdu::SerialQuery { session: 42, serial: 1 });
        let ev = c.feed(&server.answer(&q).unwrap());
        assert_eq!(ev, [Event::Synced { serial: 2, announced: 1, withdrawn: 1 }]);
        assert!(c.vrps().contains(&vrp("198.51.100.0/22", 24, 64502)));
        assert!(!c.vrps().contains(&vrp("2001:db8::/32", 48, 64501)));
        // A serial the cache no longer has: Cache Reset, then Reset Query.
        server.replace(vec![], 1);
        server.replace(vec![vrp("203.0.113.0/24", 24, 64503)], 1);
        let q = c.query();
        let ev = c.feed(&server.answer(&q).unwrap());
        let Some(Event::Send(again)) = ev.first() else { panic!("{ev:?}") };
        assert_eq!(decode(again).unwrap().1, Pdu::ResetQuery);
        let ev = c.feed(&server.answer(again).unwrap());
        assert_eq!(ev, [Event::Synced { serial: 4, announced: 1, withdrawn: 0 }]);
        assert_eq!(c.vrps().len(), 1);
    }

    #[test]
    fn half_an_update_is_never_seen_and_bad_ones_are_refused() {
        let mut c = Client::new();
        let _ = c.query();
        let mut a = Vec::new();
        encode(1, &Pdu::CacheResponse { session: 1 }, &mut a);
        encode(1, &Pdu::Prefix { announce: true, vrp: vrp("192.0.2.0/24", 24, 1) }, &mut a);
        assert!(c.feed(&a).is_empty());
        assert!(c.vrps().is_empty(), "applied before End of Data");
        let mut e = Vec::new();
        encode(1, &Pdu::EndOfData { session: 1, serial: 5, timers: Some(Timers { refresh: 0, retry: 99_999, expire: 10 }) }, &mut e);
        assert_eq!(c.feed(&e), [Event::Synced { serial: 5, announced: 1, withdrawn: 0 }]);
        // §6 ranges enforced on the cache's timers.
        assert_eq!(c.timers(), Timers { refresh: 1, retry: 7_200, expire: 600 });
        // Withdrawing what is not held: Error Report and close; data kept.
        let q = c.query();
        assert_eq!(decode(&q).unwrap().1, Pdu::SerialQuery { session: 1, serial: 5 });
        let mut a = Vec::new();
        encode(1, &Pdu::CacheResponse { session: 1 }, &mut a);
        encode(1, &Pdu::Prefix { announce: false, vrp: vrp("198.51.100.0/24", 24, 1) }, &mut a);
        encode(1, &Pdu::EndOfData { session: 1, serial: 6, timers: None }, &mut a);
        let ev = c.feed(&a);
        let Some(Event::Send(report)) = ev.first() else { panic!("{ev:?}") };
        let got = decode(report);
        assert!(matches!(got, Ok((_, Pdu::ErrorReport { code: ErrorCode::WithdrawalOfUnknown, .. }))), "{got:?}");
        assert!(matches!(ev.last(), Some(Event::Close(_))));
        assert_eq!((c.vrps().len(), c.serial()), (1, Some(5)));
    }

    #[test]
    fn version_is_negotiated_down_once() {
        let mut c = Client::new();
        let _ = c.query();
        let mut a = Vec::new();
        encode(0, &Pdu::ErrorReport { code: ErrorCode::UnsupportedVersion, pdu: vec![], text: String::new() }, &mut a);
        let ev = c.feed(&a);
        assert!(matches!(ev.as_slice(), [Event::Close(m)] if m.contains("version 0")));
        assert_eq!(c.version(), 0);
        let q = c.query();
        assert_eq!(q.first(), Some(&0));
        // A version-1 PDU in a version-0 session is an error.
        let mut a = Vec::new();
        encode(1, &Pdu::CacheResponse { session: 1 }, &mut a);
        let ev = c.feed(&a);
        assert!(matches!(ev.last(), Some(Event::Close(m)) if m.contains("unexpected")));
    }

    #[test]
    fn no_data_keeps_the_session() {
        let mut c = Client::new();
        let _ = c.query();
        let mut a = Vec::new();
        encode(1, &Pdu::ErrorReport { code: ErrorCode::NoDataAvailable, pdu: vec![], text: String::new() }, &mut a);
        assert_eq!(c.feed(&a), [Event::NoData]);
    }
}

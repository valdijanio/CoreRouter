//! DHCPv6 messages (RFC 8415 §8, §21), written here instead of over
//! `dhcproto`: the format is a flat type-length-value list with a few
//! nested options, a hand-written parser is short, and it can be made
//! panic-free by construction (part 1 found two `panic`s in `dhcproto`'s
//! DHCPv4 decoder with hostile bytes; see `docs/dhcp-client.md` §5).
//!
//! - [`Outgoing`] → bytes: what the client sends (Solicit, Request, Renew,
//!   Rebind, Release);
//! - bytes → [`Incoming`]: what the client reads from an Advertise or a
//!   Reply, already checked (lengths, nesting, lifetimes);
//! - [`raw_options`] / [`describe`]: every option received, for
//!   `ipv6.dhcp-client.options`.
//!
//! Received packets are hostile input: [`decode`] refuses anything larger
//! than [`MAX_MESSAGE`], any option running past its parent, and never
//! panics (proptest below). Nesting is bounded: an IA holds at most
//! [`MAX_IA_ENTRIES`] addresses or prefixes, a message at most
//! [`MAX_OPTIONS`] options.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

pub use corerouter_hal::dhcp::MAX_MESSAGE;

/// Message types (RFC 8415 §7.3).
pub mod msg {
    pub const SOLICIT: u8 = 1;
    pub const ADVERTISE: u8 = 2;
    pub const REQUEST: u8 = 3;
    pub const CONFIRM: u8 = 4;
    pub const RENEW: u8 = 5;
    pub const REBIND: u8 = 6;
    pub const REPLY: u8 = 7;
    pub const RELEASE: u8 = 8;
    pub const DECLINE: u8 = 9;
    pub const RECONFIGURE: u8 = 10;
    pub const INFORMATION_REQUEST: u8 = 11;
    pub const RELAY_FORW: u8 = 12;
    pub const RELAY_REPL: u8 = 13;
}

/// Option codes (RFC 8415 §21 and the RFCs named).
pub mod opt {
    pub const CLIENTID: u16 = 1;
    pub const SERVERID: u16 = 2;
    pub const IA_NA: u16 = 3;
    pub const IA_TA: u16 = 4;
    pub const IAADDR: u16 = 5;
    pub const ORO: u16 = 6;
    pub const PREFERENCE: u16 = 7;
    pub const ELAPSED_TIME: u16 = 8;
    /// Relay Message (RFC 9915 §21.10).
    pub const RELAY_MSG: u16 = 9;
    pub const UNICAST: u16 = 12;
    pub const STATUS_CODE: u16 = 13;
    pub const RAPID_COMMIT: u16 = 14;
    pub const USER_CLASS: u16 = 15;
    pub const VENDOR_CLASS: u16 = 16;
    pub const VENDOR_OPTS: u16 = 17;
    /// Interface-Id (RFC 9915 §21.18).
    pub const INTERFACE_ID: u16 = 18;
    pub const RECONF_ACCEPT: u16 = 20;
    /// RFC 3646.
    pub const DNS_SERVERS: u16 = 23;
    pub const DOMAIN_LIST: u16 = 24;
    pub const IA_PD: u16 = 25;
    pub const IAPREFIX: u16 = 26;
    /// RFC 4075.
    pub const SNTP_SERVERS: u16 = 31;
    pub const INFORMATION_REFRESH_TIME: u16 = 32;
    /// RFC 4704.
    pub const CLIENT_FQDN: u16 = 39;
    /// RFC 5908.
    pub const NTP_SERVER: u16 = 56;
    /// RFC 6334 (DS-Lite).
    pub const AFTR_NAME: u16 = 64;
    /// RFC 6603.
    pub const PD_EXCLUDE: u16 = 67;
    pub const SOL_MAX_RT: u16 = 82;
    pub const INF_MAX_RT: u16 = 83;
}

/// Status codes (RFC 8415 §21.13).
pub mod status {
    pub const SUCCESS: u16 = 0;
    pub const UNSPEC_FAIL: u16 = 1;
    pub const NO_ADDRS_AVAIL: u16 = 2;
    pub const NO_BINDING: u16 = 3;
    pub const NOT_ON_LINK: u16 = 4;
    pub const USE_MULTICAST: u16 = 5;
    pub const NO_PREFIX_AVAIL: u16 = 6;

    pub fn name(code: u16) -> &'static str {
        match code {
            SUCCESS => "Success",
            UNSPEC_FAIL => "UnspecFail",
            NO_ADDRS_AVAIL => "NoAddrsAvail",
            NO_BINDING => "NoBinding",
            NOT_ON_LINK => "NotOnLink",
            USE_MULTICAST => "UseMulticast",
            NO_PREFIX_AVAIL => "NoPrefixAvail",
            _ => "unknown",
        }
    }
}

/// Options the client asks for (Option Request, RFC 8415 §21.7). SOL_MAX_RT
/// is required in a Solicit's ORO (§18.2.1).
pub const REQUESTED: [u16; 5] = [
    opt::DNS_SERVERS,
    opt::DOMAIN_LIST,
    opt::NTP_SERVER,
    opt::SNTP_SERVERS,
    opt::SOL_MAX_RT,
];

/// Options in one message, at any depth (hostile-input bound).
pub const MAX_OPTIONS: usize = 256;
/// Addresses or prefixes kept per IA.
pub const MAX_IA_ENTRIES: usize = 16;
/// DUIDs are at most 128 bytes after the type (RFC 8415 §11.1).
pub const MAX_DUID: usize = 130;
/// Infinite lifetime (RFC 8415 §7.7).
pub const INFINITY: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("message of {0} bytes is larger than {MAX_MESSAGE}")]
    TooLarge(usize),
    #[error("not a DHCPv6 message: {0}")]
    Malformed(String),
}

fn bad(why: impl Into<String>) -> CodecError {
    CodecError::Malformed(why.into())
}

/// `(code, data)` of each option in `data`, in order. Refuses an option
/// whose length runs past the end, and more than `budget` options.
pub(crate) fn split<'a>(
    data: &'a [u8],
    budget: &mut usize,
) -> Result<Vec<(u16, &'a [u8])>, CodecError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (Some(head), Some(tail)) = (rest.get(..4), rest.get(4..)) else {
            return Err(bad("truncated option header"));
        };
        let (Some(code), Some(len)) = (u16_at(head, 0), u16_at(head, 2)) else {
            return Err(bad("truncated option header"));
        };
        let len = usize::from(len);
        let body = tail
            .get(..len)
            .ok_or_else(|| bad(format!("option {code} runs past the end")))?;
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| bad(format!("more than {MAX_OPTIONS} options")))?;
        out.push((code, body));
        rest = tail.get(len..).unwrap_or(&[]);
    }
    Ok(out)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let b: [u8; 2] = data.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(b))
}

fn v6_at(data: &[u8], at: usize) -> Option<Ipv6Addr> {
    let b: [u8; 16] = data.get(at..at.checked_add(16)?)?.try_into().ok()?;
    Some(Ipv6Addr::from(b))
}

/// A Status Code option: code and message (control characters dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: u16,
    pub message: String,
}

impl Status {
    fn parse(data: &[u8]) -> Option<Self> {
        let code = u16_at(data, 0)?;
        let message = data
            .get(2..)
            .map(|m| clean(&String::from_utf8_lossy(m)))
            .unwrap_or_default();
        Some(Self { code, message })
    }

    pub fn text(&self) -> String {
        if self.message.is_empty() {
            status::name(self.code).to_owned()
        } else {
            format!("{} ({})", status::name(self.code), self.message)
        }
    }
}

/// An address of an IA_NA (IAADDR, §21.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaAddr {
    pub addr: Ipv6Addr,
    pub preferred: u32,
    pub valid: u32,
}

/// A prefix of an IA_PD (IAPREFIX, §21.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaPrefix {
    pub prefix: Ipv6Net,
    pub preferred: u32,
    pub valid: u32,
}

/// An IA_NA or IA_PD as received.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ia {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    /// Status inside the IA (absent = Success).
    pub status: Option<Status>,
    pub addrs: Vec<IaAddr>,
    pub prefixes: Vec<IaPrefix>,
    /// Entries left out, and why (RFC 8415 §18.2.10.1: "preferred > valid").
    pub dropped: Vec<String>,
}

impl Ia {
    pub fn status_code(&self) -> u16 {
        self.status.as_ref().map_or(status::SUCCESS, |s| s.code)
    }

    fn parse(code: u16, data: &[u8], budget: &mut usize) -> Result<Self, CodecError> {
        let (Some(iaid), Some(t1), Some(t2)) = (u32_at(data, 0), u32_at(data, 4), u32_at(data, 8))
        else {
            return Err(bad(format!("option {code}: shorter than 12 bytes")));
        };
        let mut ia = Ia {
            iaid,
            t1,
            t2,
            ..Ia::default()
        };
        for (sub, body) in split(data.get(12..).unwrap_or(&[]), budget)? {
            match (code, sub) {
                (_, opt::STATUS_CODE) => ia.status = Status::parse(body),
                (opt::IA_NA, opt::IAADDR) => {
                    let (Some(addr), Some(preferred), Some(valid)) =
                        (v6_at(body, 0), u32_at(body, 16), u32_at(body, 20))
                    else {
                        return Err(bad("IAADDR shorter than 24 bytes"));
                    };
                    // RFC 8415 §21.6: preferred > valid → discard the address.
                    if preferred > valid {
                        ia.dropped
                            .push(format!("{addr}: preferred lifetime > valid lifetime"));
                    } else if ia.addrs.len() < MAX_IA_ENTRIES {
                        ia.addrs.push(IaAddr {
                            addr,
                            preferred,
                            valid,
                        });
                    }
                }
                (opt::IA_PD, opt::IAPREFIX) => {
                    let (Some(preferred), Some(valid), Some(len), Some(addr)) = (
                        u32_at(body, 0),
                        u32_at(body, 4),
                        body.get(8).copied(),
                        v6_at(body, 9),
                    ) else {
                        return Err(bad("IAPREFIX shorter than 25 bytes"));
                    };
                    let Ok(prefix) = Ipv6Net::new(addr, len) else {
                        ia.dropped.push(format!("{addr}/{len}: bad prefix length"));
                        continue;
                    };
                    // RFC 8415 §21.22: same rule as for addresses.
                    if preferred > valid {
                        ia.dropped
                            .push(format!("{prefix}: preferred lifetime > valid lifetime"));
                    } else if ia.prefixes.len() < MAX_IA_ENTRIES {
                        ia.prefixes.push(IaPrefix {
                            prefix: prefix.trunc(),
                            preferred,
                            valid,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(ia)
    }
}

/// What the client reads from an Advertise or a Reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Incoming {
    pub kind: u8,
    pub xid: u32,
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    /// Preference (§21.8); absent = 0.
    pub preference: u8,
    pub rapid_commit: bool,
    /// Top-level status.
    pub status: Option<Status>,
    pub ia_na: Vec<Ia>,
    pub ia_pd: Vec<Ia>,
    pub dns: Vec<Ipv6Addr>,
    pub domains: Vec<String>,
    /// SOL_MAX_RT (§21.24), seconds, when in 60..=86400.
    pub sol_max_rt: Option<u32>,
    /// The server asked us to reconfigure: never accepted (we send no
    /// Reconfigure Accept, §18.2.1), only noted.
    pub reconfigure: bool,
}

impl Incoming {
    pub fn status_code(&self) -> u16 {
        self.status.as_ref().map_or(status::SUCCESS, |s| s.code)
    }
}

/// A raw message: type, transaction id and top-level options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raw<'a> {
    pub kind: u8,
    pub xid: u32,
    pub options: Vec<(u16, &'a [u8])>,
}

/// Split a client/server message (not a relay message) into its parts.
pub fn decode_raw(bytes: &[u8]) -> Result<Raw<'_>, CodecError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(CodecError::TooLarge(bytes.len()));
    }
    let (Some(&kind), Some(x)) = (bytes.first(), bytes.get(1..4)) else {
        return Err(bad("shorter than 4 bytes"));
    };
    if kind == msg::RELAY_FORW || kind == msg::RELAY_REPL || kind == 0 {
        return Err(bad(format!("message type {kind} is not for a client")));
    }
    let mut id = [0u8; 4];
    if let Some(low) = id.get_mut(1..) {
        low.copy_from_slice(x);
    }
    let xid = u32::from_be_bytes(id);
    let mut budget = MAX_OPTIONS;
    let options = split(bytes.get(4..).unwrap_or(&[]), &mut budget)?;
    Ok(Raw { kind, xid, options })
}

fn ip_list(data: &[u8]) -> Vec<Ipv6Addr> {
    data.as_chunks::<16>()
        .0
        .iter()
        .take(8)
        .map(|c| Ipv6Addr::from(*c))
        .collect()
}

/// RFC 1035 §3.1 names, uncompressed (RFC 8415 §10), one after the other.
pub fn domain_list(data: &[u8]) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut name = String::new();
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        if len == 0 {
            if !name.is_empty() {
                out.push(std::mem::take(&mut name));
            }
            rest = tail;
            continue;
        }
        // Labels are at most 63 bytes; 0xC0 would be compression.
        if len > 63 || name.len() > 253 {
            return None;
        }
        let label = tail.get(..usize::from(len))?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        rest = tail.get(usize::from(len)..)?;
        if out.len() >= 8 {
            break;
        }
    }
    if !name.is_empty() {
        // A last name without its root label: keep it (lenient, like dhcpcd).
        out.push(name);
    }
    Some(out)
}

/// Encode `name` (`a.b.c`) as an uncompressed DNS name.
pub fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let l = label.as_bytes().get(..label.len().min(63)).unwrap_or(&[]);
        out.push(u8::try_from(l.len()).unwrap_or(63));
        out.extend_from_slice(l);
    }
    out.push(0);
}

/// Decode an Advertise or Reply for a client. Anything else is refused.
pub fn decode(bytes: &[u8]) -> Result<Incoming, CodecError> {
    let raw = decode_raw(bytes)?;
    if !matches!(raw.kind, msg::ADVERTISE | msg::REPLY | msg::RECONFIGURE) {
        return Err(bad(format!(
            "message type {} is not for a client",
            raw.kind
        )));
    }
    let mut m = Incoming {
        kind: raw.kind,
        xid: raw.xid,
        reconfigure: raw.kind == msg::RECONFIGURE,
        ..Incoming::default()
    };
    let mut budget = MAX_OPTIONS.saturating_sub(raw.options.len());
    for (code, data) in raw.options {
        match code {
            opt::CLIENTID if data.len() <= MAX_DUID => m.client_id = Some(data.to_vec()),
            opt::SERVERID if !data.is_empty() && data.len() <= MAX_DUID => {
                m.server_id = Some(data.to_vec());
            }
            opt::PREFERENCE => m.preference = data.first().copied().unwrap_or(0),
            opt::RAPID_COMMIT => m.rapid_commit = true,
            opt::STATUS_CODE => m.status = Status::parse(data),
            opt::IA_NA => {
                let ia = Ia::parse(code, data, &mut budget)?;
                if m.ia_na.len() < MAX_IA_ENTRIES {
                    m.ia_na.push(ia);
                }
            }
            opt::IA_PD => {
                let ia = Ia::parse(code, data, &mut budget)?;
                if m.ia_pd.len() < MAX_IA_ENTRIES {
                    m.ia_pd.push(ia);
                }
            }
            opt::DNS_SERVERS => m.dns = ip_list(data),
            opt::DOMAIN_LIST => m.domains = domain_list(data).unwrap_or_default(),
            opt::SOL_MAX_RT => {
                // §21.24: values outside 60..=86400 are ignored.
                m.sol_max_rt = u32_at(data, 0).filter(|v| (60..=86_400).contains(v));
            }
            _ => {}
        }
    }
    Ok(m)
}

/// An IA the client puts in a message: what it holds (Renew, Rebind,
/// Release, Request after an Advertise) or a hint (Solicit).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IaReq {
    pub iaid: u32,
    pub addrs: Vec<Ipv6Addr>,
    pub prefixes: Vec<Ipv6Net>,
}

/// A message the client sends.
#[derive(Debug, Clone)]
pub struct Outgoing<'a> {
    pub kind: u8,
    pub xid: u32,
    pub client_id: &'a [u8],
    /// The chosen server (Request, Renew, Release; never Solicit/Rebind).
    pub server_id: Option<&'a [u8]>,
    /// Hundredths of a second since the exchange began (§21.9).
    pub elapsed_cs: u16,
    pub rapid_commit: bool,
    pub ia_na: Option<IaReq>,
    pub ia_pd: Option<IaReq>,
    /// Option Request; empty = none (Release carries none).
    pub oro: &'a [u16],
}

pub(crate) fn put(out: &mut Vec<u8>, code: u16, data: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(data);
}

impl Outgoing<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(self.kind);
        out.extend_from_slice(self.xid.to_be_bytes().get(1..).unwrap_or(&[0, 0, 0]));
        put(&mut out, opt::CLIENTID, self.client_id);
        if let Some(s) = self.server_id {
            put(&mut out, opt::SERVERID, s);
        }
        put(&mut out, opt::ELAPSED_TIME, &self.elapsed_cs.to_be_bytes());
        if self.rapid_commit {
            put(&mut out, opt::RAPID_COMMIT, &[]);
        }
        if !self.oro.is_empty() {
            let oro: Vec<u8> = self.oro.iter().flat_map(|c| c.to_be_bytes()).collect();
            put(&mut out, opt::ORO, &oro);
        }
        // §21.4: T1/T2 in a client's IA are 0 (the server decides).
        if let Some(ia) = &self.ia_na {
            let mut body = Vec::new();
            body.extend_from_slice(&ia.iaid.to_be_bytes());
            body.extend_from_slice(&[0; 8]);
            for a in &ia.addrs {
                let mut sub = a.octets().to_vec();
                sub.extend_from_slice(&[0; 8]);
                put(&mut body, opt::IAADDR, &sub);
            }
            put(&mut out, opt::IA_NA, &body);
        }
        if let Some(ia) = &self.ia_pd {
            let mut body = Vec::new();
            body.extend_from_slice(&ia.iaid.to_be_bytes());
            body.extend_from_slice(&[0; 8]);
            for p in &ia.prefixes {
                let mut sub = vec![0u8; 8];
                sub.push(p.prefix_len());
                sub.extend_from_slice(&p.network().octets());
                put(&mut body, opt::IAPREFIX, &sub);
            }
            put(&mut out, opt::IA_PD, &body);
        }
        out
    }
}

/// A client message as a server (or a test) reads it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientMsg {
    pub kind: u8,
    pub xid: u32,
    pub client_id: Option<Vec<u8>>,
    pub server_id: Option<Vec<u8>>,
    pub rapid_commit: bool,
    pub ia_na: Option<Ia>,
    pub ia_pd: Option<Ia>,
    pub elapsed_cs: Option<u16>,
    pub oro: Vec<u16>,
}

/// Decode what a client sends (Solicit … Information-request).
pub fn decode_client(bytes: &[u8]) -> Result<ClientMsg, CodecError> {
    let raw = decode_raw(bytes)?;
    if matches!(raw.kind, msg::ADVERTISE | msg::REPLY | msg::RECONFIGURE) {
        return Err(bad(format!(
            "message type {} is not from a client",
            raw.kind
        )));
    }
    let mut m = ClientMsg {
        kind: raw.kind,
        xid: raw.xid,
        ..ClientMsg::default()
    };
    let mut budget = MAX_OPTIONS.saturating_sub(raw.options.len());
    for (code, data) in raw.options {
        match code {
            opt::CLIENTID if data.len() <= MAX_DUID => m.client_id = Some(data.to_vec()),
            opt::SERVERID if data.len() <= MAX_DUID => m.server_id = Some(data.to_vec()),
            opt::RAPID_COMMIT => m.rapid_commit = true,
            opt::ELAPSED_TIME => m.elapsed_cs = u16_at(data, 0),
            opt::ORO => {
                m.oro = data
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .take(64)
                    .map(|c| u16::from_be_bytes(*c))
                    .collect();
            }
            opt::IA_NA if m.ia_na.is_none() => m.ia_na = Some(Ia::parse(code, data, &mut budget)?),
            opt::IA_PD if m.ia_pd.is_none() => m.ia_pd = Some(Ia::parse(code, data, &mut budget)?),
            _ => {}
        }
    }
    Ok(m)
}

/// Builds a message option by option (the lab server and the tests).
#[derive(Debug, Clone)]
pub struct Builder(Vec<u8>);

impl Builder {
    pub fn new(kind: u8, xid: u32) -> Self {
        let mut b = vec![kind];
        b.extend_from_slice(xid.to_be_bytes().get(1..).unwrap_or(&[0, 0, 0]));
        Self(b)
    }

    pub fn opt(mut self, code: u16, data: &[u8]) -> Self {
        put(&mut self.0, code, data);
        self
    }

    pub fn bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Body of an IA_NA: IAID, T1, T2 and the addresses `(addr, preferred,
/// valid)`, then `status` if any.
pub fn ia_na_body(
    iaid: u32,
    t1: u32,
    t2: u32,
    addrs: &[(Ipv6Addr, u32, u32)],
    st: Option<(u16, &str)>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&iaid.to_be_bytes());
    b.extend_from_slice(&t1.to_be_bytes());
    b.extend_from_slice(&t2.to_be_bytes());
    for (a, p, v) in addrs {
        let mut sub = a.octets().to_vec();
        sub.extend_from_slice(&p.to_be_bytes());
        sub.extend_from_slice(&v.to_be_bytes());
        put(&mut b, opt::IAADDR, &sub);
    }
    if let Some((code, text)) = st {
        put(&mut b, opt::STATUS_CODE, &status_body(code, text));
    }
    b
}

/// Body of an IA_PD, like [`ia_na_body`] with `(prefix, preferred, valid)`.
pub fn ia_pd_body(
    iaid: u32,
    t1: u32,
    t2: u32,
    prefixes: &[(Ipv6Net, u32, u32)],
    st: Option<(u16, &str)>,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&iaid.to_be_bytes());
    b.extend_from_slice(&t1.to_be_bytes());
    b.extend_from_slice(&t2.to_be_bytes());
    for (p, pl, vl) in prefixes {
        let mut sub = pl.to_be_bytes().to_vec();
        sub.extend_from_slice(&vl.to_be_bytes());
        sub.push(p.prefix_len());
        sub.extend_from_slice(&p.network().octets());
        put(&mut b, opt::IAPREFIX, &sub);
    }
    if let Some((code, text)) = st {
        put(&mut b, opt::STATUS_CODE, &status_body(code, text));
    }
    b
}

pub fn status_body(code: u16, text: &str) -> Vec<u8> {
    let mut b = code.to_be_bytes().to_vec();
    b.extend_from_slice(text.as_bytes());
    b
}

/// Every top-level option of `bytes`, as (code, data), for
/// `ipv6.dhcp-client.options`. Empty when the message does not parse.
pub fn raw_options(bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
    decode_raw(bytes)
        .map(|r| {
            r.options
                .into_iter()
                .map(|(c, d)| (c, d.to_vec()))
                .collect()
        })
        .unwrap_or_default()
}

/// `0x…` of `data`.
pub fn hex(data: &[u8]) -> String {
    crate::v4::hex(data)
}

/// A DUID for people: `type: link-layer` + the MAC, or hex.
pub fn duid_text(duid: &[u8]) -> String {
    match duid_mac(duid) {
        Some(mac) => format!("{} ({})", hex(duid), corerouter_model::MacAddr(mac)),
        None => hex(duid),
    }
}

/// The Ethernet address inside a DUID-LLT (1) or DUID-LL (3), if any.
pub fn duid_mac(duid: &[u8]) -> Option<[u8; 6]> {
    let kind = u16_at(duid, 0)?;
    let hw = u16_at(duid, 2)?;
    let at = match kind {
        1 => 8,
        3 => 4,
        _ => return None,
    };
    if hw != 1 || duid.len() != at + 6 {
        return None;
    }
    duid.get(at..at + 6)?.try_into().ok()
}

/// DUID-LL (RFC 8415 §11.4) of an Ethernet address.
pub fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut d = vec![0, 3, 0, 1];
    d.extend_from_slice(&mac);
    d
}

fn lifetime(s: u32) -> String {
    if s == INFINITY {
        "infinite".into()
    } else {
        format!("{s}s")
    }
}

fn clip(s: &str) -> String {
    s.chars().take(255).collect()
}

fn clean(s: &str) -> String {
    clip(&s.chars().filter(|c| !c.is_control()).collect::<String>())
}

fn ia_text(code: u16, data: &[u8]) -> Option<String> {
    let mut budget = MAX_OPTIONS;
    let ia = Ia::parse(code, data, &mut budget).ok()?;
    let mut parts = vec![format!(
        "iaid {} t1 {} t2 {}",
        ia.iaid,
        lifetime(ia.t1),
        lifetime(ia.t2)
    )];
    for a in &ia.addrs {
        parts.push(format!(
            "{} pref {} valid {}",
            a.addr,
            lifetime(a.preferred),
            lifetime(a.valid)
        ));
    }
    for p in &ia.prefixes {
        parts.push(format!(
            "{} pref {} valid {}",
            p.prefix,
            lifetime(p.preferred),
            lifetime(p.valid)
        ));
    }
    if let Some(s) = &ia.status {
        parts.push(s.text());
    }
    parts.extend(ia.dropped.iter().map(|d| format!("dropped {d}")));
    Some(parts.join("; "))
}

/// One received option for people: its name (empty when unknown) and its
/// value decoded when we know the option and the bytes fit, hex otherwise.
pub fn describe(code: u16, data: &[u8]) -> (&'static str, String) {
    let ips = |d: &[u8]| {
        (!d.is_empty() && d.len().is_multiple_of(16)).then(|| {
            ip_list(d)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        })
    };
    let secs = |d: &[u8]| (d.len() == 4).then(|| u32_at(d, 0).map(lifetime)).flatten();
    let (name, value): (&'static str, Option<String>) = match code {
        opt::CLIENTID => ("client-id", Some(duid_text(data))),
        opt::SERVERID => ("server-id", Some(duid_text(data))),
        opt::IA_NA => ("ia-na", ia_text(code, data)),
        opt::IA_PD => ("ia-pd", ia_text(code, data)),
        opt::IA_TA => ("ia-ta", None),
        opt::ORO => (
            "option-request",
            data.len().is_multiple_of(2).then(|| {
                data.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c).to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }),
        ),
        opt::PREFERENCE => (
            "preference",
            (data.len() == 1)
                .then(|| data.first().map(|p| p.to_string()))
                .flatten(),
        ),
        opt::ELAPSED_TIME => (
            "elapsed-time",
            (data.len() == 2)
                .then(|| u16_at(data, 0).map(|v| format!("{v}0ms")))
                .flatten(),
        ),
        opt::UNICAST => (
            "server-unicast",
            v6_at(data, 0)
                .filter(|_| data.len() == 16)
                .map(|a| a.to_string()),
        ),
        opt::STATUS_CODE => ("status-code", Status::parse(data).map(|s| s.text())),
        opt::RAPID_COMMIT => ("rapid-commit", data.is_empty().then(|| "yes".to_owned())),
        opt::USER_CLASS => ("user-class", None),
        opt::VENDOR_CLASS => ("vendor-class", None),
        opt::VENDOR_OPTS => ("vendor-opts", None),
        opt::RECONF_ACCEPT => (
            "reconfigure-accept",
            data.is_empty().then(|| "yes".to_owned()),
        ),
        opt::DNS_SERVERS => ("dns-servers", ips(data)),
        opt::DOMAIN_LIST => ("domain-list", domain_list(data).map(|d| d.join(", "))),
        opt::SNTP_SERVERS => ("sntp-servers", ips(data)),
        opt::INFORMATION_REFRESH_TIME => ("information-refresh-time", secs(data)),
        opt::CLIENT_FQDN => ("client-fqdn", None),
        opt::NTP_SERVER => ("ntp-server", ntp_text(data)),
        opt::AFTR_NAME => ("aftr-name", domain_list(data).map(|d| d.join(", "))),
        opt::PD_EXCLUDE => ("pd-exclude", None),
        opt::SOL_MAX_RT => ("sol-max-rt", secs(data)),
        opt::INF_MAX_RT => ("inf-max-rt", secs(data)),
        _ => ("", None),
    };
    (name, value.unwrap_or_else(|| hex(data)))
}

/// RFC 5908 sub-options: server address (1), multicast address (2), FQDN (3).
fn ntp_text(data: &[u8]) -> Option<String> {
    let mut budget = MAX_OPTIONS;
    let subs = split(data, &mut budget).ok()?;
    let mut out = Vec::new();
    for (code, body) in subs {
        match code {
            1 | 2 if body.len() == 16 => out.push(v6_at(body, 0)?.to_string()),
            3 => out.extend(domain_list(body)?),
            _ => return None,
        }
    }
    (!out.is_empty()).then(|| out.join(", "))
}

#[cfg(test)]
mod tests;

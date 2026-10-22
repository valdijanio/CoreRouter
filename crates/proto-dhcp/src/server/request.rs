//! What a client sent, read straight from the bytes.
//!
//! Requests are hostile input and `dhcproto` 0.15 panics on some malformed
//! messages (G4.7a), so the server reads them itself: the fixed header of
//! RFC 2131 §2 and the options it acts on, every length checked, nothing
//! indexed. The reply goes out through `dhcproto` (see `reply.rs`).

use std::net::Ipv4Addr;

use crate::v4::MAX_MESSAGE;

/// Fixed header + magic cookie (RFC 2131 §3, RFC 2132 §2).
const OPTIONS_AT: usize = 240;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// BOOTREQUEST (RFC 951).
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

/// RFC 2132 §9.6 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
}

impl Kind {
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Offer => "offer",
            Self::Request => "request",
            Self::Decline => "decline",
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Release => "release",
            Self::Inform => "inform",
        }
    }
}

/// Why bytes are not a request we act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bad {
    TooShort(usize),
    TooLarge(usize),
    NoMagic,
    /// A BOOTREPLY (another server's answer: the alert looks at those).
    Reply,
    /// Neither request nor reply.
    Opcode(u8),
    /// No option 53 (plain BOOTP: not served).
    NoType,
    /// An option the server reads has the wrong length.
    Option(u8),
}

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "only {n} bytes"),
            Self::TooLarge(n) => write!(f, "{n} bytes (more than {MAX_MESSAGE})"),
            Self::NoMagic => f.write_str("no DHCP magic cookie"),
            Self::Reply => f.write_str("a BOOTREPLY"),
            Self::Opcode(o) => write!(f, "opcode {o}"),
            Self::NoType => f.write_str("no message type (BOOTP is not served)"),
            Self::Option(c) => write!(f, "malformed option {c}"),
        }
    }
}

/// Client FQDN (RFC 4702 §2): flags and the name, as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fqdn {
    pub flags: u8,
    pub name: String,
}

/// RFC 4702 §2.1 flag bits.
pub const FQDN_S: u8 = 0x01;
pub const FQDN_O: u8 = 0x02;
pub const FQDN_E: u8 = 0x04;
pub const FQDN_N: u8 = 0x08;

/// A request, with the fields and options the server uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub kind: Kind,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub broadcast: bool,
    pub ciaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// `chaddr` as sent (at most 16 bytes, `hlen` of them).
    pub chaddr: Vec<u8>,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 61.
    pub client_id: Option<Vec<u8>>,
    /// Option 12, printable.
    pub host_name: Option<String>,
    /// Option 81.
    pub fqdn: Option<Fqdn>,
    /// Option 55, in the client's order.
    pub params: Vec<u8>,
    /// Option 57.
    pub max_size: Option<u16>,
    /// Option 60.
    pub vendor_class: Option<Vec<u8>>,
    /// Option 82, raw (RFC 3046: echoed as is).
    pub relay_info: Option<Vec<u8>>,
    /// Every option, for the matchers (code → bytes, joined per RFC 3396).
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Request {
    /// The Ethernet MAC: `chaddr` when it is one.
    pub fn mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        if self.htype == 1
            && self.hlen == 6
            && let Some(c) = self.chaddr.get(..6)
        {
            m.copy_from_slice(c);
        }
        m
    }

    /// RFC 2131 §4.2: the client is its client identifier when it sent one,
    /// else `htype` + `chaddr`.
    pub fn client_key(&self) -> Vec<u8> {
        match &self.client_id {
            Some(id) => id.clone(),
            None => {
                let mut k = Vec::with_capacity(1 + self.chaddr.len());
                k.push(self.htype);
                k.extend_from_slice(&self.chaddr);
                k
            }
        }
    }

    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, d)| d.as_slice())
    }
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    match b.get(at..at + 4) {
        Some([a, b, c, d]) => Ipv4Addr::new(*a, *b, *c, *d),
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    match b.get(at..at + 2) {
        Some([a, b]) => u16::from_be_bytes([*a, *b]),
        _ => 0,
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    match b.get(at..at + 4) {
        Some([a, b, c, d]) => u32::from_be_bytes([*a, *b, *c, *d]),
        _ => 0,
    }
}

/// Printable text of a name option: control characters out, 255 at most.
fn text(d: &[u8]) -> String {
    String::from_utf8_lossy(d)
        .chars()
        .filter(|c| !c.is_control())
        .take(255)
        .collect()
}

/// RFC 4702 §2.3: the name in DNS wire format when E is set (labels, maybe
/// without the root), else ASCII.
fn fqdn(d: &[u8]) -> Option<Fqdn> {
    let (&flags, rest) = d.split_first()?;
    // RCODE1 and RCODE2 (deprecated, RFC 4702 §2.2).
    let name_bytes = rest.get(2..)?;
    let name = if flags & FQDN_E != 0 {
        let mut labels = Vec::new();
        let mut at = name_bytes;
        while let Some((&len, tail)) = at.split_first() {
            if len == 0 {
                break;
            }
            if len > 63 {
                return None;
            }
            let label = tail.get(..usize::from(len))?;
            labels.push(text(label));
            at = tail.get(usize::from(len)..)?;
        }
        labels.join(".")
    } else {
        text(name_bytes)
    };
    Some(Fqdn {
        flags: flags & 0x0f,
        name: name.trim_end_matches('.').to_owned(),
    })
}

/// Read a message. `Err(Bad::Reply)` for a BOOTREPLY (another server).
pub fn parse(bytes: &[u8]) -> Result<Request, Bad> {
    if bytes.len() > MAX_MESSAGE {
        return Err(Bad::TooLarge(bytes.len()));
    }
    if bytes.len() < OPTIONS_AT {
        return Err(Bad::TooShort(bytes.len()));
    }
    if bytes.get(236..OPTIONS_AT) != Some(&MAGIC[..]) {
        return Err(Bad::NoMagic);
    }
    match bytes.first().copied() {
        Some(BOOTREQUEST) => {}
        Some(BOOTREPLY) => return Err(Bad::Reply),
        other => return Err(Bad::Opcode(other.unwrap_or(0))),
    }
    let htype = bytes.get(1).copied().unwrap_or(0);
    let hlen = bytes.get(2).copied().unwrap_or(0).min(16);
    let options = crate::v4::raw_options(bytes);
    let mut r = Request {
        kind: Kind::Discover,
        htype,
        hlen,
        hops: bytes.get(3).copied().unwrap_or(0),
        xid: u32_at(bytes, 4),
        secs: u16_at(bytes, 8),
        broadcast: u16_at(bytes, 10) & 0x8000 != 0,
        ciaddr: ip_at(bytes, 12),
        giaddr: ip_at(bytes, 24),
        chaddr: bytes
            .get(28..28 + usize::from(hlen))
            .unwrap_or(&[])
            .to_vec(),
        requested: None,
        server_id: None,
        client_id: None,
        host_name: None,
        fqdn: None,
        params: Vec::new(),
        max_size: None,
        vendor_class: None,
        relay_info: None,
        options: Vec::new(),
    };
    let mut kind = None;
    for (code, d) in &options {
        let ip = || -> Result<Ipv4Addr, Bad> {
            match d.as_slice() {
                [a, b, c, e] => Ok(Ipv4Addr::new(*a, *b, *c, *e)),
                _ => Err(Bad::Option(*code)),
            }
        };
        match code {
            53 => match d.as_slice() {
                [t] => kind = Kind::from_code(*t),
                _ => return Err(Bad::Option(53)),
            },
            50 => r.requested = Some(ip()?),
            54 => r.server_id = Some(ip()?),
            // RFC 2132 §9.14: at least 2 bytes.
            61 if d.len() >= 2 => r.client_id = Some(d.clone()),
            61 => return Err(Bad::Option(61)),
            12 if !d.is_empty() => r.host_name = Some(text(d)).filter(|h| !h.is_empty()),
            81 => r.fqdn = fqdn(d),
            55 => r.params = d.clone(),
            // RFC 2132 §9.10: at least 576.
            57 => {
                if let [a, b] = d.as_slice() {
                    r.max_size = Some(u16::from_be_bytes([*a, *b]).max(576));
                }
            }
            60 if !d.is_empty() => r.vendor_class = Some(d.clone()),
            82 if !d.is_empty() => r.relay_info = Some(d.clone()),
            _ => {}
        }
    }
    r.kind = kind.ok_or(Bad::NoType)?;
    r.options = options;
    Ok(r)
}

/// What the alert needs from another server's reply: its identifier
/// (option 54) and the message type, when it is a DHCP reply at all.
pub fn server_reply(bytes: &[u8]) -> Option<(Kind, Option<Ipv4Addr>)> {
    if bytes.first() != Some(&BOOTREPLY) || bytes.get(236..OPTIONS_AT) != Some(&MAGIC[..]) {
        return None;
    }
    let mut kind = None;
    let mut id = None;
    for (code, d) in crate::v4::raw_options(bytes) {
        match (code, d.as_slice()) {
            (53, [t]) => kind = Kind::from_code(*t),
            (54, [a, b, c, e]) => id = Some(Ipv4Addr::new(*a, *b, *c, *e)),
            _ => {}
        }
    }
    kind.map(|k| (k, id))
}

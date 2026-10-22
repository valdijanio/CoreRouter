//! DHCPv4 messages over `dhcproto`: what a client sends ([`Outgoing`] →
//! bytes) and what it hears ([`decode`] → [`Incoming`]), plus a raw view of
//! every option received ([`raw_options`], [`describe`]) for
//! `ip.dhcp-client.options`. The same layer will serve the DHCP server (G4.2).
//!
//! Received packets are hostile input: [`decode`] refuses anything larger
//! than [`MAX_MESSAGE`], anything that is not a BOOTREPLY with a DHCP message
//! type, and never panics (proptest below).

use std::net::Ipv4Addr;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode, UnknownOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use ipnet::Ipv4Net;

pub use corerouter_hal::dhcp::MAX_MESSAGE;

/// Offset of the options in a DHCP message (fixed header + magic cookie).
const OPTIONS_AT: usize = 240;
const MAGIC: [u8; 4] = [99, 130, 83, 99];

/// Options a client asks for (option 55).
pub const REQUESTED: [u8; 9] = [1, 3, 6, 15, 26, 28, 42, 119, 121];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("message of {0} bytes is larger than {MAX_MESSAGE}")]
    TooLarge(usize),
    #[error("not a DHCP message: {0}")]
    Malformed(String),
    #[error("cannot encode: {0}")]
    Encode(String),
}

/// A message the client sends.
#[derive(Debug, Clone)]
pub struct Outgoing<'a> {
    pub kind: MessageType,
    pub xid: u32,
    /// Seconds since the client began acquiring or renewing.
    pub secs: u16,
    pub mac: [u8; 6],
    /// Our address while we hold one (renew, rebind, release).
    pub ciaddr: Ipv4Addr,
    /// Ask the server to broadcast its answer (we have no address yet).
    pub broadcast: bool,
    /// Option 50.
    pub requested: Option<Ipv4Addr>,
    /// Option 54.
    pub server_id: Option<Ipv4Addr>,
    /// Option 61.
    pub client_id: &'a [u8],
    /// Option 12.
    pub host_name: Option<&'a str>,
    /// Option 60.
    pub vendor_class: Option<&'a [u8]>,
    /// The operator's own options, already in bytes.
    pub extra: &'a [(u8, Vec<u8>)],
}

impl Outgoing<'_> {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut m = Message::new_with_id(
            self.xid,
            self.ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &self.mac,
        );
        m.set_opcode(Opcode::BootRequest).set_secs(self.secs);
        if self.broadcast {
            m.set_flags(Flags::default().set_broadcast());
        }
        let opts = m.opts_mut();
        opts.insert(DhcpOption::MessageType(self.kind));
        if !self.client_id.is_empty() {
            opts.insert(DhcpOption::ClientIdentifier(self.client_id.to_vec()));
        }
        if let Some(ip) = self.requested {
            opts.insert(DhcpOption::RequestedIpAddress(ip));
        }
        if let Some(ip) = self.server_id {
            opts.insert(DhcpOption::ServerIdentifier(ip));
        }
        let asks = matches!(self.kind, MessageType::Discover | MessageType::Request);
        if asks {
            opts.insert(DhcpOption::ParameterRequestList(
                REQUESTED.iter().map(|c| OptionCode::from(*c)).collect(),
            ));
            opts.insert(DhcpOption::MaxMessageSize(1500));
            if let Some(h) = self.host_name.filter(|h| !h.is_empty()) {
                opts.insert(DhcpOption::Hostname(h.to_owned()));
            }
            if let Some(v) = self.vendor_class.filter(|v| !v.is_empty()) {
                opts.insert(DhcpOption::ClassIdentifier(v.to_vec()));
            }
            for (code, data) in self.extra {
                opts.insert(DhcpOption::Unknown(UnknownOption::new(
                    OptionCode::from(*code),
                    data.clone(),
                )));
            }
        }
        let mut buf = Vec::with_capacity(548);
        m.encode(&mut Encoder::new(&mut buf))
            .map_err(|e| CodecError::Encode(e.to_string()))?;
        Ok(buf)
    }
}

/// A server's answer, reduced to what a client acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub kind: MessageType,
    pub xid: u32,
    /// First six bytes of `chaddr` (the client it is for).
    pub chaddr: [u8; 6],
    pub yiaddr: Ipv4Addr,
    pub server_id: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub ntp: Vec<Ipv4Addr>,
    pub domain: Option<String>,
    pub lease_secs: Option<u32>,
    pub renew_secs: Option<u32>,
    pub rebind_secs: Option<u32>,
    pub classless: Vec<(Ipv4Net, Ipv4Addr)>,
    /// Option 56 (why a NAK, usually).
    pub message: Option<String>,
}

/// Whether option `code` with these bytes may reach `dhcproto`'s decoder:
/// the options a client or the lab server reads, with lengths checked here.
/// `dhcproto` 0.15 panics on some malformed input (a `chaddr` longer than
/// 16 bytes, `debug_assert!`s on option lengths), so it never sees anything
/// else. A malformed optional option is dropped, not the whole message.
fn safe_option(code: u8, data: &[u8]) -> bool {
    match code {
        1 | 2 | 28 | 50 | 51 | 54 | 58 | 59 => data.len() == 4,
        3 | 6 | 42 => !data.is_empty() && data.len().is_multiple_of(4),
        53 => data.len() == 1,
        57 => data.len() == 2,
        55 | 60 | 61 => !data.is_empty(),
        12 | 15 | 56 => !data.is_empty() && std::str::from_utf8(data).is_ok(),
        121 => parse_classless(data).is_some(),
        _ => false,
    }
}

/// `bytes` rebuilt for `dhcproto`: the fixed header with `hlen` clamped to
/// 16, the magic cookie, and only the [`safe_option`]s (each ≤ 255 bytes).
fn sanitize(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    if bytes.len() > MAX_MESSAGE {
        return Err(CodecError::TooLarge(bytes.len()));
    }
    let header = bytes
        .get(..236)
        .ok_or_else(|| CodecError::Malformed(format!("only {} bytes", bytes.len())))?;
    if bytes.get(236..OPTIONS_AT) != Some(&MAGIC[..]) {
        return Err(CodecError::Malformed("no DHCP magic cookie".into()));
    }
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(header);
    if let Some(hlen) = out.get_mut(2) {
        *hlen = (*hlen).min(16);
    }
    out.extend_from_slice(&MAGIC);
    for (code, data) in raw_options(bytes) {
        let Ok(len) = u8::try_from(data.len()) else {
            continue;
        };
        if safe_option(code, &data) {
            out.push(code);
            out.push(len);
            out.extend_from_slice(&data);
        }
    }
    out.push(255);
    Ok(out)
}

/// Decode any DHCPv4 message through [`sanitize`] (requests too: the lab
/// server reads them).
pub fn decode_message(bytes: &[u8]) -> Result<Message, CodecError> {
    let clean = sanitize(bytes)?;
    Message::decode(&mut Decoder::new(&clean))
        .map_err(|e| CodecError::Malformed(clip(&e.to_string())))
}

/// Decode a received message. Only BOOTREPLY with a message type.
pub fn decode(bytes: &[u8]) -> Result<Incoming, CodecError> {
    let m = decode_message(bytes)?;
    if m.opcode() != Opcode::BootReply {
        return Err(CodecError::Malformed("not a reply (BOOTREQUEST)".into()));
    }
    let kind = m
        .opts()
        .msg_type()
        .ok_or_else(|| CodecError::Malformed("no DHCP message type (BOOTP?)".into()))?;
    // Straight from the bytes: `Message::chaddr` slices by `hlen`.
    let mut chaddr = [0u8; 6];
    if let Some(c) = bytes.get(28..34) {
        chaddr.copy_from_slice(c);
    }
    let mut out = Incoming {
        kind,
        xid: m.xid(),
        chaddr,
        yiaddr: m.yiaddr(),
        server_id: None,
        mask: None,
        routers: Vec::new(),
        dns: Vec::new(),
        ntp: Vec::new(),
        domain: None,
        lease_secs: None,
        renew_secs: None,
        rebind_secs: None,
        classless: Vec::new(),
        message: None,
    };
    for (_, opt) in m.opts().iter() {
        match opt {
            DhcpOption::ServerIdentifier(ip) => out.server_id = Some(*ip),
            DhcpOption::SubnetMask(ip) => out.mask = Some(*ip),
            DhcpOption::Router(v) => out.routers = bounded(v),
            DhcpOption::DomainNameServer(v) => out.dns = bounded(v),
            DhcpOption::NtpServers(v) => out.ntp = bounded(v),
            DhcpOption::DomainName(d) => out.domain = Some(clip(d)),
            DhcpOption::AddressLeaseTime(s) => out.lease_secs = Some(*s),
            DhcpOption::Renewal(s) => out.renew_secs = Some(*s),
            DhcpOption::Rebinding(s) => out.rebind_secs = Some(*s),
            DhcpOption::ClasslessStaticRoute(r) => {
                out.classless = r.iter().take(MAX_LIST).copied().collect();
            }
            DhcpOption::Message(s) => out.message = Some(clip(s)),
            _ => {}
        }
    }
    Ok(out)
}

/// Addresses kept from one list option (hostile input bound).
const MAX_LIST: usize = 32;

fn bounded(v: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    v.iter().take(MAX_LIST).copied().collect()
}

/// Text from the network for logs and tables: printable, at most 255 chars.
pub fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(255).collect()
}

/// Every option of a message as (code, bytes), in order of first
/// appearance, with split options (RFC 3396) joined. Pads and the end
/// marker are left out; a truncated option ends the walk.
pub fn raw_options(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    if bytes.len() > MAX_MESSAGE || bytes.get(236..OPTIONS_AT) != Some(&MAGIC[..]) {
        return out;
    }
    let mut rest = bytes.get(OPTIONS_AT..).unwrap_or(&[]);
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            0 => rest = tail,
            255 => break,
            _ => {
                let Some((&len, tail)) = tail.split_first() else {
                    break;
                };
                let Some(data) = tail.get(..usize::from(len)) else {
                    break;
                };
                match out.iter_mut().find(|(c, _)| *c == code) {
                    Some((_, d)) => d.extend_from_slice(data),
                    None => out.push((code, data.to_vec())),
                }
                rest = tail.get(usize::from(len)..).unwrap_or(&[]);
            }
        }
    }
    out
}

/// How an option's bytes read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Ip,
    Ips,
    Secs,
    U16,
    U8,
    Text,
    MsgType,
    Classless,
    /// Option 33: (destination, router) pairs.
    Pairs,
    Hex,
}

/// Name and shape of the options we know (RFC 2132 and later; the names
/// follow RouterOS / dhcpd usage).
fn known(code: u8) -> (&'static str, Shape) {
    match code {
        1 => ("subnet-mask", Shape::Ip),
        2 => ("time-offset", Shape::Secs),
        3 => ("router", Shape::Ips),
        4 => ("time-server", Shape::Ips),
        6 => ("domain-name-server", Shape::Ips),
        12 => ("host-name", Shape::Text),
        15 => ("domain-name", Shape::Text),
        23 => ("default-ttl", Shape::U8),
        26 => ("interface-mtu", Shape::U16),
        28 => ("broadcast-address", Shape::Ip),
        33 => ("static-route", Shape::Pairs),
        42 => ("ntp-server", Shape::Ips),
        43 => ("vendor-specific", Shape::Hex),
        44 => ("netbios-name-server", Shape::Ips),
        50 => ("requested-address", Shape::Ip),
        51 => ("lease-time", Shape::Secs),
        53 => ("message-type", Shape::MsgType),
        54 => ("server-identifier", Shape::Ip),
        56 => ("message", Shape::Text),
        57 => ("max-message-size", Shape::U16),
        58 => ("renewal-time", Shape::Secs),
        59 => ("rebinding-time", Shape::Secs),
        60 => ("vendor-class-identifier", Shape::Text),
        61 => ("client-identifier", Shape::Hex),
        66 => ("tftp-server-name", Shape::Text),
        67 => ("bootfile-name", Shape::Text),
        82 => ("relay-agent-information", Shape::Hex),
        100 => ("posix-timezone", Shape::Text),
        101 => ("tz-database", Shape::Text),
        108 => ("ipv6-only-preferred", Shape::Secs),
        114 => ("captive-portal", Shape::Text),
        119 => ("domain-search", Shape::Hex),
        121 => ("classless-static-route", Shape::Classless),
        150 => ("tftp-server-address", Shape::Ips),
        249 => ("ms-classless-static-route", Shape::Classless),
        252 => ("wpad", Shape::Text),
        _ => ("", Shape::Hex),
    }
}

/// `0x…` of `data`.
pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(2 + data.len() * 2);
    s.push_str("0x");
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One received option for people: its name (empty when unknown) and its
/// value decoded when we know the option and the bytes fit, hex otherwise.
pub fn describe(code: u8, data: &[u8]) -> (&'static str, String) {
    let (name, shape) = known(code);
    let text = match shape {
        Shape::Ip if data.len() == 4 => ips(data),
        Shape::Ips if !data.is_empty() && data.len().is_multiple_of(4) => ips(data),
        Shape::Secs => <[u8; 4]>::try_from(data)
            .ok()
            .map(|b| secs(u32::from_be_bytes(b))),
        Shape::U16 => <[u8; 2]>::try_from(data)
            .ok()
            .map(|b| u16::from_be_bytes(b).to_string()),
        Shape::U8 => <[u8; 1]>::try_from(data).ok().map(|[b]| b.to_string()),
        Shape::Text => text(data),
        Shape::MsgType => <[u8; 1]>::try_from(data)
            .ok()
            .map(|[b]| format!("{:?}", MessageType::from(b)).to_lowercase()),
        Shape::Classless => parse_classless(data).map(|r| {
            r.iter()
                .map(|(net, gw)| format!("{net} via {gw}"))
                .collect::<Vec<_>>()
                .join(", ")
        }),
        Shape::Pairs if !data.is_empty() && data.len().is_multiple_of(8) => Some(
            data.chunks(8)
                .map(|c| {
                    format!(
                        "{} via {}",
                        ips(c.get(..4).unwrap_or(&[])).unwrap_or_default(),
                        ips(c.get(4..).unwrap_or(&[])).unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
        _ => None,
    };
    (name, text.unwrap_or_else(|| hex(data)))
}

fn ips(data: &[u8]) -> Option<String> {
    Some(
        data.chunks(4)
            .map(|c| <[u8; 4]>::try_from(c).map(|b| Ipv4Addr::from(b).to_string()))
            .collect::<Result<Vec<_>, _>>()
            .ok()?
            .join(", "),
    )
}

fn secs(s: u32) -> String {
    if s == u32::MAX {
        "infinite".into()
    } else {
        format!("{s}s")
    }
}

fn text(data: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(data).ok()?;
    let s = s.trim_end_matches('\0');
    (!s.is_empty() && s.chars().all(|c| !c.is_control())).then(|| clip(s))
}

/// RFC 3442 encoding: width, significant octets of the destination, router.
pub fn parse_classless(data: &[u8]) -> Option<Vec<(Ipv4Net, Ipv4Addr)>> {
    let mut out = Vec::new();
    let mut rest = data;
    while let Some((&width, tail)) = rest.split_first() {
        if width > 32 {
            return None;
        }
        let octets = usize::from(width.div_ceil(8));
        let dst = tail.get(..octets)?;
        let gw = tail.get(octets..octets.checked_add(4)?)?;
        let mut d = [0u8; 4];
        d.get_mut(..octets)?.copy_from_slice(dst);
        let net = Ipv4Net::new(Ipv4Addr::from(d), width).ok()?.trunc();
        out.push((net, Ipv4Addr::from(<[u8; 4]>::try_from(gw).ok()?)));
        rest = tail.get(octets.checked_add(4)?..)?;
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    fn discover() -> Vec<u8> {
        Outgoing {
            kind: MessageType::Discover,
            xid: 0x1234_5678,
            secs: 3,
            mac: MAC,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            broadcast: true,
            requested: None,
            server_id: None,
            client_id: &[1, 2, 0, 0, 0, 0, 1],
            host_name: Some("cpe"),
            vendor_class: Some(b"corerouter"),
            extra: &[(77, b"wan".to_vec())],
        }
        .encode()
        .unwrap()
    }

    /// A server's answer to `request`, built with dhcproto like a server would.
    fn reply(kind: MessageType, xid: u32, opts: Vec<DhcpOption>) -> Vec<u8> {
        let mut m = Message::new_with_id(
            xid,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 0, 2, 50),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &MAC,
        );
        m.set_opcode(Opcode::BootReply);
        m.opts_mut().insert(DhcpOption::MessageType(kind));
        for o in opts {
            m.opts_mut().insert(o);
        }
        let mut buf = Vec::new();
        m.encode(&mut Encoder::new(&mut buf)).unwrap();
        buf
    }

    #[test]
    fn discover_carries_what_the_client_says() {
        let bytes = discover();
        let m = Message::decode(&mut Decoder::new(&bytes)).unwrap();
        assert_eq!(m.xid(), 0x1234_5678);
        assert!(m.flags().broadcast());
        assert_eq!(m.opts().msg_type(), Some(MessageType::Discover));
        let raw = raw_options(&bytes);
        let get = |c: u8| raw.iter().find(|(k, _)| *k == c).map(|(_, d)| d.clone());
        assert_eq!(get(12).unwrap(), b"cpe");
        assert_eq!(get(60).unwrap(), b"corerouter");
        assert_eq!(get(61).unwrap(), [1, 2, 0, 0, 0, 0, 1]);
        assert_eq!(get(77).unwrap(), b"wan");
        assert_eq!(get(55).unwrap(), REQUESTED);
        // A RELEASE does not ask for anything.
        let release = Outgoing {
            kind: MessageType::Release,
            ..Outgoing {
                kind: MessageType::Discover,
                xid: 1,
                secs: 0,
                mac: MAC,
                ciaddr: Ipv4Addr::new(192, 0, 2, 50),
                broadcast: false,
                requested: None,
                server_id: Some(Ipv4Addr::new(192, 0, 2, 1)),
                client_id: &[],
                host_name: Some("cpe"),
                vendor_class: None,
                extra: &[],
            }
        }
        .encode()
        .unwrap();
        assert!(
            raw_options(&release)
                .iter()
                .all(|(c, _)| ![12, 55].contains(c))
        );
    }

    #[test]
    fn an_ack_decodes_into_a_lease() {
        let route: Ipv4Net = "10.0.0.0/8".parse().unwrap();
        let bytes = reply(
            MessageType::Ack,
            7,
            vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
                DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                DhcpOption::Router(vec![Ipv4Addr::new(192, 0, 2, 1)]),
                DhcpOption::DomainNameServer(vec![Ipv4Addr::new(9, 9, 9, 9)]),
                DhcpOption::AddressLeaseTime(600),
                DhcpOption::ClasslessStaticRoute(vec![(route, Ipv4Addr::new(192, 0, 2, 254))]),
                DhcpOption::Unknown(UnknownOption::new(OptionCode::from(224), vec![1, 2])),
            ],
        );
        let i = decode(&bytes).unwrap();
        assert_eq!(i.kind, MessageType::Ack);
        assert_eq!(i.chaddr, MAC);
        assert_eq!(i.yiaddr, Ipv4Addr::new(192, 0, 2, 50));
        assert_eq!(i.lease_secs, Some(600));
        assert_eq!(i.classless, vec![(route, Ipv4Addr::new(192, 0, 2, 254))]);
        let raw = raw_options(&bytes);
        let shown: Vec<(u8, &str, String)> = raw
            .iter()
            .map(|(c, d)| {
                let (n, v) = describe(*c, d);
                (*c, n, v)
            })
            .collect();
        assert!(
            shown.contains(&(51, "lease-time", "600s".into())),
            "{shown:?}"
        );
        assert!(shown.contains(&(53, "message-type", "ack".into())));
        assert!(shown.contains(&(
            121,
            "classless-static-route",
            "10.0.0.0/8 via 192.0.2.254".into()
        )));
        assert!(shown.contains(&(224, "", "0x0102".into())));
    }

    #[test]
    fn requests_and_garbage_are_refused() {
        assert!(matches!(decode(&discover()), Err(CodecError::Malformed(_))));
        assert!(decode(&[]).is_err());
        assert!(matches!(
            decode(&vec![0; MAX_MESSAGE + 1]),
            Err(CodecError::TooLarge(_))
        ));
        assert!(raw_options(&[0; 10]).is_empty());
    }

    #[test]
    fn classless_routes_follow_rfc_3442() {
        // The RouterOS example: 0.0.0.0/0 and 160.0.0.0/24 (written as /24 of 0xA00000).
        let data = [0, 10, 1, 101, 1, 24, 160, 0, 0, 10, 1, 101, 1];
        let r = parse_classless(&data).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0.to_string(), "0.0.0.0/0");
        assert_eq!(r[1].0.to_string(), "160.0.0.0/24");
        assert_eq!(r[1].1, Ipv4Addr::new(10, 1, 101, 1));
        assert!(parse_classless(&[33, 0, 0, 0, 0]).is_none());
        assert!(parse_classless(&[24, 10, 0]).is_none(), "truncated");
        let (_, shown) = describe(121, &[24, 10, 0]);
        assert_eq!(shown, "0x180a00", "bad bytes show as hex");
    }

    /// Found by the proptest below: `dhcproto` slices `chaddr` by `hlen`
    /// and `debug_assert!`s option lengths; the sanitizer keeps both away.
    #[test]
    fn dhcproto_panics_are_kept_away() {
        let mut bytes = reply(MessageType::Offer, 3, vec![]);
        if let Some(h) = bytes.get_mut(2) {
            *h = 200;
        }
        assert_eq!(decode(&bytes).unwrap().chaddr, MAC);
        // Option 94 (3 bytes expected) with 1 byte, and a bad 121: dropped, message kept.
        let end = bytes.len() - 1;
        bytes.truncate(end);
        bytes.extend_from_slice(&[94, 1, 0, 121, 2, 40, 1, 255]);
        let i = decode(&bytes).unwrap();
        assert!(i.classless.is_empty());
        let raw = raw_options(&bytes);
        assert!(raw.iter().any(|(c, _)| *c == 94), "still shown raw");
    }

    proptest! {
        #[test]
        fn hostile_requests_never_panic_the_lab_server(bytes in proptest::collection::vec(any::<u8>(), 0..800)) {
            use corerouter_hal::dhcp::{Dest, DhcpResponder};
            let lab = crate::lab::LabServer::default();
            let _ = lab.answer(&"ether1".parse().unwrap(), MAC, &bytes, Dest::Broadcast);
        }

        #[test]
        fn decoding_hostile_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1500)) {
            let _ = decode(&bytes);
            for (c, d) in raw_options(&bytes) {
                let _ = describe(c, &d);
            }
        }

        #[test]
        fn mutated_real_replies_never_panic(
            flips in proptest::collection::vec((0usize..400, any::<u8>()), 1..12),
            cut in 200usize..400,
        ) {
            let mut bytes = reply(MessageType::Offer, 1, vec![
                DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 0, 2, 1)),
                DhcpOption::AddressLeaseTime(60),
                DhcpOption::ClasslessStaticRoute(vec![("0.0.0.0/0".parse().unwrap(), Ipv4Addr::new(192, 0, 2, 1))]),
                DhcpOption::DomainName("lab".into()),
            ]);
            for (at, v) in flips {
                if let Some(b) = bytes.get_mut(at) { *b = v; }
            }
            bytes.truncate(cut);
            if let Ok(i) = decode(&bytes) {
                prop_assert!(i.routers.len() <= MAX_LIST);
            }
            for (c, d) in raw_options(&bytes) {
                let _ = describe(c, &d);
            }
        }

        #[test]
        fn options_survive_encode_then_raw_view(
            extra in proptest::collection::vec((100u8..=200, proptest::collection::vec(any::<u8>(), 0..40)), 0..6)
        ) {
            let mut uniq: Vec<(u8, Vec<u8>)> = Vec::new();
            for (c, d) in extra {
                if !uniq.iter().any(|(k, _)| *k == c) { uniq.push((c, d)); }
            }
            let bytes = Outgoing {
                kind: MessageType::Discover, xid: 9, secs: 0, mac: MAC,
                ciaddr: Ipv4Addr::UNSPECIFIED, broadcast: true, requested: None,
                server_id: None, client_id: &[], host_name: None, vendor_class: None,
                extra: &uniq,
            }.encode().unwrap();
            let raw = raw_options(&bytes);
            for (c, d) in &uniq {
                let got = raw.iter().find(|(k, _)| k == c).map(|(_, v)| v.clone()).unwrap_or_default();
                prop_assert_eq!(&got, d);
            }
        }
    }
}

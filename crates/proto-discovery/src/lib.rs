//! L2 — CRDP, the CoreRouter Discovery Protocol (docs/discovery.md).
//!
//! Pure codec: [`Announcement::encode`] and [`decode`] turn one UDP payload
//! into a value and back, with no sockets, clock or randomness, so it builds
//! for wasm and is fuzzed by proptest. Datagrams come from anyone on the
//! link: [`decode`] bounds every length, checks every field and never
//! panics. TLVs it does not know are skipped, so newer senders stay
//! readable.
//!
//! Also the `proto-*` contract: [`validate`] checks the discovery settings
//! of the candidate before a commit.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use corerouter_model::neighbor::INTERVAL_RANGE;
use corerouter_model::{Config, Issue};

/// UDP port of CRDP: the number of the control channel's TCP port, so one
/// firewall rule pair covers management. Not 5678 (MNDP).
pub const PORT: u16 = 7979;
/// Largest datagram sent or accepted: the IPv6 minimum MTU (1280) minus the
/// IPv6 and UDP headers, so an announcement is never fragmented.
pub const MAX_PACKET: usize = 1232;
pub const MAGIC: [u8; 4] = *b"CRDP";
pub const VERSION: u8 = 1;
/// magic (4) + version (1) + reserved (1) + TLV bytes (2).
pub const HEADER_LEN: usize = 8;
/// Longest text field, in bytes of UTF-8.
pub const MAX_TEXT: usize = 128;
/// Most addresses of each family in one announcement.
pub const MAX_ADDRESSES: usize = 16;

/// TLV types (u16, big endian). 0 is never valid.
pub mod tlv {
    pub const NODE_ID: u16 = 1;
    pub const HOLD: u16 = 2;
    pub const IDENTITY: u16 = 3;
    pub const VERSION: u16 = 4;
    pub const PLATFORM: u16 = 5;
    pub const BOARD: u16 = 6;
    pub const UPTIME: u16 = 7;
    pub const INTERFACE: u16 = 8;
    pub const MAC: u16 = 9;
    pub const IPV4: u16 = 10;
    pub const IPV6: u16 = 11;
    pub const CONTROL_PORT: u16 = 12;
    pub const WS_PORT: u16 = 13;
    /// Control channel over TLS (`corerouter-daemon --listen`, G0.3).
    pub const TLS_PORT: u16 = 14;
    /// WebSocket over TLS (`--ws-listen`).
    pub const WSS_PORT: u16 = 15;
}

/// Stable 128-bit id of a router, generated once and kept with its config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 16]);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for NodeId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let bad = || {
            format!(
                "node id is 32 hex digits, got '{}'",
                s.chars().take(40).collect::<String>()
            )
        };
        if s.len() != 32 || !s.is_ascii() {
            return Err(bad());
        }
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            let pair = s.get(2 * i..2 * i + 2).ok_or_else(bad)?;
            *b = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
        }
        Ok(NodeId(out))
    }
}

/// One CRDP announcement: "this router is here, on this link".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub node_id: NodeId,
    /// Seconds a receiver keeps it without a new one; 0 = goodbye (forget me).
    pub hold_secs: u16,
    pub identity: String,
    pub version: String,
    pub platform: String,
    pub board: String,
    pub uptime_secs: Option<u64>,
    /// Sender's name for the interface it was sent on.
    pub interface: String,
    pub mac: Option<[u8; 6]>,
    /// Addresses of that interface with their prefix lengths.
    pub ipv4: Vec<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub control_port: Option<u16>,
    pub ws_port: Option<u16>,
    /// Ports reachable from other machines: TLS control and WebSocket.
    pub tls_port: Option<u16>,
    pub wss_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("{field} is longer than {MAX_TEXT} bytes")]
    TextTooLong { field: &'static str },
    #[error("{field} has a control character")]
    BadText { field: &'static str },
    #[error("more than {MAX_ADDRESSES} {family} addresses")]
    TooManyAddresses { family: &'static str },
    #[error("bad prefix length /{0}")]
    BadPrefix(u8),
    #[error("port 0 is not a port")]
    ZeroPort,
    #[error("the node id is all zeros")]
    ZeroNodeId,
    #[error("announcement is {0} bytes, more than {MAX_PACKET}")]
    TooLarge(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("datagram of {0} bytes is shorter than the CRDP header")]
    TooShort(usize),
    #[error("datagram of {0} bytes is larger than {MAX_PACKET}")]
    TooLarge(usize),
    #[error("not CRDP (bad magic)")]
    BadMagic,
    #[error("unsupported CRDP version {0}")]
    Version(u8),
    #[error("header says {header} TLV bytes, datagram has {actual}")]
    Length { header: usize, actual: usize },
    #[error("TLV header cut short at byte {0}")]
    Truncated(usize),
    #[error("TLV type 0 is invalid")]
    ZeroType,
    #[error("TLV {tlv} has a bad length {len}")]
    BadLength { tlv: u16, len: usize },
    #[error("TLV {0} appears twice")]
    Duplicate(u16),
    #[error("required TLV {0} is missing")]
    Missing(u16),
    #[error("TLV {0} is not clean UTF-8 text")]
    BadText(u16),
    #[error("TLV {0} repeats more than {MAX_ADDRESSES} times")]
    TooMany(u16),
    #[error("TLV {0} has an invalid value")]
    BadValue(u16),
}

/// Cut `s` to at most `max` bytes on a character boundary and drop control
/// characters, so free text (an identity) always fits an announcement.
pub fn fit_text(s: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in s.chars().filter(|c| !c.is_control()) {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out
}

fn text_ok(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

impl Announcement {
    /// The datagram for this announcement. Empty optional texts are left out.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if self.node_id.0 == [0; 16] {
            return Err(EncodeError::ZeroNodeId);
        }
        let mut body = Vec::with_capacity(256);
        let mut put = |t: u16, value: &[u8]| {
            // Every value is bounded below MAX_PACKET, so the u16 fits.
            let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(value);
        };
        put(tlv::NODE_ID, &self.node_id.0);
        put(tlv::HOLD, &self.hold_secs.to_be_bytes());
        let texts: [(u16, &'static str, &str, bool); 5] = [
            (tlv::IDENTITY, "identity", &self.identity, true),
            (tlv::VERSION, "version", &self.version, false),
            (tlv::PLATFORM, "platform", &self.platform, false),
            (tlv::BOARD, "board", &self.board, false),
            (tlv::INTERFACE, "interface", &self.interface, false),
        ];
        for (t, field, text, always) in texts {
            if text.len() > MAX_TEXT {
                return Err(EncodeError::TextTooLong { field });
            }
            if !text_ok(text) {
                return Err(EncodeError::BadText { field });
            }
            if always || !text.is_empty() {
                put(t, text.as_bytes());
            }
        }
        if let Some(up) = self.uptime_secs {
            put(tlv::UPTIME, &up.to_be_bytes());
        }
        if let Some(mac) = self.mac {
            put(tlv::MAC, &mac);
        }
        if self.ipv4.len() > MAX_ADDRESSES {
            return Err(EncodeError::TooManyAddresses { family: "IPv4" });
        }
        if self.ipv6.len() > MAX_ADDRESSES {
            return Err(EncodeError::TooManyAddresses { family: "IPv6" });
        }
        for (a, len) in &self.ipv4 {
            if *len > 32 {
                return Err(EncodeError::BadPrefix(*len));
            }
            let mut v = a.octets().to_vec();
            v.push(*len);
            put(tlv::IPV4, &v);
        }
        for (a, len) in &self.ipv6 {
            if *len > 128 {
                return Err(EncodeError::BadPrefix(*len));
            }
            let mut v = a.octets().to_vec();
            v.push(*len);
            put(tlv::IPV6, &v);
        }
        for (t, port) in [
            (tlv::CONTROL_PORT, self.control_port),
            (tlv::WS_PORT, self.ws_port),
            (tlv::TLS_PORT, self.tls_port),
            (tlv::WSS_PORT, self.wss_port),
        ] {
            match port {
                Some(0) => return Err(EncodeError::ZeroPort),
                Some(p) => put(t, &p.to_be_bytes()),
                None => {}
            }
        }
        let total = HEADER_LEN + body.len();
        if total > MAX_PACKET {
            return Err(EncodeError::TooLarge(total));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(0);
        out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Fields seen so far while decoding.
#[derive(Default)]
struct Partial {
    node_id: Option<NodeId>,
    hold: Option<u16>,
    identity: Option<String>,
    version: Option<String>,
    platform: Option<String>,
    board: Option<String>,
    uptime: Option<u64>,
    interface: Option<String>,
    mac: Option<[u8; 6]>,
    ipv4: Vec<(Ipv4Addr, u8)>,
    ipv6: Vec<(Ipv6Addr, u8)>,
    control: Option<u16>,
    ws: Option<u16>,
    tls: Option<u16>,
    wss: Option<u16>,
}

fn once<T>(slot: &mut Option<T>, t: u16, value: T) -> Result<(), DecodeError> {
    if slot.is_some() {
        return Err(DecodeError::Duplicate(t));
    }
    *slot = Some(value);
    Ok(())
}

fn fixed<const N: usize>(t: u16, v: &[u8]) -> Result<[u8; N], DecodeError> {
    <[u8; N]>::try_from(v).map_err(|_| DecodeError::BadLength {
        tlv: t,
        len: v.len(),
    })
}

fn text(t: u16, v: &[u8]) -> Result<String, DecodeError> {
    if v.len() > MAX_TEXT {
        return Err(DecodeError::BadLength {
            tlv: t,
            len: v.len(),
        });
    }
    let s = std::str::from_utf8(v).map_err(|_| DecodeError::BadText(t))?;
    if !text_ok(s) {
        return Err(DecodeError::BadText(t));
    }
    Ok(s.to_owned())
}

fn port(t: u16, v: &[u8]) -> Result<u16, DecodeError> {
    match u16::from_be_bytes(fixed::<2>(t, v)?) {
        0 => Err(DecodeError::BadValue(t)),
        p => Ok(p),
    }
}

impl Partial {
    fn take(&mut self, t: u16, v: &[u8]) -> Result<(), DecodeError> {
        match t {
            0 => return Err(DecodeError::ZeroType),
            tlv::NODE_ID => {
                let id = fixed::<16>(t, v)?;
                if id == [0; 16] {
                    return Err(DecodeError::BadValue(t));
                }
                once(&mut self.node_id, t, NodeId(id))?;
            }
            tlv::HOLD => once(&mut self.hold, t, u16::from_be_bytes(fixed::<2>(t, v)?))?,
            tlv::IDENTITY => once(&mut self.identity, t, text(t, v)?)?,
            tlv::VERSION => once(&mut self.version, t, text(t, v)?)?,
            tlv::PLATFORM => once(&mut self.platform, t, text(t, v)?)?,
            tlv::BOARD => once(&mut self.board, t, text(t, v)?)?,
            tlv::INTERFACE => once(&mut self.interface, t, text(t, v)?)?,
            tlv::UPTIME => once(&mut self.uptime, t, u64::from_be_bytes(fixed::<8>(t, v)?))?,
            tlv::MAC => once(&mut self.mac, t, fixed::<6>(t, v)?)?,
            tlv::IPV4 => {
                let raw = fixed::<5>(t, v)?;
                let [a, b, c, d, len] = raw;
                if len > 32 {
                    return Err(DecodeError::BadValue(t));
                }
                if self.ipv4.len() >= MAX_ADDRESSES {
                    return Err(DecodeError::TooMany(t));
                }
                self.ipv4.push((Ipv4Addr::new(a, b, c, d), len));
            }
            tlv::IPV6 => {
                let raw = fixed::<17>(t, v)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(raw.get(..16).unwrap_or(&[0; 16]));
                let len = raw.get(16).copied().unwrap_or(u8::MAX);
                if len > 128 {
                    return Err(DecodeError::BadValue(t));
                }
                if self.ipv6.len() >= MAX_ADDRESSES {
                    return Err(DecodeError::TooMany(t));
                }
                self.ipv6.push((Ipv6Addr::from(octets), len));
            }
            tlv::CONTROL_PORT => once(&mut self.control, t, port(t, v)?)?,
            tlv::WS_PORT => once(&mut self.ws, t, port(t, v)?)?,
            tlv::TLS_PORT => once(&mut self.tls, t, port(t, v)?)?,
            tlv::WSS_PORT => once(&mut self.wss, t, port(t, v)?)?,
            // Unknown TLV: a newer sender; skip it.
            _ => {}
        }
        Ok(())
    }

    fn finish(self) -> Result<Announcement, DecodeError> {
        Ok(Announcement {
            node_id: self.node_id.ok_or(DecodeError::Missing(tlv::NODE_ID))?,
            hold_secs: self.hold.ok_or(DecodeError::Missing(tlv::HOLD))?,
            identity: self.identity.ok_or(DecodeError::Missing(tlv::IDENTITY))?,
            version: self.version.unwrap_or_default(),
            platform: self.platform.unwrap_or_default(),
            board: self.board.unwrap_or_default(),
            uptime_secs: self.uptime,
            interface: self.interface.unwrap_or_default(),
            mac: self.mac,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            control_port: self.control,
            ws_port: self.ws,
            tls_port: self.tls,
            wss_port: self.wss,
        })
    }
}

/// Parse one datagram. Anything malformed is an error, never a panic; the
/// caller drops it.
pub fn decode(packet: &[u8]) -> Result<Announcement, DecodeError> {
    if packet.len() > MAX_PACKET {
        return Err(DecodeError::TooLarge(packet.len()));
    }
    let (Some(head), Some(body)) = (packet.get(..HEADER_LEN), packet.get(HEADER_LEN..)) else {
        return Err(DecodeError::TooShort(packet.len()));
    };
    let [m0, m1, m2, m3, version, _reserved, l0, l1] = fixed::<HEADER_LEN>(0, head)?;
    if [m0, m1, m2, m3] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if version != VERSION {
        return Err(DecodeError::Version(version));
    }
    let declared = usize::from(u16::from_be_bytes([l0, l1]));
    if declared != body.len() {
        return Err(DecodeError::Length {
            header: declared,
            actual: body.len(),
        });
    }
    let mut partial = Partial::default();
    let mut at = 0usize;
    while at < body.len() {
        let Some(&[t0, t1, n0, n1]) = body.get(at..at + 4) else {
            return Err(DecodeError::Truncated(HEADER_LEN + at));
        };
        let t = u16::from_be_bytes([t0, t1]);
        let len = usize::from(u16::from_be_bytes([n0, n1]));
        let value = body
            .get(at + 4..at + 4 + len)
            .ok_or(DecodeError::BadLength { tlv: t, len })?;
        partial.take(t, value)?;
        at += 4 + len;
    }
    partial.finish()
}

/// The discovery settings of the candidate: interval in range, listed
/// interfaces exist.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    let d = &cfg.ip.neighbor_discovery;
    if !INTERVAL_RANGE.contains(&d.interval_secs) {
        out.push(Issue::new(
            "ip.neighbor_discovery.interval_secs",
            format!(
                "must be {}..={} seconds",
                INTERVAL_RANGE.start(),
                INTERVAL_RANGE.end()
            ),
        ));
    }
    for name in &d.interfaces {
        if !cfg.interfaces.contains_key(name) {
            out.push(Issue::new(
                "ip.neighbor_discovery.interfaces",
                format!("no interface '{name}'"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> Announcement {
        Announcement {
            node_id: NodeId([7; 16]),
            hold_secs: 120,
            identity: "core-1".into(),
            version: "0.1.0".into(),
            platform: "CoreRouter".into(),
            board: "x86_64".into(),
            uptime_secs: Some(3600),
            interface: "ether1".into(),
            mac: Some([2, 0, 0, 0, 0, 1]),
            ipv4: vec![(Ipv4Addr::new(10, 0, 0, 1), 24)],
            ipv6: vec![("fe80::1".parse().unwrap(), 64)],
            control_port: Some(7979),
            ws_port: Some(7980),
            tls_port: Some(8729),
            wss_port: None,
        }
    }

    #[test]
    fn round_trip_and_wire_header() {
        let a = sample();
        let bytes = a.encode().unwrap();
        assert_eq!(&bytes[..4], b"CRDP");
        assert_eq!(bytes[4], VERSION);
        assert_eq!(
            usize::from(u16::from_be_bytes([bytes[6], bytes[7]])),
            bytes.len() - HEADER_LEN
        );
        assert_eq!(decode(&bytes).unwrap(), a);
    }

    #[test]
    fn unknown_tlvs_are_skipped() {
        let mut bytes = sample().encode().unwrap();
        bytes.extend_from_slice(&[0x12, 0x34, 0, 3, 1, 2, 3]);
        let len = u16::try_from(bytes.len() - HEADER_LEN).unwrap();
        bytes[6..8].copy_from_slice(&len.to_be_bytes());
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn hostile_datagrams_are_refused() {
        let good = sample().encode().unwrap();
        assert_eq!(decode(&good[..5]), Err(DecodeError::TooShort(5)));
        assert_eq!(
            decode(&vec![0; MAX_PACKET + 1]),
            Err(DecodeError::TooLarge(MAX_PACKET + 1))
        );
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(decode(&magic), Err(DecodeError::BadMagic));
        let mut version = good.clone();
        version[4] = 2;
        assert_eq!(decode(&version), Err(DecodeError::Version(2)));
        // Cut in the middle: the header length no longer matches.
        assert!(matches!(
            decode(&good[..good.len() - 1]),
            Err(DecodeError::Length { .. })
        ));
        // A TLV claiming more bytes than the datagram has.
        let mut long = good.clone();
        long[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&999u16.to_be_bytes());
        assert!(matches!(
            decode(&long),
            Err(DecodeError::BadLength { tlv: 1, .. })
        ));
        // Duplicate node id.
        let mut dup = good.clone();
        dup.extend_from_slice(&good[HEADER_LEN..HEADER_LEN + 20]);
        let len = u16::try_from(dup.len() - HEADER_LEN).unwrap();
        dup[6..8].copy_from_slice(&len.to_be_bytes());
        assert_eq!(decode(&dup), Err(DecodeError::Duplicate(tlv::NODE_ID)));
        // Control characters never reach the wire.
        let mut a = sample();
        a.identity = "x\u{7}".into();
        assert_eq!(a.encode(), Err(EncodeError::BadText { field: "identity" }));
    }

    #[test]
    fn too_many_addresses() {
        let mut a = sample();
        a.ipv4 = vec![(Ipv4Addr::LOCALHOST, 8); MAX_ADDRESSES + 1];
        assert!(matches!(
            a.encode(),
            Err(EncodeError::TooManyAddresses { .. })
        ));
    }

    #[test]
    fn worst_case_fits_one_datagram() {
        let long = "é".repeat(MAX_TEXT / 2);
        let a = Announcement {
            identity: long.clone(),
            version: long.clone(),
            platform: long.clone(),
            board: long.clone(),
            interface: long,
            ipv4: vec![(Ipv4Addr::BROADCAST, 32); MAX_ADDRESSES],
            ipv6: vec![(Ipv6Addr::LOCALHOST, 128); MAX_ADDRESSES],
            ..sample()
        };
        let bytes = a.encode().unwrap();
        assert!(bytes.len() <= MAX_PACKET, "{}", bytes.len());
        assert_eq!(decode(&bytes).unwrap(), a);
    }

    #[test]
    fn fit_text_cuts_on_char_boundary() {
        assert_eq!(fit_text("ação", 3), "aç");
        assert_eq!(fit_text("a\nb", 10), "ab");
        assert_eq!(fit_text("r1", 64), "r1");
    }

    #[test]
    fn node_id_text() {
        let id = NodeId([0xab; 16]);
        assert_eq!(id.to_string().parse::<NodeId>().unwrap(), id);
        assert!("xyz".parse::<NodeId>().is_err());
        assert!("ü".repeat(16).parse::<NodeId>().is_err());
    }

    #[test]
    fn settings_validation() {
        let mut cfg = Config::default();
        assert!(validate(&cfg).is_empty());
        cfg.ip.neighbor_discovery.interval_secs = 0;
        cfg.ip
            .neighbor_discovery
            .interfaces
            .insert("ether9".parse().unwrap());
        assert_eq!(validate(&cfg).len(), 2);
    }

    fn text_strategy() -> impl Strategy<Value = String> {
        "[^\\p{Cc}]{0,40}".prop_map(|s| fit_text(&s, MAX_TEXT))
    }

    fn announcement() -> impl Strategy<Value = Announcement> {
        (
            (
                any::<[u8; 16]>().prop_filter("non-zero", |b| *b != [0; 16]),
                any::<u16>(),
                text_strategy(),
                text_strategy(),
                text_strategy(),
                text_strategy(),
                text_strategy(),
            ),
            (
                proptest::option::of(any::<u64>()),
                proptest::option::of(any::<[u8; 6]>()),
                proptest::collection::vec((any::<[u8; 4]>(), 0u8..=32), 0..=MAX_ADDRESSES),
                proptest::collection::vec((any::<[u8; 16]>(), 0u8..=128), 0..=MAX_ADDRESSES),
                proptest::option::of(1u16..),
                proptest::option::of(1u16..),
                proptest::option::of(1u16..),
                proptest::option::of(1u16..),
            ),
        )
            .prop_map(
                |((id, hold, identity, version, platform, board, interface), rest)| {
                    let (uptime_secs, mac, v4, v6, control_port, ws_port, tls_port, wss_port) =
                        rest;
                    Announcement {
                        node_id: NodeId(id),
                        hold_secs: hold,
                        identity,
                        version,
                        platform,
                        board,
                        uptime_secs,
                        interface,
                        mac,
                        ipv4: v4.into_iter().map(|(a, l)| (a.into(), l)).collect(),
                        ipv6: v6.into_iter().map(|(a, l)| (a.into(), l)).collect(),
                        control_port,
                        ws_port,
                        tls_port,
                        wss_port,
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1400)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn decode_never_panics_after_a_valid_header(
            body in proptest::collection::vec(any::<u8>(), 0..1224),
        ) {
            let mut bytes = MAGIC.to_vec();
            bytes.push(VERSION);
            bytes.push(0);
            bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&body);
            let _ = decode(&bytes);
        }

        #[test]
        fn encode_decode_round_trip(a in announcement()) {
            let bytes = a.encode().unwrap();
            prop_assert!(bytes.len() <= MAX_PACKET);
            prop_assert_eq!(decode(&bytes).unwrap(), a);
        }

        #[test]
        fn flipped_bytes_never_panic(a in announcement(), at in any::<usize>(), byte in any::<u8>()) {
            let mut bytes = a.encode().unwrap();
            let i = at % bytes.len();
            bytes[i] = byte;
            let _ = decode(&bytes);
        }
    }
}

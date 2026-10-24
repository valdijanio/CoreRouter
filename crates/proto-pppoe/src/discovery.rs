//! PPPoE packets (RFC 2516 §4) and the Discovery tags (RFC 2516 Appendix A,
//! RFC 4638 PPP-Max-Payload, RFC 4679/TR-101 line identification).
//!
//! [`parse`] borrows the frame: tags are slices into it, read in one pass
//! into [`Tags`] without allocating. [`DiscoveryWriter`] appends a packet to a
//! reusable buffer and patches the length at the end.

use crate::eth::{self, ETHERTYPE_DISCOVERY, Vlans};
use crate::wire::{Mac, Reader, WireError, len_u16, patch_u16, put_u16, put_u32};

/// RFC 2516 §4: VER = 1, TYPE = 1.
pub const VER_TYPE: u8 = 0x11;
/// PPPoE header length.
pub const HEADER_LEN: usize = 6;
/// Largest PPPoE payload in a 1500-byte Ethernet payload.
pub const MAX_PAYLOAD_1500: usize = 1500 - HEADER_LEN;
/// RFC 2516 §7: the PPP MRU of a plain PPPoE session.
pub const DEFAULT_MRU: u16 = 1492;

/// PPPoE CODE field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// Session stage (§6).
    Session,
    /// Active Discovery Initiation (§5.1).
    Padi,
    /// Active Discovery Offer (§5.2).
    Pado,
    /// Active Discovery Request (§5.3).
    Padr,
    /// Active Discovery Session-confirmation (§5.4).
    Pads,
    /// Active Discovery Terminate (§5.5).
    Padt,
    /// RFC 4937 PPPoE Active Discovery Message.
    Padm,
    /// RFC 4937 PPPoE Active Discovery Network.
    Padn,
}

impl Code {
    pub fn from_u8(v: u8) -> Option<Code> {
        Some(match v {
            0x00 => Code::Session,
            0x09 => Code::Padi,
            0x07 => Code::Pado,
            0x19 => Code::Padr,
            0x65 => Code::Pads,
            0xa7 => Code::Padt,
            0xd3 => Code::Padm,
            0xd4 => Code::Padn,
            _ => return None,
        })
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Code::Session => 0x00,
            Code::Padi => 0x09,
            Code::Pado => 0x07,
            Code::Padr => 0x19,
            Code::Pads => 0x65,
            Code::Padt => 0xa7,
            Code::Padm => 0xd3,
            Code::Padn => 0xd4,
        }
    }
}

/// Tag types (RFC 2516 Appendix A, RFC 4638, RFC 4937, RFC 5578).
pub mod tag {
    pub const END_OF_LIST: u16 = 0x0000;
    pub const SERVICE_NAME: u16 = 0x0101;
    pub const AC_NAME: u16 = 0x0102;
    pub const HOST_UNIQ: u16 = 0x0103;
    pub const AC_COOKIE: u16 = 0x0104;
    pub const VENDOR_SPECIFIC: u16 = 0x0105;
    pub const CREDITS: u16 = 0x0106;
    pub const METRICS: u16 = 0x0107;
    pub const SEQUENCE_NUMBER: u16 = 0x0108;
    pub const CREDIT_SCALE: u16 = 0x0109;
    pub const RELAY_SESSION_ID: u16 = 0x0110;
    pub const HURL: u16 = 0x0111;
    pub const MOTM: u16 = 0x0112;
    pub const PPP_MAX_PAYLOAD: u16 = 0x0120;
    pub const IP_ROUTE_ADD: u16 = 0x0121;
    pub const SERVICE_NAME_ERROR: u16 = 0x0201;
    pub const AC_SYSTEM_ERROR: u16 = 0x0202;
    pub const GENERIC_ERROR: u16 = 0x0203;
}

/// RFC 4679 §5 / TR-101: the Broadband Forum (ADSL Forum) IANA enterprise
/// number carried in a Vendor-Specific tag by intermediate agents.
pub const VENDOR_BBF: u32 = 3561;
/// RFC 4679 §5.1 sub-option: Agent-Circuit-ID (≤ 63 bytes).
pub const BBF_CIRCUIT_ID: u8 = 0x01;
/// RFC 4679 §5.2 sub-option: Agent-Remote-ID (≤ 63 bytes).
pub const BBF_REMOTE_ID: u8 = 0x02;
/// RFC 4679 §5: longest Agent-Circuit-ID / Agent-Remote-ID.
pub const BBF_ID_MAX: usize = 63;

/// The PPPoE header plus the borrowed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pppoe<'a> {
    pub code: Code,
    pub session_id: u16,
    pub payload: &'a [u8],
}

/// Parses the 6-byte PPPoE header. RFC 2516 §4: VER and TYPE MUST be 1;
/// LENGTH covers the payload only, and Ethernet padding past it is ignored.
pub fn parse_header(data: &[u8]) -> Result<Pppoe<'_>, WireError> {
    let mut r = Reader::new(data);
    let vt = r.u8()?;
    if vt != VER_TYPE {
        return Err(WireError::BadVerType(vt));
    }
    let c = r.u8()?;
    let code = Code::from_u8(c).ok_or(WireError::BadCode(c))?;
    let session_id = r.u16()?;
    let len = usize::from(r.u16()?);
    let rest = r.rest();
    let payload = rest.get(..len).ok_or(WireError::BadLength {
        field: len,
        have: rest.len(),
    })?;
    Ok(Pppoe {
        code,
        session_id,
        payload,
    })
}

/// One raw tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    pub kind: u16,
    pub value: &'a [u8],
}

/// Iterates the tags of a Discovery payload; stops at End-Of-List (RFC
/// 2516 Appendix A: "no further TAGs are present") and yields an error, then
/// nothing, when a length runs past the payload.
#[derive(Clone)]
pub struct TagIter<'a> {
    r: Reader<'a>,
    done: bool,
}

pub fn tags(payload: &[u8]) -> TagIter<'_> {
    TagIter {
        r: Reader::new(payload),
        done: false,
    }
}

impl<'a> Iterator for TagIter<'a> {
    type Item = Result<Tag<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.remaining() == 0 {
            return None;
        }
        let res = (|| {
            let kind = self.r.u16()?;
            let len = usize::from(self.r.u16()?);
            let have = self.r.remaining();
            let value = self
                .r
                .take(len)
                .map_err(|_| WireError::BadLength { field: len, have })?;
            Ok(Tag { kind, value })
        })();
        match res {
            Ok(t) if t.kind == tag::END_OF_LIST => {
                self.done = true;
                None
            }
            Ok(t) => Some(Ok(t)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// The tags a BNG acts on, read in one pass. The first occurrence of each tag
/// wins; repeats are counted (RFC 2516 §5.1: a PADI carries exactly one
/// Service-Name).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tags<'a> {
    pub service_name: Option<&'a [u8]>,
    pub service_names: u8,
    pub ac_name: Option<&'a [u8]>,
    pub host_uniq: Option<&'a [u8]>,
    pub ac_cookie: Option<&'a [u8]>,
    pub relay_session_id: Option<&'a [u8]>,
    /// RFC 4638 §4: the client's PPP-Max-Payload (MRU it can carry).
    pub ppp_max_payload: Option<u16>,
    pub service_name_error: Option<&'a [u8]>,
    pub ac_system_error: Option<&'a [u8]>,
    pub generic_error: Option<&'a [u8]>,
    /// RFC 4679 §5.1 Agent-Circuit-ID from a BBF Vendor-Specific tag.
    pub circuit_id: Option<&'a [u8]>,
    /// RFC 4679 §5.2 Agent-Remote-ID.
    pub remote_id: Option<&'a [u8]>,
    /// The raw first Vendor-Specific tag (including the vendor id).
    pub vendor: Option<&'a [u8]>,
    /// Tags of a type this crate does not interpret (Credits, Metrics, HURL…).
    pub unknown: u16,
}

impl<'a> Tags<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Tags<'a>, WireError> {
        let mut t = Tags::default();
        for item in tags(payload) {
            let Tag { kind, value } = item?;
            match kind {
                tag::SERVICE_NAME => {
                    t.service_names = t.service_names.saturating_add(1);
                    t.service_name.get_or_insert(value);
                }
                tag::AC_NAME => {
                    t.ac_name.get_or_insert(value);
                }
                tag::HOST_UNIQ => {
                    t.host_uniq.get_or_insert(value);
                }
                tag::AC_COOKIE => {
                    t.ac_cookie.get_or_insert(value);
                }
                tag::RELAY_SESSION_ID => {
                    t.relay_session_id.get_or_insert(value);
                }
                tag::PPP_MAX_PAYLOAD => {
                    // RFC 4638 §4: a two-octet unsigned integer.
                    let v: [u8; 2] = value.try_into().map_err(|_| WireError::BadOption {
                        kind: 0x20,
                        len: value.len(),
                    })?;
                    t.ppp_max_payload.get_or_insert(u16::from_be_bytes(v));
                }
                tag::SERVICE_NAME_ERROR => {
                    t.service_name_error.get_or_insert(value);
                }
                tag::AC_SYSTEM_ERROR => {
                    t.ac_system_error.get_or_insert(value);
                }
                tag::GENERIC_ERROR => {
                    t.generic_error.get_or_insert(value);
                }
                tag::VENDOR_SPECIFIC => {
                    if t.vendor.is_none() {
                        t.vendor = Some(value);
                        t.read_bbf(value);
                    }
                }
                _ => t.unknown = t.unknown.saturating_add(1),
            }
        }
        Ok(t)
    }

    /// RFC 4679 §5: vendor id 3561 followed by type/length sub-options. A
    /// malformed sub-option ends the walk: line ids are informational, so a
    /// broken one is dropped instead of refusing the subscriber.
    fn read_bbf(&mut self, value: &'a [u8]) {
        let mut r = Reader::new(value);
        if r.u32().ok() != Some(VENDOR_BBF) {
            return;
        }
        while r.remaining() >= 2 {
            let (Ok(kind), Ok(len)) = (r.u8(), r.u8()) else {
                return;
            };
            let Ok(v) = r.take(usize::from(len)) else {
                return;
            };
            if v.len() > BBF_ID_MAX {
                continue;
            }
            match kind {
                BBF_CIRCUIT_ID => {
                    self.circuit_id.get_or_insert(v);
                }
                BBF_REMOTE_ID => {
                    self.remote_id.get_or_insert(v);
                }
                _ => {}
            }
        }
    }
}

/// A Discovery frame read from the wire: L2 addressing, PPPoE header, tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discovery<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub vlans: Vlans,
    pub code: Code,
    pub session_id: u16,
    pub tags: Tags<'a>,
}

/// Parses an Ethernet frame carrying a Discovery packet (EtherType 0x8863).
pub fn parse(frame: &[u8]) -> Result<Discovery<'_>, WireError> {
    let e = eth::parse(frame)?;
    if e.ethertype != ETHERTYPE_DISCOVERY {
        return Err(WireError::BadEtherType(e.ethertype));
    }
    let p = parse_header(e.payload)?;
    if p.code == Code::Session {
        return Err(WireError::BadCode(0));
    }
    Ok(Discovery {
        dst: e.dst,
        src: e.src,
        vlans: e.vlans,
        code: p.code,
        session_id: p.session_id,
        tags: Tags::parse(p.payload)?,
    })
}

/// Appends a Discovery frame to a buffer; tags in call order.
pub struct DiscoveryWriter<'b> {
    out: &'b mut Vec<u8>,
    start: usize,
    len_pos: usize,
}

impl<'b> DiscoveryWriter<'b> {
    pub fn begin(
        out: &'b mut Vec<u8>,
        dst: Mac,
        src: Mac,
        vlans: Vlans,
        code: Code,
        session_id: u16,
    ) -> Self {
        let start = out.len();
        eth::put_header(out, dst, src, vlans, ETHERTYPE_DISCOVERY);
        out.push(VER_TYPE);
        out.push(code.to_u8());
        put_u16(out, session_id);
        let len_pos = out.len();
        put_u16(out, 0);
        DiscoveryWriter {
            out,
            start,
            len_pos,
        }
    }

    pub fn tag(&mut self, kind: u16, value: &[u8]) -> &mut Self {
        put_u16(self.out, kind);
        // A value over 64 KiB cannot be framed; `finish` refuses the frame.
        put_u16(self.out, u16::try_from(value.len()).unwrap_or(u16::MAX));
        self.out.extend_from_slice(value);
        self
    }

    pub fn tag_u16(&mut self, kind: u16, v: u16) -> &mut Self {
        self.tag(kind, &v.to_be_bytes())
    }

    /// A BBF Vendor-Specific tag with circuit/remote ids (RFC 4679 §5), as a
    /// relay agent inserts it; used by the test client.
    pub fn tag_bbf(&mut self, circuit: Option<&[u8]>, remote: Option<&[u8]>) -> &mut Self {
        let mut v = Vec::with_capacity(4 + 2 * (BBF_ID_MAX + 2));
        put_u32(&mut v, VENDOR_BBF);
        for (k, s) in [(BBF_CIRCUIT_ID, circuit), (BBF_REMOTE_ID, remote)] {
            if let Some(s) = s {
                let s = s.get(..BBF_ID_MAX).unwrap_or(s);
                v.push(k);
                v.push(u8::try_from(s.len()).unwrap_or(0));
                v.extend_from_slice(s);
            }
        }
        self.tag(tag::VENDOR_SPECIFIC, &v)
    }

    /// Patches LENGTH; refuses a payload that would not fit a 1500-byte
    /// Ethernet payload (the frame is removed from the buffer).
    pub fn finish(self) -> Result<usize, WireError> {
        let payload = self.out.len() - self.len_pos - 2;
        if payload > MAX_PAYLOAD_1500 {
            self.out.truncate(self.start);
            return Err(WireError::TooLong(MAX_PAYLOAD_1500));
        }
        patch_u16(self.out, self.len_pos, len_u16(payload)?);
        Ok(self.out.len() - self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Mac = Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const AC: Mac = Mac([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);

    fn padi(extra: impl FnOnce(&mut DiscoveryWriter<'_>)) -> Vec<u8> {
        let mut b = Vec::new();
        let mut w =
            DiscoveryWriter::begin(&mut b, Mac::BROADCAST, PEER, Vlans::NONE, Code::Padi, 0);
        w.tag(tag::SERVICE_NAME, b"");
        extra(&mut w);
        w.finish().unwrap();
        b
    }

    #[test]
    fn rfc2516_5_1_padi_round_trip() {
        let b = padi(|w| {
            w.tag(tag::HOST_UNIQ, &[1, 2, 3, 4]);
        });
        let d = parse(&b).unwrap();
        assert_eq!(d.code, Code::Padi);
        assert_eq!(d.session_id, 0);
        assert_eq!(d.dst, Mac::BROADCAST);
        assert_eq!(d.tags.service_name, Some(&b""[..]));
        assert_eq!(d.tags.service_names, 1);
        assert_eq!(d.tags.host_uniq, Some(&[1u8, 2, 3, 4][..]));
    }

    #[test]
    fn rfc2516_4_ver_type_must_be_one() {
        let mut b = padi(|_| {});
        b[14] = 0x21;
        assert_eq!(parse(&b), Err(WireError::BadVerType(0x21)));
    }

    #[test]
    fn rfc2516_4_ethernet_padding_after_length_is_ignored() {
        let mut b = padi(|_| {});
        b.extend_from_slice(&[0u8; 30]);
        let d = parse(&b).unwrap();
        assert_eq!(d.tags.unknown, 0);
    }

    #[test]
    fn rfc2516_appendix_a_end_of_list_stops_the_walk() {
        let b = padi(|w| {
            w.tag(tag::END_OF_LIST, b"");
            w.tag(tag::HOST_UNIQ, b"after");
        });
        assert_eq!(parse(&b).unwrap().tags.host_uniq, None);
    }

    #[test]
    fn tag_length_past_payload_is_refused() {
        let mut b = padi(|w| {
            w.tag(tag::HOST_UNIQ, b"ab");
        });
        let n = b.len();
        b[n - 3] = 0x40; // Host-Uniq length 0x4002 > rest
        assert!(matches!(parse(&b), Err(WireError::BadLength { .. })));
    }

    #[test]
    fn pppoe_length_past_frame_is_refused() {
        let mut b = padi(|_| {});
        b[18] = 0xff;
        assert!(matches!(parse(&b), Err(WireError::BadLength { .. })));
    }

    #[test]
    fn rfc4638_ppp_max_payload_is_two_octets() {
        let b = padi(|w| {
            w.tag_u16(tag::PPP_MAX_PAYLOAD, 1500);
        });
        assert_eq!(parse(&b).unwrap().tags.ppp_max_payload, Some(1500));
        let b = padi(|w| {
            w.tag(tag::PPP_MAX_PAYLOAD, &[5, 0xdc, 0]);
        });
        assert!(parse(&b).is_err());
    }

    #[test]
    fn rfc4679_circuit_and_remote_id() {
        let b = padi(|w| {
            w.tag_bbf(Some(b"olt1 eth 1/1/1:100"), Some(b"cust-42"));
        });
        let t = parse(&b).unwrap().tags;
        assert_eq!(t.circuit_id, Some(&b"olt1 eth 1/1/1:100"[..]));
        assert_eq!(t.remote_id, Some(&b"cust-42"[..]));
    }

    #[test]
    fn other_vendor_ids_are_kept_raw_not_read_as_bbf() {
        let b = padi(|w| {
            w.tag(tag::VENDOR_SPECIFIC, &[0, 0, 0, 9, 1, 1, b'x']);
        });
        let t = parse(&b).unwrap().tags;
        assert_eq!(t.circuit_id, None);
        assert_eq!(t.vendor.map(<[u8]>::len), Some(7));
    }

    #[test]
    fn duplicate_service_names_are_counted() {
        let b = padi(|w| {
            w.tag(tag::SERVICE_NAME, b"second");
        });
        let t = parse(&b).unwrap().tags;
        assert_eq!(t.service_names, 2);
        assert_eq!(t.service_name, Some(&b""[..]));
    }

    #[test]
    fn oversized_frame_is_not_written() {
        let mut b = vec![7u8];
        let mut w = DiscoveryWriter::begin(&mut b, PEER, AC, Vlans::NONE, Code::Pado, 0);
        w.tag(tag::AC_NAME, &[0u8; 1600]);
        assert!(w.finish().is_err());
        assert_eq!(b, vec![7u8]);
    }

    #[test]
    fn session_code_on_discovery_ethertype_is_refused() {
        let mut b = Vec::new();
        DiscoveryWriter::begin(&mut b, PEER, AC, Vlans::NONE, Code::Session, 1)
            .finish()
            .unwrap();
        assert!(parse(&b).is_err());
    }
}

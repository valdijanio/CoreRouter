//! PPP over the PPPoE Session stage: the session header (RFC 2516 §6), the
//! PPP Protocol field (RFC 1661 §2), the control packet format shared by
//! LCP and the NCPs (RFC 1661 §5) and its Configuration Options (§6).

use crate::discovery::{self, Code, VER_TYPE};
use crate::eth::{self, ETHERTYPE_SESSION, Vlans};
use crate::wire::{Mac, Reader, WireError, len_u16, patch_u16, put_u16};

/// PPP protocol numbers (IANA "PPP DLL Protocol Numbers").
pub mod proto {
    pub const IPV4: u16 = 0x0021;
    pub const MP: u16 = 0x003d;
    pub const IPV6: u16 = 0x0057;
    pub const IPCP: u16 = 0x8021;
    pub const IPV6CP: u16 = 0x8057;
    pub const CCP: u16 = 0x80fd;
    pub const LCP: u16 = 0xc021;
    pub const PAP: u16 = 0xc023;
    pub const LQR: u16 = 0xc025;
    pub const CHAP: u16 = 0xc223;
    pub const EAP: u16 = 0xc227;
}

/// RFC 1661 §2: a valid Protocol value is odd in its low octet and even in its
/// high octet.
pub fn protocol_is_valid(p: u16) -> bool {
    p & 0x0101 == 0x0001
}

/// L2 addressing of one PPPoE session as seen from the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Link {
    pub dst: Mac,
    pub src: Mac,
    pub vlans: Vlans,
}

impl Link {
    /// The same link seen from the other end.
    pub fn reversed(&self) -> Link {
        Link {
            dst: self.src,
            src: self.dst,
            vlans: self.vlans,
        }
    }
}

/// A Session-stage frame: addressing, SESSION_ID, PPP protocol, information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionFrame<'a> {
    pub link: Link,
    pub session_id: u16,
    pub protocol: u16,
    pub info: &'a [u8],
}

/// Reads the PPP Protocol field. RFC 1661 §6.5: a peer that compressed it
/// (PFC) sends one octet when the value is below 0x100; a stray
/// Address/Control pair (0xFF 0x03) is dropped first — it cannot be a
/// protocol (its high octet is odd).
pub fn parse_protocol(data: &[u8]) -> Result<(u16, &[u8]), WireError> {
    let data = match data {
        [0xff, 0x03, rest @ ..] => rest,
        d => d,
    };
    match data {
        [b0, rest @ ..] if b0 & 1 == 1 => Ok((u16::from(*b0), rest)),
        [b0, b1, rest @ ..] => {
            let p = u16::from_be_bytes([*b0, *b1]);
            if protocol_is_valid(p) {
                Ok((p, rest))
            } else {
                Err(WireError::Malformed("PPP protocol field"))
            }
        }
        _ => Err(WireError::Truncated {
            need: 2,
            have: data.len(),
        }),
    }
}

/// Parses an Ethernet frame carrying a Session packet (EtherType 0x8864,
/// RFC 2516 §6: CODE 0x00, SESSION_ID non-zero for the session).
pub fn parse_session(frame: &[u8]) -> Result<SessionFrame<'_>, WireError> {
    let e = eth::parse(frame)?;
    if e.ethertype != ETHERTYPE_SESSION {
        return Err(WireError::BadEtherType(e.ethertype));
    }
    let p = discovery::parse_header(e.payload)?;
    if p.code != Code::Session {
        return Err(WireError::BadCode(p.code.to_u8()));
    }
    let (protocol, info) = parse_protocol(p.payload)?;
    Ok(SessionFrame {
        link: Link {
            dst: e.dst,
            src: e.src,
            vlans: e.vlans,
        },
        session_id: p.session_id,
        protocol,
        info,
    })
}

/// A control packet (RFC 1661 §5): Code, Identifier, Length, Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control<'a> {
    pub code: u8,
    pub id: u8,
    pub data: &'a [u8],
}

/// Shortest control packet (Code + Identifier + Length).
pub const CONTROL_HEADER: usize = 4;

/// RFC 1661 §5: "Octets outside the range of the Length field are treated as
/// padding and are ignored on reception"; a Length below 4 or past the data
/// is silently discarded.
pub fn parse_control(info: &[u8]) -> Result<Control<'_>, WireError> {
    let mut r = Reader::new(info);
    let code = r.u8()?;
    let id = r.u8()?;
    let len = usize::from(r.u16()?);
    if len < CONTROL_HEADER {
        return Err(WireError::BadLength {
            field: len,
            have: info.len(),
        });
    }
    let data = r
        .take(len - CONTROL_HEADER)
        .map_err(|_| WireError::BadLength {
            field: len,
            have: info.len(),
        })?;
    Ok(Control { code, id, data })
}

/// One Configuration Option (RFC 1661 §6): Type, Length (≥ 2), Data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opt<'a> {
    pub kind: u8,
    pub data: &'a [u8],
}

/// Iterates the options of a Configure packet; a malformed length yields an
/// error and ends the walk (RFC 1661 §6: such a packet is invalid).
#[derive(Clone)]
pub struct OptIter<'a> {
    r: Reader<'a>,
    done: bool,
}

pub fn options(data: &[u8]) -> OptIter<'_> {
    OptIter {
        r: Reader::new(data),
        done: false,
    }
}

impl<'a> Iterator for OptIter<'a> {
    type Item = Result<Opt<'a>, WireError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.r.remaining() == 0 {
            return None;
        }
        let res = (|| {
            let kind = self.r.u8()?;
            let len = usize::from(self.r.u8()?);
            if len < 2 {
                return Err(WireError::BadOption { kind, len });
            }
            let data = self
                .r
                .take(len - 2)
                .map_err(|_| WireError::BadOption { kind, len })?;
            Ok(Opt { kind, data })
        })();
        if res.is_err() {
            self.done = true;
        }
        Some(res)
    }
}

/// Checks that every option of `data` is well formed.
pub fn options_valid(data: &[u8]) -> bool {
    options(data).all(|o| o.is_ok())
}

/// Appends one option (Type, Length, Data); refuses data over 253 bytes.
pub fn put_opt(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<(), WireError> {
    let len = u8::try_from(data.len() + 2).map_err(|_| WireError::TooLong(255))?;
    out.push(kind);
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

/// Appends a Session-stage frame: Ethernet, PPPoE header, Protocol; the
/// caller appends the information field and calls [`SessionWriter::finish`].
pub struct SessionWriter<'b> {
    out: &'b mut Vec<u8>,
    start: usize,
    pppoe_len_pos: usize,
    ctl_len_pos: Option<usize>,
}

impl<'b> SessionWriter<'b> {
    pub fn begin(out: &'b mut Vec<u8>, link: &Link, session_id: u16, protocol: u16) -> Self {
        let start = out.len();
        eth::put_header(out, link.dst, link.src, link.vlans, ETHERTYPE_SESSION);
        out.push(VER_TYPE);
        out.push(Code::Session.to_u8());
        put_u16(out, session_id);
        let pppoe_len_pos = out.len();
        put_u16(out, 0);
        // RFC 2516 §7: PFC is NOT RECOMMENDED; the field is always two octets.
        put_u16(out, protocol);
        SessionWriter {
            out,
            start,
            pppoe_len_pos,
            ctl_len_pos: None,
        }
    }

    /// Begins a frame holding one control packet.
    pub fn control(
        out: &'b mut Vec<u8>,
        link: &Link,
        session_id: u16,
        protocol: u16,
        code: u8,
        id: u8,
    ) -> Self {
        let mut w = SessionWriter::begin(out, link, session_id, protocol);
        w.out.push(code);
        w.out.push(id);
        w.ctl_len_pos = Some(w.out.len());
        put_u16(w.out, 0);
        w
    }

    pub fn buf(&mut self) -> &mut Vec<u8> {
        self.out
    }

    /// Bytes of PPP information written so far (after the Protocol field).
    pub fn info_len(&self) -> usize {
        self.out.len() - self.pppoe_len_pos - 4
    }

    /// Patches the lengths. A frame whose PPP information would exceed
    /// `max_info` (the peer's MRU) is removed and refused.
    pub fn finish(self, max_info: usize) -> Result<usize, WireError> {
        if self.info_len() > max_info {
            self.out.truncate(self.start);
            return Err(WireError::TooLong(max_info));
        }
        let pppoe = self.out.len() - self.pppoe_len_pos - 2;
        patch_u16(self.out, self.pppoe_len_pos, len_u16(pppoe)?);
        if let Some(p) = self.ctl_len_pos {
            let ctl = self.out.len() - p + 2;
            patch_u16(self.out, p, len_u16(ctl)?);
        }
        Ok(self.out.len() - self.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> Link {
        Link {
            dst: Mac([2, 0, 0, 0, 0, 1]),
            src: Mac([2, 0, 0, 0, 0, 2]),
            vlans: Vlans::single(10),
        }
    }

    #[test]
    fn rfc1661_2_protocol_values() {
        assert!(protocol_is_valid(proto::LCP));
        assert!(protocol_is_valid(proto::IPV4));
        assert!(!protocol_is_valid(0xc022));
        assert!(!protocol_is_valid(0x0121));
    }

    #[test]
    fn rfc1661_6_5_compressed_protocol_field_is_read() {
        assert_eq!(parse_protocol(&[0x21, 9]).unwrap(), (0x21, &[9u8][..]));
        assert_eq!(parse_protocol(&[0xc0, 0x21]).unwrap(), (0xc021, &[][..]));
        assert_eq!(
            parse_protocol(&[0xff, 0x03, 0xc0, 0x21]).unwrap(),
            (0xc021, &[][..])
        );
        assert!(parse_protocol(&[0xc0, 0x22]).is_err());
        assert!(parse_protocol(&[0xc0]).is_err());
    }

    #[test]
    fn rfc1661_5_padding_past_length_is_ignored() {
        let c = parse_control(&[1, 7, 0, 6, 0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        assert_eq!(c.data, &[0xaa, 0xbb]);
        assert!(parse_control(&[1, 7, 0, 3]).is_err());
        assert!(parse_control(&[1, 7, 0, 9, 0]).is_err());
    }

    #[test]
    fn rfc1661_6_option_length_below_two_is_invalid() {
        assert!(options(&[1, 1]).next().unwrap().is_err());
        assert!(options(&[1, 4, 5]).next().unwrap().is_err());
        let v: Vec<_> = options(&[1, 4, 5, 220, 7, 2]).map(|o| o.unwrap()).collect();
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].kind, 7);
    }

    #[test]
    fn session_frame_round_trip() {
        let mut b = Vec::new();
        let mut w = SessionWriter::control(&mut b, &link(), 0x1234, proto::LCP, 9, 3);
        w.buf().extend_from_slice(&[0, 0, 0, 0]);
        w.finish(1492).unwrap();
        let f = parse_session(&b).unwrap();
        assert_eq!(f.session_id, 0x1234);
        assert_eq!(f.protocol, proto::LCP);
        assert_eq!(f.link.vlans, Vlans::single(10));
        let c = parse_control(f.info).unwrap();
        assert_eq!((c.code, c.id, c.data), (9, 3, &[0u8, 0, 0, 0][..]));
    }

    #[test]
    fn frame_over_peer_mru_is_refused() {
        let mut b = Vec::new();
        let mut w = SessionWriter::control(&mut b, &link(), 1, proto::LCP, 9, 3);
        w.buf().extend_from_slice(&[0u8; 100]);
        assert!(w.finish(64).is_err());
        assert!(b.is_empty());
    }
}

//! LCP (RFC 1661): codes and Configuration Options, read into typed views.
//!
//! What PPPoE allows is fixed by RFC 2516 §7: MRU at most 1492 (or the
//! RFC 4638 PPP-Max-Payload), ACCM, ACFC and FCS-Alternatives MUST NOT be
//! requested and MUST be rejected, PFC is NOT RECOMMENDED (this crate rejects
//! it: the data plane reads a two-octet protocol field), Magic-Number is
//! RECOMMENDED. The negotiation itself lives in `session::lcp`.

use crate::ppp::{Opt, put_opt};
use crate::wire::WireError;

/// LCP codes (RFC 1661 §5, RFC 1570 §2).
pub mod code {
    pub const CONFIGURE_REQUEST: u8 = 1;
    pub const CONFIGURE_ACK: u8 = 2;
    pub const CONFIGURE_NAK: u8 = 3;
    pub const CONFIGURE_REJECT: u8 = 4;
    pub const TERMINATE_REQUEST: u8 = 5;
    pub const TERMINATE_ACK: u8 = 6;
    pub const CODE_REJECT: u8 = 7;
    pub const PROTOCOL_REJECT: u8 = 8;
    pub const ECHO_REQUEST: u8 = 9;
    pub const ECHO_REPLY: u8 = 10;
    pub const DISCARD_REQUEST: u8 = 11;
    /// RFC 1570 §2.1.
    pub const IDENTIFICATION: u8 = 12;
    /// RFC 1570 §2.2.
    pub const TIME_REMAINING: u8 = 13;
}

/// LCP option types (RFC 1661 §6, RFC 1570, RFC 1990, RFC 1962).
pub mod opt {
    pub const MRU: u8 = 1;
    pub const ACCM: u8 = 2;
    pub const AUTH_PROTOCOL: u8 = 3;
    pub const QUALITY_PROTOCOL: u8 = 4;
    pub const MAGIC_NUMBER: u8 = 5;
    pub const PFC: u8 = 7;
    pub const ACFC: u8 = 8;
    pub const FCS_ALTERNATIVES: u8 = 9;
    pub const CALLBACK: u8 = 13;
    /// RFC 1990 §5.1.1 Multilink MRRU.
    pub const MRRU: u8 = 17;
    /// RFC 1990 §5.1.2.
    pub const SHORT_SEQUENCE: u8 = 18;
    /// RFC 1990 §5.1.3.
    pub const ENDPOINT_DISCRIMINATOR: u8 = 19;
}

/// The authentication protocols a BNG negotiates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthProto {
    /// RFC 1334: 0xc023.
    Pap,
    /// RFC 1994: 0xc223, algorithm 5.
    ChapMd5,
    /// RFC 2433: 0xc223, algorithm 0x80.
    MsChapV1,
    /// RFC 2759: 0xc223, algorithm 0x81.
    MsChapV2,
}

impl AuthProto {
    /// Option data (Protocol + algorithm).
    pub fn data(self) -> &'static [u8] {
        match self {
            AuthProto::Pap => &[0xc0, 0x23],
            AuthProto::ChapMd5 => &[0xc2, 0x23, 5],
            AuthProto::MsChapV1 => &[0xc2, 0x23, 0x80],
            AuthProto::MsChapV2 => &[0xc2, 0x23, 0x81],
        }
    }

    pub fn from_data(d: &[u8]) -> Option<AuthProto> {
        Some(match d {
            [0xc0, 0x23] => AuthProto::Pap,
            [0xc2, 0x23, 5] => AuthProto::ChapMd5,
            [0xc2, 0x23, 0x80] => AuthProto::MsChapV1,
            [0xc2, 0x23, 0x81] => AuthProto::MsChapV2,
            _ => return None,
        })
    }

    /// RouterOS names (`authentication=` of `/ppp profile` and the server).
    pub fn name(self) -> &'static str {
        match self {
            AuthProto::Pap => "pap",
            AuthProto::ChapMd5 => "chap",
            AuthProto::MsChapV1 => "mschap1",
            AuthProto::MsChapV2 => "mschap2",
        }
    }
}

/// A typed LCP option borrowing the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcpOpt<'a> {
    Mru(u16),
    Accm(u32),
    /// A known authentication protocol.
    Auth(AuthProto),
    /// Some other protocol (EAP, CHAP with an unknown algorithm…).
    AuthOther(&'a [u8]),
    Quality(&'a [u8]),
    Magic(u32),
    Pfc,
    Acfc,
    FcsAlternatives(u8),
    Callback(&'a [u8]),
    /// RFC 1990: parsed, never accepted (no multilink).
    Mrru(u16),
    ShortSequence,
    EndpointDiscriminator {
        class: u8,
        address: &'a [u8],
    },
    Unknown(Opt<'a>),
}

fn fixed<const N: usize>(o: &Opt<'_>) -> Result<[u8; N], WireError> {
    o.data.try_into().map_err(|_| WireError::BadOption {
        kind: o.kind,
        len: o.data.len() + 2,
    })
}

impl<'a> LcpOpt<'a> {
    /// Reads one option; a known option with the wrong length is an error
    /// (the whole Configure packet is then invalid and dropped).
    pub fn parse(o: Opt<'a>) -> Result<LcpOpt<'a>, WireError> {
        Ok(match o.kind {
            opt::MRU => LcpOpt::Mru(u16::from_be_bytes(fixed(&o)?)),
            opt::ACCM => LcpOpt::Accm(u32::from_be_bytes(fixed(&o)?)),
            opt::AUTH_PROTOCOL => {
                if o.data.len() < 2 {
                    return Err(WireError::BadOption {
                        kind: o.kind,
                        len: o.data.len() + 2,
                    });
                }
                match AuthProto::from_data(o.data) {
                    Some(a) => LcpOpt::Auth(a),
                    None => LcpOpt::AuthOther(o.data),
                }
            }
            opt::QUALITY_PROTOCOL => LcpOpt::Quality(o.data),
            opt::MAGIC_NUMBER => LcpOpt::Magic(u32::from_be_bytes(fixed(&o)?)),
            opt::PFC => {
                fixed::<0>(&o)?;
                LcpOpt::Pfc
            }
            opt::ACFC => {
                fixed::<0>(&o)?;
                LcpOpt::Acfc
            }
            opt::FCS_ALTERNATIVES => LcpOpt::FcsAlternatives(u8::from_be_bytes(fixed(&o)?)),
            opt::CALLBACK => LcpOpt::Callback(o.data),
            opt::MRRU => LcpOpt::Mrru(u16::from_be_bytes(fixed(&o)?)),
            opt::SHORT_SEQUENCE => {
                fixed::<0>(&o)?;
                LcpOpt::ShortSequence
            }
            opt::ENDPOINT_DISCRIMINATOR => match o.data {
                [class, address @ ..] => LcpOpt::EndpointDiscriminator {
                    class: *class,
                    address,
                },
                [] => {
                    return Err(WireError::BadOption {
                        kind: o.kind,
                        len: 2,
                    });
                }
            },
            _ => LcpOpt::Unknown(o),
        })
    }

    /// Appends the option.
    pub fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match *self {
            LcpOpt::Mru(v) => put_opt(out, opt::MRU, &v.to_be_bytes()),
            LcpOpt::Accm(v) => put_opt(out, opt::ACCM, &v.to_be_bytes()),
            LcpOpt::Auth(a) => put_opt(out, opt::AUTH_PROTOCOL, a.data()),
            LcpOpt::AuthOther(d) => put_opt(out, opt::AUTH_PROTOCOL, d),
            LcpOpt::Quality(d) => put_opt(out, opt::QUALITY_PROTOCOL, d),
            LcpOpt::Magic(v) => put_opt(out, opt::MAGIC_NUMBER, &v.to_be_bytes()),
            LcpOpt::Pfc => put_opt(out, opt::PFC, &[]),
            LcpOpt::Acfc => put_opt(out, opt::ACFC, &[]),
            LcpOpt::FcsAlternatives(v) => put_opt(out, opt::FCS_ALTERNATIVES, &[v]),
            LcpOpt::Callback(d) => put_opt(out, opt::CALLBACK, d),
            LcpOpt::Mrru(v) => put_opt(out, opt::MRRU, &v.to_be_bytes()),
            LcpOpt::ShortSequence => put_opt(out, opt::SHORT_SEQUENCE, &[]),
            LcpOpt::EndpointDiscriminator { class, address } => {
                let len = u8::try_from(address.len() + 3).map_err(|_| WireError::TooLong(255))?;
                out.extend_from_slice(&[opt::ENDPOINT_DISCRIMINATOR, len, class]);
                out.extend_from_slice(address);
                Ok(())
            }
            LcpOpt::Unknown(o) => put_opt(out, o.kind, o.data),
        }
    }
}

/// Appends an Echo-Request/Reply or Discard-Request body (RFC 1661 §5.8):
/// the sender's Magic-Number (zero when not negotiated) then data.
pub fn put_echo(out: &mut Vec<u8>, magic: u32, data: &[u8]) {
    out.extend_from_slice(&magic.to_be_bytes());
    out.extend_from_slice(data);
}

/// Reads the Magic-Number of an Echo/Discard body.
pub fn echo_magic(data: &[u8]) -> Option<u32> {
    let b: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppp::options;

    fn round(o: LcpOpt<'_>) {
        let mut b = Vec::new();
        o.put(&mut b).unwrap();
        let p = options(&b).next().unwrap().unwrap();
        assert_eq!(LcpOpt::parse(p).unwrap(), o);
    }

    #[test]
    fn every_option_round_trips() {
        for o in [
            LcpOpt::Mru(1492),
            LcpOpt::Accm(0),
            LcpOpt::Auth(AuthProto::Pap),
            LcpOpt::Auth(AuthProto::ChapMd5),
            LcpOpt::Auth(AuthProto::MsChapV1),
            LcpOpt::Auth(AuthProto::MsChapV2),
            LcpOpt::AuthOther(&[0xc2, 0x27]),
            LcpOpt::Quality(&[0xc0, 0x25, 0, 0, 0, 10]),
            LcpOpt::Magic(0xdeadbeef),
            LcpOpt::Pfc,
            LcpOpt::Acfc,
            LcpOpt::FcsAlternatives(1),
            LcpOpt::Callback(&[6]),
            LcpOpt::Mrru(1524),
            LcpOpt::ShortSequence,
            LcpOpt::EndpointDiscriminator {
                class: 3,
                address: &[2, 0, 0, 0, 0, 1],
            },
        ] {
            round(o);
        }
    }

    #[test]
    fn rfc1661_6_1_mru_with_wrong_length_is_invalid() {
        let o = Opt {
            kind: opt::MRU,
            data: &[5],
        };
        assert!(LcpOpt::parse(o).is_err());
    }

    #[test]
    fn rfc1661_6_4_magic_is_four_octets() {
        let o = Opt {
            kind: opt::MAGIC_NUMBER,
            data: &[0, 0, 1],
        };
        assert!(LcpOpt::parse(o).is_err());
    }

    #[test]
    fn rfc1994_2_chap_with_unknown_algorithm_is_other() {
        let o = Opt {
            kind: opt::AUTH_PROTOCOL,
            data: &[0xc2, 0x23, 6],
        };
        assert_eq!(
            LcpOpt::parse(o).unwrap(),
            LcpOpt::AuthOther(&[0xc2, 0x23, 6])
        );
    }

    #[test]
    fn echo_body() {
        let mut b = Vec::new();
        put_echo(&mut b, 0x01020304, b"x");
        assert_eq!(echo_magic(&b), Some(0x01020304));
        assert_eq!(echo_magic(&b[..3]), None);
    }
}

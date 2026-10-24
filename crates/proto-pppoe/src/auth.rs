//! Authentication protocols: PAP (RFC 1334 §2), CHAP (RFC 1994 §4) with MD5,
//! MS-CHAPv1 (RFC 2433) and MS-CHAPv2 (RFC 2759), plus the MPPE key
//! derivation of RFC 3079 §3 for a later MPPE/RADIUS step. The MS-CHAP
//! arithmetic is `corerouter_proto_radius::mschap` (one implementation for
//! the RADIUS NAS and the PPP authenticator); this module holds the PPP
//! packet layouts and the checks a local-secret caller runs.
//!
//! The packet views borrow the frame. The verification helpers are what a
//! caller with a local secret (`/ppp secret`) runs; a RADIUS caller instead
//! forwards the fields (User-Password, CHAP-Password, MS-CHAP2-Response) and
//! hands the server's answer back.

use crate::wire::{Reader, WireError, parse_hex, put_hex_upper};
use corerouter_proto_radius::mschap;
use md5::{Digest, Md5};

/// PAP and CHAP codes.
pub mod code {
    /// RFC 1334 §2.2.1.
    pub const PAP_REQUEST: u8 = 1;
    pub const PAP_ACK: u8 = 2;
    pub const PAP_NAK: u8 = 3;
    /// RFC 1994 §4.
    pub const CHAP_CHALLENGE: u8 = 1;
    pub const CHAP_RESPONSE: u8 = 2;
    pub const CHAP_SUCCESS: u8 = 3;
    pub const CHAP_FAILURE: u8 = 4;
}

/// Constant-time equality (no early exit on the first differing byte).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- PAP

/// RFC 1334 §2.2.1 Authenticate-Request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PapRequest<'a> {
    pub peer_id: &'a [u8],
    pub password: &'a [u8],
}

impl<'a> PapRequest<'a> {
    pub fn parse(data: &'a [u8]) -> Result<PapRequest<'a>, WireError> {
        let mut r = Reader::new(data);
        let n = usize::from(r.u8()?);
        let peer_id = r.take(n)?;
        let n = usize::from(r.u8()?);
        let password = r.take(n)?;
        Ok(PapRequest { peer_id, password })
    }

    pub fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        for f in [self.peer_id, self.password] {
            out.push(u8::try_from(f.len()).map_err(|_| WireError::TooLong(255))?);
            out.extend_from_slice(f);
        }
        Ok(())
    }
}

/// RFC 1334 §2.2.2 Ack/Nak body: Msg-Length then Message.
pub fn put_pap_message(out: &mut Vec<u8>, msg: &[u8]) {
    let msg = msg.get(..255).unwrap_or(msg);
    out.push(u8::try_from(msg.len()).unwrap_or(0));
    out.extend_from_slice(msg);
}

pub fn parse_pap_message(data: &[u8]) -> Result<&[u8], WireError> {
    let mut r = Reader::new(data);
    let n = usize::from(r.u8()?);
    r.take(n)
}

// ---------------------------------------------------------------- CHAP

/// RFC 1994 §4.1 Challenge/Response body: Value-Size, Value, Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChapValue<'a> {
    pub value: &'a [u8],
    pub name: &'a [u8],
}

impl<'a> ChapValue<'a> {
    pub fn parse(data: &'a [u8]) -> Result<ChapValue<'a>, WireError> {
        let mut r = Reader::new(data);
        let n = usize::from(r.u8()?);
        if n == 0 {
            return Err(WireError::Malformed("CHAP Value-Size 0"));
        }
        let value = r.take(n)?;
        Ok(ChapValue {
            value,
            name: r.rest(),
        })
    }

    pub fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.push(u8::try_from(self.value.len()).map_err(|_| WireError::TooLong(255))?);
        out.extend_from_slice(self.value);
        out.extend_from_slice(self.name);
        Ok(())
    }
}

/// RFC 1994 §4.1: Response = MD5(Identifier ‖ secret ‖ Challenge).
pub fn chap_md5(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update([id]);
    h.update(secret);
    h.update(challenge);
    h.finalize().into()
}

/// Checks a CHAP-MD5 response against a local secret.
pub fn verify_chap_md5(id: u8, secret: &[u8], challenge: &[u8], response: &[u8]) -> bool {
    ct_eq(&chap_md5(id, secret, challenge), response)
}

// ---------------------------------------------------------------- MS-CHAP

/// MS-CHAPv1 challenge length (RFC 2433 §5).
pub const MSCHAP1_CHALLENGE: usize = 8;
/// MS-CHAPv2 authenticator/peer challenge length (RFC 2759 §4).
pub const MSCHAP2_CHALLENGE: usize = 16;
/// Value-Size of an MS-CHAP Response (both versions).
pub const MSCHAP_RESPONSE: usize = 49;
/// "S=" + 40 hex digits (RFC 2759 §5).
pub const AUTH_STRING_LEN: usize = 42;

/// RFC 2759 §8.3 NtPasswordHash of a password given as text.
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    mschap::nt_password_hash(&mschap::utf16le(password))
}

/// The 20-octet authenticator digest as "S=" + 40 uppercase hex (RFC 2759
/// §8.7), without allocating a `String`.
pub fn auth_string(digest: &[u8; 20]) -> [u8; AUTH_STRING_LEN] {
    let mut s = Vec::with_capacity(AUTH_STRING_LEN);
    s.extend_from_slice(b"S=");
    put_hex_upper(&mut s, digest);
    let mut out = [0u8; AUTH_STRING_LEN];
    for (d, b) in out.iter_mut().zip(&s) {
        *d = *b;
    }
    out
}

/// RFC 2759 §8.8 CheckAuthenticatorResponse (the client side): the
/// Success message starts with the 42-octet string.
pub fn mschap2_check_authenticator(expected: &[u8; AUTH_STRING_LEN], message: &[u8]) -> bool {
    message
        .get(..AUTH_STRING_LEN)
        .is_some_and(|m| m.eq_ignore_ascii_case(expected))
}

/// An MS-CHAP Response value as PPP carries it (49 octets; RFC 2433 §5 and
/// RFC 2759 §4). RADIUS wraps the same octets with Ident and Flags first
/// (RFC 2548 §2.3.2): see [`MsChapResponse::to_radius_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsChapResponse {
    /// v2: Peer-Challenge; v1: the first 16 octets of the LM response.
    pub peer_challenge: [u8; 16],
    /// v2: reserved (zero); v1: the last 8 octets of the LM response.
    pub reserved: [u8; 8],
    pub nt_response: [u8; 24],
    /// v2: zero; v1: 1 = use the NT response.
    pub flags: u8,
}

impl MsChapResponse {
    pub fn parse(value: &[u8]) -> Result<MsChapResponse, WireError> {
        if value.len() != MSCHAP_RESPONSE {
            return Err(WireError::Malformed("MS-CHAP Response must be 49 octets"));
        }
        let mut r = Reader::new(value);
        Ok(MsChapResponse {
            peer_challenge: r.array()?,
            reserved: r.array()?,
            nt_response: r.array()?,
            flags: r.u8()?,
        })
    }

    pub fn to_bytes(&self) -> [u8; MSCHAP_RESPONSE] {
        let mut out = [0u8; MSCHAP_RESPONSE];
        let parts: [&[u8]; 4] = [
            &self.peer_challenge,
            &self.reserved,
            &self.nt_response,
            &[self.flags],
        ];
        let mut i = 0;
        for p in parts {
            if let Some(d) = out.get_mut(i..i + p.len()) {
                d.copy_from_slice(p);
            }
            i += p.len();
        }
        out
    }

    /// The RADIUS MS-CHAP2-Response attribute value (RFC 2548 §2.3.2).
    pub fn to_radius_v2(&self, ident: u8) -> mschap::Chap2Response {
        mschap::Chap2Response {
            ident,
            flags: self.flags,
            peer_challenge: self.peer_challenge,
            nt_response: self.nt_response,
        }
    }
}

/// Checks an MS-CHAPv1 response (NT response only; RFC 2433 §5: the LM
/// response is obsolete and refused, flag 0).
pub fn verify_mschap1(challenge: &[u8; 8], password: &str, resp: &MsChapResponse) -> bool {
    resp.flags == 1
        && ct_eq(
            &mschap::v1_nt_response(challenge, &mschap::utf16le(password)),
            &resp.nt_response,
        )
}

/// Checks an MS-CHAPv2 response and returns the authenticator string for
/// the Success packet (RFC 2759 §5).
pub fn verify_mschap2(
    auth: &[u8; 16],
    user: &[u8],
    password: &str,
    resp: &MsChapResponse,
) -> Option<[u8; AUTH_STRING_LEN]> {
    // RFC 2759 §8.2: the hash takes the user name without a `DOMAIN\`.
    let user = mschap::strip_domain(user);
    let pw = mschap::utf16le(password);
    let expected = mschap::generate_nt_response(auth, &resp.peer_challenge, user, &pw);
    if !ct_eq(&expected, &resp.nt_response) {
        return None;
    }
    let digest =
        mschap::authenticator_response(&pw, &resp.nt_response, &resp.peer_challenge, auth, user);
    Some(auth_string(&digest))
}

/// The client side of RFC 2759 §8.1: the 49-octet Response for a challenge.
pub fn mschap2_client_response(
    auth: &[u8; 16],
    peer: &[u8; 16],
    user: &[u8],
    password: &str,
) -> (MsChapResponse, [u8; AUTH_STRING_LEN]) {
    let user = mschap::strip_domain(user);
    let pw = mschap::utf16le(password);
    let nt = mschap::generate_nt_response(auth, peer, user, &pw);
    let digest = mschap::authenticator_response(&pw, &nt, peer, auth, user);
    (
        MsChapResponse {
            peer_challenge: *peer,
            reserved: [0; 8],
            nt_response: nt,
            flags: 0,
        },
        auth_string(&digest),
    )
}

/// RFC 2759 §6 Failure message: `E=691 R=0 C=<challenge hex> V=3 M=<text>`.
pub fn put_mschap2_failure(out: &mut Vec<u8>, error: u16, next_challenge: &[u8; 16], text: &[u8]) {
    out.extend_from_slice(b"E=");
    out.extend_from_slice(error.to_string().as_bytes());
    out.extend_from_slice(b" R=0 C=");
    put_hex_upper(out, next_challenge);
    out.extend_from_slice(b" V=3 M=");
    out.extend_from_slice(text.get(..200).unwrap_or(text));
}

/// Reads `C=` from an MS-CHAPv2 Failure message (the client side).
pub fn mschap2_failure_challenge(msg: &[u8]) -> Option<[u8; 16]> {
    let i = msg.windows(2).position(|w| w == b"C=")?;
    let hex = msg.get(i + 2..i + 2 + 32)?;
    let mut out = [0u8; 16];
    parse_hex(hex, &mut out)?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut v = vec![0u8; s.len() / 2];
        parse_hex(&s, &mut v).unwrap();
        v
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    // RFC 2759 §9.2 "Sample MS-CHAPv2 Data".
    const USER: &[u8] = b"User";
    const PASS: &str = "clientPass";
    const AUTH_CH: &str = "5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28";
    const PEER_CH: &str = "21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E";
    const NT_RESP: &str = "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF";

    #[test]
    fn rfc2759_9_2_sample_data() {
        let auth = arr::<16>(AUTH_CH);
        let peer = arr::<16>(PEER_CH);
        assert_eq!(
            nt_password_hash(PASS),
            arr::<16>("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE")
        );
        let (resp, s) = mschap2_client_response(&auth, &peer, USER, PASS);
        assert_eq!(resp.nt_response, arr::<24>(NT_RESP));
        assert_eq!(&s[..], b"S=407A5589115FD0D6209F510FE9C04566932CDA56");
    }

    #[test]
    fn rfc2759_verify_accepts_the_sample_and_refuses_a_wrong_password() {
        let auth = arr::<16>(AUTH_CH);
        let resp = MsChapResponse {
            peer_challenge: arr(PEER_CH),
            reserved: [0; 8],
            nt_response: arr(NT_RESP),
            flags: 0,
        };
        let r = MsChapResponse::parse(&resp.to_bytes()).unwrap();
        assert_eq!(r, resp);
        let s = verify_mschap2(&auth, USER, PASS, &r).unwrap();
        assert!(mschap2_check_authenticator(
            &s,
            b"S=407a5589115fd0d6209f510fe9c04566932cda56 M=ok"
        ));
        assert!(verify_mschap2(&auth, USER, "wrong", &r).is_none());
        // RFC 2759 §8.2: a prepended domain does not change the hash.
        assert!(verify_mschap2(&auth, b"CORP\\User", PASS, &r).is_some());
        // The RADIUS attribute carries the same octets after Ident/Flags.
        let rad = r.to_radius_v2(7).encode();
        assert_eq!(&rad[2..], &r.to_bytes()[..48]);
    }

    #[test]
    fn rfc3079_3_5_3_sample_128_bit_keys() {
        // The sample's SendStartKey128 is the authenticator's (server's)
        // send key (Magic3, §3.4): what the NAS hands to MPPE.
        let keys = mschap::mppe_keys(&mschap::utf16le(PASS), &arr::<24>(NT_RESP));
        assert_eq!(
            keys.send,
            arr::<16>("8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB")
        );
        assert_ne!(keys.send, keys.recv);
    }

    // RFC 2433 Appendix B.1 sample MS-CHAPv1 data.
    #[test]
    fn rfc2433_b_sample_nt_response() {
        let ch = arr::<8>("10 2D B5 DF 08 5D 30 41");
        assert_eq!(
            nt_password_hash("MyPw"),
            arr::<16>("FC 15 6A F7 ED CD 6C 0E DD E3 33 7D 42 7F 4E AC")
        );
        let resp = MsChapResponse {
            peer_challenge: [0; 16],
            reserved: [0; 8],
            nt_response: arr(
                "4E 9D 3C 8F 9C FD 38 5D 5B F4 D3 24 67 91 95 6C A4 C3 51 AB 40 9A 3D 61",
            ),
            flags: 1,
        };
        assert!(verify_mschap1(&ch, "MyPw", &resp));
        assert!(!verify_mschap1(&ch, "MyPW", &resp));
        assert!(!verify_mschap1(
            &ch,
            "MyPw",
            &MsChapResponse { flags: 0, ..resp }
        ));
    }

    #[test]
    fn rfc1994_chap_md5() {
        // MD5(0x01 ‖ "secret" ‖ 0x00..0x0f), computed with Python's hashlib.
        let ch: Vec<u8> = (0u8..16).collect();
        let r = chap_md5(1, b"secret", &ch);
        assert_eq!(r, arr::<16>("740e86463bda3a4d7017d6e0fba0699d"));
        assert!(verify_chap_md5(1, b"secret", &ch, &r));
        assert!(!verify_chap_md5(2, b"secret", &ch, &r));
        assert!(!verify_chap_md5(1, b"secreT", &ch, &r));
        assert!(!verify_chap_md5(1, b"secret", &ch, &r[..15]));
    }

    #[test]
    fn rfc1334_pap_round_trip_and_truncation() {
        let p = PapRequest {
            peer_id: b"joao",
            password: b"s3nha",
        };
        let mut b = Vec::new();
        p.put(&mut b).unwrap();
        assert_eq!(PapRequest::parse(&b).unwrap(), p);
        for n in 0..b.len() {
            assert!(PapRequest::parse(&b[..n]).is_err());
        }
    }

    #[test]
    fn rfc1994_4_1_value_size_zero_is_invalid() {
        assert!(ChapValue::parse(&[0, b'x']).is_err());
        let v = ChapValue::parse(&[2, 9, 9, b'b', b'n', b'g']).unwrap();
        assert_eq!(v.value, &[9, 9]);
        assert_eq!(v.name, b"bng");
    }

    #[test]
    fn rfc2759_6_failure_message_carries_the_next_challenge() {
        let ch = [0xabu8; 16];
        let mut m = Vec::new();
        put_mschap2_failure(&mut m, 691, &ch, b"bad password");
        assert!(m.starts_with(b"E=691 R=0 C=ABAB"));
        assert_eq!(mschap2_failure_challenge(&m), Some(ch));
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

//! Authentication protocols: PAP (RFC 1334 §2), CHAP (RFC 1994 §4) with MD5,
//! MS-CHAPv1 (RFC 2433) and MS-CHAPv2 (RFC 2759), plus the MPPE key
//! derivation of RFC 3079 §3 for a later MPPE/RADIUS step.
//!
//! The packet views borrow the frame. The verification helpers are what a
//! caller with a local secret (`/ppp secret`) runs; a RADIUS caller instead
//! forwards the fields (User-Password, CHAP-Password, MS-CHAP2-Response) and
//! hands the server's answer back.

use crate::wire::{Reader, WireError, parse_hex, put_hex_upper};
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use md4::Md4;
use md5::Md5;
use sha1::{Digest, Sha1};

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

/// RFC 2759 §8.3 NtPasswordHash: MD4 of the UTF-16LE (Unicode) password.
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    for u in password.encode_utf16() {
        h.update(u.to_le_bytes());
    }
    h.finalize().into()
}

/// RFC 2759 §8.4 HashNtPasswordHash.
pub fn hash_nt_password_hash(hash: &[u8; 16]) -> [u8; 16] {
    Md4::digest(hash).into()
}

/// RFC 2759 §8.6 DesEncrypt: a 7-octet key spread over 8 (parity bits
/// left at zero; DES ignores them).
fn des_encrypt(clear: &[u8; 8], k: &[u8; 7]) -> [u8; 8] {
    let bits = u64::from_be_bytes([0, k[0], k[1], k[2], k[3], k[4], k[5], k[6]]);
    let mut key = [0u8; 8];
    for (i, b) in key.iter_mut().enumerate() {
        let shift = 49 - 7 * i as u32;
        *b = (((bits >> shift) & 0x7f) as u8) << 1;
    }
    let cipher = des::Des::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(clear);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// RFC 2759 §8.5 ChallengeResponse: the 16-octet hash zero-padded to 21 and
/// cut in three DES keys.
pub fn challenge_response(challenge: &[u8; 8], hash: &[u8; 16]) -> [u8; 24] {
    let mut z = [0u8; 21];
    z[..16].copy_from_slice(hash);
    let mut out = [0u8; 24];
    for (chunk, key) in out
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(z.as_chunks::<7>().0)
    {
        *chunk = des_encrypt(challenge, key);
    }
    out
}

/// RFC 2433 §A.5 NtChallengeResponse (MS-CHAPv1).
pub fn mschap1_nt_response(challenge: &[u8; 8], password: &str) -> [u8; 24] {
    challenge_response(challenge, &nt_password_hash(password))
}

/// RFC 2759 §8.2: only the user name, without a prepended `DOMAIN\`.
pub fn mschap2_user(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'\\') {
        Some(i) => name.get(i + 1..).unwrap_or(name),
        None => name,
    }
}

/// RFC 2759 §8.2 ChallengeHash.
pub fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], user: &[u8]) -> [u8; 8] {
    let mut h = Sha1::new();
    h.update(peer);
    h.update(auth);
    h.update(mschap2_user(user));
    let d: [u8; 20] = h.finalize().into();
    d.first_chunk::<8>().copied().unwrap_or_default()
}

/// RFC 2759 §8.1 GenerateNTResponse.
pub fn mschap2_nt_response(
    auth: &[u8; 16],
    peer: &[u8; 16],
    user: &[u8],
    password: &str,
) -> [u8; 24] {
    challenge_response(
        &challenge_hash(peer, auth, user),
        &nt_password_hash(password),
    )
}

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// RFC 2759 §8.7 GenerateAuthenticatorResponse: "S=" + 40 uppercase hex.
pub fn mschap2_authenticator_response(
    password_hash: &[u8; 16],
    nt_response: &[u8; 24],
    peer: &[u8; 16],
    auth: &[u8; 16],
    user: &[u8],
) -> [u8; AUTH_STRING_LEN] {
    let hh = hash_nt_password_hash(password_hash);
    let mut h = Sha1::new();
    h.update(hh);
    h.update(nt_response);
    h.update(MAGIC1);
    let d1 = h.finalize();
    let mut h = Sha1::new();
    h.update(d1);
    h.update(challenge_hash(peer, auth, user));
    h.update(MAGIC2);
    let d2 = h.finalize();
    let mut s = Vec::with_capacity(AUTH_STRING_LEN);
    s.extend_from_slice(b"S=");
    put_hex_upper(&mut s, &d2);
    let mut out = [0u8; AUTH_STRING_LEN];
    out.copy_from_slice(&s);
    out
}

/// RFC 2759 §8.8 CheckAuthenticatorResponse (the client side): the
/// Success message starts with the 42-octet string.
pub fn mschap2_check_authenticator(expected: &[u8; AUTH_STRING_LEN], message: &[u8]) -> bool {
    message
        .get(..AUTH_STRING_LEN)
        .is_some_and(|m| m.eq_ignore_ascii_case(expected))
}

/// An MS-CHAP Response value (49 octets; RFC 2433 §5 and RFC 2759 §4).
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
        out[..16].copy_from_slice(&self.peer_challenge);
        out[16..24].copy_from_slice(&self.reserved);
        out[24..48].copy_from_slice(&self.nt_response);
        out[48] = self.flags;
        out
    }
}

/// Checks an MS-CHAPv1 response (NT response only; RFC 2433 §5: the LM
/// response is obsolete and refused, flag 0).
pub fn verify_mschap1(challenge: &[u8; 8], password: &str, resp: &MsChapResponse) -> bool {
    resp.flags == 1 && ct_eq(&mschap1_nt_response(challenge, password), &resp.nt_response)
}

/// Checks an MS-CHAPv2 response and returns the authenticator string for
/// the Success packet (RFC 2759 §5).
pub fn verify_mschap2(
    auth: &[u8; 16],
    user: &[u8],
    password: &str,
    resp: &MsChapResponse,
) -> Option<[u8; AUTH_STRING_LEN]> {
    let expected = mschap2_nt_response(auth, &resp.peer_challenge, user, password);
    if !ct_eq(&expected, &resp.nt_response) {
        return None;
    }
    Some(mschap2_authenticator_response(
        &nt_password_hash(password),
        &resp.nt_response,
        &resp.peer_challenge,
        auth,
        user,
    ))
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

// ---------------------------------------------------------------- MPPE keys

/// RFC 3079 §3.4 GetMasterKey.
pub fn mppe_master_key(password_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    let mut h = Sha1::new();
    h.update(password_hash_hash);
    h.update(nt_response);
    h.update(b"This is the MPPE Master Key");
    let d: [u8; 20] = h.finalize().into();
    d.first_chunk::<16>().copied().unwrap_or_default()
}

const MPPE_MAGIC2: &[u8] =
    b"On the client side, this is the send key; on the server side, it is the receive key.";
const MPPE_MAGIC3: &[u8] =
    b"On the client side, this is the receive key; on the server side, it is the send key.";

/// RFC 3079 §3.4 GetAsymmetricStartKey; `len` is 8 (40/56-bit) or 16 (128-bit).
pub fn mppe_asymmetric_start_key(
    master: &[u8; 16],
    len: usize,
    is_send: bool,
    is_server: bool,
) -> [u8; 16] {
    let magic = if is_send == is_server {
        MPPE_MAGIC3
    } else {
        MPPE_MAGIC2
    };
    let mut h = Sha1::new();
    h.update(master);
    h.update([0u8; 40]);
    h.update(magic);
    h.update([0xf2u8; 40]);
    let d = h.finalize();
    let mut out = [0u8; 16];
    let n = len.min(16);
    if let (Some(dst), Some(src)) = (out.get_mut(..n), d.get(..n)) {
        dst.copy_from_slice(src);
    }
    out
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
            challenge_hash(&peer, &auth, USER),
            arr::<8>("D0 2E 43 86 BC E9 12 26")
        );
        assert_eq!(
            nt_password_hash(PASS),
            arr::<16>("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE")
        );
        assert_eq!(
            hash_nt_password_hash(&nt_password_hash(PASS)),
            arr::<16>("41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F")
        );
        let nt = mschap2_nt_response(&auth, &peer, USER, PASS);
        assert_eq!(nt, arr::<24>(NT_RESP));
        let s = mschap2_authenticator_response(&nt_password_hash(PASS), &nt, &peer, &auth, USER);
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
    }

    #[test]
    fn rfc3079_3_5_3_sample_128_bit_keys() {
        let nt = arr::<24>(NT_RESP);
        let hh = hash_nt_password_hash(&nt_password_hash(PASS));
        let master = mppe_master_key(&hh, &nt);
        assert_eq!(
            master,
            arr::<16>("FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31")
        );
        // The sample's SendStartKey128 is the server's (Magic3, §3.4); it is
        // the client's receive key.
        let send = mppe_asymmetric_start_key(&master, 16, true, true);
        assert_eq!(
            send,
            arr::<16>("8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB")
        );
        assert_eq!(send, mppe_asymmetric_start_key(&master, 16, false, false));
        assert_ne!(send, mppe_asymmetric_start_key(&master, 16, true, false));
    }

    // RFC 2433 Appendix B.1 sample MS-CHAPv1 data.
    #[test]
    fn rfc2433_b_sample_nt_response() {
        let ch = arr::<8>("10 2D B5 DF 08 5D 30 41");
        assert_eq!(
            nt_password_hash("MyPw"),
            arr::<16>("FC 15 6A F7 ED CD 6C 0E DD E3 33 7D 42 7F 4E AC")
        );
        assert_eq!(
            mschap1_nt_response(&ch, "MyPw"),
            arr::<24>("4E 9D 3C 8F 9C FD 38 5D 5B F4 D3 24 67 91 95 6C A4 C3 51 AB 40 9A 3D 61")
        );
    }

    #[test]
    fn rfc1994_chap_md5() {
        // MD5(0x01 ‖ "secret" ‖ 0x00..0x0f), computed independently.
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

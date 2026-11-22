//! The RADIUS shared-secret cryptography.
//!
//! - Authenticators: RFC 2865 §3 (Response), RFC 2866 §3 (Accounting
//!   Request), RFC 5176 §2.3 (CoA/Disconnect, "the same way as for an
//!   Accounting-Request").
//! - Message-Authenticator: RFC 2869 §5.14 (HMAC-MD5 keyed by the secret),
//!   RFC 5176 §3.4 (requests hash with a zeroed Request Authenticator;
//!   responses with the request's), RFC 3579 §3.2.
//! - User-Password: RFC 2865 §5.2. Salt encryption: RFC 2868 §3.5
//!   (Tunnel-Password) and RFC 2548 §2.4.2 (MS-MPPE-Send/Recv-Key).
//! - CHAP: RFC 1994 §4.1 (response = MD5(Identifier ‖ secret ‖ challenge)).
//!
//! Every comparison of a received digest is constant time.

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};

use crate::packet::{Builder, Code, EncodeError, HEADER_LEN, Packet, attr};

type HmacMd5 = Hmac<Md5>;

/// RFC 2865 §5.2: "the password ... MUST be ... no longer than 128 octets".
pub const MAX_PASSWORD_LEN: usize = 128;

fn header(bytes: &[u8]) -> &[u8] {
    bytes.get(..4).unwrap_or(&[])
}

fn body(bytes: &[u8]) -> &[u8] {
    bytes.get(HEADER_LEN..).unwrap_or(&[])
}

/// Constant-time equality of two byte strings of public length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// MD5(Code ‖ Identifier ‖ Length ‖ `auth` ‖ Attributes ‖ secret): the
/// Response Authenticator (RFC 2865 §3, `auth` = the request's) and the
/// Accounting/CoA Request Authenticator (RFC 2866 §3, `auth` = 16 zeros).
pub fn packet_digest(bytes: &[u8], auth: &[u8; 16], secret: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(header(bytes));
    h.update(auth);
    h.update(body(bytes));
    h.update(secret);
    h.finalize().into()
}

/// HMAC-MD5 over the packet with `auth` in the Authenticator field and the
/// Message-Authenticator value at `ma_offset` taken as 16 zeros
/// (RFC 2869 §5.14, RFC 5176 §3.4).
pub fn message_authenticator(
    bytes: &[u8],
    ma_offset: usize,
    auth: &[u8; 16],
    secret: &[u8],
) -> [u8; 16] {
    let mut m = <HmacMd5 as KeyInit>::new_from_slice(secret).unwrap_or_else(|_| {
        // HMAC takes keys of any length; this branch is never taken.
        <HmacMd5 as KeyInit>::new(&Default::default())
    });
    let value_at = ma_offset + 2;
    m.update(header(bytes));
    m.update(auth);
    m.update(bytes.get(HEADER_LEN..value_at).unwrap_or(&[]));
    m.update(&[0u8; 16]);
    m.update(bytes.get(value_at + 16..).unwrap_or(&[]));
    m.finalize().into_bytes().into()
}

fn put_ma(buf: &mut [u8], ma_offset: usize, value: &[u8; 16]) {
    if let Some(dst) = buf.get_mut(ma_offset + 2..ma_offset + 18) {
        dst.copy_from_slice(value);
    }
}

fn put_auth(buf: &mut [u8], value: &[u8; 16]) {
    if let Some(dst) = buf.get_mut(4..HEADER_LEN) {
        dst.copy_from_slice(value);
    }
}

/// Sign a request. Access-Request and Status-Server keep the random
/// authenticator already in the builder (RFC 2865 §3, RFC 5997 §3) and only
/// get the Message-Authenticator; Accounting, CoA and Disconnect requests get
/// the Message-Authenticator over a zeroed authenticator first, then the
/// MD5 Request Authenticator (RFC 2866 §3, RFC 5176 §2.3/§3.4).
pub fn sign_request(mut b: Builder, secret: &[u8]) -> Vec<u8> {
    let computed = b
        .code()
        .is_some_and(Code::has_computed_request_authenticator);
    let ma = b.ma_offset();
    let auth = if computed {
        [0u8; 16]
    } else {
        b.authenticator()
    };
    let buf = b.bytes_mut();
    if computed {
        put_auth(buf, &[0; 16]);
    }
    if let Some(at) = ma {
        let v = message_authenticator(buf, at, &auth, secret);
        put_ma(buf, at, &v);
    }
    if computed {
        let a = packet_digest(buf, &[0; 16], secret);
        put_auth(buf, &a);
    }
    std::mem::take(buf)
}

/// Sign a response to a request whose authenticator was `request_auth`
/// (RFC 2865 §3; Message-Authenticator first, RFC 5176 §3.4).
pub fn sign_response(mut b: Builder, request_auth: &[u8; 16], secret: &[u8]) -> Vec<u8> {
    let ma = b.ma_offset();
    let buf = b.bytes_mut();
    if let Some(at) = ma {
        let v = message_authenticator(buf, at, request_auth, secret);
        put_ma(buf, at, &v);
    }
    let a = packet_digest(buf, request_auth, secret);
    put_auth(buf, &a);
    std::mem::take(buf)
}

/// RFC 2865 §3: check a response against the request's authenticator.
pub fn verify_response(p: &Packet<'_>, request_auth: &[u8; 16], secret: &[u8]) -> bool {
    let want = packet_digest(p.as_bytes(), request_auth, secret);
    ct_eq(&want, &p.authenticator())
}

/// RFC 2866 §3 / RFC 5176 §2.3: check an Accounting, CoA or Disconnect
/// request ("Invalid packets are silently discarded", RFC 5080 §2.3.3).
pub fn verify_computed_request(p: &Packet<'_>, secret: &[u8]) -> bool {
    let want = packet_digest(p.as_bytes(), &[0; 16], secret);
    ct_eq(&want, &p.authenticator())
}

/// Outcome of the Message-Authenticator check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaCheck {
    Absent,
    Valid,
    /// Wrong value, wrong length, or more than one (RFC 3579 §3.2 allows
    /// at most one).
    Invalid,
}

/// Check the Message-Authenticator, hashing with `auth` in the
/// Authenticator field: the packet's own for Access-Request and
/// Status-Server, 16 zeros for Accounting/CoA/Disconnect requests, the
/// request's for responses.
pub fn check_message_authenticator(p: &Packet<'_>, auth: &[u8; 16], secret: &[u8]) -> MaCheck {
    let mut found = None;
    for a in p
        .attributes()
        .filter(|a| a.typ == attr::MESSAGE_AUTHENTICATOR)
    {
        if found.is_some() || a.value.len() != 16 {
            return MaCheck::Invalid;
        }
        found = Some(a);
    }
    let Some(a) = found else {
        return MaCheck::Absent;
    };
    let want = message_authenticator(p.as_bytes(), a.offset, auth, secret);
    if ct_eq(&want, a.value) {
        MaCheck::Valid
    } else {
        MaCheck::Invalid
    }
}

/// The authenticator a received packet's Message-Authenticator is hashed
/// with, for requests (responses use the request's).
pub fn request_ma_auth(p: &Packet<'_>) -> [u8; 16] {
    if p.code().has_computed_request_authenticator() {
        [0; 16]
    } else {
        p.authenticator()
    }
}

/// RFC 2865 §5.2: hide a User-Password. The password is padded with zeros
/// to a multiple of 16 (at least 16) and XORed with the chain
/// b1 = MD5(S ‖ RA), bi = MD5(S ‖ c(i-1)).
pub fn hide_user_password(
    password: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Result<Vec<u8>, EncodeError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(EncodeError::PasswordTooLong);
    }
    let mut out = password.to_vec();
    out.resize(password.len().div_ceil(16).max(1) * 16, 0);
    xor_chain(&mut out, secret, authenticator, Direction::Encrypt);
    Ok(out)
}

/// RFC 2865 §5.2 reversed; trailing zero padding is removed. `None` when
/// the length is not a non-zero multiple of 16 up to 128.
pub fn unhide_user_password(
    hidden: &[u8],
    secret: &[u8],
    authenticator: &[u8; 16],
) -> Option<Vec<u8>> {
    if hidden.is_empty() || !hidden.len().is_multiple_of(16) || hidden.len() > MAX_PASSWORD_LEN {
        return None;
    }
    let mut out = hidden.to_vec();
    xor_chain(&mut out, secret, authenticator, Direction::Decrypt);
    while out.last() == Some(&0) {
        out.pop();
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// The MD5 keystream shared by RFC 2865 §5.2 and RFC 2868 §3.5: the first
/// block is keyed by `first` (RA, or RA ‖ salt), the next by the previous
/// ciphertext block.
fn xor_chain(data: &mut [u8], secret: &[u8], first: &[u8], dir: Direction) {
    let mut prev: Vec<u8> = first.to_vec();
    for block in data.chunks_mut(16) {
        let mut h = Md5::new();
        h.update(secret);
        h.update(&prev);
        let key: [u8; 16] = h.finalize().into();
        let cipher_before = block.to_vec();
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        prev = match dir {
            Direction::Encrypt => block.to_vec(),
            Direction::Decrypt => cipher_before,
        };
    }
}

/// RFC 2868 §3.5 / RFC 2548 §2.4.2: encrypt `plain` with a salt. The
/// plaintext is prefixed with its length octet and zero padded to a multiple
/// of 16. Returns salt ‖ ciphertext (Tunnel-Password adds its tag in front).
/// The salt's most significant bit MUST be set (§3.5) and each salt SHOULD
/// be unique per request.
pub fn salt_encrypt(
    plain: &[u8],
    secret: &[u8],
    request_auth: &[u8; 16],
    salt: [u8; 2],
) -> Result<Vec<u8>, EncodeError> {
    if salt[0] & 0x80 == 0 {
        return Err(EncodeError::BadSalt);
    }
    // The ciphertext with its salt (and Tunnel-Password's tag) must fit in
    // one attribute: 3 + 16 × 15 = 243 ≤ 253.
    if plain.len() > 239 {
        return Err(EncodeError::ValueTooLong(plain.len()));
    }
    let mut data = Vec::with_capacity(2 + 16 * 16);
    data.push(plain.len() as u8);
    data.extend_from_slice(plain);
    data.resize(data.len().div_ceil(16) * 16, 0);
    let mut first = request_auth.to_vec();
    first.extend_from_slice(&salt);
    xor_chain(&mut data, secret, &first, Direction::Encrypt);
    let mut out = salt.to_vec();
    out.extend_from_slice(&data);
    Ok(out)
}

/// RFC 2868 §3.5 reversed: `value` is salt ‖ ciphertext. `None` when the
/// sizes are wrong or the decrypted length octet does not fit.
pub fn salt_decrypt(value: &[u8], secret: &[u8], request_auth: &[u8; 16]) -> Option<Vec<u8>> {
    let (salt, cipher) = value.split_first_chunk::<2>()?;
    if cipher.is_empty() || cipher.len() % 16 != 0 {
        return None;
    }
    let mut data = cipher.to_vec();
    let mut first = request_auth.to_vec();
    first.extend_from_slice(salt);
    xor_chain(&mut data, secret, &first, Direction::Decrypt);
    let (&len, rest) = data.split_first()?;
    rest.get(..usize::from(len)).map(<[u8]>::to_vec)
}

/// RFC 1994 §4.1: CHAP response = MD5(Identifier ‖ secret ‖ challenge).
/// RFC 2865 §5.3: CHAP-Password is the Identifier followed by it.
pub fn chap_response(chap_id: u8, password: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update([chap_id]);
    h.update(password);
    h.update(challenge);
    h.finalize().into()
}

/// RFC 2865 §2.2/§5.3: verify a CHAP-Password against the cleartext
/// password; the challenge is CHAP-Challenge or, without it, the Request
/// Authenticator.
pub fn verify_chap(p: &Packet<'_>, password: &[u8]) -> bool {
    let Some((&id, resp)) = p.attr(attr::CHAP_PASSWORD).and_then(<[u8]>::split_first) else {
        return false;
    };
    let ra = p.authenticator();
    let challenge = p.attr(attr::CHAP_CHALLENGE).unwrap_or(&ra);
    ct_eq(&chap_response(id, password, challenge), resp)
}

/// MD5 of the concatenation (the client derives authenticators with it).
pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PushAttr;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    const SECRET: &[u8] = b"xyzzy5461";

    /// RFC 2865 §7.1: the Access-Request hides "arctangent", and the
    /// Access-Accept's Response Authenticator verifies.
    #[test]
    fn rfc_2865_section_7_1() {
        let req = hex("01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb
             98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d
             93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8
             01 10 05 06 00 00 00 03");
        let p = Packet::parse(&req).unwrap();
        let ra = p.authenticator();
        let hidden = p.attr(attr::USER_PASSWORD).unwrap();
        assert_eq!(
            unhide_user_password(hidden, SECRET, &ra).unwrap(),
            b"arctangent"
        );
        assert_eq!(
            hide_user_password(b"arctangent", SECRET, &ra).unwrap(),
            hidden
        );

        // Rebuild the request byte for byte.
        let mut b = Builder::with_authenticator(Code::AccessRequest, 0, ra);
        b.push(attr::USER_NAME, b"nemo").unwrap();
        b.push(
            attr::USER_PASSWORD,
            &hide_user_password(b"arctangent", SECRET, &ra).unwrap(),
        )
        .unwrap();
        b.push_ipv4(attr::NAS_IP_ADDRESS, [192, 168, 1, 16].into())
            .unwrap();
        b.push_u32(attr::NAS_PORT, 3).unwrap();
        assert_eq!(sign_request(b, SECRET), req);

        let resp = hex("02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf
             9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00
             0e 06 c0 a8 01 03");
        let r = Packet::parse(&resp).unwrap();
        assert!(verify_response(&r, &ra, SECRET));
        assert!(!verify_response(&r, &ra, b"wrong"));
        let mut b = Builder::new(Code::AccessAccept, 0);
        b.push_u32(6, 1).unwrap().push_u32(15, 0).unwrap();
        b.push_ipv4(14, [192, 168, 1, 3].into()).unwrap();
        assert_eq!(sign_response(b, &ra, SECRET), resp);
    }

    /// RFC 2865 §7.2 and verified errata 1469: the printed Accept carries
    /// Framed-Routing = 2 although the text says None (0); the errata gives
    /// the dump with 0 and its own authenticator. Both are valid packets.
    #[test]
    fn rfc_2865_section_7_2_with_errata_1469() {
        let req = hex("01 01 00 47 2a ee 86 f0 8d 0d 55 96 9c a5 97 8e
             0d 33 67 a2 01 08 66 6c 6f 70 73 79 03 13 16 e9
             75 57 c3 16 18 58 95 f2 93 ff 63 44 07 72 75 04
             06 c0 a8 01 10 05 06 00 00 00 14 06 06 00 00 00
             02 07 06 00 00 00 01");
        let p = Packet::parse(&req).unwrap();
        let chap = p.attr(attr::CHAP_PASSWORD).unwrap();
        assert_eq!((chap.len(), chap[0]), (17, 22));
        let corrected = hex("02 01 00 38 E8 6F A2 FE 28 70 33 AD 2F 6D 5C A3
             F7 41 5D A2 06 06 00 00 00 02 07 06 00 00 00 01
             08 06 FF FF FF FE 0A 06 00 00 00 00 0D 06 00 00
             00 01 0C 06 00 00 05 DC");
        let r = Packet::parse(&corrected).unwrap();
        assert!(verify_response(&r, &p.authenticator(), SECRET));
        let printed = hex("02 01 00 38 15 ef bc 7d ab 26 cf a3 dc 34 d9 c0
             3c 86 01 a4 06 06 00 00 00 02 07 06 00 00 00 01
             08 06 ff ff ff fe 0a 06 00 00 00 02 0d 06 00 00
             00 01 0c 06 00 00 05 dc");
        let r2 = Packet::parse(&printed).unwrap();
        assert!(verify_response(&r2, &p.authenticator(), SECRET));
        assert_eq!(r.attr_u32(10), Some(0));
        assert_eq!(r2.attr_u32(10), Some(2));
    }

    /// RFC 2865 §7.3 with verified errata 6486 (State length 0x0a, not
    /// 0x10): challenge, response with "99101462", and the Reject.
    #[test]
    fn rfc_2865_section_7_3_with_errata_6486() {
        let req = hex("01 02 00 39 f3 a4 7a 1f 6a 6d 76 71 0b 94 7a b9
             30 41 a0 39 01 07 6d 6f 70 73 79 02 12 33 65 75
             73 77 82 89 b5 70 88 5e 15 08 48 25 c5 04 06 c0
             a8 01 10 05 06 00 00 00 07");
        let p = Packet::parse(&req).unwrap();
        let ra = p.authenticator();
        let pw = unhide_user_password(p.attr(2).unwrap(), SECRET, &ra).unwrap();
        assert_eq!(pw, b"challenge");
        let chal = hex("0b 02 00 4e 36 f3 c8 76 4a e8 c7 11 57 40 3c 0c
             71 ff 9c 45 12 30 43 68 61 6c 6c 65 6e 67 65 20
             33 32 37 36 39 34 33 30 2e 20 20 45 6e 74 65 72
             20 72 65 73 70 6f 6e 73 65 20 61 74 20 70 72 6f
             6d 70 74 2e 18 0a 33 32 37 36 39 34 33 30");
        let c = Packet::parse(&chal).unwrap();
        assert!(verify_response(&c, &ra, SECRET));
        assert_eq!(c.attr(attr::STATE).unwrap(), b"32769430");

        // As printed, the State length (0x10) runs past the packet.
        let printed = hex("01 03 00 43 b1 22 55 6d 42 8a 13 d0 d6 25 38 07
             c4 57 ec f0 01 07 6d 6f 70 73 79 02 12 69 2c 1f
             20 5f c0 81 b9 19 b9 51 95 f5 61 a5 81 04 06 c0
             a8 01 10 05 06 00 00 00 07 18 10 33 32 37 36 39
             34 33 30");
        assert!(Packet::parse(&printed).is_err());
        let mut fixed = printed.clone();
        fixed[0x3a] = 0x0a;
        let p2 = Packet::parse(&fixed).unwrap();
        let ra2 = p2.authenticator();
        assert_eq!(
            unhide_user_password(p2.attr(2).unwrap(), SECRET, &ra2).unwrap(),
            b"99101462"
        );
        assert_eq!(p2.attr(attr::STATE).unwrap(), b"32769430");
        let reject = hex("03 03 00 14 a4 2f 4f ca 45 91 6c 4e 09 c8 34 0f 9e 74 6a a0");
        let r = Packet::parse(&reject).unwrap();
        assert!(verify_response(&r, &ra2, SECRET));
    }

    /// RFC 5997 §6.1 and §6.3: Status-Server with Message-Authenticator,
    /// and the Access-Accept answers.
    #[test]
    fn rfc_5997_section_6() {
        let q = hex("0c da 00 26 8a 54 f4 68 6f b3 94 c5 28 66 e3 02
             18 5d 06 23 50 12 5a 66 5e 2e 1e 84 11 f3 e2 43
             82 20 97 c8 4f a3");
        let p = Packet::parse(&q).unwrap();
        assert_eq!((p.code(), p.identifier()), (Code::StatusServer, 218));
        assert_eq!(
            check_message_authenticator(&p, &request_ma_auth(&p), SECRET),
            MaCheck::Valid
        );
        let a = hex("02 da 00 14 ef 0d 55 2a 4b f2 d6 93 ec 2b 6f e8 b5 41 1d 66");
        assert!(verify_response(
            &Packet::parse(&a).unwrap(),
            &p.authenticator(),
            SECRET
        ));

        let q = hex("0c 47 00 2c bf 58 de 56 ae 40 8a d3 b7 0c 85 13
             f9 b0 3f be 04 06 c0 00 02 10 50 12 85 2d 6f ec
             61 e7 ed 74 b8 e3 2d ac 2f 2a 5f b2");
        let p = Packet::parse(&q).unwrap();
        assert_eq!(
            check_message_authenticator(&p, &request_ma_auth(&p), SECRET),
            MaCheck::Valid
        );
        let a = hex("02 47 00 34 46 f4 3e 62 fd 03 54 42 4c bb eb fd
             6d 21 4e 06 12 20 52 41 44 49 55 53 20 53 65 72
             76 65 72 20 75 70 20 32 20 64 61 79 73 2c 20 31
             38 3a 34 30");
        let r = Packet::parse(&a).unwrap();
        assert!(verify_response(&r, &p.authenticator(), SECRET));
        assert_eq!(
            r.attr(attr::REPLY_MESSAGE).unwrap(),
            b"RADIUS Server up 2 days, 18:40"
        );
    }

    /// RFC 5997 §6.2: the text says Accounting-Response (5) but the dump
    /// starts with 02. The authenticator was computed over code 5: the 02
    /// is a typo in the dump.
    #[test]
    fn rfc_5997_section_6_2_as_printed() {
        let q = hex("0c b3 00 26 92 5f 6b 66 dd 5f ed 57 1f cb 1d b7
             ad 38 82 60 50 12 e8 d6 ea bd a9 10 87 5c d9 1f
             da de 26 36 78 58");
        let p = Packet::parse(&q).unwrap();
        assert_eq!(
            check_message_authenticator(&p, &request_ma_auth(&p), SECRET),
            MaCheck::Valid
        );
        let mut a = hex("02 b3 00 14 0f 6f 92 14 5f 10 7e 2f 50 4e 86 0a 48 60 66 9c");
        let printed = verify_response(&Packet::parse(&a).unwrap(), &p.authenticator(), SECRET);
        a[0] = 5;
        let as_text = verify_response(&Packet::parse(&a).unwrap(), &p.authenticator(), SECRET);
        assert!(!printed && as_text);
    }

    #[test]
    fn accounting_and_coa_authenticators_verify() {
        for code in [
            Code::AccountingRequest,
            Code::CoaRequest,
            Code::DisconnectRequest,
        ] {
            let mut b = Builder::new(code, 9);
            b.message_authenticator().unwrap();
            b.push_text(attr::ACCT_SESSION_ID, "s1").unwrap();
            let bytes = sign_request(b, b"s3cret");
            let p = Packet::parse(&bytes).unwrap();
            assert!(verify_computed_request(&p, b"s3cret"));
            assert!(!verify_computed_request(&p, b"other"));
            assert_eq!(
                check_message_authenticator(&p, &request_ma_auth(&p), b"s3cret"),
                MaCheck::Valid
            );
            assert_eq!(
                check_message_authenticator(&p, &request_ma_auth(&p), b"x"),
                MaCheck::Invalid
            );
        }
    }

    #[test]
    fn message_authenticator_detects_tampering_and_duplicates() {
        let mut b = Builder::with_authenticator(Code::AccessRequest, 1, [7; 16]);
        b.message_authenticator().unwrap();
        b.push_text(attr::USER_NAME, "ana").unwrap();
        let mut bytes = sign_request(b, b"k");
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            check_message_authenticator(&p, &p.authenticator(), b"k"),
            MaCheck::Valid
        );
        *bytes.last_mut().unwrap() ^= 1;
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            check_message_authenticator(&p, &p.authenticator(), b"k"),
            MaCheck::Invalid
        );

        let mut b = Builder::new(Code::AccessRequest, 1);
        b.push(attr::MESSAGE_AUTHENTICATOR, &[0; 16]).unwrap();
        b.push(attr::MESSAGE_AUTHENTICATOR, &[0; 16]).unwrap();
        let bytes = b.into_unsigned();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            check_message_authenticator(&p, &[0; 16], b"k"),
            MaCheck::Invalid
        );
    }

    #[test]
    fn responses_carry_a_message_authenticator_over_the_request_auth() {
        let ra = [3u8; 16];
        let mut b = Builder::new(Code::AccessAccept, 4);
        b.message_authenticator().unwrap();
        b.push_u32(attr::SESSION_TIMEOUT, 60).unwrap();
        let bytes = sign_response(b, &ra, b"k");
        let p = Packet::parse(&bytes).unwrap();
        assert!(verify_response(&p, &ra, b"k"));
        assert_eq!(check_message_authenticator(&p, &ra, b"k"), MaCheck::Valid);
        assert_eq!(
            check_message_authenticator(&p, &[0; 16], b"k"),
            MaCheck::Invalid
        );
    }

    #[test]
    fn salt_encryption_round_trips_and_checks_the_salt() {
        let ra = [9u8; 16];
        let v = salt_encrypt(b"tunnel-pass", b"k", &ra, [0x80, 0x01]).unwrap();
        assert_eq!(v.len(), 2 + 16);
        assert_eq!(salt_decrypt(&v, b"k", &ra).unwrap(), b"tunnel-pass");
        assert_eq!(
            salt_encrypt(b"x", b"k", &ra, [0x7f, 0]),
            Err(EncodeError::BadSalt)
        );
        // A 16-byte MPPE key: 1 + 16 = 17 → two blocks (RFC 2548 §2.4.2).
        let v = salt_encrypt(&[0xAB; 16], b"k", &ra, [0x81, 0x02]).unwrap();
        assert_eq!(v.len(), 34);
        assert_eq!(salt_decrypt(&v, b"k", &ra).unwrap(), vec![0xAB; 16]);
    }

    #[test]
    fn user_password_limits() {
        assert!(hide_user_password(&[1; 129], b"k", &[0; 16]).is_err());
        let h = hide_user_password(b"", b"k", &[0; 16]).unwrap();
        assert_eq!(h.len(), 16);
        assert_eq!(unhide_user_password(&h, b"k", &[0; 16]).unwrap(), b"");
        assert!(unhide_user_password(&[0; 15], b"k", &[0; 16]).is_none());
        let long = vec![b'a'; 128];
        let h = hide_user_password(&long, b"k", &[1; 16]).unwrap();
        assert_eq!(unhide_user_password(&h, b"k", &[1; 16]).unwrap(), long);
    }

    #[test]
    fn chap_round_trip() {
        let mut b = Builder::with_authenticator(Code::AccessRequest, 1, [5; 16]);
        let challenge = [0x11u8; 16];
        let mut v = vec![42];
        v.extend_from_slice(&chap_response(42, b"pw", &challenge));
        b.push(attr::CHAP_PASSWORD, &v).unwrap();
        b.push(attr::CHAP_CHALLENGE, &challenge).unwrap();
        let bytes = b.into_unsigned();
        let p = Packet::parse(&bytes).unwrap();
        assert!(verify_chap(&p, b"pw"));
        assert!(!verify_chap(&p, b"px"));
    }
}

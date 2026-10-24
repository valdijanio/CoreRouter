//! MS-CHAP for RADIUS: the computations of RFC 2433 (v1) and RFC 2759 (v2),
//! the MPPE key derivation of RFC 3079, and the Microsoft VSA layouts of
//! RFC 2548 (vendor 311).
//!
//! The NAS only relays MS-CHAP to the server (RFC 2548 §2.3); the
//! computations are here for the test server, for local authentication
//! and for checking an MS-CHAP2-Success (the NAS SHOULD check the
//! authenticator response before telling the peer it succeeded).

use des::cipher::{BlockCipherEncrypt, KeyInit};
use md4::Md4;
use sha1::{Digest, Sha1};

/// RFC 2548 §2: Microsoft's vendor id.
pub const VENDOR_MICROSOFT: u32 = 311;

/// RFC 2548 vendor types.
pub mod vsa {
    pub const MS_CHAP_RESPONSE: u8 = 1;
    pub const MS_CHAP_ERROR: u8 = 2;
    pub const MS_MPPE_ENCRYPTION_POLICY: u8 = 7;
    pub const MS_MPPE_ENCRYPTION_TYPES: u8 = 8;
    pub const MS_CHAP_DOMAIN: u8 = 10;
    pub const MS_CHAP_CHALLENGE: u8 = 11;
    pub const MS_MPPE_SEND_KEY: u8 = 16;
    pub const MS_MPPE_RECV_KEY: u8 = 17;
    pub const MS_CHAP2_RESPONSE: u8 = 25;
    pub const MS_CHAP2_SUCCESS: u8 = 26;
    pub const MS_PRIMARY_DNS_SERVER: u8 = 28;
    pub const MS_SECONDARY_DNS_SERVER: u8 = 29;
}

/// Password as UTF-16LE ("0-to-256-unicode-char Password", RFC 2759 §8).
pub fn utf16le(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// RFC 2759 §8.3 NtPasswordHash: MD4 of the UTF-16LE password.
pub fn nt_password_hash(password_utf16le: &[u8]) -> [u8; 16] {
    Md4::digest(password_utf16le).into()
}

/// RFC 2759 §8.4 HashNtPasswordHash: MD4 of the hash.
pub fn hash_nt_password_hash(hash: &[u8; 16]) -> [u8; 16] {
    Md4::digest(hash).into()
}

/// RFC 2759 §8.2 ChallengeHash: the first 8 octets of
/// SHA1(PeerChallenge ‖ AuthenticatorChallenge ‖ UserName). "Only the user
/// name (as presented by the peer and excluding any prepended domain name)
/// is used" — see [`strip_domain`].
pub fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], user: &[u8]) -> [u8; 8] {
    let d: [u8; 20] = Sha1::new()
        .chain_update(peer)
        .chain_update(auth)
        .chain_update(user)
        .finalize()
        .into();
    let mut c = [0u8; 8];
    c.copy_from_slice(d.get(..8).unwrap_or(&[0; 8]));
    c
}

/// `DOMAIN\user` → `user` (RFC 2759 §8.2).
pub fn strip_domain(user: &[u8]) -> &[u8] {
    match user.iter().rposition(|&b| b == b'\\') {
        Some(i) => user.get(i + 1..).unwrap_or(&[]),
        None => user,
    }
}

/// RFC 2759 §8.6 DesEncrypt key: 7 octets spread over 8 (the low bit of
/// each octet is parity, which DES ignores; RFC 2759 §9.3 sets it odd).
fn des_key(k7: &[u8]) -> [u8; 8] {
    let mut bits: u64 = 0;
    for &b in k7.iter().take(7) {
        bits = (bits << 8) | u64::from(b);
    }
    let mut k = [0u8; 8];
    for (i, out) in k.iter_mut().enumerate() {
        let seven = ((bits >> (49 - 7 * i)) & 0x7f) as u8;
        let v = seven << 1;
        *out = v | u8::from(v.count_ones().is_multiple_of(2));
    }
    k
}

fn des_encrypt(k7: &[u8], clear: &[u8; 8]) -> [u8; 8] {
    let key = des_key(k7);
    let mut block = (*clear).into();
    if let Ok(c) = des::Des::new_from_slice(&key) {
        c.encrypt_block(&mut block);
    }
    block.into()
}

/// RFC 2759 §8.5 ChallengeResponse: the hash padded to 21 octets, three
/// DES encryptions of the 8-octet challenge.
pub fn challenge_response(challenge: &[u8; 8], hash: &[u8; 16]) -> [u8; 24] {
    let mut z = [0u8; 21];
    if let Some(d) = z.get_mut(..16) {
        d.copy_from_slice(hash)
    }
    let mut out = [0u8; 24];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let r = des_encrypt(z.get(i * 7..i * 7 + 7).unwrap_or(&[0; 7]), challenge);
        chunk.copy_from_slice(&r);
    }
    out
}

/// RFC 2759 §8.1 GenerateNTResponse.
pub fn generate_nt_response(
    auth: &[u8; 16],
    peer: &[u8; 16],
    user: &[u8],
    password_utf16le: &[u8],
) -> [u8; 24] {
    let c = challenge_hash(peer, auth, user);
    challenge_response(&c, &nt_password_hash(password_utf16le))
}

/// RFC 2433 §A.5 (MS-CHAPv1) NtChallengeResponse: the 8-octet challenge
/// encrypted with the NT password hash.
pub fn v1_nt_response(challenge: &[u8; 8], password_utf16le: &[u8]) -> [u8; 24] {
    challenge_response(challenge, &nt_password_hash(password_utf16le))
}

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// RFC 2759 §8.7 GenerateAuthenticatorResponse (the 20-octet digest; see
/// [`authenticator_response_string`] for the "S=…" text).
pub fn authenticator_response(
    password_utf16le: &[u8],
    nt_response: &[u8; 24],
    peer: &[u8; 16],
    auth: &[u8; 16],
    user: &[u8],
) -> [u8; 20] {
    let hh = hash_nt_password_hash(&nt_password_hash(password_utf16le));
    let digest: [u8; 20] = Sha1::new()
        .chain_update(hh)
        .chain_update(nt_response)
        .chain_update(MAGIC1)
        .finalize()
        .into();
    let c = challenge_hash(peer, auth, user);
    Sha1::new()
        .chain_update(digest)
        .chain_update(c)
        .chain_update(MAGIC2)
        .finalize()
        .into()
}

/// "S=" followed by 40 uppercase hex digits (RFC 2759 §8.7).
pub fn authenticator_response_string(digest: &[u8; 20]) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("S=");
    for b in digest {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// RFC 3079 §3.4 GetMasterKey.
pub fn master_key(password_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    const MAGIC: &[u8] = b"This is the MPPE Master Key";
    let d: [u8; 20] = Sha1::new()
        .chain_update(password_hash_hash)
        .chain_update(nt_response)
        .chain_update(MAGIC)
        .finalize()
        .into();
    let mut k = [0u8; 16];
    k.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    k
}

/// RFC 3079 §3.4 GetAsymmetricStartKey, 128-bit keys (16 octets).
pub fn asymmetric_start_key(master: &[u8; 16], is_send: bool, is_server: bool) -> [u8; 16] {
    const CLIENT_SEND: &[u8] =
        b"On the client side, this is the send key; on the server side, it is the receive key.";
    const CLIENT_RECV: &[u8] =
        b"On the client side, this is the receive key; on the server side, it is the send key.";
    // Magic2 = CLIENT_SEND, Magic3 = CLIENT_RECV.
    let s = if is_send == is_server {
        CLIENT_RECV
    } else {
        CLIENT_SEND
    };
    let d: [u8; 20] = Sha1::new()
        .chain_update(master)
        .chain_update([0u8; 40])
        .chain_update(s)
        .chain_update([0xf2u8; 40])
        .finalize()
        .into();
    let mut k = [0u8; 16];
    k.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    k
}

/// The keys an MS-CHAPv2 server returns in MS-MPPE-Send-Key and
/// MS-MPPE-Recv-Key (RFC 2548 §2.4.2/§2.4.3): the NAS is the PPP
/// authenticator, i.e. the "server" of RFC 3079.
pub fn mppe_keys(password_utf16le: &[u8], nt_response: &[u8; 24]) -> MppeKeys {
    let hh = hash_nt_password_hash(&nt_password_hash(password_utf16le));
    let master = master_key(&hh, nt_response);
    MppeKeys {
        send: asymmetric_start_key(&master, true, true),
        recv: asymmetric_start_key(&master, false, true),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MppeKeys {
    pub send: [u8; 16],
    pub recv: [u8; 16],
}

/// RFC 2548 §2.3.2 MS-CHAP2-Response: Ident, Flags, Peer-Challenge (16),
/// Reserved (8), Response (24) = 50 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chap2Response {
    pub ident: u8,
    pub flags: u8,
    pub peer_challenge: [u8; 16],
    pub nt_response: [u8; 24],
}

impl Chap2Response {
    pub const LEN: usize = 50;

    pub fn parse(v: &[u8]) -> Option<Self> {
        let v: &[u8; 50] = v.try_into().ok()?;
        let (head, rest) = v.split_first_chunk::<2>()?;
        let (peer, rest) = rest.split_first_chunk::<16>()?;
        let (_reserved, rest) = rest.split_first_chunk::<8>()?;
        let nt: [u8; 24] = rest.try_into().ok()?;
        Some(Self {
            ident: head[0],
            flags: head[1],
            peer_challenge: *peer,
            nt_response: nt,
        })
    }

    pub fn encode(&self) -> [u8; 50] {
        let mut v = [0u8; 50];
        v[0] = self.ident;
        v[1] = self.flags;
        if let Some(d) = v.get_mut(2..18) {
            d.copy_from_slice(&self.peer_challenge)
        }
        if let Some(d) = v.get_mut(26..50) {
            d.copy_from_slice(&self.nt_response)
        }
        v
    }
}

/// RFC 2548 §2.1.3 MS-CHAP-Response (v1): Ident, Flags, LM-Response (24),
/// NT-Response (24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chap1Response {
    pub ident: u8,
    pub flags: u8,
    pub nt_response: [u8; 24],
}

impl Chap1Response {
    pub fn parse(v: &[u8]) -> Option<Self> {
        let v: &[u8; 50] = v.try_into().ok()?;
        let nt: [u8; 24] = v.get(26..50)?.try_into().ok()?;
        Some(Self {
            ident: v[0],
            flags: v[1],
            nt_response: nt,
        })
    }
}

/// RFC 2548 §2.3.3 MS-CHAP2-Success value: Ident ‖ "S=<40 hex>".
pub fn chap2_success(ident: u8, digest: &[u8; 20]) -> Vec<u8> {
    let mut v = vec![ident];
    v.extend_from_slice(authenticator_response_string(digest).as_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    const AUTH: &str = "5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28";
    const PEER: &str = "21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E";
    const NT_RESPONSE: &str =
        "82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF";

    /// RFC 2759 §9.2 "Hash Example".
    #[test]
    fn rfc_2759_section_9_2() {
        let pw = utf16le("clientPass");
        assert_eq!(
            pw,
            hex("63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00")
        );
        let (auth, peer) = (arr::<16>(AUTH), arr::<16>(PEER));
        assert_eq!(
            challenge_hash(&peer, &auth, b"User"),
            arr::<8>("D0 2E 43 86 BC E9 12 26")
        );
        let hash = nt_password_hash(&pw);
        assert_eq!(
            hash,
            arr::<16>("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE")
        );
        let nt = generate_nt_response(&auth, &peer, b"User", &pw);
        assert_eq!(nt, arr::<24>(NT_RESPONSE));
        assert_eq!(
            hash_nt_password_hash(&hash),
            arr::<16>("41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F")
        );
        let ar = authenticator_response(&pw, &nt, &peer, &auth, b"User");
        assert_eq!(
            authenticator_response_string(&ar),
            "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
    }

    /// RFC 2759 §9.3: parity-corrected DES keys of "MyPw".
    #[test]
    fn rfc_2759_section_9_3_des_keys() {
        let hash = nt_password_hash(&hex("4D 00 79 00 50 00 77 00"));
        assert_eq!(
            hash,
            arr::<16>("FC 15 6A F7 ED CD 6C 0E DD E3 33 7D 42 7F 4E AC")
        );
        assert_eq!(des_key(&hash[..7]), arr::<8>("FD 0B 5B 5E 7F 6E 34 D9"));
        assert_eq!(des_key(&hash[7..14]), arr::<8>("0E 6E 79 67 37 EA 08 FE"));
    }

    /// RFC 3079 §3.5.3 "Sample 128-bit Key Derivation": the master key and
    /// the send start key, which is the server's (Magic3): the NAS's
    /// MS-MPPE-Send-Key.
    #[test]
    fn rfc_3079_section_3_5_3() {
        let hh = arr::<16>("41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F");
        let master = master_key(&hh, &arr::<24>(NT_RESPONSE));
        assert_eq!(
            master,
            arr::<16>("FD EC E3 71 7A 8C 83 8C B3 88 E5 27 AE 3C DD 31")
        );
        let send = asymmetric_start_key(&master, true, true);
        assert_eq!(
            send,
            arr::<16>("8B 7C DC 14 9B 99 3A 1B A1 18 CB 15 3F 56 DC CB")
        );
        // The client's receive key is the server's send key.
        assert_eq!(asymmetric_start_key(&master, false, false), send);
        let keys = mppe_keys(&utf16le("clientPass"), &arr::<24>(NT_RESPONSE));
        assert_eq!(keys.send, send);
        assert_eq!(keys.recv, asymmetric_start_key(&master, true, false));
    }

    #[test]
    fn chap2_response_layout_round_trips() {
        let r = Chap2Response {
            ident: 7,
            flags: 0,
            peer_challenge: arr::<16>(PEER),
            nt_response: arr::<24>(NT_RESPONSE),
        };
        let v = r.encode();
        assert_eq!(Chap2Response::parse(&v), Some(r));
        assert_eq!(Chap2Response::parse(&v[..49]), None);
        assert_eq!(chap2_success(7, &[0xAB; 20]).len(), 43);
    }

    #[test]
    fn domain_is_stripped() {
        assert_eq!(strip_domain(b"CORP\\ana"), b"ana");
        assert_eq!(strip_domain(b"ana"), b"ana");
        assert_eq!(strip_domain(b"ana\\"), b"");
    }
}

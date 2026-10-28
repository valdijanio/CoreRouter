//! Keyed SHA1 and Meticulous Keyed SHA1 (RFC 5880 §6.7.4), with the order
//! of erratum 7083 (verified): the hash is checked **before** the
//! sequence state changes, so a forged packet cannot move the window.
//!
//! Simple Password and the MD5 types are not offered: MD5 is weak and
//! Simple Password sends the key in clear (RFC 5880 §6.7.2 itself warns);
//! a packet with them on a SHA1 session fails like any mismatch.

use sha1::{Digest, Sha1};

use crate::packet::{AuthSection, AuthType, MAX_LEN, MIN_LEN, Packet};

/// §4.4 Auth Key: "up to 20 bytes", zero-padded.
pub const MAX_KEY: usize = 20;

/// What a session authenticates with.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthConfig {
    /// Every packet carries a new sequence number (Meticulous) or only
    /// "occasionally" (Keyed; we still increment on every packet, which
    /// §6.7.4 allows and which keeps replays out).
    pub meticulous: bool,
    pub key_id: u8,
    pub key: [u8; MAX_KEY],
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuthConfig(meticulous={}, key_id={}, key=***)",
            self.meticulous, self.key_id
        )
    }
}

impl AuthConfig {
    /// `None` for a key longer than 20 bytes or empty.
    pub fn new(meticulous: bool, key_id: u8, key: &[u8]) -> Option<Self> {
        if key.is_empty() || key.len() > MAX_KEY {
            return None;
        }
        let mut k = [0u8; MAX_KEY];
        k.get_mut(..key.len())?.copy_from_slice(key);
        Some(Self {
            meticulous,
            key_id,
            key: k,
        })
    }

    pub fn kind(&self) -> AuthType {
        if self.meticulous {
            AuthType::MeticulousKeyedSha1
        } else {
            AuthType::KeyedSha1
        }
    }
}

/// The receive side of §6.8.1: bfd.RcvAuthSeq and bfd.AuthSeqKnown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RcvSeq {
    pub known: bool,
    pub last: u32,
}

fn digest(bytes: &[u8]) -> [u8; 20] {
    Sha1::new().chain_update(bytes).finalize().into()
}

/// §6.7.4 transmission: the hash over the whole packet with the key in
/// the Auth Key/Hash field, then the hash in its place.
pub fn sign(p: &mut Packet, cfg: &AuthConfig, seq: u32, out: &mut [u8; MAX_LEN]) -> usize {
    p.auth = Some(AuthSection {
        kind: cfg.kind(),
        key_id: cfg.key_id,
        seq,
        digest: cfg.key,
    });
    let n = p.encode(out);
    let h = digest(out.get(..n).unwrap_or(&[]));
    if let Some(d) = out.get_mut(MIN_LEN + 8..MIN_LEN + 28) {
        d.copy_from_slice(&h);
    }
    if let Some(a) = p.auth.as_mut() {
        a.digest = h;
    }
    n
}

/// Why an authenticated packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// A bit and session auth disagree (§6.8.6), or another auth type.
    Mismatch,
    KeyId,
    /// §6.7.4: outside the sequence window (a replay, or too far ahead).
    Sequence,
    Digest,
}

/// `a` lies in the circular range `[lo, lo + span]` of 32-bit numbers.
fn in_window(a: u32, lo: u32, span: u32) -> bool {
    a.wrapping_sub(lo) <= span
}

/// §6.7.4 reception, on the raw bytes the packet was decoded from.
/// `detect_mult` is the received Detect Mult (the window is 3 × it).
/// Returns the new [`RcvSeq`] only when the packet is accepted.
pub fn verify(raw: &[u8], p: &Packet, cfg: &AuthConfig, seq: RcvSeq) -> Result<RcvSeq, AuthError> {
    let a = p.auth.ok_or(AuthError::Mismatch)?;
    if a.kind != cfg.kind() {
        return Err(AuthError::Mismatch);
    }
    if a.key_id != cfg.key_id {
        return Err(AuthError::KeyId);
    }
    if seq.known {
        let span = 3 * u32::from(p.detect_mult);
        // Keyed: [RcvAuthSeq, RcvAuthSeq + 3·M]; Meticulous: [+1, +3·M].
        let ok = if cfg.meticulous {
            in_window(a.seq, seq.last.wrapping_add(1), span - 1)
        } else {
            in_window(a.seq, seq.last, span)
        };
        if !ok {
            return Err(AuthError::Sequence);
        }
    }
    let len = MIN_LEN + crate::packet::SHA1_AUTH_LEN;
    let mut buf = [0u8; MAX_LEN];
    let src = raw.get(..len).ok_or(AuthError::Mismatch)?;
    buf.copy_from_slice(src);
    if let Some(d) = buf.get_mut(MIN_LEN + 8..MIN_LEN + 28) {
        d.copy_from_slice(&cfg.key);
    }
    // Constant time is not needed against a network attacker who cannot
    // time SHA1 to the byte, but costs nothing.
    let h = digest(&buf);
    let diff = h
        .iter()
        .zip(a.digest.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    if diff != 0 {
        return Err(AuthError::Digest);
    }
    Ok(RcvSeq {
        known: true,
        last: a.seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(meticulous: bool) -> AuthConfig {
        AuthConfig::new(meticulous, 1, b"s3cr3t").unwrap()
    }

    fn signed(c: &AuthConfig, seq: u32) -> (Vec<u8>, Packet) {
        let mut p = Packet::new(77);
        let mut out = [0u8; MAX_LEN];
        let n = sign(&mut p, c, seq, &mut out);
        let raw = out[..n].to_vec();
        let back = Packet::decode(&raw).unwrap();
        (raw, back)
    }

    #[test]
    fn sign_then_verify() {
        let c = cfg(false);
        let (raw, p) = signed(&c, 100);
        let st = verify(&raw, &p, &c, RcvSeq::default()).unwrap();
        assert_eq!(
            st,
            RcvSeq {
                known: true,
                last: 100
            }
        );
        // Wrong key.
        let other = AuthConfig::new(false, 1, b"other").unwrap();
        assert_eq!(
            verify(&raw, &p, &other, RcvSeq::default()),
            Err(AuthError::Digest)
        );
        // Wrong key id.
        let id2 = AuthConfig::new(false, 2, b"s3cr3t").unwrap();
        assert_eq!(
            verify(&raw, &p, &id2, RcvSeq::default()),
            Err(AuthError::KeyId)
        );
        // A flipped bit anywhere in the header breaks the hash.
        let mut bad = raw.clone();
        bad[13] ^= 1;
        let pb = Packet::decode(&bad).unwrap();
        assert_eq!(
            verify(&bad, &pb, &c, RcvSeq::default()),
            Err(AuthError::Digest)
        );
    }

    #[test]
    fn rfc_5880_6_7_4_sequence_window() {
        let c = cfg(false);
        let known = RcvSeq {
            known: true,
            last: 10,
        };
        // Keyed: the same number is accepted (only "occasionally" increased).
        let (raw, p) = signed(&c, 10);
        assert!(verify(&raw, &p, &c, known).is_ok());
        // Up to 3 × Detect Mult (3) ahead.
        let (raw, p) = signed(&c, 19);
        assert!(verify(&raw, &p, &c, known).is_ok());
        let (raw, p) = signed(&c, 20);
        assert_eq!(verify(&raw, &p, &c, known), Err(AuthError::Sequence));
        // Behind: a replay.
        let (raw, p) = signed(&c, 9);
        assert_eq!(verify(&raw, &p, &c, known), Err(AuthError::Sequence));
        // Meticulous: the same number is a replay.
        let m = cfg(true);
        let (raw, p) = signed(&m, 10);
        assert_eq!(verify(&raw, &p, &m, known), Err(AuthError::Sequence));
        let (raw, p) = signed(&m, 11);
        assert!(verify(&raw, &p, &m, known).is_ok());
        let (raw, p) = signed(&m, 19);
        assert!(verify(&raw, &p, &m, known).is_ok());
        // Wraps around 2^32.
        let wrap = RcvSeq {
            known: true,
            last: u32::MAX,
        };
        let (raw, p) = signed(&m, 2);
        assert!(verify(&raw, &p, &m, wrap).is_ok());
    }

    #[test]
    fn erratum_7083_bad_hash_does_not_move_the_window() {
        let c = cfg(true);
        let known = RcvSeq {
            known: true,
            last: 10,
        };
        let (mut raw, _) = signed(&c, 15);
        raw[40] ^= 0xff; // inside the digest
        let p = Packet::decode(&raw).unwrap();
        assert_eq!(verify(&raw, &p, &c, known), Err(AuthError::Digest));
        // The caller keeps `known` (verify returned no new state): 11 still ok.
        let (raw, p) = signed(&c, 11);
        assert!(verify(&raw, &p, &c, known).is_ok());
    }

    #[test]
    fn key_limits() {
        assert!(AuthConfig::new(false, 0, b"").is_none());
        assert!(AuthConfig::new(false, 0, &[1; 21]).is_none());
        assert!(AuthConfig::new(false, 0, &[1; 20]).is_some());
        assert!(!format!("{:?}", cfg(true)).contains("s3cr3t"));
    }
}

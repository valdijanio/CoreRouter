//! Secrets sealed at rest (G4.3n): the PPP secrets' passwords.
//!
//! CHAP needs the password in clear (RFC 1994 §2.2), and RFC 1994 §6 asks
//! that secrets be readable only by the process that needs them. The config
//! (and every revision, history file and diff made from it) holds a
//! [`Sealed`] box instead: AES-256-GCM with a random 96-bit nonce and a
//! fixed associated text, under a 32-byte key kept **outside** the
//! config, in the storage's state `secret-key` (`state-secret-key.json` in
//! the config dir, mode 0600, made on first use). A copy of `running.json`
//! or of a `rev-*.json` alone does not give the passwords away; the key
//! file and the config together do, so back up both (or use
//! `/export show-sensitive`, group full).
//!
//! Without the key file a sealed password cannot be opened: the login is
//! refused as a wrong password, and the start-up log says why. A key file
//! that exists but cannot be read is never replaced by a new one.
//!
//! The browser lab (wasm) has no random source: it seals with a key and
//! nonces made for that run only (nothing is stored there).
//!
//! AES-256-GCM, not XChaCha20-Poly1305: opening a password is on the
//! PPPoE login path, and it takes 94 ns against 1.3 µs (**medido**,
//! release, 12-byte passwords; AES-NI picked at run time). Random 96-bit
//! nonces stay far below the 2^32 boxes per key of NIST SP 800-38D §8.3
//! (a router seals at most a few million in its life).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use corerouter_model::sealed::{PREFIX, Sealed};

use crate::Session;

/// The storage state that holds the key.
pub const KEY_STATE: &str = "secret-key";
/// Bound to every box: a box cannot be passed off as another kind of data.
const AAD: &[u8] = b"corerouter/ppp-secret/v1";
const NONCE: usize = 12;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD_NO_PAD;

/// The key, shared by the session and the PPPoE workers.
pub struct SealKey {
    cipher: Aes256Gcm,
    /// Made for this run (no random source): nonces from a counter.
    ephemeral: bool,
    counter: AtomicU64,
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(***)")
    }
}

impl SealKey {
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(&(*key).into()),
            ephemeral: false,
            counter: AtomicU64::new(0),
        }
    }

    fn nonce(&self) -> Result<[u8; NONCE], String> {
        let mut n = [0u8; NONCE];
        if self.ephemeral {
            let c = self.counter.fetch_add(1, Ordering::Relaxed);
            if let Some(head) = n.get_mut(..8) {
                head.copy_from_slice(&c.to_le_bytes());
            }
            return Ok(n);
        }
        crate::auth::random_bytes(&mut n)?;
        Ok(n)
    }

    /// `plain` in a box (empty stays empty: no password).
    pub fn seal(&self, plain: &str) -> Result<Sealed, String> {
        if plain.is_empty() {
            return Ok(Sealed::default());
        }
        let nonce = self.nonce()?;
        let ct = self
            .cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: plain.as_bytes(), aad: AAD })
            .map_err(|_| "sealing failed".to_owned())?;
        let mut raw = Vec::with_capacity(NONCE + ct.len());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ct);
        Ok(Sealed::from_box(format!("{PREFIX}{}", B64.encode(raw))))
    }

    /// The password in `s`; a legacy clear one as it is. `None`: a box this
    /// key did not make (another router's config, a damaged file).
    pub fn open(&self, s: &Sealed) -> Option<String> {
        open_with(Some(self), s)
    }
}

/// [`SealKey::open`] with maybe no key: only clear (legacy) values open.
pub fn open_with(key: Option<&SealKey>, s: &Sealed) -> Option<String> {
    let Some(b64) = s.stored().strip_prefix(PREFIX) else {
        return Some(s.stored().to_owned());
    };
    let key = key?;
    let raw = B64.decode(b64).ok()?;
    let (nonce, ct) = raw.split_at_checked(NONCE)?;
    let nonce: [u8; NONCE] = nonce.try_into().ok()?;
    let pt = key
        .cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad: AAD })
        .ok()?;
    String::from_utf8(pt).ok()
}

#[derive(Default)]
struct KeySlot(Option<Arc<SealKey>>);

/// The session's key: loaded from the storage, or made (and stored) on
/// first use. An error when a stored key cannot be read (it is never
/// replaced: the passwords it sealed would be lost).
pub fn key(s: &mut Session) -> Result<Arc<SealKey>, String> {
    if let Some(k) = s.ext::<KeySlot>().and_then(|k| k.0.clone()) {
        return Ok(k);
    }
    let k = Arc::new(load_or_make(s)?);
    if let Some(slot) = s.ext_mut::<KeySlot>() {
        slot.0 = Some(Arc::clone(&k));
    }
    Ok(k)
}

fn load_or_make(s: &mut Session) -> Result<SealKey, String> {
    let stored = s
        .storage_mut()
        .load_state(KEY_STATE)
        .map_err(|e| format!("secret key: {e}"))?;
    if let Some(text) = stored {
        let raw = B64
            .decode(text.trim())
            .map_err(|_| format!("secret key ({KEY_STATE}) is damaged; not replaced"))?;
        let k: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| format!("secret key ({KEY_STATE}) has the wrong size; not replaced"))?;
        return Ok(SealKey::from_bytes(&k));
    }
    let mut k = [0u8; 32];
    if crate::auth::random_bytes(&mut k).is_err() {
        // wasm: nothing is stored, a key for this run.
        let seed = s.hal().now_unix().unwrap_or(0).to_le_bytes();
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed.get(i % 8).copied().unwrap_or(0) ^ (i as u8).wrapping_mul(151);
        }
        let mut key = SealKey::from_bytes(&k);
        key.ephemeral = true;
        return Ok(key);
    }
    s.storage_mut()
        .save_state(KEY_STATE, &B64.encode(k))
        .map_err(|e| format!("secret key not stored: {e}"))?;
    Ok(SealKey::from_bytes(&k))
}

/// Start-up: seal the passwords still kept in clear (configs from before
/// G4.3n) with one automatic revision. Revisions older than it keep what
/// they had until they leave the history.
pub(crate) fn seal_legacy(s: &mut Session) {
    let clear = s
        .store()
        .running()
        .ppp
        .secrets
        .iter()
        .filter(|x| !x.password.is_empty() && !x.password.is_sealed())
        .count();
    if clear == 0 || s.store().is_dirty() {
        return;
    }
    let k = match key(s) {
        Ok(k) => k,
        Err(e) => {
            log::error!("{clear} PPP password(s) stay in clear in the config: {e}");
            return;
        }
    };
    let mut cfg = s.store().running().clone();
    for x in cfg.ppp.secrets.iter_mut() {
        if x.password.is_empty() || x.password.is_sealed() {
            continue;
        }
        match k.seal(x.password.stored()) {
            Ok(b) => x.password = b,
            Err(e) => {
                log::error!("PPP passwords stay in clear in the config: {e}");
                return;
            }
        }
    }
    s.store_mut().set_candidate(cfg);
    let result = s.commit_candidate("G4.3n: PPP passwords sealed at rest").map(Some);
    if result.is_ok() {
        log::info!("sealed {clear} PPP password(s) kept in clear (from before G4.3n)");
    }
    s.record_automatic("ppp.secret.seal", "passwords kept in clear from before G4.3n", &result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_tamper() {
        let k = SealKey::from_bytes(&[7; 32]);
        let a = k.seal("s3nh4").unwrap();
        let b = k.seal("s3nh4").unwrap();
        assert!(a.is_sealed() && !a.stored().contains("s3nh4"));
        assert_ne!(a, b, "random nonce: equal passwords do not give equal boxes");
        assert_eq!(k.open(&a).as_deref(), Some("s3nh4"));
        assert_eq!(k.seal("").unwrap(), Sealed::default());
        // Another key, a flipped byte, a cut box: nothing.
        assert_eq!(SealKey::from_bytes(&[8; 32]).open(&a), None);
        let mut t = a.stored().to_owned();
        t.pop();
        t.push(if a.stored().ends_with('A') { 'B' } else { 'A' });
        assert_eq!(k.open(&Sealed::from_box(t)), None);
        assert_eq!(k.open(&Sealed::from_box(format!("{PREFIX}AAAA"))), None);
        assert_eq!(k.open(&Sealed::from_box(format!("{PREFIX}!!"))), None);
        // A legacy clear value opens as it is, with or without a key.
        assert_eq!(open_with(None, &Sealed::from("old")).as_deref(), Some("old"));
        assert_eq!(open_with(None, &a), None);
    }

    #[test]
    fn the_key_is_stored_once_and_reused() {
        let storage = crate::storage::MemoryStorage::default();
        let mut s = Session::with_storage(
            Box::new(corerouter_hal::VirtualHal::default()),
            Box::new(storage.clone()),
        );
        let k = key(&mut s).unwrap();
        let boxed = k.seal("x").unwrap();
        let mut again = Session::with_storage(
            Box::new(corerouter_hal::VirtualHal::default()),
            Box::new(storage),
        );
        assert_eq!(key(&mut again).unwrap().open(&boxed).as_deref(), Some("x"));
    }
}


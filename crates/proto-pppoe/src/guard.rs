//! Discovery defences: the AC-Cookie (RFC 2516 §9), PADI rate limits
//! (accel-ppp `padi-limit`, global and per MAC) and the seeded generator of
//! challenges, magic numbers and interface ids.
//!
//! RFC 2516 §9: "To help protect against Denial of Service (DOS) attacks,
//! the Access Concentrator can employ the AC-Cookie TAG. The Access
//! Concentrator SHOULD be able to uniquely regenerate the TAG_VALUE based on
//! the PADR SOURCE_ADDR." The AC keeps no state per PADI: the cookie binds
//! the client MAC, the port and a timestamp under a secret, so a PADR is
//! checked without memory and a cookie captured for one MAC is useless from
//! another.

use crate::eth::Vlans;
use crate::timer::Millis;
use crate::wire::Mac;
use hmac::{Hmac, KeyInit, Mac as _};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Cookie layout: key id (1), issue time in seconds (4), HMAC tag (16).
pub const COOKIE_LEN: usize = 21;

/// Two secrets: cookies issued under the previous one stay valid across a
/// rotation, for at most the cookie timeout.
pub struct CookieJar {
    keys: [[u8; 32]; 2],
    /// Index of the current key in `keys` (and the id byte it writes).
    current: u8,
    timeout_ms: u64,
}

impl CookieJar {
    pub fn new(secret: [u8; 32], timeout_ms: u64) -> CookieJar {
        CookieJar {
            keys: [secret, secret],
            current: 0,
            timeout_ms,
        }
    }

    /// Installs a new secret; the old one still verifies until its cookies
    /// time out.
    pub fn rotate(&mut self, secret: [u8; 32]) {
        let next = self.current ^ 1;
        if let Some(k) = self.keys.get_mut(usize::from(next)) {
            *k = secret;
        }
        self.current = next;
    }

    fn tag(&self, key: u8, mac: Mac, ifindex: u32, vlans: Vlans, secs: u32) -> [u8; 16] {
        let k = self
            .keys
            .get(usize::from(key & 1))
            .copied()
            .unwrap_or([0; 32]);
        let Ok(mut h) = <HmacSha256 as KeyInit>::new_from_slice(&k) else {
            return [0; 16];
        };
        h.update(&mac.0);
        h.update(&ifindex.to_be_bytes());
        h.update(&vlans.outer.to_be_bytes());
        h.update(&vlans.inner.to_be_bytes());
        h.update(&secs.to_be_bytes());
        let full: [u8; 32] = h.finalize().into_bytes().into();
        full.first_chunk::<16>().copied().unwrap_or([0; 16])
    }

    pub fn issue(&self, now: Millis, mac: Mac, ifindex: u32, vlans: Vlans) -> [u8; COOKIE_LEN] {
        let secs = (now / 1000) as u32;
        let [s0, s1, s2, s3] = secs.to_be_bytes();
        let t = self.tag(self.current, mac, ifindex, vlans, secs);
        let mut c = [0u8; COOKIE_LEN];
        for (d, s) in c
            .iter_mut()
            .zip([self.current, s0, s1, s2, s3].iter().chain(t.iter()))
        {
            *d = *s;
        }
        c
    }

    /// True when `cookie` was issued by this AC to `mac` on this port within
    /// the timeout (constant-time tag comparison).
    pub fn verify(&self, now: Millis, cookie: &[u8], mac: Mac, ifindex: u32, vlans: Vlans) -> bool {
        let Ok(c) = <&[u8; COOKIE_LEN]>::try_from(cookie) else {
            return false;
        };
        let [key, s0, s1, s2, s3, tag @ ..] = c;
        let (key, secs) = (*key, u32::from_be_bytes([*s0, *s1, *s2, *s3]));
        let issued = u64::from(secs) * 1000;
        // A cookie from the future (clock skew is impossible: we issued it)
        // or older than the timeout is refused.
        if issued > now.saturating_add(1000) || now.saturating_sub(issued) > self.timeout_ms {
            return false;
        }
        if key > 1 {
            return false;
        }
        crate::auth::ct_eq(&self.tag(key, mac, ifindex, vlans, secs), tag)
    }
}

/// A token bucket: `rate` tokens per second, at most `burst`.
#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    /// Tokens × 1000 (millitokens), to refill per millisecond exactly.
    milli: u64,
    at: Millis,
}

impl Bucket {
    fn take(&mut self, now: Millis, rate: u32, burst: u32) -> bool {
        let cap = u64::from(burst.max(1)) * 1000;
        let refill = now.saturating_sub(self.at).saturating_mul(u64::from(rate));
        self.milli = self.milli.saturating_add(refill).min(cap);
        self.at = now;
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// Slots of the per-MAC table: fixed, so a flood from random MACs costs no
/// memory (colliding MACs share a bucket, which only makes them stricter).
const MAC_SLOTS: usize = 4096;

/// PADI limits: a global bucket and one per MAC. `0` disables a limit.
pub struct PadiLimiter {
    global: Bucket,
    per_mac: Vec<(Mac, Bucket)>,
    global_rate: u32,
    mac_rate: u32,
    mac_burst: u32,
}

impl PadiLimiter {
    pub fn new(global_per_sec: u32, mac_per_sec: u32, mac_burst: u32) -> PadiLimiter {
        PadiLimiter {
            global: Bucket {
                milli: u64::from(global_per_sec) * 1000,
                at: 0,
            },
            per_mac: if mac_per_sec == 0 {
                Vec::new()
            } else {
                vec![(Mac::ZERO, Bucket::default()); MAC_SLOTS]
            },
            global_rate: global_per_sec,
            mac_rate: mac_per_sec,
            mac_burst,
        }
    }

    fn slot(mac: Mac) -> usize {
        // FNV-1a: cheap and stable; the table is a rate limit, not a map.
        let mut h: u32 = 0x811c_9dc5;
        for b in mac.0 {
            h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
        }
        (h as usize) % MAC_SLOTS
    }

    /// True when a PADI from `mac` may be answered now.
    pub fn allow(&mut self, now: Millis, mac: Mac) -> bool {
        if self.mac_rate != 0 {
            let burst = self.mac_burst.max(1);
            let Some((owner, b)) = self.per_mac.get_mut(Self::slot(mac)) else {
                return false;
            };
            if *owner != mac {
                *owner = mac;
                *b = Bucket {
                    milli: u64::from(burst) * 1000,
                    at: now,
                };
            }
            if !b.take(now, self.mac_rate, burst) {
                return false;
            }
        }
        self.global_rate == 0 || self.global.take(now, self.global_rate, self.global_rate)
    }
}

/// Hash-based generator (SHA-256 of seed ‖ counter): unpredictable without
/// the seed, deterministic with it (simulations replay exactly). The caller
/// seeds it from the OS (`getrandom`) in production.
pub struct Rng {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    used: usize,
}

impl Rng {
    pub fn new(seed: [u8; 32]) -> Rng {
        Rng {
            seed,
            counter: 0,
            buf: [0; 32],
            used: 32,
        }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            if self.used == self.buf.len() {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.counter.to_be_bytes());
                self.buf = h.finalize().into();
                self.counter = self.counter.wrapping_add(1);
                self.used = 0;
            }
            *b = self.buf.get(self.used).copied().unwrap_or(0);
            self.used += 1;
        }
    }

    pub fn u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_be_bytes(b)
    }

    /// RFC 1661 §6.4: a Magic-Number is never zero.
    pub fn nonzero_u32(&mut self) -> u32 {
        loop {
            let v = self.u32();
            if v != 0 {
                return v;
            }
        }
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = Mac([2, 0, 0, 0, 0, 1]);
    const B: Mac = Mac([2, 0, 0, 0, 0, 2]);

    #[test]
    fn rfc2516_9_cookie_binds_mac_port_and_time() {
        let j = CookieJar::new([7; 32], 5000);
        let c = j.issue(10_000, A, 3, Vlans::single(100));
        assert!(j.verify(12_000, &c, A, 3, Vlans::single(100)));
        assert!(!j.verify(12_000, &c, B, 3, Vlans::single(100)), "other MAC");
        assert!(
            !j.verify(12_000, &c, A, 4, Vlans::single(100)),
            "other port"
        );
        assert!(
            !j.verify(12_000, &c, A, 3, Vlans::single(101)),
            "other VLAN"
        );
        assert!(!j.verify(16_000, &c, A, 3, Vlans::single(100)), "expired");
        let mut bad = c;
        bad[20] ^= 1;
        assert!(!j.verify(12_000, &bad, A, 3, Vlans::single(100)), "forged");
        assert!(
            !j.verify(12_000, &c[..20], A, 3, Vlans::single(100)),
            "short"
        );
    }

    #[test]
    fn cookie_survives_one_rotation_not_two() {
        let mut j = CookieJar::new([1; 32], 60_000);
        let c = j.issue(1000, A, 1, Vlans::NONE);
        j.rotate([2; 32]);
        assert!(j.verify(2000, &c, A, 1, Vlans::NONE));
        j.rotate([3; 32]);
        assert!(!j.verify(2000, &c, A, 1, Vlans::NONE));
    }

    #[test]
    fn per_mac_limit_does_not_starve_other_macs() {
        let mut l = PadiLimiter::new(0, 1, 2);
        assert!(l.allow(0, A));
        assert!(l.allow(0, A));
        assert!(!l.allow(0, A), "burst of 2 spent");
        assert!(l.allow(0, B));
        assert!(l.allow(1000, A), "one token per second");
    }

    #[test]
    fn global_limit() {
        let mut l = PadiLimiter::new(10, 0, 0);
        let ok = (0..100u8)
            .filter(|i| l.allow(0, Mac([2, 0, 0, 0, 1, *i])))
            .count();
        assert_eq!(ok, 10);
        assert!(l.allow(100, A), "one token per 100 ms at 10/s");
    }

    #[test]
    fn rng_is_deterministic_per_seed_and_magic_is_nonzero() {
        let mut a = Rng::new([9; 32]);
        let mut b = Rng::new([9; 32]);
        let mut c = Rng::new([8; 32]);
        let x: [u8; 40] = a.array();
        assert_eq!(x, b.array::<40>());
        assert_ne!(x, c.array::<40>());
        for _ in 0..1000 {
            assert_ne!(a.nonzero_u32(), 0);
        }
    }
}

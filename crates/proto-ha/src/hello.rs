//! The access-side hello: a small authenticated Ethernet frame each node
//! sends on its access ports every hello interval. It is the second path
//! on which a node hears its peer (the first is the sync stream), and it
//! rides the same L2 the subscribers use, so "I do not hear the peer on
//! the access side" also means "the peer does not reach my subscribers".
//!
//! The active node sends it **from the virtual MAC**: every hello is also
//! the gratuitous MAC update that teaches the access switches where the
//! virtual MAC lives (VRRP does the same with its advertisements, RFC 5798
//! §7.2); a standby sends from its own MAC.
//!
//! ```text
//! dst 03:43:52:48:41:00 | src | [tags] | type 0x88b5 |
//! "CRHA" | version 1 | node id 8 | incarnation 8 | seq 8 | hears 8 |
//! view seq 8 | acked 8 | epoch 8 | role 1 | priority 1 | flags 1 |
//! reserved 1 | HMAC-SHA-256/128 16
//! ```
//!
//! 0x88b5 is IEEE 802's Local Experimental EtherType 1 (IEEE Std 802
//! §9.2.4): for a protocol inside one network, like this one. The
//! destination is a locally administered multicast, so no other protocol
//! claims it. The tag is an HMAC under a key derived from the pair's shared
//! secret; the incarnation (random per start) and `seq` (increasing) stop
//! a replayed hello from keeping a dead node "alive". `hears` names the
//! incarnation of the peer the sender hears (see `role`).

use hmac::{Hmac, KeyInit, Mac as _};
use sha2::{Digest, Sha256};

use crate::msg::Role;
use crate::role::PeerView;
use crate::wire::{Error, Reader, Result};

type HmacSha256 = Hmac<Sha256>;

pub const ETHERTYPE: u16 = 0x88b5;
/// Locally administered (bit 1) multicast (bit 0) group of the hellos.
pub const GROUP: [u8; 6] = [0x03, 0x43, 0x52, 0x48, 0x41, 0x00];
const MAGIC: [u8; 4] = *b"CRHA";
const VERSION: u8 = 1;
/// The hello after the EtherType.
pub const BODY: usize = 4 + 1 + 8 * 7 + 4 + 16;

const F_WITNESS: u8 = 1;
const F_IN_SYNC: u8 = 2;
const F_ELIGIBLE: u8 = 4;

/// A key for one purpose derived from the pair's shared secret (the hello
/// tag, the AC-Cookie the two nodes accept from each other).
pub fn derive(label: &str, secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"corerouter-ha v1 ");
    h.update(label.as_bytes());
    h.update([0]);
    h.update(secret);
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloFrame {
    /// `view.incarnation` is the sender's boot: per boot, `seq` grows.
    pub view: PeerView,
    pub seq: u64,
}

fn role_code(r: Role) -> u8 {
    match r {
        Role::Init => 0,
        Role::Standby => 1,
        Role::Active => 2,
        Role::Fenced => 3,
        Role::Yielding => 4,
    }
}

fn tag(key: &[u8; 32], body: &[u8]) -> [u8; 16] {
    let Ok(mut h) = <HmacSha256 as KeyInit>::new_from_slice(key) else {
        return [0; 16];
    };
    h.update(body);
    let full = h.finalize().into_bytes();
    let mut t = [0u8; 16];
    for (d, s) in t.iter_mut().zip(full.iter()) {
        *d = *s;
    }
    t
}

impl HelloFrame {
    /// The hello body (after the EtherType); the caller adds the Ethernet
    /// header (destination [`GROUP`], its source MAC, its tags).
    pub fn encode(&self, key: &[u8; 32], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.view.node_id.to_le_bytes());
        out.extend_from_slice(&self.view.incarnation.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.view.hears.to_le_bytes());
        out.extend_from_slice(&self.view.view_seq.to_le_bytes());
        out.extend_from_slice(&self.view.acked.to_le_bytes());
        out.extend_from_slice(&self.view.epoch.to_le_bytes());
        out.push(role_code(self.view.role));
        out.push(self.view.priority);
        let mut f = 0;
        if self.view.witness {
            f |= F_WITNESS;
        }
        if self.view.in_sync {
            f |= F_IN_SYNC;
        }
        if self.view.eligible {
            f |= F_ELIGIBLE;
        }
        out.push(f);
        out.push(0);
        let t = tag(key, out.get(start..).unwrap_or(&[]));
        out.extend_from_slice(&t);
    }

    /// A whole Ethernet frame, untagged (tests and the lab).
    pub fn frame(&self, key: &[u8; 32], src: [u8; 6]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + BODY);
        f.extend_from_slice(&GROUP);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ETHERTYPE.to_be_bytes());
        self.encode(key, &mut f);
        f
    }

    /// Checks the tag and reads the body (padding after it is ignored:
    /// Ethernet pads short frames to 60 bytes).
    pub fn decode(key: &[u8; 32], body: &[u8]) -> Result<HelloFrame> {
        let b = body.get(..BODY).ok_or(Error::Truncated {
            need: BODY.saturating_sub(body.len()),
        })?;
        let (signed, got) = b.split_at(BODY - 16);
        let want = tag(key, signed);
        // Constant time: no early exit on the first differing byte.
        let diff = want.iter().zip(got).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(Error::BadMac);
        }
        let mut r = Reader::new(signed);
        if r.array::<4>()? != MAGIC || r.u8()? != VERSION {
            return Err(Error::BadMagic);
        }
        let node_id = r.u64()?;
        let incarnation = r.u64()?;
        let seq = r.u64()?;
        let hears = r.u64()?;
        let view_seq = r.u64()?;
        let acked = r.u64()?;
        let epoch = r.u64()?;
        let role = match r.u8()? {
            0 => Role::Init,
            1 => Role::Standby,
            2 => Role::Active,
            3 => Role::Fenced,
            4 => Role::Yielding,
            _ => return Err(Error::BadValue("role")),
        };
        let priority = r.u8()?;
        let f = r.u8()?;
        Ok(HelloFrame {
            view: PeerView {
                node_id,
                incarnation,
                hears,
                view_seq,
                acked,
                epoch,
                role,
                priority,
                witness: f & F_WITNESS != 0,
                in_sync: f & F_IN_SYNC != 0,
                eligible: f & F_ELIGIBLE != 0,
            },
            seq,
        })
    }
}

/// Refuses a replayed hello: per boot the sequence only grows, and a boot
/// id seen before the current one is never accepted again.
#[derive(Debug, Default, Clone)]
pub struct ReplayGuard {
    current: Option<(u64, u64)>,
    old: Vec<u64>,
}

impl ReplayGuard {
    pub fn check(&mut self, h: &HelloFrame) -> Result<()> {
        let b = h.view.incarnation;
        match self.current {
            Some((boot, seq)) if boot == b => {
                if h.seq <= seq {
                    return Err(Error::Replay);
                }
            }
            Some((boot, _)) => {
                if self.old.contains(&b) {
                    return Err(Error::Replay);
                }
                if self.old.len() >= 8 {
                    self.old.remove(0);
                }
                self.old.push(boot);
            }
            None => {}
        }
        self.current = Some((b, h.seq));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(seq: u64) -> HelloFrame {
        HelloFrame {
            view: PeerView {
                node_id: 7,
                incarnation: 42,
                hears: 9,
                view_seq: 5,
                acked: 4,
                epoch: 3,
                role: Role::Active,
                priority: 150,
                witness: true,
                in_sync: false,
                eligible: true,
            },
            seq,
        }
    }

    #[test]
    fn a_hello_round_trips_and_a_flipped_bit_fails_the_tag() {
        let key = derive("hello", b"segredo-compartilhado");
        let f = hello(1).frame(&key, [2, 0, 0x5e, 0, 1, 1]);
        assert_eq!(f.len(), 14 + BODY);
        let mut padded = f[14..].to_vec();
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(HelloFrame::decode(&key, &padded).unwrap(), hello(1));
        for i in 14..f.len() {
            let mut bad = f.clone();
            bad[i] ^= 1;
            assert!(HelloFrame::decode(&key, &bad[14..]).is_err(), "byte {i}");
        }
        let other = derive("hello", b"outro");
        assert_eq!(HelloFrame::decode(&other, &f[14..]), Err(Error::BadMac));
        assert!(HelloFrame::decode(&key, &f[14..30]).is_err());
        assert_ne!(derive("hello", b"x"), derive("cookie", b"x"));
    }

    #[test]
    fn replays_are_refused() {
        let mut g = ReplayGuard::default();
        g.check(&hello(5)).unwrap();
        assert_eq!(g.check(&hello(5)), Err(Error::Replay));
        assert_eq!(g.check(&hello(4)), Err(Error::Replay));
        g.check(&hello(6)).unwrap();
        let mut reboot = hello(1);
        reboot.view.incarnation = 99;
        g.check(&reboot).unwrap();
        assert_eq!(
            g.check(&hello(100)),
            Err(Error::Replay),
            "the old boot is gone"
        );
    }
}

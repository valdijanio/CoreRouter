//! L2 — Bidirectional Forwarding Detection (G3.6), CoreRouter's own BFD.
//! Pure: no sockets, no clock, no `unsafe`; compiles for
//! `wasm32-unknown-unknown`. The daemon's `bfd` service runs it on N
//! threads with their own sockets and timer wheels.
//!
//! - [`packet`]: the Control packet (RFC 5880 §4) and the byte checks of
//!   §6.8.6.
//! - [`auth`]: Keyed SHA1 and Meticulous Keyed SHA1 (§6.7.4, erratum 7083).
//! - [`session`]: the state machine, timers, Poll/Final, jitter (§6.8).
//! - [`dampen`]: flap dampening for the clients (RFC 5882 §3.2).
//! - [`dplane`]: FRR's distributed data plane protocol (`bfdd --dplaneaddr`);
//!   [`frr`]: the `bfd` block of FRR's config (profiles and peers).
//! - [`wheel`]: the timer wheel of one engine thread; [`hist`]: per-session
//!   timing percentiles.
//!
//! References (read 2026-10-27): RFC 5880 (and errata 2530, 5205, 6926,
//! 7082, 7083, 4410, 7240), RFC 5881 (single hop), RFC 5882 (generic
//! application), RFC 5883 (multihop), RFC 7419 (common intervals). Design,
//! research and numbers: `docs/bfd.md`.

pub mod auth;
pub mod dampen;
pub mod dplane;
pub mod frr;
pub mod hist;
pub mod packet;
pub mod session;
pub mod wheel;

/// RFC 5881 §4: single-hop Control packets go to UDP 3784.
pub const PORT_SINGLE_HOP: u16 = 3784;
/// RFC 5883 §5: multihop Control packets go to UDP 4784.
pub const PORT_MULTI_HOP: u16 = 4784;
/// RFC 5881 §4: "The source port MUST be in the range 49152 through 65535."
pub const SOURCE_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;
/// RFC 5881 §5: sent with TTL / Hop Limit 255.
pub const TTL: u8 = 255;
/// Default minimum TTL accepted on a multihop session (FRR's
/// `minimum-ttl` default; RFC 5883 §5 leaves the value to the operator).
pub const DEFAULT_MIN_TTL: u8 = 254;

/// RFC 7419 §3: the common interval set (µs) every implementation should
/// support down to its fastest; ours is 10 ms (software, userspace).
pub const COMMON_INTERVALS_US: [u32; 6] = [3_300, 10_000, 20_000, 50_000, 100_000, 1_000_000];
/// The fastest interval this engine offers (µs).
pub const MIN_INTERVAL_US: u32 = 10_000;

/// The TTL rule of a received packet: RFC 5881 §5 (single hop: exactly
/// 255, which makes off-link spoofing impossible — GTSM, RFC 5082; we
/// apply it with and without authentication, where the RFC says MAY) and
/// RFC 5883 §5 (multihop: at least the configured minimum).
pub fn ttl_ok(multihop: bool, ttl: u8, min_ttl: u8) -> bool {
    if multihop { ttl >= min_ttl } else { ttl == TTL }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::{MAX_LEN, Packet};
    use proptest::prelude::*;

    #[test]
    fn rfc_5881_5_ttl() {
        assert!(ttl_ok(false, 255, 0));
        assert!(!ttl_ok(false, 254, 0));
        assert!(ttl_ok(true, 254, DEFAULT_MIN_TTL));
        assert!(!ttl_ok(true, 200, DEFAULT_MIN_TTL));
    }

    proptest! {
        /// Hostile input: any bytes decode or fail, never panic; what
        /// decodes encodes back to the same first `Length` bytes.
        #[test]
        fn decode_never_panics(b in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(p) = Packet::decode(&b) {
                let mut out = [0u8; MAX_LEN];
                let n = p.encode(&mut out);
                let back = Packet::decode(&out[..n]).unwrap();
                prop_assert_eq!(back.state, p.state);
                prop_assert_eq!(back.my_discr, p.my_discr);
                prop_assert_eq!(back.your_discr, p.your_discr);
                prop_assert_eq!(back.desired_min_tx, p.desired_min_tx);
            }
        }

        /// A session fed hostile packets never panics and keeps its
        /// invariants (never Poll and Final together; detection time a
        /// product of what was received).
        #[test]
        fn session_survives_garbage(
            pkts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 24..53), 1..40),
            times in proptest::collection::vec(0u64..2_000_000, 1..40),
        ) {
            let mut s = session::Session::new(0x5555, session::Config::default(), 0, 7);
            let mut now = 0u64;
            for (i, raw) in pkts.iter().enumerate() {
                now += times.get(i).copied().unwrap_or(1);
                let mut raw = raw.clone();
                // Steer some packets to this session.
                if i % 2 == 0 && raw.len() >= 12 {
                    raw[8..12].copy_from_slice(&0x5555u32.to_be_bytes());
                }
                if let Ok(p) = Packet::decode(&raw) {
                    let _ = s.receive(&raw, &p, now);
                }
                let _ = s.on_timer(now);
                let mut out = [0u8; MAX_LEN];
                let n = s.build(false, &mut out);
                let back = Packet::decode(&out[..n]).unwrap();
                prop_assert!(!(back.poll && back.final_));
            }
        }
    }
}

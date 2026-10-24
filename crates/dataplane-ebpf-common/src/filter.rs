// SPDX-License-Identifier: GPL-2.0-or-later
//! The G2.5a filter decision: what happens to a frame before the kernel
//! sees it. In order:
//!
//! 1. not IP (ARP, LLDP, MPLS…): pass;
//! 2. malformed headers: drop if `drop_malformed` (reason `malformed`);
//!    invalid TCP flags: drop if `drop_bad_tcp_flags` (reason `tcp-flags`);
//! 3. source in an allow list: pass (neither block lists nor the rate
//!    limit apply: the operator's own peers and management hosts);
//! 4. source in a block list: drop (reason `blocked`);
//! 5. rate limit on: one token from the source's bucket, or drop (reason
//!    `rate-limit`);
//! 6. pass.

use crate::bucket;
use crate::packet::Packet;
use crate::parse::{self, Addr, IpInfo, Malformed, Parsed};

/// Why a frame passed or was dropped: the counter it adds to. The order
/// is the map layout (`maps::counter_key`); new reasons go at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Reason {
    Pass = 0,
    Blocked = 1,
    RateLimited = 2,
    Malformed = 3,
    BadTcpFlags = 4,
    /// Translated and forwarded by the CGNAT fast path (G2.5b).
    FastNat = 5,
}

impl Reason {
    pub const ALL: [Reason; 6] = [
        Reason::Pass,
        Reason::Blocked,
        Reason::RateLimited,
        Reason::Malformed,
        Reason::BadTcpFlags,
        Reason::FastNat,
    ];

    /// Stable name (commands, metrics).
    pub fn name(self) -> &'static str {
        match self {
            Reason::Pass => "pass",
            Reason::Blocked => "blocked",
            Reason::RateLimited => "rate-limit",
            Reason::Malformed => "malformed",
            Reason::BadTcpFlags => "tcp-flags",
            Reason::FastNat => "fast-nat",
        }
    }

    pub fn from_u8(v: u8) -> Option<Reason> {
        Reason::ALL.into_iter().find(|r| *r as u8 == v)
    }
}

/// What the filter does, as the loader writes it to the settings map
/// ([`Settings::to_words`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    pub drop_malformed: bool,
    pub drop_bad_tcp_flags: bool,
    /// Look sources up in the block lists.
    pub block: bool,
    /// Look sources up in the allow lists.
    pub allow: bool,
    /// Packets per second per source; 0 = no limit.
    pub rate_pps: u64,
    /// Packets a source may send at once above the rate.
    pub burst: u64,
    /// Translate and forward the flows of `NAT_FLOWS` here (G2.5b).
    pub fast_nat: bool,
}

const F_MALFORMED: u64 = 1;
const F_TCP_FLAGS: u64 = 1 << 1;
const F_BLOCK: u64 = 1 << 2;
const F_ALLOW: u64 = 1 << 3;
const F_FAST_NAT: u64 = 1 << 4;

/// Words of the settings map: flags, rate, burst.
pub const SETTINGS_WORDS: usize = 3;

impl Settings {
    pub fn to_words(&self) -> [u64; SETTINGS_WORDS] {
        let mut flags = 0;
        for (on, bit) in [
            (self.drop_malformed, F_MALFORMED),
            (self.drop_bad_tcp_flags, F_TCP_FLAGS),
            (self.block, F_BLOCK),
            (self.allow, F_ALLOW),
            (self.fast_nat, F_FAST_NAT),
        ] {
            if on {
                flags |= bit;
            }
        }
        [flags, self.rate_pps, self.burst]
    }

    pub fn from_words([flags, rate_pps, burst]: [u64; SETTINGS_WORDS]) -> Self {
        Self {
            drop_malformed: flags & F_MALFORMED != 0,
            drop_bad_tcp_flags: flags & F_TCP_FLAGS != 0,
            block: flags & F_BLOCK != 0,
            allow: flags & F_ALLOW != 0,
            fast_nat: flags & F_FAST_NAT != 0,
            rate_pps,
            burst,
        }
    }
}

/// The state the decision consults: maps in the kernel, collections in
/// the tests.
pub trait Lookups {
    /// The block list (index) whose longest prefix holds `src`.
    fn blocked(&self, src: &Addr) -> Option<u32>;
    /// Whether an allow list holds `src`.
    fn allowed(&self, src: &Addr) -> bool;
    /// `src`'s bucket, if it has one.
    fn bucket(&mut self, src: &Addr) -> Option<&mut bucket::Bucket>;
    /// Give `src` a bucket (the map may evict the least recently used).
    fn new_bucket(&mut self, src: &Addr, b: bucket::Bucket);
}

/// What to do with a frame, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub drop: bool,
    pub reason: Reason,
    /// The source, when the headers gave one (top-sources table).
    pub src: Option<Addr>,
    /// The block list that matched (index), for `Reason::Blocked`.
    pub list: Option<u32>,
    /// A clean IP packet that passed: what the CGNAT fast path looks at
    /// (G2.5b). `None` when dropped, not IP or malformed.
    pub ip: Option<IpInfo>,
}

impl Verdict {
    fn pass(src: Option<Addr>) -> Self {
        Self {
            drop: false,
            reason: Reason::Pass,
            src,
            list: None,
            ip: None,
        }
    }

    fn drop(reason: Reason, src: Option<Addr>) -> Self {
        Self {
            drop: true,
            reason,
            src,
            list: None,
            ip: None,
        }
    }
}

/// Decide the fate of frame `p` at `now_ns` (a monotonic clock).
pub fn decide<P: Packet + ?Sized, L: Lookups>(
    p: &P,
    s: &Settings,
    l: &mut L,
    now_ns: u64,
) -> Verdict {
    let info = match parse::parse(p) {
        Parsed::NotIp => return Verdict::pass(None),
        Parsed::Bad(_) if s.drop_malformed => return Verdict::drop(Reason::Malformed, None),
        Parsed::Bad(_) => return Verdict::pass(None),
        Parsed::Ip(info) => info,
    };
    let src = info.src;
    match info.malformed {
        Some(Malformed::BadTcpFlags) if s.drop_bad_tcp_flags => {
            return Verdict::drop(Reason::BadTcpFlags, Some(src));
        }
        Some(Malformed::BadTcpFlags) | None => {}
        Some(_) if s.drop_malformed => return Verdict::drop(Reason::Malformed, Some(src)),
        Some(_) => {}
    }
    let clean = (info.malformed.is_none()).then_some(info);
    if s.allow && l.allowed(&src) {
        return Verdict {
            ip: clean,
            ..Verdict::pass(Some(src))
        };
    }
    if s.block
        && let Some(list) = l.blocked(&src)
    {
        return Verdict {
            list: Some(list),
            ..Verdict::drop(Reason::Blocked, Some(src))
        };
    }
    if s.rate_pps > 0 {
        match l.bucket(&src) {
            Some(b) => {
                if !bucket::take(b, now_ns, s.rate_pps, s.burst) {
                    return Verdict::drop(Reason::RateLimited, Some(src));
                }
            }
            None => l.new_bucket(&src, bucket::fresh(now_ns, s.burst)),
        }
    }
    Verdict {
        ip: clean,
        ..Verdict::pass(Some(src))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let s = Settings {
            drop_malformed: true,
            drop_bad_tcp_flags: false,
            block: true,
            allow: true,
            rate_pps: 1000,
            burst: 50,
            fast_nat: true,
        };
        assert_eq!(Settings::from_words(s.to_words()), s);
        assert_eq!(Settings::from_words([0; 3]), Settings::default());
    }

    #[test]
    fn reasons_have_stable_codes() {
        for r in Reason::ALL {
            assert_eq!(Reason::from_u8(r as u8), Some(r));
        }
        assert_eq!(Reason::from_u8(200), None);
    }
}

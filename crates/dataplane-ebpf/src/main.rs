// SPDX-License-Identifier: GPL-2.0-or-later
//! CoreRouter's XDP filter (G2.5a): runs in the NIC driver (native mode) or
//! right after it (generic mode), before the kernel allocates anything for
//! the packet. The decision is `corerouter_dataplane_ebpf_common::filter::decide`,
//! the same function the host tests run; this file only backs it with maps
//! and counts the outcome.
//!
//! `unsafe` is allowed in this crate only (AGENTS.md), and every block says
//! why it holds in a `SAFETY:` comment. Each one needs a human review.

#![no_std]
#![no_main]

use aya_ebpf::bindings::{BPF_ANY, BPF_NOEXIST, xdp_action};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuHashMap};
use aya_ebpf::programs::XdpContext;
use corerouter_dataplane_ebpf_common::bucket::Bucket;
use corerouter_dataplane_ebpf_common::filter::{self, Lookups, SETTINGS_WORDS, Settings, Verdict};
use corerouter_dataplane_ebpf_common::maps::{self as m, Counter, Top};
use corerouter_dataplane_ebpf_common::packet::Packet;
use corerouter_dataplane_ebpf_common::parse::Addr;

#[map(name = "SETTINGS")]
static SETTINGS: Array<u64> = Array::with_max_entries(m::SETTINGS_SLOTS, 0);
#[map(name = "BLOCK_V4")]
static BLOCK_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(m::PREFIXES_V4, 0);
#[map(name = "BLOCK_V6")]
static BLOCK_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(m::PREFIXES_V6, 0);
#[map(name = "ALLOW_V4")]
static ALLOW_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(m::PREFIXES_V4, 0);
#[map(name = "ALLOW_V6")]
static ALLOW_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(m::PREFIXES_V6, 0);
#[map(name = "RATE")]
static RATE: LruHashMap<[u8; 16], Bucket> = LruHashMap::with_max_entries(m::RATE_SOURCES, 0);
#[map(name = "COUNTERS")]
static COUNTERS: PerCpuHashMap<u64, Counter> =
    PerCpuHashMap::with_max_entries(m::COUNTER_ENTRIES, 0);
#[map(name = "TOP")]
static TOP: LruPerCpuHashMap<[u8; 16], Top> =
    LruPerCpuHashMap::with_max_entries(m::TOP_SOURCES, 0);

/// The frame between `data` and `data_end`.
struct Frame<'a>(&'a XdpContext);

impl Packet for Frame<'_> {
    #[inline(always)]
    fn len(&self) -> usize {
        self.0.data_end() - self.0.data()
    }

    #[inline(always)]
    fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let start = self.0.data();
        let end = self.0.data_end();
        if start + off + N > end {
            return None;
        }
        // SAFETY: `start + off .. start + off + N` lies inside the packet
        // (checked against `data_end` just above, which is also the check
        // the verifier needs before it allows the load). `[u8; N]` has no
        // invalid bit patterns and `read_unaligned` needs no alignment.
        Some(unsafe { core::ptr::read_unaligned((start + off) as *const [u8; N]) })
    }
}

/// The maps behind `filter::Lookups`.
struct Maps;

impl Lookups for Maps {
    #[inline(always)]
    fn blocked(&self, src: &Addr) -> Option<u32> {
        match *src {
            Addr::V4(a) => BLOCK_V4.get(Key::new(32, a)).copied(),
            Addr::V6(a) => BLOCK_V6.get(Key::new(128, a)).copied(),
        }
    }

    #[inline(always)]
    fn allowed(&self, src: &Addr) -> bool {
        match *src {
            Addr::V4(a) => ALLOW_V4.get(Key::new(32, a)).is_some(),
            Addr::V6(a) => ALLOW_V6.get(Key::new(128, a)).is_some(),
        }
    }

    #[inline(always)]
    fn bucket(&mut self, src: &Addr) -> Option<&mut Bucket> {
        let p = RATE.get_ptr_mut(src.mapped())?;
        // SAFETY: the kernel returned a pointer to this element's value,
        // valid and aligned for `Bucket` for the rest of the program run
        // (RCU keeps it alive even if another CPU evicts the entry). Two
        // CPUs may update the same source's bucket at once: the bucket is
        // plain integers, so a race loses or adds a token, never memory
        // safety (the rate limit is approximate under that race).
        Some(unsafe { &mut *p })
    }

    #[inline(always)]
    fn new_bucket(&mut self, src: &Addr, b: Bucket) {
        // Full map: the LRU evicts; a failed insert only means this source
        // starts over next time.
        let _ = RATE.insert(src.mapped(), b, u64::from(BPF_ANY));
    }
}

#[inline(always)]
fn settings() -> Settings {
    let mut w = [0u64; SETTINGS_WORDS];
    let mut i = 0;
    while i < SETTINGS_WORDS {
        if let (Some(slot), Some(v)) = (w.get_mut(i), SETTINGS.get(i as u32)) {
            *slot = *v;
        }
        i += 1;
    }
    Settings::from_words(w)
}

/// Add one packet of `len` bytes to this interface's counter for the
/// verdict's reason.
#[inline(always)]
fn count(ifindex: u32, v: &Verdict, len: u64) {
    let key = m::counter_key(ifindex, v.reason);
    match COUNTERS.get_ptr_mut(key) {
        Some(c) => {
            // SAFETY: a per-CPU map value: this CPU's copy, which only
            // this program run touches (XDP runs with preemption off), so
            // the plain read-modify-write is not racy. The pointer comes
            // from the kernel, valid and aligned for `Counter`.
            unsafe {
                (*c)[0] += 1;
                (*c)[1] += len;
            }
        }
        None => {
            let _ = COUNTERS.insert(key, [1, len], u64::from(BPF_NOEXIST));
        }
    }
}

/// Remember a dropped source for the top-sources table.
#[inline(always)]
fn top(src: &Addr, v: &Verdict, len: u64, now: u64) {
    let key = src.mapped();
    let tag = m::top_tag(v.reason, v.list);
    match TOP.get_ptr_mut(key) {
        Some(t) => {
            // SAFETY: a per-CPU map value: this CPU's copy of the
            // element, which only this program run touches (XDP runs with
            // preemption off). The pointer comes from the kernel, valid and
            // aligned for `Top`; the loader sums the CPUs' copies.
            unsafe {
                (*t)[0] += 1;
                (*t)[1] += len;
                (*t)[2] = now;
                (*t)[3] = tag;
            }
        }
        None => {
            let _ = TOP.insert(key, [1, len, now, tag], u64::from(BPF_ANY));
        }
    }
}

#[xdp]
pub fn corerouter_xdp(ctx: XdpContext) -> u32 {
    let frame = Frame(&ctx);
    let len = frame.len() as u64;
    let s = settings();
    // SAFETY: a BPF helper with no arguments and no preconditions
    // (CLOCK_MONOTONIC in nanoseconds).
    let now = unsafe { bpf_ktime_get_ns() };
    let v = filter::decide(&frame, &s, &mut Maps, now);
    count(ctx.ingress_ifindex() as u32, &v, len);
    if !v.drop {
        return xdp_action::XDP_PASS;
    }
    if let Some(src) = &v.src {
        top(src, &v, len, now);
    }
    xdp_action::XDP_DROP
}

/// Kernel-side license string. This crate is GPL-2.0-or-later (the rest of
/// CoreRouter is AGPL-3.0-or-later, which GPL-2.0-or-later combines with):
/// the kernel lets only a GPL-compatible program call GPL-only helpers, and
/// the CGNAT fast path forwards with `bpf_fib_lookup`, one of them.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Unreachable in a verified program: the common code has no panic
    // path, and a program that called this would not pass the verifier.
    loop {}
}

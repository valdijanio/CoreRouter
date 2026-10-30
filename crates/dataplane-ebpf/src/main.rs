// SPDX-License-Identifier: GPL-2.0-or-later
//! CoreRouter's XDP program: runs in the NIC driver (native mode) or right
//! after it (generic mode), before the kernel allocates anything for the
//! packet. In order:
//!
//! 1. PPPoE subscribers (G4.3c), when on: session frames are checked,
//!    policed and decapsulated (`pppoe::upstream`, `pppoe::decap`); control
//!    frames pass to the daemon untouched. IPoE subscribers (G4.3f), when
//!    on: the IP↔MAC binding and the policer (`ipoe::upstream`), nothing
//!    to strip;
//! 2. the filter (G2.5a, `filter::decide`);
//! 3. the CGNAT fast path (G2.5b, `fastnat`);
//! 4. PPPoE again: a packet to a subscriber is encapsulated and sent out of
//!    its access port (`pppoe::downstream`, `pppoe::encap`); one from a
//!    subscriber goes out where the FIB says, or to the kernel.
//!
//! The same object holds the tc programs of the shaper (G4.9b) and of
//! `bng0` (G4.3ca), at the end of this file: they share the session maps.
//!
//! The decisions are the common crate's functions, the same the host tests
//! run; this file only backs them with maps and counts the outcome.
//!
//! `unsafe` is allowed in this crate only (AGENTS.md), and every block says
//! why it holds in a `SAFETY:` comment. Each one needs a human review.

#![no_std]
#![no_main]
// `atomic_xadd`: the BPF target has no `AtomicU64::fetch_add` in core, but
// LLVM lowers the intrinsic to a BPF atomic add (the per-session counters
// every CPU adds to).
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::bindings::{
    BPF_ANY, BPF_FIB_LKUP_RET_SUCCESS, BPF_NOEXIST, TC_ACT_OK, TC_ACT_SHOT, bpf_fib_lookup as FibParams,
    bpf_fib_lookup__bindgen_ty_1, bpf_fib_lookup__bindgen_ty_2, bpf_fib_lookup__bindgen_ty_3,
    bpf_fib_lookup__bindgen_ty_4, bpf_fib_lookup__bindgen_ty_5, xdp_action,
};
use aya_ebpf::helpers::{
    bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect, bpf_skb_change_head, bpf_skb_set_tstamp,
    bpf_xdp_adjust_head,
};
use aya_ebpf::macros::{classifier, map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{
    Array, HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, PerCpuHashMap, RingBuf,
};
use aya_ebpf::programs::{TcContext, XdpContext};
use core::intrinsics::AtomicOrdering;
use corerouter_dataplane_ebpf_common::bucket::Bucket;
use corerouter_dataplane_ebpf_common::fastnat::{self, FlowKey, FlowValue};
use corerouter_dataplane_ebpf_common::nat::PacketMut;
use corerouter_dataplane_ebpf_common::filter::{self, Lookups, SETTINGS_WORDS, Settings, Verdict};
use corerouter_dataplane_ebpf_common::maps::{self as m, Counter, Top};
use corerouter_dataplane_ebpf_common::packet::Packet;
use corerouter_dataplane_ebpf_common::parse::{Addr, ETH_HLEN, IpInfo};
use corerouter_dataplane_ebpf_common::ipoe;
use corerouter_dataplane_ebpf_common::lsp_tap::{self, Keep};
use corerouter_dataplane_ebpf_common::policer;
use corerouter_dataplane_ebpf_common::queue;
use corerouter_dataplane_ebpf_common::shaper;
use corerouter_dataplane_ebpf_common::words::Words;
use corerouter_dataplane_ebpf_common::pppoe::{
    self, Counters, DownKind, DownSession, KEY_LEN, PacketHead, SessionWords, Sessions, Stat, Up,
};

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
#[map(name = "NAT_FLOWS")]
static NAT_FLOWS: LruHashMap<FlowKey, FlowValue> =
    LruHashMap::with_max_entries(m::NAT_FLOWS_MAX, 0);
#[map(name = "NAT_MISS")]
static NAT_MISS: PerCpuArray<u64> = PerCpuArray::with_max_entries(fastnat::MISS_SLOTS, 0);
#[map(name = "TOP")]
static TOP: LruPerCpuHashMap<[u8; 16], Top> =
    LruPerCpuHashMap::with_max_entries(m::TOP_SOURCES, 0);
#[map(name = "PPPOE_KEYS")]
static PPPOE_KEYS: HashMap<[u8; KEY_LEN], u32> =
    HashMap::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "PPPOE_SESSIONS")]
static PPPOE_SESSIONS: Array<SessionWords> = Array::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "PPPOE_V4")]
static PPPOE_V4: HashMap<[u8; 4], u32> = HashMap::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "PPPOE_V6")]
static PPPOE_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(pppoe::PREFIXES_V6, 0);
#[map(name = "PPPOE_RT4")]
static PPPOE_RT4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(pppoe::ROUTES_V4, 0);
#[map(name = "PPPOE_RT6")]
static PPPOE_RT6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(pppoe::ROUTES_V6, 0);
#[map(name = "PPPOE_POLICER")]
static PPPOE_POLICER: Array<policer::State> =
    Array::with_max_entries(pppoe::SESSIONS_MAX * 2, 0);
#[map(name = "PPPOE_COUNTERS")]
static PPPOE_COUNTERS: Array<Counters> = Array::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "PPPOE_STATS")]
static PPPOE_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(Stat::SLOTS, 0);
#[map(name = "IPOE_PORTS")]
static IPOE_PORTS: HashMap<u32, u32> = HashMap::with_max_entries(ipoe::PORTS_MAX, 0);

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

impl PacketMut for Frame<'_> {
    #[inline(always)]
    fn store<const N: usize>(&mut self, off: usize, bytes: [u8; N]) -> Option<()> {
        let start = self.0.data();
        let end = self.0.data_end();
        if start + off + N > end {
            return None;
        }
        // SAFETY: `start + off .. start + off + N` lies inside the packet
        // (checked against `data_end` just above, as the verifier wants
        // before a store). XDP packet data is writable, and
        // `write_unaligned` needs no alignment.
        unsafe { core::ptr::write_unaligned((start + off) as *mut [u8; N], bytes) };
        Some(())
    }
}

impl PacketHead for Frame<'_> {
    #[inline(always)]
    fn adjust_head(&mut self, delta: i32) -> Option<()> {
        // SAFETY: a BPF helper on this program's own context; it moves
        // `data` within the headroom/frame or fails (non-zero) and changes
        // nothing. Every later load re-reads `data` and `data_end` from the
        // context (`Frame::bytes`), so no pointer from before survives.
        let rc = unsafe { bpf_xdp_adjust_head(self.0.ctx, delta) };
        (rc == 0).then_some(())
    }
}

/// The PPPoE session maps behind `pppoe::Sessions`.
struct Subs;

impl Sessions for Subs {
    #[inline(always)]
    fn by_key(&self, key: &[u8; KEY_LEN]) -> Option<u32> {
        let p = PPPOE_KEYS.get_ptr(key)?;
        // SAFETY: the kernel returned a pointer to this element's value
        // (a `u32`, valid and aligned for the rest of the run under RCU);
        // the daemon replaces it whole, a plain word read cannot tear.
        Some(unsafe { *p })
    }

    #[inline(always)]
    fn session(&self, idx: u32) -> Option<&SessionWords> {
        PPPOE_SESSIONS.get(idx)
    }

    #[inline(always)]
    fn by_v4(&self, dst: [u8; 4]) -> Option<u32> {
        let p = PPPOE_V4.get_ptr(dst)?;
        // SAFETY: as in `by_key`: a kernel pointer to a `u32` value.
        Some(unsafe { *p })
    }

    #[inline(always)]
    fn by_v6(&self, dst: [u8; 16]) -> Option<u32> {
        PPPOE_V6.get(Key::new(128, dst)).copied()
    }

    type Policer<'a> = Atomic<{ policer::STATE_WORDS }>;

    /// The element's words through BPF atomics (G4.3cc): every CPU may
    /// police one subscriber at once and the rate stays exact.
    #[inline(always)]
    fn policer(&mut self, idx: u32, dir: u32) -> Atomic<{ policer::STATE_WORDS }> {
        // The pointer is null when there is no element (`present()`).
        Atomic(
            PPPOE_POLICER
                .get_ptr_mut(idx.wrapping_mul(2).wrapping_add(dir & 1))
                .unwrap_or(core::ptr::null_mut()),
        )
    }

    #[inline(always)]
    fn by_route_v4(&self, dst: [u8; 4]) -> Option<u32> {
        PPPOE_RT4.get(Key::new(32, dst)).copied()
    }

    #[inline(always)]
    fn by_route_v6(&self, dst: [u8; 16]) -> Option<u32> {
        PPPOE_RT6.get(Key::new(128, dst)).copied()
    }

    #[inline(always)]
    fn ipoe_port(&self, ifindex: u32) -> bool {
        IPOE_PORTS.get_ptr(&ifindex).is_some()
    }
}

/// One more `what` in the global PPPoE statistics (this CPU's copy).
#[inline(always)]
fn stat(what: Stat) {
    if let Some(c) = PPPOE_STATS.get_ptr_mut(what as u32) {
        // SAFETY: this CPU's copy of a per-CPU array element (XDP runs
        // with preemption off: no other writer); valid and aligned `u64`.
        unsafe { *c += 1 };
    }
}

/// Add `n` to counter `field` of session `idx`.
#[inline(always)]
fn sess_add(idx: u32, field: usize, n: u64) {
    let Some(c) = PPPOE_COUNTERS.get_ptr_mut(idx) else {
        return;
    };
    let field = field & (pppoe::COUNTER_WORDS - 1);
    // SAFETY: the kernel's pointer to this array element, valid and aligned
    // for `Counters` (never freed); `field` is masked into it. Every CPU
    // may add to one session at once, so the add is atomic (BPF_ATOMIC
    // add, no fetch): the counters are exact.
    unsafe {
        let word = (c as *mut u64).add(field);
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::Relaxed }>(
            word, n,
        );
    }
}

/// A packet to subscriber session `d`: encapsulate it and send it out of
/// the access port.
#[inline(always)]
fn encap_out(frame: &mut Frame, d: &DownSession) -> u32 {
    if pppoe::encap(frame, d).is_none() {
        stat(Stat::Malformed);
        return xdp_action::XDP_DROP;
    }
    sent(d)
}

/// An encapsulated packet out of the access port, counted.
#[inline(always)]
fn sent(d: &DownSession) -> u32 {
    stat(Stat::DownFast);
    sess_add(d.idx, pppoe::C_DOWN_PACKETS, 1);
    sess_add(d.idx, pppoe::C_DOWN_BYTES, u64::from(d.ip_len));
    // SAFETY: a BPF helper taking the access port's index from the
    // session map and no flags; it only records where the packet goes.
    unsafe { bpf_redirect(d.ifindex, 0) as u32 }
}

/// Counted a downstream verdict that does not encapsulate; the action.
#[inline(always)]
fn down_other(d: &pppoe::Verdict) -> Option<u32> {
    match d.kind {
        DownKind::NotSub | DownKind::Encap => None,
        DownKind::Counted => {
            stat(d.stat);
            sess_add(d.idx, pppoe::C_DOWN_PACKETS, 1);
            sess_add(d.idx, pppoe::C_DOWN_BYTES, u64::from(d.ip_len));
            Some(xdp_action::XDP_PASS)
        }
        DownKind::Kernel => {
            stat(d.stat);
            sess_add(d.idx, pppoe::C_KERNEL, 1);
            Some(xdp_action::XDP_PASS)
        }
        DownKind::Drop => {
            stat(d.stat);
            sess_add(d.idx, pppoe::C_DOWN_POLICED, 1);
            Some(xdp_action::XDP_DROP)
        }
    }
}

/// A clean IP packet to a subscriber (its address, its prefixes or a block
/// routed to it; untagged or from an uplink with one or two VLAN tags):
/// encapsulated and redirected, or to the kernel. `None`: not to a
/// subscriber.
#[inline(always)]
fn to_subscriber(frame: &mut Frame, now: u64) -> Option<u32> {
    let d = pppoe::to_subscriber(frame, &mut Subs, now)?;
    if d.routed {
        stat(Stat::DownRouted);
    }
    let v = &d.verdict;
    match v.kind {
        DownKind::Encap => {
            if d.tagged {
                stat(Stat::DownTagged);
            }
            Some(sent(&v.session))
        }
        DownKind::Drop if v.stat == Stat::Malformed => {
            stat(Stat::Malformed);
            Some(xdp_action::XDP_DROP)
        }
        _ => down_other(v),
    }
}

/// A subscriber's decapsulated packet, forwarded where the FIB says
/// (TTL/hop limit minus one, new MACs). `None`: the kernel must do it.
#[inline(always)]
fn forward(ctx: &XdpContext, frame: &mut Frame, v6: bool) -> Option<u32> {
    let (ip_len, ttl) = pppoe::ip_meta(frame, v6)?;
    if ttl <= 1 {
        return None;
    }
    let mut fib = FibParams {
        family: if v6 { 10 } else { 2 }, // AF_INET6, AF_INET
        l4_protocol: 0,
        sport: 0,
        dport: 0,
        __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 { tot_len: ip_len },
        ifindex: ctx.ingress_ifindex() as u32,
        __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2 { tos: 0 },
        __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3 { ipv6_src: [0; 4] },
        __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4 { ipv6_dst: [0; 4] },
        __bindgen_anon_5: bpf_fib_lookup__bindgen_ty_5 { tbid: 0 },
        smac: [0; 6],
        dmac: [0; 6],
    };
    if v6 {
        let [s0, s1, s2, s3] = words(frame.bytes::<16>(ETH_HLEN + 8)?);
        let [d0, d1, d2, d3] = words(frame.bytes::<16>(ETH_HLEN + 24)?);
        fib.__bindgen_anon_3 = bpf_fib_lookup__bindgen_ty_3 {
            ipv6_src: [s0, s1, s2, s3],
        };
        fib.__bindgen_anon_4 = bpf_fib_lookup__bindgen_ty_4 {
            ipv6_dst: [d0, d1, d2, d3],
        };
    } else {
        let [_, _, _, _, s0, s1, s2, s3, d0, d1, d2, d3] = frame.bytes::<12>(ETH_HLEN + 8)?;
        fib.__bindgen_anon_2 = bpf_fib_lookup__bindgen_ty_2 {
            tos: frame.u8_at(ETH_HLEN + 1)?,
        };
        fib.__bindgen_anon_3 = bpf_fib_lookup__bindgen_ty_3 {
            ipv4_src: u32::from_ne_bytes([s0, s1, s2, s3]),
        };
        fib.__bindgen_anon_4 = bpf_fib_lookup__bindgen_ty_4 {
            ipv4_dst: u32::from_ne_bytes([d0, d1, d2, d3]),
        };
    }
    // SAFETY: as in `fast_nat`: this program's context and a fully
    // initialized `bpf_fib_lookup` on the stack with its size.
    let rc = unsafe {
        bpf_fib_lookup(
            ctx.ctx.cast(),
            &mut fib,
            core::mem::size_of::<FibParams>() as i32,
            0,
        )
    };
    if rc != i64::from(BPF_FIB_LKUP_RET_SUCCESS) {
        return None;
    }
    pppoe::ttl_dec(frame, v6)?;
    frame.store(0, fib.dmac)?;
    frame.store(6, fib.smac)?;
    // SAFETY: a BPF helper taking the interface index the FIB returned.
    Some(unsafe { bpf_redirect(fib.ifindex, 0) } as u32)
}

/// 16 address bytes as the four network-order words the FIB wants.
#[inline(always)]
fn words(b: [u8; 16]) -> [u32; 4] {
    let [a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3] = b;
    [
        u32::from_ne_bytes([a0, a1, a2, a3]),
        u32::from_ne_bytes([b0, b1, b2, b3]),
        u32::from_ne_bytes([c0, c1, c2, c3]),
        u32::from_ne_bytes([d0, d1, d2, d3]),
    ]
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

/// Count one fast-path miss in slot `slot` (this CPU's copy).
#[inline(always)]
fn miss(slot: u32) {
    if let Some(c) = NAT_MISS.get_ptr_mut(slot) {
        // SAFETY: this CPU's copy of a per-CPU array element (preemption is
        // off in XDP: no other writer); the kernel's pointer is valid and
        // aligned for `u64`.
        unsafe { *c += 1 };
    }
}

/// What `fast_nat` returns for a flow toward a PPPoE subscriber: nothing
/// written yet, [`nat_to_subscriber`] takes it (not an XDP action).
const NAT_TO_SUB: u32 = 0xffff;

/// A CGNAT fast-path flow toward a PPPoE subscriber (G4.3c): translated,
/// then encapsulated. Its own BPF function (stack frame): it finds the
/// flow again from the frame, which `fast_nat` already admitted (untagged
/// IPv4 without options, TCP/UDP, whole datagram: constant offsets).
#[inline(never)]
fn nat_to_subscriber(ctx: &XdpContext, now: u64) -> u32 {
    let mut frame = Frame(ctx);
    match nat_sub(&mut frame, now) {
        Some(action) => action,
        None => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn nat_sub(frame: &mut Frame, now: u64) -> Option<u32> {
    let [_, _, _, _, _, _, _, _, _, proto, _, _, s0, s1, s2, s3, d0, d1, d2, d3] =
        frame.bytes::<20>(ETH_HLEN)?;
    let [sp0, sp1, dp0, dp1] = frame.bytes::<4>(fastnat::L4_OFF)?;
    let (sport, dport) = (u16::from_be_bytes([sp0, sp1]), u16::from_be_bytes([dp0, dp1]));
    let (src, dst) = ([s0, s1, s2, s3], [d0, d1, d2, d3]);
    let flow = NAT_FLOWS.get_ptr_mut(fastnat::key(proto, src, dst, sport, dport))?;
    // SAFETY: the kernel's pointer to this flow's value, valid and aligned
    // for the run (RCU); see `fast_nat` for why a plain copy is whole.
    let v: FlowValue = unsafe { *flow };
    let [_, new_dst, ..] = v;
    let new_dst = fastnat::decode(new_dst);
    let idx = Subs.by_v4(new_dst.addr)?;
    // Shaped (G4.9b): the kernel translates it and the egress queue holds
    // it (nothing written yet). Here, not in `fast_nat`: there it made LLVM
    // spill an undefined register in `filter_stage` ("R2 !read_ok").
    if pppoe::shaped(&Subs, idx) {
        stat(Stat::DownShaped);
        return None;
    }
    let (ip_len, ttl) = pppoe::ip_meta(frame, false)?;
    let verdict = pppoe::verdict(&mut Subs, idx, false, ip_len, ttl, now, true);
    match verdict.kind {
        DownKind::Encap => {
            let d = verdict.session;
            let info = IpInfo {
                ip_off: ETH_HLEN,
                src: Addr::V4(src),
                dst: Addr::V4(dst),
                proto,
                fragment: corerouter_dataplane_ebpf_common::parse::Fragment::No,
                l4_off: fastnat::L4_OFF,
                src_port: sport,
                dst_port: dport,
                tcp_flags: 0,
                malformed: None,
            };
            if let Err(k) = fastnat::translate(frame, &info, &v) {
                miss(k.slot());
                return None;
            }
            // SAFETY: as in `fast_nat`: whole-word stores of the last use
            // and the packet count; a race loses a count (statistics).
            unsafe {
                (*flow)[2] = now;
                (*flow)[3] += 1;
            }
            Some(encap_out(frame, &d))
        }
        _ => down_other(&verdict),
    }
}

/// The CGNAT fast path (G2.5b): a packet of a flow conntrack already NATed
/// is translated and sent out of the interface the FIB names. `None`: not
/// a known flow, or something the kernel must do (the packet is untouched
/// then: nothing is written before the FIB lookup succeeds).
#[inline(always)]
fn fast_nat(
    ctx: &XdpContext,
    frame: &mut Frame,
    info: &IpInfo,
    now: u64,
    pppoe_on: bool,
) -> Option<u32> {
    let key = fastnat::key_of(info)?;
    let flow = NAT_FLOWS.get_ptr_mut(key)?;
    // SAFETY: the kernel returned a pointer to this flow's value, valid and
    // aligned for `FlowValue` for the rest of the run (RCU). The daemon
    // replaces values whole and other CPUs only store the last-seen time and
    // bump the packet count: a torn read cannot happen on 64-bit words.
    let v: FlowValue = unsafe { *flow };
    if let Err(k) = fastnat::admit(frame, info) {
        miss(k.slot());
        return None;
    }
    let [src, dst, ..] = v;
    let (src, dst) = (fastnat::decode(src), fastnat::decode(dst));
    // Toward a PPPoE subscriber (G4.3c): conntrack accepted the flow, so
    // the subscriber's session takes it without the FIB (whose route for
    // the subscriber is the kernel's slow path).
    if pppoe_on && Subs.by_v4(dst.addr).is_some() {
        return Some(NAT_TO_SUB);
    }
    let tot_len = frame.be16(fastnat::L4_OFF - 20 + 2)?;
    let mut fib = FibParams {
        family: 2, // AF_INET
        l4_protocol: info.proto,
        sport: src.port.to_be(),
        dport: dst.port.to_be(),
        __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 { tot_len },
        ifindex: ctx.ingress_ifindex() as u32,
        __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2 { tos: 0 },
        __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3 {
            ipv4_src: u32::from_ne_bytes(src.addr),
        },
        __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4 {
            ipv4_dst: u32::from_ne_bytes(dst.addr),
        },
        __bindgen_anon_5: bpf_fib_lookup__bindgen_ty_5 { tbid: 0 },
        smac: [0; 6],
        dmac: [0; 6],
    };
    // SAFETY: `ctx.ctx` is this program's context; `fib` is a fully
    // initialized `bpf_fib_lookup` on the stack, its size passed along, as
    // the helper requires. The helper only writes into `fib`.
    let rc = unsafe {
        bpf_fib_lookup(
            ctx.ctx.cast(),
            &mut fib,
            core::mem::size_of::<FibParams>() as i32,
            0,
        )
    };
    if rc != i64::from(BPF_FIB_LKUP_RET_SUCCESS) {
        miss(fastnat::MISS_FIB + (rc as u32).min(8));
        return None;
    }
    if let Err(k) = fastnat::translate(frame, info, &v) {
        miss(k.slot());
        return None;
    }
    frame.store(0, fib.dmac)?;
    frame.store(6, fib.smac)?;
    // SAFETY: as above; plain stores of whole words (last seen, packets).
    // Two CPUs racing on one flow may lose a packet count: statistics only.
    unsafe {
        (*flow)[2] = now;
        (*flow)[3] += 1;
    }
    // SAFETY: a BPF helper taking an interface index the FIB returned and
    // no flags; it only records where the packet goes.
    Some(unsafe { bpf_redirect(fib.ifindex, 0) } as u32)
}

/// The subscriber switches: bit 0 PPPoE, [`ipoe::SETTINGS_BIT`] IPoE.
#[inline(always)]
fn subscribers() -> u64 {
    SETTINGS.get(pppoe::SETTINGS_SLOT).map_or(0, |w| *w & (1 | ipoe::SETTINGS_BIT))
}

/// What [`up_stage`] says: go on as a plain frame, stop with an XDP
/// action, or go on as a decapsulated frame of a session.
const UP_NONE: u64 = 0;
const UP_DONE: u64 = 1 << 63;
const UP_SESSION: u64 = 1 << 62;
const UP_V6: u64 = 1 << 33;
const UP_FAST: u64 = 1 << 34;

/// Stage 1 (G4.3c): a frame from a PPPoE access port. Its own BPF
/// function (own stack frame, 512 bytes each in the verifier's call
/// chain), so it returns one word: [`UP_NONE`], [`UP_DONE`] | action, or
/// [`UP_SESSION`] | flags | session index (decapsulated by then).
#[inline(never)]
fn up_stage(ctx: &XdpContext, now: u64, on: u64) -> u64 {
    let mut frame = Frame(ctx);
    let ifindex = ctx.ingress_ifindex() as u32;
    let mut up = if on & 1 != 0 {
        pppoe::upstream(&frame, ifindex, &mut Subs, now)
    } else {
        Up::NotPppoe
    };
    if up == Up::NotPppoe && on & ipoe::SETTINGS_BIT != 0 {
        up = ipoe::upstream(&frame, ifindex, &mut Subs, now);
    }
    match up {
        Up::NotPppoe => UP_NONE,
        Up::User(st) => {
            stat(st);
            UP_DONE | u64::from(xdp_action::XDP_PASS)
        }
        Up::Drop(st, idx) => {
            stat(st);
            match (st, idx) {
                (Stat::UpPoliced, Some(idx)) => sess_add(idx, pppoe::C_UP_POLICED, 1),
                (Stat::Spoofed, Some(idx)) => sess_add(idx, pppoe::C_SPOOFED, 1),
                _ => {}
            }
            UP_DONE | u64::from(xdp_action::XDP_DROP)
        }
        Up::Session(u) => {
            if !u.ipoe && pppoe::decap(&mut frame, u.tags, u.v6).is_none() {
                stat(Stat::Malformed);
                return UP_DONE | u64::from(xdp_action::XDP_DROP);
            }
            sess_add(u.idx, pppoe::C_UP_PACKETS, 1);
            sess_add(u.idx, pppoe::C_UP_BYTES, u64::from(u.ip_len));
            let mut w = UP_SESSION | u64::from(u.idx);
            if u.v6 {
                w |= UP_V6;
            }
            if u.fast {
                w |= UP_FAST;
            }
            w
        }
    }
}

/// Stages 2 and 3: the filter (G2.5a) and the CGNAT fast path (G2.5b).
/// [`UP_DONE`] | action, or 0 / [`CLEAN`] to go on (`CLEAN`: a clean IP
/// packet the filter let through).
const CLEAN: u64 = 1;
/// A CGNAT flow toward a subscriber: [`nat_to_subscriber`].
const TO_SUB: u64 = 2;

#[inline(never)]
fn filter_stage(ctx: &XdpContext, now: u64, pppoe_on: bool, up: u64) -> u64 {
    let mut frame = Frame(ctx);
    let len = frame.len() as u64;
    let s = settings();
    let mut v = filter::decide(&frame, &s, &mut Maps, now);
    let ifindex = ctx.ingress_ifindex() as u32;
    if v.drop {
        count(ifindex, &v, len);
        if let Some(src) = &v.src {
            top(src, &v, len, now);
        }
        return UP_DONE | u64::from(xdp_action::XDP_DROP);
    }
    if s.fast_nat
        && let Some(info) = v.ip
        && let Some(action) = fast_nat(ctx, &mut frame, &info, now, pppoe_on)
    {
        v.reason = filter::Reason::FastNat;
        count(ifindex, &v, len);
        if action == NAT_TO_SUB {
            return TO_SUB;
        }
        if up & UP_SESSION != 0 {
            stat(Stat::UpFast);
        }
        return UP_DONE | u64::from(action);
    }
    count(ifindex, &v, len);
    if v.ip.is_some() { CLEAN } else { 0 }
}

/// Stage 4 (G4.3c): after the filter and the CGNAT fast path. A clean
/// packet to a subscriber is encapsulated; one from a subscriber (`up`
/// from [`up_stage`]) is forwarded by the FIB when its session allows, or
/// goes to the kernel.
#[inline(never)]
fn down_stage(ctx: &XdpContext, clean: bool, up: u64, now: u64) -> u32 {
    let mut frame = Frame(ctx);
    if clean && let Some(action) = to_subscriber(&mut frame, now) {
        return action;
    }
    if up & UP_SESSION == 0 {
        return xdp_action::XDP_PASS;
    }
    let idx = up as u32;
    if up & UP_FAST != 0 {
        if let Some(action) = forward(ctx, &mut frame, up & UP_V6 != 0) {
            stat(Stat::UpFast);
            return action;
        }
        stat(Stat::UpFib);
    } else {
        stat(Stat::UpKernel);
    }
    sess_add(idx, pppoe::C_KERNEL, 1);
    xdp_action::XDP_PASS
}

#[xdp]
pub fn corerouter_xdp(ctx: XdpContext) -> u32 {
    // SAFETY: a BPF helper with no arguments and no preconditions
    // (CLOCK_MONOTONIC in nanoseconds).
    let now = unsafe { bpf_ktime_get_ns() };
    let subs = subscribers();
    let pppoe_on = subs != 0;
    let up = if pppoe_on { up_stage(&ctx, now, subs) } else { UP_NONE };
    if up & UP_DONE != 0 {
        return up as u32;
    }
    let f = filter_stage(&ctx, now, pppoe_on, up);
    if f & UP_DONE != 0 {
        return f as u32;
    }
    if f & TO_SUB != 0 {
        return nat_to_subscriber(&ctx, now);
    }
    if !pppoe_on {
        return xdp_action::XDP_PASS;
    }
    down_stage(&ctx, f & CLEAN != 0, up, now)
}

// --- G4.9b / G4.3ca: the tc programs ---------------------------------------
//
// Three classifiers in the same object as the XDP program, so they share
// its session maps (a subscriber's address → its session, its rates):
//
// - `shape_egress` (clsact egress of every port with a target behind it):
//   the download shaper. A session's address (shaped sessions only), else a
//   queue's prefix, else the port's interface queue: the departure time goes
//   in `skb->tstamp` and `fq` holds the packet until then (EDT);
// - `shape_ingress` (clsact ingress of the same ports): the upload policer
//   of the queues (sessions are policed by the XDP program);
// - `bng_egress` (clsact egress of `bng0`, G4.3ca): what the kernel routes
//   to a PPPoE subscriber (slow path, ICMP, shaped download) gets the
//   access-side header and goes to the session's port.

#[map(name = "SUB_SHAPE")]
static SUB_SHAPE: Array<[u64; shaper::SESSION_WORDS]> =
    Array::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "SUB_EDT")]
static SUB_EDT: Array<shaper::State> = Array::with_max_entries(pppoe::SESSIONS_MAX, 0);
#[map(name = "Q_V4")]
static Q_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(queue::Q_PREFIXES, 0);
#[map(name = "Q_V6")]
static Q_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(queue::Q_PREFIXES, 0);
#[map(name = "Q_IFACE")]
static Q_IFACE: HashMap<u32, u32> = HashMap::with_max_entries(queue::Q_IFACES, 0);
#[map(name = "Q_CONF")]
static Q_CONF: Array<queue::ConfWords> = Array::with_max_entries(queue::Q_MAX, 0);
#[map(name = "Q_STATE")]
static Q_STATE: Array<shaper::State> = Array::with_max_entries(queue::Q_MAX * 2, 0);
#[map(name = "Q_COUNT")]
static Q_COUNT: Array<queue::Counts> = Array::with_max_entries(queue::Q_MAX * 2, 0);
#[map(name = "Q_PCQ")]
static Q_PCQ: LruHashMap<[u8; queue::PCQ_KEY_LEN], shaper::SubState> =
    LruHashMap::with_max_entries(queue::PCQ_MAX, 0);
#[map(name = "SHAPE_STATS")]
static SHAPE_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(queue::Stat::SLOTS, 0);

/// The words of a map element every CPU updates, through BPF atomic
/// instructions (G4.3cc).
/// tc verdicts (`TC_ACT_OK`, `TC_ACT_SHOT`) and `BPF_SKB_TSTAMP_DELIVERY_MONO`
/// (a bindgen-numbered module in aya's bindings).
const TC_OK: i32 = TC_ACT_OK as i32;
const TC_SHOT: i32 = TC_ACT_SHOT as i32;
const TSTAMP_DELIVERY_MONO: u32 = 1;

struct Atomic<const N: usize>(*mut [u64; N]);

impl<const N: usize> Words for Atomic<N> {
    #[inline(always)]
    fn get(&self, i: usize) -> u64 {
        if i >= N || self.0.is_null() {
            return 0;
        }
        // SAFETY: `self.0` is the kernel's pointer to an array or LRU map
        // element of `N` words (valid and aligned for the run; null was
        // checked above); `i < N`. A
        // volatile 64-bit load (BPF has no atomic-load instruction before
        // v4; an aligned 64-bit load does not tear): another CPU stores the
        // word whole.
        unsafe { core::ptr::read_volatile((self.0 as *const u64).add(i)) }
    }

    #[inline(always)]
    fn set(&mut self, i: usize, v: u64) {
        if i >= N || self.0.is_null() {
            return;
        }
        // SAFETY: as in `get`; a whole-word volatile store.
        unsafe { core::ptr::write_volatile((self.0 as *mut u64).add(i), v) }
    }

    #[inline(always)]
    fn cas(&mut self, i: usize, old: u64, new: u64) -> bool {
        if i >= N || self.0.is_null() {
            return false;
        }
        // SAFETY: as in `get`; BPF_CMPXCHG (kernel 5.12+, `-C
        // target-cpu=v3`) on one word of the element.
        unsafe {
            core::intrinsics::atomic_cxchg::<u64, { AtomicOrdering::SeqCst }, { AtomicOrdering::SeqCst }>(
                (self.0 as *mut u64).add(i),
                old,
                new,
            )
            .1
        }
    }

    #[inline(always)]
    fn present(&self) -> bool {
        !self.0.is_null()
    }

    #[inline(always)]
    fn add(&mut self, i: usize, v: u64) {
        if i >= N || self.0.is_null() {
            return;
        }
        // SAFETY: as in `get`; BPF atomic add (no fetch).
        unsafe {
            core::intrinsics::atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(
                (self.0 as *mut u64).add(i),
                v,
            );
        }
    }
}

/// The skb's linear data as a frame (direct packet access, as in XDP).
struct Skb<'a>(&'a TcContext);

impl Packet for Skb<'_> {
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
        // SAFETY: inside `data..data_end` (checked just above, the check the
        // verifier needs for direct packet access in tc); any bit pattern
        // is a valid `[u8; N]`; unaligned read.
        Some(unsafe { core::ptr::read_unaligned((start + off) as *const [u8; N]) })
    }
}

impl PacketMut for Skb<'_> {
    #[inline(always)]
    fn store<const N: usize>(&mut self, off: usize, bytes: [u8; N]) -> Option<()> {
        let start = self.0.data();
        let end = self.0.data_end();
        if start + off + N > end {
            return None;
        }
        // SAFETY: inside the linear data (checked above); the helpers that
        // could make it shared (clone) are not called by these programs,
        // and `bpf_skb_pull_data` made the head writable.
        unsafe { core::ptr::write_unaligned((start + off) as *mut [u8; N], bytes) };
        Some(())
    }
}

impl PacketHead for Skb<'_> {
    /// Only growing the head: `bpf_skb_change_head` pushes `-delta`
    /// bytes in front of the MAC header.
    #[inline(always)]
    fn adjust_head(&mut self, delta: i32) -> Option<()> {
        if delta >= 0 {
            return None;
        }
        // SAFETY: a BPF helper on this program's own skb; it reallocates
        // the head or fails without change. Every later access re-reads
        // `data`/`data_end` (`Skb::bytes`).
        let rc = unsafe { bpf_skb_change_head(self.0.skb.skb, (-delta) as u32, 0) };
        (rc == 0).then_some(())
    }
}

/// One more `what` in the tc programs' statistics (this CPU's copy).
#[inline(always)]
fn shape_stat(what: queue::Stat) {
    if let Some(c) = SHAPE_STATS.get_ptr_mut(what as u32) {
        // SAFETY: this CPU's copy of a per-CPU array element; tc programs
        // run with preemption (migration) off, so no other writer.
        unsafe { *c += 1 };
    }
}

/// Add to counter `field` of queue `idx`, direction `dir`.
#[inline(always)]
fn q_add(idx: u32, dir: u32, field: usize, n: u64) {
    if let Some(p) = Q_COUNT.get_ptr_mut(idx.wrapping_mul(2) | (dir & 1)) {
        Atomic(p).add(field, n);
    }
}

/// The linear head holds at least the headers the parse reads (two tags,
/// PPPoE, an IPv6 header).
#[inline(always)]
fn pull(ctx: &TcContext) {
    const HEAD: usize = 14 + 8 + 8 + 40;
    if ctx.data_end() - ctx.data() < HEAD {
        let _ = ctx.pull_data(HEAD.min(ctx.len() as usize) as u32);
    }
}

/// Set CE on the packet at `l3` if it is ECN-capable; `false`: it is not
/// (the caller drops it instead, RFC 3168 §6.1.1).
#[inline(always)]
fn mark_ce(ctx: &TcContext, l3: &queue::L3) -> bool {
    let frame = Skb(ctx);
    match queue::ecn(&frame, l3) {
        Some(1 | 2) => {}
        Some(3) => return true,
        _ => return false,
    }
    if l3.v6 {
        let Some(b) = frame.u8_at(l3.off + 1) else {
            return false;
        };
        let _ = ctx.store(l3.off + 1, &(b | 0x30), 0);
    } else {
        let Some(tos) = frame.u8_at(l3.off + 1) else {
            return false;
        };
        let Some(ver) = frame.u8_at(l3.off) else {
            return false;
        };
        let old = u16::from_be_bytes([ver, tos]);
        let new = u16::from_be_bytes([ver, tos | 3]);
        let _ = ctx.l3_csum_replace(
            l3.off + 10,
            u64::from(old.to_be()),
            u64::from(new.to_be()),
            2,
        );
        let _ = ctx.store(l3.off + 1, &(tos | 3), 0);
    }
    true
}

/// Whether the packet at `l3` is ECN-capable (ECT(0), ECT(1) or already
/// CE): only then may CoDel mark instead of dropping. A mark on a packet
/// that is not would be a drop after the clock already counted it (the
/// target loses that capacity: 43% of the rate delivered, **medido**).
#[inline(always)]
fn ect(ctx: &TcContext, l3: &queue::L3) -> bool {
    matches!(queue::ecn(&Skb(ctx), l3), Some(1..=3))
}

/// `q` as this packet may use it: no marking unless it is ECN-capable.
#[inline(always)]
fn for_packet(mut q: shaper::Queue, ctx: &TcContext, l3: &queue::L3) -> shaper::Queue {
    q.ecn = q.ecn && ect(ctx, l3);
    q
}

/// Apply verdict `v` of a packet at `l3`: the departure time, a mark, or
/// the drop. `(action, counted as sent, marked)`.
#[inline(always)]
fn finish(ctx: &TcContext, l3: &queue::L3, v: shaper::Verdict, now: u64) -> (i32, bool, bool) {
    let (t, marked) = match v {
        shaper::Verdict::Drop => {
            shape_stat(queue::Stat::Dropped);
            return (TC_SHOT, false, false);
        }
        shaper::Verdict::Busy => {
            shape_stat(queue::Stat::Contended);
            return (TC_SHOT, false, false);
        }
        shaper::Verdict::Mark(t) => {
            if !mark_ce(ctx, l3) {
                shape_stat(queue::Stat::Dropped);
                return (TC_SHOT, false, false);
            }
            shape_stat(queue::Stat::Marked);
            (t, true)
        }
        shaper::Verdict::Send(t) => (t, false),
    };
    if t > now {
        // SAFETY: a BPF helper on this program's skb: the departure time as
        // CLOCK_MONOTONIC (`fq` compares it with `ktime_get_ns`); marked
        // mono so a redirect keeps it.
        unsafe {
            bpf_skb_set_tstamp(ctx.skb.skb, t, TSTAMP_DELIVERY_MONO);
        }
        shape_stat(queue::Stat::Held);
    } else {
        shape_stat(queue::Stat::Sent);
    }
    (TC_OK, true, marked)
}

/// A shaped session's download: the session's own clock.
#[inline(always)]
fn shape_session(ctx: &TcContext, l3: &queue::L3, idx: u32, now: u64) -> Option<i32> {
    let w = PPPOE_SESSIONS.get(idx)?;
    let v = pppoe::View::of(w);
    if !v.has(pppoe::F_ACTIVE) || !v.has(pppoe::F_SHAPE_DOWN) {
        return None;
    }
    let (r, q) = shaper::of_session_words(SUB_SHAPE.get(idx)?);
    let q = for_packet(q, ctx, l3);
    let st = SUB_EDT.get_ptr_mut(idx)?;
    let verdict = shaper::depart(&mut Atomic(st), shaper::FULL, &r, &q, now, u64::from(l3.ip_len), 0);
    let (action, sent, _) = finish(ctx, l3, verdict, now);
    shape_stat(queue::Stat::SessionShaped);
    // IPoE: the XDP program counted it already (on its way to the kernel).
    if sent && !v.has(corerouter_dataplane_ebpf_common::ipoe::F_IPOE) {
        sess_add(idx, pppoe::C_DOWN_PACKETS, 1);
        sess_add(idx, pppoe::C_DOWN_BYTES, u64::from(l3.ip_len));
    } else if !sent {
        sess_add(idx, pppoe::C_DOWN_POLICED, 1);
    }
    Some(action)
}

/// The session holding the destination of `l3` (its /32, /64, delegated
/// prefix, or a block routed to it, G4.3cd).
#[inline(always)]
fn session_of(l3: &queue::L3) -> Option<u32> {
    if l3.v6 {
        Subs.by_v6(l3.dst).or_else(|| Subs.by_route_v6(l3.dst))
    } else {
        let a = queue::L3::v4(&l3.dst);
        Subs.by_v4(a).or_else(|| Subs.by_route_v4(a))
    }
}

/// The queue of address `a` (prefix tries), else of the port.
#[inline(always)]
fn queue_of(v6: bool, a: &[u8; 16], ifindex: u32) -> Option<u32> {
    let by_prefix = if v6 {
        Q_V6.get(Key::new(128, *a)).copied()
    } else {
        Q_V4.get(Key::new(32, queue::L3::v4(a))).copied()
    };
    by_prefix.or_else(|| Q_IFACE.get_ptr(&ifindex).map(|p| {
        // SAFETY: the kernel's pointer to a `u32` value (replaced whole).
        unsafe { *p }
    }))
}

/// A PCQ sub-stream's departure (`not_before` for the queue's own clock).
#[inline(always)]
fn pcq_time(idx: u32, dir: u32, p: &queue::Pcq, q: &shaper::Queue, v6: bool, addr: &[u8; 16], now: u64, bytes: u64) -> Option<shaper::Verdict> {
    let key = queue::pcq_key(idx, dir as u8, v6, addr, p.mask4, p.mask6);
    let st = match Q_PCQ.get_ptr_mut(&key) {
        Some(st) => st,
        None => {
            let _ = Q_PCQ.insert(&key, &[0u64; shaper::SUB_WORDS], u64::from(BPF_NOEXIST));
            Q_PCQ.get_ptr_mut(&key)?
        }
    };
    Some(shaper::depart(&mut Atomic(st), shaper::SUB, &p.rate, q, now, bytes, 0))
}

/// Shape (download) or police (upload) one packet of queue `idx`.
#[inline(always)]
fn shape_queue(ctx: &TcContext, l3: &queue::L3, idx: u32, dir: u32, now: u64) -> i32 {
    let Some(conf) = Q_CONF.get(idx) else {
        return TC_OK;
    };
    if !queue::active(conf) {
        shape_stat(queue::Stat::NoTarget);
        return TC_OK;
    }
    let d = queue::Dir::of(conf, dir as usize);
    let bytes = u64::from(l3.ip_len);
    let Some(st) = Q_STATE.get_ptr_mut(idx.wrapping_mul(2) | (dir & 1)) else {
        return TC_OK;
    };
    if dir == 0 {
        // Upload: police (the sub-stream first, then the queue).
        let ok = match &d.pcq {
            p if p.on => {
                let a = if p.by_src { &l3.src } else { &l3.dst };
                let key = queue::pcq_key(idx, 0, l3.v6, a, p.mask4, p.mask6);
                match Q_PCQ.get_ptr_mut(&key) {
                    Some(s) => policer::admit(&mut Atomic(s), &p.rate, now, bytes),
                    None => {
                        let _ = Q_PCQ.insert(&key, &[0u64; shaper::SUB_WORDS], u64::from(BPF_NOEXIST));
                        true
                    }
                }
            }
            _ => true,
        } && policer::admit(&mut Atomic(st), &d.rate, now, bytes);
        if ok {
            q_add(idx, 0, queue::C_PACKETS, 1);
            q_add(idx, 0, queue::C_BYTES, bytes);
            return TC_OK;
        }
        q_add(idx, 0, queue::C_DROPPED, 1);
        shape_stat(queue::Stat::Policed);
        return TC_SHOT;
    }
    let not_before = match &d.pcq {
        p if p.on => {
            let a = if p.by_src { &l3.src } else { &l3.dst };
            match pcq_time(idx, 1, p, &for_packet(p.queue, ctx, l3), l3.v6, a, now, bytes) {
                Some(shaper::Verdict::Drop | shaper::Verdict::Busy) => {
                    q_add(idx, 1, queue::C_DROPPED, 1);
                    shape_stat(queue::Stat::Dropped);
                    return TC_SHOT;
                }
                Some(v) => v.time().unwrap_or(0),
                None => 0,
            }
        }
        _ => 0,
    };
    let q = for_packet(d.queue, ctx, l3);
    let v = shaper::depart(&mut Atomic(st), shaper::FULL, &d.rate, &q, now, bytes, not_before);
    let (action, sent, marked) = finish(ctx, l3, v, now);
    if sent {
        q_add(idx, 1, queue::C_PACKETS, 1);
        q_add(idx, 1, queue::C_BYTES, bytes);
    } else {
        q_add(idx, 1, queue::C_DROPPED, 1);
    }
    if marked {
        q_add(idx, 1, queue::C_MARKED, 1);
    }
    action
}

#[inline(always)]
fn shaper_on() -> u64 {
    SETTINGS.get(queue::SETTINGS_SLOT).copied().unwrap_or(0)
}

/// Download shaper (clsact egress).
#[classifier]
pub fn shape_egress(ctx: TcContext) -> i32 {
    let on = shaper_on();
    if on == 0 {
        return TC_OK;
    }
    pull(&ctx);
    let Some(l3) = queue::l3(&Skb(&ctx)) else {
        shape_stat(queue::Stat::NotIp);
        return TC_OK;
    };
    // SAFETY: a BPF helper with no arguments (CLOCK_MONOTONIC, ns).
    let now = unsafe { bpf_ktime_get_ns() };
    if on & queue::ON_SESSIONS != 0
        && let Some(idx) = session_of(&l3)
        && let Some(action) = shape_session(&ctx, &l3, idx, now)
    {
        return action;
    }
    if on & queue::ON_QUEUES == 0 {
        shape_stat(queue::Stat::NoTarget);
        return TC_OK;
    }
    // SAFETY: reading `ifindex` of this program's own `__sk_buff`.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    match queue_of(l3.v6, &l3.dst, ifindex) {
        Some(idx) => shape_queue(&ctx, &l3, idx, 1, now),
        None => {
            shape_stat(queue::Stat::NoTarget);
            TC_OK
        }
    }
}

/// Upload policer of the queues (clsact ingress).
#[classifier]
pub fn shape_ingress(ctx: TcContext) -> i32 {
    if shaper_on() & queue::ON_QUEUES == 0 {
        return TC_OK;
    }
    pull(&ctx);
    let Some(l3) = queue::l3(&Skb(&ctx)) else {
        return TC_OK;
    };
    // SAFETY: as in `shape_egress`.
    let now = unsafe { bpf_ktime_get_ns() };
    // SAFETY: as in `shape_egress`.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    match queue_of(l3.v6, &l3.src, ifindex) {
        Some(idx) => shape_queue(&ctx, &l3, idx, 0, now),
        None => TC_OK,
    }
}

/// `bng0` (G4.3ca): a packet the kernel routed to a PPPoE subscriber gets
/// the access-side header (tags, PPPoE, PPP) and goes out of the session's
/// port, where `shape_egress` sees it. The kernel already did the TTL,
/// the firewall and the MTU of the subscriber's route (ICMP "too big" from
/// the route's `mtu`).
#[classifier]
pub fn bng_egress(ctx: TcContext) -> i32 {
    pull(&ctx);
    let mut frame = Skb(&ctx);
    let Some(l3) = queue::l3(&frame) else {
        shape_stat(queue::Stat::BngNoSession);
        return TC_SHOT;
    };
    let Some(idx) = session_of(&l3) else {
        shape_stat(queue::Stat::BngNoSession);
        return TC_SHOT;
    };
    let Some(d) = pppoe::session_down(&Subs, idx, l3.ip_len, l3.v6) else {
        shape_stat(queue::Stat::BngNoSession);
        return TC_SHOT;
    };
    if pppoe::encap(&mut frame, &d).is_none() {
        shape_stat(queue::Stat::BngFailed);
        return TC_SHOT;
    }
    shape_stat(queue::Stat::BngEncap);
    // SAFETY: a BPF helper taking the access port from the session map and
    // no flags (to its egress, where the shaper runs).
    unsafe { bpf_redirect(d.ifindex, 0) as i32 }
}

// --- G3.9db: the LSP responder's tap ---------------------------------------
//
// `lsp_tap` (clsact ingress of each interface the `lsp-ping` service
// listens on) copies the frames `lsp_tap::keep` picks — expired or
// explicit-null MPLS, maybe-too-big MPLS, echo requests to 127/8 and ::1 —
// to the `LSP_TAP` ring buffer and lets every frame go on. It replaces the
// service's three `AF_PACKET` taps, whose `packet_rcv` ran for every frame
// of the host (G3.9d: −19% of MPLS switching on one core).

#[map(name = "LSP_TAP")]
static LSP_TAP: RingBuf = RingBuf::with_byte_size(m::LSP_TAP_BYTES, 0);
#[map(name = "LSP_TAP_SET")]
static LSP_TAP_SET: Array<u64> = Array::with_max_entries(1, 0);
#[map(name = "LSP_TAP_STATS")]
static LSP_TAP_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(lsp_tap::Stat::SLOTS, 0);

#[inline(always)]
fn tap_stat(what: lsp_tap::Stat) {
    if let Some(c) = LSP_TAP_STATS.get_ptr_mut(what as u32) {
        // SAFETY: this CPU's copy of a per-CPU array slot the kernel
        // returned (valid for the run; tc runs without migration, so no
        // other writer).
        unsafe { *c += 1 };
    }
}

/// One record of `N` octets of frame: the header, then the frame's first
/// `want` octets (at most `N`). `false`: the ring buffer is full.
#[inline(always)]
fn tap_copy<const N: usize>(ctx: &TcContext, ifindex: u32, len: u32, want: usize) -> bool {
    let Some(mut r) = LSP_TAP.reserve_bytes(lsp_tap::HEADER + N, 0) else {
        return false;
    };
    let n = r
        .get_mut(lsp_tap::HEADER..)
        .and_then(|d| d.get_mut(..want.min(N)))
        .and_then(|d| ctx.load_bytes(0, d).ok())
        .unwrap_or(0) as u32;
    let mut head = [0u8; lsp_tap::HEADER];
    for (i, w) in [ifindex, len, n].into_iter().enumerate() {
        if let Some(d) = head.get_mut(i * 4..i * 4 + 4) {
            for (b, v) in d.iter_mut().zip(w.to_le_bytes()) {
                *b = v;
            }
        }
    }
    if let Some(h) = r.get_mut(..lsp_tap::HEADER)
        && let Ok(h) = <&mut [u8; lsp_tap::HEADER]>::try_from(h)
    {
        *h = head;
    }
    r.submit(0);
    true
}

/// The LSP responder's tap (clsact ingress).
#[classifier]
pub fn lsp_tap(ctx: TcContext) -> i32 {
    // Headers in the linear part (the decision reads 58 octets at most);
    // a frame that has them already costs no helper call.
    const HEAD: usize = 14 + 4 + 40 + 2;
    let len = ctx.len();
    if ctx.data_end() - ctx.data() < HEAD.min(len as usize) {
        let _ = ctx.pull_data(HEAD.min(len as usize) as u32);
    }
    // SAFETY: reading two fields of this program's own `__sk_buff`.
    let (ifindex, gso) = unsafe { ((*ctx.skb.skb).ifindex, (*ctx.skb.skb).gso_size != 0) };
    let set = lsp_tap::Settings::from_word(LSP_TAP_SET.get(0).copied().unwrap_or(0));
    let k = lsp_tap::keep(&Skb(&ctx), len, gso, set);
    if k == Keep::No {
        return TC_OK;
    }
    let want = lsp_tap::copied(k, len);
    let ok = if want <= lsp_tap::SMALL {
        tap_copy::<{ lsp_tap::SMALL }>(&ctx, ifindex, len, want)
    } else {
        tap_copy::<{ lsp_tap::FRAME }>(&ctx, ifindex, len, want)
    };
    tap_stat(if ok { lsp_tap::Stat::Kept } else { lsp_tap::Stat::Full });
    TC_OK
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

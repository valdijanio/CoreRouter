//! The metering process (RFC 7011 §2 "Metering Process"): conntrack events
//! and periodic reads of the table in, flow records and NAT events out.
//!
//! Each connection the kernel tracks becomes, per direction, one flow
//! record when it ends (the `DESTROY` event carries the final counters),
//! plus one more for each active timeout it lives through and one when it
//! goes quiet for the inactive timeout (both seen on the periodic read of
//! the table). The records carry the addresses and ports before and after
//! NAT: the original tuple and the reply tuple, swapped.
//!
//! A translated IPv4 connection also gives RFC 8158 NAT44 session events,
//! create on `NEW` and delete on `DESTROY`, always (sampling never drops
//! them: they are the connection log a provider must keep).
//!
//! Memory is bounded: at most `max_entries` connections are followed; one
//! more is not followed but nothing is lost — its `DESTROY` still reports
//! the whole connection (only the active/inactive split is missing), and
//! the miss is counted.

use std::collections::HashMap;
use std::collections::hash_map::Entry as Slot;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::conntrack::{Conn, Event, EventKind, Tuple, status};

use crate::record::{Direction, EndReason, Flow, NatEvent, NatEventType, Record};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterConfig {
    /// Report a running flow after this long (RouterOS
    /// `active-flow-timeout`, 30 min by default).
    pub active_ms: u64,
    /// Report a flow quiet for this long (`inactive-flow-timeout`, 15 s).
    pub inactive_ms: u64,
    /// One connection in N gets flow records (1: all). Deterministic by a
    /// hash of the original tuple, so both events of a connection agree.
    pub sampling: u32,
    /// Connections followed at most.
    pub max_entries: usize,
    pub flows: bool,
    pub nat_events: bool,
    /// Keep the destination in NAT events (off: 0.0.0.0 and port 0, the
    /// connection log of Marco Civil art. 13 without the application
    /// access art. 14 forbids).
    pub nat_destination: bool,
}

impl Default for MeterConfig {
    fn default() -> Self {
        Self {
            active_ms: 30 * 60 * 1000,
            inactive_ms: 15 * 1000,
            sampling: 1,
            max_entries: 262_144,
            flows: true,
            nat_events: true,
            nat_destination: false,
        }
    }
}

/// Where a connection's packets go in and out (ifIndex, 0 unknown) and
/// whether its flows are wanted (RouterOS `interfaces`).
pub trait Router {
    fn ifindex(&self, addr: IpAddr) -> u32;
    fn wanted(&self, ingress: u32, egress: u32) -> bool;
}

/// Every interface, all unknown.
pub struct AnyInterface;

impl Router for AnyInterface {
    fn ifindex(&self, _: IpAddr) -> u32 {
        0
    }
    fn wanted(&self, _: u32, _: u32) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeterStats {
    pub events: u64,
    pub flows: u64,
    pub nat_events: u64,
    /// Connections not followed for a full table (still reported at the end).
    pub cache_full: u64,
    /// Connections left out by sampling.
    pub sampled_out: u64,
    /// Followed connections that vanished from the table without a
    /// `DESTROY` (an event the kernel dropped).
    pub vanished: u64,
}

type Key = (u32, u8, Tuple);

/// `TCP_CONNTRACK_ESTABLISHED`.
const TCP_ESTABLISHED: u8 = 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Count {
    op: u64,
    ob: u64,
    rp: u64,
    rb: u64,
}

impl Count {
    fn of(c: &Conn) -> Self {
        Self {
            op: c.orig_packets,
            ob: c.orig_bytes,
            rp: c.reply_packets,
            rb: c.reply_bytes,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    /// Start of the part not reported yet.
    seg_start: u64,
    /// When the counters last moved (inactive timeout).
    changed: u64,
    reported: Count,
    seen: Count,
    ingress: u32,
    egress: u32,
    /// The reply tuple: the translation, for a connection that vanishes.
    reply: Tuple,
}

#[derive(Debug)]
pub struct Meter {
    cfg: MeterConfig,
    entries: HashMap<Key, Entry>,
    stats: MeterStats,
}

fn key(c: &Conn) -> Key {
    (c.id, c.protocol, c.orig)
}

/// FNV-1a over the original tuple: the sampling decision.
fn hash(c: &Conn) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for x in b {
            h ^= u64::from(*x);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    };
    let ip = |a: IpAddr| match a {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    };
    eat(&ip(c.orig.src));
    eat(&ip(c.orig.dst));
    eat(&c.orig.src_port.to_be_bytes());
    eat(&c.orig.dst_port.to_be_bytes());
    eat(&[c.protocol]);
    h
}

fn ns_to_ms(ns: Option<u64>) -> Option<u64> {
    ns.filter(|n| *n > 0).map(|n| n / 1_000_000)
}

impl Meter {
    pub fn new(cfg: MeterConfig) -> Self {
        Self {
            cfg,
            entries: HashMap::new(),
            stats: MeterStats::default(),
        }
    }

    pub fn config(&self) -> &MeterConfig {
        &self.cfg
    }

    /// New settings; followed connections stay followed (a smaller cap
    /// only stops new ones).
    pub fn set_config(&mut self, cfg: MeterConfig) {
        self.cfg = cfg;
    }

    pub fn stats(&self) -> MeterStats {
        self.stats
    }

    /// Connections followed now.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn sampled(&self, c: &Conn) -> bool {
        self.cfg.sampling <= 1 || hash(c).is_multiple_of(u64::from(self.cfg.sampling))
    }

    fn nat(
        &mut self,
        c: &Conn,
        event: NatEventType,
        (start_ms, time_ms): (u64, u64),
        out: &mut Vec<Record>,
    ) {
        if !self.cfg.nat_events || !(c.has(status::SRC_NAT) || c.has(status::DST_NAT)) {
            return;
        }
        let (IpAddr::V4(src), IpAddr::V4(dst), IpAddr::V4(post_src), IpAddr::V4(post_dst)) =
            (c.orig.src, c.orig.dst, c.reply.dst, c.reply.src)
        else {
            return;
        };
        self.stats.nat_events += 1;
        let keep = self.cfg.nat_destination;
        let (dst, post_dst, dst_port, post_dst_port) = if keep {
            (dst, post_dst, c.orig.dst_port, c.reply.src_port)
        } else {
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0)
        };
        out.push(Record::Nat(NatEvent {
            time_ms,
            start_ms,
            event,
            protocol: c.protocol,
            src,
            dst,
            src_port: c.orig.src_port,
            dst_port,
            post_src,
            post_dst,
            post_src_port: c.reply.dst_port,
            post_dst_port,
        }));
    }

    /// The flow records of `c` for the counts between `from` and `to`
    /// (one per direction that moved).
    #[allow(clippy::too_many_arguments)]
    fn flows(
        &mut self,
        c: &Conn,
        from: Count,
        to: Count,
        start_ms: u64,
        end_ms: u64,
        reason: EndReason,
        (ingress, egress): (u32, u32),
        out: &mut Vec<Record>,
    ) {
        let (o, r) = (&c.orig, &c.reply);
        let orig = Flow {
            start_ms,
            end_ms,
            protocol: c.protocol,
            src: o.src,
            dst: o.dst,
            src_port: o.src_port,
            dst_port: o.dst_port,
            post_src: r.dst,
            post_dst: r.src,
            post_src_port: r.dst_port,
            post_dst_port: r.src_port,
            octets: to.ob.saturating_sub(from.ob),
            packets: to.op.saturating_sub(from.op),
            ingress,
            egress,
            end_reason: reason,
            direction: Direction::Initiator,
        };
        let reply = Flow {
            src: r.src,
            dst: r.dst,
            src_port: r.src_port,
            dst_port: r.dst_port,
            post_src: o.dst,
            post_dst: o.src,
            post_src_port: o.dst_port,
            post_dst_port: o.src_port,
            octets: to.rb.saturating_sub(from.rb),
            packets: to.rp.saturating_sub(from.rp),
            ingress: egress,
            egress: ingress,
            direction: Direction::Reverse,
            ..orig.clone()
        };
        for f in [orig, reply] {
            if f.packets > 0 {
                self.stats.flows += 1;
                out.push(Record::Flow(f));
            }
        }
    }

    fn interfaces(c: &Conn, router: &dyn Router) -> (u32, u32) {
        // In: where the initiator is; out: toward the destination after
        // DNAT (the reply's source).
        (router.ifindex(c.orig.src), router.ifindex(c.reply.src))
    }

    /// One event at `now_ms` (Unix ms), its records appended to `out`.
    pub fn event(&mut self, ev: &Event, now_ms: u64, router: &dyn Router, out: &mut Vec<Record>) {
        self.stats.events += 1;
        let c = &ev.conn;
        match ev.kind {
            EventKind::New => {
                let start = ns_to_ms(ev.start_ns).unwrap_or(now_ms);
                self.nat(c, NatEventType::Nat44SessionCreate, (start, start), out);
                if !self.cfg.flows {
                    return;
                }
                if !self.sampled(c) {
                    self.stats.sampled_out += 1;
                    return;
                }
                let ifs = Self::interfaces(c, router);
                if !router.wanted(ifs.0, ifs.1) {
                    return;
                }
                let full = self.entries.len() >= self.cfg.max_entries;
                match self.entries.entry(key(c)) {
                    Slot::Occupied(_) => {}
                    Slot::Vacant(_) if full => self.stats.cache_full += 1,
                    Slot::Vacant(v) => {
                        v.insert(Entry {
                            seg_start: start,
                            changed: start,
                            reported: Count::default(),
                            seen: Count::of(c),
                            ingress: ifs.0,
                            egress: ifs.1,
                            reply: c.reply,
                        });
                    }
                }
            }
            EventKind::Destroy => {
                let end = ns_to_ms(ev.stop_ns).unwrap_or(now_ms);
                let began = ns_to_ms(ev.start_ns).unwrap_or(0);
                self.nat(c, NatEventType::Nat44SessionDelete, (began, end), out);
                let entry = self.entries.remove(&key(c));
                if !self.cfg.flows {
                    return;
                }
                let (from, start, ifs) = match entry {
                    Some(e) => (e.reported, e.seg_start, (e.ingress, e.egress)),
                    None => {
                        if !self.sampled(c) {
                            return;
                        }
                        let ifs = Self::interfaces(c, router);
                        if !router.wanted(ifs.0, ifs.1) {
                            return;
                        }
                        let start = ns_to_ms(ev.start_ns).unwrap_or(end);
                        (Count::default(), start, ifs)
                    }
                };
                // A UDP or ICMP connection ends by the kernel's timeout:
                // idle. TCP that closed: end of flow.
                let reason = match c.tcp_state {
                    Some(s) if s != TCP_ESTABLISHED => EndReason::End,
                    _ => EndReason::Idle,
                };
                self.flows(c, from, Count::of(c), start, end, reason, ifs, out);
            }
        }
    }

    /// The table as read now: the active and inactive timeouts. `complete`
    /// when the read reached the end (only then do followed connections
    /// missing from it count as gone).
    pub fn scan(
        &mut self,
        table: &[Conn],
        complete: bool,
        now_ms: u64,
        router: &dyn Router,
        out: &mut Vec<Record>,
    ) {
        if !self.cfg.flows {
            self.entries.clear();
            return;
        }
        let mut present = std::collections::HashSet::with_capacity(table.len().min(1 << 20));
        for c in table {
            let k = key(c);
            if complete {
                present.insert(k);
            }
            let now = Count::of(c);
            let (cfg_active, cfg_inactive) = (self.cfg.active_ms, self.cfg.inactive_ms);
            let full = self.entries.len() >= self.cfg.max_entries;
            let report = match self.entries.get_mut(&k) {
                Some(e) => {
                    if now != e.seen {
                        if e.seen == e.reported && now_ms > e.changed + cfg_inactive {
                            // Quiet until now: a new flow starts here.
                            e.seg_start = now_ms;
                        }
                        e.seen = now;
                        e.changed = now_ms;
                    }
                    let pending = e.seen != e.reported;
                    let reason = if pending && now_ms.saturating_sub(e.seg_start) >= cfg_active {
                        Some(EndReason::Active)
                    } else if pending && now_ms.saturating_sub(e.changed) >= cfg_inactive {
                        Some(EndReason::Idle)
                    } else {
                        None
                    };
                    reason.map(|r| {
                        let from = e.reported;
                        let start = e.seg_start;
                        e.reported = e.seen;
                        e.seg_start = now_ms;
                        (from, start, r, (e.ingress, e.egress))
                    })
                }
                None => {
                    // Opened before we listened, or its NEW was lost.
                    if !full && self.sampled(c) {
                        let ifs = Self::interfaces(c, router);
                        if router.wanted(ifs.0, ifs.1) {
                            self.entries.insert(
                                k,
                                Entry {
                                    seg_start: now_ms,
                                    changed: now_ms,
                                    reported: Count::default(),
                                    seen: now,
                                    ingress: ifs.0,
                                    egress: ifs.1,
                                    reply: c.reply,
                                },
                            );
                        }
                    }
                    None
                }
            };
            if let Some((from, start, reason, ifs)) = report {
                self.flows(c, from, now, start, now_ms, reason, ifs, out);
            }
        }
        if complete {
            let gone: Vec<Key> = self
                .entries
                .keys()
                .filter(|k| !present.contains(*k))
                .copied()
                .collect();
            for k in gone {
                if let Some(e) = self.entries.remove(&k) {
                    self.stats.vanished += 1;
                    let c = conn_of(k, &e);
                    let ifs = (e.ingress, e.egress);
                    self.flows(
                        &c,
                        e.reported,
                        e.seen,
                        e.seg_start,
                        now_ms,
                        EndReason::LackOfResources,
                        ifs,
                        out,
                    );
                }
            }
        }
    }

    /// Report what is pending of every followed connection (as last
    /// seen) and forget them: traffic flow turned off, the exporter
    /// stopping.
    pub fn flush(&mut self, now_ms: u64, out: &mut Vec<Record>) {
        let entries = std::mem::take(&mut self.entries);
        for (k, e) in entries {
            let c = conn_of(k, &e);
            let ifs = (e.ingress, e.egress);
            self.flows(
                &c,
                e.reported,
                e.seen,
                e.seg_start,
                now_ms,
                EndReason::Forced,
                ifs,
                out,
            );
        }
    }
}

/// A followed connection as last seen (no event at hand).
fn conn_of(k: Key, e: &Entry) -> Conn {
    Conn {
        id: k.0,
        protocol: k.1,
        orig: k.2,
        reply: e.reply,
        status: 0,
        timeout: 0,
        tcp_state: None,
        mark: 0,
        orig_packets: e.seen.op,
        orig_bytes: e.seen.ob,
        reply_packets: e.seen.rp,
        reply_bytes: e.seen.rb,
    }
}

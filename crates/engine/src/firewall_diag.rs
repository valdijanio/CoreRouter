//! Firewall diagnosis state (G2.1c): live rule counters and the packet
//! trace. Operational state, never config: kept in the session's
//! extensions (`Session::ext_mut`), lost on restart.
//!
//! **Counters.** The kernel is read by the daemon (service `fw-diag`), in
//! one netlink dump of the whole table, *outside* the session lock, and only
//! while someone looks (a counters or rule-list query in the last
//! [`WANT_SECS`]); [`Session::firewall_counters_feed`] then takes the lock
//! only for the hand-over, O(rules). A commit replaces the kernel table and
//! its counters restart at zero: a value lower than the last one is taken
//! as that restart and added to what was counted before, so the totals go
//! on across commits (the packets between the last read and the commit,
//! ≤ one interval, are lost). Reset (`…reset-counters`) keeps a base and
//! shows the difference, like RouterOS shows zero.
//!
//! **Trace.** `ip.firewall.trace.start` asks for a filter and a time and
//! event limit; the service turns `meta nftrace` on for that filter only (a
//! table of its own, `inet corerouter_trace`, rate-limited in the kernel),
//! listens to the kernel's trace events and hands them over here. Past the
//! deadline or the event cap it stops by itself and removes the table.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use corerouter_model::ItemId;
use corerouter_model::firewall::{AddrMatch, Family, Protocol, Table};

use crate::Session;

/// A counters query keeps the reads going this long.
pub const WANT_SECS: u64 = 30;
/// The daemon reads the kernel at most this often.
pub const INTERVAL_SECS: u64 = 2;
/// A rule unused this long is flagged as stale (default of `stale_days`).
pub const STALE_DAYS: u64 = 30;
/// Trace limits: at most this long and this many events.
pub const TRACE_MAX_SECS: u64 = 300;
pub const TRACE_DEFAULT_SECS: u64 = 60;
pub const TRACE_MAX_EVENTS: usize = 10_000;
pub const TRACE_DEFAULT_EVENTS: usize = 1000;
/// Packets per second the kernel marks for tracing at most (`limit rate`):
/// a flood matching the filter cannot flood the trace.
pub const TRACE_RATE: u32 = 20;

/// One kernel rule's counter, as read (the rules of one CoreRouter rule
/// summed: one per family or per address-list set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCounter {
    pub table: Table,
    pub id: ItemId,
    pub packets: u64,
    pub bytes: u64,
}

/// What the session keeps per rule.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Live {
    /// Totals across table replacements.
    pub packets: u64,
    pub bytes: u64,
    /// The kernel's last values (to see a restart) and the offset added.
    raw_packets: u64,
    raw_bytes: u64,
    off_packets: u64,
    off_bytes: u64,
    /// Rates over the last interval.
    pub pps: f64,
    pub bps: f64,
    /// Unix seconds when the packets last went up (`None`: not since the
    /// reads began).
    pub last_used: Option<u64>,
    /// Unix seconds of the first read of this rule.
    pub since: u64,
    /// Reset base.
    base_packets: u64,
    base_bytes: u64,
}

impl Live {
    pub fn shown_packets(&self) -> u64 {
        self.packets.saturating_sub(self.base_packets)
    }

    pub fn shown_bytes(&self) -> u64 {
        self.bytes.saturating_sub(self.base_bytes)
    }

    /// Seconds without a packet (since the first read when never seen).
    pub fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_used.unwrap_or(self.since))
    }
}

/// The trace filter: at least one field set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceFilter {
    pub family: Option<Family>,
    pub src: Option<AddrMatch>,
    pub dst: Option<AddrMatch>,
    pub protocol: Option<Protocol>,
    pub port: Option<u16>,
    pub in_interface: Option<String>,
}

impl TraceFilter {
    pub fn is_empty(&self) -> bool {
        self.src.is_none()
            && self.dst.is_none()
            && self.protocol.is_none()
            && self.port.is_none()
            && self.in_interface.is_none()
    }
}

/// One kernel trace event, mapped to our rules by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    /// The packet's trace id (the kernel's; one per packet).
    pub trace: u32,
    pub at: u64,
    /// `table`/`chain` as RouterOS names them (`filter`/`input`), or the
    /// kernel's chain name when it is not ours.
    pub table: String,
    pub chain: String,
    pub rule: Option<ItemId>,
    /// `rule`, `return` or `policy`.
    pub kind: &'static str,
    /// `accept`, `drop`, `continue`, `jump`, `return`…
    pub verdict: String,
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
}

/// What the service must do for a trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceJob {
    pub generation: u64,
    pub filter: TraceFilter,
    /// Unix seconds.
    pub until: u64,
    pub max_events: usize,
}

#[derive(Debug, Default)]
pub struct Trace {
    pub job: Option<TraceJob>,
    pub events: Vec<TraceEvent>,
    pub generation: u64,
    /// Why the last trace ended (`time`, `events`, `stopped`, an error).
    pub ended: Option<String>,
    pub started: Option<u64>,
}

/// The session extension.
#[derive(Debug, Default)]
pub struct FwDiag {
    pub want_until: Option<u64>,
    pub read_at: Option<u64>,
    /// Why the last read failed (shown instead of numbers).
    pub read_error: Option<String>,
    /// Shared with a rule list built outside the session lock (G0.31b).
    pub live: Arc<HashMap<(Table, ItemId), Live>>,
    pub trace: Trace,
}

impl Session {
    fn diag_now(&self) -> u64 {
        self.now().unwrap_or(0)
    }

    /// A query looked at the counters: keep the reads going.
    pub(crate) fn firewall_counters_want(&mut self) {
        let until = self.diag_now().saturating_add(WANT_SECS);
        if let Some(d) = self.ext_mut::<FwDiag>() {
            d.want_until = Some(until);
        }
    }

    /// Whether the daemon should read the counters now (someone looks, and
    /// the last read is at least [`INTERVAL_SECS`] old).
    pub fn firewall_counters_wanted(&self) -> bool {
        let now = self.diag_now();
        self.ext::<FwDiag>().is_some_and(|d| {
            d.want_until.is_some_and(|u| now < u)
                && d.read_at
                    .is_none_or(|t| now.saturating_sub(t) >= INTERVAL_SECS)
        })
    }

    /// Hand over a read of the kernel's counters (or why it failed).
    pub fn firewall_counters_feed(&mut self, read: Result<Vec<RuleCounter>, String>) {
        let now = self.diag_now();
        let Some(d) = self.ext_mut::<FwDiag>() else {
            return;
        };
        let dt = d.read_at.map(|t| now.saturating_sub(t)).filter(|t| *t > 0);
        d.read_at = Some(now);
        let read = match read {
            Ok(r) => r,
            Err(e) => {
                d.read_error = Some(e.chars().take(300).collect());
                return;
            }
        };
        d.read_error = None;
        // Sum the kernel rules of one CoreRouter rule first.
        let mut sums: BTreeMap<(Table, ItemId), (u64, u64)> = BTreeMap::new();
        for c in read {
            let e = sums.entry((c.table, c.id)).or_default();
            e.0 = e.0.saturating_add(c.packets);
            e.1 = e.1.saturating_add(c.bytes);
        }
        // Rules gone from the kernel go from the view too.
        let live = Arc::make_mut(&mut d.live);
        live.retain(|k, _| sums.contains_key(k));
        for (key, (packets, bytes)) in sums {
            let l = live.entry(key).or_insert_with(|| Live {
                since: now,
                raw_packets: packets,
                raw_bytes: bytes,
                packets,
                bytes,
                ..Live::default()
            });
            if packets < l.raw_packets {
                // The table was replaced (a commit): counting restarted.
                l.off_packets = l.off_packets.saturating_add(l.raw_packets);
                l.off_bytes = l.off_bytes.saturating_add(l.raw_bytes);
            }
            let total_p = l.off_packets.saturating_add(packets);
            let total_b = l.off_bytes.saturating_add(bytes);
            let dp = total_p.saturating_sub(l.packets);
            let db = total_b.saturating_sub(l.bytes);
            if dp > 0 {
                l.last_used = Some(now);
            }
            if let Some(dt) = dt {
                l.pps = dp as f64 / dt as f64;
                l.bps = db as f64 * 8.0 / dt as f64;
            }
            l.packets = total_p;
            l.bytes = total_b;
            l.raw_packets = packets;
            l.raw_bytes = bytes;
        }
    }

    /// Zero what `reset-counters` shows for `id` (all of `table` when
    /// `None`); how many rules.
    pub(crate) fn firewall_counters_reset(&mut self, table: Table, id: Option<ItemId>) -> usize {
        let now = self.diag_now();
        let Some(d) = self.ext_mut::<FwDiag>() else {
            return 0;
        };
        let mut n = 0;
        for ((t, i), l) in Arc::make_mut(&mut d.live).iter_mut() {
            if *t == table && id.is_none_or(|x| x == *i) {
                l.base_packets = l.packets;
                l.base_bytes = l.bytes;
                l.last_used = None;
                l.since = now;
                l.pps = 0.0;
                l.bps = 0.0;
                n += 1;
            }
        }
        n
    }

    /// The trace the daemon should run, if any (and still in time).
    pub fn firewall_trace_job(&self) -> Option<TraceJob> {
        self.ext::<FwDiag>()?.trace.job.clone()
    }

    /// Hand over trace events of `generation`; `false` once the trace is
    /// over (deadline, cap, stopped or replaced): the service then removes
    /// its table.
    pub fn firewall_trace_push(&mut self, generation: u64, events: Vec<TraceEvent>) -> bool {
        let now = self.diag_now();
        let Some(d) = self.ext_mut::<FwDiag>() else {
            return false;
        };
        let t = &mut d.trace;
        let Some(job) = t.job.as_ref().filter(|j| j.generation == generation) else {
            return false;
        };
        let (until, max) = (job.until, job.max_events);
        let room = max.saturating_sub(t.events.len());
        t.events.extend(events.into_iter().take(room));
        let end = if t.events.len() >= max {
            Some("events")
        } else if now >= until {
            Some("time")
        } else {
            None
        };
        if let Some(why) = end {
            t.job = None;
            t.ended = Some(why.into());
            return false;
        }
        true
    }

    /// The service could not trace (no nftables, no permission…).
    pub fn firewall_trace_failed(&mut self, generation: u64, why: &str) {
        if let Some(d) = self.ext_mut::<FwDiag>()
            && d.trace.job.as_ref().is_some_and(|j| j.generation == generation)
        {
            d.trace.job = None;
            d.trace.ended = Some(why.chars().take(300).collect());
        }
    }
}

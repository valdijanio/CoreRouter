//! The BNG of the `pppoe` service (G4.3d), without I/O: it takes frames,
//! the time and the running config, drives one `proto_pppoe::Server` per
//! `/interface pppoe-server server`, answers authentication (local
//! `/ppp secret`, or RADIUS through the G4.3j service) and addresses (its
//! own allocator over `/ip pool`), and returns frames to send and
//! [`Effect`]s for the driver (`pppoe.rs`): the XDP session map, the slow
//! path routes, hooks and address lists, which need the HAL or the
//! session lock. What the engine's commands read (`ppp.active.list`,
//! `ppp.why`, `ppp.history`) is kept in [`Shared`], behind its own lock.
//!
//! Driven by the service's thread only; RADIUS answers come back over a
//! channel ([`Bng::auth_inbox`]), so no callback ever touches the BNG.

// Only the Linux driver (`pppoe.rs`) runs the BNG.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_engine::ppp::{PppBackend, expand_hook};
use corerouter_engine::radius::{AaaBackend, AcctSource, SessionOwner};
use corerouter_hal::pppoe::{PppoeCounters, PppoeOp, PppoeSession, Rate};
use corerouter_model::MacAddr;
use corerouter_model::ip_pool::IpPools;
use corerouter_model::ppp::{
    ActiveSession, AddrOrPool, Effective, HistoryEntry, Ppp, PppAuth, PppHook, PppService,
    PppoeServer, ServiceStats, Stage, Why,
};
use corerouter_model::radius::{
    AaaService, AcctCounters, AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply,
    AuthRequest as RadiusRequest, CoaKind, CoaOutcome, CoaRequest, Credentials,
};
use corerouter_proto_pppoe::auth::AUTH_STRING_LEN;
use corerouter_proto_pppoe::discovery::{self, Code};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::ppp::{self as wire_ppp, proto};
use corerouter_proto_pppoe::server::{
    AuthMethod, AuthVerdict, Authorization, DownReason, Event, Ipv4Assignment, Ipv6Mode, Server,
    ServerConfig, ServerOutput, SessionRef, VlanFilter,
};
use corerouter_proto_pppoe::timer::Millis;
use corerouter_proto_pppoe::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;

use super::pppoe_bng6::{self as v6, Pools6, RadiusV6, Source, V6};

/// Lines kept by `ppp.history`: a mass reconnect of 20 k subscribers is
/// 40 k lines (**estimado**: 50 k × ~250 B = 12 MB).
pub(crate) const HISTORY: usize = 50_000;
/// Users and MACs `ppp.why` remembers: two per session the data plane
/// holds. Past it the oldest goes (a flood of MACs pushes out only what
/// nobody used since; G4.3g: clearing everything at 100 000 forgot every
/// subscriber each 50 000 logins).
pub(crate) const WHY_KEYS: usize = 2 * XDP_SLOTS as usize;
/// Slots of the XDP session map the PPPoE service may use: the lower half
/// of `dataplane-ebpf-common::pppoe::SESSIONS_MAX` (1 << 17). The upper half
/// is the IPoE service's (G4.3f, `ipoe_bng::SLOT_TOP` downward).
pub(crate) const XDP_SLOTS: u32 = 1 << 16;
/// A subscriber's address-list entry is made again this often (dynamic
/// entries last at most 35 days; the driver adds them for 35).
const LIST_REFRESH_MS: u64 = 30 * 86_400_000;
/// RADIUS answers older than this are dropped (the server gave up first).
const RADIUS_GRACE_MS: u64 = 35_000;

pub(crate) fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the driver must do outside the BNG.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Effect {
    /// The XDP session map (G4.3c).
    Xdp(PppoeOp),
    /// The slow path's /32 route to `bng0` (no XDP).
    Route { ip: Ipv4Addr, add: bool },
    /// Engine commands (hooks, address lists), run under the session lock.
    Run {
        command: String,
        params: serde_json::Value,
    },
    /// A dynamic firewall address-list entry for a subscriber's address.
    AddressList {
        list: String,
        ip: Ipv4Addr,
        add: bool,
        comment: String,
    },
    /// A line for the router's log (`ppp` topic), Portuguese.
    Log { error: bool, text: String },
}

/// The stages in order, for [`Track::attempts`].
const STAGES: [Stage; 6] = [
    Stage::Padi,
    Stage::Padr,
    Stage::Lcp,
    Stage::Auth,
    Stage::Ncp,
    Stage::Up,
];

/// Per-stage attempts of one user or MAC (`ppp.why`). Small: there is one
/// per user and one per MAC (the last failure or end only, boxed; a
/// subscriber that is up is in the active table).
#[derive(Debug, Clone, Default)]
struct Track {
    /// When it was last used ([`Shared::why_seq`]): what eviction looks at.
    seq: u64,
    attempts: [u32; 6],
    last_stage: Option<Stage>,
    last: Option<Box<HistoryEntry>>,
}

fn stage_index(s: Stage) -> usize {
    STAGES.iter().position(|x| *x == s).unwrap_or(0)
}

/// What the engine's commands and the RADIUS service read and ask.
#[derive(Default)]
pub(crate) struct Shared {
    pub active: BTreeMap<String, ActiveSession>,
    pub history: VecDeque<HistoryEntry>,
    /// Each worker's "Why?" table (its own lock: a MAC always comes to
    /// the same worker, and the workers do not wait on each other for it).
    whys: Vec<Arc<Mutex<WhyTable>>>,
    /// Sessions up by address (the identity chip, CGNAT's "Who was?").
    by_ip: HashMap<Ipv4Addr, String>,
    pub stats: ServiceStats,
    /// `ppp.active.remove` and Disconnect-Requests, for the next round.
    pub terminate: Vec<String>,
    /// CoA rate changes: session id, RouterOS rate-limit text.
    pub rates: Vec<(String, String)>,
    /// CoA address-list changes (`Mikrotik-Address-List`, the arrears
    /// notice): session id, list (empty: none).
    pub lists: Vec<(String, String)>,
    /// Acct-Session-Id → session id.
    by_acct: HashMap<String, String>,
    /// What each worker counts on its own (summed by [`Backend::stats`]).
    lanes: Vec<LaneStats>,
}

/// One worker's share of the service counters.
#[derive(Debug, Clone, Default)]
pub(crate) struct LaneStats {
    throttled: u64,
    admission_rate: u32,
    admission_reason: Option<String>,
    counts: Counts,
}

/// Discovery and login counters a worker keeps without the shared lock
/// (published once a second).
#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    padi: u64,
    pado: u64,
    padr: u64,
    pads: u64,
    padt_rx: u64,
    padt_tx: u64,
    auth_accept: u64,
    auth_reject: u64,
}

/// `ppp.why`'s memory of one worker: per user and per MAC.
#[derive(Default)]
pub(crate) struct WhyTable {
    /// The key is kept once, shared with `why_order`.
    why: HashMap<Arc<str>, Track>,
    /// Keys in the order they were used (a key used again is pushed again;
    /// the old place is skipped when popped): the oldest is evicted first.
    why_order: VecDeque<(Arc<str>, u64)>,
    why_seq: u64,
    /// [`WHY_KEYS`] (shared by the workers) unless a test sets it.
    why_cap: usize,
    lanes: usize,
}

impl WhyTable {
    fn track(&mut self, key: &str) -> Option<&mut Track> {
        let cap = if self.why_cap == 0 {
            WHY_KEYS / self.lanes.max(1)
        } else {
            self.why_cap
        };
        self.why_seq += 1;
        let seq = self.why_seq;
        let k: Arc<str> = match self.why.get_key_value(key) {
            Some((k, _)) => k.clone(),
            None => {
                while self.why.len() >= cap {
                    let Some((old, at)) = self.why_order.pop_front() else {
                        break;
                    };
                    if self.why.get(&old).is_some_and(|t| t.seq == at) {
                        self.why.remove(&old);
                    }
                }
                Arc::from(key)
            }
        };
        self.why_order.push_back((k.clone(), seq));
        if self.why_order.len() > 2 * cap + 1024 {
            // Mostly places of keys used again since: drop them.
            let why = &self.why;
            self.why_order
                .retain(|(k, at)| why.get(k).is_some_and(|t| t.seq == *at));
        }
        let t = self.why.entry(k).or_default();
        t.seq = seq;
        Some(t)
    }

    fn reach(&mut self, keys: &[&str], stage: Stage) {
        for k in keys {
            if let Some(t) = self.track(k) {
                if let Some(n) = t.attempts.get_mut(stage_index(stage)) {
                    *n = n.saturating_add(1);
                }
                t.last_stage = Some(stage);
            }
        }
    }

    fn record(&mut self, keys: &[&str], h: &HistoryEntry) {
        for k in keys {
            if let Some(t) = self.track(k) {
                if let Some(st) = h.stage {
                    t.last_stage = Some(st);
                }
                if h.event != "up" {
                    t.last = Some(Box::new(h.clone()));
                }
            }
        }
    }
}

impl Shared {
    fn record(&mut self, h: HistoryEntry) {
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(h);
    }
}

/// The [`PppBackend`] the engine gets: reads [`Shared`] only.
pub(crate) struct Backend(pub Arc<Mutex<Shared>>);

impl PppBackend for Backend {
    fn active(&self) -> Vec<ActiveSession> {
        guard(&self.0).active.values().cloned().collect()
    }

    fn active_page(
        &self,
        keep: &dyn Fn(&ActiveSession) -> bool,
        limit: usize,
    ) -> (usize, Vec<ActiveSession>) {
        let sh = guard(&self.0);
        let mut hits: Vec<&ActiveSession> = sh.active.values().filter(|a| keep(a)).collect();
        let total = hits.len();
        let order =
            |a: &&ActiveSession, b: &&ActiveSession| a.name.cmp(&b.name).then(a.id.cmp(&b.id));
        // The first `limit` without sorting the rest: O(n).
        if limit > 0 && limit < hits.len() {
            hits.select_nth_unstable_by(limit - 1, order);
            hits.truncate(limit);
        }
        hits.truncate(limit);
        hits.sort_by(order);
        (total, hits.into_iter().cloned().collect())
    }

    fn sessions_by_server(&self) -> std::collections::BTreeMap<String, usize> {
        let sh = guard(&self.0);
        let mut m = std::collections::BTreeMap::new();
        for a in sh.active.values() {
            match m.get_mut(&a.server) {
                Some(n) => *n += 1,
                None => {
                    m.insert(a.server.clone(), 1);
                }
            }
        }
        m
    }

    fn terminate(&self, ids: &[String]) -> usize {
        let mut sh = guard(&self.0);
        let found: Vec<String> = ids
            .iter()
            .filter(|i| sh.active.contains_key(*i))
            .cloned()
            .collect();
        let n = found.len();
        sh.terminate.extend(found);
        n
    }

    fn history(&self) -> Vec<HistoryEntry> {
        guard(&self.0).history.iter().cloned().collect()
    }

    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why {
        let (active, whys) = {
            let sh = guard(&self.0);
            let active = sh
                .active
                .values()
                .find(|a| {
                    name.is_some_and(|n| a.name == n)
                        || mac.is_some_and(|m| a.caller_id == m.to_string())
                })
                .map(|a| a.id.clone());
            (active, sh.whys.clone())
        };
        let key = name
            .map(str::to_owned)
            .or_else(|| mac.map(|m| m.to_string()))
            .unwrap_or_default();
        // A key may be in several workers' tables (a user from MACs that
        // hash apart): attempts add up, the newest end is the one shown.
        let lookup = |key: &str| -> Option<Track> {
            let mut out: Option<Track> = None;
            for w in &whys {
                let Some(t) = guard(w).why.get(key).cloned() else {
                    continue;
                };
                out = Some(match out {
                    None => t,
                    Some(mut o) => {
                        for (a, b) in o.attempts.iter_mut().zip(t.attempts) {
                            *a = a.saturating_add(b);
                        }
                        let newer = |x: &Track| x.last.as_ref().map_or(0, |l| l.at);
                        if newer(&t) > newer(&o) {
                            o.last = t.last;
                            o.last_stage = t.last_stage;
                        }
                        o
                    }
                });
            }
            out
        };
        let mut t = lookup(&key).unwrap_or_default();
        // Before authentication the user is not known: the discovery
        // stages of a user are those of the MAC it last came from.
        if name.is_some()
            && let Some(m) = t.last.as_ref().map(|l| l.caller_id.clone())
            && let Some(by_mac) = lookup(&m)
        {
            for st in [Stage::Padi, Stage::Padr, Stage::Lcp] {
                let i = stage_index(st);
                if let (Some(n), Some(slot)) = (by_mac.attempts.get(i), t.attempts.get_mut(i)) {
                    *slot = *n;
                }
            }
        }
        Why {
            query: key,
            active,
            attempts: STAGES
                .iter()
                .copied()
                .zip(t.attempts)
                .filter(|(_, n)| *n > 0)
                .collect(),
            last_stage: t.last_stage,
            last: t.last.map(|b| *b),
        }
    }

    fn stats(&self) -> ServiceStats {
        let sh = guard(&self.0);
        let mut st = sh.stats.clone();
        st.sessions = sh.active.len() as u64;
        // The workers' own counters (G4.3g): the limits are per worker, the
        // service's rate is their sum.
        st.throttled = sh.lanes.iter().map(|l| l.throttled).sum();
        let sum = |f: fn(&Counts) -> u64| sh.lanes.iter().map(|l| f(&l.counts)).sum::<u64>();
        st.padi = sum(|c| c.padi);
        st.pado = sum(|c| c.pado);
        st.padr = sum(|c| c.padr);
        st.pads = sum(|c| c.pads);
        st.padt_rx = sum(|c| c.padt_rx);
        st.padt_tx = sum(|c| c.padt_tx);
        st.auth_accept = sum(|c| c.auth_accept);
        st.auth_reject = sum(|c| c.auth_reject);
        st.admission_rate = sh.lanes.iter().map(|l| l.admission_rate).sum();
        st.admission_reason = sh.lanes.iter().find_map(|l| l.admission_reason.clone());
        st.workers = sh.lanes.len().max(1) as u32;
        st.ipv6_sessions = sh
            .active
            .values()
            .filter(|a| a.link_local.is_some())
            .count() as u64;
        st.delegated = sh.active.values().filter(|a| a.delegated_bound).count() as u64;
        st
    }

    fn who(&self, ip: Ipv4Addr) -> Option<String> {
        let sh = guard(&self.0);
        let id = sh.by_ip.get(&ip)?;
        sh.active.get(id).map(|a| a.name.clone())
    }

    fn who_at(&self, ip: Ipv4Addr, at: u64) -> Option<String> {
        let sh = guard(&self.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // A session that ended after `at` and began before it.
        sh.history
            .iter()
            .rev()
            .find(|h| {
                h.address == Some(ip)
                    && h.event == "down"
                    && h.at >= at
                    && h.at.saturating_sub(h.uptime_secs) <= at
            })
            .map(|h| h.name.clone())
            .or_else(|| {
                sh.active
                    .values()
                    .find(|a| a.address == Some(ip) && now.saturating_sub(a.uptime_secs) <= at)
                    .map(|a| a.name.clone())
            })
    }
}

/// The RADIUS CoA/Disconnect owner (RFC 5176): matches the selector
/// against the active sessions and queues the change for the BNG.
pub(crate) struct Owner(pub Arc<Mutex<Shared>>);

impl SessionOwner for Owner {
    fn name(&self) -> &str {
        "ppp"
    }

    fn handle(&self, req: &CoaRequest) -> CoaOutcome {
        let mut sh = guard(&self.0);
        let sel = &req.selector;
        let hits: Vec<String> = sh
            .active
            .values()
            .filter(|a| {
                sel.user_name.as_deref().is_none_or(|u| a.name == u)
                    && sel.framed_ip.is_none_or(|ip| a.address == Some(ip))
                    && sel
                        .calling_station_id
                        .as_deref()
                        .is_none_or(|c| a.caller_id.eq_ignore_ascii_case(&c.replace('-', ":")))
                    && sel
                        .nas_port_id
                        .as_deref()
                        .is_none_or(|n| a.interface == n || a.circuit_id.as_deref() == Some(n))
            })
            .filter(|a| {
                sel.acct_session_id
                    .as_deref()
                    .is_none_or(|s| sh.by_acct.get(s) == Some(&a.id))
            })
            .map(|a| a.id.clone())
            .collect();
        let empty = sel.user_name.is_none()
            && sel.framed_ip.is_none()
            && sel.calling_station_id.is_none()
            && sel.nas_port_id.is_none()
            && sel.acct_session_id.is_none();
        if hits.is_empty() || empty {
            return CoaOutcome::NotMine;
        }
        match req.kind {
            CoaKind::Disconnect => sh.terminate.extend(hits),
            CoaKind::Coa => {
                let rate = req
                    .changes
                    .iter()
                    .find(|a| a.name == "Mikrotik-Rate-Limit")
                    .map(|a| a.value.clone());
                let list = req
                    .changes
                    .iter()
                    .find(|a| a.name == "Mikrotik-Address-List")
                    .map(|a| a.value.clone());
                let new_ip = req.changes.iter().any(|a| a.name == "Framed-IP-Address");
                if new_ip {
                    // PPP cannot move an open IPCP to a new address: the
                    // subscriber reconnects and gets it.
                    sh.terminate.extend(hits);
                } else if rate.is_some() || list.is_some() {
                    let bad_list = list.as_deref().is_some_and(|l| {
                        !l.is_empty() && l.parse::<corerouter_model::firewall::Name>().is_err()
                    });
                    if rate
                        .as_deref()
                        .is_some_and(|r| r.parse::<RateLimit>().is_err())
                        || bad_list
                    {
                        return CoaOutcome::Nak(407); // Invalid Attribute Value
                    }
                    for h in hits {
                        if let Some(r) = &rate {
                            sh.rates.push((h.clone(), r.clone()));
                        }
                        if let Some(l) = &list {
                            sh.lists.push((h, l.clone()));
                        }
                    }
                } else if !req.authorize_only {
                    return CoaOutcome::Nak(401); // Unsupported Attribute
                }
            }
        }
        CoaOutcome::Ack
    }
}

/// Counters of one session for the RADIUS interims.
struct Counters {
    shared: Arc<Mutex<Shared>>,
    id: String,
}

impl AcctSource for Counters {
    fn counters(&self) -> Option<AcctCounters> {
        let sh = guard(&self.shared);
        let a = sh.active.get(&self.id)?;
        Some(acct_counters(a))
    }
}

fn acct_counters(a: &ActiveSession) -> AcctCounters {
    AcctCounters {
        // RFC 2866 §5.3/§5.4: from the NAS port's view: input = from the user.
        input_octets: a.rx_bytes,
        output_octets: a.tx_bytes,
        input_packets: a.rx_packets,
        output_packets: a.tx_packets,
        session_time: u32::try_from(a.uptime_secs).unwrap_or(u32::MAX),
    }
}

/// An `/ip pool` allocator of the PPP service. The pool's addresses the
/// DHCP server hands out are not seen here: a pool belongs to one of them.
#[derive(Default)]
struct Pools {
    used: HashSet<u32>,
    cursor: HashMap<String, u32>,
}

impl Pools {
    fn take(&mut self, pools: &IpPools, name: &str) -> Option<(Ipv4Addr, String)> {
        for p in pools.chain(name) {
            let size = p.size();
            if size == 0 {
                continue;
            }
            let start = self.cursor.get(&p.name).copied().unwrap_or(0);
            let mut i = 0u64;
            while i < size {
                let at = (u64::from(start) + i) % size;
                if let Some(ip) = nth(p, at)
                    && !self.used.contains(&u32::from(ip))
                {
                    self.used.insert(u32::from(ip));
                    self.cursor
                        .insert(p.name.clone(), u32::try_from((at + 1) % size).unwrap_or(0));
                    return Some((ip, p.name.clone()));
                }
                i += 1;
            }
        }
        None
    }

    fn hold(&mut self, ip: Ipv4Addr) -> bool {
        self.used.insert(u32::from(ip))
    }

    fn give_back(&mut self, ip: Ipv4Addr) {
        self.used.remove(&u32::from(ip));
    }
}

fn nth(p: &corerouter_model::ip_pool::IpPool, mut at: u64) -> Option<Ipv4Addr> {
    for r in &p.ranges {
        if at < r.len() {
            let base = u64::from(u32::from(r.start));
            return u32::try_from(base + at).ok().map(Ipv4Addr::from);
        }
        at -= r.len();
    }
    None
}

/// A token bucket of new sessions per second (`new_session_rate`).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    rate: u32,
    tokens: f64,
    at: Millis,
}

impl Bucket {
    fn new(rate: u32, now: Millis) -> Self {
        Self {
            rate,
            tokens: f64::from(rate.max(1)),
            at: now,
        }
    }

    fn allow(&mut self, now: Millis) -> bool {
        if self.rate == 0 {
            return true;
        }
        let dt = now.saturating_sub(self.at) as f64 / 1000.0;
        self.at = now;
        let cap = f64::from(self.rate);
        self.tokens = (self.tokens + dt * cap).min(cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Bucket {
    /// A new rate for the same bucket (`new_session_rate=auto`): the
    /// tokens saved so far stay, capped at the new size.
    fn set_rate(&mut self, rate: u32) {
        self.rate = rate;
        self.tokens = self.tokens.min(f64::from(rate.max(1)));
    }
}

/// `new_session_rate=auto` (G4.3g): the session rate follows the RADIUS
/// server's health, AIMD like TCP's window. It grows while answers come
/// fast and the limit is what holds the wave back, and halves when they
/// slow down or time out. A MK-Auth/IXC-class server is the usual
/// bottleneck of a mass reconnect: a fixed number either buries it or
/// keeps the CPEs waiting for nothing.
pub(crate) const AUTO_START: f64 = 1000.0;
pub(crate) const AUTO_MIN: f64 = 50.0;
/// The ceiling: what one BNG thread sets up (lab: ~10 000/s), doubled.
pub(crate) const AUTO_MAX: f64 = 20_000.0;
/// The second's p90 answer slower than this halves the rate…
const AUTO_SLOW_MS: u64 = 300;
/// …and faster than this lets it grow, by this much a second.
const AUTO_FAST_MS: u64 = 100;
const AUTO_STEP: f64 = 500.0;
/// Answers kept for the second's percentile.
const AUTO_SAMPLES: usize = 4096;
/// RADIUS questions in flight at most: the rate times this much time
/// (Little's law). The window holds a wave back while the server is
/// already busy, before its answers slow down (G4.3g: without it the
/// queue of a 3000/s server filled with questions nobody waited for any
/// more, and the latency the rate followed was the queue's).
const AUTO_WINDOW_MS: f64 = 300.0;
const AUTO_WINDOW_MIN: usize = 8;
/// The window before the server's capacity is measured.
const AUTO_WINDOW_START: usize = 64;

pub(crate) struct Admission {
    pub rate: f64,
    pub reason: String,
    /// Workers sharing the service's rate (each measures its own share).
    pub lanes: u16,
    latencies: Vec<u64>,
    timeouts: u32,
    held_before: u64,
    /// Logins answered per second, last seconds (the whole service's,
    /// estimated from this worker's share): the server's measured capacity.
    delivered: VecDeque<f64>,
    /// Fastest answer of each of the last seconds: the server's time with
    /// no queue in front of it.
    fastest: VecDeque<u64>,
    /// Still finding the server's capacity (rate doubling each second).
    startup: bool,
    best: f64,
    flat: u8,
    cycle: u8,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            rate: AUTO_START,
            reason: "início".into(),
            lanes: 1,
            latencies: Vec::new(),
            timeouts: 0,
            held_before: 0,
            delivered: VecDeque::new(),
            fastest: VecDeque::new(),
            startup: true,
            best: 0.0,
            flat: 0,
            cycle: 0,
        }
    }
}

/// Seconds of the RADIUS server's measured capacity that may wait in the
/// BNG (in the Authenticate phase) before PADIs are held back: well under
/// the 30 s a login may take (`answer_timeout_ms`).
const AUTO_BACKLOG_S: f64 = 10.0;
/// Seconds of history the capacity and the base latency look back over.
const AUTO_HISTORY: usize = 10;
/// BBR's gain cycle (1.25 to probe for more, 0.9 to drain what the probe
/// queued, then cruise), one step a second.
const AUTO_GAINS: [f64; 8] = [1.25, 0.9, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Admission {
    /// One RADIUS answer: its round trip, or that it never came.
    fn answer(&mut self, ms: u64, timeout: bool) {
        if timeout {
            self.timeouts = self.timeouts.saturating_add(1);
        } else if self.latencies.len() < AUTO_SAMPLES {
            self.latencies.push(ms);
        }
    }

    /// The server's capacity in logins a second, as measured (0: unknown).
    fn capacity(&self) -> f64 {
        self.delivered.iter().copied().fold(0.0, f64::max)
    }

    fn base_ms(&self) -> Option<u64> {
        self.fastest.iter().copied().min()
    }

    /// RADIUS questions this worker may have in flight (`lanes` workers
    /// share it): the bandwidth-delay product, the measured capacity times
    /// the base answer time (at least [`AUTO_WINDOW_MS`]), twice that while
    /// still probing, as BBR's cwnd gain; [`AUTO_WINDOW_START`] before any
    /// answer. Following the rate instead let the startup's
    /// doubling put 3.6× the server's capacity in flight (G4.3g, VM round
    /// 3: a 5503/s limit against ~1500 logins/s).
    fn window(&self, lanes: u16) -> usize {
        let cap = self.capacity();
        if cap == 0.0 {
            // Nothing measured yet: a small first window, as TCP's and
            // BBR's, that the first answers open. The starting rate's
            // (1000/s × 0.6 s) queued 2 s at a 300/s server, past the
            // client's 1.1 s timeout: a copy of every login.
            return (AUTO_WINDOW_START / usize::from(lanes.max(1))).max(AUTO_WINDOW_MIN);
        }
        let bw = cap;
        let gain = if self.startup { 2.0 } else { 1.0 };
        let base = self.base_ms().map_or(0.0, |b| b as f64).max(AUTO_WINDOW_MS);
        let share = bw / f64::from(lanes.max(1));
        ((share * gain * base / 1000.0) as usize).max(AUTO_WINDOW_MIN)
    }

    /// Logins this worker lets queue (sent or waiting for the window)
    /// before it holds PADIs back: [`AUTO_BACKLOG_S`] of the measured
    /// capacity, never under the window.
    fn backlog(&self, lanes: u16) -> usize {
        let share = self.capacity().max(self.rate) / f64::from(lanes.max(1));
        ((share * AUTO_BACKLOG_S) as usize).max(self.window(lanes))
    }

    /// Once a second. `held`: sessions the limit has held back so far;
    /// `pending`: questions still unanswered.
    ///
    /// Like BBR (Cardwell et al., 2016): the rate follows the measured
    /// capacity (answers per second, the best of the last
    /// [`AUTO_HISTORY`] s) with a gain, doubling while that capacity still
    /// grows; a standing queue (answers much slower than the base) drains
    /// it to 0.9×, a timeout cuts it to 0.75×. A plain AIMD on the latency
    /// alone halved itself into a slow crawl (G4.3g: 100 000 in 517 s
    /// against a 3000/s server).
    fn second(&mut self, held: u64, pending: usize) {
        let waiting = held > self.held_before;
        self.held_before = held;
        self.latencies.sort_unstable();
        let p90 = self
            .latencies
            .get(self.latencies.len().saturating_mul(9) / 10)
            .copied();
        let lanes = f64::from(self.lanes.max(1));
        let answered = self.latencies.len() as f64 * lanes;
        self.delivered.push_back(answered);
        if let Some(f) = self.latencies.first() {
            self.fastest.push_back(*f);
        }
        while self.delivered.len() > AUTO_HISTORY {
            self.delivered.pop_front();
        }
        while self.fastest.len() > AUTO_HISTORY {
            self.fastest.pop_front();
        }
        let cap = self.capacity();
        let base = self.base_ms();
        // A standing queue: the p90 well above what the server takes with
        // nothing in front (and above what anyone would call fast).
        let queued = match (p90, base) {
            (Some(p), Some(b)) => p > (2 * b + 50).max(AUTO_FAST_MS) || p > AUTO_SLOW_MS,
            (Some(p), None) => p > AUTO_SLOW_MS,
            _ => false,
        };
        if self.timeouts > 0 {
            self.startup = false;
            self.rate = (cap * 0.75).max(self.rate / 2.0).max(AUTO_MIN);
            self.reason = format!("RADIUS sem resposta: {} timeouts", self.timeouts);
        } else if p90.is_none() && pending > 0 {
            // A whole second with questions out and no answer at all.
            self.startup = false;
            self.rate = (self.rate / 2.0).max(AUTO_MIN);
            self.reason = format!("RADIUS parado: {pending} pedidos sem resposta");
        } else if queued {
            self.startup = false;
            let p = p90.unwrap_or(0);
            self.rate = if cap > 0.0 {
                cap * 0.9
            } else {
                self.rate / 2.0
            }
            .max(AUTO_MIN);
            self.reason = match base {
                Some(b) => format!("RADIUS lento: {p} ms (sem fila: {b} ms)"),
                None => format!("RADIUS lento: {p} ms"),
            };
        } else if !waiting {
            self.reason = "sem fila".into();
        } else if cap == 0.0 {
            // Local secrets, no RADIUS answers to measure: grow as before.
            self.rate = (self.rate + AUTO_STEP).min(AUTO_MAX);
            self.reason = "subindo: sem RADIUS no caminho".into();
        } else if self.startup {
            // Still finding the ceiling: twice what was answered, while that
            // keeps growing.
            if cap > self.best * 1.25 {
                self.best = cap;
                self.flat = 0;
            } else {
                self.flat += 1;
            }
            if self.flat >= 3 {
                self.startup = false;
            }
            self.rate = (cap * 2.0).clamp(AUTO_MIN, AUTO_MAX);
            self.reason = format!("subindo: RADIUS responde {cap:.0}/s");
        } else {
            let gain = AUTO_GAINS
                .get(usize::from(self.cycle))
                .copied()
                .unwrap_or(1.0);
            self.cycle = (self.cycle + 1) % AUTO_GAINS.len() as u8;
            self.rate = (cap * gain).clamp(AUTO_MIN, AUTO_MAX);
            self.reason = format!("na capacidade do RADIUS: {cap:.0}/s");
        }
        self.latencies.clear();
        self.timeouts = 0;
    }
}

/// Slow path: subscriber address → the worker holding it.
pub(crate) type Routes = Arc<std::sync::RwLock<HashMap<Ipv4Addr, u16>>>;

/// A worker's share of a per-second rate (0 = no limit stays 0).
fn share(rate: u32, lanes: u16) -> u32 {
    if rate == 0 {
        0
    } else {
        rate.div_ceil(u32::from(lanes.max(1))).max(1)
    }
}

/// A port the driver opened for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortInfo {
    pub ifindex: u32,
    pub mac: [u8; 6],
}

struct Slot {
    cfg: PppoeServer,
    port: PortInfo,
    server: Server,
    bucket: Bucket,
}

/// A session the BNG knows (from PADR to its Down).
struct Sub {
    slot: usize,
    sref: SessionRef,
    user: String,
    mac: Mac,
    stage: Stage,
    effective: Effective,
    radius: bool,
    /// The address and the pool it came from (`None`: fixed).
    ip: Option<Ipv4Addr>,
    pool: Option<String>,
    rate: Option<String>,
    acct_id: String,
    interim: Option<u32>,
    xdp: Option<u32>,
    up_at: Option<Millis>,
    limit_in: u64,
    limit_out: u64,
    session_timeout: Option<u32>,
    reply_message: Option<String>,
    /// Why it was ended here, when the reason is ours (idle, limit).
    cause: Option<(u32, &'static str)>,
    last_bytes: (u64, u64),
    /// Bytes and time of the last tick, for the rates.
    prev: (u64, u64, Millis),
    /// When its address-list entry was (re)made: dynamic entries last at
    /// most 35 days, so a longer session gets it made again.
    list_at: Millis,
    idle_since: Millis,
    descriptor_vlan: Option<u16>,
    /// The RADIUS question in flight, to call off if the session ends.
    auth_cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    circuit_id: Option<String>,
    remote_id: Option<String>,
    mtu: u16,
    /// G4.3e: what RADIUS said about IPv6, and the session's IPv6 once
    /// IPv6CP is up.
    radius6: RadiusV6,
    v6: Option<Box<V6>>,
}

/// What the hot paths look up in [`Bng::subs`] without walking it
/// (G4.3g: a walk per PADI, per login and per slow-path packet made a
/// session cost grow with the sessions up: 19 → 181 µs from 0 to 60 000).
#[derive(Default)]
struct SubIndex {
    /// Sessions up, by address: the slow path's downstream lookup.
    by_ip: HashMap<Ipv4Addr, (usize, u16)>,
    /// Sessions up per login: `only-one`.
    users_up: HashMap<String, u32>,
    /// Sessions between authentication and Up, per (slot, MAC): the PADI's
    /// `new_session_rate`.
    pending: HashMap<(usize, [u8; 6]), u32>,
}

impl SubIndex {
    fn add(&mut self, key: (usize, u16), sub: &Sub) {
        if sub.up_at.is_some() {
            *self.users_up.entry(sub.user.clone()).or_default() += 1;
            if let Some(ip) = sub.ip {
                self.by_ip.insert(ip, key);
            }
        } else {
            *self.pending.entry((sub.slot, sub.mac.0)).or_default() += 1;
        }
    }

    fn remove(&mut self, key: (usize, u16), sub: &Sub) {
        fn dec<K: std::hash::Hash + Eq>(m: &mut HashMap<K, u32>, k: &K) {
            if let Some(n) = m.get_mut(k) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
        if sub.up_at.is_some() {
            dec(&mut self.users_up, &sub.user);
            if let Some(ip) = sub.ip
                && self.by_ip.get(&ip) == Some(&key)
            {
                self.by_ip.remove(&ip);
            }
        } else {
            dec(&mut self.pending, &(sub.slot, sub.mac.0));
        }
    }
}

/// An answer for the server, queued while its events are handled.
enum Reply {
    Auth(AuthVerdict),
    Address(Option<Ipv4Assignment>),
    Terminate,
    Ipv6(Ipv6Mode),
}

/// A RADIUS answer on its way back to the BNG thread.
pub(crate) struct AuthDone {
    slot: usize,
    sref: SessionRef,
    asked: Millis,
    reply: AuthReply,
}

/// The running config the BNG follows.
#[derive(Clone, Default)]
pub(crate) struct Snapshot {
    pub ppp: Ppp,
    pub pools: IpPools,
    /// The daemon's RADIUS service, if any.
    pub aaa: Option<Arc<dyn AaaBackend>>,
    /// Unix time of `now` = 0 (the history's clock).
    pub unix_base: u64,
    /// G4.3e: `/ipv6 pool` (the profiles' IPv6 pools).
    pub pools6: Vec<corerouter_model::dhcp6_server::Ipv6Pool>,
    /// RFC 8064 secret of the IPv6CP identifiers (kept on disk by the
    /// driver, so a line keeps its link-local across restarts); `None`:
    /// one drawn from the seed, for this run.
    pub iid_key: Option<[u8; 32]>,
    /// G4.9b: `/queue type`s, for the profiles' download queue.
    pub queues: corerouter_model::queue::Queues,
}

pub(crate) struct Bng {
    slots: Vec<Slot>,
    subs: HashMap<(usize, u16), Sub>,
    /// Kept with `subs` (every insert, remove and Up goes through it).
    index: SubIndex,
    /// Shared by the workers: an address is lent once in the whole BNG.
    pools: Arc<Mutex<Pools>>,
    /// This worker's "Why?" table (also in `Shared::whys` for the reads).
    why: Arc<Mutex<WhyTable>>,
    /// Counters published in `tick` (no shared lock per frame).
    counts: Counts,
    /// This worker and how many there are (G4.3g): SESSION_IDs and XDP
    /// slots are split by `lane`, frames come by the client's MAC.
    lane: u16,
    lanes: u16,
    /// Slow path: which worker holds each subscriber address (the driver
    /// hands it the packets the kernel routes to `bng0`).
    routes: Routes,
    xdp_free: Vec<u32>,
    xdp_next: u32,
    pub shared: Arc<Mutex<Shared>>,
    pub effects: Vec<Effect>,
    /// Frames to send: (ifindex, bytes).
    pub frames: Vec<(u32, Vec<u8>)>,
    /// Slow path: subscribers' IPv4 packets for the stack.
    pub upstream: Vec<Vec<u8>>,
    replies: VecDeque<(usize, SessionRef, Reply)>,
    auth_tx: Sender<AuthDone>,
    auth_rx: Receiver<AuthDone>,
    pending_auth: usize,
    cfg: Snapshot,
    seq: u64,
    seed: [u8; 32],
    out: ServerOutput,
    /// The data plane takes the traffic (else the slow path does).
    pub xdp: bool,
    /// PADIs held back by `new_session_rate`.
    padr_throttled: u64,
    /// The rate of the servers with `new_session_rate=auto`.
    pub admission: Admission,
    /// auto: Access-Requests waiting for room in the window.
    auth_queue: VecDeque<(usize, SessionRef, RadiusRequest)>,
    queued_total: u64,
    /// G4.3e: the /64s and delegated prefixes the sessions hold.
    pools6: Arc<Mutex<Pools6>>,
    /// IPv6 packets refused before reaching a session's control plane.
    v6_dropped: u64,
}

/// One discovery or session frame's code and source, read before the
/// server sees it (`ppp.why` counts, the session-rate limit).
fn peek(frame: &[u8]) -> Option<(Code, Mac)> {
    let d = discovery::parse(frame).ok()?;
    Some((d.code, d.src))
}

fn mac_text(m: Mac) -> String {
    MacAddr(m.0).to_string()
}

fn auth_set(list: &[PppAuth]) -> AuthSet {
    let protos: Vec<AuthProto> = list
        .iter()
        .map(|a| match a {
            PppAuth::Mschap2 => AuthProto::MsChapV2,
            PppAuth::Mschap1 => AuthProto::MsChapV1,
            PppAuth::Chap => AuthProto::ChapMd5,
            PppAuth::Pap => AuthProto::Pap,
        })
        .collect();
    AuthSet::new(&protos)
}

/// `proto-pppoe`'s configuration for one server entry.
pub(crate) fn server_config(
    v: &PppoeServer,
    mac: [u8; 6],
    local: Option<Ipv4Addr>,
) -> ServerConfig {
    let mut c = ServerConfig {
        ac_mac: Mac(mac),
        ac_name: b"CoreRouter".to_vec(),
        service_names: if v.service_name.is_empty() {
            Vec::new()
        } else {
            vec![v.service_name.as_bytes().to_vec()]
        },
        one_session_per_host: v.one_session_per_host,
        auth: auth_set(&v.authentication),
        max_mru: v.max_mru,
        max_mtu: v.max_mtu,
        require_cookie: v.ac_cookie,
        padi_limit: v.padi_limit,
        mac_padi_limit: v.mac_padi_limit,
        local_ipv4: local,
        ..ServerConfig::default()
    };
    // RouterOS keepalive-timeout: echoes from timeout/2, gone after timeout.
    match v.keepalive_timeout {
        Some(t) => {
            c.keepalive_interval_ms = u64::from(t) * 500;
            c.keepalive_misses = 2;
        }
        None => c.keepalive_interval_ms = 0,
    }
    let mut tiers: Vec<(u32, u32)> = vec![(0, v.pado_delay)];
    tiers.extend(
        v.pado_delay_by_load
            .iter()
            .map(|t| (t.sessions, v.pado_delay.saturating_add(t.delay_ms))),
    );
    tiers.retain(|t| t.1 > 0);
    c.pado_delay = tiers;
    c.vlans = if v.pppoe_over_vlan_range.is_empty() {
        VlanFilter::Untagged
    } else {
        let mut r: Vec<std::ops::RangeInclusive<u16>> = v
            .pppoe_over_vlan_range
            .iter()
            .map(|x| x.first..=x.last)
            .collect();
        if v.accept_untagged {
            r.push(0..=0);
        }
        VlanFilter::Ranges(r)
    };
    c
}

/// The VLAN ids a server listens on (for the driver's sockets).
pub(crate) fn vlan_ids(v: &PppoeServer) -> Vec<u16> {
    v.pppoe_over_vlan_range
        .iter()
        .flat_map(|r| r.first..=r.last)
        .collect()
}

/// What a session ending means, for the log, the history and RADIUS.
pub(crate) fn explain(r: DownReason) -> (&'static str, &'static str, Stage, u32) {
    // (reason, hint in Portuguese, stage, RFC 2866 §5.10 Acct-Terminate-Cause)
    match r {
        DownReason::PeerPadt => (
            "peer-padt",
            "O CPE encerrou a sessão (PADT). Normal ao desligar; se repete em loop, veja o CPE.",
            Stage::Up,
            1,
        ),
        DownReason::PeerTerminate => (
            "peer-terminate",
            "O CPE pediu o fim do enlace (LCP Terminate-Request).",
            Stage::Up,
            1,
        ),
        DownReason::Admin => (
            "admin",
            "Desconectado pelo operador (ppp.active.remove) ou por um Disconnect/CoA do RADIUS.",
            Stage::Up,
            6,
        ),
        DownReason::AuthFailed => (
            "auth-failed",
            "Usuário ou senha recusados: confira o secret (ppp.secret.list) ou a mensagem do RADIUS.",
            Stage::Auth,
            17,
        ),
        DownReason::AuthTimeout => (
            "auth-timeout",
            "A autenticação não respondeu a tempo: RADIUS lento ou fora (radius.monitor), ou o CPE não mandou as credenciais.",
            Stage::Auth,
            17,
        ),
        DownReason::LcpFailed => (
            "lcp-failed",
            "O LCP não fechou: MRU/MTU ou método de autenticação que o CPE não aceita (authentication do servidor).",
            Stage::Lcp,
            8,
        ),
        DownReason::NcpFailed => (
            "ncp-failed",
            "Sem endereço IP: pool cheio ou sem remote_address no perfil (ip.pool.print).",
            Stage::Ncp,
            8,
        ),
        DownReason::Keepalive => (
            "keepalive",
            "O CPE parou de responder ao LCP echo: queda de energia, do enlace ou CPE travado.",
            Stage::Up,
            2,
        ),
        DownReason::SetupTimeout => (
            "setup-timeout",
            "A sessão não subiu em 60 s depois do PADS.",
            Stage::Lcp,
            8,
        ),
        DownReason::SessionTimeout => (
            "session-timeout",
            "Fim do tempo de sessão (session_timeout do perfil ou Session-Timeout do RADIUS).",
            Stage::Up,
            5,
        ),
        DownReason::Replaced => (
            "replaced",
            "Nova sessão do mesmo MAC (one-session-per-host): o CPE reiniciou sem mandar PADT.",
            Stage::Up,
            10,
        ),
    }
}

impl Bng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        let (auth_tx, auth_rx) = channel();
        let why = Arc::new(Mutex::new(WhyTable {
            lanes: 1,
            ..WhyTable::default()
        }));
        let shared = Arc::new(Mutex::new(Shared::default()));
        guard(&shared).whys.push(why.clone());
        Self {
            slots: Vec::new(),
            subs: HashMap::new(),
            index: SubIndex::default(),
            pools: Arc::new(Mutex::new(Pools::default())),
            lane: 0,
            lanes: 1,
            routes: Arc::new(std::sync::RwLock::new(HashMap::new())),
            xdp_free: Vec::new(),
            xdp_next: 0,
            shared,
            why,
            counts: Counts::default(),
            effects: Vec::new(),
            frames: Vec::new(),
            upstream: Vec::new(),
            replies: VecDeque::new(),
            auth_tx,
            auth_rx,
            pending_auth: 0,
            cfg: Snapshot::default(),
            seq: 0,
            seed,
            out: ServerOutput::new(),
            xdp: false,
            padr_throttled: 0,
            admission: Admission::default(),
            auth_queue: VecDeque::new(),
            queued_total: 0,
            pools6: Arc::new(Mutex::new(Pools6::default())),
            v6_dropped: 0,
        }
    }

    /// Worker `lane` of `lanes`, sharing this one's tables: the active
    /// table and history (`Shared`), the address pools and the slow path's
    /// routes. Its own servers, sessions and timers (G4.3g).
    pub(crate) fn sibling(&self, seed: [u8; 32], lane: u16, lanes: u16) -> Self {
        let mut b = Self::new(seed);
        b.shared = self.shared.clone();
        guard(&b.why).lanes = usize::from(lanes.max(1));
        guard(&b.shared).whys.push(b.why.clone());
        b.pools = self.pools.clone();
        b.pools6 = self.pools6.clone();
        b.routes = self.routes.clone();
        b.lane = lane;
        b.lanes = lanes.max(1);
        b.admission.lanes = b.lanes;
        b
    }

    /// The first of `lanes` workers.
    pub(crate) fn first_of(seed: [u8; 32], lanes: u16) -> Self {
        let mut b = Self::new(seed);
        b.lanes = lanes.max(1);
        b.admission.lanes = b.lanes;
        let n = usize::from(b.lanes);
        guard(&b.shared).lanes = vec![LaneStats::default(); n];
        guard(&b.why).lanes = n;
        b
    }

    /// The slow path's address → worker table, for the reader.
    pub(crate) fn clone_routes(&self) -> Routes {
        self.routes.clone()
    }

    /// The worker of slow-path address `ip`, if a session holds it.
    pub(crate) fn route_lane_in(routes: &Routes, ip: Ipv4Addr) -> Option<u16> {
        routes.read().ok().and_then(|r| r.get(&ip).copied())
    }

    /// The worker of a frame from a client (its source MAC; RSS-like): a
    /// multiplicative hash of the last four bytes of the MAC (frame bytes
    /// 8..12), so a vendor's shared OUI and a power-of-two `lanes` still
    /// spread.
    pub(crate) fn lane_of(frame: &[u8], lanes: u16) -> u16 {
        let b = |i: usize| frame.get(i).copied().unwrap_or(0);
        let k = u32::from_be_bytes([b(8), b(9), b(10), b(11)]);
        ((k.wrapping_mul(0x9E37_79B1) >> 16) % u32::from(lanes.max(1))) as u16
    }

    fn log(&mut self, error: bool, text: String) {
        self.effects.push(Effect::Log { error, text });
    }

    /// Servers the config wants, with what the driver must open.
    pub(crate) fn wanted(cfg: &Ppp) -> Vec<PppoeServer> {
        cfg.pppoe_servers
            .iter()
            .filter(|v| !v.disabled)
            .cloned()
            .collect()
    }

    /// Follow the config: `ports` has the port of each wanted server the
    /// driver opened (by server name). A server whose port or restart
    /// fields changed starts over (its sessions end); other changes reach
    /// new sessions.
    pub(crate) fn configure(
        &mut self,
        now: Millis,
        snap: Snapshot,
        ports: &HashMap<String, PortInfo>,
    ) {
        let wanted = Self::wanted(&snap.ppp);
        self.cfg = snap;
        // Servers gone or restarted: end their sessions.
        let mut keep: Vec<bool> = Vec::with_capacity(self.slots.len());
        for s in &self.slots {
            let same = wanted.iter().find(|w| w.id == s.cfg.id).is_some_and(|w| {
                w.interface == s.cfg.interface
                    && w.service_name == s.cfg.service_name
                    && w.pppoe_over_vlan_range == s.cfg.pppoe_over_vlan_range
                    && w.accept_untagged == s.cfg.accept_untagged
                    && ports.get(&w.name) == Some(&s.port)
            });
            keep.push(same);
        }
        let mut i = self.slots.len();
        while i > 0 {
            i -= 1;
            if keep.get(i).copied().unwrap_or(false) {
                continue;
            }
            self.drop_slot(now, i);
        }
        for w in wanted {
            let Some(port) = ports.get(&w.name).copied() else {
                continue;
            };
            let local = match self
                .cfg
                .ppp
                .profile(&w.default_profile)
                .and_then(|p| p.local_address)
            {
                Some(AddrOrPool::Address(ip)) => Some(ip),
                _ => None,
            };
            let mut sc = server_config(&w, port.mac, local);
            // G4.3g: this worker's share of the port's SESSION_IDs, of the
            // PADI limit and of the load the PADO delay looks at (a MAC
            // always comes to the same worker: its own limit stays).
            sc.sid_lane = (self.lane, self.lanes);
            let lanes = u32::from(self.lanes);
            if sc.padi_limit > 0 {
                sc.padi_limit = sc.padi_limit.div_ceil(lanes);
            }
            for t in &mut sc.pado_delay {
                t.0 = t.0.div_ceil(lanes);
            }
            // G4.3e: IPv6CP everywhere, each session as its profile says
            // (`Reply::Ipv6` before the verdict); identifiers stable per line.
            sc.ipv6 = true;
            sc.ipv6_iid_key = Some(self.cfg.iid_key.unwrap_or(self.seed));
            match self.slots.iter_mut().find(|s| s.cfg.id == w.id) {
                Some(s) => {
                    s.server.reconfigure(sc);
                    if w.new_session_rate_auto {
                        // The tick moves it; switching to auto keeps the
                        // tokens.
                        s.bucket
                            .set_rate(share(self.admission.rate as u32, self.lanes));
                    } else if s.bucket.rate != share(w.new_session_rate, self.lanes)
                        || s.cfg.new_session_rate_auto
                    {
                        s.bucket = Bucket::new(share(w.new_session_rate, self.lanes), now);
                    }
                    s.cfg = w;
                }
                None => {
                    let mut seed = self.seed;
                    if let Some(b) = seed.first_mut() {
                        *b ^= (self.slots.len() as u8).wrapping_add(1);
                    }
                    let name = w.name.clone();
                    let interface = w.interface.to_string();
                    let rate = share(
                        if w.new_session_rate_auto {
                            self.admission.rate as u32
                        } else {
                            w.new_session_rate
                        },
                        self.lanes,
                    );
                    self.slots.push(Slot {
                        bucket: Bucket::new(rate, now),
                        server: Server::new(sc, seed, now),
                        port,
                        cfg: w,
                    });
                    if self.lane == 0 {
                        self.log(
                            false,
                            format!("PPPoE: servidor {name} atendendo em {interface}"),
                        );
                    }
                }
            }
        }
    }

    /// Remove slot `i`, ending its sessions without frames (the port is
    /// gone or restarts: the CPEs reconnect after their keepalive or our
    /// PADT to their next frame).
    fn drop_slot(&mut self, now: Millis, i: usize) {
        let keys: Vec<(usize, u16)> = self.subs.keys().filter(|k| k.0 == i).copied().collect();
        for k in keys {
            if let Some(sub) = self.take_sub(k) {
                self.ended(now, sub, DownReason::Admin, true);
            }
        }
        if i < self.slots.len() {
            let s = self.slots.remove(i);
            if self.lane == 0 {
                self.log(false, format!("PPPoE: servidor {} parado", s.cfg.name));
            }
        }
        // Slots after `i` moved down one.
        let moved: Vec<((usize, u16), Sub)> = self
            .subs
            .drain()
            .map(|((slot, sid), mut sub)| {
                let slot = if slot > i { slot - 1 } else { slot };
                sub.slot = slot;
                ((slot, sid), sub)
            })
            .collect();
        self.subs.extend(moved);
        // The slots were renumbered: index again (a server removed, rare).
        self.index = SubIndex::default();
        for (k, sub) in &self.subs {
            self.index.add(*k, sub);
        }
    }

    /// Remove a session, keeping the index.
    fn take_sub(&mut self, key: (usize, u16)) -> Option<Sub> {
        let sub = self.subs.remove(&key)?;
        if let Some(c) = &sub.auth_cancel {
            c.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.index.remove(key, &sub);
        if sub.up_at.is_some()
            && let Some(ip) = sub.ip
            && let Ok(mut r) = self.routes.write()
            && r.get(&ip) == Some(&self.lane)
        {
            r.remove(&ip);
        }
        Some(sub)
    }

    /// The earliest time [`Bng::timers`] has work.
    pub(crate) fn next_deadline(&self) -> Option<Millis> {
        self.slots
            .iter()
            .filter_map(|s| s.server.next_deadline())
            .min()
    }

    pub(crate) fn waiting_radius(&self) -> bool {
        self.pending_auth > 0
    }

    /// A frame from the port `ifindex`.
    pub(crate) fn frame(&mut self, now: Millis, ifindex: u32, frame: &[u8]) {
        let Some(i) = self.slots.iter().position(|s| s.port.ifindex == ifindex) else {
            return;
        };
        if let Some((code, src)) = peek(frame) {
            let key = mac_text(src);
            let sessions = self.subs.len();
            let Some(slot) = self.slots.get_mut(i) else {
                return;
            };
            let full =
                slot.cfg.max_sessions > 0 && slot.server.active() >= slot.cfg.max_sessions as usize;
            match code {
                Code::Padi => {
                    self.counts.padi += 1;
                    guard(&self.why).reach(&[&key], Stage::Padi);
                    if full {
                        return;
                    }
                    // `new_session_rate` is spent at the PADI: no PADO, the
                    // CPE asks again (RFC 2516 §5.1: PADI retransmitted with
                    // back-off). At the PADR it would be worse: the CPE
                    // repeats the PADR with an AC-Cookie that expires.
                    let setting_up = self.index.pending.contains_key(&(i, src.0));
                    // auto: the limit is the RADIUS server's, applied to the
                    // logins queued here (about AUTO_BACKLOG_S of what it
                    // answers), not to the PADIs: a CPE told "no" backs off
                    // (RFC 2516 §5) and comes back late, idling the server.
                    let held = if slot.cfg.new_session_rate_auto {
                        let backlog = self.admission.backlog(self.lanes);
                        self.pending_auth + self.auth_queue.len() >= backlog
                    } else {
                        !slot.bucket.allow(now)
                    };
                    if !setting_up && held {
                        self.padr_throttled += 1;
                        return;
                    }
                }
                Code::Padr => {
                    self.counts.padr += 1;
                    if full {
                        return;
                    }
                    guard(&self.why).reach(&[&key], Stage::Padr);
                }
                Code::Padt => self.counts.padt_rx += 1,
                _ => {}
            }
            let _ = sessions;
        } else if let Ok(f) = wire_ppp::parse_session(frame)
            && matches!(f.protocol, proto::IPV4 | proto::IPV6)
        {
            if f.protocol == proto::IPV6 {
                // ND, DHCPv6 and Echo to our link-local (the XDP passes
                // link-local and multicast up, `Stat::Ipv6Control`).
                self.data6(now, i, &f);
            } else {
                // Slow path upstream: the XDP would have taken it.
                self.data_up(i, &f);
            }
            return;
        }
        self.run(now, i, |srv, out| {
            srv.handle_frame(now, ifindex, frame, out)
        });
    }

    /// Upstream IPv4 of a session without XDP: checked (the session and its
    /// address, the anti-spoofing of G4.3c) and counted; the driver sends
    /// the packet into the stack.
    fn data_up(&mut self, slot: usize, f: &wire_ppp::SessionFrame<'_>) {
        let Some(sub) = self.subs.get(&(slot, f.session_id)) else {
            return;
        };
        if sub.mac != f.link.src || sub.up_at.is_none() {
            return;
        }
        let src = f.info.get(12..16).map(|b| {
            Ipv4Addr::new(
                b.first().copied().unwrap_or(0),
                b.get(1).copied().unwrap_or(0),
                b.get(2).copied().unwrap_or(0),
                b.get(3).copied().unwrap_or(0),
            )
        });
        if src.is_none() || src != sub.ip {
            return;
        }
        let id = session_id(slot, &self.slots, f.session_id);
        let len = f.info.len() as u64;
        if let Some(a) = guard(&self.shared).active.get_mut(&id) {
            a.rx_bytes += len;
            a.rx_packets += 1;
        }
        self.upstream.push(f.info.to_vec());
    }

    /// A pseudo-random 32-bit value (RA spread; no security role).
    fn next_rand(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        let mut x = self.seq.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ u64::from_le_bytes(self.seed.first_chunk::<8>().copied().unwrap_or([7; 8]));
        x ^= x >> 29;
        x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        (x >> 32) as u32
    }

    /// G4.3e: IPv6CP opened on a session: take its /64 and delegated
    /// prefix (RADIUS over the profile, RFC 3162/4818/6911), start its RA
    /// and DHCPv6, and, if it was already up on IPv4, show and account
    /// the change (Interim-Update with the prefixes).
    fn start_v6(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        d: &corerouter_proto_pppoe::descriptor::SessionDescriptor,
    ) {
        let (Some(peer), Some(local)) = (d.ipv6_iid, d.local_iid) else {
            return;
        };
        let Some(port) = self.slots.get(i).map(|s| s.port) else {
            return;
        };
        let rand = self.next_rand();
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        if sub.v6.is_some() {
            return;
        }
        let mut problems: Vec<String> = Vec::new();
        let mut alloc = |fixed: Option<ipnet::Ipv6Net>, pool: Option<&str>, what: &str| {
            if let Some(n) = fixed {
                if guard(&self.pools6).hold(n) {
                    return Some((n, Source::Radius));
                }
                problems.push(format!("{what} {n} do RADIUS já está em uso"));
                return None;
            }
            let name = pool?;
            match guard(&self.pools6).take(&self.cfg.pools6, name) {
                Some(n) => Some((n, Source::Pool(name.to_owned()))),
                None => {
                    problems.push(format!("/ipv6 pool '{name}' sem {what} livre"));
                    None
                }
            }
        };
        let r = &sub.radius6;
        let e = &sub.effective;
        let link = alloc(
            r.framed_prefix,
            r.framed_pool
                .as_deref()
                .or(e.remote_ipv6_prefix_pool.as_deref()),
            "/64",
        );
        let delegated = alloc(
            r.delegated,
            r.delegated_pool.as_deref().or(e.dhcpv6_pd_pool.as_deref()),
            "prefixo delegado",
        );
        let dns = if r.dns.is_empty() {
            e.dns_server_ipv6.clone()
        } else {
            r.dns.clone()
        };
        let mut x = V6::new(
            now,
            local,
            peer,
            link,
            delegated,
            dns,
            e.dhcpv6_lease_time,
            d.mtu,
            port.mac,
        );
        // RFC 4861 §6.2.4: the first RA right away (the link just came up).
        if let Some(p) = x.due(now, rand) {
            self.frames.push((
                port.ifindex,
                v6::frame(sub.mac.0, port.mac, sub.descriptor_vlan, sref.sid, &p),
            ));
        }
        let user = sub.user.clone();
        let text = format!(
            "PPP: {user} com IPv6 (link-local {}{}{}{})",
            x.peer(),
            x.global()
                .map(|a| format!(", endereço {a}"))
                .unwrap_or_default(),
            x.link
                .as_ref()
                .map(|(n, _)| format!(", /64 {n}"))
                .unwrap_or_default(),
            x.delegated
                .as_ref()
                .map(|(n, _)| format!(", PD {n}"))
                .unwrap_or_default()
        );
        let was_up = sub.up_at.is_some();
        let attrs = x.acct_attributes();
        let acct = (sub.radius || self.cfg.ppp.aaa.use_radius) && self.cfg.ppp.aaa.accounting;
        let acct_id = sub.acct_id.clone();
        let interim = sub.interim;
        sub.v6 = Some(Box::new(x));
        let fields = sub.v6.as_deref().map(active_v6);
        let id = session_id(i, &self.slots, sref.sid);
        for p in problems {
            self.log(true, format!("PPP: {user}: {p}"));
        }
        self.log(false, text);
        if !was_up {
            // `up` puts the row and the Accounting-Start with these.
            return;
        }
        if let (Some(f), Some(a)) = (fields, guard(&self.shared).active.get_mut(&id)) {
            f.apply(a);
        }
        if acct && let Some(aaa) = &self.cfg.aaa {
            let req = AcctRequest {
                service: AaaService::Ppp,
                status: AcctStatus::InterimUpdate,
                session_id: acct_id,
                user: user.clone(),
                counters: None,
                terminate_cause: None,
                interim_secs: interim,
                attributes: attrs,
            };
            if let Err(e) = aaa.account(req, None) {
                self.log(
                    true,
                    format!("PPP: Accounting-Interim (IPv6) de {user} não enviado: {e}"),
                );
            }
        }
    }

    /// G4.3e: an IPv6 packet from a subscriber that reached the control
    /// plane (link-local or multicast with XDP; everything without it):
    /// RS, NS, Echo to our link-local and DHCPv6 are answered. Forwarded
    /// IPv6 on the slow path is G4.3l.
    fn data6(&mut self, now: Millis, i: usize, f: &wire_ppp::SessionFrame<'_>) {
        let Some(port) = self.slots.get(i).map(|s| s.port) else {
            return;
        };
        let rand = self.next_rand();
        let id = session_id(i, &self.slots, f.session_id);
        let Some(sub) = self.subs.get_mut(&(i, f.session_id)) else {
            self.v6_dropped += 1;
            return;
        };
        let Some(x) = sub.v6.as_deref_mut().filter(|_| sub.mac == f.link.src) else {
            self.v6_dropped += 1;
            return;
        };
        let before = x.dropped;
        let Some(out) = x.handle(now, f.info, rand) else {
            self.v6_dropped += 1;
            return;
        };
        self.v6_dropped += x.dropped - before;
        let changed = v6::pd_changed(&out.events);
        let bound = x.pd_bound();
        for p in &out.packets {
            self.frames.push((
                port.ifindex,
                v6::frame(sub.mac.0, port.mac, sub.descriptor_vlan, f.session_id, p),
            ));
        }
        let mut sh = guard(&self.shared);
        sh.stats.ipv6_dropped = self.v6_dropped;
        if changed && let Some(a) = sh.active.get_mut(&id) {
            a.delegated_bound = bound;
        }
    }

    /// G4.3e: the unsolicited RAs that are due (RFC 4861 §6.2.4), once a
    /// second.
    fn ra_tick(&mut self, now: Millis) {
        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut rand = self.next_rand();
        for ((slot, sid), sub) in self.subs.iter_mut() {
            let Some(x) = sub.v6.as_deref_mut() else {
                continue;
            };
            let Some(port) = self.slots.get(*slot).map(|s| s.port) else {
                continue;
            };
            rand = rand.rotate_left(7) ^ u32::from(*sid).wrapping_mul(0x9e37_79b9);
            if let Some(p) = x.due(now, rand) {
                due.push((
                    port.ifindex,
                    v6::frame(sub.mac.0, port.mac, sub.descriptor_vlan, *sid, &p),
                ));
            }
        }
        self.frames.extend(due);
    }

    /// Downstream IPv4 to a subscriber (slow path): encapsulated for its
    /// session, or dropped when nobody has the address.
    pub(crate) fn data_down(&mut self, packet: &[u8]) {
        let Some(dst) = packet.get(16..20) else {
            return;
        };
        let dst = Ipv4Addr::new(
            dst.first().copied().unwrap_or(0),
            dst.get(1).copied().unwrap_or(0),
            dst.get(2).copied().unwrap_or(0),
            dst.get(3).copied().unwrap_or(0),
        );
        let Some(((slot, sid), sub)) = self
            .index
            .by_ip
            .get(&dst)
            .and_then(|k| self.subs.get_key_value(k))
        else {
            return;
        };
        let Some(port) = self.slots.get(*slot).map(|s| s.port) else {
            return;
        };
        if packet.len() > usize::from(sub.mtu.max(576)) {
            return;
        }
        let mut f = Vec::with_capacity(packet.len() + 26);
        f.extend_from_slice(&sub.mac.0);
        f.extend_from_slice(&port.mac);
        if let Some(v) = sub.descriptor_vlan {
            f.extend_from_slice(&0x8100u16.to_be_bytes());
            f.extend_from_slice(&(v & 0x0FFF).to_be_bytes());
        }
        f.extend_from_slice(&0x8864u16.to_be_bytes());
        let len = u16::try_from(packet.len() + 2).unwrap_or(u16::MAX);
        f.extend_from_slice(&[0x11, 0x00]);
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(&len.to_be_bytes());
        f.extend_from_slice(&proto::IPV4.to_be_bytes());
        f.extend_from_slice(packet);
        let id = session_id(*slot, &self.slots, *sid);
        if let Some(a) = guard(&self.shared).active.get_mut(&id) {
            a.tx_bytes += packet.len() as u64;
            a.tx_packets += 1;
        }
        self.frames.push((port.ifindex, f));
    }

    /// Call server `i`, handle what it says, then the answers that
    /// produced, until nothing is left.
    fn run(&mut self, now: Millis, i: usize, f: impl FnOnce(&mut Server, &mut ServerOutput)) {
        let mut out = std::mem::take(&mut self.out);
        if let Some(slot) = self.slots.get_mut(i) {
            f(&mut slot.server, &mut out);
        }
        self.absorb(now, i, &mut out);
        while let Some((j, sref, reply)) = self.replies.pop_front() {
            if let Some(slot) = self.slots.get_mut(j) {
                let srv = &mut slot.server;
                match reply {
                    Reply::Auth(v) => {
                        srv.auth_reply(now, sref, v, &mut out);
                    }
                    Reply::Address(a) => {
                        srv.address_reply(now, sref, a, &mut out);
                    }
                    Reply::Terminate => {
                        srv.terminate(now, sref, &mut out);
                    }
                    Reply::Ipv6(m) => {
                        srv.set_ipv6(now, sref, m, &mut out);
                    }
                }
            }
            self.absorb(now, j, &mut out);
        }
        self.out = out;
    }

    fn absorb(&mut self, now: Millis, i: usize, out: &mut ServerOutput) {
        for (ifindex, f) in out.frames() {
            if let Ok(d) = discovery::parse(f) {
                match d.code {
                    Code::Pado => self.counts.pado += 1,
                    Code::Pads if d.session_id != 0 => {
                        self.counts.pads += 1;
                        guard(&self.why).reach(&[&mac_text(d.dst)], Stage::Lcp);
                    }
                    Code::Padt => self.counts.padt_tx += 1,
                    _ => {}
                }
            }
            self.frames.push((ifindex, f.to_vec()));
        }
        let events: Vec<Event> = std::mem::take(&mut out.events);
        out.clear();
        for ev in events {
            self.event(now, i, ev);
        }
    }

    fn event(&mut self, now: Millis, i: usize, ev: Event) {
        match ev {
            Event::Authenticate { session, request } => {
                self.authenticate(now, i, session, &request)
            }
            Event::NeedAddress { session } => {
                let a = self.subs.get_mut(&(i, session.sid)).and_then(|sub| {
                    let pool =
                        sub.pool
                            .clone()
                            .or_else(|| match &sub.effective.remote_address {
                                Some(AddrOrPool::Pool(p)) => Some(p.clone()),
                                _ => None,
                            })?;
                    let (ip, from) = guard(&self.pools).take(&self.cfg.pools, &pool)?;
                    sub.ip = Some(ip);
                    sub.pool = Some(from);
                    Some(assignment(ip, &sub.effective.dns_server))
                });
                self.replies.push_back((i, session, Reply::Address(a)));
            }
            Event::Up {
                session,
                descriptor,
            } => {
                // IPv6 first, so the Accounting-Start names the prefixes.
                self.start_v6(now, i, session, &descriptor);
                self.up(now, i, session, &descriptor);
            }
            Event::Changed {
                session,
                descriptor,
            } => {
                self.start_v6(now, i, session, &descriptor);
                if let Some(sub) = self.subs.get(&(i, session.sid))
                    && let Some(idx) = sub.xdp
                {
                    let shape = corerouter_engine::queue::shape_of(&self.cfg.queues, &sub.effective);
                    let s = xdp_session(&descriptor, sub.rate.as_deref(), sub.v6.as_deref(), shape);
                    self.effects.push(Effect::Xdp(PppoeOp::Upsert(idx, s)));
                }
            }
            Event::Down {
                session,
                key,
                reason,
                was_up,
                ..
            } => {
                if let Some(sub) = self.take_sub((i, session.sid)) {
                    self.ended(now, sub, reason, was_up);
                } else {
                    // Before authentication (LCP failed, setup timeout): no
                    // login yet, the MAC tells who.
                    self.failed_early(now, i, key.client_mac, reason);
                }
            }
        }
    }

    fn reject(&mut self, i: usize, sref: SessionRef, why: &str) {
        self.counts.auth_reject += 1;
        if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
            sub.reply_message = Some(why.to_owned());
        }
        self.replies.push_back((
            i,
            sref,
            Reply::Auth(AuthVerdict::Reject {
                message: why.as_bytes().into(),
            }),
        ));
    }

    fn authenticate(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
    ) {
        let user = String::from_utf8_lossy(&req.username).into_owned();
        let mac = req.client_mac;
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let default_profile = slot.cfg.default_profile.clone();
        let vlan = (req.vlans.outer != 0).then_some(req.vlans.outer);
        let fresh = Sub {
            slot: i,
            sref,
            user: user.clone(),
            mac,
            stage: Stage::Auth,
            effective: self
                .cfg
                .ppp
                .effective(None, &default_profile, &default_profile),
            radius: false,
            ip: None,
            pool: None,
            rate: None,
            acct_id: String::new(),
            interim: None,
            xdp: None,
            up_at: None,
            limit_in: 0,
            limit_out: 0,
            session_timeout: None,
            reply_message: None,
            cause: None,
            last_bytes: (0, 0),
            prev: (0, 0, now),
            list_at: now,
            idle_since: now,
            descriptor_vlan: vlan,
            auth_cancel: None,
            circuit_id: req
                .circuit_id
                .as_ref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
            remote_id: req
                .remote_id
                .as_ref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
            mtu: 1480,
            radius6: RadiusV6::default(),
            v6: None,
        };
        self.index.add((i, sref.sid), &fresh);
        if let Some(old) = self.subs.insert((i, sref.sid), fresh) {
            // Authenticated again (LCP renegotiated): the old entry's
            // place in the index goes.
            self.index.remove((i, sref.sid), &old);
        }
        guard(&self.why).reach(&[&user, &mac_text(mac)], Stage::Auth);
        // O(1): the list's name index (`corerouter_model::ppp_secrets`).
        match self.cfg.ppp.secret(&user).cloned() {
            Some(sec) if sec.disabled => self.reject(i, sref, "secret disabled"),
            Some(sec) => self.local(i, sref, req, &sec, &default_profile),
            None => match self.cfg.aaa.clone().filter(|_| self.cfg.ppp.aaa.use_radius) {
                Some(aaa) => self.ask_radius(now, i, sref, req, &user, &aaa),
                None => self.reject(i, sref, "no such user"),
            },
        }
    }

    fn local(
        &mut self,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
        sec: &corerouter_model::ppp::PppSecret,
        default_profile: &str,
    ) {
        if !sec.service.allows(PppService::Pppoe) {
            return self.reject(i, sref, "service not allowed for this secret");
        }
        if sec.caller_id.is_some_and(|m| m.0 != req.client_mac.0) {
            return self.reject(i, sref, "caller-id mismatch");
        }
        let e = self
            .cfg
            .ppp
            .effective(Some(sec), &sec.profile, default_profile);
        if e.only_one && self.index.users_up.contains_key(&sec.name) {
            return self.reject(i, sref, "only-one: the user is already connected");
        }
        let Some(mschap2) = req.verify_local(&sec.password) else {
            return self.reject(i, sref, "wrong password");
        };
        let (limit_in, limit_out) = (sec.limit_bytes_in, sec.limit_bytes_out);
        let fixed = match &e.remote_address {
            Some(AddrOrPool::Address(ip)) => Some(*ip),
            _ => None,
        };
        let pool = match &e.remote_address {
            Some(AddrOrPool::Pool(p)) => Some(p.clone()),
            _ => None,
        };
        let rate = e.rate_limit.clone();
        let timeout = e.session_timeout;
        if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
            sub.effective = e;
            sub.limit_in = limit_in;
            sub.limit_out = limit_out;
        }
        self.accept(i, sref, mschap2, fixed, pool, rate, timeout, false, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn accept(
        &mut self,
        i: usize,
        sref: SessionRef,
        mschap2: Option<[u8; AUTH_STRING_LEN]>,
        fixed: Option<Ipv4Addr>,
        pool: Option<String>,
        rate: Option<String>,
        timeout: Option<u32>,
        radius: bool,
        interim: Option<u32>,
    ) {
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        // A fixed address held by another session: refuse rather than
        // hand one address to two subscribers.
        let ipv4 = match fixed {
            Some(ip) if !guard(&self.pools).hold(ip) => {
                sub.reply_message = Some(format!("address {ip} is in use"));
                self.replies.push_back((
                    i,
                    sref,
                    Reply::Auth(AuthVerdict::Reject {
                        message: format!("address {ip} is in use").into_bytes().into(),
                    }),
                ));
                return;
            }
            Some(ip) => {
                sub.ip = Some(ip);
                Some(assignment(ip, &sub.effective.dns_server))
            }
            None => match pool
                .as_deref()
                .and_then(|p| guard(&self.pools).take(&self.cfg.pools, p))
            {
                Some((ip, from)) => {
                    sub.ip = Some(ip);
                    sub.pool = Some(from);
                    Some(assignment(ip, &sub.effective.dns_server))
                }
                // Asked again at IPCP (`NeedAddress`); none then = NCP fails.
                None => {
                    sub.pool = pool;
                    None
                }
            },
        };
        sub.rate = rate.clone();
        sub.radius = radius;
        sub.interim = interim;
        sub.session_timeout = timeout;
        self.counts.auth_accept += 1;
        let mode = match sub.effective.use_ipv6 {
            corerouter_model::ppp::UseIpv6::No => Ipv6Mode::Off,
            corerouter_model::ppp::UseIpv6::Require => Ipv6Mode::Require,
            _ => Ipv6Mode::On,
        };
        self.replies.push_back((i, sref, Reply::Ipv6(mode)));
        let auth = Authorization {
            mschap2_success: mschap2,
            message: Box::default(),
            ipv4,
            rate_limit: rate.as_deref().and_then(|r| r.parse::<RateLimit>().ok()),
            session_timeout: timeout,
        };
        self.replies
            .push_back((i, sref, Reply::Auth(AuthVerdict::Accept(auth))));
    }

    fn ask_radius(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
        user: &str,
        aaa: &Arc<dyn AaaBackend>,
    ) {
        let credentials = match &req.method {
            AuthMethod::Pap { password } => Credentials::Pap {
                password: String::from_utf8_lossy(password).into_owned(),
            },
            AuthMethod::Chap {
                id,
                challenge,
                response,
            } => Credentials::Chap {
                id: *id,
                challenge: challenge.to_vec(),
                response: response.to_vec(),
            },
            AuthMethod::MsChapV2 {
                id,
                challenge,
                response,
            } => Credentials::MsChapV2 {
                ident: *id,
                challenge: challenge.to_vec(),
                peer_challenge: response.peer_challenge.to_vec(),
                nt_response: response.nt_response.to_vec(),
            },
            AuthMethod::MsChapV1 { .. } => {
                return self.reject(
                    i,
                    sref,
                    "MS-CHAPv1 is not sent to RADIUS: use mschap2, chap or pap",
                );
            }
        };
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let circuit = req
            .circuit_id
            .as_ref()
            .map(|c| String::from_utf8_lossy(c).into_owned());
        let nas_port_id = match circuit {
            Some(c) if self.cfg.ppp.aaa.use_circuit_id_in_nas_port_id => c,
            _ => slot.cfg.interface.to_string(),
        };
        let r = RadiusRequest {
            service: AaaService::Ppp,
            user: user.to_owned(),
            credentials,
            nas_port_id: Some(nas_port_id),
            nas_port: Some(u32::from(sref.sid)),
            calling_station_id: Some(mac_text(req.client_mac)),
            called_station_id: (!slot.cfg.service_name.is_empty())
                .then(|| slot.cfg.service_name.clone()),
            // RFC 2865 §5.6 Framed (2), §5.7 PPP (1), §5.41 Virtual (5):
            // what a PPPoE NAS sends (RFC 4679 §4 for the DSL ones).
            attributes: vec![
                Attribute::new("Service-Type", "2"),
                Attribute::new("Framed-Protocol", "1"),
                Attribute::new("NAS-Port-Type", "5"),
            ],
        };
        // auto: no more questions out than the window; the rest wait here,
        // their CPEs in the Authenticate phase (repeats ignored while one
        // is pending), and go as answers come back.
        if self
            .slots
            .get(i)
            .is_some_and(|s| s.cfg.new_session_rate_auto)
            && self.pending_auth >= self.admission.window(self.lanes)
        {
            self.auth_queue.push_back((i, sref, r));
            self.queued_total += 1;
            return;
        }
        self.send_radius(now, i, sref, r, aaa);
    }

    /// One Access-Request out, called off if the session ends first.
    fn send_radius(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        r: RadiusRequest,
        aaa: &Arc<dyn AaaBackend>,
    ) {
        let tx = self.auth_tx.clone();
        self.pending_auth += 1;
        // Called off if the session ends first (the CPE gave up, LCP or the
        // setup timed out): the server is not spent on it (G4.3g).
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
            sub.auth_cancel = Some(cancel.clone());
        }
        aaa.authenticate_until(
            r,
            Box::new(move |reply| {
                // The BNG's thread reads it; nothing else happens here.
                let _ = tx.send(AuthDone {
                    slot: i,
                    sref,
                    asked: now,
                    reply,
                });
            }),
            cancel,
        );
    }

    /// Queued Access-Requests out while the window has room; those of
    /// sessions that ended meanwhile are dropped.
    fn drain_auth_queue(&mut self, now: Millis) {
        let Some(aaa) = self.cfg.aaa.clone() else {
            self.auth_queue.clear();
            return;
        };
        while self.pending_auth < self.admission.window(self.lanes) {
            let Some((i, sref, r)) = self.auth_queue.pop_front() else {
                break;
            };
            if self
                .subs
                .get(&(i, sref.sid))
                .is_some_and(|s| s.sref == sref && s.up_at.is_none())
            {
                self.send_radius(now, i, sref, r, &aaa);
            }
        }
    }

    /// RADIUS answers that arrived, then what the window lets out.
    pub(crate) fn radius(&mut self, now: Millis) {
        self.radius_answers(now);
        self.drain_auth_queue(now);
    }

    fn radius_answers(&mut self, now: Millis) {
        while let Ok(done) = self.auth_rx.try_recv() {
            self.pending_auth = self.pending_auth.saturating_sub(1);
            let late = now.saturating_sub(done.asked);
            self.admission.answer(
                late,
                matches!(done.reply.outcome, AuthOutcome::Timeout) || late > RADIUS_GRACE_MS,
            );
            let key = (done.slot, done.sref.sid);
            if self.subs.get(&key).is_none_or(|s| s.sref != done.sref)
                || now.saturating_sub(done.asked) > RADIUS_GRACE_MS
            {
                continue;
            }
            let (i, sref) = (done.slot, done.sref);
            let attr = |name: &str| {
                done.reply
                    .attributes
                    .iter()
                    .find(|a| a.name == name)
                    .map(|a| a.value.clone())
            };
            let message = attr("Reply-Message").or_else(|| done.reply.message.clone());
            if let Some(sub) = self.subs.get_mut(&key) {
                sub.reply_message = message.clone();
            }
            match done.reply.outcome {
                AuthOutcome::Accept => {
                    let profile = attr("Mikrotik-Group");
                    let default_profile = self
                        .slots
                        .get(i)
                        .map(|s| s.cfg.default_profile.clone())
                        .unwrap_or_default();
                    let e = self.cfg.ppp.effective(
                        None,
                        profile.as_deref().unwrap_or(&default_profile),
                        &default_profile,
                    );
                    let fixed = attr("Framed-IP-Address").and_then(|v| v.parse::<Ipv4Addr>().ok());
                    let pool = attr("Framed-Pool").or(match &e.remote_address {
                        Some(AddrOrPool::Pool(p)) => Some(p.clone()),
                        _ => None,
                    });
                    let fixed = fixed.or(match &e.remote_address {
                        Some(AddrOrPool::Address(ip)) if pool.is_none() => Some(*ip),
                        _ => None,
                    });
                    let rate = attr("Mikrotik-Rate-Limit")
                        .filter(|r| r.parse::<RateLimit>().is_ok())
                        .or(e.rate_limit.clone());
                    let timeout = attr("Session-Timeout")
                        .and_then(|v| v.parse::<u32>().ok())
                        .or(e.session_timeout);
                    let interim = attr("Acct-Interim-Interval").and_then(|v| v.parse::<u32>().ok());
                    let mschap2 = attr("MS-CHAP2-Success").and_then(|v| success_string(&v));
                    let list = attr("Mikrotik-Address-List");
                    let r6 = RadiusV6::of(
                        done.reply
                            .attributes
                            .iter()
                            .map(|a| (a.name.as_str(), a.value.as_str())),
                    );
                    if let Some(sub) = self.subs.get_mut(&key) {
                        sub.radius6 = r6;
                        sub.effective = e;
                        if list.is_some() {
                            sub.effective.address_list = list;
                        }
                    }
                    self.accept(i, sref, mschap2, fixed, pool, rate, timeout, true, interim);
                }
                AuthOutcome::Reject | AuthOutcome::Challenge => {
                    let m = message.unwrap_or_else(|| "rejected by RADIUS".into());
                    self.reject(i, sref, &m);
                }
                AuthOutcome::Timeout | AuthOutcome::Error => {
                    let m = message.unwrap_or_else(|| "RADIUS did not answer".into());
                    self.reject(i, sref, &format!("RADIUS: {m}"));
                }
            }
            self.run(now, i, |_, _| {});
        }
    }

    fn up(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        d: &corerouter_proto_pppoe::descriptor::SessionDescriptor,
    ) {
        let id = session_id(i, &self.slots, sref.sid);
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let server = slot.cfg.name.clone();
        let interface = slot.cfg.interface.to_string();
        let unix = self.cfg.unix_base + now / 1000;
        self.seq += 1;
        let acct_id = format!("{:08X}{:04X}", unix as u32, self.seq as u16);
        let xdp = if self.xdp { self.slot_index() } else { None };
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        self.index.remove((i, sref.sid), sub);
        sub.up_at = Some(now);
        sub.list_at = now;
        sub.stage = Stage::Up;
        sub.idle_since = now;
        sub.acct_id = acct_id.clone();
        sub.mtu = d.mtu;
        sub.xdp = xdp;
        if sub.ip.is_none() {
            sub.ip = d.ipv4;
        }
        self.index.add((i, sref.sid), sub);
        if xdp.is_none()
            && let Some(ip) = sub.ip
            && let Ok(mut r) = self.routes.write()
        {
            r.insert(ip, self.lane);
        }
        let ip = sub.ip;
        let user = sub.user.clone();
        let mac = mac_text(sub.mac);
        match xdp {
            Some(idx) => self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                idx,
                xdp_session(
                    d,
                    sub.rate.as_deref(),
                    sub.v6.as_deref(),
                    corerouter_engine::queue::shape_of(&self.cfg.queues, &sub.effective),
                ),
            ))),
            None => {
                if let Some(ip) = ip {
                    self.effects.push(Effect::Route { ip, add: true });
                }
            }
        }
        let a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "pppoe".into(),
            caller_id: mac.clone(),
            address: ip,
            session_id: sref.sid,
            server: server.clone(),
            interface: interface.clone(),
            vlan: sub.descriptor_vlan,
            circuit_id: sub.circuit_id.clone(),
            remote_id: sub.remote_id.clone(),
            rate_limit: sub.rate.clone(),
            profile: sub.effective.profile.clone(),
            encoding: d
                .auth
                .map(|a| match a {
                    AuthProto::Pap => "pap",
                    AuthProto::ChapMd5 => "chap",
                    AuthProto::MsChapV1 => "mschap1",
                    AuthProto::MsChapV2 => "mschap2",
                })
                .unwrap_or("none")
                .into(),
            radius: sub.radius,
            mtu: d.mtu,
            limit_bytes_in: (sub.limit_in > 0).then_some(sub.limit_in),
            limit_bytes_out: (sub.limit_out > 0).then_some(sub.limit_out),
            ..ActiveSession::default()
        };
        let mut a = a;
        if let Some(f) = sub.v6.as_deref().map(active_v6) {
            f.apply(&mut a);
        }
        let v6_attrs = sub
            .v6
            .as_deref()
            .map(V6::acct_attributes)
            .unwrap_or_default();
        let radius_acct = sub.radius || self.cfg.ppp.aaa.use_radius;
        let interim = sub.interim;
        let list = sub.effective.address_list.clone();
        let hooks = sub.effective.on_up.clone();
        {
            let h = HistoryEntry {
                at: unix,
                name: user.clone(),
                caller_id: mac.clone(),
                server: server.clone(),
                event: "up".into(),
                stage: Some(Stage::Up),
                address: ip,
                ..HistoryEntry::default()
            };
            {
                let mut w = guard(&self.why);
                w.reach(&[&user, &mac], Stage::Up);
                w.record(&[&user, &mac], &h);
            }
            let mut sh = guard(&self.shared);
            sh.active.insert(id.clone(), a);
            sh.by_acct.insert(acct_id.clone(), id.clone());
            if let Some(ip) = ip {
                sh.by_ip.insert(ip, id.clone());
            }
            sh.record(h);
        }
        if radius_acct
            && self.cfg.ppp.aaa.accounting
            && let Some(aaa) = &self.cfg.aaa
        {
            let src: Arc<dyn AcctSource> = Arc::new(Counters {
                shared: self.shared.clone(),
                id: id.clone(),
            });
            let req = AcctRequest {
                service: AaaService::Ppp,
                status: AcctStatus::Start,
                session_id: acct_id,
                user: user.clone(),
                counters: None,
                terminate_cause: None,
                interim_secs: interim,
                attributes: {
                    let mut a = acct_attributes(ip, &mac, &interface);
                    a.extend(v6_attrs);
                    a
                },
            };
            if let Err(e) = aaa.account(req, Some(src)) {
                self.log(
                    true,
                    format!("PPP: Accounting-Start de {user} não enviado: {e}"),
                );
            }
        }
        if let (Some(l), Some(ip)) = (list, ip) {
            self.effects.push(Effect::AddressList {
                list: l,
                ip,
                add: true,
                comment: format!("ppp {user}"),
            });
        }
        self.hooks(&hooks, &user, ip, &mac, &interface);
        self.log(
            false,
            format!(
                "PPP: {user} conectado ({mac}, {}, {server})",
                ip.map_or_else(|| "sem IPv4".into(), |i| i.to_string())
            ),
        );
    }

    fn hooks(
        &mut self,
        hooks: &[PppHook],
        user: &str,
        ip: Option<Ipv4Addr>,
        mac: &str,
        interface: &str,
    ) {
        let local = match self
            .cfg
            .ppp
            .profile(corerouter_model::ppp::DEFAULT_PROFILE)
            .and_then(|p| p.local_address)
        {
            Some(AddrOrPool::Address(ip)) => ip.to_string(),
            _ => String::new(),
        };
        let vars = [
            ("$user", user.to_owned()),
            (
                "$remote-address",
                ip.map(|i| i.to_string()).unwrap_or_default(),
            ),
            ("$local-address", local),
            ("$caller-id", mac.to_owned()),
            ("$interface", interface.to_owned()),
            ("$service", "pppoe".to_owned()),
        ];
        for h in hooks {
            self.effects.push(Effect::Run {
                command: h.command.clone(),
                params: expand_hook(&h.params, &vars),
            });
        }
    }

    /// A free XDP slot of this worker's lane (slots `lane`, `lane +
    /// lanes`, …: no lock between workers).
    fn slot_index(&mut self) -> Option<u32> {
        if let Some(i) = self.xdp_free.pop() {
            return Some(i);
        }
        let idx = self
            .xdp_next
            .checked_mul(u32::from(self.lanes))?
            .checked_add(u32::from(self.lane))?;
        (idx < XDP_SLOTS).then(|| {
            self.xdp_next += 1;
            idx
        })
    }

    /// A session is gone: undo everything [`Bng::up`] did.
    fn ended(&mut self, now: Millis, sub: Sub, reason: DownReason, was_up: bool) {
        let (mut key, mut hint, stage, mut cause) = explain(reason);
        if let Some((c, k)) = sub.cause {
            cause = c;
            key = k;
            hint = match k {
                "idle-timeout" => "Sem tráfego pelo idle_timeout do perfil.",
                "limit-bytes" => "Atingiu limit_bytes_in/out do secret.",
                _ => hint,
            };
        }
        let id = session_id(sub.slot, &self.slots, sub.sref.sid);
        if let Some(idx) = sub.xdp {
            self.effects.push(Effect::Xdp(PppoeOp::Remove(idx)));
            self.xdp_free.push(idx);
        } else if let (Some(ip), true) = (sub.ip, was_up) {
            self.effects.push(Effect::Route { ip, add: false });
        }
        if let Some(ip) = sub.ip {
            guard(&self.pools).give_back(ip);
        }
        if let Some(x) = &sub.v6 {
            for (n, src) in [&x.link, &x.delegated].into_iter().flatten() {
                let pool = match src {
                    Source::Pool(p) => Some(p.as_str()),
                    Source::Radius => None,
                };
                guard(&self.pools6).give_back(*n, pool);
            }
        }
        let mac = mac_text(sub.mac);
        let server = self
            .slots
            .get(sub.slot)
            .map(|s| s.cfg.name.clone())
            .unwrap_or_default();
        let interface = self
            .slots
            .get(sub.slot)
            .map(|s| s.cfg.interface.to_string())
            .unwrap_or_default();
        let unix = self.cfg.unix_base + now / 1000;
        let gone = {
            let mut sh = guard(&self.shared);
            let gone = sh.active.remove(&id);
            sh.by_acct.remove(&sub.acct_id);
            if let Some(ip) = sub.ip
                && sh.by_ip.get(&ip) == Some(&id)
            {
                sh.by_ip.remove(&ip);
            }
            gone
        };
        let uptime = sub.up_at.map_or(0, |t| now.saturating_sub(t) / 1000);
        if was_up {
            if (sub.radius || self.cfg.ppp.aaa.use_radius)
                && self.cfg.ppp.aaa.accounting
                && let Some(aaa) = &self.cfg.aaa
            {
                let mut counters = gone.as_ref().map(acct_counters).unwrap_or_default();
                counters.session_time = u32::try_from(uptime).unwrap_or(u32::MAX);
                let req = AcctRequest {
                    service: AaaService::Ppp,
                    status: AcctStatus::Stop,
                    session_id: sub.acct_id.clone(),
                    user: sub.user.clone(),
                    counters: Some(counters),
                    terminate_cause: Some(cause),
                    interim_secs: None,
                    attributes: {
                        let mut a = acct_attributes(sub.ip, &mac, &interface);
                        if let Some(x) = &sub.v6 {
                            a.extend(x.acct_attributes());
                        }
                        a
                    },
                };
                if let Err(e) = aaa.account(req, None) {
                    self.log(
                        true,
                        format!("PPP: Accounting-Stop de {} não enviado: {e}", sub.user),
                    );
                }
            }
            if let (Some(l), Some(ip)) = (&sub.effective.address_list, sub.ip) {
                self.effects.push(Effect::AddressList {
                    list: l.clone(),
                    ip,
                    add: false,
                    comment: String::new(),
                });
            }
            let hooks = sub.effective.on_down.clone();
            self.hooks(&hooks, &sub.user, sub.ip, &mac, &interface);
        }
        let failed_stage = if was_up {
            Stage::Up
        } else if stage == Stage::Up {
            sub.stage
        } else {
            stage
        };
        let h = HistoryEntry {
            at: unix,
            name: sub.user.clone(),
            caller_id: mac.clone(),
            server,
            event: if was_up {
                "down".into()
            } else {
                "failed".into()
            },
            stage: Some(failed_stage),
            reason: key.into(),
            hint: hint.into(),
            reply_message: sub.reply_message.clone(),
            address: sub.ip,
            uptime_secs: uptime,
            rx_bytes: gone.as_ref().map_or(0, |a| a.rx_bytes),
            tx_bytes: gone.as_ref().map_or(0, |a| a.tx_bytes),
        };
        guard(&self.why).record(&[&sub.user, &mac], &h);
        guard(&self.shared).record(h);
        if was_up {
            self.log(
                false,
                format!("PPP: {} desconectado ({key}, {uptime} s): {hint}", sub.user),
            );
        } else {
            let msg = sub
                .reply_message
                .as_deref()
                .map(|m| format!(" — {m}"))
                .unwrap_or_default();
            self.log(
                false,
                format!(
                    "PPP: login de {} ({mac}) falhou em {}{msg}: {hint}",
                    sub.user,
                    failed_stage.as_str()
                ),
            );
        }
    }

    /// A session that ended before authentication: the history line and
    /// the "Why?" of its MAC.
    fn failed_early(&mut self, now: Millis, i: usize, mac: Mac, reason: DownReason) {
        let (mut key, mut hint, stage, _) = explain(reason);
        let mut stage = if stage == Stage::Up {
            Stage::Lcp
        } else {
            stage
        };
        if reason == DownReason::AuthFailed {
            // No credentials ever came: the CPE refused every method the
            // server offered in LCP (RFC 1661 §6.2, Authentication-Protocol).
            key = "auth-protocol";
            hint = "O CPE recusou todos os métodos de autenticação do servidor no LCP: habilite no servidor (authentication) um que o CPE aceite, como chap ou pap.";
            stage = Stage::Lcp;
        }
        let mac = mac_text(mac);
        let server = self
            .slots
            .get(i)
            .map(|s| s.cfg.name.clone())
            .unwrap_or_default();
        let h = HistoryEntry {
            at: self.cfg.unix_base + now / 1000,
            name: String::new(),
            caller_id: mac.clone(),
            server,
            event: "failed".into(),
            stage: Some(stage),
            reason: key.into(),
            hint: hint.into(),
            ..HistoryEntry::default()
        };
        guard(&self.why).record(&[&mac], &h);
        guard(&self.shared).record(h);
        self.log(
            false,
            format!("PPP: sessão de {mac} caiu antes do login ({key}): {hint}"),
        );
    }

    /// The servers' timers.
    pub(crate) fn timers(&mut self, now: Millis) {
        for i in 0..self.slots.len() {
            let due = self
                .slots
                .get(i)
                .and_then(|s| s.server.next_deadline())
                .is_some_and(|d| d <= now);
            if due {
                self.run(now, i, |srv, out| srv.handle_timers(now, out));
            }
        }
    }

    /// Once a second: counters (from XDP when it carries the traffic),
    /// uptime, idle and byte limits, and what the commands and the RADIUS
    /// service asked for.
    pub(crate) fn tick(&mut self, now: Millis, xdp: &[(u32, PppoeCounters)]) {
        self.ra_tick(now);
        let by_idx: HashMap<u32, PppoeCounters> = xdp.iter().copied().collect();
        // PADIs the servers' limiters held back count as throttled too.
        let limited: u64 = self
            .slots
            .iter()
            .map(|s| s.server.stats().padi_limited)
            .sum();
        let throttled = self.padr_throttled + limited;
        // new_session_rate=auto: one AIMD step a second.
        self.admission
            .second(self.padr_throttled + self.queued_total, self.pending_auth);
        let rate = share(self.admission.rate as u32, self.lanes);
        let mut auto = false;
        for s in self
            .slots
            .iter_mut()
            .filter(|s| s.cfg.new_session_rate_auto)
        {
            s.bucket.set_rate(rate);
            auto = true;
        }
        {
            let mut sh = guard(&self.shared);
            let lane = usize::from(self.lane);
            if sh.lanes.len() <= lane {
                sh.lanes.resize(lane + 1, LaneStats::default());
            }
            if let Some(l) = sh.lanes.get_mut(lane) {
                *l = LaneStats {
                    throttled,
                    admission_rate: if auto { rate } else { 0 },
                    admission_reason: auto.then(|| self.admission.reason.clone()),
                    counts: self.counts,
                };
            }
        }
        let mut ending: Vec<(usize, SessionRef, (u32, &'static str))> = Vec::new();
        {
            let mut sh = guard(&self.shared);
            for ((slot, sid), sub) in self.subs.iter_mut() {
                let Some(up) = sub.up_at else { continue };
                let id = session_id(*slot, &self.slots, *sid);
                let Some(a) = sh.active.get_mut(&id) else {
                    continue;
                };
                if let Some(c) = sub.xdp.and_then(|i| by_idx.get(&i)) {
                    a.rx_bytes = c.up_bytes;
                    a.rx_packets = c.up_packets;
                    a.tx_bytes = c.down_bytes;
                    a.tx_packets = c.down_packets;
                }
                a.uptime_secs = now.saturating_sub(up) / 1000;
                let dt = now.saturating_sub(sub.prev.2);
                if dt > 0 {
                    let bps =
                        |now: u64, was: u64| now.saturating_sub(was).saturating_mul(8_000) / dt;
                    a.rx_bps = bps(a.rx_bytes, sub.prev.0);
                    a.tx_bps = bps(a.tx_bytes, sub.prev.1);
                }
                sub.prev = (a.rx_bytes, a.tx_bytes, now);
                if let (Some(l), Some(ip)) = (&sub.effective.address_list, sub.ip)
                    && now.saturating_sub(sub.list_at) >= LIST_REFRESH_MS
                {
                    sub.list_at = now;
                    self.effects.push(Effect::AddressList {
                        list: l.clone(),
                        ip,
                        add: false,
                        comment: String::new(),
                    });
                    self.effects.push(Effect::AddressList {
                        list: l.clone(),
                        ip,
                        add: true,
                        comment: format!("ppp {}", sub.user),
                    });
                }
                let bytes = (a.rx_bytes, a.tx_bytes);
                if bytes != sub.last_bytes {
                    sub.last_bytes = bytes;
                    sub.idle_since = now;
                }
                if sub.cause.is_some() {
                    continue;
                }
                if let Some(idle) = sub.effective.idle_timeout
                    && now.saturating_sub(sub.idle_since) >= u64::from(idle) * 1000
                {
                    sub.cause = Some((4, "idle-timeout"));
                } else if (sub.limit_in > 0 && a.rx_bytes >= sub.limit_in)
                    || (sub.limit_out > 0 && a.tx_bytes >= sub.limit_out)
                {
                    sub.cause = Some((10, "limit-bytes"));
                }
                if let Some(c) = sub.cause {
                    ending.push((*slot, sub.sref, c));
                }
            }
        }
        for (i, sref, _) in ending {
            self.replies.push_back((i, sref, Reply::Terminate));
            self.run(now, i, |_, _| {});
        }
        self.requests(now);
    }

    /// `ppp.active.remove`, Disconnect and CoA rate changes.
    pub(crate) fn requests(&mut self, now: Millis) {
        // Each worker takes the requests for its own SESSION_IDs and leaves
        // the rest for the others (the id says which: `*server-sid`).
        let (lane, lanes) = (self.lane, self.lanes);
        let mine = |id: &str| parse_session_id(id).is_none_or(|(_, sid)| sid % lanes == lane);
        let (ids, rates, lists) = {
            let mut sh = guard(&self.shared);
            if sh.terminate.is_empty() && sh.rates.is_empty() && sh.lists.is_empty() {
                return;
            }
            let (ids, rest): (Vec<String>, Vec<String>) = std::mem::take(&mut sh.terminate)
                .into_iter()
                .partition(|id| mine(id));
            sh.terminate = rest;
            let (rates, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut sh.rates)
                .into_iter()
                .partition(|(id, _)| mine(id));
            sh.rates = rest;
            let (lists, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut sh.lists)
                .into_iter()
                .partition(|(id, _)| mine(id));
            sh.lists = rest;
            (ids, rates, lists)
        };
        for (id, list) in lists {
            let Some((i, sref)) = self.find(&id) else {
                continue;
            };
            let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
                continue;
            };
            let Some(ip) = sub.ip else { continue };
            let user = sub.user.clone();
            let new = (!list.is_empty()).then(|| list.clone());
            let old = std::mem::replace(&mut sub.effective.address_list, new);
            if let Some(o) = old {
                self.effects.push(Effect::AddressList {
                    list: o,
                    ip,
                    add: false,
                    comment: String::new(),
                });
            }
            if !list.is_empty() {
                self.effects.push(Effect::AddressList {
                    list: list.clone(),
                    ip,
                    add: true,
                    comment: format!("ppp {user}"),
                });
            }
            self.log(false, format!("PPP: {user} na address-list '{list}' (CoA)"));
        }
        for id in ids {
            if let Some((i, sref)) = self.find(&id) {
                self.replies.push_back((i, sref, Reply::Terminate));
                self.run(now, i, |_, _| {});
            }
        }
        for (id, rate) in rates {
            let Some((i, sref)) = self.find(&id) else {
                continue;
            };
            let Some(srv) = self.slots.get(i).map(|s| &s.server) else {
                continue;
            };
            let Some(d) = srv.session(sref.sid) else {
                continue;
            };
            if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
                sub.rate = Some(rate.clone());
                if let Some(idx) = sub.xdp {
                    // CoA: the rate changes, the queue (its clock) stays.
                    let shape = corerouter_engine::queue::shape_of(&self.cfg.queues, &sub.effective);
                    self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                        idx,
                        xdp_session(&d, Some(&rate), sub.v6.as_deref(), shape),
                    )));
                }
                let user = sub.user.clone();
                if let Some(a) = guard(&self.shared).active.get_mut(&id) {
                    a.rate_limit = Some(rate.clone());
                }
                self.log(
                    false,
                    format!("PPP: {user} com rate-limit novo {rate} (CoA)"),
                );
            }
        }
    }

    /// The session of an id from `ppp.active` (`*server-sid`), in O(1)
    /// (a walk of every session per id made removing N sessions O(N²)).
    fn find(&self, id: &str) -> Option<(usize, SessionRef)> {
        let (server, sid) = parse_session_id(id)?;
        let slot = self.slots.iter().position(|s| s.cfg.id.0 == server)?;
        self.subs.get(&(slot, sid)).map(|s| (s.slot, s.sref))
    }

    /// End every session (service stopping): Terminate and PADT to each.
    pub(crate) fn shutdown(&mut self, now: Millis) {
        let all: Vec<(usize, SessionRef)> = self.subs.values().map(|s| (s.slot, s.sref)).collect();
        for (i, sref) in all {
            self.replies.push_back((i, sref, Reply::Terminate));
            self.run(now, i, |_, _| {});
        }
    }

    /// XDP slots of the sessions up, for the counters.
    pub(crate) fn xdp_slots(&self) -> Vec<u32> {
        self.subs.values().filter_map(|s| s.xdp).collect()
    }

    /// Debug builds and tests: the servers' indexes agree.
    #[cfg(test)]
    pub(crate) fn check(&self) -> Result<(), String> {
        for s in &self.slots {
            s.server.check_invariants()?;
        }
        let ips: Vec<u32> = self
            .subs
            .values()
            .filter_map(|s| s.ip)
            .map(u32::from)
            .collect();
        let unique: HashSet<u32> = ips.iter().copied().collect();
        if unique.len() != ips.len() {
            return Err("an address is held by two sessions".into());
        }
        let mut again = SubIndex::default();
        for (k, sub) in &self.subs {
            again.add(*k, sub);
        }
        if again.by_ip != self.index.by_ip
            || again.users_up != self.index.users_up
            || again.pending != self.index.pending
        {
            return Err("the session index disagrees with the sessions".into());
        }
        // G4.3e: every prefix taken is a live session's, once.
        let v6: Vec<ipnet::Ipv6Net> = self
            .subs
            .values()
            .filter_map(|s| s.v6.as_deref())
            .flat_map(|x| [x.link.as_ref(), x.delegated.as_ref()])
            .flatten()
            .map(|p| p.0)
            .collect();
        let unique6: HashSet<_> = v6.iter().copied().collect();
        // The pools are shared by the workers: their count is everyone's.
        let taken = guard(&self.pools6).taken();
        if unique6.len() != v6.len() || (self.lanes == 1 && v6.len() != taken) {
            return Err(format!(
                "IPv6 prefixes: {} held, {} distinct, {taken} taken",
                v6.len(),
                unique6.len(),
            ));
        }
        Ok(())
    }
}

/// The IPv6 columns of a session's `ppp.active` row.
struct ActiveV6 {
    prefix: Option<ipnet::Ipv6Net>,
    delegated: Option<ipnet::Ipv6Net>,
    bound: bool,
    link_local: std::net::Ipv6Addr,
}

impl ActiveV6 {
    fn apply(self, a: &mut ActiveSession) {
        a.ipv6_prefix = self.prefix;
        a.delegated_prefix = self.delegated;
        a.delegated_bound = self.bound;
        a.link_local = Some(self.link_local);
    }
}

fn active_v6(x: &V6) -> ActiveV6 {
    ActiveV6 {
        prefix: x.link.as_ref().map(|l| l.0),
        delegated: x.delegated.as_ref().map(|d| d.0),
        bound: x.pd_bound(),
        link_local: x.peer(),
    }
}

fn session_id(slot: usize, slots: &[Slot], sid: u16) -> String {
    let server = slots.get(slot).map_or(0, |s| s.cfg.id.0);
    format!("*{server:X}-{sid}")
}

/// [`session_id`] read back: (server id, SESSION_ID).
fn parse_session_id(id: &str) -> Option<(u32, u16)> {
    let (server, sid) = id.strip_prefix('*')?.split_once('-')?;
    Some((u32::from_str_radix(server, 16).ok()?, sid.parse().ok()?))
}

fn assignment(ip: Ipv4Addr, dns: &[Ipv4Addr]) -> Ipv4Assignment {
    Ipv4Assignment {
        address: ip,
        dns: [dns.first().copied(), dns.get(1).copied()],
        nbns: [None, None],
    }
}

fn acct_attributes(ip: Option<Ipv4Addr>, mac: &str, interface: &str) -> Vec<Attribute> {
    let mut v = vec![
        Attribute::new("Calling-Station-Id", mac),
        Attribute::new("NAS-Port-Id", interface),
        Attribute::new("Framed-Protocol", "1"),
    ];
    if let Some(ip) = ip {
        v.push(Attribute::new("Framed-IP-Address", ip.to_string()));
    }
    v
}

/// The `S=…` string of an MS-CHAP2-Success attribute (RFC 2548 §2.3.3:
/// Ident, then 42 octets), shown as text or as hex.
fn success_string(v: &str) -> Option<[u8; AUTH_STRING_LEN]> {
    let bytes: Vec<u8> = if let Some(at) = v.find("S=") {
        v.get(at..)?.as_bytes().to_vec()
    } else {
        let hex = v.strip_prefix("0x").unwrap_or(v);
        let raw: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| {
                hex.get(i * 2..i * 2 + 2)
                    .and_then(|b| u8::from_str_radix(b, 16).ok())
            })
            .collect();
        raw.get(1..)?.to_vec()
    };
    bytes.get(..AUTH_STRING_LEN)?.try_into().ok()
}

fn rate_dir(r: &RateLimit, up: bool) -> Rate {
    let pick = |p: corerouter_proto_radius::rate_limit::Pair<u64>| if up { p.rx } else { p.tx };
    Rate {
        rate_bps: pick(r.rate),
        burst_bps: r.burst_rate.map_or(0, pick),
        threshold_bps: r.burst_threshold.map_or(0, pick),
        burst_secs: r.burst_time.map_or(0, |t| if up { t.rx } else { t.tx }),
    }
}

/// The XDP map entry of a session (G4.3c): downstream in XDP, or, shaped
/// (G4.9b), through the kernel and `bng0` to the shaper on the access port;
/// upstream through the kernel so `forward` and the queues see it.
fn xdp_session(
    d: &corerouter_proto_pppoe::descriptor::SessionDescriptor,
    rate: Option<&str>,
    v6: Option<&V6>,
    shape: Option<corerouter_hal::queue::Kind>,
) -> PppoeSession {
    let r = rate
        .and_then(|t| t.parse::<RateLimit>().ok())
        .or(d.rate_limit);
    PppoeSession {
        ifindex: d.ifindex,
        sid: d.sid,
        vlan: d.vlan,
        inner_vlan: d.inner_vlan,
        outer_tpid: d.outer_tpid,
        mtu: d.mtu,
        client_mac: d.client_mac.0,
        server_mac: d.server_mac.0,
        ipv4: d.ipv4,
        up: r.as_ref().map(|r| rate_dir(r, true)).unwrap_or_default(),
        down: r.as_ref().map(|r| rate_dir(r, false)).unwrap_or_default(),
        fast_up: false,
        fast_down: true,
        ipoe: false,
        ipv6_prefix: v6
            .and_then(|x| x.link.as_ref())
            .map(|(n, _)| v6::high64(*n)),
        delegated: v6
            .and_then(|x| x.delegated.as_ref())
            .map(|(n, _)| (v6::high64(*n), n.prefix_len())),
        shape,
    }
}

#[cfg(test)]
mod admission_tests {
    // The bench includes this file with cfg(test) and no test harness.
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn why_evicts_the_least_recently_used_not_everything() {
        let mut sh = WhyTable {
            why_cap: 3,
            ..WhyTable::default()
        };
        for k in ["a", "b", "c"] {
            sh.reach(&[k], Stage::Padi);
        }
        sh.reach(&["a"], Stage::Auth);
        sh.reach(&["d"], Stage::Padi);
        let mut keys: Vec<&str> = sh.why.keys().map(|k| &**k).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["a", "c", "d"], "b was the oldest unused");
        // A flood of new keys keeps the table at its size.
        for i in 0..10_000 {
            sh.reach(&[&format!("m{i}")], Stage::Padi);
        }
        assert_eq!(sh.why.len(), 3);
        assert!(sh.why_order.len() <= 2 * 3 + 1024 + 1);
        assert!(sh.why.contains_key("m9999"));
    }

    #[test]
    fn auto_rate_follows_the_radius_server() {
        let mut held = 0;
        // One second: `n` answers in `ms`, a timeout or not, CPEs waiting
        // or not.
        let mut second = |a: &mut Admission, n: usize, ms: u64, timeout: bool, waiting: bool| {
            for _ in 0..n {
                a.answer(ms, false);
            }
            if timeout {
                a.answer(1100, true);
            }
            if waiting {
                held += 10;
            }
            a.second(held, 0);
        };
        let mut a = Admission::default();
        // Startup: twice what the server answered, while that keeps growing
        // (not twice the last rate: that ran to 3.6× the capacity).
        second(&mut a, 100, 20, false, true);
        assert_eq!(a.rate, 200.0);
        assert!(a.reason.contains("100/s"), "{}", a.reason);
        // The answers stop growing (the server's capacity: 100/s): after
        // three such seconds the rate is that capacity times BBR's gains.
        for _ in 0..4 {
            second(&mut a, 100, 20, false, true);
        }
        assert!(!a.startup);
        assert!((90.0..=125.0).contains(&a.rate), "{}", a.rate);
        assert!(
            a.reason.contains("capacidade do RADIUS: 100/s"),
            "{}",
            a.reason
        );
        // A standing queue (380 ms against 20 ms with none): 0.9× the capacity.
        second(&mut a, 100, 380, false, true);
        assert_eq!(a.rate, 90.0);
        assert_eq!(a.reason, "RADIUS lento: 380 ms (sem fila: 20 ms)");
        // A timeout: 0.75× the capacity, never the floor while it answers.
        second(&mut a, 100, 20, true, true);
        assert_eq!(a.rate, 75.0);
        assert!(a.reason.starts_with("RADIUS sem resposta"), "{}", a.reason);
        // No queue: it holds.
        let r = a.rate;
        second(&mut a, 100, 20, false, false);
        assert_eq!(a.rate, r);
        assert_eq!(a.reason, "sem fila");
        // Questions out and a whole second without an answer: halved.
        a.second(1 << 40, 40);
        assert_eq!(a.rate, (r / 2.0).max(AUTO_MIN));
        assert!(a.reason.starts_with("RADIUS parado"), "{}", a.reason);
        // Local secrets (no RADIUS answers ever) and CPEs waiting: it grows.
        let mut b = Admission::default();
        second(&mut b, 0, 0, false, true);
        assert_eq!(b.rate, AUTO_START + AUTO_STEP);
        // The window: a small one before any answer; then the capacity
        // times the base answer time (at least 300 ms), twice while
        // probing, shared by the workers; the backlog: 10 s of capacity.
        b.rate = 2000.0;
        assert_eq!(b.window(1), AUTO_WINDOW_START);
        assert_eq!(b.window(4), AUTO_WINDOW_START / 4);
        b.delivered.push_back(2000.0);
        b.startup = false;
        assert_eq!(b.window(1), 600);
        assert_eq!(b.window(4), 150);
        b.startup = true;
        assert_eq!(b.window(1), 1200);
        b.startup = false;
        b.delivered.clear();
        assert_eq!(b.backlog(1), 20_000);
        b.rate = AUTO_MIN;
        assert_eq!(b.window(8), AUTO_WINDOW_MIN);
    }
}

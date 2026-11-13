//! Statistics (G4.1e, G4.1h; `ip.dns.statistics.print`): what the
//! forwarder did with every query — which stage answered (cache, static,
//! upstream, stale, refused, limit…), the response codes, the record
//! types asked, the extended error each failure stands for (RFC 8914),
//! UDP or TCP over IPv4 or IPv6, replies truncated, the time to answer, the
//! clients that ask most and the upstream servers that answered. Messages
//! refused before the chain (malformed, another opcode or class) are
//! counted too, as `malformed`.
//!
//! Only an `after` hook: it sees every reply, drops included, once the
//! chain is done. `handle` never decides anything; the stage sits last so
//! it costs nothing on the way down.
//!
//! **No shared lock on the way (G4.1h).** The counters are split in
//! [`STRIPES`] stripes, each on its own cache lines, with fixed arrays
//! indexed by category, response code and type (no map, no string key).
//! A thread counts into its own stripe (given round-robin the first time
//! it counts) under that stripe's lock, which nobody else takes but a
//! reader once a second: with up to [`STRIPES`] threads counting none ever
//! waits, and past that a busy stripe is skipped for the next free one
//! (`try_lock`). Reading sums the stripes. Before, one `Mutex` for all made
//! four threads slower than one (`benches/statistics.rs`).
//!
//! Bounded memory under a flood from spoofed sources: each stripe keeps at
//! most [`CLIENTS_PER_STRIPE`] clients. Past that, the client with the
//! fewest queries makes room (Space-Saving, Metwally et al. 2005): the
//! newcomer starts from that count, so the top of the list is right and
//! each count is off by at most its `error`. The smallest is the root of a
//! min-heap: O(log n) per query, where the scan it replaces was O(n) for
//! every new client (CGNAT: thousands of them).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

use crate::histogram::Hist;
use crate::resolver::{Source, Transport};
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "statistics",
    order: 100,
    handle,
    after: Some(after),
};

/// Stripes of counters (threads counting at once without waiting).
pub const STRIPES: usize = 16;
/// Clients counted one by one in each stripe.
pub const CLIENTS_PER_STRIPE: usize = 256;
/// Clients counted at most, all stripes.
pub const MAX_CLIENTS: usize = STRIPES * CLIENTS_PER_STRIPE;
/// Record types counted one by one (`0..TYPES`, CAA = 257 included); the
/// rest go under `other`.
const TYPES: usize = 260;
/// Upstream servers counted per stripe (static FWD entries can name others).
const MAX_UPSTREAMS: usize = 64;
/// RFC 8914 codes counted one by one (IANA has 0–30 now); the rest, `other`.
const EDE_CODES: usize = 32;

/// What a query counts as, in the order `print` lists them.
pub const CATEGORIES: [&str; 14] = [
    "cache",
    "static",
    "upstream",
    "stale",
    "refused",
    "limit",
    "busy",
    "special",
    "adlist",
    "zones",
    "malformed",
    "none",
    "parse",
    "other",
];
const OTHER_CATEGORY: usize = CATEGORIES.len() - 1;
const MALFORMED: usize = 10;

/// Response codes by their number (RFC 6895 §2.3, the 4 header bits).
const RCODES: [&str; 16] = [
    "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset",
    "nxrrset", "notauth", "notzone", "rcode11", "rcode12", "rcode13", "rcode14", "rcode15",
];
/// Index of a dropped query (no reply) and of a code past 15.
const DROPPED: usize = RCODES.len();
const OTHER_RCODE: usize = RCODES.len() + 1;

/// RFC 8914 §4: the extended errors the forwarder can stand for.
pub const EDE_PROHIBITED: u16 = 18;
pub const EDE_STALE: u16 = 3;
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_CACHED_ERROR: u16 = 13;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;

/// One client's counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    pub queries: u64,
    /// Refused (ACL, limit over TCP) or dropped (limit over UDP).
    pub refused: u64,
    /// Space-Saving: how many of `queries` may belong to clients it
    /// replaced (0 while the table never filled up).
    pub error: u64,
}

/// The counts since the last reset, all stripes summed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub queries: u64,
    pub udp: u64,
    pub tcp: u64,
    /// By transport and family: UDP over IPv4, UDP over IPv6, TCP…
    pub udp4: u64,
    pub udp6: u64,
    pub tcp4: u64,
    pub tcp6: u64,
    /// UDP replies sent without records and with TC set (too large for the
    /// client: it asks again over TCP, RFC 1035 §4.2.1).
    pub truncated: u64,
    /// Refused before the chain: not a query, malformed, another opcode
    /// or class (also under `answered.malformed` and their rcode).
    pub malformed: u64,
    /// Queries per stage that answered, by [`category`].
    pub answered: BTreeMap<&'static str, u64>,
    /// Replies per response code (`noerror`, `nxdomain`, … `dropped`).
    pub rcodes: BTreeMap<&'static str, u64>,
    /// Queries per record type asked (its code; [`Snapshot::types`] names
    /// them).
    pub types: BTreeMap<u16, u64>,
    /// Queries of types past the ones counted one by one.
    pub types_other: u64,
    /// Replies per RFC 8914 extended error they stand for (counted, not
    /// sent: the forwarder does not add the EDNS option yet).
    pub ede: BTreeMap<u16, u64>,
    /// Time from the query read to the reply sent, as the daemon measured
    /// it ([`Statistics::answered_in`]).
    pub latency: Hist,
    /// Client answers per upstream server.
    pub upstreams: BTreeMap<IpAddr, u64>,
    /// Clients that had to replace another (a stripe's table was full).
    pub clients_replaced: u64,
    /// Queries waiting for an upstream now and the most at once
    /// (`max_concurrent_queries`; the daemon reports them).
    pub in_flight: u64,
    pub in_flight_peak: u64,
    /// Datagrams the kernel dropped on the forwarder's UDP sockets (its
    /// queue was full), as the daemon read them.
    pub socket_drops: u64,
}

/// A copy to show: the counters and the `top` clients.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub counters: Counters,
    /// Clients tracked now.
    pub clients_tracked: usize,
    /// Most queries first.
    pub top_clients: Vec<(IpAddr, ClientStats)>,
}

impl Snapshot {
    /// Queries per record type by name (`A`, `AAAA`, `TYPE65534`…), most
    /// first; the types past the limit as `other`.
    pub fn types(&self) -> Vec<(String, u64)> {
        let c = &self.counters;
        let mut out: Vec<(String, u64)> = c
            .types
            .iter()
            .map(|(t, n)| (RecordType::from(*t).to_string(), *n))
            .collect();
        if c.types_other > 0 {
            out.push(("other".to_owned(), c.types_other));
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }
}

/// One stripe's counters (plain integers: only its lock reaches them).
#[derive(Debug)]
struct Shard {
    /// UDP4, UDP6, TCP4, TCP6.
    transport: [u64; 4],
    truncated: u64,
    malformed: u64,
    answered: [u64; CATEGORIES.len()],
    rcodes: [u64; OTHER_RCODE + 1],
    types: [u64; TYPES],
    types_other: u64,
    ede: [u64; EDE_CODES + 1],
    latency: Hist,
    upstreams: BTreeMap<IpAddr, u64>,
    clients: Clients,
}

impl Default for Shard {
    fn default() -> Self {
        Self {
            transport: [0; 4],
            truncated: 0,
            malformed: 0,
            answered: [0; CATEGORIES.len()],
            rcodes: [0; OTHER_RCODE + 1],
            types: [0; TYPES],
            types_other: 0,
            ede: [0; EDE_CODES + 1],
            latency: Hist::default(),
            upstreams: BTreeMap::new(),
            clients: Clients::default(),
        }
    }
}

/// A stripe on cache lines of its own (no false sharing with the next).
#[derive(Debug, Default)]
#[repr(align(128))]
struct Stripe(Mutex<Shard>);

/// What one reply counts.
struct Event {
    category: usize,
    rcode: usize,
    qtype: Option<u16>,
    client: IpAddr,
    tcp: bool,
    refused: bool,
    truncated: bool,
    ede: Option<u16>,
    upstream: Option<IpAddr>,
}

/// The forwarder's statistics (`f.state::<Statistics>()`).
#[derive(Debug)]
pub struct Statistics {
    stripes: Box<[Stripe]>,
    in_flight: AtomicU64,
    in_flight_peak: AtomicU64,
    /// The kernel's count, what it was at the last reset, and what was
    /// counted since the reset by sockets closed since.
    socket_drops: AtomicU64,
    socket_drops_base: AtomicU64,
    socket_drops_carried: AtomicU64,
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| Stripe::default()).collect(),
            in_flight: AtomicU64::new(0),
            in_flight_peak: AtomicU64::new(0),
            socket_drops: AtomicU64::new(0),
            socket_drops_base: AtomicU64::new(0),
            socket_drops_carried: AtomicU64::new(0),
        }
    }
}

/// Next stripe to hand a thread that counts for the first time.
static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This thread's stripe (`usize::MAX`: not given yet).
    static MY_STRIPE: Cell<usize> = const { Cell::new(usize::MAX) };
}

fn my_stripe() -> usize {
    MY_STRIPE.with(|s| {
        let mine = s.get();
        if mine != usize::MAX {
            return mine;
        }
        let given = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) % STRIPES;
        s.set(given);
        given
    })
}

fn locked(m: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    // A panic elsewhere never stops the counting.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Statistics {
    /// This thread's stripe, or the next free one when another thread
    /// holds it; waits only when every stripe is busy.
    fn shard(&self) -> MutexGuard<'_, Shard> {
        let mine = my_stripe();
        let n = self.stripes.len();
        for k in 0..n {
            if let Some(s) = self.stripes.get((mine + k) % n) {
                match s.0.try_lock() {
                    Ok(g) => return g,
                    Err(std::sync::TryLockError::Poisoned(p)) => return p.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {}
                }
            }
        }
        let fallback = self.stripes.get(mine % n.max(1)).or_else(|| self.stripes.first());
        match fallback {
            Some(s) => locked(&s.0),
            // No stripes (never: `default` makes them); a fresh one.
            None => unreachable_shard(),
        }
    }

    /// The counters and the `top` clients, all stripes summed.
    pub fn snapshot(&self, top: usize) -> Snapshot {
        self.gather(Some(top))
    }

    /// The counters only (no client is copied): what the engine reads
    /// every second for the graph and the window's "now" values.
    pub fn totals(&self) -> Counters {
        self.gather(None).counters
    }

    fn gather(&self, top: Option<usize>) -> Snapshot {
        let mut c = Counters::default();
        let mut transport = [0u64; 4];
        let mut answered = [0u64; CATEGORIES.len()];
        let mut rcodes = [0u64; OTHER_RCODE + 1];
        let mut types = [0u64; TYPES];
        let mut ede = [0u64; EDE_CODES + 1];
        let mut clients: HashMap<IpAddr, ClientStats> = HashMap::new();
        for s in self.stripes.iter() {
            let g = locked(&s.0);
            add(&mut transport, &g.transport);
            add(&mut answered, &g.answered);
            add(&mut rcodes, &g.rcodes);
            add(&mut types, &g.types);
            add(&mut ede, &g.ede);
            c.truncated += g.truncated;
            c.malformed += g.malformed;
            c.types_other += g.types_other;
            c.latency.merge(&g.latency);
            for (ip, n) in &g.upstreams {
                *c.upstreams.entry(*ip).or_default() += n;
            }
            c.clients_replaced += g.clients.replaced;
            if top.is_none() {
                continue;
            }
            for slot in &g.clients.slots {
                let e = clients.entry(slot.ip).or_default();
                e.queries += slot.stats.queries;
                e.refused += slot.stats.refused;
                e.error += slot.stats.error;
            }
        }
        let [udp4, udp6, tcp4, tcp6] = transport;
        (c.udp4, c.udp6, c.tcp4, c.tcp6) = (udp4, udp6, tcp4, tcp6);
        c.udp = udp4 + udp6;
        c.tcp = tcp4 + tcp6;
        c.queries = answered.iter().sum();
        for (name, n) in CATEGORIES.iter().zip(answered) {
            if n > 0 {
                c.answered.insert(name, n);
            }
        }
        for (i, n) in rcodes.iter().enumerate() {
            let name = match i {
                DROPPED => "dropped",
                OTHER_RCODE => "other",
                _ => RCODES.get(i).copied().unwrap_or("other"),
            };
            if *n > 0 {
                *c.rcodes.entry(name).or_default() += n;
            }
        }
        for (t, n) in types.iter().enumerate() {
            if *n > 0
                && let Ok(t) = u16::try_from(t)
            {
                c.types.insert(t, *n);
            }
        }
        for (code, n) in ede.iter().enumerate() {
            if *n > 0
                && let Ok(code) = u16::try_from(code)
            {
                // The last slot holds the codes past the table: 32 = "other".
                c.ede.insert(code, *n);
            }
        }
        c.in_flight = self.in_flight.load(Ordering::Relaxed);
        c.in_flight_peak = self.in_flight_peak.load(Ordering::Relaxed);
        c.socket_drops = self.socket_drops_carried.load(Ordering::Relaxed).saturating_add(
            self.socket_drops
                .load(Ordering::Relaxed)
                .saturating_sub(self.socket_drops_base.load(Ordering::Relaxed)),
        );
        let clients_tracked = clients.len();
        let mut top_clients: Vec<(IpAddr, ClientStats)> = clients.into_iter().collect();
        top_clients.sort_by(|a, b| b.1.queries.cmp(&a.1.queries).then(a.0.cmp(&b.0)));
        top_clients.truncate(top.unwrap_or(0));
        Snapshot {
            counters: c,
            clients_tracked,
            top_clients,
        }
    }

    /// Back to zero (`ip.dns.statistics.reset`). The queries in flight
    /// stay (they are not a count); their peak starts again from them.
    pub fn reset(&self) {
        for s in self.stripes.iter() {
            *locked(&s.0) = Shard::default();
        }
        self.in_flight_peak
            .store(self.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);
        self.socket_drops_base
            .store(self.socket_drops.load(Ordering::Relaxed), Ordering::Relaxed);
        self.socket_drops_carried.store(0, Ordering::Relaxed);
    }

    /// A reply went out `us` microseconds after its query was read (the
    /// daemon measures it: the chain has no clock of its own).
    pub fn answered_in(&self, us: u64) {
        self.shard().latency.add_us(us);
    }

    /// Queries waiting for an upstream now (the daemon's gate).
    pub fn set_in_flight(&self, now: usize) {
        let now = u64::try_from(now).unwrap_or(u64::MAX);
        self.in_flight.store(now, Ordering::Relaxed);
        self.in_flight_peak.fetch_max(now, Ordering::Relaxed);
    }

    /// The kernel's count of datagrams dropped on the forwarder's UDP
    /// sockets (cumulative; `print` shows it since the last reset).
    pub fn set_socket_drops(&self, total: u64) {
        let old = self.socket_drops.swap(total, Ordering::Relaxed);
        // The sockets were opened again (the kernel counts from zero):
        // what the old ones counted since the reset is carried.
        if total < old {
            let base = self.socket_drops_base.swap(0, Ordering::Relaxed);
            self.socket_drops_carried
                .fetch_add(old.saturating_sub(base), Ordering::Relaxed);
        }
    }

    /// A message refused before the chain (`reply`: the bytes sent back,
    /// `None`: dropped).
    pub(crate) fn malformed(&self, client: IpAddr, tcp: bool, reply: Option<&[u8]>) {
        // The reply's RCODE: the low 4 bits of byte 3 (RFC 1035 §4.1.1).
        let rcode = match reply {
            Some(r) => r.get(3).map_or(OTHER_RCODE, |b| usize::from(b & 0x0f)),
            None => DROPPED,
        };
        self.count(&Event {
            category: MALFORMED,
            rcode,
            qtype: None,
            client: client.to_canonical(),
            tcp,
            refused: true,
            truncated: false,
            ede: None,
            upstream: None,
        });
    }

    fn record(&self, q: &Query, r: &Reply) {
        let what = category(q.answered_by, q.source.as_ref());
        let refused = q.dropped() || r.rcode == ResponseCode::Refused;
        let ede = q.ede.or(match what {
            "refused" => Some(EDE_PROHIBITED),
            "stale" => Some(EDE_STALE),
            "adlist" => Some(EDE_BLOCKED),
            _ => None,
        });
        let upstream = match q.source {
            Some(Source::Server(ip)) if what == "upstream" => Some(ip),
            _ => None,
        };
        self.count(&Event {
            category: index(what),
            rcode: if q.dropped() { DROPPED } else { rcode(r.rcode) },
            qtype: Some(u16::from(q.qtype)),
            client: q.client,
            tcp: q.tcp,
            refused,
            truncated: q.truncated(),
            ede,
            upstream,
        });
    }

    fn count(&self, e: &Event) {
        let mut s = self.shard();
        let t = usize::from(e.tcp) * 2 + usize::from(e.client.is_ipv6());
        bump(s.transport.get_mut(t));
        bump(s.answered.get_mut(e.category));
        bump(s.rcodes.get_mut(e.rcode));
        if e.category == MALFORMED {
            s.malformed += 1;
        }
        s.truncated += u64::from(e.truncated);
        if let Some(t) = e.qtype {
            match s.types.get_mut(usize::from(t)) {
                Some(n) => *n += 1,
                None => s.types_other += 1,
            }
        }
        if let Some(code) = e.ede {
            let i = usize::from(code).min(EDE_CODES);
            bump(s.ede.get_mut(i));
        }
        if let Some(ip) = e.upstream
            && (s.upstreams.contains_key(&ip) || s.upstreams.len() < MAX_UPSTREAMS)
        {
            *s.upstreams.entry(ip).or_default() += 1;
        }
        s.clients.touch(e.client, e.refused);
    }
}

#[cold]
fn unreachable_shard() -> MutexGuard<'static, Shard> {
    static SPARE: std::sync::OnceLock<Mutex<Shard>> = std::sync::OnceLock::new();
    locked(SPARE.get_or_init(Mutex::default))
}

fn bump(n: Option<&mut u64>) {
    if let Some(n) = n {
        *n += 1;
    }
}

fn add<const N: usize>(into: &mut [u64; N], from: &[u64; N]) {
    for (a, b) in into.iter_mut().zip(from) {
        *a += b;
    }
}

/// The position of category `name` in [`CATEGORIES`] (unknown: `other`).
fn index(name: &str) -> usize {
    match name {
        "cache" => 0,
        "static" => 1,
        "upstream" => 2,
        "stale" => 3,
        "refused" => 4,
        "limit" => 5,
        "busy" => 6,
        "special" => 7,
        "adlist" => 8,
        "zones" => 9,
        "malformed" => MALFORMED,
        "none" => 11,
        "parse" => 12,
        _ => OTHER_CATEGORY,
    }
}

/// One client in a stripe's table.
#[derive(Debug, Clone, Copy)]
struct Slot {
    ip: IpAddr,
    stats: ClientStats,
}

/// Space-Saving over a min-heap of the slots by `queries`: the root is
/// the client a newcomer replaces.
#[derive(Debug, Default)]
struct Clients {
    slots: Vec<Slot>,
    /// Slot numbers, a min-heap by their `queries`.
    heap: Vec<usize>,
    /// Where each slot sits in `heap`.
    pos: Vec<usize>,
    index: HashMap<IpAddr, usize>,
    /// Newcomers that replaced someone.
    replaced: u64,
}

impl Clients {
    fn queries(&self, h: usize) -> u64 {
        self.heap
            .get(h)
            .and_then(|s| self.slots.get(*s))
            .map_or(u64::MAX, |s| s.stats.queries)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        for h in [a, b] {
            if let Some(&slot) = self.heap.get(h)
                && let Some(p) = self.pos.get_mut(slot)
            {
                *p = h;
            }
        }
    }

    /// The count at heap position `h` grew: down to its place.
    fn sift_down(&mut self, mut h: usize) {
        loop {
            let (l, r) = (2 * h + 1, 2 * h + 2);
            let mut least = h;
            if self.queries(l) < self.queries(least) {
                least = l;
            }
            if self.queries(r) < self.queries(least) {
                least = r;
            }
            if least == h {
                return;
            }
            self.swap(h, least);
            h = least;
        }
    }

    fn sift_up(&mut self, mut h: usize) {
        while h > 0 {
            let parent = (h - 1) / 2;
            if self.queries(parent) <= self.queries(h) {
                return;
            }
            self.swap(h, parent);
            h = parent;
        }
    }

    /// One query from `ip`.
    fn touch(&mut self, ip: IpAddr, refused: bool) {
        let slot = match self.index.get(&ip) {
            Some(s) => *s,
            None if self.slots.len() < CLIENTS_PER_STRIPE => {
                let s = self.slots.len();
                self.slots.push(Slot {
                    ip,
                    stats: ClientStats::default(),
                });
                self.heap.push(s);
                self.pos.push(s);
                self.index.insert(ip, s);
                self.sift_up(s);
                s
            }
            None => {
                // Space-Saving: the smallest count makes room.
                let Some(&s) = self.heap.first() else { return };
                let Some(old) = self.slots.get_mut(s) else {
                    return;
                };
                let min = old.stats.queries;
                let gone = old.ip;
                *old = Slot {
                    ip,
                    stats: ClientStats {
                        queries: min,
                        refused: 0,
                        error: min,
                    },
                };
                self.index.remove(&gone);
                self.index.insert(ip, s);
                self.replaced += 1;
                s
            }
        };
        if let Some(st) = self.slots.get_mut(slot) {
            st.stats.queries += 1;
            st.stats.refused += u64::from(refused);
        }
        if let Some(h) = self.pos.get(slot).copied() {
            self.sift_down(h);
        }
    }
}

/// What a query counts as: the stage that answered, with the ACL's refusal
/// called `refused`, and the upstream stage split by where its answer came
/// from (`stale`: RFC 8767; `cache`: another query filled it meanwhile).
pub fn category(answered_by: &'static str, source: Option<&Source>) -> &'static str {
    match (answered_by, source) {
        ("acl", _) => "refused",
        ("upstream", Some(Source::Stale)) => "stale",
        ("upstream", Some(Source::Cache)) => "cache",
        ("", _) => "none",
        (stage, _) => stage,
    }
}

fn rcode(r: ResponseCode) -> usize {
    let n = usize::from(u16::from(r));
    if n < RCODES.len() { n } else { OTHER_RCODE }
}

/// A record type's name (`A`, `HTTPS`, `TYPE65534`).
pub fn type_name(t: u16) -> String {
    RecordType::from(t).to_string()
}

/// The name of RFC 8914 code `code` (IANA registry), `None` past it.
pub fn ede_name(code: u16) -> Option<&'static str> {
    const NAMES: [&str; 31] = [
        "Other",
        "Unsupported DNSKEY Algorithm",
        "Unsupported DS Digest Type",
        "Stale Answer",
        "Forged Answer",
        "DNSSEC Indeterminate",
        "DNSSEC Bogus",
        "Signature Expired",
        "Signature Not Yet Valid",
        "DNSKEY Missing",
        "RRSIGs Missing",
        "No Zone Key Bit Set",
        "NSEC Missing",
        "Cached Error",
        "Not Ready",
        "Blocked",
        "Censored",
        "Filtered",
        "Prohibited",
        "Stale NXDOMAIN Answer",
        "Not Authoritative",
        "Not Supported",
        "No Reachable Authority",
        "Network Error",
        "Invalid Data",
        "Signature Expired before Valid",
        "Too Early",
        "Unsupported NSEC3 Iterations Value",
        "Unable to conform to policy",
        "Synthesized",
        "Invalid Query Type",
    ];
    NAMES.get(usize::from(code)).copied()
}

fn handle(_: &Forwarder, _: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    Step::Next
}

fn after(f: &Forwarder, q: &mut Query, r: &Reply) {
    f.statistics().record(q, r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        let up: IpAddr = [198, 51, 100, 53].into();
        assert_eq!(category("acl", None), "refused");
        assert_eq!(category("upstream", Some(&Source::Server(up))), "upstream");
        assert_eq!(category("upstream", Some(&Source::Stale)), "stale");
        assert_eq!(category("cache", Some(&Source::Cache)), "cache");
        assert_eq!(category("limit", None), "limit");
        assert_eq!(category("busy", None), "busy");
        for (i, c) in CATEGORIES.iter().enumerate() {
            assert_eq!(index(c), i, "{c}");
        }
        assert_eq!(CATEGORIES.get(index("a stage to come")), Some(&"other"));
        // Every stage of the chain has a category of its own.
        for s in crate::server::stages() {
            let c = category(s.name, None);
            assert!(
                s.name == "statistics" || CATEGORIES.contains(&c),
                "stage {} has no category",
                s.name
            );
        }
    }

    #[test]
    fn the_chain_counts_every_reply_and_drop() {
        use crate::server::tests::{LAN, Up, ask, forwarder, run};
        let f = forwarder(|c| c.ip.dns.max_queries_per_client = 1);
        let mut up = Up::new();
        let q = ask("www.example.com.", RecordType::A);
        // Burst of 2: upstream, cache, then dropped (UDP over the limit).
        for _ in 0..3 {
            run(&f, &mut up, LAN, &q);
        }
        run(&f, &mut up, [203, 0, 113, 9], &ask("x.example.", RecordType::TXT));
        let s = f.state::<Statistics>().snapshot(10);
        let c = &s.counters;
        assert_eq!((c.queries, c.udp, c.tcp), (4, 4, 0));
        assert_eq!((c.udp4, c.udp6), (4, 0));
        let got = |k| c.answered.get(k).copied().unwrap_or(0);
        assert_eq!(
            [got("upstream"), got("cache"), got("limit"), got("refused")],
            [1, 1, 1, 1]
        );
        assert_eq!(c.rcodes.get("dropped"), Some(&1));
        assert_eq!(c.rcodes.get("refused"), Some(&1));
        assert_eq!(c.ede.get(&EDE_PROHIBITED), Some(&1), "RFC 8914 §4.19");
        assert_eq!(s.types(), [("A".to_owned(), 3), ("TXT".to_owned(), 1)]);
        assert_eq!(c.upstreams.get(&IpAddr::from([198, 51, 100, 53])), Some(&1));
        let lan = s.top_clients.first().copied().unwrap();
        assert_eq!(lan.0, IpAddr::from(LAN));
        assert_eq!((lan.1.queries, lan.1.refused), (3, 1));
        f.state::<Statistics>().reset();
        assert_eq!(f.state::<Statistics>().snapshot(10), Snapshot::default());
    }

    #[test]
    fn malformed_messages_are_counted() {
        use crate::server::tests::forwarder;
        let f = forwarder(|_| {});
        let from = IpAddr::from([192, 168, 88, 10]);
        // Junk shorter than a header: dropped, nothing to reflect.
        assert!(matches!(f.start(&[1, 2, 3], from, false, 1), crate::server::Start::Done(d) if d.reply.is_none()));
        // A header and a question cut short: FORMERR (RFC 1035 §4.1.1).
        let cut = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w'];
        assert!(matches!(f.start(&cut, from, true, 1), crate::server::Start::Done(d) if d.reply.is_some()));
        // An opcode the forwarder does not do (STATUS = 2): NOTIMP.
        let status = [0x12, 0x35, 0x10, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(f.start(&status, from, false, 1), crate::server::Start::Done(d) if d.reply.is_some()));
        let c = f.statistics().snapshot(1).counters;
        assert_eq!((c.queries, c.malformed), (3, 3));
        assert_eq!(c.answered.get("malformed"), Some(&3));
        assert_eq!(c.rcodes.get("dropped"), Some(&1));
        assert_eq!(c.rcodes.get("formerr"), Some(&1));
        assert_eq!(c.rcodes.get("notimp"), Some(&1));
        assert_eq!((c.udp4, c.tcp4), (2, 1));
        assert!(c.types.is_empty(), "no question to count");
    }

    #[test]
    fn latency_flight_and_drops() {
        let s = Statistics::default();
        s.answered_in(80);
        s.answered_in(40_000);
        s.set_in_flight(7);
        s.set_in_flight(2);
        s.set_socket_drops(10);
        let c = s.snapshot(1).counters;
        assert_eq!(c.latency.total(), 2);
        assert_eq!((c.in_flight, c.in_flight_peak), (2, 7));
        assert_eq!(c.socket_drops, 10);
        s.reset();
        s.set_socket_drops(12);
        let c = s.snapshot(1).counters;
        assert_eq!((c.latency.total(), c.in_flight_peak, c.socket_drops), (0, 2, 2));
        // The sockets were opened again: the kernel counts from zero.
        s.set_socket_drops(1);
        assert_eq!(s.snapshot(1).counters.socket_drops, 3, "2 before, 1 after");
    }

    #[test]
    fn threads_count_without_losing_any() {
        let s = Statistics::default();
        std::thread::scope(|sc| {
            for t in 0..(STRIPES as u8 + 4) {
                let s = &s;
                sc.spawn(move || {
                    for i in 0..1000u32 {
                        s.count(&Event {
                            category: index("cache"),
                            rcode: 0,
                            qtype: Some(1),
                            client: IpAddr::from([10, t, (i % 7) as u8, 1]),
                            tcp: false,
                            refused: false,
                            truncated: i % 10 == 0,
                            ede: None,
                            upstream: None,
                        });
                    }
                });
            }
        });
        let c = s.snapshot(1).counters;
        let n = (STRIPES as u64 + 4) * 1000;
        assert_eq!((c.queries, c.udp4, c.truncated), (n, n, n / 10));
        assert_eq!(c.types.get(&1), Some(&n));
    }

    #[test]
    fn space_saving_keeps_the_heavy_client() {
        let mut c = Clients::default();
        let heavy: IpAddr = [10, 0, 0, 1].into();
        for _ in 0..50 {
            c.touch(heavy, false);
        }
        // A flood from as many sources as the table holds, and more.
        for i in 0..(CLIENTS_PER_STRIPE as u32 * 3) {
            c.touch(IpAddr::from((0x0a01_0000 + i).to_be_bytes()), true);
        }
        assert_eq!(c.slots.len(), CLIENTS_PER_STRIPE, "bounded");
        assert_eq!(c.index.len(), CLIENTS_PER_STRIPE);
        let h = c.slots.iter().find(|s| s.ip == heavy).unwrap().stats;
        assert_eq!((h.queries, h.error), (50, 0), "never replaced");
        assert!(c.replaced >= CLIENTS_PER_STRIPE as u64 * 2 - 1);
        // Every count is at least the truth and at most truth + error.
        assert!(c.slots.iter().all(|s| s.stats.queries > s.stats.error));
        // The heap holds the smallest at its root, every slot once.
        let min = c.slots.iter().map(|s| s.stats.queries).min().unwrap();
        assert_eq!(c.queries(0), min);
        let mut seen: Vec<usize> = c.heap.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..CLIENTS_PER_STRIPE).collect::<Vec<_>>());
        for (h, slot) in c.heap.iter().enumerate() {
            assert_eq!(c.pos[*slot], h);
            for child in [2 * h + 1, 2 * h + 2] {
                assert!(c.queries(h) <= c.queries(child), "heap order at {h}");
            }
        }
    }

    #[test]
    fn ede_names_follow_the_registry() {
        assert_eq!(ede_name(EDE_NO_REACHABLE_AUTHORITY), Some("No Reachable Authority"));
        assert_eq!(ede_name(EDE_PROHIBITED), Some("Prohibited"));
        assert_eq!(ede_name(EDE_STALE), Some("Stale Answer"));
        assert_eq!(ede_name(EDE_BLOCKED), Some("Blocked"));
        assert_eq!(ede_name(EDE_CACHED_ERROR), Some("Cached Error"));
        assert_eq!(ede_name(99), None);
    }
}

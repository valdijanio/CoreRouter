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
//! Bounded memory under a flood from spoofed sources or random names
//! (G4.1za, G4.1zb): each stripe keeps at most [`CLIENTS_PER_STRIPE`]
//! clients, [`NAMES_PER_STRIPE`] names and [`DOMAINS_PER_STRIPE`] failing
//! domains in a [`TopK`] (Space-Saving): past that, the key with the lowest
//! count makes room and the newcomer starts from it, so the top of each
//! list is right and each count is off by at most its `error`. The cost of
//! a query is a keyed hash of its name (and of its domain when it failed),
//! three table lookups and at most 8 heap swaps each: bounded by the table
//! sizes, never by how many clients or names there are.
//!
//! Privacy (LGPD, Marco Civil art. 14): a client's slot keeps counts only
//! (queries, NXDOMAIN, refused, limited, when last seen), never a name;
//! names and domains are counted for all clients together. Nothing is
//! written anywhere: the counts live in memory until the reset or a
//! restart. IPv6 clients count per /56 ([`CLIENT_V6_PREFIX`]), what an
//! operator delegates to a subscriber: one home, not each temporary
//! address of its devices (RFC 8981).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

use crate::histogram::Hist;
use crate::resolver::{Source, Transport};
use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::sketch::{Hll, Rate, TopK};
use crate::suffix::domain_of;

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
/// Names asked counted one by one in each stripe.
pub const NAMES_PER_STRIPE: usize = 256;
/// Domains with NXDOMAIN or SERVFAIL counted in each stripe (each holds a
/// 256-byte [`Hll`] of its names).
pub const DOMAINS_PER_STRIPE: usize = 64;
/// IPv6 clients count per prefix of this length.
pub const CLIENT_V6_PREFIX: u8 = 56;
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
const LIMIT: usize = 5;
const MALFORMED: usize = 10;

/// Response codes by their number (RFC 6895 §2.3, the 4 header bits).
const RCODES: [&str; 16] = [
    "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset",
    "nxrrset", "notauth", "notzone", "rcode11", "rcode12", "rcode13", "rcode14", "rcode15",
];
/// Index of a dropped query (no reply) and of a code past 15.
const DROPPED: usize = RCODES.len();
const SERVFAIL: usize = 2;
const NXDOMAIN: usize = 3;
const OTHER_RCODE: usize = RCODES.len() + 1;

/// RFC 8914 §4: the extended errors the forwarder can stand for.
pub const EDE_PROHIBITED: u16 = 18;
pub const EDE_STALE: u16 = 3;
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_CACHED_ERROR: u16 = 13;
pub const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;

/// One client's counts (never a name: see the module).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ClientStats {
    pub queries: u64,
    /// Refused (ACL, limit over TCP) or dropped (limit over UDP).
    pub refused: u64,
    /// Of them, over `max_queries_per_client`.
    pub limited: u64,
    pub nxdomain: u64,
    /// Space-Saving: how many of `queries` may belong to clients it
    /// replaced (0 while the table never filled up).
    pub error: u64,
    /// The forwarder's clock (ms) at its last query.
    pub last_ms: u64,
    /// Queries per second over the last 10 s.
    pub per_sec: f64,
}

/// A name asked, all clients together.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct NameStats {
    pub queries: u64,
    pub error: u64,
    pub per_sec: f64,
}

/// A domain whose names got NXDOMAIN or SERVFAIL ([`domain_of`]).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DomainStats {
    pub nxdomain: u64,
    pub servfail: u64,
    /// Space-Saving's error on `nxdomain + servfail`.
    pub error: u64,
    /// Failures per second over the last 10 s.
    pub per_sec: f64,
    /// Different names that failed (HyperLogLog, ±6.5 %).
    pub names: u64,
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
    /// Clients, names and failing domains that had to replace another (a
    /// stripe's table was full).
    pub clients_replaced: u64,
    pub names_replaced: u64,
    pub domains_replaced: u64,
    /// Queries waiting for an upstream now and the most at once
    /// (`max_concurrent_queries`; the daemon reports them).
    pub in_flight: u64,
    pub in_flight_peak: u64,
    /// Datagrams the kernel dropped on the forwarder's UDP sockets (its
    /// queue was full), as the daemon read them.
    pub socket_drops: u64,
}

/// A copy to show: the counters and the `top` clients, names and failing
/// domains.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Snapshot {
    pub counters: Counters,
    /// Clients tracked now.
    pub clients_tracked: usize,
    /// Most queries first; an IPv6 client is its /56 ([`CLIENT_V6_PREFIX`]).
    pub top_clients: Vec<(IpAddr, ClientStats)>,
    pub names_tracked: usize,
    /// Most queries first.
    pub top_names: Vec<(String, NameStats)>,
    pub domains_tracked: usize,
    /// Most failures (NXDOMAIN + SERVFAIL) first.
    pub failing_domains: Vec<(String, DomainStats)>,
    /// The clock (ms) the rates were taken at.
    pub now_ms: u64,
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
    clients: TopK<IpAddr, ClientSlot, CLIENTS_PER_STRIPE>,
    names: TopK<String, Rate, NAMES_PER_STRIPE>,
    domains: TopK<String, DomainSlot, DOMAINS_PER_STRIPE>,
    /// The latest clock seen (the rates' "now" when the caller has none).
    last_ms: u64,
}

/// What a client's slot counts besides its queries.
#[derive(Debug, Clone, Copy, Default)]
struct ClientSlot {
    refused: u64,
    limited: u64,
    nxdomain: u64,
    last_ms: u64,
    rate: Rate,
}

/// What a failing domain's slot counts.
#[derive(Debug, Clone, Default)]
struct DomainSlot {
    nxdomain: u64,
    servfail: u64,
    rate: Rate,
    names: Hll,
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
            clients: TopK::default(),
            names: TopK::default(),
            domains: TopK::default(),
            last_ms: 0,
        }
    }
}

/// A stripe on cache lines of its own (no false sharing with the next).
#[derive(Debug, Default)]
#[repr(align(128))]
struct Stripe(Mutex<Shard>);

/// What one reply counts.
struct Event<'a> {
    category: usize,
    rcode: usize,
    qtype: Option<u16>,
    /// The name asked (lowercase, no final dot); none for a malformed one.
    name: Option<&'a str>,
    client: IpAddr,
    tcp: bool,
    refused: bool,
    truncated: bool,
    ede: Option<u16>,
    upstream: Option<IpAddr>,
    now_ms: u64,
}

/// The forwarder's statistics (`f.state::<Statistics>()`).
#[derive(Debug)]
pub struct Statistics {
    stripes: Box<[Stripe]>,
    /// Keys the hash of names, domains and clients (one for all stripes:
    /// their tables are summed by key).
    hasher: RandomState,
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
            hasher: RandomState::new(),
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

    /// The counters and the `top` clients, names and failing domains, all
    /// stripes summed, with the rates at the latest query counted.
    pub fn snapshot(&self, top: usize) -> Snapshot {
        self.gather(Some(top), None)
    }

    /// [`Self::snapshot`] with the rates and "last seen" taken at `now_ms`
    /// (the forwarder's clock: the daemon's `clock_ms`).
    pub fn snapshot_at(&self, top: usize, now_ms: Option<u64>) -> Snapshot {
        self.gather(Some(top), now_ms)
    }

    /// The counters only (no client is copied): what the engine reads
    /// every second for the graph and the window's "now" values.
    pub fn totals(&self) -> Counters {
        self.gather(None, None).counters
    }

    fn gather(&self, top: Option<usize>, now_ms: Option<u64>) -> Snapshot {
        let mut c = Counters::default();
        let mut transport = [0u64; 4];
        let mut answered = [0u64; CATEGORIES.len()];
        let mut rcodes = [0u64; OTHER_RCODE + 1];
        let mut types = [0u64; TYPES];
        let mut ede = [0u64; EDE_CODES + 1];
        let mut clients: HashMap<IpAddr, ClientStats> = HashMap::new();
        let mut names: HashMap<String, (NameStats, Vec<Rate>)> = HashMap::new();
        let mut domains: HashMap<String, (DomainStats, Vec<Rate>, Hll)> = HashMap::new();
        let mut latest = 0u64;
        // Rates are read per stripe at the end (each stripe's own buckets).
        let mut client_rates: Vec<(IpAddr, Rate)> = Vec::new();
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
            c.clients_replaced += g.clients.replaced();
            c.names_replaced += g.names.replaced();
            c.domains_replaced += g.domains.replaced();
            latest = latest.max(g.last_ms);
            if top.is_none() {
                continue;
            }
            for e in g.clients.iter() {
                let st = clients.entry(e.key).or_default();
                st.queries += e.count;
                st.error += e.error;
                st.refused += e.value.refused;
                st.limited += e.value.limited;
                st.nxdomain += e.value.nxdomain;
                st.last_ms = st.last_ms.max(e.value.last_ms);
                client_rates.push((e.key, e.value.rate));
            }
            for e in g.names.iter() {
                let (st, rates) = names.entry(e.key.clone()).or_default();
                st.queries += e.count;
                st.error += e.error;
                rates.push(e.value);
            }
            for e in g.domains.iter() {
                let (st, rates, hll) = domains.entry(e.key.clone()).or_default();
                st.nxdomain += e.value.nxdomain;
                st.servfail += e.value.servfail;
                st.error += e.error;
                rates.push(e.value.rate);
                hll.merge(&e.value.names);
            }
        }
        let now = now_ms.unwrap_or(latest).max(latest);
        for (ip, r) in client_rates {
            if let Some(st) = clients.get_mut(&ip) {
                st.per_sec += r.per_sec(now);
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
        let top = top.unwrap_or(0);
        let clients_tracked = clients.len();
        let mut top_clients: Vec<(IpAddr, ClientStats)> = clients
            .into_iter()
            .filter(|(_, c)| own(c.queries, c.error))
            .collect();
        top_clients.sort_by(|a, b| {
            floor(b.1.queries, b.1.error)
                .cmp(&floor(a.1.queries, a.1.error))
                .then(a.0.cmp(&b.0))
        });
        top_clients.truncate(top);
        let names_tracked = names.len();
        let mut top_names: Vec<(String, NameStats)> = names
            .into_iter()
            .map(|(k, (mut st, rates))| {
                st.per_sec = rates.iter().map(|r| r.per_sec(now)).sum();
                (k, st)
            })
            .filter(|(_, n)| own(n.queries, n.error))
            .collect();
        top_names.sort_by(|a, b| {
            floor(b.1.queries, b.1.error)
                .cmp(&floor(a.1.queries, a.1.error))
                .then_with(|| a.0.cmp(&b.0))
        });
        top_names.truncate(top);
        let domains_tracked = domains.len();
        let mut failing_domains: Vec<(String, DomainStats)> = domains
            .into_iter()
            .map(|(k, (mut st, rates, hll))| {
                st.per_sec = rates.iter().map(|r| r.per_sec(now)).sum();
                // Never more names than failures (the estimate's error).
                st.names = hll.estimate().min(st.nxdomain + st.servfail);
                (k, st)
            })
            .filter(|(_, d)| own(d.nxdomain + d.servfail, d.error))
            .collect();
        failing_domains.sort_by(|a, b| {
            let fails = |d: &DomainStats| floor(d.nxdomain + d.servfail, d.error);
            fails(&b.1).cmp(&fails(&a.1)).then_with(|| a.0.cmp(&b.0))
        });
        failing_domains.truncate(top);
        Snapshot {
            counters: c,
            clients_tracked,
            top_clients,
            names_tracked,
            top_names,
            domains_tracked,
            failing_domains,
            now_ms: now,
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
    pub(crate) fn malformed(&self, client: IpAddr, tcp: bool, reply: Option<&[u8]>, now_ms: u64) {
        // The reply's RCODE: the low 4 bits of byte 3 (RFC 1035 §4.1.1).
        let rcode = match reply {
            Some(r) => r.get(3).map_or(OTHER_RCODE, |b| usize::from(b & 0x0f)),
            None => DROPPED,
        };
        self.count(&Event {
            category: MALFORMED,
            rcode,
            qtype: None,
            name: None,
            client: client.to_canonical(),
            tcp,
            refused: true,
            truncated: false,
            ede: None,
            upstream: None,
            now_ms,
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
            name: Some(q.asked.key.as_str()),
            client: q.client,
            tcp: q.tcp,
            refused,
            truncated: q.truncated(),
            ede,
            upstream,
            now_ms: q.now_ms,
        });
    }

    fn count(&self, e: &Event<'_>) {
        // Hashed before the lock (the stripe is held for the counting only).
        let client = client_key(e.client);
        let client_hash = self.hasher.hash_one(client);
        let name = e.name.map(|n| (n, self.hasher.hash_one(n)));
        let failed = e.rcode == NXDOMAIN || e.rcode == SERVFAIL;
        let domain = name
            .filter(|_| failed)
            .map(|(n, _)| domain_of(n))
            .map(|d| (d, self.hasher.hash_one(d)));
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
        s.last_ms = s.last_ms.max(e.now_ms);
        let nx = e.rcode == NXDOMAIN;
        if let Some(c) = s.clients.add(client_hash, &client, 1) {
            let v = &mut c.value;
            v.refused += u64::from(e.refused);
            v.limited += u64::from(e.category == LIMIT);
            v.nxdomain += u64::from(nx);
            v.last_ms = v.last_ms.max(e.now_ms);
            v.rate.add(e.now_ms, 1);
        }
        if let Some((n, h)) = name
            && let Some(slot) = s.names.add(h, n, 1)
        {
            slot.value.add(e.now_ms, 1);
        }
        if let (Some((d, dh)), Some((_, nh))) = (domain, name)
            && let Some(slot) = s.domains.add(dh, d, 1)
        {
            let v = &mut slot.value;
            if nx {
                v.nxdomain += 1;
            } else {
                v.servfail += 1;
            }
            v.rate.add(e.now_ms, 1);
            v.names.add(nh);
        }
    }
}

/// The key a client counts under: itself, or its /56 for IPv6.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let keep = u128::MAX << (128 - u32::from(CLIENT_V6_PREFIX));
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & keep))
        }
        v4 => v4,
    }
}

/// Space-Saving's guaranteed part of a count: at least this many events
/// were the key's own. Lists sort by it, so a newcomer that took over a
/// slot's count does not sit among keys that earned theirs.
fn floor(count: u64, error: u64) -> u64 {
    count.saturating_sub(error)
}

/// Whether most of a count is the key's own (more than its inherited
/// `error`): a newcomer of a flood (count ≈ error) is tracked but not
/// listed.
fn own(count: u64, error: u64) -> bool {
    error == 0 || floor(count, error) > error
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
                            name: Some("www.example.com"),
                            client: IpAddr::from([10, t, (i % 7) as u8, 1]),
                            tcp: false,
                            refused: false,
                            truncated: i % 10 == 0,
                            ede: None,
                            upstream: None,
                            now_ms: 1000 + u64::from(i),
                        });
                    }
                });
            }
        });
        let snap = s.snapshot(1);
        let c = &snap.counters;
        let n = (STRIPES as u64 + 4) * 1000;
        assert_eq!((c.queries, c.udp4, c.truncated), (n, n, n / 10));
        assert_eq!(c.types.get(&1), Some(&n));
        assert_eq!(snap.top_names[0].0, "www.example.com");
        assert_eq!(snap.top_names[0].1.queries, n, "every stripe's count summed");
    }

    #[test]
    fn names_domains_and_clients() {
        use crate::server::tests::{LAN, Up, ask, forwarder, run};
        let f = forwarder(|c| c.ip.dns.max_queries_per_client = 0);
        let mut up = Up::new();
        for _ in 0..3 {
            run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A));
        }
        // A random-subdomain attack: every name new, every answer NXDOMAIN.
        for i in 0..300 {
            let name = format!("nope.r{i}.victim.com.br.");
            run(&f, &mut up, [192, 168, 88, 20], &ask(&name, RecordType::A));
        }
        let s = f.statistics().snapshot_at(5, Some(up.now));
        assert_eq!(s.top_names.len(), 5);
        assert_eq!(s.top_names[0].0, "www.example.com");
        assert_eq!(s.top_names[0].1.queries, 3);
        assert!(s.names_tracked <= NAMES_PER_STRIPE, "bounded: {}", s.names_tracked);
        assert!(
            s.top_names.iter().all(|(_, n)| n.error == 0 || n.queries - n.error > n.error),
            "no flood newcomer listed among the names: {:?}",
            s.top_names
        );
        let (d, st) = s.failing_domains.first().cloned().unwrap();
        assert_eq!(d, "victim.com.br", "every name under its domain");
        assert_eq!((st.nxdomain, st.servfail), (300, 0));
        assert!((260..=300).contains(&st.names), "≈300 different names: {}", st.names);
        assert!(st.per_sec > 0.0);
        // The clients: counts only, the attacker's NXDOMAIN share.
        let attacker = s.top_clients.iter().find(|(ip, _)| *ip == IpAddr::from([192, 168, 88, 20])).unwrap().1;
        assert_eq!((attacker.queries, attacker.nxdomain), (300, 300));
        assert!(attacker.last_ms > 0 && attacker.last_ms <= up.now, "seen at {}", attacker.last_ms);
        let lan = s.top_clients.iter().find(|(ip, _)| *ip == IpAddr::from(LAN)).unwrap().1;
        assert_eq!((lan.queries, lan.nxdomain, lan.limited), (3, 0, 0));
        f.statistics().reset();
        let s = f.statistics().snapshot(5);
        assert!(s.top_names.is_empty() && s.failing_domains.is_empty());
    }

    #[test]
    fn the_limit_and_ipv6_per_56() {
        let s = Statistics::default();
        let ev = |client: IpAddr, category: usize, rcode: usize| Event {
            category,
            rcode,
            qtype: Some(1),
            name: Some("a.example"),
            client,
            tcp: false,
            refused: category == LIMIT,
            truncated: false,
            ede: None,
            upstream: None,
            now_ms: 5_000,
        };
        let home: IpAddr = "2001:db8:1:ab12::1".parse().unwrap();
        let laptop: IpAddr = "2001:db8:1:abff:1234::9".parse().unwrap();
        let neighbour: IpAddr = "2001:db8:1:ac00::1".parse().unwrap();
        s.count(&ev(home, 0, 0));
        s.count(&ev(laptop, LIMIT, DROPPED));
        s.count(&ev(neighbour, 0, NXDOMAIN));
        let snap = s.snapshot(10);
        let prefix: IpAddr = "2001:db8:1:ab00::".parse().unwrap();
        let c = snap.top_clients.iter().find(|(ip, _)| *ip == prefix).unwrap().1;
        assert_eq!((c.queries, c.limited, c.refused), (2, 1, 1), "one /56, one home");
        assert_eq!(snap.clients_tracked, 2);
        assert_eq!(client_key("::ffff:10.0.0.1".parse().unwrap()), IpAddr::from([10, 0, 0, 1]));
        // A SERVFAIL counts for the domain too; a NOERROR does not.
        assert_eq!(snap.failing_domains.len(), 1);
        assert_eq!(snap.failing_domains[0].1.nxdomain, 1);
        s.count(&ev(home, 2, SERVFAIL));
        assert_eq!(s.snapshot(10).failing_domains[0].1.servfail, 1);
        // The rates: 4 queries at 5 s, read at 10 s (half of the window
        // still holds them).
        let at = s.snapshot_at(10, Some(10_000));
        let total: f64 = at.top_clients.iter().map(|(_, c)| c.per_sec).sum();
        assert!((total - 0.4).abs() < 1e-9, "{total}");
        assert_eq!(at.now_ms, 10_000);
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

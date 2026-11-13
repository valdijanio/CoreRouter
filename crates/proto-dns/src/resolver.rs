//! The router's resolver: cache first, then the upstream servers, each for
//! at most `query_server_timeout`, all of them for at most
//! `query_total_timeout`. Two ways to pick the order (`server_selection`):
//! `sequential` is RouterOS (static servers, then the dynamic ones; the
//! last one that answered goes first next time), `fastest` measures each
//! server's latency and asks the fastest first, a failing one going last
//! for a minute. A truncated UDP answer is asked again over TCP on the same
//! server (RFC 7766 §5). NXDOMAIN is final: another server would say the
//! same. When every server fails, an expired answer still inside the
//! serve-stale window is used (RFC 8767).
//!
//! The router's own lookups (ping, NTP: [`Resolver::lookup`]) and the LAN
//! forwarder ([`Resolver::resolve`], any record type) share the cache.
//!
//! G4.1d: an upstream may be encrypted (DoH, DoT: `encrypted.rs`) —
//! `use_doh_server` for everything, or a `/ip dns forwarders` group for
//! a static FWD entry ([`Upstreams`]). Its host name is resolved by the
//! static entries or the plain servers (RouterOS), never by itself.
//!
//! RFC 9520: a name and type that no server could answer is not asked
//! again for a while (5 s, doubling up to 5 min while it keeps failing);
//! the lookups in between fail at once (or get the stale answer), so a
//! dead domain asked by every client does not keep every server busy.
//!
//! No sockets here. A lookup is a state machine ([`Lookup`], G4.1t):
//! [`Resolver::begin`] answers from the cache or starts one, the caller
//! moves its messages, [`Resolver::complete`] keeps the result. The
//! daemon's event loop carries thousands of them on a few sockets; the
//! blocking [`Resolver::resolve`] runs one over a [`Transport`] (the
//! router's tools; a fake in tests). The lock is held only around the
//! cache, never across the network, so one slow lookup does not stall the
//! others.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};

mod flight;
mod lookup;
use flight::{Flights, Role};
pub use flight::{Follow, MAX_WAITING, Waiter};
pub use lookup::{Exchange, Lookup, Way};

use corerouter_model::Config;
use corerouter_model::dns::{CacheRow, Dns, ServerSelection};
use hickory_proto::rr::RecordType;

use crate::cache::{Cache, Hit};
use crate::encrypted::SecureServer;
use crate::histogram::Hist;
use crate::message::{Answer, NameError, QName, Rcode, parse_name};

/// Moves bytes to a server and back.
pub trait Transport {
    /// Milliseconds of a monotonic clock (any origin).
    fn now_ms(&self) -> u64;

    /// Sends `query` to `server` and returns the first message `accept`
    /// takes, waiting at most `wait_ms`. Over UDP, messages `accept`
    /// refuses (late or spoofed) are skipped; over TCP the stream is
    /// framed with the 2-byte length of RFC 1035 §4.2.2.
    fn exchange(
        &mut self,
        server: SocketAddr,
        query: &[u8],
        tcp: bool,
        wait_ms: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError>;

    /// Sends `query` to an encrypted server (`via`) at `server` and returns
    /// its answer, waiting at most `wait_ms`. Only the daemon speaks TLS.
    fn exchange_secure(
        &mut self,
        server: SocketAddr,
        via: &SecureServer,
        query: &[u8],
        wait_ms: u64,
    ) -> Result<Vec<u8>, TransportError> {
        let _ = (server, via, query, wait_ms);
        Err(TransportError::Io(
            "DNS over TLS/HTTPS needs the router daemon".into(),
        ))
    }
}

/// Where a lookup goes instead of the configured servers: a static FWD
/// entry's servers, or a `/ip dns forwarders` group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Upstreams {
    pub servers: Vec<IpAddr>,
    pub secure: Vec<SecureServer>,
}

impl Upstreams {
    pub fn plain(servers: Vec<IpAddr>) -> Self {
        Self {
            servers,
            secure: Vec::new(),
        }
    }

    /// The group `name` of `cfg` (`None`: no such group, or disabled).
    pub fn group(cfg: &Config, name: &str) -> Option<Self> {
        let g = cfg.ip.dns_forwarders.get(name).filter(|g| !g.disabled)?;
        Some(Self {
            servers: g.dns_servers.clone(),
            secure: g
                .doh_servers
                .iter()
                .filter_map(|u| SecureServer::parse(u, g.verify_doh_cert).ok())
                .collect(),
        })
    }
}

/// One server to ask, as `fetch` sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Plain(IpAddr),
    /// An encrypted server, at one of its addresses.
    Secure(IpAddr, SecureServer),
}

impl Target {
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::Plain(ip) | Self::Secure(ip, _) => *ip,
        }
    }
}

/// An encrypted exchange waits at least this long: a TLS handshake is two
/// round trips more (RouterOS `doh-timeout` 5 s).
pub const SECURE_TIMEOUT_MS: u64 = 5000;
/// A lookup waiting for an equal one in flight (G4.1o) gives up this long
/// after the leader's own deadline.
const FOLLOW_SLACK_MS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    #[error("no answer")]
    Timeout,
    #[error("{0}")]
    Io(String),
}

/// What a lookup uses, taken from `/ip dns` and the learned servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub servers: Vec<IpAddr>,
    pub port: u16,
    pub server_timeout_ms: u32,
    pub total_timeout_ms: u32,
    pub udp_payload: u16,
    pub max_ttl: u32,
    pub cache_bytes: usize,
    pub selection: ServerSelection,
    pub stale_secs: u32,
    /// `max_concurrent_queries`: lookups in flight upstream at most
    /// (G4.1t; equal ones waiting for them do not count).
    pub max_queries: u32,
    /// `use_doh_server`: asked instead of `servers` (G4.1d).
    pub secure: Vec<SecureServer>,
    /// Static A/AAAA names, for an encrypted server's host name.
    pub hosts: Vec<(String, IpAddr)>,
}

impl Settings {
    /// Static servers first, then the dynamic ones, without repeats.
    pub fn new(dns: &Dns, dynamic: &[IpAddr]) -> Self {
        let mut servers: Vec<IpAddr> = Vec::new();
        for ip in dns.servers.iter().chain(dynamic) {
            if !servers.contains(ip) {
                servers.push(*ip);
            }
        }
        Self {
            servers,
            port: crate::message::PORT,
            server_timeout_ms: dns.query_server_timeout_ms,
            total_timeout_ms: dns.query_total_timeout_ms,
            udp_payload: dns.max_udp_packet_size,
            max_ttl: dns.cache_max_ttl_secs,
            cache_bytes: usize::try_from(dns.cache_size)
                .unwrap_or(usize::MAX)
                .saturating_mul(1024),
            selection: dns.server_selection,
            stale_secs: dns.serve_stale_secs,
            max_queries: dns.max_concurrent_queries,
            secure: SecureServer::parse(&dns.use_doh_server, dns.verify_doh_cert)
                .ok()
                .into_iter()
                .collect(),
            hosts: Vec::new(),
        }
    }

    /// [`Self::new`], plus the static A/AAAA names (an encrypted server's
    /// name is looked up there first, as RouterOS advises).
    pub fn from_config(cfg: &Config, dynamic: &[IpAddr]) -> Self {
        use corerouter_model::dns_static::StaticType;
        let mut s = Self::new(&cfg.ip.dns, dynamic);
        if !s.secure.is_empty() || !cfg.ip.dns_forwarders.entries.is_empty() {
            s.hosts = cfg
                .ip
                .dns_static
                .entries
                .iter()
                .filter(|e| !e.disabled && e.regexp.is_empty())
                .filter(|e| matches!(e.rtype, StaticType::A | StaticType::Aaaa))
                .filter_map(|e| Some((e.name.to_ascii_lowercase(), e.address?)))
                .collect();
        }
        s
    }

    /// Whether any server is configured (plain or encrypted).
    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty() || !self.secure.is_empty()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(&Dns::default(), &[])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error(
        "no DNS server configured: set one with ip.dns.set servers=… or a DHCP client with use_peer_dns"
    )]
    NoServers,
    #[error("{0}")]
    BadName(#[from] NameError),
    #[error("name '{0}' does not exist")]
    NotFound(String),
    #[error("name '{name}' could not be resolved: {why}")]
    Failed { name: String, why: String },
    /// `max_concurrent_queries` lookups in flight already (G4.1t).
    #[error("too many lookups in flight (max_concurrent_queries)")]
    Busy,
}

/// Where an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cache,
    Server(IpAddr),
    /// Expired, served because no server answered (RFC 8767).
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub answer: Answer,
    pub source: Source,
}

/// Latency a server is assumed to have before it answered once (Unbound's
/// `UNKNOWN_SERVER_NICENESS`): a known fast server goes first, an unknown
/// one before a slow one. Also its first retransmission timeout (G4.1u;
/// Knot Resolver starts at 400 ms).
const UNKNOWN_RTT_MS: u64 = 376;
/// G4.1u: the shortest retransmission timeout (Unbound's `RTT_MIN_TIMEOUT`;
/// RFC 6298 §2.4's 1 s is for TCP segments, not a 50-byte query)…
pub const RTO_MIN_MS: u64 = 50;
/// …and the longest kept (Unbound's `RTT_MAX_TIMEOUT`; RFC 6298 §2.5: at
/// least 60 s). A query never waits more than `query_server_timeout`.
pub const RTO_MAX_MS: u64 = 120_000;
/// Timeouts in a row before a server counts as down (one lost datagram
/// does not; Knot Resolver: 4). A definite failure (SERVFAIL, refused,
/// unreachable) counts at once.
const DOWN_AFTER_TIMEOUTS: u32 = 3;
/// A server that failed goes last for this long (`fastest`).
const DOWN_MS: u64 = 60_000;

/// What the resolver knows of one server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Smoothed round-trip time (RFC 6298 §2.3: 7/8 old + 1/8 new).
    pub srtt_ms: Option<u64>,
    /// Its variation (RFC 6298 §2.3: 3/4 old + 1/4 new) (G4.1u).
    pub rttvar_ms: u64,
    /// Retransmission timeout: SRTT + 4·RTTVAR, doubled after a timeout
    /// (RFC 6298 §2.2, §5.5), within [`RTO_MIN_MS`]..[`RTO_MAX_MS`]; 0:
    /// never measured ([`UNKNOWN_RTT_MS`]) (G4.1u).
    pub rto_ms: u64,
    /// Timeouts since its last answer.
    pub timeouts_in_row: u32,
    pub down_until_ms: u64,
    pub answers: u64,
    pub failures: u64,
    /// G4.1h: of the failures, no answer in time and SERVFAIL from it.
    pub timeouts: u64,
    pub servfails: u64,
    /// UDP answers with TC asked again over TCP (RFC 7766 §5).
    pub truncated: u64,
    /// Round-trip times of its answers.
    pub rtt: Hist,
    /// How it was asked the last time.
    pub via: Via,
    /// When it last went down or came back (the transport's clock, ms;
    /// 0: never changed).
    pub changed_ms: u64,
}

/// How a server is asked (G4.1h).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Via {
    /// UDP, TCP when truncated.
    #[default]
    Plain,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "udp",
            Self::Tls => "dot",
            Self::Https => "doh",
        }
    }
}

#[derive(Debug, Default)]
struct State {
    settings: Arc<Settings>,
    cache: Cache,
    /// The last server that answered (RouterOS keeps using it).
    preferred: Option<IpAddr>,
    stats: BTreeMap<IpAddr, ServerStats>,
    /// RFC 9520 §3.2: recent failures, by name and type.
    failures: HashMap<(String, RecordType), Failure>,
}

/// A name and type no server could answer (RFC 9520 §2).
#[derive(Debug, Clone)]
struct Failure {
    /// Not asked again before this.
    until_ms: u64,
    /// The hold this time; doubled on the next failure.
    hold_ms: u64,
    why: String,
}

/// RFC 9520 §3.2: the first hold (the RFC's example starts at 5 s; at
/// least 1 s, MUST)…
pub const FAILURE_HOLD_MS: u64 = 5_000;
/// …doubling up to this (MUST NOT exceed 5 minutes).
pub const FAILURE_MAX_HOLD_MS: u64 = 300_000;
/// Failures remembered at most (§3.2: the cache SHOULD be bounded).
pub const MAX_FAILURES: usize = 4096;

/// Resolver shared by every thread of the router (tools, NTP, the LAN
/// forwarder).
#[derive(Debug, Default)]
pub struct Resolver {
    state: Mutex<State>,
    /// G4.1o: lookups in flight.
    flights: Arc<Flights>,
}

impl Resolver {
    pub fn new(settings: Settings) -> Self {
        let mut cache = Cache::new(settings.cache_bytes);
        cache.set_stale(settings.stale_secs);
        Self {
            state: Mutex::new(State {
                settings: Arc::new(settings),
                cache,
                preferred: None,
                stats: BTreeMap::new(),
                failures: HashMap::new(),
            }),
            flights: Arc::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A panic elsewhere never makes the resolver unusable.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// New settings (config change or a DHCP lease). The cache stays,
    /// shrunk to the new budget; a server no longer listed stops being
    /// preferred.
    pub fn configure(&self, settings: Settings, _now_ms: u64) {
        let mut st = self.state();
        if *st.settings == settings {
            return;
        }
        st.cache.set_budget(settings.cache_bytes);
        st.cache.set_stale(settings.stale_secs);
        if st.preferred.is_some_and(|p| !settings.servers.contains(&p)) {
            st.preferred = None;
        }
        st.settings = Arc::new(settings);
    }

    pub fn settings(&self) -> Settings {
        (*self.state().settings).clone()
    }

    pub fn cache_rows(&self, now_ms: u64) -> Vec<CacheRow> {
        self.state().cache.rows(now_ms)
    }

    /// See [`Cache::rows_matching`].
    pub fn cache_rows_matching(
        &self,
        now_ms: u64,
        name: Option<&str>,
        qtype: Option<&str>,
        limit: usize,
    ) -> Vec<CacheRow> {
        self.state().cache.rows_matching(now_ms, name, qtype, limit)
    }

    pub fn cache_len(&self) -> usize {
        self.state().cache.len()
    }

    pub fn cache_used_bytes(&self) -> usize {
        self.state().cache.used_bytes()
    }

    /// Entries, bytes, evictions and types of the cache (G4.1h).
    pub fn cache_stats(&self) -> crate::cache::CacheStats {
        self.state().cache.stats()
    }

    /// Empties the cache and the failure holds. The entries are freed
    /// after the lock is let go: lookups do not wait for it (G4.1r).
    pub fn flush(&self) {
        let old = {
            let mut st = self.state();
            st.failures.clear();
            st.cache.take()
        };
        drop(old);
    }

    /// Names and types held after a failure now (RFC 9520).
    pub fn failures(&self, now_ms: u64) -> usize {
        self.state()
            .failures
            .values()
            .filter(|f| f.until_ms > now_ms)
            .count()
    }

    /// Seconds `key`/`rtype` stays held after a failure (RFC 9520 §3.2):
    /// no server is asked until then. `None`: not held.
    pub fn held_secs(&self, key: &str, rtype: RecordType, now_ms: u64) -> Option<u64> {
        self.state()
            .failures
            .get(&(key.to_owned(), rtype))
            .filter(|f| f.until_ms > now_ms)
            .map(|f| f.until_ms.saturating_sub(now_ms).div_ceil(1000))
    }

    /// What the resolver measured of each server it asked.
    pub fn server_stats(&self) -> Vec<(IpAddr, ServerStats)> {
        self.state().stats.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// The fresh cached answer, if any (never touches the network).
    pub fn cached(&self, key: &str, rtype: RecordType, now_ms: u64) -> Option<Hit> {
        self.state().cache.get(key, rtype, now_ms)
    }

    /// Addresses of `name`: IPv4 first, then IPv6. IP literals come back
    /// as they are.
    pub fn lookup(&self, t: &mut dyn Transport, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(ip) = name.trim().parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let qn = parse_name(name)?;
        if let Some(special) = special_use(&qn) {
            return special;
        }
        let mut out = Vec::new();
        let mut failure = None;
        for rtype in [RecordType::A, RecordType::AAAA] {
            match self.resolve(t, &qn, rtype, None) {
                // RFC 2308 §2.1: no such name, for any type.
                Ok(r) if r.answer.rcode == Rcode::NxDomain => break,
                Ok(r) => out.extend(r.answer.addresses()),
                Err(e @ ResolveError::NoServers) => return Err(e),
                // Every server failed for A: AAAA would wait as long again.
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        match (out.is_empty(), failure) {
            (false, _) => Ok(out),
            (true, Some(e)) => Err(e),
            (true, None) => Err(ResolveError::NotFound(qn.key)),
        }
    }

    /// One name and type: from the cache, or asked (of `via` when a
    /// static FWD entry says so, else of `use_doh_server` or the
    /// configured servers) and then cached; stale when every server failed
    /// (RFC 8767).
    pub fn resolve(
        &self,
        t: &mut dyn Transport,
        qn: &QName,
        rtype: RecordType,
        via: Option<&Upstreams>,
    ) -> Result<Resolved, ResolveError> {
        match self.begin(qn, rtype, via, t.now_ms()) {
            Begin::Now(r) => r,
            Begin::Follow(flight) => {
                let settings = self.state().settings.clone();
                let wait =
                    u64::from(settings.total_timeout_ms).max(SECURE_TIMEOUT_MS) + FOLLOW_SLACK_MS;
                let until = t.now_ms().saturating_add(wait);
                flight.wait(until, &|| t.now_ms()).unwrap_or_else(|| {
                    Err(ResolveError::Failed {
                        name: qn.key.clone(),
                        why: format!(
                            "no answer in {wait} ms (waiting for the same lookup in flight)"
                        ),
                    })
                })
            }
            Begin::Lead(mut lookup) => {
                self.drive(t, &mut lookup);
                self.complete(*lookup, t.now_ms())
            }
        }
    }

    /// The part of a lookup that needs no network (G4.1t): the cache, a
    /// held failure (RFC 9520), the equal lookup in flight to follow
    /// (G4.1o), or a new [`Lookup`] to lead, which the caller runs and
    /// hands to [`Self::complete`]. Past `max_concurrent_queries` lookups
    /// in flight: [`ResolveError::Busy`].
    pub fn begin(&self, qn: &QName, rtype: RecordType, via: Option<&Upstreams>, now: u64) -> Begin {
        let (settings, plain, secure, rtos) = {
            let mut st = self.state();
            if let Some(hit) = st.cache.get(&qn.key, rtype, now) {
                return Begin::Now(Ok(Resolved {
                    answer: hit.answer,
                    source: Source::Cache,
                }));
            }
            // RFC 9520 §3.2: no query while a failure is held; the stale
            // answer (RFC 8767) still serves.
            let failed_key = (qn.key.clone(), rtype);
            if let Some(f) = st
                .failures
                .get(&failed_key)
                .filter(|f| f.until_ms > now)
                .cloned()
            {
                if let Some(hit) = st.cache.get_stale(&qn.key, rtype, now) {
                    return Begin::Now(Ok(Resolved {
                        answer: hit.answer,
                        source: Source::Stale,
                    }));
                }
                return Begin::Now(Err(ResolveError::Failed {
                    name: qn.key.clone(),
                    why: format!(
                        "{} (failed recently; asked again in {} s, RFC 9520)",
                        f.why,
                        f.until_ms.saturating_sub(now).div_ceil(1000)
                    ),
                }));
            }
            let (plain, secure) = match via {
                Some(u) => (sorted(&st, &u.servers, now), u.secure.clone()),
                None if !st.settings.secure.is_empty() => (Vec::new(), st.settings.secure.clone()),
                None => (order(&st, now), Vec::new()),
            };
            // G4.1u: each server's retransmission timeout as it stands.
            let rtos: Vec<(IpAddr, u64)> = plain
                .iter()
                .map(|ip| {
                    let rto = st.stats.get(ip).map_or(0, |s| s.rto_ms);
                    (*ip, if rto == 0 { UNKNOWN_RTT_MS } else { rto })
                })
                .collect();
            (st.settings.clone(), plain, secure, rtos)
        };
        // G4.1o: one lookup per name, type and upstreams in flight; the
        // equal ones wait for its result (`resolver/flight.rs`). No second
        // look at the cache here: a lookup that missed it just before the
        // previous leader filled it and joins just after that leader left
        // asks again (one extra query, rare); the look cost ~110 ns on
        // every miss (`benches/forwarder.rs`, G4.1r).
        let max = usize::try_from(settings.max_queries).unwrap_or(usize::MAX);
        let lead = match self
            .flights
            .join((qn.key.clone(), rtype, via.cloned()), max)
        {
            Role::Lead(lead) => lead,
            Role::Follow(f) => return Begin::Follow(f),
            Role::Busy => return Begin::Now(Err(ResolveError::Busy)),
        };
        let mut targets: Vec<Target> = plain.into_iter().map(Target::Plain).collect();
        let mut unresolved = Vec::new();
        for s in secure {
            match pinned_addrs(&settings, &s) {
                // Two addresses at most: a dead one, then a live one.
                Some(ips) => targets.extend(
                    ips.into_iter()
                        .take(2)
                        .map(|ip| Target::Secure(ip, s.clone())),
                ),
                None => unresolved.push(s),
            }
        }
        let mut lookup = Lookup::new(
            qn.clone(),
            rtype,
            via.cloned(),
            settings,
            targets,
            unresolved,
            Some(lead),
        );
        lookup.rtos = rtos;
        Begin::Lead(Box::new(lookup))
    }

    /// Runs `lookup` to the end with blocking exchanges (the router's own
    /// tools, the tests; the daemon's threads for encrypted servers).
    pub fn drive(&self, t: &mut dyn Transport, lookup: &mut Lookup) {
        // An encrypted server named by host: its address first (asked of
        // the plain servers, never of itself: RouterOS).
        for s in std::mem::take(&mut lookup.unresolved) {
            match self.secure_addrs(t, &lookup.settings, &s) {
                Ok(ips) => lookup.targets.extend(
                    ips.into_iter()
                        .take(2)
                        .map(|ip| Target::Secure(ip, s.clone())),
                ),
                Err(why) => lookup.errors.push(why),
            }
        }
        let mut next = lookup.start(t.now_ms());
        while let Some(x) = next.pop() {
            let got = match &x.way {
                Way::Secure(s) => t.exchange_secure(x.server, s, &x.query, x.wait_ms),
                way => {
                    let l = &*lookup;
                    t.exchange(x.server, &x.query, *way == Way::Tcp, x.wait_ms, &mut |b| {
                        l.accepts(x.token, b)
                    })
                }
            };
            let now = t.now_ms();
            next.extend(match got {
                Ok(b) => lookup.reply(x.token, &b, now),
                Err(e) => lookup.failed(x.token, e, now),
            });
        }
    }

    /// The end of a lookup this resolver led ([`Self::begin`]): the server
    /// statistics, the failure hold and the cache updated, the result
    /// given to the equal lookups that waited (G4.1o) and returned. A
    /// lookup that failed everywhere serves the stale answer (RFC 8767).
    pub fn complete(&self, mut lookup: Lookup, now_ms: u64) -> Result<Resolved, ResolveError> {
        let result = self.record(&mut lookup, now_ms);
        if let Some(lead) = lookup.lead.take() {
            lead.finish(&result);
        }
        result
    }

    fn record(&self, lookup: &mut Lookup, now: u64) -> Result<Resolved, ResolveError> {
        let fetched = lookup.take_result();
        let qn = &lookup.qn;
        let rtype = lookup.rtype;
        let settings = lookup.settings.clone();
        let asked: Vec<IpAddr> = lookup.targets.iter().map(Target::ip).collect();
        let mut st = self.state();
        for tr in &lookup.tried {
            let s = st.stats.entry(tr.ip).or_default();
            let was_down = s.down_until_ms > now;
            s.via = tr.via;
            s.truncated = s.truncated.saturating_add(u64::from(tr.truncated));
            match tr.outcome {
                Outcome::Answered(ms) => {
                    // RFC 6298 §2.2 (first sample) and §2.3.
                    match s.srtt_ms {
                        None => {
                            s.srtt_ms = Some(ms);
                            s.rttvar_ms = ms / 2;
                        }
                        Some(old) => {
                            s.rttvar_ms = (s.rttvar_ms * 3 + old.abs_diff(ms)) / 4;
                            s.srtt_ms = Some((old * 7 + ms) / 8);
                        }
                    }
                    let srtt = s.srtt_ms.unwrap_or(ms);
                    s.rto_ms = srtt
                        .saturating_add(s.rttvar_ms.saturating_mul(4))
                        .clamp(RTO_MIN_MS, RTO_MAX_MS);
                    s.timeouts_in_row = 0;
                    s.down_until_ms = 0;
                    s.answers = s.answers.saturating_add(1);
                    s.rtt.add_ms(ms);
                }
                Outcome::Timeout => {
                    // RFC 6298 §5.5: back off. From the RTO this query
                    // waited, not the current one: many queries timing out
                    // together double it once (Unbound's `rtt_lost`).
                    let now_rto = if s.rto_ms == 0 {
                        UNKNOWN_RTT_MS
                    } else {
                        s.rto_ms
                    };
                    s.rto_ms = now_rto
                        .max(tr.rto_ms.saturating_mul(2))
                        .clamp(RTO_MIN_MS, RTO_MAX_MS);
                    s.timeouts_in_row = s.timeouts_in_row.saturating_add(1);
                    if s.timeouts_in_row >= DOWN_AFTER_TIMEOUTS {
                        s.down_until_ms = now.saturating_add(DOWN_MS);
                    }
                    s.failures = s.failures.saturating_add(1);
                    s.timeouts = s.timeouts.saturating_add(1);
                }
                failed => {
                    s.down_until_ms = now.saturating_add(DOWN_MS);
                    s.failures = s.failures.saturating_add(1);
                    if failed == Outcome::ServFail {
                        s.servfails = s.servfails.saturating_add(1);
                    }
                }
            }
            if was_down != (s.down_until_ms > now) {
                s.changed_ms = now;
            }
        }
        // Forget servers no longer configured (the map stays small); a
        // group's servers stay while there is room.
        if st.stats.len() > MAX_STATS {
            let keep = st.settings.servers.clone();
            st.stats
                .retain(|ip, _| keep.contains(ip) || asked.contains(ip));
        }
        let key = (qn.key.clone(), rtype);
        match &fetched {
            Ok(_) => {
                st.failures.remove(&key);
            }
            Err(ResolveError::Failed { why, .. }) => {
                let hold = st
                    .failures
                    .get(&key)
                    .map_or(FAILURE_HOLD_MS, |f| f.hold_ms.saturating_mul(2))
                    .clamp(FAILURE_HOLD_MS, FAILURE_MAX_HOLD_MS);
                if st.failures.len() >= MAX_FAILURES {
                    st.failures.retain(|_, f| f.until_ms > now);
                }
                if st.failures.len() < MAX_FAILURES || st.failures.contains_key(&key) {
                    st.failures.insert(
                        key,
                        Failure {
                            until_ms: now.saturating_add(hold),
                            hold_ms: hold,
                            why: why.chars().take(200).collect(),
                        },
                    );
                }
            }
            Err(_) => {}
        }
        match fetched {
            Ok((answer, server, wire)) => {
                if lookup.via.is_none() && settings.secure.is_empty() {
                    st.preferred = Some(server);
                }
                st.cache.put(
                    &qn.key,
                    rtype,
                    &answer,
                    Some(server),
                    now,
                    settings.max_ttl,
                    wire,
                );
                Ok(Resolved {
                    answer,
                    source: Source::Server(server),
                })
            }
            Err(e) => match st.cache.get_stale(&qn.key, rtype, now) {
                Some(hit) => Ok(Resolved {
                    answer: hit.answer,
                    source: Source::Stale,
                }),
                None => Err(e),
            },
        }
    }

    /// `qn`/`rtype` asked of `server` alone, past the cache, the equal
    /// lookups in flight and the statistics (RouterOS `:resolve server=`).
    pub fn ask_server(
        &self,
        t: &mut dyn Transport,
        qn: &QName,
        rtype: RecordType,
        server: IpAddr,
    ) -> Result<(Answer, IpAddr), ResolveError> {
        let settings = self.state().settings.clone();
        let mut lookup = Lookup::new(
            qn.clone(),
            rtype,
            None,
            settings,
            vec![Target::Plain(server)],
            Vec::new(),
            None,
        );
        self.drive(t, &mut lookup);
        lookup.take_result().map(|(answer, from, _)| (answer, from))
    }

    /// Lookups in flight upstream (G4.1t: at most `max_concurrent_queries`)
    /// and equal ones waiting for them (G4.1o).
    pub fn in_flight(&self) -> (usize, usize) {
        self.flights.counts()
    }
}

/// What [`Resolver::begin`] found.
#[derive(Debug)]
pub enum Begin {
    /// Answered without the network (cache, held failure, busy).
    Now(Result<Resolved, ResolveError>),
    /// The same lookup is in flight: wait for its result.
    Follow(Follow),
    /// Ask the servers: run it, then [`Resolver::complete`].
    Lead(Box<Lookup>),
}

/// An encrypted server's address without asking anyone: its literal or a
/// static entry (`None`: it must be looked up).
fn pinned_addrs(settings: &Settings, s: &SecureServer) -> Option<Vec<IpAddr>> {
    if let Some(ip) = s.ip() {
        return Some(vec![ip]);
    }
    let pinned: Vec<IpAddr> = settings
        .hosts
        .iter()
        .filter(|(n, _)| *n == s.host)
        .map(|(_, ip)| *ip)
        .collect();
    (!pinned.is_empty()).then_some(pinned)
}

impl Resolver {
    /// The addresses of an encrypted server: its literal, a static entry,
    /// or asked of the plain servers (never of itself: RouterOS).
    fn secure_addrs(
        &self,
        t: &mut dyn Transport,
        settings: &Settings,
        s: &SecureServer,
    ) -> Result<Vec<IpAddr>, String> {
        if let Some(ips) = pinned_addrs(settings, s) {
            return Ok(ips);
        }
        let why = |e: String| format!("{}: cannot resolve {}: {e}", s.url(), s.host);
        if settings.servers.is_empty() {
            return Err(why(
                "add a static entry for it, or a plain server in ip.dns servers".into(),
            ));
        }
        let qn = parse_name(&s.host).map_err(|e| why(e.to_string()))?;
        let plain = Upstreams::plain(settings.servers.clone());
        let mut out = Vec::new();
        for rtype in [RecordType::A, RecordType::AAAA] {
            match self.resolve(t, &qn, rtype, Some(&plain)) {
                Ok(r) if r.answer.rcode == Rcode::NxDomain => break,
                Ok(r) => out.extend(r.answer.addresses()),
                Err(e) => return Err(why(e.to_string())),
            }
            if !out.is_empty() {
                break;
            }
        }
        if out.is_empty() {
            Err(why("no address".into()))
        } else {
            Ok(out)
        }
    }

    /// PTR names or TXT texts (`rtype`) of `name`, from the cache or
    /// asked; a name that does not exist, or has none, gives no records
    /// (G6.3b).
    pub fn records(
        &self,
        t: &mut dyn Transport,
        name: &str,
        rtype: RecordType,
    ) -> Result<Vec<String>, ResolveError> {
        let qn = parse_name(name)?;
        if special_use(&qn).is_some() {
            return Ok(Vec::new());
        }
        Ok(self.resolve(t, &qn, rtype, None)?.answer.texts())
    }

    /// The name of `ip` (its first PTR, RFC 1035 §3.5 / RFC 3596 §2.5).
    pub fn reverse(
        &self,
        t: &mut dyn Transport,
        ip: IpAddr,
    ) -> Result<Option<String>, ResolveError> {
        let name = crate::reverse::reverse_name(ip);
        Ok(self
            .records(t, &name, RecordType::PTR)?
            .first()
            .map(|n| crate::reverse::printable(n, crate::message::MAX_NAME_LEN)))
    }
}

/// RFC 6761 §6.3: `localhost` is the loopback, never asked upstream;
/// §6.4: `invalid` never exists.
fn special_use(qn: &QName) -> Option<Result<Vec<IpAddr>, ResolveError>> {
    let k = qn.key.as_str();
    if k == "localhost" || k.ends_with(".localhost") {
        return Some(Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]));
    }
    if k == "invalid" || k.ends_with(".invalid") {
        return Some(Err(ResolveError::NotFound(qn.key.clone())));
    }
    None
}

/// Server stats kept at most beyond the configured servers.
const MAX_STATS: usize = 64;

/// `list` (a group's servers) by the same rule as `order`, without the
/// preferred server.
fn sorted(st: &State, list: &[IpAddr], now_ms: u64) -> Vec<IpAddr> {
    let mut out = list.to_vec();
    if st.settings.selection == ServerSelection::Fastest {
        out.sort_by_key(|ip| {
            let s = st.stats.get(ip).copied().unwrap_or_default();
            (
                s.down_until_ms > now_ms,
                s.srtt_ms.unwrap_or(UNKNOWN_RTT_MS),
            )
        });
    }
    out
}

/// Servers in asking order.
fn order(st: &State, now_ms: u64) -> Vec<IpAddr> {
    let servers = &st.settings.servers;
    match st.settings.selection {
        // The preferred one first, then the list.
        ServerSelection::Sequential => {
            let mut out: Vec<IpAddr> = st
                .preferred
                .filter(|p| servers.contains(p))
                .into_iter()
                .collect();
            out.extend(servers.iter().filter(|s| Some(**s) != st.preferred));
            out
        }
        // Up before down, then by latency; ties keep the list order.
        ServerSelection::Fastest => {
            let mut out = servers.clone();
            out.sort_by_key(|ip| {
                let s = st.stats.get(ip).copied().unwrap_or_default();
                (
                    s.down_until_ms > now_ms,
                    s.srtt_ms.unwrap_or(UNKNOWN_RTT_MS),
                )
            });
            out
        }
    }
}

/// One server asked for a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tried {
    pub ip: IpAddr,
    pub via: Via,
    pub outcome: Outcome,
    /// Its UDP answer was truncated and it was asked again over TCP.
    pub truncated: bool,
    /// The server's RTO the query went with (G4.1u; a timeout backs off
    /// from it).
    pub rto_ms: u64,
}

/// How a server did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered, in this many milliseconds.
    Answered(u64),
    Timeout,
    ServFail,
    /// Refused, malformed, a network error.
    Failed,
}

fn tried(ip: IpAddr, via: Via, outcome: Outcome, truncated: bool, rto_ms: u64) -> Tried {
    Tried {
        ip,
        via,
        outcome,
        truncated,
        rto_ms,
    }
}

fn failed(qn: &QName, errors: &[String]) -> ResolveError {
    let mut why = errors.join("; ");
    if why.len() > 300 {
        let mut cut = 297;
        while !why.is_char_boundary(cut) {
            cut -= 1;
        }
        why.truncate(cut);
        why.push_str("...");
    }
    ResolveError::Failed {
        name: qn.key.clone(),
        why,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::{a, reply};
    use hickory_proto::op::{Message, ResponseCode};
    use std::collections::BTreeMap;

    #[derive(Clone, Copy)]
    enum Behave {
        Answer([u8; 4]),
        Silent,
        ServFail,
        NxDomain,
        /// UDP truncated, TCP answers.
        Truncate([u8; 4]),
        /// A stray reply (other id) first, then the real one.
        Spoofed([u8; 4]),
        /// PTR → `router-<first label>.example`; TXT → Team Cymru answers.
        Reverse,
    }

    struct Fake {
        now: u64,
        servers: BTreeMap<IpAddr, Behave>,
        log: Vec<(IpAddr, bool)>,
    }

    impl Fake {
        fn new(servers: &[(&str, Behave)]) -> Self {
            Self {
                now: 0,
                servers: servers
                    .iter()
                    .map(|(ip, b)| (ip.parse().unwrap(), *b))
                    .collect(),
                log: Vec::new(),
            }
        }
    }

    impl Transport for Fake {
        /// An encrypted server answers like a plain one at the same
        /// address; the log says which way it was asked (`true`).
        fn exchange_secure(
            &mut self,
            server: SocketAddr,
            via: &SecureServer,
            query: &[u8],
            wait_ms: u64,
        ) -> Result<Vec<u8>, TransportError> {
            let m = Message::from_vec(query).unwrap();
            assert_eq!(m.metadata.id, 0, "RFC 8484 §4.1");
            assert_eq!(query.len() % crate::encrypted::PAD_BLOCK, 0, "RFC 8467");
            assert_eq!(server.port(), via.port);
            let out = self.exchange(server, query, true, wait_ms, &mut |_| true);
            if let Some(last) = self.log.last_mut() {
                last.1 = true;
            }
            out
        }

        fn now_ms(&self) -> u64 {
            self.now
        }

        fn exchange(
            &mut self,
            server: SocketAddr,
            query: &[u8],
            tcp: bool,
            wait_ms: u64,
            accept: &mut dyn FnMut(&[u8]) -> bool,
        ) -> Result<Vec<u8>, TransportError> {
            self.log.push((server.ip(), tcp));
            self.now += 5;
            let owner = Message::from_vec(query).unwrap().queries[0]
                .name()
                .to_ascii();
            let answer = |ip: [u8; 4]| {
                reply(
                    query,
                    ResponseCode::NoError,
                    vec![a(&owner, 300, ip)],
                    Some((300, 300)),
                )
            };
            let qtype = Message::from_vec(query).unwrap().queries[0].query_type();
            let out = match self
                .servers
                .get(&server.ip())
                .copied()
                .unwrap_or(Behave::Silent)
            {
                Behave::Silent => None,
                Behave::Answer(ip) => Some(answer(ip)),
                Behave::ServFail => Some(reply(query, ResponseCode::ServFail, vec![], None)),
                Behave::NxDomain => {
                    Some(reply(query, ResponseCode::NXDomain, vec![], Some((60, 60))))
                }
                Behave::Reverse => {
                    use hickory_proto::rr::rdata::{PTR, TXT};
                    use hickory_proto::rr::{RData, Record};
                    let n = crate::message::tests::name(&owner);
                    let data = match qtype {
                        RecordType::PTR => {
                            let first = owner.split('.').next().unwrap_or("x");
                            RData::PTR(PTR(crate::message::tests::name(&format!(
                                "router-{first}.example"
                            ))))
                        }
                        RecordType::TXT if owner.starts_with("AS") => RData::TXT(TXT::new(vec![
                            "64500 | ZZ | lab | 2026-01-01 | SIM-TRANSIT, ZZ".into(),
                        ])),
                        RecordType::TXT => RData::TXT(TXT::new(vec![
                            "64500 | 198.51.100.0/24 | ZZ | lab | 2026-01-01".into(),
                        ])),
                        _ => RData::A(hickory_proto::rr::rdata::A([192, 0, 2, 1].into())),
                    };
                    Some(reply(
                        query,
                        ResponseCode::NoError,
                        vec![Record::from_rdata(n, 300, data)],
                        None,
                    ))
                }
                Behave::Truncate(ip) if tcp => Some(answer(ip)),
                Behave::Truncate(_) => {
                    let mut m =
                        Message::from_vec(&reply(query, ResponseCode::NoError, vec![], None))
                            .unwrap();
                    m.metadata.truncation = true;
                    Some(m.to_vec().unwrap())
                }
                Behave::Spoofed(ip) => {
                    let mut m = Message::from_vec(&answer([6, 6, 6, 6])).unwrap();
                    m.metadata.id = m.metadata.id.wrapping_add(1);
                    let stray = m.to_vec().unwrap();
                    assert!(!accept(&stray), "a stray reply must be skipped");
                    Some(answer(ip))
                }
            };
            match out {
                Some(b) if accept(&b) => Ok(b),
                _ => {
                    self.now += wait_ms;
                    Err(TransportError::Timeout)
                }
            }
        }
    }

    fn resolver(servers: &[&str]) -> Resolver {
        let dns = Dns {
            servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
            ..Dns::default()
        };
        Resolver::new(Settings::new(&dns, &[]))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn answers_are_cached() {
        let r = resolver(&["192.0.2.53"]);
        let mut t = Fake::new(&[("192.0.2.53", Behave::Answer([198, 51, 100, 1]))]);
        assert_eq!(
            r.lookup(&mut t, "uol.com.br").unwrap(),
            vec![ip("198.51.100.1")]
        );
        let asked = t.log.len();
        assert_eq!(asked, 2, "A and AAAA");
        assert_eq!(
            r.lookup(&mut t, "UOL.com.br.").unwrap(),
            vec![ip("198.51.100.1")]
        );
        assert_eq!(t.log.len(), asked, "second lookup from the cache");
        let rows = r.cache_rows(t.now);
        assert_eq!(rows.len(), 2, "A, and AAAA NODATA (RFC 2308 §5)");
        assert_eq!(rows[0].server, Some(ip("192.0.2.53")));
        r.flush();
        assert!(r.cache_rows(t.now).is_empty());
    }

    #[test]
    fn dead_servers_fail_over_and_the_good_one_is_preferred() {
        let r = resolver(&["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Silent),
            ("192.0.2.2", Behave::ServFail),
            ("192.0.2.3", Behave::Answer([198, 51, 100, 3])),
        ]);
        assert_eq!(
            r.lookup(&mut t, "a.example").unwrap(),
            vec![ip("198.51.100.3")]
        );
        let first: Vec<IpAddr> = t.log.iter().map(|(s, _)| *s).take(3).collect();
        assert_eq!(
            first,
            vec![ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")]
        );
        // G4.1u: the silent one gets its RTO (never measured: 376 ms), not
        // the whole query_server_timeout.
        assert!(
            (376..1000).contains(&t.now),
            "{} ms on the silent one",
            t.now
        );
        t.log.clear();
        r.lookup(&mut t, "b.example").unwrap();
        assert_eq!(
            t.log[0].0,
            ip("192.0.2.3"),
            "the server that answered goes first"
        );
    }

    #[test]
    fn total_timeout_bounds_the_lookup() {
        let dns = Dns {
            servers: vec![ip("192.0.2.1"), ip("192.0.2.2"), ip("192.0.2.3")],
            query_server_timeout_ms: 2000,
            query_total_timeout_ms: 1000,
            ..Dns::default()
        };
        let r = Resolver::new(Settings::new(&dns, &[]));
        let mut t = Fake::new(&[]);
        let err = r.lookup(&mut t, "slow.example").unwrap_err();
        assert!(matches!(err, ResolveError::Failed { .. }), "{err}");
        assert!(err.to_string().contains("query_total_timeout"), "{err}");
        assert!(t.now <= 1100, "{} ms", t.now);
        // 376 ms each for the first two (G4.1u), the rest of the second
        // for the third; no AAAA after a failed A.
        assert_eq!(t.log.len(), 3);
    }

    #[test]
    fn nxdomain_is_final_and_cached() {
        let r = resolver(&["192.0.2.1", "192.0.2.2"]);
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::NxDomain),
            ("192.0.2.2", Behave::Answer([6, 6, 6, 6])),
        ]);
        assert_eq!(
            r.lookup(&mut t, "nope.example"),
            Err(ResolveError::NotFound("nope.example".into()))
        );
        assert_eq!(t.log.len(), 1, "no second server, no AAAA");
        r.lookup(&mut t, "nope.example").unwrap_err();
        assert_eq!(t.log.len(), 1, "negative answer from the cache");
    }

    #[test]
    fn truncated_goes_to_tcp_and_strays_are_skipped() {
        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[("192.0.2.1", Behave::Truncate([198, 51, 100, 9]))]);
        assert_eq!(
            r.lookup(&mut t, "big.example").unwrap(),
            vec![ip("198.51.100.9")]
        );
        assert_eq!(
            &t.log[..2],
            &[(ip("192.0.2.1"), false), (ip("192.0.2.1"), true)]
        );

        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[("192.0.2.1", Behave::Spoofed([198, 51, 100, 10]))]);
        assert_eq!(
            r.lookup(&mut t, "x.example").unwrap(),
            vec![ip("198.51.100.10")]
        );
    }

    #[test]
    fn literals_special_names_and_no_servers() {
        let r = resolver(&[]);
        let mut t = Fake::new(&[]);
        assert_eq!(
            r.lookup(&mut t, "192.0.2.7").unwrap(),
            vec![ip("192.0.2.7")]
        );
        assert_eq!(r.lookup(&mut t, "localhost").unwrap()[0], ip("127.0.0.1"));
        assert!(matches!(
            r.lookup(&mut t, "x.invalid"),
            Err(ResolveError::NotFound(_))
        ));
        assert_eq!(r.lookup(&mut t, "uol.com.br"), Err(ResolveError::NoServers));
        assert!(matches!(
            r.lookup(&mut t, "bad name"),
            Err(ResolveError::BadName(_))
        ));
        assert!(t.log.is_empty());
    }

    #[test]
    fn reverse_names_and_as_numbers_are_cached() {
        let r = resolver(&["192.0.2.53"]);
        let mut t = Fake::new(&[("192.0.2.53", Behave::Reverse)]);
        let hop = ip("198.51.100.7");
        assert_eq!(
            r.reverse(&mut t, hop).unwrap().as_deref(),
            Some("router-7.example")
        );
        assert_eq!(t.log.len(), 1);
        r.reverse(&mut t, hop).unwrap();
        assert_eq!(t.log.len(), 1, "PTR from the cache");
        let o = crate::asn::lookup(&r, &mut t, hop).unwrap().unwrap();
        assert_eq!((o.asn, o.name.as_deref()), (64500, Some("SIM-TRANSIT")));
        assert_eq!(o.prefix.as_deref(), Some("198.51.100.0/24"));
        assert_eq!(t.log.len(), 3, "origin and AS name");
        crate::asn::lookup(&r, &mut t, hop).unwrap();
        assert_eq!(t.log.len(), 3, "both TXT answers from the cache");
        let rows = r.cache_rows(t.now);
        assert!(
            rows.iter()
                .any(|row| row.qtype == "PTR" && row.name == "7.100.51.198.in-addr.arpa")
        );
    }

    #[test]
    fn settings_merge_static_and_dynamic() {
        let dns = Dns {
            servers: vec![ip("192.0.2.1")],
            ..Dns::default()
        };
        let s = Settings::new(&dns, &[ip("192.0.2.9"), ip("192.0.2.1")]);
        assert_eq!(s.servers, vec![ip("192.0.2.1"), ip("192.0.2.9")]);
        assert_eq!(s.cache_bytes, 2048 * 1024);
        let r = Resolver::new(s);
        r.configure(Settings::new(&Dns::default(), &[]), 0);
        assert!(r.settings().servers.is_empty());
    }

    #[test]
    fn fastest_server_first_and_a_failing_one_goes_last() {
        let r = resolver(&["192.0.2.1", "192.0.2.2"]);
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Silent),
            ("192.0.2.2", Behave::Answer([198, 51, 100, 2])),
        ]);
        r.lookup(&mut t, "a.example").unwrap();
        let stats = r.server_stats();
        assert_eq!(stats[0].1.failures, 1);
        assert!(stats[1].1.srtt_ms.is_some());
        t.log.clear();
        r.lookup(&mut t, "b.example").unwrap();
        assert_eq!(
            t.log[0].0,
            ip("192.0.2.2"),
            "the one that answered goes first"
        );
        // A minute later the failed one is tried again (it is still unknown,
        // and unknown (376 ms) loses to a measured 5 ms).
        t.now += DOWN_MS + 1;
        t.log.clear();
        r.lookup(&mut t, "c.example").unwrap();
        assert_eq!(t.log[0].0, ip("192.0.2.2"));
    }

    #[test]
    fn stale_answer_when_every_server_fails() {
        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[("192.0.2.1", Behave::Answer([198, 51, 100, 5]))]);
        let qn = parse_name("s.example").unwrap();
        r.resolve(&mut t, &qn, RecordType::A, None).unwrap();
        t.now += 301_000;
        t.servers.insert(ip("192.0.2.1"), Behave::Silent);
        let got = r.resolve(&mut t, &qn, RecordType::A, None).unwrap();
        assert_eq!(got.source, Source::Stale, "RFC 8767");
        assert_eq!(got.answer.records[0].ttl, crate::cache::STALE_TTL);
        // serve_stale off: the failure goes through.
        let dns = Dns {
            servers: vec![ip("192.0.2.1")],
            serve_stale_secs: 0,
            ..Dns::default()
        };
        r.configure(Settings::new(&dns, &[]), t.now);
        assert!(r.resolve(&mut t, &qn, RecordType::A, None).is_err());
    }

    #[test]
    fn forward_to_overrides_the_servers() {
        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Answer([198, 51, 100, 1])),
            ("192.0.2.9", Behave::Answer([198, 51, 100, 9])),
        ]);
        let qn = parse_name("corp.example").unwrap();
        let got = r
            .resolve(
                &mut t,
                &qn,
                RecordType::A,
                Some(&Upstreams::plain(vec![ip("192.0.2.9")])),
            )
            .unwrap();
        assert_eq!(got.source, Source::Server(ip("192.0.2.9")));
        assert_eq!(got.answer.addresses(), vec![ip("198.51.100.9")]);
        assert_eq!(t.log.len(), 1);
        // Shared cache: the router's own lookup is answered from it.
        assert_eq!(
            r.lookup(&mut t, "corp.example").unwrap()[0],
            ip("198.51.100.9")
        );
    }

    fn doh(dns: Dns, hosts: &[(&str, &str)]) -> Resolver {
        let mut st = Settings::new(&dns, &[]);
        st.hosts = hosts
            .iter()
            .map(|(n, a)| ((*n).to_owned(), ip(a)))
            .collect();
        Resolver::new(st)
    }

    #[test]
    fn use_doh_server_replaces_the_servers() {
        // An address literal: asked directly, plain servers never.
        let r = doh(
            Dns {
                servers: vec![ip("192.0.2.1")],
                use_doh_server: "https://192.0.2.53/dns-query".into(),
                ..Dns::default()
            },
            &[],
        );
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Answer([198, 51, 100, 1])),
            ("192.0.2.53", Behave::Answer([198, 51, 100, 53])),
        ]);
        assert_eq!(
            r.lookup(&mut t, "www.example").unwrap()[0],
            ip("198.51.100.53")
        );
        assert!(
            t.log
                .iter()
                .all(|(a, secure)| *a == ip("192.0.2.53") && *secure),
            "{:?}",
            t.log
        );

        // A name: the plain servers resolve it (and only it).
        let r = doh(
            Dns {
                servers: vec![ip("192.0.2.1")],
                use_doh_server: "tls://dns.example#dns.example".into(),
                ..Dns::default()
            },
            &[],
        );
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Answer([192, 0, 2, 77])),
            ("192.0.2.77", Behave::Answer([198, 51, 100, 7])),
        ]);
        let qn = parse_name("www.example").unwrap();
        let got = r.resolve(&mut t, &qn, RecordType::A, None).unwrap();
        assert_eq!(got.source, Source::Server(ip("192.0.2.77")));
        assert_eq!(
            t.log,
            vec![(ip("192.0.2.1"), false), (ip("192.0.2.77"), true)]
        );

        // A static entry pins the name; with no plain server and no
        // entry, the error says what to do.
        let r = doh(
            Dns {
                use_doh_server: "https://dns.example/q".into(),
                ..Dns::default()
            },
            &[("dns.example", "192.0.2.78")],
        );
        let mut t = Fake::new(&[("192.0.2.78", Behave::Answer([198, 51, 100, 8]))]);
        assert_eq!(
            r.lookup(&mut t, "a.example").unwrap()[0],
            ip("198.51.100.8")
        );
        let r = doh(
            Dns {
                use_doh_server: "https://dns.example/q".into(),
                ..Dns::default()
            },
            &[],
        );
        let err = r.lookup(&mut t, "b.example").unwrap_err().to_string();
        assert!(err.contains("add a static entry"), "{err}");
    }

    #[test]
    fn a_group_mixes_plain_and_encrypted_and_fails_over() {
        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[
            ("192.0.2.1", Behave::Answer([198, 51, 100, 1])),
            ("192.0.2.60", Behave::ServFail),
            ("192.0.2.61", Behave::Answer([198, 51, 100, 61])),
        ]);
        let group = Upstreams {
            servers: vec![ip("192.0.2.60")],
            secure: vec![SecureServer::parse("tls://192.0.2.61", true).unwrap()],
        };
        let qn = parse_name("corp.example").unwrap();
        let got = r.resolve(&mut t, &qn, RecordType::A, Some(&group)).unwrap();
        assert_eq!(got.source, Source::Server(ip("192.0.2.61")));
        assert_eq!(
            t.log,
            vec![(ip("192.0.2.60"), false), (ip("192.0.2.61"), true)]
        );
        // Without the daemon (the default transport method): a clear error.
        struct Plain;
        impl Transport for Plain {
            fn now_ms(&self) -> u64 {
                0
            }
            fn exchange(
                &mut self,
                _: SocketAddr,
                _: &[u8],
                _: bool,
                _: u64,
                _: &mut dyn FnMut(&[u8]) -> bool,
            ) -> Result<Vec<u8>, TransportError> {
                Err(TransportError::Timeout)
            }
        }
        let only = Upstreams {
            servers: Vec::new(),
            secure: group.secure.clone(),
        };
        let qn = parse_name("other.example").unwrap();
        let err = r
            .resolve(&mut Plain, &qn, RecordType::A, Some(&only))
            .unwrap_err()
            .to_string();
        assert!(err.contains("router daemon"), "{err}");
    }

    #[test]
    fn failures_are_held_rfc9520() {
        let r = resolver(&["192.0.2.1"]);
        let mut t = Fake::new(&[("192.0.2.1", Behave::ServFail)]);
        let qn = parse_name("dead.example").unwrap();
        assert!(r.resolve(&mut t, &qn, RecordType::A, None).is_err());
        assert_eq!(t.log.len(), 1);
        // Held: no query, the error says why and for how long.
        let err = r
            .resolve(&mut t, &qn, RecordType::A, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("RFC 9520"), "{err}");
        assert_eq!(t.log.len(), 1, "not asked while held");
        assert_eq!(r.failures(t.now), 1);
        // Another type is its own key.
        assert!(r.resolve(&mut t, &qn, RecordType::AAAA, None).is_err());
        assert_eq!(t.log.len(), 2);
        // After 5 s it is asked again; failing again doubles the hold.
        t.now += FAILURE_HOLD_MS;
        assert!(r.resolve(&mut t, &qn, RecordType::A, None).is_err());
        assert_eq!(t.log.len(), 3);
        t.now += FAILURE_HOLD_MS;
        assert!(r.resolve(&mut t, &qn, RecordType::A, None).is_err());
        assert_eq!(t.log.len(), 3, "second hold is 10 s");
        // The server comes back: after the hold it answers, and the
        // failure is forgotten.
        t.servers
            .insert(ip("192.0.2.1"), Behave::Answer([198, 51, 100, 1]));
        t.now += 2 * FAILURE_HOLD_MS;
        assert!(r.resolve(&mut t, &qn, RecordType::A, None).is_ok());
        // Flush forgets holds too.
        t.servers.insert(ip("192.0.2.1"), Behave::ServFail);
        let other = parse_name("other.example").unwrap();
        assert!(r.resolve(&mut t, &other, RecordType::A, None).is_err());
        r.flush();
        assert_eq!(r.failures(t.now), 0);
        // NXDOMAIN is an answer, not a failure (RFC 9520 §2).
        t.servers.insert(ip("192.0.2.1"), Behave::NxDomain);
        let gone = parse_name("gone.example").unwrap();
        assert!(r.resolve(&mut t, &gone, RecordType::A, None).is_ok());
        assert_eq!(r.failures(t.now), 0);
    }
}

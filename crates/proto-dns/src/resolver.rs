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
//! No sockets here: the caller brings a [`Transport`] (UDP/TCP in the
//! daemon, a fake in tests). The lock is held only around the cache, never
//! across the network, so one slow lookup does not stall the others.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};

use corerouter_model::dns::{CacheRow, Dns, ServerSelection};
use hickory_proto::rr::RecordType;

use crate::cache::{Cache, Hit};
use crate::message::{Answer, NameError, QName, Rcode, ReplyError, check_reply, parse_name, query};

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
}

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
        }
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
/// one before a slow one.
const UNKNOWN_RTT_MS: u64 = 376;
/// A server that failed goes last for this long (`fastest`).
const DOWN_MS: u64 = 60_000;

/// What the resolver knows of one server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServerStats {
    /// Smoothed round-trip time (RFC 6298 style, 7/8 old + 1/8 new).
    pub srtt_ms: Option<u64>,
    pub down_until_ms: u64,
    pub answers: u64,
    pub failures: u64,
}

#[derive(Debug, Default)]
struct State {
    settings: Settings,
    cache: Cache,
    /// The last server that answered (RouterOS keeps using it).
    preferred: Option<IpAddr>,
    stats: BTreeMap<IpAddr, ServerStats>,
}

/// Resolver shared by every thread of the router (tools, NTP, the LAN
/// forwarder).
#[derive(Debug, Default)]
pub struct Resolver {
    state: Mutex<State>,
}

impl Resolver {
    pub fn new(settings: Settings) -> Self {
        let mut cache = Cache::new(settings.cache_bytes);
        cache.set_stale(settings.stale_secs);
        Self {
            state: Mutex::new(State {
                settings,
                cache,
                preferred: None,
                stats: BTreeMap::new(),
            }),
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
    pub fn configure(&self, settings: Settings, now_ms: u64) {
        let mut st = self.state();
        if st.settings == settings {
            return;
        }
        st.cache.set_budget(settings.cache_bytes, now_ms);
        st.cache.set_stale(settings.stale_secs);
        if st.preferred.is_some_and(|p| !settings.servers.contains(&p)) {
            st.preferred = None;
        }
        st.settings = settings;
    }

    pub fn settings(&self) -> Settings {
        self.state().settings.clone()
    }

    pub fn cache_rows(&self, now_ms: u64) -> Vec<CacheRow> {
        self.state().cache.rows(now_ms)
    }

    pub fn cache_used_bytes(&self) -> usize {
        self.state().cache.used_bytes()
    }

    pub fn flush(&self) {
        self.state().cache.flush();
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

    /// One name and type: from the cache, or asked (of `forward_to` when a
    /// static FWD entry says so, else of the configured servers) and then
    /// cached; stale when every server failed (RFC 8767).
    pub fn resolve(
        &self,
        t: &mut dyn Transport,
        qn: &QName,
        rtype: RecordType,
        forward_to: Option<&[IpAddr]>,
    ) -> Result<Resolved, ResolveError> {
        let (settings, servers) = {
            let mut st = self.state();
            if let Some(hit) = st.cache.get(&qn.key, rtype, t.now_ms()) {
                return Ok(Resolved {
                    answer: hit.answer,
                    source: Source::Cache,
                });
            }
            let servers = match forward_to {
                Some(list) => list.to_vec(),
                None => order(&st, t.now_ms()),
            };
            (st.settings.clone(), servers)
        };
        let fetched = fetch(t, &settings, &servers, qn, rtype);
        let mut st = self.state();
        let now = t.now_ms();
        for (ip, rtt) in &fetched.tried {
            let s = st.stats.entry(*ip).or_default();
            match rtt {
                Some(ms) => {
                    s.srtt_ms = Some(s.srtt_ms.map_or(*ms, |old| (old * 7 + ms) / 8));
                    s.down_until_ms = 0;
                    s.answers = s.answers.saturating_add(1);
                }
                None => {
                    s.down_until_ms = now.saturating_add(DOWN_MS);
                    s.failures = s.failures.saturating_add(1);
                }
            }
        }
        // Forget servers no longer configured (the map stays small).
        let keep = st.settings.servers.clone();
        st.stats
            .retain(|ip, _| keep.contains(ip) || servers.contains(ip));
        match fetched.result {
            Ok((answer, server, wire)) => {
                if forward_to.is_none() {
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
}

impl Resolver {
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

/// The result of asking the servers, and how each one did (round-trip
/// time, or `None` for a failure).
pub struct Fetched {
    pub result: Result<(Answer, IpAddr, usize), ResolveError>,
    pub tried: Vec<(IpAddr, Option<u64>)>,
}

/// Asks `servers` in order until one gives a definite answer.
pub fn fetch(
    t: &mut dyn Transport,
    settings: &Settings,
    servers: &[IpAddr],
    qn: &QName,
    rtype: RecordType,
) -> Fetched {
    let mut tried = Vec::new();
    if servers.is_empty() {
        return Fetched {
            result: Err(ResolveError::NoServers),
            tried,
        };
    }
    let deadline = t
        .now_ms()
        .saturating_add(u64::from(settings.total_timeout_ms));
    let mut errors: Vec<String> = Vec::new();
    for ip in servers {
        let server = SocketAddr::new(*ip, settings.port);
        let mut tcp = false;
        let started = t.now_ms();
        loop {
            let left = deadline.saturating_sub(t.now_ms());
            if left == 0 {
                errors.push("query_total_timeout reached".into());
                return Fetched {
                    result: Err(failed(qn, &errors)),
                    tried,
                };
            }
            let wait = left.min(u64::from(settings.server_timeout_ms));
            match ask(t, server, settings.udp_payload, qn, rtype, tcp, wait) {
                Ok((answer, wire)) => {
                    tried.push((*ip, Some(t.now_ms().saturating_sub(started))));
                    return Fetched {
                        result: Ok((answer, *ip, wire)),
                        tried,
                    };
                }
                // RFC 7766 §5: a truncated UDP answer is retried over TCP.
                Err(Ask::Reply(ReplyError::Truncated)) if !tcp => tcp = true,
                Err(e) => {
                    tried.push((*ip, None));
                    errors.push(format!("{ip}: {e}"));
                    break;
                }
            }
        }
    }
    Fetched {
        result: Err(failed(qn, &errors)),
        tried,
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

#[derive(Debug, thiserror::Error)]
enum Ask {
    #[error("{0}")]
    Transport(TransportError),
    #[error("{0}")]
    Reply(ReplyError),
}

fn ask(
    t: &mut dyn Transport,
    server: SocketAddr,
    payload: u16,
    qn: &QName,
    rtype: RecordType,
    tcp: bool,
    wait: u64,
) -> Result<(Answer, usize), Ask> {
    let (id, bytes) =
        query(&qn.name, rtype, payload).map_err(|e| Ask::Transport(TransportError::Io(e)))?;
    let mut accept = |b: &[u8]| {
        !matches!(
            check_reply(id, &qn.name, rtype, b),
            Err(ReplyError::Mismatch)
        )
    };
    let reply = t
        .exchange(server, &bytes, tcp, wait, &mut accept)
        .map_err(Ask::Transport)?;
    let m = check_reply(id, &qn.name, rtype, &reply).map_err(Ask::Reply)?;
    Ok((Answer::from_reply(&qn.name, rtype, &m), reply.len()))
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
        assert!(
            t.now >= 2000,
            "waited query_server_timeout on the silent one"
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
            query_total_timeout_ms: 3000,
            ..Dns::default()
        };
        let r = Resolver::new(Settings::new(&dns, &[]));
        let mut t = Fake::new(&[]);
        let err = r.lookup(&mut t, "slow.example").unwrap_err();
        assert!(matches!(err, ResolveError::Failed { .. }), "{err}");
        assert!(err.to_string().contains("query_total_timeout"), "{err}");
        assert!(t.now <= 3100, "{} ms", t.now);
        assert_eq!(
            t.log.len(),
            2,
            "third server never asked; no AAAA after a failed A"
        );
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
            .resolve(&mut t, &qn, RecordType::A, Some(&[ip("192.0.2.9")]))
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
}

//! The router's stub resolver: cache first, then the servers one by one
//! (RouterOS `/ip dns`: static servers, then the dynamic ones; the last
//! server that answered goes first next time), each for at most
//! `query_server_timeout`, all of them for at most `query_total_timeout`.
//! A truncated UDP answer is asked again over TCP on the same server
//! (RFC 7766 §5). NXDOMAIN is final: another server would say the same.
//!
//! No sockets here: the caller brings a [`Transport`] (UDP/TCP in the
//! daemon, a fake in tests). The lock is held only around the cache, never
//! across the network, so one slow lookup does not stall the others.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};

use corerouter_model::dns::{CacheRow, CachedData, Dns, QType};

use crate::cache::Cache;
use crate::message::{NameError, Outcome, QName, ReplyError, parse_name, parse_reply, query};

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

#[derive(Debug, Default)]
struct State {
    settings: Settings,
    cache: Cache,
    /// The last server that answered (RouterOS keeps using it).
    preferred: Option<IpAddr>,
}

/// Resolver shared by every thread of the router (tools, NTP, later the
/// LAN forwarder of G4.1b).
#[derive(Debug, Default)]
pub struct Resolver {
    state: Mutex<State>,
}

impl Resolver {
    pub fn new(settings: Settings) -> Self {
        let cache = Cache::new(settings.cache_bytes);
        Self {
            state: Mutex::new(State {
                settings,
                cache,
                preferred: None,
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
        for q in [QType::A, QType::Aaaa] {
            match self.lookup_type(t, &qn, q) {
                Ok(CachedData::Addresses { addresses, .. }) => out.extend(addresses),
                // RFC 2308 §2.1: no such name, for any type.
                Ok(CachedData::NxDomain) => break,
                Ok(CachedData::NoData | CachedData::Records { .. }) => {}
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

    /// One type: from the cache, or asked and then cached.
    fn lookup_type(
        &self,
        t: &mut dyn Transport,
        qn: &QName,
        q: QType,
    ) -> Result<CachedData, ResolveError> {
        let (settings, preferred) = {
            let mut st = self.state();
            let now = t.now_ms();
            if let Some((data, _)) = st.cache.get(&qn.key, q, now) {
                return Ok(data);
            }
            (st.settings.clone(), st.preferred)
        };
        let (outcome, server) = fetch(t, &settings, preferred, qn, q)?;
        let mut st = self.state();
        st.preferred = Some(server);
        st.cache.put(
            &qn.key,
            q,
            &outcome,
            Some(server),
            t.now_ms(),
            settings.max_ttl,
        );
        Ok(match outcome {
            Outcome::Addresses {
                addresses,
                canonical,
                ..
            } => CachedData::Addresses {
                addresses,
                canonical,
            },
            Outcome::Records {
                records, canonical, ..
            } => CachedData::Records { records, canonical },
            Outcome::NxDomain { .. } => CachedData::NxDomain,
            Outcome::NoData { .. } => CachedData::NoData,
        })
    }

    /// Records of type `q` (PTR or TXT) for `name`, from the cache or
    /// asked; a name that does not exist, or has none, gives no records.
    pub fn records(
        &self,
        t: &mut dyn Transport,
        name: &str,
        q: QType,
    ) -> Result<Vec<String>, ResolveError> {
        let qn = parse_name(name)?;
        if special_use(&qn).is_some() {
            return Ok(Vec::new());
        }
        match self.lookup_type(t, &qn, q)? {
            CachedData::Records { records, .. } => Ok(records),
            _ => Ok(Vec::new()),
        }
    }

    /// The name of `ip` (its first PTR, RFC 1035 §3.5 / RFC 3596 §2.5).
    pub fn reverse(
        &self,
        t: &mut dyn Transport,
        ip: IpAddr,
    ) -> Result<Option<String>, ResolveError> {
        let name = crate::reverse::reverse_name(ip);
        Ok(self
            .records(t, &name, QType::Ptr)?
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

/// Servers in asking order: the preferred one first, then the list.
fn order(servers: &[IpAddr], preferred: Option<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = preferred
        .filter(|p| servers.contains(p))
        .into_iter()
        .collect();
    out.extend(servers.iter().filter(|s| Some(**s) != preferred));
    out
}

/// Asks the servers until one gives a definite answer.
pub fn fetch(
    t: &mut dyn Transport,
    settings: &Settings,
    preferred: Option<IpAddr>,
    qn: &QName,
    q: QType,
) -> Result<(Outcome, IpAddr), ResolveError> {
    if settings.servers.is_empty() {
        return Err(ResolveError::NoServers);
    }
    let deadline = t
        .now_ms()
        .saturating_add(u64::from(settings.total_timeout_ms));
    let mut errors: Vec<String> = Vec::new();
    for ip in order(&settings.servers, preferred) {
        let server = SocketAddr::new(ip, settings.port);
        let mut tcp = false;
        loop {
            let left = deadline.saturating_sub(t.now_ms());
            if left == 0 {
                errors.push("query_total_timeout reached".into());
                return Err(failed(qn, &errors));
            }
            let wait = left.min(u64::from(settings.server_timeout_ms));
            match ask(t, server, settings.udp_payload, qn, q, tcp, wait) {
                Ok(outcome) => return Ok((outcome, ip)),
                // RFC 7766 §5: a truncated UDP answer is retried over TCP.
                Err(Ask::Reply(ReplyError::Truncated)) if !tcp => tcp = true,
                Err(e) => {
                    errors.push(format!("{ip}: {e}"));
                    break;
                }
            }
        }
    }
    Err(failed(qn, &errors))
}

fn failed(qn: &QName, errors: &[String]) -> ResolveError {
    let mut why = errors.join("; ");
    if why.len() > 300 {
        why.truncate(297);
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
    q: QType,
    tcp: bool,
    wait: u64,
) -> Result<Outcome, Ask> {
    let (id, bytes) =
        query(&qn.name, q, payload).map_err(|e| Ask::Transport(TransportError::Io(e)))?;
    let mut accept =
        |b: &[u8]| !matches!(parse_reply(id, &qn.name, q, b), Err(ReplyError::Mismatch));
    let reply = t
        .exchange(server, &bytes, tcp, wait, &mut accept)
        .map_err(Ask::Transport)?;
    parse_reply(id, &qn.name, q, &reply).map_err(Ask::Reply)
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
                    use hickory_proto::rr::{RData, Record, RecordType};
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
                .any(|row| row.qtype == QType::Ptr && row.name == "7.100.51.198.in-addr.arpa")
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
}

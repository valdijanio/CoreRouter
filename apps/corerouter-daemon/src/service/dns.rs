//! The router's own DNS resolver (G4.1a, `/ip dns`): what ping, MTU, MTR
//! and the NTP client use to turn names into addresses, instead of the
//! host's resolver (`/etc/resolv.conf` → `127.0.0.53`, which the router's
//! namespace and its image do not have).
//!
//! The logic (cache, failover, reply checks) is `corerouter_proto_dns`;
//! this file brings the sockets: blocking UDP with a timeout, TCP when an
//! answer is truncated (RFC 7766 §5), one socket per exchange on a random
//! port (RFC 5452 §9.2: id and port both unpredictable). A thread copies
//! the running `/ip dns` and the servers learned by DHCP into the resolver
//! every second, so a lookup never needs the session lock. The LAN
//! forwarder (G4.1b, `dns_server.rs`) answers from the same [`Resolver`]
//! and cache, through [`router`].
//!
//! G6.3b: the MTR asks for hop names (PTR) and AS numbers (Team Cymru TXT)
//! without waiting. Those go to a bounded queue served by a few worker
//! threads; the answer is kept a while so the next pass of the MTR finds
//! it, and the resolver's cache keeps it for its TTL.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::dns::{DnsBackend, Resolution};
use hickory_proto::rr::RecordType;
use corerouter_engine::{Shared, lock};
use corerouter_hal::probe::{AsInfo, Lookup};
use corerouter_model::dns::CacheRow;
use corerouter_proto_dns::resolver::{
    ResolveError, Resolver, ServerStats, Transport, TransportError,
};

/// How often the thread looks at the config.
/// G0.30: 50 ms in the unit tests, which follow the config through it.
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(1)
};
/// Largest reply read over UDP (RFC 6891 payloads go up to 65535).
const MAX_REPLY: usize = 65_535;

/// Threads answering the lookups nobody waits for.
const WORKERS: usize = 4;
/// Lookups queued at most; more are refused (and asked again later).
const MAX_QUEUE: usize = 256;
/// Answers kept for the next ask; the oldest go when full.
const MAX_DONE: usize = 4096;
/// How long an answer (or a failure) is handed out before it is asked
/// again (the resolver's cache still answers within the record's TTL).
const KEEP: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Ask {
    Ptr(IpAddr),
    Asn(IpAddr),
}

#[derive(Debug, Clone)]
enum Answer {
    Name(Option<String>),
    Asn(Option<AsInfo>),
}

#[derive(Default)]
struct Queue {
    waiting: VecDeque<Ask>,
    busy: BTreeSet<Ask>,
    done: BTreeMap<Ask, (Answer, Instant)>,
}

#[derive(Default)]
struct Background {
    queue: Mutex<Queue>,
    wake: Condvar,
}

impl Background {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The resolver plus the clock its cache runs on.
pub(crate) struct RouterDns {
    pub(crate) resolver: Arc<Resolver>,
    start: Instant,
    background: Arc<Background>,
    workers: OnceLock<()>,
}

/// The daemon's resolver, once the service started (the LAN forwarder
/// shares it).
static ROUTER: OnceLock<Arc<RouterDns>> = OnceLock::new();

pub(crate) fn router() -> Option<Arc<RouterDns>> {
    ROUTER.get().cloned()
}

impl RouterDns {
    pub(crate) fn new() -> Self {
        Self {
            resolver: Arc::new(Resolver::default()),
            start: Instant::now(),
            background: Arc::default(),
            workers: OnceLock::new(),
        }
    }

    /// The answer to `ask` if known, else queue it (`Pending`). `None`: no
    /// DNS server, the prober's own names apply.
    fn nowait(&self, ask: Ask) -> Option<Lookup<Answer>> {
        if !self.resolver.settings().has_servers() {
            return None;
        }
        self.workers.get_or_init(|| self.spawn_workers());
        let mut q = self.background.queue();
        if let Some((answer, at)) = q.done.get(&ask) {
            if at.elapsed() < KEEP {
                return Some(Lookup::Done(answer.clone()));
            }
            q.done.remove(&ask);
        }
        if !q.busy.contains(&ask) && !q.waiting.contains(&ask) && q.waiting.len() < MAX_QUEUE {
            q.waiting.push_back(ask);
            self.background.wake.notify_one();
        }
        Some(Lookup::Pending)
    }

    fn spawn_workers(&self) {
        for i in 0..WORKERS {
            let bg = self.background.clone();
            let resolver = self.resolver.clone();
            let start = self.start;
            let spawned = thread::Builder::new()
                .name(format!("dns-lookup-{i}"))
                .spawn(move || work(&bg, &resolver, start));
            if let Err(e) = spawned {
                log::error!("DNS: cannot start lookup thread {i}: {e}");
            }
        }
    }

    pub(crate) fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The network, on the cache's clock.
    pub(crate) fn transport(&self) -> Sockets {
        Sockets { start: self.start }
    }
}

impl DnsBackend for RouterDns {
    fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let mut t = Sockets { start: self.start };
        self.resolver.lookup(&mut t, name)
    }

    fn cache_rows(&self) -> Vec<CacheRow> {
        self.resolver.cache_rows(self.now_ms())
    }

    fn cache_rows_matching(&self, name: Option<&str>, qtype: Option<&str>, limit: usize) -> Vec<CacheRow> {
        self.resolver
            .cache_rows_matching(self.now_ms(), name, qtype, limit)
    }

    fn cache_len(&self) -> usize {
        self.resolver.cache_len()
    }

    fn cache_used_bytes(&self) -> usize {
        self.resolver.cache_used_bytes()
    }

    fn flush(&self) {
        self.resolver.flush();
        self.background.queue().done.clear();
    }

    /// `down_until_ms` only while it lasts (the engine has not this clock).
    fn server_stats(&self) -> Vec<(IpAddr, ServerStats)> {
        let now = self.now_ms();
        let mut out = self.resolver.server_stats();
        for (_, s) in &mut out {
            if s.down_until_ms <= now {
                s.down_until_ms = 0;
            }
        }
        out
    }

    fn resolve_query(
        &self,
        name: &str,
        rtype: &str,
        server: Option<IpAddr>,
    ) -> Result<Resolution, String> {
        use corerouter_proto_dns::message::{Rcode, parse_name};
        use corerouter_proto_dns::resolver::{Source, Target, fetch};
        let qn = parse_name(name).map_err(|e| e.to_string())?;
        let rt: RecordType = rtype
            .parse()
            .map_err(|_| format!("unknown record type {rtype}"))?;
        let mut t = self.transport();
        let (answer, source) = match server {
            None => {
                let r = self
                    .resolver
                    .resolve(&mut t, &qn, rt, None)
                    .map_err(|e| e.to_string())?;
                let source = match r.source {
                    Source::Cache => "cache".to_owned(),
                    Source::Stale => "stale".to_owned(),
                    Source::Server(ip) => ip.to_string(),
                };
                (r.answer, source)
            }
            // One server, past the cache (RouterOS `:resolve server=`).
            Some(ip) => {
                let settings = self.resolver.settings();
                let f = fetch(&mut t, &settings, &[Target::Plain(ip)], &qn, rt);
                let (answer, from, _) = f.result.map_err(|e| e.to_string())?;
                (answer, from.to_string())
            }
        };
        Ok(Resolution {
            rcode: match answer.rcode {
                Rcode::NoError => "NOERROR".into(),
                Rcode::NxDomain => "NXDOMAIN".into(),
            },
            records: answer
                .records
                .iter()
                // Text from the network: printable ASCII only (no terminal
                // escapes), bounded; names keep their final dot (`MX 0 .`).
                .map(|r| {
                    format!("{} {}", r.record_type(), r.data)
                        .chars()
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .take(512)
                        .collect()
                })
                .collect(),
            addresses: answer.addresses(),
            ttl: answer.ttl,
            source,
        })
    }

    fn exchange(
        &self,
        to: &corerouter_engine::dns_lookup::LookupServer,
        query: &[u8],
        tcp: bool,
    ) -> Result<corerouter_engine::dns_lookup::Exchanged, String> {
        super::dns_lookup::exchange(self, to, query, tcp)
    }

    fn ask_router(
        &self,
        query: &[u8],
        tcp: bool,
        how: corerouter_engine::dns_lookup::RouterAsk,
    ) -> Result<corerouter_engine::dns_lookup::Exchanged, String> {
        super::dns_lookup::ask_router(query, tcp, how)
    }

    fn exchange_all(
        &self,
        asks: &[(corerouter_engine::dns_lookup::LookupServer, Vec<u8>)],
        tcp: bool,
    ) -> Vec<Result<corerouter_engine::dns_lookup::Exchanged, String>> {
        super::dns_lookup::exchange_all(self, asks, tcp)
    }

    fn reverse_nowait(&self, ip: IpAddr) -> Option<Lookup<Option<String>>> {
        Some(match self.nowait(Ask::Ptr(ip))? {
            Lookup::Done(Answer::Name(n)) => Lookup::Done(n),
            Lookup::Done(Answer::Asn(_)) => Lookup::Done(None),
            Lookup::Pending => Lookup::Pending,
        })
    }

    fn origin_as_nowait(&self, ip: IpAddr) -> Option<Lookup<Option<AsInfo>>> {
        Some(match self.nowait(Ask::Asn(ip))? {
            Lookup::Done(Answer::Asn(a)) => Lookup::Done(a),
            Lookup::Done(Answer::Name(_)) => Lookup::Done(None),
            Lookup::Pending => Lookup::Pending,
        })
    }
}

/// One worker: takes a lookup, asks the network, keeps the answer.
fn work(bg: &Background, resolver: &Resolver, start: Instant) {
    loop {
        let ask = {
            let mut q = bg.queue();
            loop {
                if let Some(a) = q.waiting.pop_front() {
                    q.busy.insert(a);
                    break a;
                }
                q = bg
                    .wake
                    .wait(q)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let mut t = Sockets { start };
        // A failure (timeout, SERVFAIL) is "no answer" for a while too:
        // the MTR shows the address and does not hammer the servers.
        let answer = match ask {
            Ask::Ptr(ip) => Answer::Name(resolver.reverse(&mut t, ip).ok().flatten()),
            Ask::Asn(ip) => Answer::Asn(
                corerouter_proto_dns::asn::lookup(resolver, &mut t, ip)
                    .ok()
                    .flatten()
                    .map(|o| AsInfo {
                        asn: o.asn,
                        name: o.name,
                        prefix: o.prefix,
                    }),
            ),
        };
        let mut q = bg.queue();
        q.busy.remove(&ask);
        if q.done.len() >= MAX_DONE {
            q.done.retain(|_, (_, at)| at.elapsed() < KEEP);
        }
        while q.done.len() >= MAX_DONE {
            let Some(oldest) = q.done.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k) else {
                break;
            };
            q.done.remove(&oldest);
        }
        q.done.insert(ask, (answer, Instant::now()));
    }
}

/// The real network.
pub(crate) struct Sockets {
    start: Instant,
}

fn io(e: std::io::Error) -> TransportError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => TransportError::Timeout,
        _ => TransportError::Io(e.to_string()),
    }
}

impl Sockets {
    fn udp(
        server: SocketAddr,
        query: &[u8],
        deadline: Instant,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let local: SocketAddr = if server.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let sock = UdpSocket::bind(local).map_err(io)?;
        // `connect` makes the kernel drop datagrams from anyone else.
        sock.connect(server).map_err(io)?;
        sock.send(query).map_err(io)?;
        let mut buf = vec![0u8; MAX_REPLY];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TransportError::Timeout);
            }
            sock.set_read_timeout(Some(left)).map_err(io)?;
            let n = sock.recv(&mut buf).map_err(io)?;
            let msg = buf.get(..n).unwrap_or_default();
            // Late or forged answers are skipped (RFC 5452 §9.1).
            if accept(msg) {
                return Ok(msg.to_vec());
            }
        }
    }

    /// RFC 1035 §4.2.2: each message prefixed by its 2-byte length.
    fn tcp(
        server: SocketAddr,
        query: &[u8],
        deadline: Instant,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let left = |_: ()| {
            let l = deadline.saturating_duration_since(Instant::now());
            if l.is_zero() {
                Err(TransportError::Timeout)
            } else {
                Ok(l)
            }
        };
        let mut s = TcpStream::connect_timeout(&server, left(())?).map_err(io)?;
        let len = u16::try_from(query.len())
            .map_err(|_| TransportError::Io("query too long for TCP".into()))?;
        s.set_write_timeout(Some(left(())?)).map_err(io)?;
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(query);
        s.write_all(&framed).map_err(io)?;
        loop {
            s.set_read_timeout(Some(left(())?)).map_err(io)?;
            let mut head = [0u8; 2];
            s.read_exact(&mut head).map_err(io)?;
            let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
            s.set_read_timeout(Some(left(())?)).map_err(io)?;
            s.read_exact(&mut msg).map_err(io)?;
            if accept(&msg) {
                return Ok(msg);
            }
        }
    }
}

impl Transport for Sockets {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn exchange(
        &mut self,
        server: SocketAddr,
        query: &[u8],
        tcp: bool,
        wait_ms: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        if tcp {
            Self::tcp(server, query, deadline, accept)
        } else {
            Self::udp(server, query, deadline, accept)
        }
    }

    fn exchange_secure(
        &mut self,
        server: SocketAddr,
        via: &corerouter_proto_dns::encrypted::SecureServer,
        query: &[u8],
        wait_ms: u64,
    ) -> Result<Vec<u8>, TransportError> {
        super::dns_secure::exchange(server, via, query, wait_ms)
    }
}

/// Starts the resolver: registered in the session (the tools use it from
/// there) and kept in step with the config by a thread, outside the
/// supervisor (tests).
#[cfg(test)]
pub(crate) fn spawn(session: Shared) -> std::io::Result<Arc<RouterDns>> {
    let dns = Arc::new(RouterDns::new());
    register(&session, &dns);
    let keep = dns.clone();
    let health = super::Health::new(corerouter_control::Shutdown::default());
    thread::Builder::new()
        .name("dns".into())
        .spawn(move || follow(&session, &keep, &health))?;
    Ok(dns)
}

fn register(session: &Shared, dns: &Arc<RouterDns>) {
    let mut s = lock(session);
    dns.resolver.configure(s.dns_settings(), dns.now_ms());
    s.set_dns_backend(dns.clone());
}

/// Copies the running `/ip dns` into the resolver every tick, until stopped.
fn follow(session: &Shared, dns: &RouterDns, health: &super::Health) {
    let mut warned = false;
    while health.sleep(TICK) {
        health.beat();
        let settings = lock(session).dns_settings();
        if !settings.has_servers() && !warned {
            log::info!(
                "DNS: no server configured; names will not resolve until ip.dns.set \
                 servers=… or a DHCP client with use_peer_dns gets one"
            );
            health.event("no DNS server configured (ip.dns.set servers=… or DHCP)");
        } else if settings.has_servers() && warned {
            health.event("DNS servers configured");
        }
        warned = !settings.has_servers();
        dns.resolver.configure(settings, dns.now_ms());
    }
}

/// Addresses of `host` for the daemon's own services (NTP client): an IP
/// literal as it is, a name through the router's resolver.
pub(crate) fn resolve(session: &Shared, host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    // Taken out of the session first: the lookup waits on the network.
    let backend = lock(session).dns_backend();
    match backend {
        Some(b) => b.lookup(host).map_err(|e| e.to_string()),
        None => Err(ResolveError::NoServers.to_string()),
    }
}

/// No flags: configured with `ip.dns.*`.
pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns-resolver",
    flags: &[],
    topic: "dns",
    enable: "always on (ip.dns.set servers=…)",
    depends: &[],
    start,
};

/// One resolver for the daemon's life: a restart keeps it and its cache.
fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        let dns = ROUTER.get_or_init(|| Arc::new(RouterDns::new())).clone();
        register(&session, &dns);
        follow(&session, &dns, health);
        Ok(())
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_dns::resolver::Settings;
    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, PTR, TXT};
    use hickory_proto::rr::{RData, Record, RecordType};
    use serde_json::json;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A UDP+TCP DNS server on 127.0.0.1 that answers every A query with
    /// `ip` (TTL 300) and AAAA with NODATA; with `truncate`, UDP answers
    /// only carry TC. Returns the port and the query counter.
    pub(crate) fn server(ip: Ipv4Addr, truncate: bool) -> (u16, Arc<AtomicUsize>) {
        // A free UDP port may be taken for TCP by a parallel test (flaked
        // with AddrInUse in CI, 2026-10-25): retry until one is free on both.
        let (udp, port, tcp) = (0..64)
            .find_map(|_| {
                let udp = UdpSocket::bind("127.0.0.1:0").ok()?;
                let port = udp.local_addr().ok()?.port();
                let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).ok()?;
                Some((udp, port, tcp))
            })
            .expect("no port free for both UDP and TCP on 127.0.0.1");
        let count = Arc::new(AtomicUsize::new(0));
        let answer = move |q: &[u8], tc: bool| {
            let q = Message::from_vec(q).unwrap();
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.response_code = ResponseCode::NoError;
            m.metadata.truncation = tc;
            m.add_queries(q.queries.clone());
            let qq = &q.queries[0];
            let owner = qq.name().to_ascii();
            let data = match qq.query_type() {
                RecordType::A => Some(RData::A(A(ip))),
                RecordType::PTR => Some(RData::PTR(PTR(
                    format!("hop-{}.isp.example.", owner.split('.').next().unwrap_or("x"))
                        .parse()
                        .unwrap(),
                ))),
                RecordType::TXT if owner.starts_with("AS") => Some(RData::TXT(TXT::new(vec![
                    "3356 | US | arin | 2000-03-10 | LEVEL3, US".into(),
                ]))),
                RecordType::TXT => Some(RData::TXT(TXT::new(vec![
                    "3356 | 4.0.0.0/9 | US | arin | 1992-12-01".into(),
                ]))),
                _ => None,
            };
            if let (false, Some(d)) = (tc, data) {
                m.add_answer(Record::from_rdata(qq.name().clone(), 300, d));
            }
            m.to_vec().unwrap()
        };
        let c = count.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = udp.recv_from(&mut buf) {
                c.fetch_add(1, Ordering::Relaxed);
                let _ = udp.send_to(&answer(&buf[..n], truncate), from);
            }
        });
        thread::spawn(move || {
            for mut s in tcp.incoming().flatten() {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).unwrap();
                let mut q = vec![0u8; usize::from(u16::from_be_bytes(head))];
                s.read_exact(&mut q).unwrap();
                let r = answer(&q, false);
                let mut out = u16::try_from(r.len()).unwrap().to_be_bytes().to_vec();
                out.extend(r);
                s.write_all(&out).unwrap();
            }
        });
        (port, count)
    }

    fn settings(port: u16, servers: &[&str]) -> Settings {
        let mut s = Settings::new(&corerouter_model::dns::Dns::default(), &[]);
        s.servers = servers.iter().map(|s| s.parse().unwrap()).collect();
        s.port = port;
        s.server_timeout_ms = 300;
        s
    }

    #[test]
    fn resolves_over_udp_and_caches() {
        let (port, count) = server(Ipv4Addr::new(192, 0, 2, 10), false);
        let dns = RouterDns::new();
        dns.resolver.configure(settings(port, &["127.0.0.1"]), 0);
        assert_eq!(dns.lookup("uol.com.br").unwrap(), vec![IpAddr::from([192, 0, 2, 10])]);
        let asked = count.load(Ordering::Relaxed);
        assert_eq!(asked, 2, "A and AAAA");
        dns.lookup("uol.com.br").unwrap();
        // AAAA NODATA without SOA is not cached (RFC 2308 §5): asked again.
        assert_eq!(count.load(Ordering::Relaxed), asked + 1);
        let rows = dns.cache_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "uol.com.br");
    }

    #[test]
    fn hop_names_and_as_numbers_do_not_wait() {
        let (port, count) = server(Ipv4Addr::new(192, 0, 2, 13), false);
        let dns = RouterDns::new();
        assert_eq!(dns.reverse_nowait("4.2.2.2".parse().unwrap()), None, "no servers: no lookup");
        dns.resolver.configure(settings(port, &["127.0.0.1"]), 0);
        let hop: IpAddr = "4.69.1.7".parse().unwrap();
        assert_eq!(dns.reverse_nowait(hop), Some(Lookup::Pending), "answers at once");
        let deadline = Instant::now() + Duration::from_secs(5);
        let name = loop {
            match dns.reverse_nowait(hop) {
                Some(Lookup::Done(n)) => break n,
                _ if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                other => panic!("no answer: {other:?}"),
            }
        };
        assert_eq!(name.as_deref(), Some("hop-7.isp.example"));
        let asn = loop {
            match dns.origin_as_nowait(hop) {
                Some(Lookup::Done(a)) => break a,
                _ if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                other => panic!("no answer: {other:?}"),
            }
        };
        let asn = asn.unwrap();
        assert_eq!((asn.asn, asn.name.as_deref()), (3356, Some("LEVEL3")));
        let asked = count.load(Ordering::Relaxed);
        assert_eq!(asked, 3, "PTR, origin TXT, AS name TXT");
        dns.reverse_nowait(hop);
        dns.origin_as_nowait(hop);
        assert_eq!(count.load(Ordering::Relaxed), asked, "kept for the next pass");
    }

    #[test]
    fn resolve_query_reports_records_and_source() {
        let (port, count) = server(Ipv4Addr::new(192, 0, 2, 14), false);
        let dns = RouterDns::new();
        dns.resolver.configure(settings(port, &["127.0.0.1"]), 0);
        let r = dns.resolve_query("www.example", "A", None).unwrap();
        assert_eq!((r.rcode.as_str(), r.source.as_str()), ("NOERROR", "127.0.0.1"));
        assert_eq!(r.records, vec!["A 192.0.2.14".to_owned()]);
        assert_eq!(r.ttl, Some(300));
        assert_eq!(dns.resolve_query("www.example", "A", None).unwrap().source, "cache");
        // `server`: asked directly, past the cache.
        let before = count.load(Ordering::Relaxed);
        let r = dns
            .resolve_query("www.example", "A", Some("127.0.0.1".parse().unwrap()))
            .unwrap();
        assert_eq!(r.source, "127.0.0.1");
        assert_eq!(count.load(Ordering::Relaxed), before + 1);
        assert!(dns.resolve_query("www.example", "BOGUS", None).is_err());
    }

    #[test]
    fn truncated_answers_come_over_tcp() {
        let (port, _) = server(Ipv4Addr::new(192, 0, 2, 11), true);
        let dns = RouterDns::new();
        dns.resolver.configure(settings(port, &["127.0.0.1"]), 0);
        assert_eq!(dns.lookup("big.example").unwrap(), vec![IpAddr::from([192, 0, 2, 11])]);
    }

    #[test]
    fn a_silent_server_is_skipped() {
        let (port, _) = server(Ipv4Addr::new(192, 0, 2, 12), false);
        // 127.0.0.2 has nothing on `port`: ICMP port unreachable or silence.
        let dns = RouterDns::new();
        dns.resolver.configure(settings(port, &["127.0.0.2", "127.0.0.1"]), 0);
        let t = Instant::now();
        assert_eq!(dns.lookup("x.example").unwrap(), vec![IpAddr::from([192, 0, 2, 12])]);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn the_service_follows_the_config_and_serves_the_tools() {
        let session = shared(Session::virtual_lab());
        let dns = spawn(session.clone()).unwrap();
        assert!(matches!(dns.lookup("uol.com.br"), Err(ResolveError::NoServers)));
        lock(&session)
            .execute("ip.dns.set", &json!({"servers": ["192.0.2.53"]}))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while dns.resolver.settings().servers.is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(dns.resolver.settings().servers, vec![IpAddr::from([192, 0, 2, 53])]);
        let got = lock(&session).execute("ip.dns.get", &json!({})).unwrap();
        assert_eq!(got["resolver"], "router");
        assert_eq!(resolve(&session, "192.0.2.1").unwrap(), vec![IpAddr::from([192, 0, 2, 1])]);
    }
}

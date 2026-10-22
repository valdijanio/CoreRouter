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

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::dns::DnsBackend;
use corerouter_engine::{Shared, lock};
use corerouter_model::dns::CacheRow;
use corerouter_proto_dns::resolver::{
    ResolveError, Resolver, ServerStats, Transport, TransportError,
};

/// How often the thread looks at the config.
const TICK: Duration = Duration::from_secs(1);
/// Largest reply read over UDP (RFC 6891 payloads go up to 65535).
const MAX_REPLY: usize = 65_535;

/// The resolver plus the clock its cache runs on.
pub(crate) struct RouterDns {
    pub(crate) resolver: Arc<Resolver>,
    start: Instant,
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

    fn cache_used_bytes(&self) -> usize {
        self.resolver.cache_used_bytes()
    }

    fn flush(&self) {
        self.resolver.flush();
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
}

/// Starts the resolver: registered in the session (the tools use it from
/// there) and kept in step with the config by a thread.
pub(crate) fn spawn(session: Shared) -> std::io::Result<Arc<RouterDns>> {
    let dns = Arc::new(RouterDns::new());
    {
        let mut s = lock(&session);
        dns.resolver.configure(s.dns_settings(), dns.now_ms());
        s.set_dns_backend(dns.clone());
    }
    let keep = dns.clone();
    thread::Builder::new().name("dns".into()).spawn(move || {
        let mut warned = false;
        loop {
            thread::sleep(TICK);
            let settings = lock(&session).dns_settings();
            if settings.servers.is_empty() && !warned {
                log::info!(
                    "DNS: no server configured; names will not resolve until ip.dns.set \
                     servers=… or a DHCP client with use_peer_dns gets one"
                );
            }
            warned = settings.servers.is_empty();
            keep.resolver.configure(settings, keep.now_ms());
        }
    })?;
    Ok(dns)
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
    name: "dns resolver",
    flags: &[],
    start,
};

/// A router without it still forwards: a failure is logged, not fatal.
fn start(ctx: &super::Ctx) -> Result<(), String> {
    match spawn(ctx.session.clone()) {
        Ok(dns) => {
            let _ = ROUTER.set(dns);
        }
        Err(e) => log::error!("DNS resolver is off: cannot start its thread: {e}"),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_dns::resolver::Settings;
    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record, RecordType};
    use serde_json::json;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A UDP+TCP DNS server on 127.0.0.1 that answers every A query with
    /// `ip` (TTL 300) and AAAA with NODATA; with `truncate`, UDP answers
    /// only carry TC. Returns the port and the query counter.
    pub(crate) fn server(ip: Ipv4Addr, truncate: bool) -> (u16, Arc<AtomicUsize>) {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let tcp = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let answer = move |q: &[u8], tc: bool| {
            let q = Message::from_vec(q).unwrap();
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.response_code = ResponseCode::NoError;
            m.metadata.truncation = tc;
            m.add_queries(q.queries.clone());
            let qq = &q.queries[0];
            if !tc && qq.query_type() == RecordType::A {
                m.add_answer(Record::from_rdata(qq.name().clone(), 300, RData::A(A(ip))));
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

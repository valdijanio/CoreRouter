//! The router's resolver (G4.1a) as seen by the engine. The daemon owns it
//! (sockets, threads) and registers it here with
//! [`Session::set_dns_backend`]; ping, MTU and MTR then resolve through it
//! instead of the host's resolver. Without a daemon (headless lab, WASM,
//! tests) nothing is registered and the tools keep the prober's own
//! resolver: the simulated one in the lab.

use std::net::IpAddr;
use std::sync::Arc;

use corerouter_hal::probe::{AsInfo, Lookup, ProbeError, ProbeSocket, Prober, SocketOptions};
use corerouter_hal::SharedProber;
use corerouter_model::dns::CacheRow;
use corerouter_proto_dns::resolver::{ResolveError, ServerStats, Settings};

use crate::Session;

/// What the daemon's resolver offers. Implementations never lock the
/// session (they keep their own copy of the settings), so a lookup can run
/// on any thread, even while a command holds the session.
pub trait DnsBackend: Send + Sync {
    fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError>;
    fn cache_rows(&self) -> Vec<CacheRow>;
    /// At most `limit` entries whose name contains `name` and whose type
    /// is `qtype` (upper case). Implementations filter before formatting,
    /// under their lock: a large cache is never copied whole.
    fn cache_rows_matching(&self, name: Option<&str>, qtype: Option<&str>, limit: usize) -> Vec<CacheRow> {
        self.cache_rows()
            .into_iter()
            .filter(|r| name.is_none_or(|f| r.name.contains(f)))
            .filter(|r| qtype.is_none_or(|t| r.qtype == t))
            .take(limit)
            .collect()
    }
    /// Entries in the cache (without formatting them).
    fn cache_len(&self) -> usize {
        self.cache_rows().len()
    }
    fn cache_used_bytes(&self) -> usize;
    fn flush(&self);

    /// The settings in force now (G1.6qc): called each time the session
    /// hands the backend out, so a command right after `ip.dns.set` uses
    /// the new servers instead of waiting for the daemon's next copy.
    /// Cheap when nothing changed (implementations compare first).
    fn configure(&self, settings: Settings) {
        let _ = settings;
    }
    /// What the resolver measured of each upstream server.
    fn server_stats(&self) -> Vec<(IpAddr, ServerStats)> {
        Vec::new()
    }

    /// The PTR name of `ip`, without waiting (G6.3b): the lookup runs on
    /// the backend's own threads and a later call gets the answer. `None`:
    /// no server configured (the prober's own names apply).
    fn reverse_nowait(&self, _ip: IpAddr) -> Option<Lookup<Option<String>>> {
        None
    }

    /// The origin AS of `ip` (Team Cymru over DNS), like
    /// [`Self::reverse_nowait`].
    fn origin_as_nowait(&self, _ip: IpAddr) -> Option<Lookup<Option<AsInfo>>> {
        None
    }

    /// `ip.dns.resolve` (G4.1d): `name` and `rtype` through the cache and
    /// the servers, or asked of `server` alone (no cache). Waits on the
    /// network: called from a task, never under the session lock.
    fn resolve_query(
        &self,
        name: &str,
        rtype: &str,
        server: Option<IpAddr>,
    ) -> Result<Resolution, String> {
        let _ = (name, rtype, server);
        Err("ip.dns.resolve needs the router daemon's resolver".into())
    }

    /// `tool.dns.query` (G6.6): `query` sent as it is to `to` (the router's
    /// own chain, a server, or an encrypted one), over TCP if `tcp` (UDP
    /// retried over TCP when truncated), and the reply's bytes. Waits on
    /// the network: called from a task.
    fn exchange(
        &self,
        to: &crate::dns_lookup::LookupServer,
        query: &[u8],
        tcp: bool,
    ) -> Result<crate::dns_lookup::Exchanged, String> {
        let _ = (to, query, tcp);
        Err(crate::dns_lookup::NEEDS_DAEMON.into())
    }

    /// `tool.dns.query` to the router's own chain with `explain` or
    /// `as_client` (G6.8): the reply, and each stage's decision. Without a
    /// daemon chain that knows them: [`Self::exchange`] to the router.
    fn ask_router(
        &self,
        query: &[u8],
        tcp: bool,
        how: crate::dns_lookup::RouterAsk,
    ) -> Result<crate::dns_lookup::Exchanged, String> {
        let _ = how;
        self.exchange(&crate::dns_lookup::LookupServer::Router, query, tcp)
    }

    /// [`Self::exchange`] with every `(server, query)` at once (`compare`):
    /// the daemon asks them in parallel, so the slowest sets the time.
    fn exchange_all(
        &self,
        asks: &[(crate::dns_lookup::LookupServer, Vec<u8>)],
        tcp: bool,
    ) -> Vec<Result<crate::dns_lookup::Exchanged, String>> {
        asks.iter().map(|(to, q)| self.exchange(to, q, tcp)).collect()
    }
}

/// One answer of `ip.dns.resolve`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Resolution {
    /// `NOERROR` or `NXDOMAIN` (the others are failures).
    pub rcode: String,
    /// The records as text (`CNAME edge.example.`, `A 192.0.2.7`).
    pub records: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub ttl: Option<u32>,
    /// `cache`, `stale`, `simulated`, or the server that answered.
    pub source: String,
}

#[derive(Default)]
struct DnsRuntime {
    backend: Option<Arc<dyn DnsBackend>>,
}

impl Session {
    pub fn set_dns_backend(&mut self, backend: Arc<dyn DnsBackend>) {
        if let Some(rt) = self.ext_mut::<DnsRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The registered resolver, brought up to the running config first
    /// (G1.6qc): `ip.dns.set` and the lookup that follows it see the same
    /// servers, without waiting for the daemon's periodic copy.
    pub fn dns_backend(&self) -> Option<Arc<dyn DnsBackend>> {
        let backend = self.ext::<DnsRuntime>()?.backend.clone()?;
        backend.configure(self.dns_settings());
        Some(backend)
    }

    /// RouterOS `dynamic-servers`: learned by DHCP clients with
    /// `use_peer_dns`, then by PPPoE clients with `use-peer-dns` (G3.9ga).
    pub fn dns_dynamic_servers(&self) -> Vec<IpAddr> {
        let mut out = self.dhcp_peer_dns();
        for d in self.pppoe_peer_dns() {
            if !out.contains(&d) {
                out.push(d);
            }
        }
        out.into_iter().map(IpAddr::V4).collect()
    }

    /// What the resolver must use now: the running `/ip dns` and the
    /// learned servers.
    pub fn dns_settings(&self) -> Settings {
        Settings::from_config(self.store().running(), &self.dns_dynamic_servers())
    }

    /// A static DNS entry's `address_list` (G4.1b): `address` goes into
    /// firewall list `list` as a dynamic entry for `timeout_secs`. One
    /// already there is refreshed only when it has less than half of that
    /// left (every answer would otherwise rewrite the list).
    pub fn dns_address_list(
        &mut self,
        list: &str,
        address: IpAddr,
        timeout_secs: u64,
    ) -> Result<(), String> {
        let timeout = timeout_secs.max(1);
        let name: corerouter_model::firewall::Name = list.parse().map_err(|e| format!("{e}"))?;
        let addr = corerouter_model::firewall::AddrMatch::Net(ipnet::IpNet::from(address));
        let now = self.now();
        if let Some(e) = self.dynamic_addresses.find(&name, &addr) {
            if e.left(now) >= timeout / 2 {
                return Ok(());
            }
            let id = e.id;
            self.execute("ip.firewall.address-list.remove", &serde_json::json!({"id": id}))
                .map_err(|e| e.to_string())?;
        }
        self.execute(
            "ip.firewall.address-list.add",
            &serde_json::json!({
                "list": list,
                "address": address.to_string(),
                "timeout": timeout,
                "comment": "dns static",
            }),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    /// The tools' prober, resolving names through the router's resolver
    /// when the daemon registered one.
    pub fn tool_prober(&self) -> Result<SharedProber, String> {
        let inner = self.hal().prober()?;
        Ok(match self.dns_backend() {
            Some(dns) => Arc::new(RouterResolver { inner, dns }),
            None => inner,
        })
    }
}

/// A prober whose names come from the router's resolver.
struct RouterResolver {
    inner: SharedProber,
    dns: Arc<dyn DnsBackend>,
}

impl Prober for RouterResolver {
    fn describe(&self) -> String {
        self.inner.describe()
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ProbeError> {
        match self.dns.lookup(name) {
            Ok(addrs) => Ok(addrs),
            // No server configured: the lab's simulated network still has
            // its own names; the host prober says why it has none.
            Err(ResolveError::NoServers) => self.inner.resolve(name),
            Err(ResolveError::NotFound(_)) => {
                Err(ProbeError::NotFound(name.chars().take(64).collect()))
            }
            Err(e) => Err(ProbeError::Unavailable(e.to_string())),
        }
    }

    fn open(&self, options: &SocketOptions) -> Result<Box<dyn ProbeSocket>, ProbeError> {
        self.inner.open(options)
    }

    fn reverse_name(&self, ip: IpAddr) -> Lookup<Option<String>> {
        self.dns
            .reverse_nowait(ip)
            .unwrap_or_else(|| self.inner.reverse_name(ip))
    }

    fn origin_as(&self, ip: IpAddr) -> Lookup<Option<AsInfo>> {
        self.dns
            .origin_as_nowait(ip)
            .unwrap_or_else(|| self.inner.origin_as(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fixed(Mutex<u32>);

    impl DnsBackend for Fixed {
        fn lookup(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            *self.0.lock().unwrap() += 1;
            match name {
                "uol.com.br" => Ok(vec![[200, 147, 3, 157].into()]),
                "none.example" => Err(ResolveError::NotFound(name.into())),
                _ => Err(ResolveError::NoServers),
            }
        }
        fn cache_rows(&self) -> Vec<CacheRow> {
            Vec::new()
        }
        fn cache_used_bytes(&self) -> usize {
            0
        }
        fn flush(&self) {}
    }

    #[test]
    fn address_list_from_dns_is_added_once_and_refreshed() {
        let mut s = Session::virtual_lab();
        let ip: IpAddr = [192, 0, 2, 7].into();
        s.dns_address_list("vpn", ip, 300).unwrap();
        s.dns_address_list("vpn", ip, 300).unwrap();
        let rows = s
            .execute("ip.firewall.address-list.list", &serde_json::json!({"list": "vpn"}))
            .unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
        assert_eq!(rows[0]["dynamic"], true);
        assert!(s.dns_address_list("bad list!", ip, 300).is_err());
    }

    #[test]
    fn tools_resolve_through_the_registered_backend() {
        let mut s = Session::virtual_lab();
        let sim = s.tool_prober().unwrap();
        let simulated = sim.resolve("uol.com.br").unwrap();
        let backend = Arc::new(Fixed::default());
        s.set_dns_backend(backend.clone());
        let p = s.tool_prober().unwrap();
        assert_eq!(p.resolve("uol.com.br").unwrap(), vec![IpAddr::from([200, 147, 3, 157])]);
        assert_ne!(simulated, p.resolve("uol.com.br").unwrap());
        assert!(matches!(p.resolve("none.example"), Err(ProbeError::NotFound(_))));
        // No server: the lab's simulated names still work.
        assert!(p.resolve("other.example").is_ok());
        assert_eq!(*backend.0.lock().unwrap(), 4);
    }
}

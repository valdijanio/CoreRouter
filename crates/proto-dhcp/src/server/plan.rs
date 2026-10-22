//! The running config, compiled for the server: what it reads on every
//! message, looked up by name once (pools, option sets) and option values
//! already in bytes when they have no `$(…)`.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::dhcp_server::{
    Authoritative, DhcpNetwork, MatchingType, StaticLease, parse_client_id,
};
use corerouter_model::ip_pool::{IpPools, PoolRange};
use corerouter_model::{Config, IfName, ItemId};
use ipnet::Ipv4Net;

use super::checks::router_addresses;
use crate::optval::{self, Vars};

/// One option to send: its code, its value (bytes, or the text to expand
/// per client when it has variables) and whether it goes unasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptPlan {
    pub code: u8,
    pub value: OptValue,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptValue {
    Bytes(Vec<u8>),
    /// Has `$(HOSTNAME)` / `$(CLIENT_MAC)`: parsed per client.
    Text(String),
}

impl OptPlan {
    fn new(code: u8, value: &str, force: bool) -> Option<Self> {
        let value = if value.contains("$(") {
            OptValue::Text(value.to_owned())
        } else {
            OptValue::Bytes(
                optval::parse(
                    value,
                    &Vars {
                        host_name: "",
                        mac: [0; 6],
                    },
                )
                .ok()?,
            )
        };
        Some(Self { code, value, force })
    }

    /// The bytes for a client with this host name and MAC.
    pub fn bytes(&self, host_name: &str, mac: [u8; 6]) -> Option<Vec<u8>> {
        match &self.value {
            OptValue::Bytes(b) => Some(b.clone()),
            OptValue::Text(t) => optval::parse(t, &Vars { host_name, mac }).ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPlan {
    pub id: ItemId,
    pub name: String,
    pub interface: IfName,
    /// The interface's own addresses (direct service picks the one whose
    /// subnet holds the client's address).
    pub on_link: Vec<Ipv4Net>,
    pub pool: Option<String>,
    pub lease_time: u32,
    pub authoritative: Authoritative,
    pub conflict_detection: bool,
    pub always_broadcast: bool,
    pub server_address: Option<Ipv4Addr>,
    pub relay: Option<Ipv4Addr>,
    pub options: Vec<OptPlan>,
    pub address_lists: Vec<String>,
    pub client_mac_limit: Option<u32>,
    pub client_rate_limit: u32,
}

impl ServerPlan {
    /// The address this server answers from for a client at `yiaddr` (or
    /// relayed by `giaddr`).
    pub fn source_for(&self, yiaddr: Ipv4Addr) -> Option<Ipv4Addr> {
        self.server_address
            .or_else(|| {
                self.on_link
                    .iter()
                    .find(|n| n.contains(&yiaddr))
                    .map(Ipv4Net::addr)
            })
            .or_else(|| self.on_link.first().map(Ipv4Net::addr))
    }

    /// Every address the server may call itself (option 54 from clients:
    /// RFC 2131 errata 7177, a server with several addresses).
    pub fn is_me(&self, ip: Ipv4Addr) -> bool {
        self.server_address == Some(ip) || self.on_link.iter().any(|n| n.addr() == ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPlan {
    pub net: Ipv4Net,
    pub cfg: DhcpNetwork,
    pub dns: Vec<Ipv4Addr>,
    pub options: Vec<OptPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPlan {
    pub cfg: StaticLease,
    /// Client id bytes, when it matches by client id.
    pub client_id: Option<Vec<u8>>,
    /// Option 82 circuit and remote id it must carry (G4.2b).
    pub circuit: Option<Vec<u8>>,
    pub remote: Option<Vec<u8>>,
    pub options: Vec<OptPlan>,
}

impl StaticPlan {
    /// Whether this static lease is for the client with `key` (RFC 2131
    /// §4.2 identity) and hardware address `mac`. RFC 4361 §6.3: a lease
    /// written by MAC matches that MAC even when the client sends a client
    /// id (RouterOS does the same).
    pub fn matches(&self, server: &str, key: &[u8], mac: [u8; 6], agent: Option<&[u8]>) -> bool {
        if self.cfg.server.as_deref().is_some_and(|s| s != server) {
            return false;
        }
        // Every identity it names must match; it must name one.
        let id = match (&self.client_id, self.cfg.mac_address) {
            (Some(id), _) => Some(id.as_slice() == key),
            (None, Some(m)) => Some(m.0 == mac),
            (None, None) => None,
        };
        let sub = |want: &Option<Vec<u8>>, code: u8| {
            want.as_ref().map(|w| {
                agent
                    .and_then(|a| crate::server::agent::get(a, code))
                    .is_some_and(|got| got == w.as_slice())
            })
        };
        let checks = [
            id,
            sub(&self.circuit, crate::server::agent::CIRCUIT_ID),
            sub(&self.remote, crate::server::agent::REMOTE_ID),
        ];
        checks.iter().any(Option::is_some) && checks.iter().flatten().all(|ok| *ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherPlan {
    pub name: String,
    pub server: Option<String>,
    pub code: u8,
    pub value: Vec<u8>,
    pub kind: MatchingType,
    pub options: Vec<OptPlan>,
    pub pool: Option<String>,
}

impl MatcherPlan {
    pub fn hits(&self, server: &str, data: Option<&[u8]>) -> bool {
        if self.server.as_deref().is_some_and(|s| s != server) {
            return false;
        }
        let Some(d) = data else {
            return false;
        };
        match self.kind {
            MatchingType::Exact => d == self.value.as_slice(),
            MatchingType::Substring => {
                !self.value.is_empty()
                    && d.windows(self.value.len())
                        .any(|w| w == self.value.as_slice())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertPlan {
    pub interface: IfName,
    pub valid: Vec<[u8; 6]>,
    pub timeout: u64,
}

/// Everything the server reads, from one running config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub servers: Vec<ServerPlan>,
    pub networks: Vec<NetPlan>,
    pub statics: Vec<StaticPlan>,
    pub matchers: Vec<MatcherPlan>,
    pub alerts: Vec<AlertPlan>,
    pub pools: IpPools,
    /// Pool name → its ranges, followed by its `next_pool` chain.
    pub chains: HashMap<String, Vec<(String, Vec<PoolRange>)>>,
    /// The router's addresses (never handed out, whatever the pools say).
    pub router: Vec<Ipv4Addr>,
}

fn options_of(
    d: &corerouter_model::dhcp_server::DhcpServers,
    names: &[String],
    set: Option<&String>,
) -> Vec<OptPlan> {
    let mut all: Vec<&String> = Vec::new();
    if let Some(s) = set.and_then(|s| d.option_set(s)) {
        all.extend(&s.options);
    }
    all.extend(names);
    // Later ones replace earlier ones with the same code.
    let mut out: Vec<OptPlan> = Vec::new();
    for n in all {
        if let Some(o) = d.option(n)
            && let Some(p) = OptPlan::new(o.code, &o.value, o.force)
        {
            out.retain(|q| q.code != p.code);
            out.push(p);
        }
    }
    out
}

impl Plan {
    pub fn from_config(cfg: &Config) -> Self {
        let d = &cfg.ip.dhcp_server;
        let mine = router_addresses(cfg);
        let servers = d
            .servers
            .iter()
            .filter(|s| !s.disabled)
            .map(|s| ServerPlan {
                id: s.id,
                name: s.name.clone(),
                interface: s.interface.clone(),
                on_link: mine
                    .iter()
                    .filter(|(_, i)| **i == s.interface)
                    .map(|(n, _)| *n)
                    .collect(),
                pool: s.address_pool.clone(),
                lease_time: s.lease_time,
                authoritative: s.authoritative,
                conflict_detection: s.conflict_detection,
                always_broadcast: s.always_broadcast,
                server_address: s.server_address,
                relay: s.relay,
                options: options_of(d, &[], s.dhcp_option_set.as_ref()),
                address_lists: s
                    .address_lists
                    .iter()
                    .map(|n| n.as_str().to_owned())
                    .collect(),
                client_mac_limit: s.client_mac_limit,
                client_rate_limit: s.client_rate_limit,
            })
            .collect();
        // Option 6 when the network names none: the router itself when its
        // resolver serves the LAN, else the router's own upstreams.
        let own_dns: Vec<Ipv4Addr> = cfg
            .ip
            .dns
            .servers
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v) => Some(*v),
                IpAddr::V6(_) => None,
            })
            .collect();
        let networks = d
            .networks
            .iter()
            .map(|n| {
                let dns = if n.dns_none {
                    Vec::new()
                } else if !n.dns_server.is_empty() {
                    n.dns_server.clone()
                } else if cfg.ip.dns.allow_remote_requests {
                    mine.iter()
                        .map(|(a, _)| a.addr())
                        .filter(|a| n.address.contains(a))
                        .take(1)
                        .collect()
                } else {
                    own_dns.clone()
                };
                NetPlan {
                    net: n.address,
                    cfg: n.clone(),
                    dns,
                    options: options_of(d, &n.dhcp_option, n.dhcp_option_set.as_ref()),
                }
            })
            .collect();
        let statics = d
            .leases
            .iter()
            .filter(|l| !l.disabled)
            .map(|l| StaticPlan {
                cfg: l.clone(),
                client_id: if l.client_id.is_empty() {
                    None
                } else {
                    parse_client_id(&l.client_id)
                },
                circuit: crate::server::agent::parse(&l.agent_circuit_id),
                remote: crate::server::agent::parse(&l.agent_remote_id),
                options: options_of(d, &l.dhcp_option, l.dhcp_option_set.as_ref()),
            })
            .collect();
        let matchers = d
            .matchers
            .iter()
            .filter(|m| !m.disabled)
            .filter_map(|m| {
                let value = optval::parse(
                    &m.value,
                    &Vars {
                        host_name: "",
                        mac: [0; 6],
                    },
                )
                .ok()?;
                Some(MatcherPlan {
                    name: m.name.clone(),
                    server: m.server.clone(),
                    code: m.code,
                    value,
                    kind: m.matching_type,
                    options: options_of(d, &[], m.option_set.as_ref()),
                    pool: m.address_pool.clone(),
                })
            })
            .collect();
        let alerts = d
            .alerts
            .iter()
            .filter(|a| !a.disabled)
            .map(|a| AlertPlan {
                interface: a.interface.clone(),
                valid: a.valid_server.iter().map(|m| m.0).collect(),
                timeout: u64::from(a.alert_timeout),
            })
            .collect();
        let chains = cfg
            .ip
            .pools
            .pools
            .iter()
            .map(|p| {
                let chain = cfg
                    .ip
                    .pools
                    .chain(&p.name)
                    .into_iter()
                    .map(|q| (q.name.clone(), q.ranges.clone()))
                    .collect();
                (p.name.clone(), chain)
            })
            .collect();
        Self {
            servers,
            networks,
            statics,
            matchers,
            alerts,
            pools: cfg.ip.pools.clone(),
            chains,
            router: mine.iter().map(|(a, _)| a.addr()).collect(),
        }
    }

    /// The server for a request heard on `iface`, relayed by `giaddr`
    /// (0.0.0.0: direct). A relayed request goes to the server whose
    /// `relay` is that agent (RouterOS: 255.255.255.255 takes any relay
    /// no other server takes).
    pub fn server_for(&self, iface: &IfName, giaddr: Ipv4Addr) -> Option<usize> {
        if giaddr.is_unspecified() {
            return self
                .servers
                .iter()
                .position(|s| s.interface == *iface && s.relay.is_none());
        }
        self.servers
            .iter()
            .position(|s| s.relay == Some(giaddr))
            .or_else(|| {
                self.servers
                    .iter()
                    .position(|s| s.relay == Some(Ipv4Addr::BROADCAST))
            })
    }

    /// The most specific network of `ip`.
    pub fn network_of(&self, ip: Ipv4Addr) -> Option<&NetPlan> {
        self.networks
            .iter()
            .filter(|n| n.net.contains(&ip))
            .max_by_key(|n| n.net.prefix_len())
    }

    /// The pool `name`, then its `next_pool`s.
    pub fn chain(&self, name: &str) -> &[(String, Vec<PoolRange>)] {
        self.chains.get(name).map_or(&[], Vec::as_slice)
    }

    /// Which pool of a server's (or a matcher's) chain holds `ip`.
    pub fn pool_of(&self, chain: &str, ip: Ipv4Addr) -> Option<&str> {
        self.chain(chain)
            .iter()
            .find(|(_, ranges)| ranges.iter().any(|r| r.contains(ip)))
            .map(|(n, _)| n.as_str())
    }

    /// The static lease of a client.
    pub fn static_for(
        &self,
        server: &str,
        key: &[u8],
        mac: [u8; 6],
        agent: Option<&[u8]>,
    ) -> Option<&StaticPlan> {
        // A client-id match beats a MAC match (the more specific identity).
        self.statics
            .iter()
            .find(|s| s.client_id.is_some() && s.matches(server, key, mac, agent))
            .or_else(|| {
                self.statics
                    .iter()
                    .find(|s| s.matches(server, key, mac, agent))
            })
    }

    /// The static lease of `ip` on `server`, whoever it is for.
    pub fn static_of(&self, server: &str, ip: Ipv4Addr) -> Option<&StaticPlan> {
        self.statics
            .iter()
            .find(|s| s.cfg.address == ip && s.cfg.server.as_deref().is_none_or(|x| x == server))
    }

    pub fn alert_on(&self, iface: &IfName) -> Option<&AlertPlan> {
        self.alerts.iter().find(|a| a.interface == *iface)
    }

    /// The interfaces the server must listen on (servers and alerts).
    pub fn interfaces(&self) -> Vec<IfName> {
        let mut v: BTreeMap<IfName, ()> = BTreeMap::new();
        for s in &self.servers {
            v.insert(s.interface.clone(), ());
        }
        for a in &self.alerts {
            v.insert(a.interface.clone(), ());
        }
        v.into_keys().collect()
    }
}

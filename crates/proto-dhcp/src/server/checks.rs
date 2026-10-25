//! What the DHCP server's config gets wrong, before it is committed.
//!
//! Each [`Check`] is about one item (a server, a network, a pool, a lease)
//! and is an error (the commit is refused: `validate`), a warning (shown in
//! the GUI as an amber chip and in the commands' replies) or a check that
//! passed (a green chip on the network's form). The usual operator
//! mistakes are here: a pool that hands out the gateway or one of the
//! router's own addresses, two pools sharing addresses, a server on what
//! looks like the WAN.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::dhcp_server::{
    DhcpServers, MAX_ALERTS, MAX_LEASE_TIME, MAX_LIST, MAX_MATCHERS, MAX_NETWORKS, MAX_OPTION_SETS,
    MAX_OPTIONS, MAX_SERVERS, MAX_STATIC_LEASES, MAX_VALUE_TEXT, MIN_LEASE_TIME, parse_client_id,
};
use corerouter_model::dns_zone::ZoneType;
use corerouter_model::ip_pool::{self, IpPool, MAX_POOL_SIZE, MAX_POOLS, MAX_RANGES};
use corerouter_model::{Config, IfName, InterfaceKind, Issue, ItemId};
use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;

use crate::optval::{self, Vars};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Config path, as validation issues name it.
    pub path: String,
    pub item: ItemId,
    /// Short chip text (`gateway`, `pool ∩ router`, `WAN?`).
    pub label: &'static str,
    pub level: Level,
    pub text: String,
}

struct Out(Vec<Check>);

impl Out {
    fn push(
        &mut self,
        path: String,
        item: ItemId,
        label: &'static str,
        level: Level,
        text: String,
    ) {
        self.0.push(Check {
            path,
            item,
            label,
            level,
            text,
        });
    }
    fn err(&mut self, path: String, item: ItemId, label: &'static str, text: impl Into<String>) {
        self.push(path, item, label, Level::Error, text.into());
    }
    fn warn(&mut self, path: String, item: ItemId, label: &'static str, text: impl Into<String>) {
        self.push(path, item, label, Level::Warn, text.into());
    }
    fn ok(&mut self, path: String, item: ItemId, label: &'static str, text: impl Into<String>) {
        self.push(path, item, label, Level::Ok, text.into());
    }
}

/// The router's own IPv4 addresses (enabled), with their interface.
pub fn router_addresses(cfg: &Config) -> Vec<(Ipv4Net, &IfName)> {
    cfg.ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && a.from_pool.is_none())
        .filter_map(|a| match a.address {
            IpNet::V4(n) => Some((n, &a.interface)),
            IpNet::V6(_) => None,
        })
        .collect()
}

/// Why `iface` looks like a WAN port, if it does: a DHCP client runs on
/// it, it is in an interface list called WAN, or the default route leaves
/// through it.
pub fn looks_like_wan(cfg: &Config, iface: &IfName) -> Option<String> {
    if cfg
        .ip
        .dhcp_clients
        .iter()
        .any(|c| !c.disabled && c.interface == *iface)
    {
        return Some(format!(
            "'{iface}' has a DHCP client (it gets its address from upstream)"
        ));
    }
    if cfg
        .interface_lists
        .lists_of(iface)
        .any(|l| l.as_str().eq_ignore_ascii_case("wan"))
    {
        return Some(format!("'{iface}' is in interface list WAN"));
    }
    let nets: Vec<Ipv4Net> = router_addresses(cfg)
        .into_iter()
        .filter(|(_, i)| *i == iface)
        .map(|(n, _)| n)
        .collect();
    let default = cfg.ip.routes.iter().filter(|r| !r.disabled).find(|r| {
        matches!(r.dst_address, IpNet::V4(d) if d.prefix_len() == 0)
            && (r.gateway.iface() == Some(iface)
                || matches!(r.gateway.address(), Some(IpAddr::V4(g)) if nets.iter().any(|n| n.contains(&g))))
    });
    default.map(|_| format!("the default route leaves through '{iface}'"))
}

fn options_ok(cfg: &DhcpServers, names: &[String]) -> Result<(), String> {
    if names.len() > MAX_LIST {
        return Err(format!("at most {MAX_LIST} options"));
    }
    for n in names {
        if cfg.option(n).is_none() {
            return Err(format!("no option '{n}' (ip.dhcp-server.option.add)"));
        }
    }
    Ok(())
}

fn set_ok(cfg: &DhcpServers, set: Option<&String>) -> Result<(), String> {
    match set {
        Some(s) if cfg.option_set(s).is_none() => Err(format!(
            "no option set '{s}' (ip.dhcp-server.option-set.add)"
        )),
        _ => Ok(()),
    }
}

/// Bytes of an option value as the server would send it (variables
/// expanded with placeholders).
pub fn option_bytes(value: &str) -> Result<Vec<u8>, String> {
    if value.len() > MAX_VALUE_TEXT {
        return Err(format!("at most {MAX_VALUE_TEXT} characters"));
    }
    optval::parse(
        value,
        &Vars {
            host_name: "host",
            mac: [0; 6],
        },
    )
}

fn pool_checks(cfg: &Config, out: &mut Out) {
    let pools = &cfg.ip.pools.pools;
    if pools.len() > MAX_POOLS {
        out.err(
            "ip.pools".into(),
            ItemId(0),
            "too many",
            format!("at most {MAX_POOLS} pools"),
        );
    }
    let mine = router_addresses(cfg);
    let mut names = BTreeSet::new();
    for (i, p) in pools.iter().enumerate() {
        let at = |f: &str| format!("ip.pools[{}].{f}", p.id);
        if !ip_pool::name_ok(&p.name) {
            out.err(
                at("name"),
                p.id,
                "name",
                "letters, digits, '-', '_' and '.'; 1..=63",
            );
        }
        if !names.insert(p.name.as_str()) {
            out.err(
                at("name"),
                p.id,
                "name",
                format!("pool '{}' exists twice", p.name),
            );
        }
        if p.ranges.is_empty() || p.ranges.len() > MAX_RANGES {
            out.err(
                at("ranges"),
                p.id,
                "ranges",
                format!("1..={MAX_RANGES} ranges"),
            );
        }
        if p.size() > MAX_POOL_SIZE {
            out.err(
                at("ranges"),
                p.id,
                "size",
                format!("{} addresses: at most {MAX_POOL_SIZE} per pool (split it, chain with next_pool)", p.size()),
            );
        }
        if let Some(n) = &p.next_pool
            && cfg.ip.pools.get(n).is_none()
        {
            out.err(at("next_pool"), p.id, "next-pool", format!("no pool '{n}'"));
        }
        for (net, iface) in &mine {
            if p.contains(net.addr()) {
                out.err(
                    at("ranges"),
                    p.id,
                    "pool ∩ router",
                    format!(
                        "includes {} (the router's address on '{iface}'): a client would get it",
                        net.addr()
                    ),
                );
            }
        }
        for q in pools.iter().skip(i + 1) {
            if let Some((a, b)) = overlap(p, q) {
                out.err(
                    at("ranges"),
                    p.id,
                    "overlap",
                    format!(
                        "{a} overlaps {b} of pool '{}': two servers would hand out one address",
                        q.name
                    ),
                );
            }
        }
    }
}

fn overlap(p: &IpPool, q: &IpPool) -> Option<(String, String)> {
    p.ranges.iter().find_map(|a| {
        q.ranges
            .iter()
            .find(|b| a.overlaps(b))
            .map(|b| (a.to_string(), b.to_string()))
    })
}

fn server_checks(cfg: &Config, out: &mut Out) {
    let d = &cfg.ip.dhcp_server;
    if d.servers.len() > MAX_SERVERS {
        out.err(
            "ip.dhcp_server.servers".into(),
            ItemId(0),
            "too many",
            format!("at most {MAX_SERVERS} servers"),
        );
    }
    let mine = router_addresses(cfg);
    let mut names = BTreeSet::new();
    let mut by_link: BTreeMap<(&IfName, Option<Ipv4Addr>), &str> = BTreeMap::new();
    for s in &d.servers {
        let at = |f: &str| format!("ip.dhcp_server.servers[{}].{f}", s.id);
        if !ip_pool::name_ok(&s.name) {
            out.err(
                at("name"),
                s.id,
                "name",
                "letters, digits, '-', '_' and '.'; 1..=63",
            );
        }
        if !names.insert(s.name.as_str()) {
            out.err(
                at("name"),
                s.id,
                "name",
                format!("server '{}' exists twice", s.name),
            );
        }
        match cfg.interfaces.get(&s.interface) {
            None => out.err(
                at("interface"),
                s.id,
                "interface",
                format!("interface '{}' does not exist", s.interface),
            ),
            Some(i) if matches!(i.kind, InterfaceKind::Vrf { .. }) => out.err(
                at("interface"),
                s.id,
                "interface",
                format!("'{}' is a VRF; serve on one of its members", s.interface),
            ),
            Some(i) => {
                if let Some(b) = &i.bridge {
                    out.err(
                        at("interface"),
                        s.id,
                        "interface",
                        format!(
                            "'{}' is a port of bridge '{b}'; serve on '{b}'",
                            s.interface
                        ),
                    );
                }
            }
        }
        if !s.disabled
            && let Some(other) = by_link.insert((&s.interface, s.relay), &s.name)
        {
            out.err(
                at("interface"),
                s.id,
                "interface",
                format!(
                    "server '{other}' already serves '{}'{}",
                    s.interface,
                    match s.relay {
                        Some(r) => format!(" for relay {r}"),
                        None => String::new(),
                    }
                ),
            );
        }
        if !(MIN_LEASE_TIME..=MAX_LEASE_TIME).contains(&s.lease_time) {
            out.err(
                at("lease_time"),
                s.id,
                "lease-time",
                format!("{MIN_LEASE_TIME}..={MAX_LEASE_TIME} seconds"),
            );
        }
        if let Some(p) = &s.address_pool
            && cfg.ip.pools.get(p).is_none()
        {
            out.err(
                at("address_pool"),
                s.id,
                "pool",
                format!("no pool '{p}' (ip.pool.add)"),
            );
        }
        if let Err(e) = set_ok(d, s.dhcp_option_set.as_ref()) {
            out.err(at("dhcp_option_set"), s.id, "option set", e);
        }
        if s.address_lists.len() > MAX_LIST {
            out.err(
                at("address_lists"),
                s.id,
                "lists",
                format!("at most {MAX_LIST} lists"),
            );
        }
        if s.client_mac_limit == Some(0) {
            out.err(
                at("client_mac_limit"),
                s.id,
                "mac limit",
                "at least 1 (or unset: unlimited)",
            );
        }
        if s.disabled {
            continue;
        }
        let on_link: Vec<Ipv4Net> = mine
            .iter()
            .filter(|(_, i)| **i == s.interface)
            .map(|(n, _)| *n)
            .collect();
        if s.relay.is_none() && on_link.is_empty() && s.server_address.is_none() {
            out.warn(
                at("interface"),
                s.id,
                "no address",
                format!(
                    "'{}' has no IPv4 address: the server cannot answer (ip.address.add)",
                    s.interface
                ),
            );
        }
        if let Some(why) = looks_like_wan(cfg, &s.interface) {
            out.warn(
                at("interface"),
                s.id,
                "WAN?",
                format!("{why}: a DHCP server there hands addresses to the provider's network"),
            );
        }
        if let Some(pool) = s.address_pool.as_deref().and_then(|p| cfg.ip.pools.get(p))
            && s.relay.is_none()
            && !on_link.is_empty()
        {
            let outside = pool.ranges.iter().find(|r| {
                !on_link
                    .iter()
                    .any(|n| n.contains(&r.start) && n.contains(&r.end))
            });
            if let Some(r) = outside {
                out.warn(
                    at("address_pool"),
                    s.id,
                    "pool ∉ link",
                    format!("{r} of pool '{}' is not on '{}' ({}): those clients get an address they cannot use", pool.name, s.interface,
                        on_link.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
                );
            }
        }
    }
}

fn network_checks(cfg: &Config, out: &mut Out) {
    let d = &cfg.ip.dhcp_server;
    if d.networks.len() > MAX_NETWORKS {
        out.err(
            "ip.dhcp_server.networks".into(),
            ItemId(0),
            "too many",
            format!("at most {MAX_NETWORKS} networks"),
        );
    }
    let mine = router_addresses(cfg);
    let mut seen = BTreeSet::new();
    for n in &d.networks {
        let at = |f: &str| format!("ip.dhcp_server.networks[{}].{f}", n.id);
        let net = n.address;
        if !seen.insert(net) {
            out.err(
                at("address"),
                n.id,
                "address",
                format!("network {net} exists twice"),
            );
        }
        if n.gateway.len() > MAX_LIST
            || n.dns_server.len() > MAX_LIST
            || n.ntp_server.len() > MAX_LIST
            || n.wins_server.len() > MAX_LIST
        {
            out.err(
                at("gateway"),
                n.id,
                "lists",
                format!("at most {MAX_LIST} addresses per list"),
            );
        }
        if n.boot_file_name.len() > 127 {
            out.err(
                at("boot_file_name"),
                n.id,
                "boot file",
                "at most 127 bytes (the 'file' field)",
            );
        }
        if n.domain.len() > 255 {
            out.err(at("domain"), n.id, "domain", "at most 255 characters");
        }
        if let Some(m) = n.netmask
            && m > 32
        {
            out.err(at("netmask"), n.id, "netmask", "0..=32");
        }
        if let Err(e) = options_ok(d, &n.dhcp_option) {
            out.err(at("dhcp_option"), n.id, "options", e);
        }
        if let Err(e) = set_ok(d, n.dhcp_option_set.as_ref()) {
            out.err(at("dhcp_option_set"), n.id, "option set", e);
        }
        if let Some(z) = &n.dns_zone {
            match cfg.ip.dns_zones.zone(z) {
                None => out.err(
                    at("dns_zone"),
                    n.id,
                    "DNS zone",
                    format!("no zone '{z}' (ip.dns.zone.add)"),
                ),
                Some(zone) if zone.ztype != ZoneType::Primary => {
                    out.err(
                        at("dns_zone"),
                        n.id,
                        "DNS zone",
                        format!("'{z}' is a secondary zone: leases go in a primary"),
                    );
                }
                Some(_) => out.ok(at("dns_zone"), n.id, "DNS", format!("leases named in {z}")),
            }
        }
        // Gateways: inside the network, and never handed out.
        for g in &n.gateway {
            if net.contains(g) {
                out.ok(
                    at("gateway"),
                    n.id,
                    "gateway",
                    format!("{g} is inside {net}"),
                );
            } else {
                out.warn(
                    at("gateway"),
                    n.id,
                    "gateway ∉ net",
                    format!("{g} is outside {net}: clients cannot reach it on the link"),
                );
            }
        }
        let pools: Vec<&IpPool> = cfg
            .ip
            .pools
            .pools
            .iter()
            .filter(|p| {
                p.ranges
                    .iter()
                    .any(|r| net.contains(&r.start) || net.contains(&r.end))
            })
            .collect();
        let mut clean = true;
        for p in &pools {
            for g in &n.gateway {
                if p.contains(*g) {
                    clean = false;
                    out.err(
                        at("gateway"),
                        n.id,
                        "pool ∩ gateway",
                        format!(
                            "pool '{}' includes the gateway {g}: a client would get it",
                            p.name
                        ),
                    );
                }
            }
            for (a, iface) in &mine {
                if net.contains(&a.addr()) && p.contains(a.addr()) {
                    clean = false;
                    out.err(
                        at("address"),
                        n.id,
                        "pool ∩ router",
                        format!(
                            "pool '{}' includes {} (the router on '{iface}')",
                            p.name,
                            a.addr()
                        ),
                    );
                }
            }
            if let Some(r) = p
                .ranges
                .iter()
                .find(|r| !(net.contains(&r.start) && net.contains(&r.end)))
            {
                clean = false;
                out.warn(
                    at("address"),
                    n.id,
                    "pool ∉ net",
                    format!("{r} of pool '{}' goes beyond {net}", p.name),
                );
            }
            if p.ranges.iter().any(|r| {
                r.contains(net.network()) || (net.prefix_len() < 31 && r.contains(net.broadcast()))
            }) {
                clean = false;
                out.err(
                    at("address"),
                    n.id,
                    "network/broadcast",
                    format!(
                        "pool '{}' includes {}'s network or broadcast address",
                        p.name, net
                    ),
                );
            }
        }
        if !pools.is_empty() && clean {
            let names: Vec<&str> = pools.iter().map(|p| p.name.as_str()).collect();
            out.ok(
                at("address"),
                n.id,
                "pool",
                format!("{} clear of gateway and router", names.join(", ")),
            );
        }
        let served = d
            .servers
            .iter()
            .filter(|s| !s.disabled)
            .any(|s| match s.relay {
                Some(r) => net.contains(&r),
                None => mine
                    .iter()
                    .any(|(a, i)| **i == s.interface && net.contains(&a.addr())),
            });
        if served {
            out.ok(
                at("address"),
                n.id,
                "served",
                format!("a server hands out {net}"),
            );
        } else {
            out.warn(
                at("address"),
                n.id,
                "no server",
                format!("no enabled server is on {net} (its interface needs an address in it)"),
            );
        }
        let wan = d
            .servers
            .iter()
            .filter(|s| !s.disabled && s.relay.is_none())
            .filter(|s| {
                mine.iter()
                    .any(|(a, i)| **i == s.interface && net.contains(&a.addr()))
            })
            .find_map(|s| looks_like_wan(cfg, &s.interface));
        match wan {
            Some(why) => out.warn(at("address"), n.id, "WAN?", why),
            None if served => out.ok(
                at("address"),
                n.id,
                "LAN",
                "the server's interface does not look like a WAN",
            ),
            None => {}
        }
    }
}

fn lease_checks(cfg: &Config, out: &mut Out) {
    let d = &cfg.ip.dhcp_server;
    if d.leases.len() > MAX_STATIC_LEASES {
        out.err(
            "ip.dhcp_server.leases".into(),
            ItemId(0),
            "too many",
            format!("at most {MAX_STATIC_LEASES} static leases"),
        );
    }
    let mine = router_addresses(cfg);
    let mut by_addr: BTreeMap<(Option<&str>, Ipv4Addr), ItemId> = BTreeMap::new();
    let mut by_client: BTreeMap<(Option<&str>, Vec<u8>), ItemId> = BTreeMap::new();
    for l in &d.leases {
        let at = |f: &str| format!("ip.dhcp_server.leases[{}].{f}", l.id);
        if let Some(s) = &l.server
            && d.server(s).is_none()
        {
            out.err(at("server"), l.id, "server", format!("no server '{s}'"));
        }
        if l.mac_address.is_none()
            && l.client_id.is_empty()
            && l.agent_circuit_id.is_empty()
            && l.agent_remote_id.is_empty()
        {
            out.err(
                at("mac_address"),
                l.id,
                "client",
                "a static lease needs a MAC or a client id (or an option 82 id)",
            );
        }
        for (field, v) in [
            ("agent_circuit_id", &l.agent_circuit_id),
            ("agent_remote_id", &l.agent_remote_id),
        ] {
            if !v.is_empty() && super::agent::parse(v).is_none() {
                out.err(
                    at(field),
                    l.id,
                    "option 82",
                    "text, or 0x… bytes; at most 255",
                );
            }
        }
        let cid = if l.client_id.is_empty() {
            None
        } else {
            match parse_client_id(&l.client_id) {
                Some(c) => Some(c),
                None => {
                    out.err(
                        at("client_id"),
                        l.id,
                        "client id",
                        "write it as RouterOS prints it (1:aa:bb:cc:dd:ee:ff) or 0x…",
                    );
                    None
                }
            }
        };
        if let Some(t) = l.lease_time
            && !(MIN_LEASE_TIME..=MAX_LEASE_TIME).contains(&t)
        {
            out.err(
                at("lease_time"),
                l.id,
                "lease-time",
                format!("{MIN_LEASE_TIME}..={MAX_LEASE_TIME} seconds"),
            );
        }
        if let Err(e) = options_ok(d, &l.dhcp_option) {
            out.err(at("dhcp_option"), l.id, "options", e);
        }
        if let Err(e) = set_ok(d, l.dhcp_option_set.as_ref()) {
            out.err(at("dhcp_option_set"), l.id, "option set", e);
        }
        if l.address_lists.len() > MAX_LIST {
            out.err(
                at("address_lists"),
                l.id,
                "lists",
                format!("at most {MAX_LIST} lists"),
            );
        }
        if l.host_name.len() > 63 || !crate::check_host_name(&l.host_name).is_ok() {
            out.err(
                at("host_name"),
                l.id,
                "host name",
                "a DNS label: letters, digits, '-'; at most 63",
            );
        }
        if let Some((_, iface)) = mine.iter().find(|(a, _)| a.addr() == l.address) {
            out.err(
                at("address"),
                l.id,
                "router",
                format!("{} is the router's address on '{iface}'", l.address),
            );
        }
        if l.disabled {
            continue;
        }
        let srv = l.server.as_deref();
        if let Some(other) = by_addr.insert((srv, l.address), l.id) {
            out.err(
                at("address"),
                l.id,
                "address",
                format!("{} is already static lease {other}", l.address),
            );
        }
        let key = cid.or_else(|| {
            l.mac_address.map(|m| {
                let mut k = vec![1u8];
                k.extend_from_slice(&m.0);
                k
            })
        });
        if let Some(k) = key
            && let Some(other) = by_client.insert((srv, k), l.id)
        {
            out.err(
                at("mac_address"),
                l.id,
                "client",
                format!("that client already has static lease {other}"),
            );
        }
        if d.network_of(l.address).is_none() {
            out.warn(
                at("address"),
                l.id,
                "no network",
                format!(
                    "no /ip dhcp-server network holds {}: the client gets no mask nor gateway",
                    l.address
                ),
            );
        }
    }
}

fn other_checks(cfg: &Config, out: &mut Out) {
    let d = &cfg.ip.dhcp_server;
    if d.options.len() > MAX_OPTIONS
        || d.option_sets.len() > MAX_OPTION_SETS
        || d.matchers.len() > MAX_MATCHERS
        || d.alerts.len() > MAX_ALERTS
    {
        out.err(
            "ip.dhcp_server".into(),
            ItemId(0),
            "too many",
            "too many options, option sets, matchers or alerts",
        );
    }
    let mut names = BTreeSet::new();
    for o in &d.options {
        let at = |f: &str| format!("ip.dhcp_server.options[{}].{f}", o.id);
        if !ip_pool::name_ok(&o.name) || !names.insert(o.name.as_str()) {
            out.err(
                at("name"),
                o.id,
                "name",
                format!(
                    "'{}': a unique name of letters, digits, '-', '_', '.'",
                    o.name
                ),
            );
        }
        if matches!(o.code, 0 | 255 | 53 | 54 | 51 | 58 | 59 | 61 | 82 | 52) {
            out.err(
                at("code"),
                o.id,
                "code",
                format!("option {} is the server's own", o.code),
            );
        }
        if let Err(e) = option_bytes(&o.value) {
            out.err(at("value"), o.id, "value", e);
        }
    }
    let mut sets = BTreeSet::new();
    for s in &d.option_sets {
        let at = |f: &str| format!("ip.dhcp_server.option_sets[{}].{f}", s.id);
        if !ip_pool::name_ok(&s.name) || !sets.insert(s.name.as_str()) {
            out.err(
                at("name"),
                s.id,
                "name",
                format!("'{}': a unique name", s.name),
            );
        }
        if let Err(e) = options_ok(d, &s.options) {
            out.err(at("options"), s.id, "options", e);
        }
    }
    let mut matchers = BTreeSet::new();
    for m in &d.matchers {
        let at = |f: &str| format!("ip.dhcp_server.matchers[{}].{f}", m.id);
        if !ip_pool::name_ok(&m.name) || !matchers.insert(m.name.as_str()) {
            out.err(
                at("name"),
                m.id,
                "name",
                format!("'{}': a unique name", m.name),
            );
        }
        if let Some(s) = &m.server
            && d.server(s).is_none()
        {
            out.err(at("server"), m.id, "server", format!("no server '{s}'"));
        }
        if let Err(e) = option_bytes(&m.value) {
            out.err(at("value"), m.id, "value", e);
        }
        if let Err(e) = set_ok(d, m.option_set.as_ref()) {
            out.err(at("option_set"), m.id, "option set", e);
        }
        if let Some(p) = &m.address_pool
            && cfg.ip.pools.get(p).is_none()
        {
            out.err(at("address_pool"), m.id, "pool", format!("no pool '{p}'"));
        }
        if m.option_set.is_none() && m.address_pool.is_none() {
            out.err(
                at("option_set"),
                m.id,
                "does nothing",
                "give it an option_set, an address_pool or both",
            );
        }
    }
    let mut watched = BTreeSet::new();
    for a in &d.alerts {
        let at = |f: &str| format!("ip.dhcp_server.alerts[{}].{f}", a.id);
        if !cfg.interfaces.contains_key(&a.interface) {
            out.err(
                at("interface"),
                a.id,
                "interface",
                format!("interface '{}' does not exist", a.interface),
            );
        }
        if !watched.insert(&a.interface) {
            out.err(
                at("interface"),
                a.id,
                "interface",
                format!("'{}' already has an alert", a.interface),
            );
        }
        if a.valid_server.len() > MAX_LIST {
            out.err(
                at("valid_server"),
                a.id,
                "valid servers",
                format!("at most {MAX_LIST}"),
            );
        }
        if a.alert_timeout < 60 {
            out.err(at("alert_timeout"), a.id, "timeout", "at least 60 seconds");
        }
    }
}

fn relay_checks(cfg: &Config, out: &mut Out) {
    use corerouter_model::dhcp_relay::{MAX_RELAYS, MAX_SERVERS as MAX_RELAY_SERVERS};
    let relays = &cfg.ip.dhcp_relays.relays;
    if relays.len() > MAX_RELAYS {
        out.err(
            "ip.dhcp_relays".into(),
            ItemId(0),
            "too many",
            format!("at most {MAX_RELAYS} relays"),
        );
    }
    let mine = router_addresses(cfg);
    let mut names = BTreeSet::new();
    let mut ifaces = BTreeSet::new();
    for r in relays {
        let at = |f: &str| format!("ip.dhcp_relays.relays[{}].{f}", r.id);
        if !ip_pool::name_ok(&r.name) || !names.insert(r.name.as_str()) {
            out.err(
                at("name"),
                r.id,
                "name",
                format!("'{}': a unique name", r.name),
            );
        }
        if !cfg.interfaces.contains_key(&r.interface) {
            out.err(
                at("interface"),
                r.id,
                "interface",
                format!("interface '{}' does not exist", r.interface),
            );
        }
        if r.dhcp_server.is_empty() || r.dhcp_server.len() > MAX_RELAY_SERVERS {
            out.err(
                at("dhcp_server"),
                r.id,
                "servers",
                format!("1..={MAX_RELAY_SERVERS} DHCP servers"),
            );
        }
        if r.relay_info_remote_id.len() > 64 {
            out.err(
                at("relay_info_remote_id"),
                r.id,
                "remote id",
                "at most 64 characters",
            );
        }
        if r.disabled {
            continue;
        }
        if !ifaces.insert(&r.interface) {
            out.err(
                at("interface"),
                r.id,
                "interface",
                format!("another relay already serves '{}'", r.interface),
            );
        }
        if let Some(s) = cfg
            .ip
            .dhcp_server
            .servers
            .iter()
            .find(|s| !s.disabled && s.interface == r.interface && s.relay.is_none())
        {
            out.err(
                at("interface"),
                r.id,
                "server here",
                format!(
                    "DHCP server '{}' already answers on '{}': a client would get two answers",
                    s.name, r.interface
                ),
            );
        }
        let on_link: Vec<_> = mine
            .iter()
            .filter(|(_, i)| **i == r.interface)
            .map(|(n, _)| *n)
            .collect();
        match r.local_address {
            Some(a) if !mine.iter().any(|(n, _)| n.addr() == a) => out.err(
                at("local_address"),
                r.id,
                "local address",
                format!("{a} is not one of the router's addresses"),
            ),
            None if on_link.is_empty() => out.warn(
                at("interface"),
                r.id,
                "no address",
                format!(
                    "'{}' has no IPv4 address to relay from (giaddr): set local_address or add one",
                    r.interface
                ),
            ),
            _ => {}
        }
        if r.dhcp_server
            .iter()
            .any(|s| on_link.iter().any(|n| n.contains(s)))
        {
            out.warn(
                at("dhcp_server"),
                r.id,
                "same link",
                "a server on the clients' own link hears them directly",
            );
        }
    }
}

/// Every check of the DHCP server's config (and of `/ip pool`).
pub fn checks(cfg: &Config) -> Vec<Check> {
    let mut out = Out(Vec::new());
    relay_checks(cfg, &mut out);
    pool_checks(cfg, &mut out);
    server_checks(cfg, &mut out);
    network_checks(cfg, &mut out);
    lease_checks(cfg, &mut out);
    other_checks(cfg, &mut out);
    ipoe_checks(cfg, &mut out);
    out.0
}

/// IPoE (G4.3f): the mistakes that leave subscribers without an address
/// or without the limits the operator meant.
fn ipoe_checks(cfg: &Config, out: &mut Out) {
    use corerouter_model::ipoe::{IpoeUnknown, UseRadius};
    use corerouter_model::ppp::PppService;
    use corerouter_model::radius::AaaService;
    let radius_dhcp = cfg
        .radius
        .servers
        .iter()
        .any(|r| !r.disabled && r.service.contains(&AaaService::Dhcp));
    let secrets = cfg
        .ppp
        .secrets
        .iter()
        .any(|x| !x.disabled && x.service == PppService::Ipoe);
    for s in &cfg.ip.dhcp_server.servers {
        let at = |f: &str| format!("ip.dhcp_server.servers[{}].{f}", s.id);
        if s.use_radius != UseRadius::No && !radius_dhcp {
            out.warn(
                at("use_radius"),
                s.id,
                "no RADIUS",
                "use_radius is on but no /radius server has service=dhcp: new clients wait for an answer that never comes",
            );
        }
        if s.authorizes()
            && s.use_radius != UseRadius::Yes
            && s.ipoe_unknown == IpoeUnknown::Reject
            && !secrets
        {
            out.warn(
                at("ipoe_unknown"),
                s.id,
                "nobody",
                "ipoe_unknown=reject and no ppp.secret with service=ipoe: no client gets an address",
            );
        }
        if s.authorizes()
            && s.relay.is_none()
            && !s.relay_info_trusted
            && s.ipoe_username.needs_agent()
        {
            out.warn(
                at("ipoe_username"),
                s.id,
                "option 82",
                format!(
                    "ipoe_username={} needs option 82, but clients on the link are not believed (relay_info_trusted=no): only relayed requests carry it",
                    s.ipoe_username
                ),
            );
        }
    }
    for l in &cfg.ip.dhcp_server.leases {
        if l.rate_limit.is_empty() {
            continue;
        }
        let on_ipoe = cfg
            .ip
            .dhcp_server
            .servers
            .iter()
            .filter(|s| l.server.as_ref().is_none_or(|n| *n == s.name))
            .any(|s| s.sessions());
        if !on_ipoe {
            out.warn(
                format!("ip.dhcp_server.leases[{}].rate_limit", l.id),
                l.id,
                "rate-limit",
                "rate_limit applies only on an ipoe server (ipoe=yes or use_radius): here it does nothing",
            );
        }
    }
}

/// The errors, as validation issues: the commit is refused while any exist.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    if cfg.ip.pools.is_empty() && cfg.ip.dhcp_server.is_empty() && cfg.ip.dhcp_relays.is_empty() {
        return Vec::new();
    }
    checks(cfg)
        .into_iter()
        .filter(|c| c.level == Level::Error)
        .map(|c| Issue::new(c.path, c.text))
        .collect()
}

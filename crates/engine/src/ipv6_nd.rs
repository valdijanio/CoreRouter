//! Router Advertisements (G3.9ha): which interfaces advertise, with what,
//! and why the others do not — computed from the running config, so the
//! daemon's sender, `ipv6.nd.list` and the GUI agree. Plus the sender's
//! counters, kept in the session (`Session::ext`), never saved.
//!
//! `interface=all` is conservative where RouterOS is not: it leaves out
//! every interface that looks like a WAN (a DHCPv6 client, Router
//! Advertisements accepted, a default route out of it), the PPPoE servers'
//! ports (the BNG answers its subscribers itself, `pppoe_bng6`), bridge
//! and bond ports, loopbacks, VRF devices, and interfaces with nothing to
//! advertise (RouterOS 7.23 started sending prefix-less RAs everywhere and
//! made every LAN host take it as the default router). An explicit entry
//! for one interface is the operator's choice: it advertises there and
//! carries the warning instead.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use corerouter_model::ipv6::{self, ra_mode};
use corerouter_model::ipv6_nd::{
    MAX_DNS, MAX_PREFIXES_PER_RA, ND_PREFERRED_LIMIT, ND_VALID_LIMIT, NdInterface, NdPrefix,
    default_preferred, default_valid, dns_lifetime,
};
use corerouter_model::{Config, IfName, InterfaceKind, ItemId};
use ipnet::{IpNet, Ipv6Net};

/// Where a prefix of an RA comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A global /64 address of the interface (RouterOS `advertise=yes`).
    Address(ItemId),
    /// `/ipv6 nd prefix`.
    Static(ItemId),
    /// An address of the interface taken from a DHCPv6-PD pool
    /// (`ip.address from_pool`): lifetimes follow the delegation, capped
    /// by RFC 9096 §3.4.
    Pool(ItemId),
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Address(_) => "address",
            Origin::Static(_) => "static",
            Origin::Pool(_) => "dhcp-pd",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPrefix {
    pub prefix: Ipv6Net,
    pub valid: u32,
    pub preferred: u32,
    pub on_link: bool,
    pub autonomous: bool,
    pub origin: Origin,
}

/// One interface that advertises.
#[derive(Debug, Clone, PartialEq)]
pub struct Advert {
    pub interface: IfName,
    /// The `/ipv6 nd` entry it follows (its own, or `all`).
    pub entry: NdInterface,
    pub prefixes: Vec<PlanPrefix>,
    /// RDNSS and DNSSL (RFC 8106), with `advertise_dns`.
    pub rdnss: Vec<Ipv6Addr>,
    pub dnssl: Vec<String>,
    pub dns_lifetime: u32,
    /// Why an explicit entry may be a mistake (it still advertises).
    pub warnings: Vec<String>,
}

impl Advert {
    /// Whether `other` says the same, but for the lifetimes of prefixes
    /// from DHCPv6-PD (they shrink every second; RFC 4861 §6.2.4's rapid
    /// re-advertising is for changed information, not for a clock).
    pub fn same_but_clock(&self, other: &Advert) -> bool {
        let strip = |a: &Advert| {
            let mut a = a.clone();
            for p in &mut a.prefixes {
                if matches!(p.origin, Origin::Pool(_)) {
                    (p.valid, p.preferred) = (0, 0);
                }
            }
            a
        };
        strip(self) == strip(other)
    }
}

/// What the plan needs besides the config: the prefixes DHCPv6-PD holds
/// now and the DNS servers it learned, on the session's clock.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Live {
    pub pools: Vec<crate::dhcp6_client::Pool>,
    pub now_ms: Option<u64>,
    pub peer_dns: Vec<Ipv6Addr>,
}

impl Live {
    pub fn of(s: &crate::Session, cfg: &Config) -> Self {
        Self {
            pools: s.pools(cfg),
            now_ms: s.dhcp.now_ms,
            peer_dns: s.dhcp6_peer_dns(),
        }
    }

    /// (valid, preferred) seconds left of pool `name`'s prefix, capped by
    /// RFC 9096 §3.4 (L-16: ND_VALID_LIMIT, ND_PREFERRED_LIMIT).
    fn left(&self, p: &crate::dhcp6_client::Pool) -> (u32, u32) {
        let (valid, preferred) = (p.valid.unwrap_or(0), p.preferred.unwrap_or(0));
        let left_valid = match (p.expires_ms, self.now_ms) {
            (Some(e), Some(now)) => u32::try_from(e.saturating_sub(now) / 1000).unwrap_or(u32::MAX),
            _ => valid,
        };
        // The preferred lifetime ends (valid - preferred) before the valid one.
        let left_pref = left_valid.saturating_sub(valid.saturating_sub(preferred));
        (left_valid.min(ND_VALID_LIMIT), left_pref.min(ND_PREFERRED_LIMIT))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub interface: IfName,
    pub entry: ItemId,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    pub adverts: Vec<Advert>,
    pub skipped: Vec<Skipped>,
}

impl Plan {
    pub fn advert(&self, name: &IfName) -> Option<&Advert> {
        self.adverts.iter().find(|a| &a.interface == name)
    }
}

/// What an interface looks like, computed once for every interface (the
/// lists are indexed by interface first: O(addresses + routes + entries),
/// not their product).
#[derive(Default)]
struct Facts<'a> {
    addresses: BTreeMap<&'a IfName, Vec<(ItemId, Ipv6Net)>>,
    /// Addresses from DHCPv6-PD pools, resolved: (address id, /64, valid, preferred).
    pooled: BTreeMap<&'a IfName, Vec<(ItemId, Ipv6Net, u32, u32)>>,
    /// Any global address of each interface (the router as RDNSS).
    own: BTreeMap<&'a IfName, Ipv6Addr>,
    statics: BTreeMap<&'a IfName, Vec<&'a NdPrefix>>,
    default_out: BTreeSet<IfName>,
    dhcp6: BTreeSet<&'a IfName>,
    pppoe: BTreeSet<&'a IfName>,
}

fn facts<'a>(cfg: &'a Config, live: &Live) -> Facts<'a> {
    let mut f = Facts::default();
    // Every IPv6 subnet, to find which interface a gateway address is on.
    let mut subnets: Vec<(Ipv6Net, &IfName)> = Vec::new();
    for a in cfg.ip.addresses.iter() {
        let IpNet::V6(net) = a.address else { continue };
        if a.disabled {
            continue;
        }
        if let Some(name) = &a.from_pool {
            let Some(pool) = live.pools.iter().find(|p| &p.name == name) else { continue };
            let Some(net) = pool.prefix.and_then(|pre| ipv6::from_pool(net, pre).ok()) else { continue };
            if net.prefix_len() == 64 {
                let (v, p) = live.left(pool);
                f.pooled.entry(&a.interface).or_default().push((a.id, net.trunc(), v, p));
            }
            f.own.entry(&a.interface).or_insert(net.addr());
            continue;
        }
        if is_global(&net) {
            f.own.entry(&a.interface).or_insert(net.addr());
        }
        subnets.push((net.trunc(), &a.interface));
        if net.prefix_len() == 64 && is_global(&net) {
            f.addresses
                .entry(&a.interface)
                .or_default()
                .push((a.id, net.trunc()));
        }
    }
    for p in &cfg.ipv6.nd.prefixes {
        f.statics.entry(&p.interface).or_default().push(p);
    }
    for r in cfg.ip.routes.iter() {
        let IpNet::V6(dst) = r.dst_address else { continue };
        if r.disabled || dst.prefix_len() != 0 {
            continue;
        }
        if let Some(i) = r.gateway.iface() {
            f.default_out.insert(i.clone());
        } else if let Some(std::net::IpAddr::V6(gw)) = r.gateway.address()
            && let Some((_, i)) = subnets.iter().find(|(n, _)| n.contains(&gw))
        {
            f.default_out.insert((*i).clone());
        }
    }
    f.dhcp6 = cfg
        .ipv6
        .dhcp_clients
        .iter()
        .filter(|c| !c.disabled)
        .map(|c| &c.interface)
        .collect();
    f.pppoe = cfg
        .ppp
        .pppoe_servers
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| &s.interface)
        .collect();
    f
}

fn is_global(net: &Ipv6Net) -> bool {
    let a = net.addr();
    !(a.is_unicast_link_local() || a.is_multicast() || a.is_loopback() || a.is_unspecified())
}

/// The prefixes `name` advertises: its global /64 addresses, replaced or
/// hidden by static entries for the same prefix, plus the other static
/// ones; at most [`MAX_PREFIXES_PER_RA`].
fn prefixes(f: &Facts<'_>, name: &IfName) -> Vec<PlanPrefix> {
    let statics = f.statics.get(name).map(Vec::as_slice).unwrap_or_default();
    let mut out: Vec<PlanPrefix> = Vec::new();
    for (id, net, valid, preferred) in f.pooled.get(name).map(Vec::as_slice).unwrap_or_default() {
        if statics.iter().any(|p| p.prefix == *net) || out.iter().any(|p| p.prefix == *net) {
            continue;
        }
        out.push(PlanPrefix {
            prefix: *net,
            valid: *valid,
            preferred: *preferred,
            on_link: true,
            autonomous: true,
            origin: Origin::Pool(*id),
        });
    }
    for (id, net) in f.addresses.get(name).map(Vec::as_slice).unwrap_or_default() {
        if statics.iter().any(|p| p.prefix == *net) || out.iter().any(|p| p.prefix == *net) {
            continue;
        }
        out.push(PlanPrefix {
            prefix: *net,
            valid: default_valid(),
            preferred: default_preferred(),
            on_link: true,
            autonomous: true,
            origin: Origin::Address(*id),
        });
    }
    for p in statics.iter().filter(|p| !p.disabled) {
        if out.iter().any(|o| o.prefix == p.prefix) {
            continue;
        }
        out.push(PlanPrefix {
            prefix: p.prefix,
            valid: p.valid_lifetime,
            preferred: p.preferred_lifetime.min(p.valid_lifetime),
            on_link: p.on_link,
            autonomous: p.autonomous,
            origin: Origin::Static(p.id),
        });
    }
    out.sort_by_key(|p| p.prefix);
    out.truncate(MAX_PREFIXES_PER_RA);
    out
}

/// Why `name` should not advertise under `interface=all` (or what to warn
/// about on an explicit entry), if anything.
fn wan_reason(cfg: &Config, f: &Facts<'_>, name: &IfName) -> Option<String> {
    if f.dhcp6.contains(name) {
        return Some("WAN: it runs a DHCPv6 client".into());
    }
    if ra_mode(cfg, name).0.accepts() {
        return Some("WAN: it accepts Router Advertisements (ipv6.settings)".into());
    }
    if f.default_out.contains(name) {
        return Some("WAN: the IPv6 default route leaves through it".into());
    }
    None
}

/// The RDNSS of `entry` on `name` (RFC 8106 §5.1): its own list; else
/// this router (an address of the interface) when it answers queries;
/// else the IPv6 servers of `/ip dns` and those DHCPv6 learned.
fn rdnss(cfg: &Config, live: &Live, f: &Facts<'_>, entry: &NdInterface, name: &IfName) -> Vec<Ipv6Addr> {
    if !entry.advertise_dns {
        return Vec::new();
    }
    if !entry.dns.is_empty() {
        return entry.dns.clone();
    }
    if cfg.ip.dns.allow_remote_requests
        && let Some(a) = f.own.get(name)
    {
        return vec![*a];
    }
    let mut out: Vec<Ipv6Addr> = Vec::new();
    let learned = live.peer_dns.iter().copied();
    for a in cfg.ip.dns.servers.iter().filter_map(|a| match a {
        IpAddr::V6(v) => Some(*v),
        IpAddr::V4(_) => None,
    }).chain(learned)
    {
        if !out.contains(&a) && out.len() < MAX_DNS {
            out.push(a);
        }
    }
    out
}

/// The interfaces that advertise and the ones left out, from `cfg` alone
/// (no DHCPv6-PD prefix, no learned DNS).
pub fn plan(cfg: &Config) -> Plan {
    plan_live(cfg, &Live::default())
}

/// The plan with what DHCPv6 holds now ([`Live::of`]).
pub fn plan_live(cfg: &Config, live: &Live) -> Plan {
    let mut out = Plan::default();
    let nd = &cfg.ipv6.nd;
    if nd.interfaces.iter().all(|e| e.disabled) {
        return out;
    }
    let f = facts(cfg, live);
    let explicit: BTreeMap<&IfName, &NdInterface> = nd
        .interfaces
        .iter()
        .filter(|e| !e.is_all())
        .map(|e| (&e.interface, e))
        .collect();
    let all = nd.interfaces.iter().find(|e| e.is_all() && !e.disabled);
    for (name, iface) in cfg.interfaces.iter() {
        let (entry, is_all) = match (explicit.get(name), all) {
            (Some(e), _) if e.disabled => continue,
            (Some(e), _) => (*e, false),
            (None, Some(a)) => (a, true),
            (None, None) => continue,
        };
        let skip = |reason: String| Skipped {
            interface: name.clone(),
            entry: entry.id,
            reason,
        };
        // Never: the interface cannot carry an RA of its own, or the BNG
        // owns the port.
        let never = if iface.disabled {
            Some("the interface is disabled")
        } else if matches!(iface.kind, InterfaceKind::Loopback | InterfaceKind::Vrf { .. }) {
            Some("loopback and VRF devices have no link")
        } else if iface.bridge.is_some() {
            Some("a bridge port: the bridge advertises")
        } else if iface.bond.is_some() {
            Some("a bond port: the bond advertises")
        } else if f.pppoe.contains(name) {
            Some("a PPPoE server port: the BNG advertises to each session")
        } else {
            None
        };
        if let Some(r) = never {
            out.skipped.push(skip(r.into()));
            continue;
        }
        let prefixes = prefixes(&f, name);
        let wan = wan_reason(cfg, &f, name);
        if is_all {
            if let Some(r) = wan {
                out.skipped.push(skip(r));
                continue;
            }
            if prefixes.is_empty() {
                out.skipped.push(skip(
                    "no prefix to advertise (no global /64 address, no ipv6.nd.prefix, no prefix from DHCPv6-PD yet)".into(),
                ));
                continue;
            }
        }
        let mut warnings: Vec<String> = wan.into_iter().collect();
        if prefixes.is_empty() && !entry.managed_address_configuration && entry.ra_lifetime > 0 {
            warnings.push(
                "no prefix: hosts take this router as default gateway but get no address".into(),
            );
        }
        let rdnss = rdnss(cfg, live, &f, entry, name);
        if entry.advertise_dns && rdnss.is_empty() {
            warnings.push(
                "advertise_dns: no IPv6 DNS server to announce (dns, ip.dns servers, or allow_remote_requests with a global address here)".into(),
            );
        }
        let dnssl = if entry.advertise_dns { entry.dnssl.clone() } else { Vec::new() };
        out.adverts.push(Advert {
            interface: name.clone(),
            entry: entry.clone(),
            prefixes,
            rdnss,
            dnssl,
            dns_lifetime: dns_lifetime(entry.ra_interval_max),
            warnings,
        });
    }
    out
}

/// What the sender did on one interface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdIfStatus {
    pub ra_sent: u64,
    pub rs_received: u64,
    /// Unix seconds of the last RA sent.
    pub last_ra: Option<u64>,
    pub error: Option<String>,
    /// The last disagreement with another router's RA (RFC 4861 §6.2.7).
    pub conflict: Option<String>,
}

/// The sender's state (`Session::ext`), written by the daemon.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NdStatus {
    /// The sender runs (`--backend linux`).
    pub running: bool,
    pub interfaces: BTreeMap<IfName, NdIfStatus>,
    /// Prefixes that left an RA and go out with lifetimes 0 a few more
    /// times (RFC 9096 §3.5), by interface.
    pub deprecated: BTreeMap<IfName, Vec<Ipv6Net>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::config::AddressEntry;
    use corerouter_model::ipv6_nd::{ALL, NdInterface};
    use corerouter_model::{Gateway, Interface, RouteEntry, RoutingTable};

    fn iface(name: &str) -> Interface {
        Interface {
            name: name.parse().unwrap(),
            kind: InterfaceKind::Ethernet,
            mtu: 1500,
            disabled: false,
            mac: None,
            comment: String::new(),
            bridge: None,
            vrf: None,
            bond: None,
            ethernet: Default::default(),
        }
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        for n in ["ether1", "ether2", "ether3"] {
            c.interfaces.insert(n.parse().unwrap(), iface(n));
        }
        let mut add = |a: &str, i: &str| {
            let id = c.ip.next_address_id();
            c.ip.addresses.push(AddressEntry {
                id,
                address: a.parse().unwrap(),
                interface: i.parse().unwrap(),
                disabled: false,
                comment: String::new(),
                from_pool: None,
            });
        };
        add("2001:db8:2::1/64", "ether2");
        add("2001:db8:3::1/64", "ether3");
        add("2001:db8:1::2/64", "ether1");
        c
    }

    fn all(c: &mut Config) {
        let id = c.ipv6.nd.next_id();
        c.ipv6.nd.interfaces.push(NdInterface::new(id, ALL.parse().unwrap()));
    }

    fn default_route(c: &mut Config, gw: &str) {
        let id = c.ip.next_route_id();
        c.ip.routes.push(RouteEntry {
            id,
            dst_address: "::/0".parse().unwrap(),
            gateway: gw.parse::<Gateway>().unwrap(),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
    }

    fn names(p: &Plan) -> Vec<String> {
        p.adverts.iter().map(|a| a.interface.to_string()).collect()
    }

    #[test]
    fn nothing_without_an_entry() {
        assert_eq!(plan(&cfg()), Plan::default());
    }

    #[test]
    fn all_skips_the_wan_and_the_bng() {
        let mut c = cfg();
        all(&mut c);
        assert_eq!(names(&plan(&c)), ["ether1", "ether2", "ether3"]);
        // ether1 gets the default route: it is the WAN now.
        default_route(&mut c, "2001:db8:1::1");
        // ether3 serves PPPoE.
        let srv: corerouter_model::ppp::PppoeServer =
            serde_json::from_value(serde_json::json!({"id": "*1", "interface": "ether3"})).unwrap();
        c.ppp.pppoe_servers.push(srv);
        let p = plan(&c);
        assert_eq!(names(&p), ["ether2"]);
        let why: Vec<(String, String)> = p
            .skipped
            .iter()
            .map(|s| (s.interface.to_string(), s.reason.clone()))
            .collect();
        assert!(why[0].0 == "ether1" && why[0].1.contains("default route"), "{why:?}");
        assert!(why[1].0 == "ether3" && why[1].1.contains("PPPoE"), "{why:?}");
    }

    #[test]
    fn all_skips_dhcp6_clients_and_prefixless_ports() {
        let mut c = cfg();
        all(&mut c);
        let id = c.ipv6.next_dhcp_client_id();
        c.ipv6.dhcp_clients.push(corerouter_model::Dhcp6Client::new(
            id,
            "ether1".parse().unwrap(),
            corerouter_model::Request6::Prefix,
        ));
        c.interfaces.insert("ether4".parse().unwrap(), iface("ether4"));
        let p = plan(&c);
        assert_eq!(names(&p), ["ether2", "ether3"]);
        assert!(p.skipped.iter().any(|s| s.interface.as_str() == "ether1" && s.reason.contains("DHCPv6")));
        assert!(p.skipped.iter().any(|s| s.interface.as_str() == "ether4" && s.reason.contains("no prefix")));
    }

    #[test]
    fn explicit_entry_advertises_with_a_warning() {
        let mut c = cfg();
        default_route(&mut c, "ether1");
        let id = c.ipv6.nd.next_id();
        c.ipv6.nd.interfaces.push(NdInterface::new(id, "ether1".parse().unwrap()));
        let p = plan(&c);
        assert_eq!(names(&p), ["ether1"]);
        assert!(p.adverts[0].warnings[0].contains("default route"));
        // Disabled explicit entry: nothing, even under `all`.
        all(&mut c);
        c.ipv6.nd.interfaces[0].disabled = true;
        assert_eq!(names(&plan(&c)), ["ether2", "ether3"]);
    }

    #[test]
    fn dhcp_pd_prefix_is_advertised_with_rfc_9096_lifetimes() {
        let mut c = cfg();
        let id = c.ip.next_address_id();
        c.ip.addresses.push(AddressEntry {
            id,
            address: "::1/64".parse().unwrap(),
            interface: "ether3".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: Some("pd".into()),
        });
        let nid = c.ipv6.nd.next_id();
        c.ipv6.nd.interfaces.push(NdInterface::new(nid, "ether3".parse().unwrap()));
        let mut live = Live {
            pools: vec![crate::dhcp6_client::Pool {
                name: "pd".into(),
                client: ItemId(1),
                interface: "ether1".parse().unwrap(),
                prefix: Some("2001:db8:100::/56".parse().unwrap()),
                expires_ms: Some(1_000_000 + 86_400_000),
                preferred: Some(3600 * 12),
                valid: Some(86_400),
            }],
            now_ms: Some(1_000_000),
            peer_dns: Vec::new(),
        };
        let p = plan_live(&c, &live);
        let got: Vec<(String, u32, u32, &str)> = p.adverts[0]
            .prefixes
            .iter()
            .map(|x| (x.prefix.to_string(), x.valid, x.preferred, x.origin.as_str()))
            .collect();
        // RFC 9096 §3.4: at most 5400/2700 s however long the delegation.
        assert!(got.contains(&("2001:db8:100::/64".into(), 5400, 2700, "dhcp-pd")), "{got:?}");
        // Near its end: what is left (preferred ends 12 h before valid).
        live.now_ms = Some(1_000_000 + 86_400_000 - 1_000_000);
        let p2 = plan_live(&c, &live);
        let pd = p2.adverts[0].prefixes.iter().find(|x| x.origin.as_str() == "dhcp-pd").unwrap();
        assert_eq!((pd.valid, pd.preferred), (1000, 0));
        assert!(p.adverts[0].same_but_clock(&p2.adverts[0]), "only the clock moved");
        // Without the prefix, nothing from the pool (and `plan` sees none).
        assert!(plan(&c).adverts[0].prefixes.iter().all(|x| x.origin.as_str() != "dhcp-pd"));
    }

    #[test]
    fn rdnss_comes_from_the_entry_the_router_or_ip_dns() {
        let mut c = cfg();
        let id = c.ipv6.nd.next_id();
        let mut e = NdInterface::new(id, "ether2".parse().unwrap());
        e.advertise_dns = true;
        e.dnssl = vec!["isp.example".into()];
        c.ipv6.nd.interfaces.push(e);
        // Nothing to announce: a warning.
        let p = plan(&c);
        assert!(p.adverts[0].rdnss.is_empty());
        assert!(p.adverts[0].warnings[0].contains("advertise_dns"));
        // `/ip dns` servers (IPv6 only) and the learned ones.
        c.ip.dns.servers = vec!["8.8.8.8".parse().unwrap(), "2001:4860:4860::8888".parse().unwrap()];
        let live = Live { peer_dns: vec!["2001:db8::53".parse().unwrap()], ..Live::default() };
        let p = plan_live(&c, &live);
        assert_eq!(p.adverts[0].rdnss, ["2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap(), "2001:db8::53".parse().unwrap()]);
        assert_eq!(p.adverts[0].dnssl, ["isp.example"]);
        // RFC 8106 §5.1: 3 × MaxRtrAdvInterval.
        assert_eq!(p.adverts[0].dns_lifetime, 1800);
        // The router answers queries: it announces itself.
        c.ip.dns.allow_remote_requests = true;
        assert_eq!(plan(&c).adverts[0].rdnss, ["2001:db8:2::1".parse::<Ipv6Addr>().unwrap()]);
        // Its own list wins.
        c.ipv6.nd.interfaces[0].dns = vec!["2001:db8::99".parse().unwrap()];
        assert_eq!(plan(&c).adverts[0].rdnss, ["2001:db8::99".parse::<Ipv6Addr>().unwrap()]);
    }

    #[test]
    fn static_prefix_replaces_or_hides_the_address_one() {
        let mut c = cfg();
        let id = c.ipv6.nd.next_id();
        c.ipv6.nd.interfaces.push(NdInterface::new(id, "ether2".parse().unwrap()));
        let p = plan(&c);
        assert_eq!(p.adverts[0].prefixes.len(), 1);
        assert_eq!(p.adverts[0].prefixes[0].origin.as_str(), "address");
        let pid = c.ipv6.nd.next_prefix_id();
        let mut s = NdPrefix::new(pid, "2001:db8:2::/64".parse().unwrap(), "ether2".parse().unwrap());
        s.valid_lifetime = 7200;
        s.preferred_lifetime = 3600;
        c.ipv6.nd.prefixes.push(s);
        let pid = c.ipv6.nd.next_prefix_id();
        let mut extra = NdPrefix::new(pid, "2001:db8:99::/64".parse().unwrap(), "ether2".parse().unwrap());
        extra.autonomous = false;
        c.ipv6.nd.prefixes.push(extra);
        let p = plan(&c);
        let got: Vec<(String, u32, bool, &str)> = p.adverts[0]
            .prefixes
            .iter()
            .map(|x| (x.prefix.to_string(), x.valid, x.autonomous, x.origin.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("2001:db8:2::/64".into(), 7200, true, "static"),
                ("2001:db8:99::/64".into(), 2_592_000, false, "static")
            ]
        );
        c.ipv6.nd.prefixes[0].disabled = true;
        let p = plan(&c);
        assert_eq!(p.adverts[0].prefixes.len(), 1);
        assert_eq!(p.adverts[0].prefixes[0].prefix.to_string(), "2001:db8:99::/64");
    }
}

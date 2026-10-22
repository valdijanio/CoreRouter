//! The DHCPv6 server and relay at run time (G4.2c): the pure server of
//! `proto-dhcp` ([`Server6`]) on the HAL's sockets, driven with the DHCPv4
//! server ([`Session::dhcp_server_poll`]). Effects, in order: the journal
//! (`journal-dhcp6-leases.log`, synced before any reply), the replies, then
//! what a binding means outside the server:
//!
//! - a delegated prefix gets a route via the client (or its relay), a
//!   dynamic route (flag D) the data plane runs through
//!   [`Session::effective`], like the DHCP client's;
//! - an address with a name gets its AAAA and PTR (G4.1c-3).
//!
//! The relay (`/ipv6 dhcp-relay`) wraps the client messages heard on its
//! interface in Relay-Forw (RFC 9915 §19) and sends them to its servers —
//! in memory when a server is the router itself — and unwraps their
//! Relay-Repl back to the client.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv6Addr};

use corerouter_hal::dhcp_server::{Dhcp6ServerPort, Dhcp6Uplink, Heard6};
use corerouter_model::{Gateway, IfName, ItemId, RouteEntry, RoutingTable};
use corerouter_proto_dhcp::server::{Level, Now};
use corerouter_proto_dhcp::server6::{
    Bound6, Effect6, IaKind, Plan6, Server6, relay_forward, relay_unwrap_reply,
};
use ipnet::{IpNet, Ipv6Net};
use serde_json::json;

use crate::Session;
use crate::dns_dynamic::LeaseName;

pub const JOURNAL: &str = "dhcp6-leases";
const RECV_BUDGET: usize = 256;
const RETRY_MS: u64 = 10_000;
const COMPACT_EVERY_SECS: u64 = 3600;
/// Ids of the routes to delegated prefixes: `0xDF000000 | n` (inside the
/// range `dhcp_client::is_dynamic` shows with flag D).
const ROUTE_BASE: u32 = 0xDF00_0000;
/// All_DHCP_Servers (RFC 9915 §7.1): where a relay without servers sends.
const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 1, 3);

#[derive(Default)]
struct Slot {
    port: Option<Box<dyn Dhcp6ServerPort>>,
    error: Option<String>,
    retry_at: u64,
}

/// A relay at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayPlan6 {
    name: String,
    interface: IfName,
    servers: Vec<Ipv6Addr>,
    link: Ipv6Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Relay6Counters {
    pub requests: u64,
    pub replies: u64,
    pub dropped: u64,
}

#[derive(Default)]
pub struct Dhcp6Runtime {
    core: Option<Server6>,
    revision: Option<u32>,
    slots: BTreeMap<IfName, Slot>,
    loaded: bool,
    appended: u64,
    compacted_at: u64,
    journal_error: Option<String>,
    dns: HashMap<Ipv6Net, (String, String)>,
    /// Routes to delegated prefixes.
    routes: BTreeMap<Ipv6Net, RouteEntry>,
    next_route: u32,
    relays: Vec<RelayPlan6>,
    /// The router's own IPv6 addresses (servers reached in memory).
    local: Vec<Ipv6Addr>,
    uplink: Option<Box<dyn Dhcp6Uplink>>,
    uplink_error: Option<String>,
    uplink_retry_at: u64,
    relay_counters: BTreeMap<String, Relay6Counters>,
}

/// A socket, for `ipv6.dhcp-server.print`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port6Status {
    pub interface: IfName,
    pub listening: bool,
    pub error: Option<String>,
}

fn route_comment(server: &str) -> String {
    format!("dhcpv6 delegated by {server}")
}

impl Session {
    /// The DHCPv6 server, if it has run.
    pub fn dhcp6_server(&self) -> Option<&Server6> {
        self.ext::<Dhcp6Runtime>().and_then(|r| r.core.as_ref())
    }

    pub(crate) fn dhcp6_server_mut(&mut self) -> Option<&mut Server6> {
        self.ext_mut::<Dhcp6Runtime>().and_then(|r| r.core.as_mut())
    }

    pub fn dhcp6_server_ports(&self) -> Vec<Port6Status> {
        self.ext::<Dhcp6Runtime>()
            .map(|r| {
                r.slots
                    .iter()
                    .map(|(i, s)| Port6Status {
                        interface: i.clone(),
                        listening: s.port.is_some(),
                        error: s.error.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn dhcp6_relay_counters(&self, name: &str) -> Option<Relay6Counters> {
        self.ext::<Dhcp6Runtime>()
            .and_then(|r| r.relay_counters.get(name).cloned())
    }

    pub fn dhcp6_uplink_error(&self) -> Option<String> {
        self.ext::<Dhcp6Runtime>().and_then(|r| r.uplink_error.clone())
    }

    /// The name a binding has in the DNS.
    pub fn dhcp6_dns(&self, net: &Ipv6Net) -> Option<(String, String)> {
        self.ext::<Dhcp6Runtime>().and_then(|r| r.dns.get(net).cloned())
    }

    /// Whether no delegated-prefix route is up (the data plane is the
    /// config's).
    pub(crate) fn dhcp6_server_quiet(&self) -> bool {
        self.ext::<Dhcp6Runtime>().is_none_or(|r| r.routes.is_empty())
    }

    /// Add the routes to delegated prefixes (those of servers still in
    /// `cfg`, not already a static route's).
    pub(crate) fn dhcp6_server_extend(&self, cfg: &corerouter_model::Config, out: &mut corerouter_model::Config) {
        let Some(rt) = self.ext::<Dhcp6Runtime>() else {
            return;
        };
        for r in rt.routes.values() {
            let live = cfg
                .ipv6
                .dhcp_server
                .servers
                .iter()
                .any(|s| !s.disabled && r.comment == route_comment(&s.name));
            let taken = out
                .ip
                .routes
                .iter()
                .any(|o| !o.disabled && o.dst_address == r.dst_address && o.distance == r.distance);
            if live && !taken {
                out.ip.routes.push(r.clone());
            }
        }
    }

    fn dhcp6_sync(&mut self, now: Now, fx: &mut Vec<Effect6>) {
        let rev = self.store().current_revision();
        let running = self.store().running();
        let empty = running.ipv6.dhcp_server.servers.is_empty() && running.ipv6.dhcp_server.relays.is_empty();
        let changed = self.ext::<Dhcp6Runtime>().is_none_or(|r| r.revision != Some(rev));
        if changed {
            let plan = Plan6::from_config(running);
            let relays: Vec<RelayPlan6> = running
                .ipv6
                .dhcp_server
                .relays
                .iter()
                .filter(|r| !r.disabled)
                .map(|r| {
                    let link = r.link_address.or_else(|| {
                        running.ip.addresses.iter().find_map(|a| match a.address {
                            IpNet::V6(n) if a.interface == r.interface && !n.addr().is_unicast_link_local() => Some(n.addr()),
                            _ => None,
                        })
                    });
                    RelayPlan6 {
                        name: r.name.clone(),
                        interface: r.interface.clone(),
                        servers: r.dhcp_server.clone(),
                        link: link.unwrap_or(Ipv6Addr::UNSPECIFIED),
                    }
                })
                .collect();
            let local: Vec<Ipv6Addr> = running
                .ip
                .addresses
                .iter()
                .filter_map(|a| match a.address {
                    IpNet::V6(n) => Some(n.addr()),
                    IpNet::V4(_) => None,
                })
                .collect();
            let journal = if self.ext::<Dhcp6Runtime>().is_none_or(|r| !r.loaded) && !running.ipv6.dhcp_server.servers.is_empty() {
                Some(self.storage_mut().load_journal(JOURNAL))
            } else {
                None
            };
            let Some(rt) = self.ext_mut::<Dhcp6Runtime>() else {
                return;
            };
            rt.revision = Some(rev);
            rt.relays = relays;
            rt.local = local;
            rt.relay_counters.retain(|n, _| rt.relays.iter().any(|r| r.name == *n));
            match rt.core.as_mut() {
                Some(core) => fx.extend(core.configure(plan)),
                None if empty => {}
                None => {
                    let mut core = Server6::new(plan);
                    match journal {
                        Some(Ok(Some(text))) => {
                            rt.appended = text.lines().count() as u64;
                            let bad = core.replay(text.lines());
                            if bad > 0 {
                                log::warn!("dhcpv6 server: {bad} unreadable journal lines skipped");
                            }
                        }
                        Some(Err(e)) => rt.journal_error = Some(e.to_string()),
                        _ => {}
                    }
                    rt.loaded = true;
                    rt.compacted_at = now.unix;
                    let plan = core.plan().clone();
                    fx.extend(core.configure(plan));
                    // Bindings from the journal: their routes and names.
                    for l in core.leases().iter().filter(|l| l.state == corerouter_proto_dhcp::server::leases::State::Bound) {
                        let srv = core.plan().servers.iter().find(|s| s.name == l.server);
                        fx.push(Effect6::Bound(Bound6 {
                            lease: l.clone(),
                            new: true,
                            dns: srv
                                .and_then(|s| s.zone.clone())
                                .filter(|_| l.kind == IaKind::Na && !l.host_name.is_empty())
                                .map(|z| (z, l.host_name.clone())),
                            ttl: corerouter_proto_dhcp::server::dns_ttl(l.lease_time),
                            distance: srv.map_or(1, |s| s.route_distance),
                        }));
                    }
                    rt.core = Some(core);
                }
            }
        }
        // Sockets: the servers' interfaces and the relays'.
        let mut wanted: Vec<IfName> = self
            .dhcp6_server()
            .map(|c| c.plan().servers.iter().filter(|s| s.relay.is_none()).map(|s| s.interface.clone()).collect())
            .unwrap_or_default();
        let (relay_ifaces, remote) = self
            .ext::<Dhcp6Runtime>()
            .map(|r| {
                (
                    r.relays.iter().map(|x| x.interface.clone()).collect::<Vec<_>>(),
                    r.relays
                        .iter()
                        .any(|x| x.servers.is_empty() || x.servers.iter().any(|s| !r.local.contains(s))),
                )
            })
            .unwrap_or_default();
        wanted.extend(relay_ifaces);
        wanted.sort();
        wanted.dedup();
        let mut open = Vec::new();
        let mut want_uplink = false;
        if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
            rt.slots.retain(|i, _| wanted.contains(i));
            for i in &wanted {
                let s = rt.slots.entry(i.clone()).or_default();
                if s.port.is_none() && s.retry_at <= now.ms {
                    open.push(i.clone());
                }
            }
            if !remote {
                rt.uplink = None;
                rt.uplink_error = None;
            }
            want_uplink = remote && rt.uplink.is_none() && rt.uplink_retry_at <= now.ms;
        }
        for i in open {
            let r = self.hal_mut().dhcp6_server_port(&i);
            if let Some(s) = self.ext_mut::<Dhcp6Runtime>().and_then(|rt| rt.slots.get_mut(&i)) {
                match r {
                    Ok(p) => {
                        s.port = Some(p);
                        s.error = None;
                    }
                    Err(e) => {
                        s.error = Some(e.to_string());
                        s.retry_at = now.ms + RETRY_MS;
                    }
                }
            }
        }
        if want_uplink {
            let r = self.hal_mut().dhcp6_relay_uplink();
            if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
                match r {
                    Ok(u) => rt.uplink = Some(u),
                    Err(e) => {
                        rt.uplink_error = Some(e.to_string());
                        rt.uplink_retry_at = now.ms + RETRY_MS;
                    }
                }
            }
        }
    }

    /// One round of the DHCPv6 server and relays. Returns whether anything
    /// was heard.
    pub(crate) fn dhcp6_server_poll(&mut self, now: Now) -> bool {
        let mut fx: Vec<Effect6> = Vec::new();
        self.dhcp6_sync(now, &mut fx);
        let Some(rt) = self.ext_mut::<Dhcp6Runtime>() else {
            return false;
        };
        let mut heard = false;
        let Dhcp6Runtime {
            core,
            slots,
            relays,
            local,
            uplink,
            relay_counters,
            ..
        } = rt;
        // To hand to the server: (interface, mac, src, bytes).
        let mut to_core: Vec<(IfName, [u8; 6], Ipv6Addr, Vec<u8>)> = Vec::new();
        for (iface, slot) in slots.iter_mut() {
            let Some(port) = slot.port.as_mut() else {
                continue;
            };
            port.tick(now.unix);
            let relay = relays.iter().find(|r| r.interface == *iface);
            for _ in 0..RECV_BUDGET {
                let h: Heard6 = match port.recv() {
                    Ok(Some(h)) => h,
                    Ok(None) => break,
                    Err(e) => {
                        slot.error = Some(e.to_string());
                        break;
                    }
                };
                heard = true;
                match relay {
                    None => to_core.push((iface.clone(), port.mac(), h.src, h.payload)),
                    Some(r) => {
                        let c = relay_counters.entry(r.name.clone()).or_default();
                        let Some(fwd) = relay_forward(r.link, h.src, iface.as_str().as_bytes(), &h.payload) else {
                            c.dropped += 1;
                            continue;
                        };
                        let servers = if r.servers.is_empty() { vec![ALL_DHCP_SERVERS] } else { r.servers.clone() };
                        for s in servers {
                            if local.contains(&s) {
                                // The router's own server, in memory: the
                                // relay's link-address stands for it.
                                to_core.push((iface.clone(), port.mac(), r.link, fwd.clone()));
                                c.requests += 1;
                            } else if let Some(u) = uplink.as_mut() {
                                match u.send(&fwd, s) {
                                    Ok(()) => c.requests += 1,
                                    Err(e) => {
                                        slot.error = Some(e.to_string());
                                        c.dropped += 1;
                                    }
                                }
                            } else {
                                c.dropped += 1;
                            }
                        }
                    }
                }
            }
        }
        let mut replies: Vec<Vec<u8>> = Vec::new();
        if let Some(u) = uplink.as_mut() {
            for _ in 0..RECV_BUDGET {
                match u.recv() {
                    Ok(Some(h)) => replies.push(h.payload),
                    Ok(None) | Err(_) => break,
                }
            }
        }
        heard |= !replies.is_empty();
        if let Some(core) = core.as_mut() {
            for (iface, mac, src, bytes) in to_core {
                fx.extend(core.handle(now, &iface, mac, src, &bytes));
            }
            fx.extend(core.tick(now));
        }
        for r in replies {
            self.dhcp6_relay_down(&r);
        }
        self.dhcp6_apply(now, fx);
        self.dhcp6_compact(now);
        heard
    }

    /// A Relay-Repl for one of our relays: to its client.
    fn dhcp6_relay_down(&mut self, bytes: &[u8]) {
        let Some(rt) = self.ext_mut::<Dhcp6Runtime>() else {
            return;
        };
        let Some((peer, id, inner)) = relay_unwrap_reply(bytes) else {
            return;
        };
        let iface = id.and_then(|i| String::from_utf8(i).ok());
        let Some(relay) = rt
            .relays
            .iter()
            .find(|r| iface.as_deref() == Some(r.interface.as_str()))
            .cloned()
        else {
            return;
        };
        let c = rt.relay_counters.entry(relay.name.clone()).or_default();
        match rt.slots.get_mut(&relay.interface).and_then(|s| s.port.as_mut()) {
            Some(p) => match p.send(&inner, peer, 546) {
                Ok(()) => c.replies += 1,
                Err(_) => c.dropped += 1,
            },
            None => c.dropped += 1,
        }
    }

    fn dhcp6_apply(&mut self, now: Now, fx: Vec<Effect6>) {
        if fx.is_empty() {
            return;
        }
        let mut text = String::new();
        let mut n = 0u64;
        for e in &fx {
            if let Effect6::Journal(r) = e
                && let Ok(line) = serde_json::to_string(r)
            {
                text.push_str(&line);
                text.push('\n');
                n += 1;
            }
        }
        if n > 0 {
            let r = self.storage_mut().append_journal(JOURNAL, &text);
            if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
                rt.appended += n;
                rt.journal_error = r.err().map(|e| e.to_string());
            }
        }
        let relay_links: Vec<Ipv6Addr> = self
            .ext::<Dhcp6Runtime>()
            .map(|r| r.relays.iter().map(|x| x.link).collect())
            .unwrap_or_default();
        let mut later = Vec::new();
        let mut down = Vec::new();
        if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
            for e in fx {
                match e {
                    Effect6::Send { payload, to, port: 547, .. } if relay_links.contains(&to) => down.push(payload),
                    Effect6::Send { interface, payload, to, port } => {
                        if let Some(slot) = rt.slots.get_mut(&interface)
                            && let Some(p) = slot.port.as_mut()
                            && let Err(err) = p.send(&payload, to, port)
                        {
                            slot.error = Some(format!("send: {err}"));
                        }
                    }
                    Effect6::Journal(_) => {}
                    other => later.push(other),
                }
            }
        }
        for d in down {
            self.dhcp6_relay_down(&d);
        }
        let mut routes_changed = false;
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        for e in later {
            match e {
                Effect6::Bound(b) => routes_changed |= self.dhcp6_bound(&b, now),
                Effect6::Gone(l) => {
                    if let Some((zone, host)) = self.ext_mut::<Dhcp6Runtime>().and_then(|r| r.dns.remove(&l.net)) {
                        let _ = self.dns_dynamic_release(&zone, &host, IpAddr::V6(l.net.addr()), now.unix);
                    }
                    if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
                        routes_changed |= rt.routes.remove(&l.net).is_some();
                    }
                }
                Effect6::Log { level, text } => {
                    let topics: &[&str] = match level {
                        Level::Info => &["dhcp", "info"],
                        Level::Warning => &["dhcp", "warning"],
                        Level::Critical => &["dhcp", "critical"],
                    };
                    self.log_event(topics, "dhcpv6-server", text, json!({}));
                }
                _ => {}
            }
        }
        if routes_changed {
            let after = self.effective(&running).into_owned();
            if before != after
                && let Err(e) = self.hal_mut().apply(&before, &after)
            {
                self.log_event(
                    &["dhcp", "warning"],
                    "dhcpv6-server",
                    format!("routes to delegated prefixes not applied: {e}"),
                    json!({}),
                );
            }
        }
    }

    /// Returns whether a route changed.
    fn dhcp6_bound(&mut self, b: &Bound6, now: Now) -> bool {
        let l = &b.lease;
        if l.kind == IaKind::Na {
            let had = self.ext::<Dhcp6Runtime>().and_then(|r| r.dns.get(&l.net).cloned());
            if had != b.dns {
                if let Some((zone, host)) = &had {
                    let _ = self.dns_dynamic_release(zone, host, IpAddr::V6(l.net.addr()), now.unix);
                }
                let mut ok = None;
                if let Some((zone, host)) = &b.dns {
                    let lease = LeaseName {
                        zone: zone.clone(),
                        host: host.clone(),
                        address: IpAddr::V6(l.net.addr()),
                        ttl_secs: b.ttl,
                        expires_unix: None,
                        source: format!("dhcpv6 {}", l.server),
                    };
                    match self.dns_dynamic_lease(&lease, now.unix) {
                        Ok(()) => ok = Some((zone.clone(), host.clone())),
                        Err(e) => self.log_event(&["dhcp", "warning"], "dhcpv6-server", format!("{}: not named: {e}", l.net), json!({})),
                    }
                }
                if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
                    match ok {
                        Some(n) => rt.dns.insert(l.net, n),
                        None => rt.dns.remove(&l.net),
                    };
                }
            }
            return false;
        }
        let Ok(iface) = l.interface.parse::<IfName>() else {
            return false;
        };
        let Some(rt) = self.ext_mut::<Dhcp6Runtime>() else {
            return false;
        };
        let gateway = Gateway::via(IpAddr::V6(l.via), iface);
        if rt.routes.get(&l.net).is_some_and(|r| r.gateway == gateway && r.distance == b.distance) {
            return false;
        }
        rt.next_route = (rt.next_route + 1) & 0x00ff_ffff;
        let id = ItemId(ROUTE_BASE | rt.next_route);
        rt.routes.insert(
            l.net,
            RouteEntry {
                id,
                dst_address: IpNet::V6(l.net),
                gateway,
                distance: b.distance.max(1),
                routing_table: RoutingTable::Main,
                disabled: false,
                comment: route_comment(&l.server),
            },
        );
        true
    }

    fn dhcp6_compact(&mut self, now: Now) {
        let due = self.ext::<Dhcp6Runtime>().is_some_and(|r| {
            let records = r.core.as_ref().map_or(0, |c| c.leases().len() as u64);
            r.loaded && r.appended > 0 && (r.appended > 2 * records + 1024 || now.unix >= r.compacted_at + COMPACT_EVERY_SECS)
        });
        if !due {
            return;
        }
        let Some(text) = self.dhcp6_server().map(|c| c.compact(now.unix)) else {
            return;
        };
        let lines = text.lines().count() as u64;
        let r = self.storage_mut().rewrite_journal(JOURNAL, &text);
        if let Some(rt) = self.ext_mut::<Dhcp6Runtime>() {
            rt.compacted_at = now.unix;
            match r {
                Ok(()) => rt.appended = lines,
                Err(e) => rt.journal_error = Some(e.to_string()),
            }
        }
    }

    /// The operator ends a binding.
    pub(crate) fn dhcp6_release(&mut self, net: &Ipv6Net) -> Result<(), String> {
        let now = self.dhcp_server_clock();
        let fx = self
            .dhcp6_server_mut()
            .ok_or_else(|| format!("no binding for {net}"))?
            .release(net, now)?;
        self.dhcp6_apply(now, fx);
        Ok(())
    }
}

//! DHCP clients at run time (G4.7): one state machine
//! ([`corerouter_proto_dhcp::client::Client`]) per enabled client of the
//! running config, on the socket the HAL opens for its interface, driven by
//! [`Session::dhcp_service`] (the app calls it a few times a second with a
//! monotonic clock; the engine has none).
//!
//! What a lease brings — the address and the routes — is operational state,
//! like RouterOS' dynamic entries: never in the config, never saved, shown
//! with flag `D` by `ip.address.list` / `ip.route.list`. The data plane gets
//! it through the one `Hal::apply` path: the HAL always sees the config plus
//! these entries ([`Session::effective`]), so commits and leases cannot undo
//! each other.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::dhcp::DhcpPort;
use corerouter_model::dhcp_client::{self, AddDefaultRoute, AllowedServer};
use corerouter_model::route::{self, table_of};
use corerouter_model::{
    AddressEntry, Config, DhcpClient, Gateway, IfName, ItemId, RouteEntry, RoutingTable,
};
use corerouter_proto_dhcp::client::{Action, Client, Event, Lease, State};
use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;
use serde_json::{Value, json};

use crate::Session;

/// Events kept for `ip.dhcp-client.history` (a ring; **estimado**).
pub const MAX_HISTORY: usize = 512;
/// Datagrams read per client per service call (a flood cannot stall it).
const RECV_BUDGET: usize = 32;
/// Send/receive rounds per service call: the lab answers at once, so a
/// whole DISCOVER…ACK exchange fits in one call there.
const ROUNDS: usize = 6;
/// Retry opening a socket that failed (interface missing in the kernel…).
const PORT_RETRY_MS: u64 = 10_000;
/// Ids of dynamic addresses and routes: `0xDC000000 | client << 8 | n`.
pub const DYN_BASE: u32 = 0xDC00_0000;

pub(crate) fn dyn_id(client: ItemId, n: usize) -> ItemId {
    let n = u32::try_from(n).unwrap_or(0xFF) & 0xFF;
    ItemId(DYN_BASE | ((client.0 & 0x3_FFFF) << 8) | n)
}

/// Whether `id` names an address or route a DHCP client installed (v4 or
/// v6) or the kernel learned from Router Advertisements.
pub fn is_dynamic(id: ItemId) -> bool {
    id.0 & 0xFC00_0000 == DYN_BASE
        || crate::dhcp6_client::is_dynamic6(id)
        || crate::dhcp6_client::is_learned(id)
}

/// One line of the history.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub seq: u64,
    /// Session clock (Unix seconds), when known.
    pub time: Option<u64>,
    pub client: ItemId,
    pub interface: IfName,
    pub event: &'static str,
    pub message: String,
}

/// A client of the running config, at run time.
pub(crate) struct Runner {
    /// The config it runs with (compared each service call).
    pub cfg: DhcpClient,
    pub(crate) port: Option<Box<dyn DhcpPort>>,
    pub client: Option<Client>,
    /// Why it cannot run (no socket, bad option): status `error`.
    pub error: Option<String>,
    retry_at: u64,
    /// What it installed.
    pub addresses: Vec<AddressEntry>,
    pub routes: Vec<RouteEntry>,
    /// Lease routes that could not be installed, and why.
    pub notes: Vec<String>,
    /// The fallback address while it is up (G4.7c).
    pub fallback: Option<AddressEntry>,
    /// Since when the client has had no lease.
    pub(crate) searching_since: Option<u64>,
    pub(crate) gw: crate::dhcp_resilience::GatewayCheck,
}

impl Runner {
    pub fn lease(&self) -> Option<&Lease> {
        self.client.as_ref().and_then(Client::lease)
    }

    pub fn state(&self) -> State {
        self.client.as_ref().map_or(State::Stopped, Client::state)
    }

    /// Carry out the actions that only need the socket; return the rest
    /// (bind, unbind, log) for the session.
    fn perform(&mut self, actions: Vec<Action>, out: &mut Vec<Action>) {
        for a in actions {
            match a {
                Action::Send { payload, src, dest } => {
                    let sent = match self.port.as_mut() {
                        Some(p) => p.send(&payload, src, dest).map_err(|e| e.to_string()),
                        None => Err("no socket".into()),
                    };
                    if let Err(e) = sent {
                        out.push(Action::Log(Event::Error(format!("send failed: {e}"))));
                    }
                }
                Action::Probe(ip) => {
                    if let Some(p) = self.port.as_mut()
                        && let Err(e) = p.probe(ip)
                    {
                        log::debug!("dhcp-client: ARP probe of {ip} not sent: {e}");
                    }
                }
                Action::EndProbe => {
                    if let Some(p) = self.port.as_mut() {
                        p.end_probe();
                    }
                }
                other => out.push(other),
            }
        }
    }

    /// Feed the socket's datagrams and the timers to the state machine.
    fn step(&mut self, now: u64) -> Vec<Action> {
        let mut out = Vec::new();
        for _ in 0..ROUNDS {
            let (Some(port), Some(client)) = (self.port.as_mut(), self.client.as_mut()) else {
                break;
            };
            let mut actions = Vec::new();
            let mut heard = false;
            for _ in 0..RECV_BUDGET {
                match port.recv() {
                    Ok(Some(d)) => {
                        heard = true;
                        actions.extend(client.input(now, &d));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("dhcp-client {}: recv: {e}", self.cfg.interface);
                        break;
                    }
                }
            }
            if client.state() == State::Probing {
                match port.conflict() {
                    Ok(Some(by)) => actions.extend(client.conflict(now, by)),
                    Ok(None) => {}
                    Err(e) => log::debug!("dhcp-client {}: arp: {e}", self.cfg.interface),
                }
            }
            actions.extend(client.poll(now));
            let busy = heard || !actions.is_empty();
            self.perform(actions, &mut out);
            if !busy {
                break;
            }
        }
        out
    }
}

/// The session's DHCP clients at run time.
#[derive(Default)]
pub struct DhcpRuntime {
    pub(crate) runners: BTreeMap<ItemId, Runner>,
    history: VecDeque<HistoryEntry>,
    seq: u64,
    /// Last time given to [`Session::dhcp_service`].
    pub(crate) now_ms: Option<u64>,
    /// Leases kept across restarts (G4.7c), by client.
    pub(crate) remembered: BTreeMap<ItemId, crate::dhcp_resilience::Remembered>,
    /// Whether `remembered` was read from the storage.
    pub(crate) loaded: bool,
}

impl DhcpRuntime {
    pub fn history(&self) -> impl Iterator<Item = &HistoryEntry> {
        self.history.iter()
    }

    pub(crate) fn runner(&self, id: ItemId) -> Option<&Runner> {
        self.runners.get(&id)
    }

    /// Dynamic addresses of every client.
    pub fn addresses(&self) -> impl Iterator<Item = (ItemId, &AddressEntry)> {
        self.runners.iter().flat_map(|(id, r)| {
            r.addresses
                .iter()
                .chain(r.fallback.iter())
                .map(move |a| (*id, a))
        })
    }
}

fn allow(list: Vec<AllowedServer>) -> impl Fn(&[Ipv4Addr], Option<[u8; 6]>) -> bool + Send {
    move |ips, mac| dhcp_client::allows(&list, ips, mac)
}

/// The routing table a client's routes go to.
pub fn table_for(cfg: &Config, c: &DhcpClient) -> RoutingTable {
    c.default_route_table
        .clone()
        .unwrap_or_else(|| table_of(cfg, &c.interface))
}

/// Address and routes `lease` brings for client `c`, and notes on the
/// routes left out (RouterOS rules, see `docs/dhcp-client.md` §3).
pub fn lease_entries(
    cfg: &Config,
    c: &DhcpClient,
    lease: &Lease,
) -> (AddressEntry, Vec<RouteEntry>, Vec<String>) {
    let address = AddressEntry {
        id: dyn_id(c.id, 0),
        address: IpNet::V4(lease.address),
        interface: c.interface.clone(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    };
    let mut wanted: Vec<(Ipv4Net, Ipv4Addr)> = Vec::new();
    let classless = !lease.classless.is_empty();
    match c.add_default_route {
        AddDefaultRoute::No => {}
        AddDefaultRoute::Yes | AddDefaultRoute::SpecialClassless => {
            wanted.extend(lease.classless.iter().copied());
            let router_too = c.add_default_route == AddDefaultRoute::SpecialClassless || !classless;
            if router_too && let Some(gw) = lease.gateway() {
                wanted.push((Ipv4Net::default(), gw));
            }
        }
    }
    let table = table_for(cfg, c);
    let mut routes: Vec<RouteEntry> = Vec::new();
    let mut notes = Vec::new();
    for (dst, gw) in wanted {
        let dst = dst.trunc();
        if routes.iter().any(|r| r.dst_address == IpNet::V4(dst)) {
            notes.push(format!(
                "{dst} via {gw}: the lease already routes {dst} (option 121 wins over option 3)"
            ));
            continue;
        }
        let gateway = if gw.is_unspecified() {
            // RFC 3442: router 0.0.0.0 = the destination is on the link.
            Gateway::interface(c.interface.clone())
        } else if lease.address.contains(&gw) && gw != lease.address.addr() {
            Gateway::via(IpAddr::V4(gw), c.interface.clone())
        } else {
            notes.push(format!(
                "{dst} via {gw}: the gateway is not in {}; not installed",
                lease.address.trunc()
            ));
            continue;
        };
        routes.push(RouteEntry {
            id: dyn_id(c.id, routes.len().saturating_add(1)),
            dst_address: IpNet::V4(dst),
            gateway,
            distance: c.default_route_distance.max(1),
            routing_table: table.clone(),
            disabled: false,
            comment: String::new(),
        });
    }
    (address, routes, notes)
}

/// `1d2h3m4s`, RouterOS style.
pub fn duration_text(secs: u64) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let (d, h, m, s) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    for (n, unit) in [(d, "d"), (h, "h"), (m, "m"), (s, "s")] {
        if n > 0 {
            out.push_str(&format!("{n}{unit}"));
        }
    }
    out
}

fn mac_text(mac: [u8; 6]) -> String {
    corerouter_model::MacAddr(mac).to_string()
}

/// History kind and text of an event.
fn describe(e: &Event) -> (&'static str, String) {
    match e {
        Event::Rebooting { address } => (
            "rebooting",
            format!("asking to keep the remembered lease {address} (INIT-REBOOT)"),
        ),
        Event::Reused { address, server } => (
            "bound",
            format!(
                "no server answered: using the remembered lease {address} from {server} while it lasts"
            ),
        ),
        Event::Searching => ("searching", "searching for a DHCP server".into()),
        Event::Offered { server, address } => ("offered", format!("{address} offered by {server}")),
        Event::Bound {
            address,
            server,
            lease_secs,
        } => (
            "bound",
            format!(
                "got {address} from {server}, lease {}",
                lease_text(*lease_secs)
            ),
        ),
        Event::Renewed {
            address,
            server,
            lease_secs,
        } => (
            "renewed",
            format!(
                "{address} renewed by {server}, lease {}",
                lease_text(*lease_secs)
            ),
        ),
        Event::Lost { address, reason } => ("lost", format!("{address} lost: {reason}")),
        Event::Nak { server, message } => (
            "nak",
            match message {
                Some(m) => format!("{server} said NAK: {m}"),
                None => format!("{server} said NAK"),
            },
        ),
        Event::Refused { server, mac } => (
            "refused",
            match mac {
                Some(m) => format!(
                    "ignored server {server} ({}): not in allowed-servers",
                    mac_text(*m)
                ),
                None => format!("ignored server {server}: not in allowed-servers"),
            },
        ),
        Event::Declined { address, by } => (
            "declined",
            format!(
                "{address} is already used by {}; DECLINE sent",
                mac_text(*by)
            ),
        ),
        Event::Ignored { server, why } => {
            ("ignored", format!("answer from {server} ignored: {why}"))
        }
        Event::Error(e) => ("error", e.clone()),
    }
}

fn lease_text(secs: u32) -> String {
    if secs == u32::MAX {
        "infinite".into()
    } else {
        duration_text(u64::from(secs))
    }
}

impl Session {
    /// `cfg` plus the addresses and routes the DHCP clients installed: what
    /// the data plane runs. Entries of clients that `cfg` no longer has (or
    /// has disabled) are left out, and so is a route a static route already
    /// holds (same table, destination and distance: the kernel takes one).
    pub(crate) fn effective<'a>(&self, cfg: &'a Config) -> Cow<'a, Config> {
        let v4_quiet = self
            .dhcp
            .runners
            .values()
            .all(|r| r.addresses.is_empty() && r.routes.is_empty() && r.fallback.is_none());
        if v4_quiet && self.dhcp6_quiet(cfg) {
            return Cow::Borrowed(cfg);
        }
        let mut out = cfg.clone();
        for (id, r) in &self.dhcp.runners {
            let live = cfg
                .ip
                .dhcp_clients
                .iter()
                .any(|c| c.id == *id && !c.disabled && c.interface == r.cfg.interface);
            if !live {
                continue;
            }
            out.ip.addresses.extend(r.addresses.iter().cloned());
            out.ip.addresses.extend(r.fallback.iter().cloned());
            for route in r.routes.iter().filter(|rt| !r.withholds(rt)) {
                let taken = out.ip.routes.iter().any(|o| {
                    !o.disabled
                        && o.routing_table == route.routing_table
                        && o.dst_address == route.dst_address
                        && o.distance == route.distance
                });
                if !taken {
                    out.ip.routes.push(route.clone());
                }
            }
        }
        // DHCPv6 (G4.7b): leases, and the addresses taken from pools.
        self.dhcp6_extend(cfg, &mut out);
        Cow::Owned(out)
    }

    /// Drive the DHCP clients: start and stop them as the running config
    /// says, read their sockets, fire their timers, install and remove
    /// leases. `now_ms`: a monotonic clock in milliseconds. The daemon and
    /// the native GUI call it a few times a second (`control::spawn_clock`).
    pub fn dhcp_service(&mut self, now_ms: u64) {
        self.dhcp.now_ms = Some(now_ms);
        self.dhcp_load_leases();
        self.dhcp_reconcile(now_ms);
        let ids: Vec<ItemId> = self.dhcp.runners.keys().copied().collect();
        for id in ids {
            let actions = match self.dhcp.runners.get_mut(&id) {
                Some(r) => r.step(now_ms),
                None => continue,
            };
            self.dhcp_after(id, actions);
            self.dhcp_resilience(id, now_ms);
        }
        // The DHCPv6 clients (G4.7b) run on the same clock.
        self.dhcp6_service(now_ms);
    }

    /// Apply what a state machine asked for (bind, unbind, log).
    pub(crate) fn dhcp_after(&mut self, id: ItemId, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Bind(lease) => {
                    self.dhcp_install(id, Some(&lease));
                    self.dhcp_remember(id, &lease);
                }
                Action::Unbind => self.dhcp_install(id, None),
                Action::Log(e) => {
                    // A NAK says the remembered address is not ours.
                    if matches!(e, Event::Nak { .. }) {
                        self.dhcp_forget(id);
                    }
                    self.dhcp_log(id, &e);
                }
                // Socket actions were done by the runner.
                Action::Send { .. } | Action::Probe(_) | Action::EndProbe => {}
            }
        }
    }

    fn dhcp_log(&mut self, id: ItemId, e: &Event) {
        let Some(iface) = self.dhcp.runners.get(&id).map(|r| r.cfg.interface.clone()) else {
            return;
        };
        let (event, message) = describe(e);
        self.dhcp_note(id, iface, event, message);
    }

    pub(crate) fn dhcp_note(
        &mut self,
        id: ItemId,
        interface: IfName,
        event: &'static str,
        message: String,
    ) {
        match event {
            "error" | "refused" | "declined" | "nak" | "lost" | "gateway" | "fallback" => {
                log::warn!("dhcp-client {id} on {interface}: {message}");
            }
            "searching" | "offered" => log::debug!("dhcp-client {id} on {interface}: {message}"),
            _ => log::info!("dhcp-client {id} on {interface}: {message}"),
        }
        let (topics, text, detail) = crate::logging::dhcp_event(
            false,
            &id.to_string(),
            interface.as_str(),
            event,
            &message,
        );
        self.log_event(&topics, crate::logging::DAEMON, text, detail);
        self.dhcp.seq = self.dhcp.seq.saturating_add(1);
        let time = self.now();
        self.dhcp.history.push_back(HistoryEntry {
            seq: self.dhcp.seq,
            time,
            client: id,
            interface,
            event,
            message,
        });
        while self.dhcp.history.len() > MAX_HISTORY {
            self.dhcp.history.pop_front();
        }
    }

    /// Install `lease` for client `id` (`None`: remove what it installed),
    /// through `Hal::apply` on the running config.
    fn dhcp_install(&mut self, id: ItemId, lease: Option<&Lease>) {
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        let Some(r) = self.dhcp.runners.get_mut(&id) else {
            return;
        };
        let old = (
            std::mem::take(&mut r.addresses),
            std::mem::take(&mut r.routes),
            std::mem::take(&mut r.notes),
        );
        let old_fallback = r.fallback.clone();
        let old_gw_down = r.gw.down;
        // A lease replaces the fallback address in the same apply; a stop
        // takes it away too.
        r.fallback = None;
        if lease.is_some() {
            r.searching_since = None;
            r.gw.new_lease();
        } else {
            r.gw = crate::dhcp_resilience::GatewayCheck::default();
        }
        if let Some(l) = lease {
            let (a, routes, notes) = lease_entries(&running, &r.cfg, l);
            r.addresses = vec![a];
            r.routes = routes;
            r.notes = notes.clone();
            for n in notes {
                log::warn!("dhcp-client {id}: {n}");
            }
        }
        let after = self.effective(&running).into_owned();
        if before == after {
            return;
        }
        if let Err(e) = self.hal_mut().apply(&before, &after) {
            let msg = format!("lease not applied: {e}");
            if let Some(r) = self.dhcp.runners.get_mut(&id) {
                (r.addresses, r.routes, r.notes) = old;
                r.fallback = old_fallback;
                r.gw.down = old_gw_down;
                r.error = Some(msg.clone());
            }
            self.dhcp_log(id, &Event::Error(msg));
        } else if let Some(r) = self.dhcp.runners.get_mut(&id)
            && r.error
                .as_deref()
                .is_some_and(|e| e.starts_with("lease not applied"))
        {
            r.error = None;
        }
    }

    /// Make the runners match the running config.
    fn dhcp_reconcile(&mut self, now: u64) {
        let running = self.store().running();
        let identity = running.system.identity.clone();
        let wanted: Vec<DhcpClient> = running
            .ip
            .dhcp_clients
            .iter()
            .filter(|c| !c.disabled && route::is_up(running, &c.interface))
            .cloned()
            .collect();
        let gone: Vec<(ItemId, String)> = self
            .dhcp
            .runners
            .iter()
            .filter_map(|(id, r)| {
                let now_cfg = running.ip.dhcp_clients.iter().find(|c| c.id == *id);
                let why = match now_cfg {
                    None => "client removed",
                    Some(c) if c.disabled => "client disabled",
                    Some(c) if c.interface != r.cfg.interface => {
                        "client moved to another interface"
                    }
                    Some(_) if !wanted.iter().any(|w| w.id == *id) => {
                        "interface disabled or removed"
                    }
                    Some(_) => return None,
                };
                Some((*id, why.to_owned()))
            })
            .collect();
        for (id, why) in gone {
            if why == "client removed" {
                self.dhcp_forget(id);
            }
            let actions = self
                .dhcp
                .runners
                .get_mut(&id)
                .and_then(|r| r.client.as_mut())
                .map(|c| c.stop(&why))
                .unwrap_or_default();
            // Log first (the runner names the interface), then remove what
            // it installed, then the runner.
            for a in &actions {
                if let Action::Log(e) = a {
                    self.dhcp_log(id, e);
                }
            }
            self.dhcp_install(id, None);
            if let Some(mut r) = self.dhcp.runners.remove(&id) {
                if let Some(p) = r.port.as_mut() {
                    p.end_probe();
                }
                let iface = r.cfg.interface.clone();
                self.dhcp_note(id, iface, "stopped", why);
            }
        }
        for c in wanted {
            match self.dhcp.runners.get(&c.id) {
                None => self.dhcp_start(c, &identity, now),
                Some(r) if r.port.is_none() && now >= r.retry_at => {
                    self.dhcp_start(c, &identity, now)
                }
                Some(r) if r.cfg != c => self.dhcp_update(c, &identity),
                Some(_) => {}
            }
        }
    }

    fn dhcp_start(&mut self, c: DhcpClient, identity: &str, now: u64) {
        let id = c.id;
        let port = self.hal_mut().dhcp_port(&c.interface);
        let mut r = Runner {
            cfg: c.clone(),
            port: None,
            client: None,
            error: None,
            retry_at: now.saturating_add(PORT_RETRY_MS),
            addresses: Vec::new(),
            routes: Vec::new(),
            notes: Vec::new(),
            fallback: None,
            searching_since: Some(now),
            gw: crate::dhcp_resilience::GatewayCheck::default(),
        };
        let started = match port {
            Err(e) => Err(format!(
                "cannot open a DHCP socket on '{}': {e}",
                c.interface
            )),
            Ok(p) => {
                let mac = p.mac();
                r.port = Some(p);
                corerouter_proto_dhcp::settings(&c, identity, mac)
                    .map(|s| {
                        let seed = u64::from_be_bytes([
                            0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        ]) ^ now.rotate_left(17)
                            ^ u64::from(id.0);
                        Client::new(s, allow(c.allowed_servers.clone()), seed)
                    })
                    .map_err(|(field, why)| format!("{field}: {why}"))
            }
        };
        let had_error = self.dhcp.runners.get(&id).and_then(|o| o.error.clone());
        match started {
            Ok(mut client) => {
                let mac = r.port.as_ref().map(|p| p.mac()).unwrap_or_default();
                let actions = match self.dhcp_recall(id, &c.interface, mac, now) {
                    Some(lease) => client.reboot(now, lease),
                    None => client.start(now),
                };
                r.client = Some(client);
                let mut rest = Vec::new();
                r.perform(actions, &mut rest);
                self.dhcp.runners.insert(id, r);
                self.dhcp_after(id, rest);
            }
            Err(e) => {
                r.error = Some(e.clone());
                self.dhcp.runners.insert(id, r);
                // Say it once, not every retry.
                if had_error.as_deref() != Some(e.as_str()) {
                    self.dhcp_log(id, &Event::Error(e));
                }
            }
        }
    }

    /// The client's config changed (still the same interface).
    fn dhcp_update(&mut self, c: DhcpClient, identity: &str) {
        let id = c.id;
        let Some(r) = self.dhcp.runners.get_mut(&id) else {
            return;
        };
        let routes_changed = r.cfg.add_default_route != c.add_default_route
            || r.cfg.default_route_distance != c.default_route_distance
            || r.cfg.default_route_table != c.default_route_table;
        let mac = r.port.as_ref().map(|p| p.mac()).unwrap_or_default();
        match corerouter_proto_dhcp::settings(&c, identity, mac) {
            Ok(s) => {
                if let Some(client) = r.client.as_mut() {
                    client.set_settings(s);
                    client.set_allowed(allow(c.allowed_servers.clone()));
                }
            }
            Err((field, why)) => r.error = Some(format!("{field}: {why}")),
        }
        r.cfg = c;
        if routes_changed {
            let lease = r.lease().cloned();
            if let Some(l) = lease {
                self.dhcp_install(id, Some(&l));
            }
        }
    }

    /// `ip.dhcp-client.renew` / `release` on the state machine.
    pub(crate) fn dhcp_kick(&mut self, id: ItemId, release: bool) -> Result<State, String> {
        let now = self.dhcp.now_ms.ok_or_else(|| {
            "DHCP clients do not run here (no service clock: the in-browser lab)".to_owned()
        })?;
        let r =
            self.dhcp.runners.get_mut(&id).ok_or_else(|| {
                format!("client {id} is not running (disabled, or its interface is)")
            })?;
        let Some(client) = r.client.as_mut() else {
            return Err(format!(
                "client {id} cannot run: {}",
                r.error.clone().unwrap_or_default()
            ));
        };
        let actions = if release {
            client.release(now)
        } else {
            client.renew(now)
        };
        let mut rest = Vec::new();
        r.perform(actions, &mut rest);
        if release {
            self.dhcp_forget(id);
        }
        self.dhcp_after(id, rest);
        // The lab answers at once: let the exchange finish now.
        self.dhcp_service(now);
        Ok(self
            .dhcp
            .runners
            .get(&id)
            .map_or(State::Stopped, Runner::state))
    }

    /// DNS servers learned by clients with `use_peer_dns` (for the DNS
    /// resolver, G4.1), in client order, without repeats.
    pub fn dhcp_peer_dns(&self) -> Vec<Ipv4Addr> {
        self.peer(|c| c.use_peer_dns, |l| &l.dns)
    }

    /// NTP servers learned by clients with `use_peer_ntp` (for G4.6).
    pub fn dhcp_peer_ntp(&self) -> Vec<Ipv4Addr> {
        self.peer(|c| c.use_peer_ntp, |l| &l.ntp)
    }

    fn peer(
        &self,
        wants: impl Fn(&DhcpClient) -> bool,
        list: impl Fn(&Lease) -> &Vec<Ipv4Addr>,
    ) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = Vec::new();
        for r in self.dhcp.runners.values().filter(|r| wants(&r.cfg)) {
            for ip in r.lease().map(&list).into_iter().flatten() {
                if !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
        out
    }

    /// History after `after_seq`, of one client or all.
    pub(crate) fn dhcp_history(&self, client: Option<ItemId>, after_seq: u64) -> Value {
        let events: Vec<&HistoryEntry> = self
            .dhcp
            .history()
            .filter(|h| h.seq > after_seq && client.is_none_or(|c| c == h.client))
            .collect();
        json!({ "events": events, "last_seq": self.dhcp.seq })
    }
}

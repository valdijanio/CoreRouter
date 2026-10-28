//! DHCPv6 clients at run time (G4.7b), like the DHCPv4 ones
//! ([`crate::dhcp_client`]): one state machine
//! ([`corerouter_proto_dhcp::client6::Client`]) per enabled client of the
//! running config, on the socket the HAL opens for its interface, driven by
//! [`Session::dhcp_service`].
//!
//! What a lease brings is operational state, never in the config:
//! - the address (IA_NA) as a dynamic `/128` on the interface;
//! - `::/0` via the server's link-local address when `add_default_route`;
//! - the delegated prefix (IA_PD) as a **pool** named by `pool_name`.
//!   Addresses with `from_pool` take their prefix from it (see
//!   `corerouter_model::ipv6::from_pool`): [`Session::effective`] resolves
//!   them, so the data plane gets `<prefix>::1/64` and renumbers with the
//!   prefix; with no prefix they are not installed.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use corerouter_hal::dhcp::Dhcp6Port;
use corerouter_model::ipv6::{self, AllowedServer6};
use corerouter_model::route;
use corerouter_model::{AddressEntry, Config, Dhcp6Client, Gateway, IfName, ItemId, RouteEntry};
use corerouter_proto_dhcp::client6::{Action, Client, Event, Held, Lease, State};
use ipnet::{IpNet, Ipv6Net};
use serde_json::{Value, json};

use crate::Session;
use crate::dhcp_client::{HistoryEntry, MAX_HISTORY};

const RECV_BUDGET: usize = 32;
const ROUNDS: usize = 6;
const PORT_RETRY_MS: u64 = 10_000;
/// Ids of dynamic addresses and routes of DHCPv6 clients:
/// `0xD8000000 | client << 8 | n`.
pub const DYN6_BASE: u32 = 0xD800_0000;
/// Ids of what the kernel learned from Router Advertisements, by position
/// (`0xD4000000 | n`): listed, never editable.
pub const RA_BASE: u32 = 0xD400_0000;

fn dyn_id(client: ItemId, n: usize) -> ItemId {
    let n = u32::try_from(n).unwrap_or(0xFF) & 0xFF;
    ItemId(DYN6_BASE | ((client.0 & 0x3_FFFF) << 8) | n)
}

pub fn ra_id(n: usize) -> ItemId {
    ItemId(RA_BASE | (u32::try_from(n).unwrap_or(0) & 0x03FF_FFFF))
}

/// Whether `id` names something a DHCPv6 client installed.
pub fn is_dynamic6(id: ItemId) -> bool {
    id.0 & 0xFC00_0000 == DYN6_BASE
}

/// Whether `id` names something learned from Router Advertisements.
pub fn is_learned(id: ItemId) -> bool {
    id.0 & 0xFC00_0000 == RA_BASE
}

pub(crate) struct Runner6 {
    pub cfg: Dhcp6Client,
    port: Option<Box<dyn Dhcp6Port>>,
    pub client: Option<Client>,
    pub error: Option<String>,
    retry_at: u64,
    pub addresses: Vec<AddressEntry>,
    pub routes: Vec<RouteEntry>,
    /// The delegated prefix as installed (its pool's addresses follow it).
    pub pool: Option<Held<Ipv6Net>>,
    pub duid: Vec<u8>,
}

impl Runner6 {
    pub fn lease(&self) -> Option<&Lease> {
        self.client.as_ref().and_then(Client::lease)
    }

    pub fn state(&self) -> State {
        self.client.as_ref().map_or(State::Stopped, Client::state)
    }

    fn perform(&mut self, actions: Vec<Action>, out: &mut Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(payload) => {
                    let sent = match self.port.as_mut() {
                        Some(p) => p.send(&payload).map_err(|e| e.to_string()),
                        None => Err("no socket".into()),
                    };
                    if let Err(e) = sent {
                        out.push(Action::Log(Event::Error(format!("send failed: {e}"))));
                    }
                }
                other => out.push(other),
            }
        }
    }

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
                        log::debug!("dhcpv6-client {}: recv: {e}", self.cfg.interface);
                        break;
                    }
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

#[derive(Default)]
pub struct Dhcp6Runtime {
    pub(crate) runners: BTreeMap<ItemId, Runner6>,
    history: VecDeque<HistoryEntry>,
    seq: u64,
}

impl Dhcp6Runtime {
    pub(crate) fn runner(&self, id: ItemId) -> Option<&Runner6> {
        self.runners.get(&id)
    }

    fn quiet(&self) -> bool {
        self.runners
            .values()
            .all(|r| r.addresses.is_empty() && r.routes.is_empty() && r.pool.is_none())
    }
}

fn allow(list: Vec<AllowedServer6>) -> impl Fn(&[u8], Ipv6Addr, Option<[u8; 6]>) -> bool + Send {
    move |duid, src, mac| ipv6::allows6(&list, duid, src, mac)
}

/// Address and routes `lease` brings for client `c`.
pub fn lease_entries(
    cfg: &Config,
    c: &Dhcp6Client,
    lease: &Lease,
) -> (Vec<AddressEntry>, Vec<RouteEntry>) {
    let mut addresses = Vec::new();
    if let Some(a) = lease.address
        && let Ok(net) = Ipv6Net::new(a.value, 128)
    {
        addresses.push(AddressEntry {
            id: dyn_id(c.id, 0),
            address: IpNet::V6(net),
            interface: c.interface.clone(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let mut routes = Vec::new();
    if c.add_default_route && route::is_link_local(IpAddr::V6(lease.server_addr)) {
        routes.push(RouteEntry {
            id: dyn_id(c.id, 1),
            dst_address: IpNet::V6(Ipv6Net::default()),
            gateway: Gateway::via(IpAddr::V6(lease.server_addr), c.interface.clone()),
            distance: c.default_route_distance.max(1),
            routing_table: ipv6::table_of(cfg, c),
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
    }
    (addresses, routes)
}

/// One pool as `ipv6.pool.list` shows it.
#[derive(Debug, Clone)]
pub struct Pool {
    pub name: String,
    pub client: ItemId,
    pub interface: IfName,
    pub prefix: Option<Ipv6Net>,
    pub expires_ms: Option<u64>,
    pub preferred: Option<u32>,
    pub valid: Option<u32>,
}

fn event_text(e: &Event) -> (&'static str, String) {
    match e {
        Event::Searching => ("searching", "soliciting DHCPv6 servers".into()),
        Event::Advertised {
            server,
            what,
            preference,
        } => (
            "advertised",
            format!("{what} advertised by {server} (preference {preference})"),
        ),
        Event::Bound { server, what } => ("bound", format!("got {what} from {server}")),
        Event::Renewed { server, what } => ("renewed", format!("{what} renewed by {server}")),
        Event::Lost { what, reason } => ("lost", format!("{what} lost: {reason}")),
        Event::Status { server, text } => ("status", format!("{server}: {text}")),
        Event::Refused { server } => (
            "refused",
            format!("ignored server {server}: not in allowed-servers"),
        ),
        Event::Ignored { server, why } => {
            ("ignored", format!("answer from {server} ignored: {why}"))
        }
        Event::Error(e) => ("error", e.clone()),
    }
}

impl Session {
    /// Whether DHCPv6 has nothing for [`Session::effective`] to add.
    pub(crate) fn dhcp6_quiet(&self, cfg: &Config) -> bool {
        self.dhcp6.quiet() && cfg.ip.addresses.iter().all(|a| a.from_pool.is_none())
    }

    /// Add the DHCPv6 clients' entries to `out` (a copy of `cfg`) and
    /// resolve the addresses taken from pools; the unresolved ones leave.
    pub(crate) fn dhcp6_extend(&self, cfg: &Config, out: &mut Config) {
        for (id, r) in &self.dhcp6.runners {
            let live = cfg
                .ipv6
                .dhcp_clients
                .iter()
                .any(|c| c.id == *id && !c.disabled && c.interface == r.cfg.interface);
            if !live {
                continue;
            }
            out.ip.addresses.extend(r.addresses.iter().cloned());
            // Listed even beside a static route to the same prefix (G1.27h).
            out.ip.routes.extend(r.routes.iter().cloned());
        }
        let pools = self.pools(cfg);
        out.ip.addresses.retain_mut(|a| {
            let Some(pool) = &a.from_pool else {
                return true;
            };
            match resolve(&pools, pool, a.address) {
                Ok(net) => {
                    a.address = IpNet::V6(net);
                    true
                }
                Err(_) => false,
            }
        });
    }

    /// The pools: one per client of `cfg` that asks for a prefix, with the
    /// prefix it holds now (if any).
    pub fn pools(&self, cfg: &Config) -> Vec<Pool> {
        cfg.ipv6
            .dhcp_clients
            .iter()
            .filter(|c| c.request.prefix() && !c.pool_name.is_empty())
            .map(|c| {
                let held = self
                    .dhcp6
                    .runner(c.id)
                    .filter(|r| !c.disabled && r.cfg.interface == c.interface)
                    .and_then(|r| r.pool);
                Pool {
                    name: c.pool_name.clone(),
                    client: c.id,
                    interface: c.interface.clone(),
                    prefix: held.map(|h| h.value),
                    expires_ms: held.and_then(|h| h.expires_ms),
                    preferred: held.map(|h| h.preferred),
                    valid: held.map(|h| h.valid),
                }
            })
            .collect()
    }

    /// Address `address` of pool `pool` as installed now, or why it is not.
    pub fn pool_address(
        &self,
        cfg: &Config,
        pool: &str,
        address: IpNet,
    ) -> Result<Ipv6Net, String> {
        resolve(&self.pools(cfg), pool, address)
    }

    pub(crate) fn dhcp6_service(&mut self, now: u64) {
        self.dhcp6_reconcile(now);
        let ids: Vec<ItemId> = self.dhcp6.runners.keys().copied().collect();
        for id in ids {
            let actions = match self.dhcp6.runners.get_mut(&id) {
                Some(r) => r.step(now),
                None => continue,
            };
            self.dhcp6_after(id, actions);
        }
    }

    fn dhcp6_after(&mut self, id: ItemId, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Bind(lease) => self.dhcp6_install(id, Some(&lease)),
                Action::Unbind => self.dhcp6_install(id, None),
                Action::Log(e) => self.dhcp6_log(id, &e),
                Action::Send(_) => {}
            }
        }
    }

    fn dhcp6_log(&mut self, id: ItemId, e: &Event) {
        let Some(iface) = self.dhcp6.runners.get(&id).map(|r| r.cfg.interface.clone()) else {
            return;
        };
        let (event, message) = event_text(e);
        self.dhcp6_note(id, iface, event, message);
    }

    fn dhcp6_note(&mut self, id: ItemId, interface: IfName, event: &'static str, message: String) {
        match event {
            "error" | "refused" | "status" | "lost" => {
                log::warn!("dhcpv6-client {id} on {interface}: {message}");
            }
            "searching" | "advertised" => {
                log::debug!("dhcpv6-client {id} on {interface}: {message}");
            }
            _ => log::info!("dhcpv6-client {id} on {interface}: {message}"),
        }
        let (topics, text, detail) = crate::logging::dhcp_event(
            true,
            &id.to_string(),
            interface.as_str(),
            event,
            &message,
        );
        self.log_event(&topics, crate::logging::DAEMON, text, detail);
        self.dhcp6.seq = self.dhcp6.seq.saturating_add(1);
        let time = self.now();
        self.dhcp6.history.push_back(HistoryEntry {
            seq: self.dhcp6.seq,
            time,
            client: id,
            interface,
            event,
            message,
        });
        while self.dhcp6.history.len() > MAX_HISTORY {
            self.dhcp6.history.pop_front();
        }
    }

    /// Install `lease` (`None`: remove), through `Hal::apply` on the running
    /// config: the address, the route and every address of its pool.
    fn dhcp6_install(&mut self, id: ItemId, lease: Option<&Lease>) {
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        let Some(r) = self.dhcp6.runners.get_mut(&id) else {
            return;
        };
        let old = (
            std::mem::take(&mut r.addresses),
            std::mem::take(&mut r.routes),
            r.pool.take(),
        );
        if let Some(l) = lease {
            (r.addresses, r.routes) = lease_entries(&running, &r.cfg, l);
            r.pool = l.prefix;
        }
        let after = self.effective(&running).into_owned();
        if before == after {
            return;
        }
        if let Err(e) = self.hal_mut().apply(&before, &after) {
            let msg = format!("lease not applied: {e}");
            if let Some(r) = self.dhcp6.runners.get_mut(&id) {
                (r.addresses, r.routes, r.pool) = old;
                r.error = Some(msg.clone());
            }
            self.dhcp6_log(id, &Event::Error(msg));
        } else if let Some(r) = self.dhcp6.runners.get_mut(&id)
            && r.error
                .as_deref()
                .is_some_and(|e| e.starts_with("lease not applied"))
        {
            r.error = None;
        }
    }

    fn dhcp6_reconcile(&mut self, now: u64) {
        let running = self.store().running();
        let wanted: Vec<Dhcp6Client> = running
            .ipv6
            .dhcp_clients
            .iter()
            .filter(|c| !c.disabled && route::is_up(running, &c.interface))
            .cloned()
            .collect();
        let gone: Vec<(ItemId, String)> = self
            .dhcp6
            .runners
            .iter()
            .filter_map(|(id, r)| {
                let now_cfg = running.ipv6.dhcp_clients.iter().find(|c| c.id == *id);
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
            let actions = self
                .dhcp6
                .runners
                .get_mut(&id)
                .and_then(|r| r.client.as_mut())
                .map(|c| c.stop(&why))
                .unwrap_or_default();
            for a in &actions {
                if let Action::Log(e) = a {
                    self.dhcp6_log(id, e);
                }
            }
            self.dhcp6_install(id, None);
            if let Some(r) = self.dhcp6.runners.remove(&id) {
                self.dhcp6_note(id, r.cfg.interface.clone(), "stopped", why);
            }
        }
        for c in wanted {
            match self.dhcp6.runners.get(&c.id) {
                None => self.dhcp6_start(c, now),
                Some(r) if r.port.is_none() && now >= r.retry_at => self.dhcp6_start(c, now),
                Some(r) if r.cfg != c => self.dhcp6_update(c, now),
                Some(_) => {}
            }
        }
    }

    fn dhcp6_start(&mut self, c: Dhcp6Client, now: u64) {
        let id = c.id;
        let port = self.hal_mut().dhcp6_port(&c.interface);
        let mut r = Runner6 {
            cfg: c.clone(),
            port: None,
            client: None,
            error: None,
            retry_at: now.saturating_add(PORT_RETRY_MS),
            addresses: Vec::new(),
            routes: Vec::new(),
            pool: None,
            duid: Vec::new(),
        };
        let started = match port {
            Err(e) => Err(format!(
                "cannot open a DHCPv6 socket on '{}': {e}",
                c.interface
            )),
            Ok(p) => {
                let mac = p.mac();
                r.port = Some(p);
                corerouter_proto_dhcp::settings6(&c, mac)
                    .map(|s| {
                        r.duid = s.duid.clone();
                        let seed = u64::from_be_bytes([
                            0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        ]) ^ now.rotate_left(23)
                            ^ u64::from(id.0).rotate_left(7);
                        Client::new(s, allow(c.allowed_servers.clone()), seed)
                    })
                    .map_err(|(field, why)| format!("{field}: {why}"))
            }
        };
        let had_error = self.dhcp6.runners.get(&id).and_then(|o| o.error.clone());
        match started {
            Ok(mut client) => {
                let actions = client.start(now);
                r.client = Some(client);
                let mut rest = Vec::new();
                r.perform(actions, &mut rest);
                self.dhcp6.runners.insert(id, r);
                self.dhcp6_after(id, rest);
            }
            Err(e) => {
                r.error = Some(e.clone());
                self.dhcp6.runners.insert(id, r);
                if had_error.as_deref() != Some(e.as_str()) {
                    self.dhcp6_log(id, &Event::Error(e));
                }
            }
        }
    }

    fn dhcp6_update(&mut self, c: Dhcp6Client, now: u64) {
        let id = c.id;
        let Some(r) = self.dhcp6.runners.get_mut(&id) else {
            return;
        };
        let routes_changed = r.cfg.add_default_route != c.add_default_route
            || r.cfg.default_route_distance != c.default_route_distance;
        let mac = r.port.as_ref().map(|p| p.mac()).unwrap_or_default();
        let mut actions = Vec::new();
        match corerouter_proto_dhcp::settings6(&c, mac) {
            Ok(s) => {
                r.duid = s.duid.clone();
                if let Some(client) = r.client.as_mut() {
                    client.set_allowed(allow(c.allowed_servers.clone()));
                    actions = client.set_settings(s, now);
                }
            }
            Err((field, why)) => r.error = Some(format!("{field}: {why}")),
        }
        r.cfg = c;
        let mut rest = Vec::new();
        r.perform(actions, &mut rest);
        self.dhcp6_after(id, rest);
        if routes_changed {
            let lease = self.dhcp6.runners.get(&id).and_then(|r| r.lease().cloned());
            if let Some(l) = lease {
                self.dhcp6_install(id, Some(&l));
            }
        }
    }

    /// `ipv6.dhcp-client.renew` / `release`.
    pub(crate) fn dhcp6_kick(&mut self, id: ItemId, release: bool) -> Result<State, String> {
        let now = self.dhcp.now_ms.ok_or_else(|| {
            "DHCPv6 clients do not run here (no service clock: the in-browser lab)".to_owned()
        })?;
        let r =
            self.dhcp6.runners.get_mut(&id).ok_or_else(|| {
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
        self.dhcp6_after(id, rest);
        self.dhcp_service(now);
        Ok(self
            .dhcp6
            .runners
            .get(&id)
            .map_or(State::Stopped, Runner6::state))
    }

    /// DNS servers learned by DHCPv6 clients with `use_peer_dns` (for G4.1).
    pub fn dhcp6_peer_dns(&self) -> Vec<Ipv6Addr> {
        let mut out: Vec<Ipv6Addr> = Vec::new();
        for r in self.dhcp6.runners.values().filter(|r| r.cfg.use_peer_dns) {
            for ip in r.lease().map(|l| &l.dns).into_iter().flatten() {
                if !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
        out
    }

    pub(crate) fn dhcp6_history(&self, client: Option<ItemId>, after_seq: u64) -> Value {
        let events: Vec<&HistoryEntry> = self
            .dhcp6
            .history
            .iter()
            .filter(|h| h.seq > after_seq && client.is_none_or(|c| c == h.client))
            .collect();
        json!({ "events": events, "last_seq": self.dhcp6.seq })
    }
}

fn resolve(pools: &[Pool], pool: &str, address: IpNet) -> Result<Ipv6Net, String> {
    let IpNet::V6(entry) = address else {
        return Err("only IPv6 addresses come from a pool".into());
    };
    let p = pools
        .iter()
        .find(|p| p.name == pool)
        .ok_or_else(|| format!("no DHCPv6 client delegates into pool '{pool}'"))?;
    let prefix = p.prefix.ok_or_else(|| {
        format!(
            "pool '{pool}' has no prefix yet (client {} on {})",
            p.client, p.interface
        )
    })?;
    ipv6::from_pool(entry, prefix)
}
